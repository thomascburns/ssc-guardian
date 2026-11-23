# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""``ssc-guardian install --venv PATH PACKAGE...``: the checked install (plan §3.1 steps 1-8,
§2.1 install requests, §2.2 exit codes).

1. **Target:** a venv only. A path that is not a venv, a base Python (Apple's, Homebrew's
   externally managed one, python.org's) or a Python older than 3.9 is refused (exit 2)
   with the fix "create a venv and install there". So is a venv whose interpreter an
   installed package could have replaced (:func:`check_interpreter`): ``bin/python`` must
   be a link that resolves outside the venv to the interpreter ``pyvenv.cfg``'s ``home``
   names, ``home`` itself a plain path no folder of which resolves inside the venv, and
   ``bin`` holds no ``pyvenv.cfg`` or ``._pth``
   file. A venv made with ``--copies`` has a file there, not a link, and is refused with a
   message saying so.
2. **Refused before resolving** (exit 1): direct-URL, VCS, local-path and editable
   requirements and requirement-file option lines. The command line already accepts only
   ``NAME`` and ``NAME==VERSION`` (D5); :func:`refusal` is a second gate on every requirement
   handed to pip.
3. **The request's versions.** A loose request is handed to pip as ``NAME<=V``, V the newest
   version that passes every rule today and has a wheel that fits the venv
   (``policy.replacements``), or the newest that passes when none fits, so pip takes V or, when
   it cannot, the newest older version it can, if any; the resolved set is then checked as a whole.
   An exact request that fails a rule (after the workstation overrides) is refused, and the
   output names the newest version that passes and fits, if any, and its command.
4. **Check step, locked down:** Guardian's pinned pip (``pinned_pip``) under the venv's
   Python with ``-I -S``, the venv's package folders as plain paths, a clean environment,
   ``PIP_CONFIG_FILE`` set to the null device, ``--isolated``, the PyPI index,
   ``--only-binary :all:``, ``--upgrade`` (so a loose request replaces an older version),
   ``--uploaded-prior-to`` (today minus the shortest cooldown that applies to the request) and
   ``--dry-run --report``. No installed package code runs: imports come from the wheel and
   the standard library only (``pinned_pip``).
5. **Binding** (``binding``): every reported file is a wheel from ``files.pythonhosted.org``
   whose SHA-256 equals PyPI's published digest; otherwise nothing is installed (exit 2).
6. **Every package pip resolved** is checked as ``check --envs`` checks it: deny list, age,
   compromise against ``block_on``, known vulnerabilities, then the workstation overrides.
   A failing dependency refuses the whole request (exit 1); there is no re-resolve loop.
   A requested package pip leaves in place (its report has no entry for it) is checked at the
   version installed in the venv, which is what the request ends with; when that version
   cannot be read, the check cannot finish (exit 2), never "Nothing to install" (#228).
7. **Install step, after confirmation:** the same pinned pip under the venv's Python with
   ``-I`` (normal mode, so the venv's own startup files run, as they do whenever it starts),
   the same clean environment, ``--no-deps --require-hashes --only-binary :all:`` and each
   bound file as ``name==version --hash=sha256:...``.
8. Nothing is installed on exit 1 or 2. Declined, or no terminal: exit 2 (D15). A re-run
   installs nothing new: pip's report is empty once every package is in place, and each
   requested package's installed version is checked again.

Messages go to stderr (text only) and name the next step; the findings carry the options.
"""

from __future__ import annotations

import glob
import json
import os
import re
import stat
import sys
import tempfile
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import TYPE_CHECKING, Protocol, TextIO

from ssc_guardian import discovery, pep440, pinned_pip, policy
from ssc_guardian.binding import PYPI_ENDPOINTS, Endpoints, Reported, bind, read_report, uploaded
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.discovery import Environment, Roots
from ssc_guardian.feeds import merge, pypi
from ssc_guardian.feeds.kev import Kev
from ssc_guardian.findings import (
    Collector,
    Ecosystem,
    ExitCode,
    Finding,
    FindingField,
    IncompleteCheckError,
    Level,
    Option,
    OptionKind,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    make_finding,
)
from ssc_guardian.grammars import Field, MalformedValueError, matches, normalize_pypi_name
from ssc_guardian.net import Client, FeedError, find_token
from ssc_guardian.overrides import utc_today
from ssc_guardian.plugin import InstallPlan, PlannedFile, Requirement
from ssc_guardian.plugins import pip
from ssc_guardian.render import strip_controls
from ssc_guardian.settings import ConfigFileError, Key, Settings, workstation_settings

if TYPE_CHECKING:
    from ssc_guardian.cli import Request

PYPI = Ecosystem.PYPI
OLDEST_PYTHON = (3, 9)
NEXT_STEP = "create a venv and install there"
REPORT_LIMIT = 32 * 1024 * 1024
CONFIG_LIMIT = 64 * 1024  # pyvenv.cfg is a few lines
# Bytes in one pyvenv.cfg line: Python 3.9 and 3.10 read a line into 2 * MAXPATHLEN bytes, which
# is 2048 on macOS, and a longer line ends their reading of the file.
CONFIG_LINE_LIMIT = 2000
# Characters str.splitlines() or universal newlines treat as line ends (a CR not before an LF
# included), or that have no place in a text file: refused, so every reader sees the same lines.
_CONFIG_CONTROLS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029]|\r(?!\n)")
# A version no candidate can be: replacements() never offers a pre-release, so passing this as
# the "current" version excludes nothing.
_NO_CURRENT = pep440.parse("0.dev0")
_VCS = re.compile(r"(?:git|hg|svn|bzr)\+", re.IGNORECASE)
_ARCHIVES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".egg")


class RefusedError(IncompleteCheckError):
    """The request cannot be installed as asked; the message names the next step (exit 2)."""

    def __init__(self, message: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.message = message

    def __str__(self) -> str:
        return self.message


def refusal(requirement: str) -> str | None:
    """Why ``requirement`` is refused before anything is resolved (plan §3.1 step 2), or None
    for ``NAME`` or ``NAME==VERSION``. pip would build or fetch the refused forms outside the
    index's checked files (fact 5): an editable or local project is built, a direct URL or VCS
    reference is fetched as given, and an option line changes where pip looks or lets
    ``--no-binary`` override ``--only-binary``."""
    text = requirement.strip()
    if text.startswith(("-e", "--editable")):
        return "an editable requirement is refused: Guardian installs released wheels from PyPI by name"
    if text.startswith("-"):
        return (
            "requirement-file option lines (--no-binary, --find-links, --index-url and the like) are refused: "
            "Guardian sets pip's options itself"
        )
    if _VCS.match(text):
        return "a VCS requirement is refused: install a released version from PyPI by name"
    if "://" in text or "@" in text:
        return "a direct URL is refused: install a released version from PyPI by name"
    if text.startswith((".", "/", "~")) or "/" in text or "\\" in text or text.lower().endswith(_ARCHIVES):
        return "a local path is refused: install a released version from PyPI by name"
    name, sep, version = text.partition("==")
    if matches(Field.PYPI_NAME, name) and (not sep or matches(Field.PEP440_VERSION, version)):
        return None
    return "only NAME or NAME==VERSION is accepted"


def _requirement_text(requirement: Requirement) -> str:
    return requirement.name if requirement.version is None else f"{requirement.name}=={requirement.version}"


def python_of(env: Environment) -> str:
    """The venv's own interpreter, as the venv names it (never resolved, so the venv is recognized)."""
    return os.path.join(env.prefix, "bin", "python")


def check_folders(env: Environment) -> tuple[str, ...]:
    """The package folders the install step's Python sees: ``-I`` leaves out the per-user one."""
    return tuple(folder for folder in env.search_order if folder != env.user_site)


def _home(prefix: str) -> str | None:
    """``home`` from the venv's ``pyvenv.cfg`` (``key = value`` lines, keys lowered), or None.

    The interpreter's startup code takes the first ``home``, ``site.venv`` the last, and the
    two split lines differently, so only a file both read alike is accepted: more than one
    ``home``, a control character other than tab, LF or CR before LF, a line longer than
    :data:`CONFIG_LINE_LIMIT` bytes or a file longer than :data:`CONFIG_LIMIT` raises ValueError.
    Python 3.9 and 3.10 match ``home`` more narrowly (case and spacing); a line they skip
    leaves them on the base interpreter's own prefix, which is outside the venv anyway.
    Opened non-blocking and read only as a regular file, so a FIFO in its place cannot hang
    the run."""
    fd = os.open(os.path.join(prefix, "pyvenv.cfg"), os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError("not a regular file")
        data = handle.read(CONFIG_LIMIT + 1)
    if len(data) > CONFIG_LIMIT:
        raise ValueError("too large")
    text = data.decode("utf-8")
    if _CONFIG_CONTROLS.search(text):
        raise ValueError("a control character")
    homes = []
    for line in text.split("\n"):
        if len(line.encode("utf-8")) > CONFIG_LINE_LIMIT:
            raise ValueError("a line too long")
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() == "home":
            homes.append(value.strip())
    if len(homes) > 1:
        raise ValueError("more than one home")
    return homes[0] if homes else None


def _inside(place: str, venv: os.stat_result) -> bool:
    """Whether ``place``, resolved, is the venv folder or lies under it. Folders are compared by
    device and inode, never by spelling: APFS finds ``/Users/X`` as ``/users/x``, and
    ``realpath`` keeps the spelling it was given. A folder that cannot be looked at counts as
    the venv."""
    here = os.path.realpath(place)
    while True:
        try:
            if os.path.samestat(os.stat(here), venv):
                return True
        except OSError:
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def _leads_into(path: str, venv: os.stat_result) -> bool:
    """Whether ``path`` or a folder above it, as written, resolves inside the venv: Python looks
    for its standard library by walking up from ``home`` as written, not as resolved."""
    here = path
    while True:
        if _inside(here, venv):
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


class InterpreterRefusedError(RefusedError):
    """Why the venv's ``bin/python`` is not run: one refusal, with its own site, per reason
    (#148). :func:`target` names the venv in front of it."""


def check_interpreter(env: Environment) -> None:
    """Raise :class:`InterpreterRefusedError` saying why the venv's ``bin/python`` is not run (the
    check step must run no installed code, plan §2.3 boundary item 2). An installed wheel can
    replace ``bin/python`` (``X.data/scripts/python``) or ``pyvenv.cfg``
    (``X.data/data/pyvenv.cfg``), so the venv's own files are trusted only as far as they lead
    out of it: ``bin/python`` is a symlink;
    the file it resolves to lies outside the venv; ``home`` from ``pyvenv.cfg`` is a plain
    absolute path (no ``.`` or ``..`` part) and neither it nor any folder above it resolves
    inside the venv, since Python walks up from ``home`` as written to find its standard
    library; and ``home`` joined with the link's own name resolves to that same file. A
    wheel's ``X.data/scripts`` files land in ``bin``, beside the interpreter, where some
    Pythons read a ``pyvenv.cfg`` too and, from 3.11, a ``python._pth`` (in any case, on a
    case-insensitive disk) replaces ``sys.path`` whatever the options (``-I -S`` included); so
    a ``pyvenv.cfg`` or any ``._pth`` file in ``bin`` is refused. Nothing is run."""
    python = python_of(env)
    try:
        venv = os.stat(env.prefix)
    except OSError:
        raise InterpreterRefusedError(
            f"cannot be looked at, so its interpreter cannot be checked; {NEXT_STEP}",
            site="install.venv-cannot-be-looked-at",
        ) from None
    if not os.path.islink(python):
        if not os.path.lexists(python):
            raise InterpreterRefusedError(f"has no bin/python; {NEXT_STEP}", site="install.no-bin-python")
        raise InterpreterRefusedError(
            "has a file, not a link, at bin/python: a venv made with --copies or by a tool that copies "
            "the interpreter, or a Python an installed package replaced. Guardian runs only an interpreter "
            "outside the venv; create a venv without --copies and install there",
            site="install.bin-python-is-a-file",
        )
    folder = os.path.join(env.prefix, "bin")
    try:
        names = os.listdir(folder)
    except OSError:
        raise InterpreterRefusedError(
            f"has a bin folder that cannot be listed, so its interpreter cannot be checked; {NEXT_STEP}",
            site="install.bin-folder-cannot-be-listed",
        ) from None
    if os.path.lexists(os.path.join(folder, "pyvenv.cfg")):
        raise InterpreterRefusedError(
            "has a pyvenv.cfg in bin, which Python may read instead of the venv's own; an installed "
            f"package may have put it there; {NEXT_STEP}",
            site="install.pyvenv-cfg-in-bin",
        )
    if any(name.casefold().endswith("._pth") for name in names):  # APFS finds python._PTH as python._pth
        raise InterpreterRefusedError(
            "has a ._pth file in bin, which sets Python's import path whatever its options; an installed "
            f"package may have put it there; {NEXT_STEP}",
            site="install.pth-file-in-bin",
        )
    try:
        home = _home(env.prefix)
    except (OSError, ValueError):  # UnicodeDecodeError included
        raise InterpreterRefusedError(
            "has a pyvenv.cfg that is not plain text with at most one home line, so its interpreter "
            f"cannot be checked; {NEXT_STEP}",
            site="install.pyvenv-cfg-not-plain-text",
        ) from None
    if not home or not os.path.isabs(home) or os.path.normpath(home) != home:
        raise InterpreterRefusedError(
            f"has no plain absolute home in pyvenv.cfg, so its interpreter cannot be checked; {NEXT_STEP}",
            site="install.home-not-plain-absolute",
        )
    try:
        link = os.readlink(python)
        resolved = os.path.realpath(python, strict=True)
        os.path.realpath(home, strict=True)
        named = os.path.realpath(os.path.join(home, os.path.basename(link)), strict=True)
        same = os.path.samefile(named, resolved)
    except (OSError, ValueError):
        raise InterpreterRefusedError(
            f"has a bin/python or a pyvenv.cfg home that does not lead to an interpreter; {NEXT_STEP}",
            site="install.interpreter-not-reached",
        ) from None
    if _inside(resolved, venv) or not os.path.isfile(resolved):
        raise InterpreterRefusedError(
            f"has a bin/python that resolves inside the venv, not to the Python it was made from; {NEXT_STEP}",
            site="install.python-resolves-inside-venv",
        )
    if _leads_into(home, venv):
        raise InterpreterRefusedError(
            f"has a pyvenv.cfg home inside the venv, not the Python it was made from; {NEXT_STEP}",
            site="install.home-inside-venv",
        )
    if not same:
        raise InterpreterRefusedError(
            f"has a bin/python that is not the interpreter pyvenv.cfg's home names; {NEXT_STEP}",
            site="install.python-not-home-interpreter",
        )


def target(prefix: str, roots: Roots) -> Environment:
    """The venv at ``prefix``, or :class:`RefusedError` with the fix (plan §3.1 step 1)."""
    if not os.path.isfile(os.path.join(prefix, "pyvenv.cfg")):
        base = glob.glob(os.path.join(glob.escape(prefix), "lib", "python3.*", "os.py"))
        what = "a base Python installation, not a venv" if base else "not a venv"
        raise RefusedError(
            f"{prefix} is {what}: Guardian installs into venvs only; {NEXT_STEP}",
            site="install.guardian-installs-into-venvs-only",
        )
    survey = discovery.Survey()
    env = discovery.venv(prefix, roots, survey)
    if env is None:
        why = next((s.detail for s in survey.skipped if s.detail), "its files cannot be read")
        raise RefusedError(f"{prefix} cannot be read as a venv ({why}); {NEXT_STEP}", site="install.cannot-read-venv")
    if not env.is_venv or env.externally_managed or discovery.is_apple(env.prefix):
        raise RefusedError(
            f"{prefix} is a base Python installation, not a venv; {NEXT_STEP}",
            site="install.base-python-installation-not-venv",
        )
    if env.python < OLDEST_PYTHON:
        major, minor = env.python
        raise RefusedError(
            f"{prefix} runs Python {major}.{minor}; Guardian installs into Python 3.9 or later: "
            f"{NEXT_STEP} with a newer Python",
            site="install.guardian-installs-into-python-3",
        )
    try:
        check_interpreter(env)
    except InterpreterRefusedError as exc:
        raise RefusedError(f"{prefix} {exc}", site="install.target-unchecked") from exc
    return env


def cutoff_for(today: date, cooldown_days: int) -> str:
    """``--uploaded-prior-to`` for pip 26.0: a fixed UTC midnight, today minus the cooldown, the
    same instant a ``protect`` fixed date names (fact 2)."""
    return f"{pip.fixed_date(today, cooldown_days).isoformat()}T00:00:00+00:00"


# --- the two pip steps -------------------------------------------------------------------


class Runner(Protocol):
    """The check step and the install step. Tests replace the pinned pip with a fake."""

    def check(self, env: Environment, pins: Sequence[str], cutoff: str) -> object:
        """pip's installation report (parsed JSON) for ``pins``; installs nothing."""
        ...

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        """Install exactly ``files``, each by name, version and SHA-256."""
        ...


@dataclass
class PinnedPip:
    """Both steps with Guardian's pinned pip, in one run's private ``folder``."""

    client: Client
    home: str
    folder: str
    endpoints: Endpoints = PYPI_ENDPOINTS
    _wheel: str | None = field(default=None, init=False)

    def _run(self, env: Environment, mode: tuple[str, ...], folders: Sequence[str], args: list[str]) -> None:
        if self._wheel is None:
            self._wheel = pinned_pip.place(self.client, self.home, self.folder)
        common = [
            "install",
            "--isolated",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "--index-url",
            self.endpoints.index_url,
            "--only-binary",
            ":all:",
            "--quiet",
        ]
        environment = pinned_pip.clean_environment(self.folder)
        done = pinned_pip.run(
            python_of(env), mode, self._wheel, folders, [*common, *args], env=environment, cwd=self.folder
        )
        if done.returncode != 0:
            last = [strip_controls(line) for line in done.stderr.splitlines() if line.strip()][-5:]
            step = "check" if mode == pinned_pip.LOCKED_DOWN else "install"
            said = "; ".join(last) or "no message"
            raise pinned_pip.PinnedPipError(
                f"pip's {step} step stopped (exit {done.returncode}): {said}", site="install.step-stopped-exit"
            )

    def check(self, env: Environment, pins: Sequence[str], cutoff: str) -> object:
        report = os.path.join(self.folder, "report.json")
        # --upgrade: a loose NAME<=V replaces an older installed version, as an exact pin does;
        # dependencies change only where the request needs it (pip's default strategy).
        args = ["--upgrade", "--uploaded-prior-to", cutoff, "--dry-run", "--report", report, *pins]
        self._run(env, pinned_pip.LOCKED_DOWN, check_folders(env), args)
        try:
            with open(report, "rb") as handle:
                data = handle.read(REPORT_LIMIT + 1)
            if len(data) > REPORT_LIMIT:
                raise ValueError("too large")
            return json.loads(data.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise pinned_pip.PinnedPipError(
                f"pip's report could not be read ({type(exc).__name__})", site="install.pips-report-could-not-read"
            ) from exc

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        pinned = os.path.join(self.folder, "pinned-requirements.txt")
        with open(pinned, "x", encoding="ascii") as out:
            for planned in files:
                out.write(f"{planned.item.name}=={planned.item.version} --hash=sha256:{planned.digest}\n")
        self._run(env, pinned_pip.NORMAL, (), ["--no-deps", "--require-hashes", "-r", pinned])


# --- the plug-in's two steps -------------------------------------------------------------


def _cooldown(settings: Settings, requirements: Sequence[Requirement]) -> int:
    """The shortest cooldown that applies to the request, so pip's cutoff never hides a
    version the rules accept. pip takes one cutoff per run, so a file it chooses may be
    younger than its own package's cooldown: after binding, each package's release is checked
    against that package's cooldown, and so is the file actually bound for it, by its own
    upload time (:func:`_file_cooldowns`, #129)."""
    default = int(settings.value(Key.COOLDOWN_DAYS) or 0)
    return min([default, *(settings.cooldown_days(PYPI, r.name) for r in requirements)])


def plan_install(
    roots: Roots,
    target_path: str,
    requirements: tuple[Requirement, ...],
    *,
    client: Client | None = None,
    endpoints: Endpoints = PYPI_ENDPOINTS,
) -> InstallPlan:
    """``PipPlugin.plan_install``: the locked-down check step and the binding; writes nothing.
    The core checks the plan's items against the rules."""
    env = target(target_path, roots)
    for requirement in requirements:
        if refusal(_requirement_text(requirement)) is not None:
            raise MalformedValueError(
                Field.PYPI_NAME, _requirement_text(requirement), site="install.malformed-requirement-name"
            )
    requirements, twice = _one_each(requirements)
    if twice is not None:
        raise MalformedValueError(Field.PEP440_VERSION, twice, site="install.malformed-requirement-version")
    client = client or Client(find_token(roots.environ))
    cutoff = cutoff_for(utc_today(), _cooldown(workstation_settings(roots.home), requirements))
    with tempfile.TemporaryDirectory(prefix="ssc-guardian-install-") as folder:
        runner = PinnedPip(client, roots.home, folder, endpoints)
        entries = read_report(runner.check(env, [_requirement_text(r) for r in requirements], cutoff))
    projects = {name: pypi.project(client, name) for name in {normalize_pypi_name(e.name) for e in entries}}
    files = bind(entries, projects, target=env.prefix, endpoints=endpoints)
    return InstallPlan(env.prefix, tuple(f.item for f in files), files)


def apply_plan(
    roots: Roots, plan: InstallPlan, *, client: Client | None = None, endpoints: Endpoints = PYPI_ENDPOINTS
) -> None:
    """``PipPlugin.apply``: the install step for exactly ``plan``'s files."""
    env = target(plan.target, roots)
    with tempfile.TemporaryDirectory(prefix="ssc-guardian-install-") as folder:
        PinnedPip(client or Client(find_token(roots.environ)), roots.home, folder, endpoints).install(env, plan.files)


# --- the handler ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Staged:
    env: Environment
    plan: InstallPlan


@dataclass(frozen=True)
class Install:
    """The ``install`` handler, with its places, clock, network client, streams, endpoints, pip
    runner and host injectable for tests."""

    home: str | None = None
    environ: Mapping[str, str] | None = None
    root: str = "/"
    today: date | None = None
    client: Client | None = None
    stdin: TextIO | None = None
    stderr: TextIO | None = None
    endpoints: Endpoints = PYPI_ENDPOINTS
    runner: Runner | None = None
    host: policy.Host | None = None

    def __call__(self, request: Request) -> Result:
        err = self.stderr or sys.stderr
        collector = Collector(Verb.INSTALL)
        with tempfile.TemporaryDirectory(prefix="ssc-guardian-install-") as folder:
            self._install(request, collector, folder, err)
        collector.skipped[:] = list(dict.fromkeys(collector.skipped))  # an overrides file checked twice
        return collector.result()

    def roots(self) -> Roots:
        environ = self.environ if self.environ is not None else os.environ
        return Roots(self.home if self.home is not None else os.path.expanduser("~"), environ, self.root)

    def _install(self, request: Request, collector: Collector, folder: str, err: TextIO) -> None:
        from ssc_guardian import cli  # imported here: cli imports this handler

        venv = request.venv
        if venv is None:
            raise ValueError("install needs --venv")
        roots = self.roots()
        try:
            settings = workstation_settings(roots.home)
        except ConfigFileError as exc:
            collector.skipped.append(exc.skip(PYPI))
            _say(err, [f"{strip_controls(exc)}; fix the file by hand. Nothing installed."])
            return
        client = self.client or Client(find_token(roots.environ))
        runner = self.runner or PinnedPip(client, roots.home, folder, self.endpoints)
        staged: _Staged | None = None
        stopped = False
        with collector.check(PYPI, venv) as ok:
            if ok:
                try:
                    staged = self._plan(request, venv, roots, settings, client, runner, collector, err)
                except IncompleteCheckError as exc:
                    _say(err, [f"ssc-guardian: {strip_controls(exc)}; nothing installed."])
                    stopped = True
                    raise
        if staged is None or collector.result().exit_code is not ExitCode.RULES_MET:
            if not stopped:
                _say(err, ["ssc-guardian: refused; nothing installed."])
            return
        plan = staged.plan
        if not plan.files:
            _say(err, ["Nothing to install: every requested package is already in place."])
            return
        # Each value is stripped as it goes in (#161, as #147 does), so a line break in a file
        # name PyPI gives cannot add a line to the change; the lines Guardian writes stay.
        into = strip_controls(venv)
        lines = [f"Guardian will install into {into} exactly these files, each bound to PyPI's SHA-256:"]
        lines += [
            f"  {strip_controls(f.item.name)} {strip_controls(f.item.version)}  {strip_controls(_file_name(f.url))}  "
            f"sha256:{strip_controls(f.digest)}"
            for f in plan.files
        ]
        change = "\n".join(lines)
        if request.yes:
            _say(err, [change, "Confirmed in advance (--yes)."])  # the record D15 asks for
        if not cli.confirm(change, verb=Verb.INSTALL, yes=request.yes, stdin=self.stdin or sys.stdin, stdout=err):
            _say(err, ["ssc-guardian: not confirmed; nothing installed. Add --yes to confirm in advance."])
            collector.skipped.append(
                Skip(
                    PYPI,
                    None,
                    SkipReason.CHECK_ERROR,
                    detail="not confirmed; nothing installed",
                    site="install.not-confirmed",
                )
            )
            return
        self._apply(staged, runner, collector, err)

    def _plan(
        self,
        request: Request,
        venv: str,
        roots: Roots,
        settings: Settings,
        client: Client,
        runner: Runner,
        collector: Collector,
        err: TextIO,
    ) -> _Staged | None:
        """Every check before the install step; None when the request is refused (exit 1)."""
        today = self.today or utc_today()
        env = target(venv, roots)
        fit = policy.Target(env.python, self.host or policy.Host.current())
        if not request.requirements:
            raise RefusedError(
                f"name at least one package: ssc-guardian install --venv {venv} NAME[==VERSION]",
                site="install.name-least-one-package-ssc",
            )
        for requirement in request.requirements:
            text = _requirement_text(requirement)
            why = refusal(text)
            if why is not None:  # the second gate: the command line's own gate let it through
                collector.findings.append(
                    Finding(
                        Rule.MALFORMED_NAME,
                        PYPI,
                        place=venv if matches(Field.PATH, venv) else None,
                        malformed_field=FindingField.ITEM,
                        malformed_value=text,
                        site="install.second-gate-malformed",
                    )
                )
                _say(err, [f"{text}: {why}."])
                return None
        wanted, twice = _one_each(request.requirements)
        if twice is not None:
            collector.findings.append(
                Finding(
                    Rule.MALFORMED_NAME,
                    PYPI,
                    place=venv if matches(Field.PATH, venv) else None,
                    malformed_field=FindingField.VERSION,
                    malformed_value=twice,
                    site="install.requested-twice",
                )
            )
            _say(err, [f"{twice}: the package is requested twice, at different versions; name it once."])
            return None
        denied = [
            make_finding(
                Rule.DENY_LIST,
                PYPI,
                place=venv,
                item=r.name,
                version=r.version,
                options=(Option(OptionKind.REMOVE),),
                site="install.denied-requested",
            )
            for r in wanted
            if settings.denied(PYPI, r.name)
        ]
        if denied:
            collector.findings += denied
            _say(err, [f"{f.item} is on the deny list; it is never installed." for f in denied])
            return None

        kev = Kev(client)
        block_on = policy.BlockOn(settings.block_on.value)
        facts = policy.gather_pypi(client, [r.name for r in wanted])
        said: list[str] = []
        pins = [
            self._version(r, facts, kev, settings, today, block_on, venv, fit, roots, collector, err, said)
            for r in wanted
        ]
        if any(pin is None for pin in pins):
            return None

        cutoff = cutoff_for(today, _cooldown(settings, wanted))
        entries = read_report(runner.check(env, [pin for pin in pins if pin is not None], cutoff))
        # A requested package pip leaves in place has no entry in its report: the installed
        # version is what the request ends with, so it is checked as a planned one is (#228).
        kept, unreadable, unread = _kept(env, wanted, entries)
        collector.skipped += unreadable
        files: tuple[PlannedFile, ...] = ()
        if entries:
            more = sorted({normalize_pypi_name(e.name) for e in entries} - facts.osv.keys())
            if more:
                facts = _merged(facts, policy.gather_pypi(client, more))
            files = bind(entries, facts.projects, target=venv, endpoints=self.endpoints)

        start = len(collector.findings)
        collector.findings += [
            make_finding(
                Rule.DENY_LIST,
                PYPI,
                place=venv,
                item=f.item.name,
                version=f.item.version,
                options=(Option(OptionKind.REMOVE),),
                site="install.denied-resolved",
            )
            for f in files
            if settings.denied(PYPI, f.item.name)
        ]
        packages = [(f.item.name, f.item.version) for f in files] + kept
        failure = self._evaluate(facts, kev, packages, venv, fit, settings, today, block_on, collector)
        unfinished = _file_cooldowns(facts, files, venv, fit, settings, today, block_on, collector, err)
        failure = failure or unfinished or unread
        self._release(facts, kev, today, collector, roots, err, said)
        if failure is not None:
            raise failure
        failing = [f for f in collector.findings[start:] if f.level is Level.VIOLATION]
        if failing:
            requested = {normalize_pypi_name(r.name) for r in wanted}
            in_place = {normalize_pypi_name(name) for name, _ in kept}
            for finding in failing:
                if finding.item is not None and normalize_pypi_name(finding.item) in in_place:
                    who = "installed; pip keeps it for this request, so nothing replaces it"
                elif finding.item is not None and normalize_pypi_name(finding.item) in requested:
                    who = "requested"
                elif _names_a_version([finding]):
                    who = "a dependency pip chose for this request; install a version named below, then run again"
                else:
                    who = "a dependency pip chose for this request"
                # A malformed-name finding leaves out the value it rejects: never shown as "None".
                parts = [strip_controls(v) for v in (finding.item, finding.version) if v is not None]
                shown = " ".join(parts) or "a package"
                _say(err, [f"{shown} fails {finding.rule.value} ({who})."])
            _say(err, ["A package that fails a rule refuses the whole request; there is no second resolve."])
            return None
        return _Staged(env, InstallPlan(venv, tuple(f.item for f in files), files))

    @staticmethod
    def _release(
        facts: policy.PypiFacts,
        kev: Kev,
        today: date,
        collector: Collector,
        roots: Roots,
        err: TextIO,
        said: list[str],
    ) -> None:
        """The workstation overrides, re-checked against today's facts, as ``check --envs``
        applies them (§10.4). Every call re-reads all the findings so far, so ``said`` keeps
        the notes already printed this run: each is printed once (#89)."""
        notes: list[str] = []
        CheckEnvs(home=roots.home)._apply_overrides(facts, kev, today, collector, notes, roots)
        for note in (strip_controls(n) for n in notes):  # one line each, whatever a value in it holds
            if note not in said:
                said.append(note)
                _say(err, [note])

    def _version(
        self,
        requirement: Requirement,
        facts: policy.PypiFacts,
        kev: Kev,
        settings: Settings,
        today: date,
        block_on: policy.BlockOn,
        venv: str,
        fit: policy.Target,
        roots: Roots,
        collector: Collector,
        err: TextIO,
        said: list[str],
    ) -> str | None:
        """The requirement handed to pip: ``NAME==VERSION`` for an exact request that passes
        every rule, after the overrides; ``NAME<=VERSION`` for a loose one, VERSION the newest
        that passes every rule today and fits the venv, or the newest that passes when none
        fits. None when refused."""
        name = normalize_pypi_name(requirement.name)
        project = facts.projects.get(name)
        if project is None:
            raise FeedError(
                facts.pypi_failures.get(name, f"PyPI was not read for {name}"), site="install.pypi-not-read"
            )
        if not project.found:
            raise RefusedError(f"PyPI has no project named {requirement.name}", site="install.pypi-no-project-named")
        rules = policy.Rules(
            cooldown_days=settings.cooldown_days(PYPI, requirement.name), today=today, block_on=block_on
        )
        version = requirement.version
        if version is None:
            advisories = merge(facts.osv.get(name, ()), facts.github_malware.get(name, ()))
            # Only the venv's X.Y is known, so a file can read as no fit and still install: when
            # nothing fits, pip decides what does, and the resolved set is checked as a whole.
            for fitting in (fit, None):
                options = policy.replacements(
                    project,
                    advisories,
                    item=requirement.name,
                    current=_NO_CURRENT,
                    rules=rules,
                    venv=venv,
                    target=fitting,
                )
                ready = next((o.version for o in options if o.command is not None), None)
                if ready is not None:
                    return f"{requirement.name}<={ready}"
            # Nothing passes today: the newest release's findings say why, and name the date
            # one becomes eligible.
            released = [r for r in project.releases.values() if not r.version.is_prerelease and r.first_wheel_upload]
            if not released:
                if self._quarantined(project, requirement, venv, block_on, collector, err):
                    return None
                raise RefusedError(
                    f"PyPI has no released wheel of {requirement.name}; Guardian installs wheels only",
                    site="install.guardian-installs-wheels-only",
                )
            version = max(released, key=lambda r: r.version).version.text
        elif project.release(pep440.parse(version)) is None:
            if self._quarantined(project, requirement, venv, block_on, collector, err):
                return None
            raise RefusedError(f"PyPI has no release {version} of {requirement.name}", site="install.pypi-no-release")

        def failing() -> list[Finding]:
            return [
                f
                for f in collector.findings
                if f.level is Level.VIOLATION
                and f.item is not None
                and normalize_pypi_name(f.item) == name
                and f.version == version
            ]

        policy.evaluate_packages(
            facts,
            kev,
            [(requirement.name, version)],
            place=venv,
            venv=venv,
            rules=rules,
            into=collector.findings,
            target=fit,
        )
        failed = bool(failing())
        if failed:
            self._release(facts, kev, today, collector, roots, err, said)
        still = failing()
        if not still:
            if requirement.version is not None or failed:  # passes, or an override releases it
                return f"{requirement.name}=={version}"
            raise RefusedError(
                f"no version of {requirement.name} passes every rule and can be installed now",
                site="install.passes-every-rule-can-installed",
            )
        shown = strip_controls(version)  # from PyPI on a loose request
        if not any(f.options for f in still):  # a malformed record: no replacement was looked for
            _say(err, [f"{requirement.name}=={shown} fails a rule."])
        elif not _names_a_version(still):
            _say(err, [f"No version of {requirement.name} that passes every rule installs in this venv today."])
        elif requirement.version is not None:
            _say(err, [f"{requirement.name}=={shown} fails a rule; the version that passes is named below."])
        else:
            _say(err, [f"No version of {requirement.name} passes every rule today; see below for when one will."])
        return None

    @staticmethod
    def _quarantined(
        project: pypi.Project,
        requirement: Requirement,
        venv: str,
        block_on: policy.BlockOn,
        collector: Collector,
        err: TextIO,
    ) -> bool:
        """When the request has no version to evaluate (no released wheel, or no such release),
        a quarantined project is still a compromise (#228): its finding is recorded and True
        returned, before the "no released wheel" or "no release" refusal, so 1 wins over 2.
        PyPI lists no files for a quarantined project, so this is its usual case; a version PyPI
        does list is evaluated as any other, quarantine included."""
        finding = policy.quarantined_project(
            project, place=venv, item=requirement.name, version=requirement.version, block_on=block_on
        )
        if finding is not None:
            collector.findings.append(finding)
            _say(err, [f"PyPI has quarantined {requirement.name}; Guardian installs no version of it."])
        return finding is not None

    @staticmethod
    def _evaluate(
        facts: policy.PypiFacts,
        kev: Kev,
        packages: Sequence[tuple[str, str]],
        venv: str,
        fit: policy.Target,
        settings: Settings,
        today: date,
        block_on: policy.BlockOn,
        collector: Collector,
    ) -> IncompleteCheckError | None:
        """The feed rules for every package the request ends with (each resolved one, and each
        requested one pip keeps), each against its own cooldown; every group is evaluated before
        the first failure is returned."""
        groups: dict[int, list[tuple[str, str]]] = defaultdict(list)
        for name, version in packages:
            groups[settings.cooldown_days(PYPI, name)].append((name, version))
        failure: IncompleteCheckError | None = None
        for days, packages in sorted(groups.items()):
            rules = policy.Rules(cooldown_days=days, today=today, block_on=block_on)
            try:
                policy.evaluate_packages(
                    facts, kev, packages, place=venv, venv=venv, rules=rules, into=collector.findings, target=fit
                )
            except IncompleteCheckError as exc:
                failure = failure or exc
        return failure

    @staticmethod
    def _apply(staged: _Staged, runner: Runner, collector: Collector, err: TextIO) -> None:
        """The install step, then a read-back of the venv's records; a failure is an unfinished
        check, and the message says what, if anything, was written."""
        env, plan = staged.env, staged.plan
        before = _installed(env)
        try:
            runner.install(env, plan.files)
            after = _installed(env)
            missing = [f.item for f in plan.files if _key(f.item.name, f.item.version) not in after]
            if missing:
                names = ", ".join(f"{i.name} {i.version}" for i in missing)
                raise pinned_pip.PinnedPipError(
                    f"pip finished, but {names} is not in {env.main_site}",
                    site="install.pip-finished-but-not-installed",
                )
        except Exception as exc:  # the install is one step; report it and what it left behind
            now = _installed(env)
            written = ", ".join(_shown(n, v) for n, v in sorted(now - before)) or "nothing"
            removed = ", ".join(_shown(n, v) for n, v in sorted(before - now)) or "nothing"
            where, why = strip_controls(plan.target), strip_controls(exc)
            _say(err, [f"ssc-guardian: {where}: {why}; written: {written}; removed: {removed}."])
            collector.skipped.append(
                Skip(
                    PYPI,
                    plan.target,
                    SkipReason.CHECK_ERROR,
                    detail=f"not installed ({type(exc).__name__})",
                    site="install.not-installed",
                )
            )
            return
        installed = ", ".join(_shown(i.name, i.version) for i in plan.items)
        _say(err, [f"Installed into {strip_controls(plan.target)}: {installed}"])


# The options every feed finding carries besides a replacement, as ``policy`` gives them.
_PERSON_OPTIONS = (Option(OptionKind.REMOVE), Option(OptionKind.EXCEPTION, person_command=Verb.OVERRIDE_ADD))


def _file_cooldowns(
    facts: policy.PypiFacts,
    files: Sequence[PlannedFile],
    venv: str,
    fit: policy.Target,
    settings: Settings,
    today: date,
    block_on: policy.BlockOn,
    collector: Collector,
    err: TextIO,
) -> IncompleteCheckError | None:
    """Each bound file's own upload time against its package's own cooldown (#129).

    pip's one cutoff is the shortest cooldown in the request, and the release-level check dates
    a version by its earliest file (contracts §7, ``trusted_age``), so a wheel uploaded later
    to an old release passes both. Here the file that would install is held to its package's
    cooldown with the same ``cooldown_met`` comparison: a file inside it is a ``cooldown``
    violation for that package and version (one finding, not two, when the release is inside it
    too), so nothing installs. A file with no upload time is the ``unknown-age`` skip, never a
    pass; every file is checked before that failure is returned, so the findings are kept."""
    failure: IncompleteCheckError | None = None
    already = {_key(f.item, f.version) for f in collector.findings if f.rule is Rule.COOLDOWN and f.item and f.version}
    for planned in files:
        name, version = planned.item.name, planned.item.version
        when = uploaded(planned, facts.projects)
        shown, filename = _shown(name, version), strip_controls(_file_name(planned.url))
        if when is None:
            _say(err, [f"{shown}: PyPI gives no upload time for {filename}, so its age is unknown."])
            if failure is None:  # names the package as check's unknown-age skip does (#284)
                failure = IncompleteCheckError(
                    SkipReason.UNKNOWN_AGE, detail=_age_detail(name, version), site="install.bound-file-unknown-age"
                )
            continue
        days = settings.cooldown_days(PYPI, name)
        started = policy.cooldown_start(when)
        if policy.cooldown_met(started, days, today) or _key(name, version) in already:
            continue
        key = normalize_pypi_name(name)
        project = facts.projects.get(key)
        advisories = merge(facts.osv.get(key, ()), facts.github_malware.get(key, ()))
        rules = policy.Rules(cooldown_days=days, today=today, block_on=block_on)
        replace = (
            policy.replacements(
                project, advisories, item=name, current=pep440.parse(version), rules=rules, venv=venv, target=fit
            )
            if project is not None
            else ()
        )
        collector.findings.append(
            make_finding(
                Rule.COOLDOWN,
                PYPI,
                place=venv,
                item=name,
                version=version,
                options=replace + _PERSON_OPTIONS,
                site="install.file-cooldown",
            )
        )
        already.add(_key(name, version))
        _say(
            err,
            [
                f"{shown}: {filename}, the file pip chose, was uploaded on "
                f"{when.date().isoformat()}: inside its {days}-day cooldown, eligible on "
                f"{policy.eligible_on(started, days).isoformat()}."
            ],
        )
    return failure


def _kept(
    env: Environment, wanted: Sequence[Requirement], entries: Sequence[Reported]
) -> tuple[list[tuple[str, str]], list[Skip], RefusedError | None]:
    """Each requested package pip's report leaves out, with its installed version; the records
    that cannot be read, which the result lists; and why the check cannot finish, or None
    (#228).

    pip leaves an installed package out of its report when that version already meets the
    request and nothing better can be installed (``NAME<=V`` whose newer files do not fit the
    venv, say), so that version is what the request ends with, and it is checked as a planned
    one is. The records are read from every folder the venv's Python reads (``search_order``):
    the folders pip's check step sees, and the per-user folder, which it does not (``-I``) but
    which the venv's Python reads before its base's, so a copy there could be the one imported.
    Fail-closed: a requested name with no record there, or with more than one, or any record
    there that cannot be read, leaves the check unfinished (exit 2, nothing installed), never
    "Nothing to install"; the versions that were read are still checked, so a rule they fail
    still gives exit 1."""
    planned = {normalize_pypi_name(e.name) for e in entries}
    left = [r for r in wanted if normalize_pypi_name(r.name) not in planned]
    if not left:
        return [], [], None
    records: list[discovery.Package] = []
    problems: list[Skip] = []
    for folder in env.search_order:
        found, skips = discovery.packages(folder)
        records += found
        problems += skips
    failure: RefusedError | None = None
    if problems:
        first = problems[0]
        failure = RefusedError(
            f"a package record in {first.place} cannot be read ({first.detail}), so the installed version of "
            f"{', '.join(r.name for r in left)} cannot be told",
            site="install.kept-record-unreadable",
        )
    kept: list[tuple[str, str]] = []
    for requirement in left:
        found = [p for p in records if p.key == normalize_pypi_name(requirement.name)]
        if len(found) == 1:
            kept.append((requirement.name, found[0].version))
        elif failure is None and not found:
            failure = RefusedError(
                f"pip installs nothing for {requirement.name}, yet {env.prefix} has no record of it, so the version "
                "the request ends with cannot be told",
                site="install.kept-not-installed",
            )
        elif failure is None:
            where = "; ".join(f"{p.version} in {p.folder}" for p in found)
            failure = RefusedError(
                f"{requirement.name} is recorded {len(found)} times where {env.prefix}'s Python reads packages "
                f"({where}), so its installed version cannot be told",
                site="install.kept-recorded-twice",
            )
    return kept, problems, failure


def _one_each(requirements: Sequence[Requirement]) -> tuple[tuple[Requirement, ...], str | None]:
    """Each package once, in its first spelling (D18), and the first requirement that names a
    package already asked for at another version (a malformed request, exit 1), or None."""
    kept: dict[str, Requirement] = {}
    for requirement in requirements:
        first = kept.setdefault(normalize_pypi_name(requirement.name), requirement)
        same = first.version == requirement.version or (
            first.version is not None
            and requirement.version is not None
            and pep440.canonical(first.version) == pep440.canonical(requirement.version)
        )
        if not same:
            return tuple(kept.values()), _requirement_text(requirement)
    return tuple(kept.values()), None


def _merged(first: policy.PypiFacts, second: policy.PypiFacts) -> policy.PypiFacts:
    return policy.PypiFacts(
        {**first.osv, **second.osv},
        {**first.github_malware, **second.github_malware},
        {**first.projects, **second.projects},
        {**first.pypi_failures, **second.pypi_failures},
        first.github_failure or second.github_failure,
        first.github_rate_limit or second.github_rate_limit,
    )


def _key(name: str, version: str) -> tuple[str, str]:
    parsed = pep440.try_parse(version)
    return normalize_pypi_name(name), pep440.canonical_of(parsed) if parsed is not None else version


def _installed(env: Environment) -> set[tuple[str, str]]:
    records, _ = discovery.packages(env.main_site)
    return {_key(p.name, p.version) for p in records if matches(Field.PYPI_NAME, p.name)}


def _file_name(url: str) -> str:
    """The URL's last path segment, percent-decoded: it can hold a line break (``%0A``), so a
    message strips it as it goes in (#161)."""
    return urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])


def _age_detail(name: str, version: str) -> str | None:
    """An unknown-age skip's text-only detail: the normalized name and the version as pip gives
    it (#298, #284); None when either fails its grammar, so a malformed value is never shown."""
    if not (matches(Field.PYPI_NAME, name) and matches(Field.PEP440_VERSION, version)):
        return None
    return f"{normalize_pypi_name(name)} {version}"


def _shown(name: str, version: str) -> str:
    """``NAME VERSION`` for a message, each value stripped as it goes in (#161): both can come
    from pip's report or a venv's records."""
    return f"{strip_controls(name)} {strip_controls(version)}"


def _names_a_version(findings: Iterable[Finding]) -> bool:
    """Whether a message may point at a version: a REPLACE option always names one, with its
    command or the date it becomes eligible."""
    return any(o.kind is OptionKind.REPLACE for f in findings for o in f.options)


def _say(err: TextIO | None, lines: list[str]) -> None:
    """Each line of each message to stderr through ``cli._say``: a closed or broken stream
    never changes the exit code, even after a completed install (contracts §3)."""
    from ssc_guardian import cli  # imported here: cli imports this handler

    for line in lines:
        for part in line.splitlines() or [""]:
            cli._say(err, part)


handle = Install()
