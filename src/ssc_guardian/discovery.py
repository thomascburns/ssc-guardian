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

"""The Python environments at or under the paths a command names, found by reading files only
(plan §1, §3.1, §2.3).

What is read is decided only by the named paths (``--path``, owner's rulings of 2026-11-13,
#255): nothing is looked for outside them. The walk lists only folders reached from a named
path; it follows symlinked folders there as it always did, and an environment it reaches that
resolves outside every named path is an unfinished check where it was reached, never read. A
named path that holds a venv is that venv; one that is a base installation's ``sys.prefix`` is
that installation, and is walked too; a named folder is walked for venvs and for base
installations (a Homebrew keg under a named Cellar folder). Base installations under a named path are
found in the usual places (python.org's framework, Homebrew's Python, Apple's Python, pyenv,
uv-managed Pythons), and through interpreters in the ``PATH`` folders at or under a named
path (a venv's own ``bin`` there names that venv, not a base installation). Each one's
package folders in its search order: per-user before main, as ``site.py`` adds them; a venv's
own folder first, then, when ``pyvenv.cfg`` lets it see them, the per-user folder and its
base's main folder. A named path that does not exist, cannot be read or holds no environment
is never a pass: the first two are unfinished checks there, and the
command reports the third (``Survey.empty``).

No interpreter, pip or script found here is ever run (#233): the Python version comes from
the ``lib/pythonX.Y`` folder that holds the standard library, and each package from its
``dist-info`` or ``egg-info`` record. Places are named with their symlinks resolved, as the
core does for path arguments (D18). A folder that cannot be read, or is reached through a
symlink to a missing one, is listed as an unfinished check, never passed over (plan §2.1); a
place whose name fails the path grammar is reported as malformed. The venv walk stops at
``MAX_VENV_DEPTH`` and at the pruned names, and a venv one level past either is listed as an
unfinished check (contracts §2).

A record's ``direct_url.json`` can claim a local install; :func:`local_install` checks the claim
against the folder it names (contracts §10.6). The record belongs to the distribution, and code
that has run can make that folder too, so a verified claim excuses only the upload age.
"""

from __future__ import annotations

import configparser
import fnmatch
import os
import re
import stat
import tomllib
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from ssc_guardian import direct_url
from ssc_guardian.direct_url import DirectUrlError, Kind, LocalInstall
from ssc_guardian.feeds import pypi
from ssc_guardian.findings import Ecosystem, Skip, SkipReason, record_site
from ssc_guardian.grammars import Field, matches, normalize_pypi_name
from ssc_guardian.settings import _dangling_link_on

PYPI = Ecosystem.PYPI
MAX_RECORD_BYTES = 1024 * 1024
MAX_VENV_DEPTH = 8
# A project file is the distribution's to write, and both parsers slow with the square of what is
# in it (1 MiB of ``a.a.a``, or of spaces in a ``setup.cfg`` line, takes about an hour). These
# limits hold the worst file measured to about two seconds; they bound one file, not a run.
MAX_PROJECT_FILE_CHARS = 64 * 1024
MAX_PROJECT_LINE_CHARS = 1024
# Folders that never hold a venv worth walking into; a venv's own tree is not walked either.
_PRUNED = frozenset({".git", "node_modules", "__pycache__", "site-packages"})  # tox and nox envs are venvs
_LIB = re.compile(r"python(3)\.([0-9]{1,3})(t?)", re.ASCII)
_PATH_PYTHON = re.compile(r"python3(?:\.[0-9]{1,3})?", re.ASCII)
_MAGIC = re.compile(r"[*?[]")  # a wildcard, as glob reads one
_DANGLING = "reached through a symlink to a missing folder"

# Where base installations live, relative to the file-system root (tests use a fake root).
# Wildcards are in whole path parts, as glob takes them.
_SYSTEM_GLOBS = (
    ("python.org", "Library/Frameworks/Python.framework/Versions/*"),
    ("homebrew", "opt/homebrew/opt/python@3*/Frameworks/Python.framework/Versions/*"),
    ("homebrew", "usr/local/opt/python@3*/Frameworks/Python.framework/Versions/*"),
    ("apple", "Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*"),
    ("apple", "Applications/Xcode*.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/*"),
)


class Source(StrEnum):
    PYTHON_ORG = "python.org"
    HOMEBREW = "homebrew"
    APPLE = "apple"
    PYENV = "pyenv"
    UV = "uv"
    PATH = "path"  # an interpreter on PATH, or a named prefix, in none of the places above
    VENV = "venv"


@dataclass(frozen=True)
class Environment:
    """One Python environment as its files describe it. Every path is resolved."""

    source: Source
    prefix: str  # sys.prefix
    python: tuple[int, int]
    main_site: str
    user_site: str | None = None  # the per-user folder, when this interpreter adds it
    base_site: str | None = None  # a venv that sees its base's packages: the base's main folder
    externally_managed: bool = False  # PEP 668 marker (Homebrew, uv-managed; §8 fact 40)
    # Apple's site.py adds /Library/Python/X.Y/site-packages after the main folder (for a venv,
    # after its base's), and pip installs there by default.
    system_site: str | None = None

    @property
    def is_venv(self) -> bool:
        return self.source is Source.VENV

    @property
    def search_order(self) -> tuple[str, ...]:
        """The package folders in the order ``site.py`` adds them: a venv's own folder before
        the per-user folder (CPython ``site.venv``), a base's per-user folder before its main."""
        venv_order = (self.main_site, self.user_site, self.base_site, self.system_site)
        order = venv_order if self.is_venv else (self.user_site, self.main_site, self.system_site)
        return tuple(dict.fromkeys(p for p in order if p is not None))

    @property
    def pip_conf(self) -> str:
        """The installation's own pip configuration file, ``sys.prefix/pip.conf``."""
        return os.path.join(self.prefix, "pip.conf")


@dataclass(frozen=True)
class Package:
    """One installed distribution, as its record names it (unchecked: the core checks it)."""

    name: str
    version: str
    folder: str
    record: str  # the record's file name inside ``folder``
    # The tags its WHEEL file claims (read by pypi.record_tags); None when it has none Guardian can read
    tags: frozenset[tuple[str, str, str]] | None = None

    @property
    def key(self) -> str:
        return normalize_pypi_name(self.name) if matches(Field.PYPI_NAME, self.name) else self.name


@dataclass
class Survey:
    """What discovery found: environments, folders it could not read, malformed places, and
    the named paths at or under which it found nothing at all (``empty``)."""

    environments: list[Environment] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)
    empty: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Roots:
    """Where to look. ``root`` stands for ``/`` and ``home`` for the home folder, so a test
    can build a whole fake Mac in a temporary folder; ``environ`` gives ``PATH`` and the
    variables that move pyenv, uv and the per-user folder."""

    home: str
    environ: Mapping[str, str]
    root: str = "/"

    def system(self, pattern: str) -> str:
        return os.path.join(self.root, pattern)


def _resolved(path: str) -> str:
    from ssc_guardian import cli  # imported here: cli imports the handlers, which import this module

    return cli._resolved("/" + os.path.abspath(path).lstrip("/"))


def _isdir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.stat(path).st_mode)
    except OSError:
        return False


def _isfile(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def _holds_file(path: str) -> bool:
    """Whether ``path`` is a regular file. A folder on the way that cannot be searched raises,
    so it is never taken for one that holds nothing."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def _lib_dirs(prefix: str, *, stdlib: bool) -> list[tuple[str, tuple[int, int]]]:
    """Each ``lib/pythonX.Y`` folder and its X.Y; with ``stdlib``, only one that holds a
    standard library (``os.py``), which a venv's does not. A prefix with no ``lib`` folder has
    none; one whose ``lib`` cannot be read, or is a symlink to a missing folder, raises."""
    lib = os.path.join(prefix, "lib")
    try:
        names = sorted(os.listdir(lib))
    except (FileNotFoundError, NotADirectoryError):
        if _dangling_link_on(lib):
            raise
        return []
    return [
        (name, (int(m.group(1)), int(m.group(2))))
        for name in names
        if (m := _LIB.fullmatch(name)) and (not stdlib or _holds_file(os.path.join(lib, name, "os.py")))
    ]


def _lib_dir(prefix: str) -> tuple[str, tuple[int, int]] | None:
    """A base installation's one standard-library folder, or None if it has not exactly one."""
    found = _lib_dirs(prefix, stdlib=True)
    return found[0] if len(found) == 1 else None


def _framework(prefix: str) -> bool:
    return "/Python.framework/Versions/" in prefix or "/Python3.framework/Versions/" in prefix


def user_site(prefix: str, lib: str, python: tuple[int, int], roots: Roots) -> str | None:
    """The per-user folder ``site.py`` adds for this interpreter, or None when it adds none
    (``PYTHONNOUSERSITE``). A framework build uses ``~/Library/Python/X.Y``; any other
    ``~/.local``; ``PYTHONUSERBASE`` moves either (CPython ``site._getuserbase``)."""
    if roots.environ.get("PYTHONNOUSERSITE"):
        return None
    framework = _framework(prefix)
    base = roots.environ.get("PYTHONUSERBASE") or (
        os.path.join(roots.home, "Library", "Python", f"{python[0]}.{python[1]}")
        if framework
        else os.path.join(roots.home, ".local")
    )
    if framework:
        return _resolved(os.path.join(base, "lib", "python", "site-packages"))
    return _resolved(os.path.join(base, "lib", lib, "site-packages"))


def _place_ok(path: str, survey: Survey) -> bool:
    if matches(Field.PATH, path):
        return True
    survey.malformed.append(path)
    return False


def is_apple(prefix: str) -> bool:
    """Apple's Python (Xcode under any name, or the Command Line Tools), wherever it was found:
    a signed bundle, which only an administrator changes."""
    return "/Python3.framework/Versions/" in prefix


def apple_system_site(prefix: str, python: tuple[int, int], roots: Roots) -> str | None:
    if not is_apple(prefix):
        return None
    return _resolved(roots.system(f"Library/Python/{python[0]}.{python[1]}/site-packages"))


def _base(prefix: str, source: Source, roots: Roots, survey: Survey) -> Environment | None:
    lib = _lib_dir(prefix)
    if lib is None or _isfile(os.path.join(prefix, "pyvenv.cfg")):
        return None
    name, python = lib
    main = _resolved(os.path.join(prefix, "lib", name, "site-packages"))
    if not (_place_ok(prefix, survey) and _place_ok(main, survey)):
        return None
    mine = user_site(prefix, name, python, roots)
    if mine is not None and not _place_ok(mine, survey):
        mine = None
    system = apple_system_site(prefix, python, roots)
    if system is not None and not _place_ok(system, survey):
        return None
    managed = _isfile(os.path.join(prefix, "lib", name, "EXTERNALLY-MANAGED"))
    source = Source.APPLE if is_apple(prefix) else source
    return Environment(source, prefix, python, main, mine, None, managed, system)


def _venv_config(prefix: str) -> dict[str, str]:
    """``pyvenv.cfg`` read the way ``site.venv`` reads it: ``key = value`` lines, keys lowered.
    Read like a package record, so a FIFO in its place cannot hang the run."""
    values: dict[str, str] = {}
    for line in _read_record(os.path.join(prefix, "pyvenv.cfg")).splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key.strip().lower()] = value.strip()
    return values


_VERSION = re.compile(r"(3)\.([0-9]{1,3})(?:\.|$)", re.ASCII)


def _base_of(home: str, python: tuple[int, int]) -> str | None:
    """The base installation's ``sys.prefix`` for a venv's ``home`` (its base's ``bin``). The
    interpreter there is resolved, never run, so ``/opt/homebrew/opt/python@3.11/bin`` leads
    to the framework folder in Homebrew's Cellar; else ``home``'s parent folder."""
    for name in (f"python{python[0]}.{python[1]}", f"python{python[0]}", "python"):
        program = os.path.realpath(os.path.join(home, name))
        if _isfile(program) and _lib_dir(prefix := os.path.dirname(os.path.dirname(program))):
            return _resolved(prefix)
    parent = _resolved(os.path.dirname(home.rstrip("/")))
    return parent if _lib_dir(parent) else None


def _not_checked(survey: Survey, place: str, detail: str) -> None:
    if _place_ok(place, survey):
        survey.skipped.append(Skip(PYPI, place, SkipReason.CHECK_ERROR, detail=detail, site="discovery.not-checked"))


def venv(prefix: str, roots: Roots, survey: Survey) -> Environment | None:
    """The venv at ``prefix`` (resolved, holding ``pyvenv.cfg``). One that cannot be read
    exactly (no ``lib/pythonX.Y``, two of them that ``pyvenv.cfg`` does not settle, a base it
    cannot find while it sees its base's packages, or a ``lib`` folder of its own or its base's
    that cannot be read) is an unfinished check, never dropped."""
    try:
        return _venv(prefix, roots, survey)
    except OSError as exc:
        _unreadable(survey, prefix, exc)
        return None


def _venv(prefix: str, roots: Roots, survey: Survey) -> Environment | None:
    config = _venv_config(prefix)
    libs = _lib_dirs(prefix, stdlib=False)
    stated = _VERSION.match(config.get("version_info") or config.get("version") or "")
    if len(libs) > 1 and stated:
        libs = [lib for lib in libs if lib[1] == (int(stated.group(1)), int(stated.group(2)))]
    if len(libs) != 1:
        _not_checked(survey, prefix, "venv with no single lib/pythonX.Y folder")
        return None
    name, python = libs[0]
    main = _resolved(os.path.join(prefix, "lib", name, "site-packages"))
    if not (_place_ok(prefix, survey) and _place_ok(main, survey)):
        return None
    # site.venv: a missing key means "true", as Python reads it.
    if config.get("include-system-site-packages", "true").lower() != "true":
        return Environment(Source.VENV, prefix, python, main)
    home = config.get("home", "")
    base_prefix = _base_of(home, python) if home.startswith("/") else None
    base_lib = _lib_dir(base_prefix) if base_prefix else None
    if base_prefix is None or base_lib is None:
        _not_checked(survey, prefix, "venv sees its base's packages, but its base was not found")
        return None
    base_site = _resolved(os.path.join(base_prefix, "lib", base_lib[0], "site-packages"))
    mine = user_site(base_prefix, base_lib[0], base_lib[1], roots)
    system = apple_system_site(base_prefix, base_lib[1], roots)
    for path in (mine, base_site, system):
        if path is not None and not _place_ok(path, survey):
            return None
    return Environment(Source.VENV, prefix, python, main, mine, base_site, system_site=system)


def _names(folder: str, survey: Survey) -> list[str]:
    """The names in ``folder``, sorted. A folder that does not exist holds none; one that
    cannot be listed, or is reached through a symlink to a missing one, is an unfinished check."""
    try:
        return sorted(os.listdir(folder))
    except (FileNotFoundError, NotADirectoryError):
        if _dangling_link_on(folder):
            _not_checked(survey, _resolved(folder), _DANGLING)
    except OSError as exc:
        _unreadable(survey, _resolved(folder), exc)
    return []


def _at_or_under(place: str, wanted: Iterable[str]) -> bool:
    return any(_under(place, top) for top in wanted)


def _matching(base: str, pattern: str, wanted: tuple[str, ...], survey: Survey) -> list[str]:
    """The places under the folder ``base`` that ``pattern`` matches, as ``glob`` matches them
    (a hidden name only for a part that starts with ``.``), kept only at or under a named path.
    A folder is listed only when it is at or under one; above one, the match follows the named
    path's own next part and lists nothing, so no folder outside the named paths is read. A
    folder on the way that cannot be listed is an unfinished check, never "nothing here"."""
    places = [base]
    for part in pattern.split("/"):
        following: list[str] = []
        for place in places:
            if _at_or_under(place, wanted):
                if not _MAGIC.search(part):
                    following.append(os.path.join(place, part))
                    continue
                names = fnmatch.filter(_names(place, survey), part)
            else:  # above a named path, or beside every one: follow only the named paths
                top_of = place.rstrip("/") + "/"
                names = [top[len(top_of) :].split("/")[0] for top in wanted if top.startswith(top_of)]
                names = [name for name in dict.fromkeys(names) if fnmatch.fnmatch(name, part)]
            following += [
                os.path.join(place, name) for name in names if part.startswith(".") or not name.startswith(".")
            ]
        places = list(dict.fromkeys(following))
    return [place for place in places if _at_or_under(place, wanted)]


def _venv_home(prefix: str) -> str | None:
    """The ``home`` (its base's ``bin``) in the ``pyvenv.cfg`` of the venv at ``prefix``, or None
    when there is none, the file cannot be read or the value is no path (a NUL byte, which
    ``realpath`` refuses with ``ValueError``)."""
    try:
        home = _venv_config(prefix).get("home", "")
    except OSError:
        return None
    return home if home.startswith("/") and "\x00" not in home else None


def _candidates(roots: Roots, wanted: tuple[str, ...], survey: Survey) -> list[tuple[Source, str, str]]:
    """Each place at or under a named path where a base installation may be: its source, the
    place, and where it was found (a ``PATH`` entry's program; else the place itself)."""
    found = [
        (Source(source), path, path)
        for source, pattern in _SYSTEM_GLOBS
        for path in _matching(_resolved(roots.root), pattern, wanted, survey)
    ]
    pyenv = roots.environ.get("PYENV_ROOT") or os.path.join(roots.home, ".pyenv")
    versions = _resolved(os.path.join(pyenv, "versions"))
    found += [(Source.PYENV, path, path) for path in _matching(versions, "*", wanted, survey)]
    data = roots.environ.get("XDG_DATA_HOME", "")
    data = data if data.startswith("/") else os.path.join(roots.home, ".local", "share")
    uv = _resolved(roots.environ.get("UV_PYTHON_INSTALL_DIR") or os.path.join(data, "uv", "python"))
    found += [(Source.UV, path, path) for path in _matching(uv, "*", wanted, survey)]
    for folder in roots.environ.get("PATH", "").split(os.pathsep):
        if not folder.startswith("/") or not _at_or_under(folder, wanted):  # never list a PATH folder elsewhere
            continue
        # A venv's own bin (an activated venv) names that venv, not a base installation (#301):
        # the venv is the candidate, and an interpreter there that is its base's (the one of
        # that name in pyvenv.cfg's home) only when that base is at or under a named path too.
        # Any other interpreter there is handled as before. Only a pyvenv.cfg that is, links
        # resolved, at or under a named path counts, and it is read, nothing is run; a parent
        # that cannot be searched or a pyvenv.cfg that is outside or cannot be read drops nothing.
        here = _resolved(folder)
        config = os.path.join(os.path.dirname(here), "pyvenv.cfg")
        home = None
        if os.path.basename(here) == "bin" and os.path.lexists(config) and _at_or_under(_resolved(config), wanted):
            found.append((Source.PATH, os.path.dirname(here), folder))
            home = _venv_home(os.path.dirname(here))
        for name in _names(folder, survey):
            if _PATH_PYTHON.fullmatch(name):
                # The program is never run: its resolved place names the installation.
                program = os.path.realpath(os.path.join(folder, name))
                if os.path.basename(os.path.dirname(program)) == "bin":
                    prefix = os.path.dirname(os.path.dirname(program))
                    base = home is not None and real_place(os.path.join(home, os.path.basename(program))) == program
                    if base and not _at_or_under(_resolved(prefix), wanted):
                        continue  # the venv's own base, which no named path names
                    found.append((Source.PATH, prefix, os.path.join(folder, name)))
    # A known place names its source; PATH only adds what none of them holds.
    return sorted(found, key=lambda entry: (entry[0] is Source.PATH, entry[1]))


def base_installations(roots: Roots, survey: Survey, wanted: tuple[str, ...]) -> None:
    """Add every base installation at or under a named path once, by its resolved
    ``sys.prefix``; a place found there that is a venv (one on ``PATH``, a pyenv-virtualenv
    venv) is added as a venv. A place that cannot be looked at, or is a symlink to a missing
    folder, is an unfinished check. One found under a named path whose prefix resolves outside
    every named path is an unfinished check where it was found, never read and never passed over."""
    seen = {env.prefix for env in survey.environments}
    for source, path, shown in _candidates(roots, wanted, survey):
        prefix = _resolved(path)
        if prefix in seen:
            continue
        if not _at_or_under(prefix, wanted):
            _not_checked(survey, shown, f"resolves outside the named paths, to {prefix}")
            continue
        try:
            if not stat.S_ISDIR(os.stat(prefix).st_mode):
                continue
        except (FileNotFoundError, NotADirectoryError):
            if _dangling_link_on(path):
                _not_checked(survey, prefix, _DANGLING)
            continue
        except OSError as exc:
            _unreadable(survey, prefix, exc)
            continue
        try:
            if os.path.lexists(os.path.join(prefix, "pyvenv.cfg")):
                env = venv(prefix, roots, survey)
            else:
                env = _base(prefix, source, roots, survey)
        except (OSError, ValueError) as exc:
            _unreadable(survey, prefix, exc)
            continue
        if env is not None:
            seen.add(env.prefix)
            survey.environments.append(env)


def _unreadable(survey: Survey, place: str, exc: BaseException) -> None:
    _not_checked(survey, place, f"unreadable ({type(exc).__name__})")


def venvs(paths: Iterable[str], roots: Roots, survey: Survey, named: Iterable[str] = ()) -> None:
    """Add every venv under the named folders ``paths`` (a folder holding ``pyvenv.cfg``),
    walking at most ``MAX_VENV_DEPTH`` levels, following symlinked folders, never into a venv or
    a pruned name. One look, never a walk, goes a level further: a venv one level past the
    limit, or directly inside a pruned folder, that no other route checks is listed as an
    unfinished check. ``survey`` has already looked at each named path itself.

    ``named`` is every path the command names (``paths`` and, say, a named venv, which is not
    walked); a place at or under one of them is inside. The walk tracks for each folder whether
    it is inside a named path, by its resolved place or through an inside ancestor, and how it is
    spelled there. A venv or unreadable folder reached inside one that resolves outside every
    named path is listed as an unfinished check where it was reached (contracts §7), never read
    and never passed over. A folder is walked again only from a shallower depth than before,
    inside or outside the named paths, so link loops end and a longer route reached first hides
    nothing."""
    tops = tuple(paths)
    wanted = tuple(dict.fromkeys((*tops, *named)))
    seen = {env.prefix for env in survey.environments}

    def in_scope(place: str) -> bool:
        return _at_or_under(place, wanted)

    def outside(resolved: str, shown: str | None) -> None:
        if shown is not None and not in_scope(resolved):
            _not_checked(survey, shown, f"resolves outside the named paths, to {resolved}")

    def add(prefix: str, shown: str | None) -> None:
        outside(prefix, shown)
        if prefix in seen or not in_scope(prefix):  # a venv outside the named paths is never read
            return
        seen.add(prefix)
        try:
            env = venv(prefix, roots, survey)
        except (OSError, ValueError) as exc:
            _unreadable(survey, prefix, exc)
            return
        if env is not None:
            survey.environments.append(env)

    def add_base(here: str, shown: str | None) -> None:
        """A base installation the walk reaches (a Homebrew keg under a named Cellar folder):
        added once by its resolved prefix; one that resolves outside is unfinished where it
        was reached, and one whose ``lib`` cannot be read is unfinished at its folder."""
        try:
            prefix = _walked_base(here)
            if prefix is None:
                return
            outside(prefix, shown)
            if prefix in seen or not in_scope(prefix):
                return
            seen.add(prefix)
            env = _base(prefix, _source_of(prefix), roots, survey)
        except (OSError, ValueError) as exc:
            _unreadable(survey, _resolved(here), exc)
            return
        if env is not None:
            survey.environments.append(env)

    past: dict[str, str] = {}  # a venv the walk did not reach -> why

    for top in tops:
        depth0 = top.rstrip("/").count("/")
        visited: dict[tuple[int, int, bool], int] = {}  # each folder -> the shallowest depth walked
        resolved_top = _resolved(top)
        # Each walked folder -> its spelling inside a named path, or None when outside.
        shown: dict[str, str | None] = {top: resolved_top if in_scope(resolved_top) else None}

        def unreadable(where: str, exc: OSError, shown: dict[str, str | None] = shown) -> None:
            resolved = _resolved(where)
            outside(resolved, shown.get(where))
            if in_scope(resolved):
                _unreadable(survey, resolved, exc)

        def failed(exc: OSError, top: str = top, unreadable: Callable[[str, OSError], None] = unreadable) -> None:
            unreadable(exc.filename or top, exc)

        def spelled(child: str, parent: str | None, name: str) -> str | None:
            """``child``'s spelling inside a named path, or None when it is outside."""
            resolved = _resolved(child)
            if in_scope(resolved):
                return resolved
            return os.path.join(parent, name) if parent is not None else None

        def look(folder: str, names: Iterable[str], why: str, shown: dict[str, str | None] = shown) -> None:
            """Each folder in ``names`` inside ``folder`` that holds ``pyvenv.cfg``: one look,
            never walked, listed as unfinished unless another route checks it."""
            for name in names:
                child = os.path.join(folder, name)
                if os.path.lexists(os.path.join(child, "pyvenv.cfg")):
                    resolved = _resolved(child)
                    outside(resolved, spelled(child, shown.get(folder), name))
                    if in_scope(resolved):
                        past.setdefault(resolved, why)

        for here, dirs, files in os.walk(top, onerror=failed, followlinks=True):
            if "pyvenv.cfg" in files:  # before the visited check: every place it is reached counts
                dirs[:] = []
                add(_resolved(here), shown.get(here))
                continue
            try:
                info = os.stat(here)
            except OSError as exc:
                unreadable(here, exc)
                dirs[:] = []
                continue
            # A folder is walked again only from a strictly shallower depth, so a longer route
            # reached first never hides what a shorter one finds; the recorded depth only goes
            # down, so link loops end, and each folder is walked at most MAX_VENV_DEPTH times
            # inside the named paths and as many outside.
            depth = here.count("/") - depth0
            if depth >= MAX_VENV_DEPTH:
                look(here, sorted(dirs), "past the walk limit")
                dirs[:] = []
                continue
            key = (info.st_dev, info.st_ino, shown.get(here) is not None)
            if visited.get(key, MAX_VENV_DEPTH) <= depth:
                dirs[:] = []
                continue
            visited[key] = depth
            if "lib" in dirs:  # one look for a standard library: a base installation found by the walk
                add_base(here, shown.get(here))
            for name in sorted(d for d in dirs if d in _PRUNED):
                pruned = os.path.join(here, name)
                shown[pruned] = spelled(pruned, shown.get(here), name)
                try:
                    inside = sorted(os.listdir(pruned))
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    unreadable(pruned, exc)
                    continue
                look(pruned, inside, f"under a pruned folder name ({name})")
            dirs[:] = sorted(d for d in dirs if d not in _PRUNED)
            for name in dirs:
                child = os.path.join(here, name)
                shown[child] = spelled(child, shown.get(here), name)

    for place, why in past.items():
        if place not in seen:  # a shorter route checked it
            _not_checked(survey, place, why)


NO_SUCH_PATH = "the named path does not exist"
NO_ENVIRONMENT = "no Python environment at or under the named path"


def _named(place: str, roots: Roots, survey: Survey) -> bool:
    """Look at one named path: a venv or a base installation's prefix is added; a path that
    does not exist, is behind a dangling link or cannot be looked at is an unfinished check
    there. True when it is a folder to walk for venvs: every folder but a venv, whose own tree
    is never walked, so a venv inside a named base installation (pyenv's ``envs``) is found."""
    try:
        info = os.stat(place)
    except FileNotFoundError:
        _not_checked(survey, place, _DANGLING if _dangling_link_on(place) else NO_SUCH_PATH)
        return False
    except OSError as exc:
        _unreadable(survey, place, exc)
        return False
    if not stat.S_ISDIR(info.st_mode):
        return False  # a file holds no environment; the command decides whether it reads it
    found = {env.prefix: env for env in survey.environments}
    if place in found:
        return not found[place].is_venv
    try:
        if os.path.lexists(os.path.join(place, "pyvenv.cfg")):
            env = venv(place, roots, survey)  # a venv's own tree is never walked
            survey.environments += [env] if env is not None else []
            return False
        env = _base(place, _source_of(place), roots, survey)
    except (OSError, ValueError) as exc:  # a lib folder that cannot be read: unknown, never walked as empty
        _unreadable(survey, place, exc)
        return False
    if env is not None:
        survey.environments.append(env)
    return True


def _source_of(prefix: str) -> Source:
    """The source a base installation's resolved ``sys.prefix`` names, for one found by being
    named or walked rather than in its usual place (Apple's is settled by ``_base``)."""
    for mark, source in (
        ("/Cellar/python@", Source.HOMEBREW),
        ("/.pyenv/versions/", Source.PYENV),
        ("/uv/python/", Source.UV),
        ("/Python.framework/Versions/", Source.PYTHON_ORG),
    ):
        if mark in prefix:
            return source
    return Source.PATH


def _walked_base(folder: str) -> str | None:
    """The resolved ``sys.prefix`` of the base installation whose standard library ``folder``
    holds (``lib/pythonX.Y/os.py``, no ``pyvenv.cfg``), or None: named through its real
    ``lib/pythonX.Y``, so a Homebrew keg and its framework folder are one installation. A link
    there that cannot be resolved raises, so the folder is an unfinished check."""
    lib = _lib_dir(folder)
    if lib is None or os.path.lexists(os.path.join(folder, "pyvenv.cfg")):
        return None
    real = real_place(os.path.join(folder, "lib", lib[0]))
    if real is None:  # realpath could not follow the link: unknown, never "not a base" (real_place)
        raise OSError("the standard library folder's symlinks cannot be resolved")
    return _resolved(os.path.dirname(os.path.dirname(real)))


def survey(roots: Roots, paths: Iterable[str]) -> Survey:
    """The environments at or under the named paths ``paths`` (``--path``, each already
    resolved and grammar-checked by the command line), and nothing else: the base
    installations in the usual places under them, each named path that is itself an
    environment, and the venvs and base installations the walk of each named folder reaches.
    Nothing is looked for outside the named paths (a symlinked folder under one is followed, and
    what it leads to outside them is unfinished, never read). ``Survey.empty`` lists each named
    path at or under which nothing was found and nothing failed. A survey with no named path is
    refused: there is no default scope."""
    wanted = tuple(dict.fromkeys(paths))
    if not wanted:
        raise ValueError("discovery reads only named paths, and none was named")
    found = Survey()
    base_installations(roots, found, wanted)
    walk = [place for place in wanted if _named(place, roots, found)]
    venvs(walk, roots, found, wanted)
    # Nothing found is dropped: everything here was reached from a named path, so a malformed
    # folder a named environment depends on (its base's, its per-user one) is reported wherever
    # it is, and never hides that environment (#255 review).
    found.skipped = list(dict.fromkeys(found.skipped))  # one folder reached through two links
    found.malformed = list(dict.fromkeys(found.malformed))
    reported = [e.prefix for e in found.environments] + [s.place for s in found.skipped if s.place] + found.malformed
    found.empty = [top for top in wanted if not any(_under(place, top) for place in reported)]
    return found


def holding(paths: Iterable[str], place: str) -> list[str]:
    """The named paths that are ``place`` or a folder above it: a command reads or writes a file
    of its own (uv's user config) only when one of its arguments names it. The file is judged
    where it is read (its folder's symlinks resolved) and, when it is a symlink, where it leads,
    since the command line resolves a path that names the file itself. Whether what it leads to
    is inside the named paths is :func:`resolves_outside`'s question."""
    where = os.path.join(_resolved(os.path.dirname(place)), os.path.basename(place))
    spellings = {where, _resolved(place)}
    return [top for top in dict.fromkeys(paths) if any(_under(s, top) for s in spellings)]


def resolves_outside(paths: Iterable[str], place: str) -> str | None:
    """Where ``place`` really is when that is outside every named path (a dotfiles symlink),
    else None: such a file is an unfinished check where it was named, never read or written,
    as the venv walk treats a place that resolves outside (#255 review)."""
    resolved = _resolved(place)
    return None if _at_or_under(resolved, tuple(paths)) else resolved


def _under(place: str, top: str) -> bool:
    return place == top or place.startswith(top.rstrip("/") + "/")


# --- package records ----------------------------------------------------------------


def _read_record(path: str) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)  # a FIFO in a record's place cannot hang the run
    try:
        file = os.fdopen(fd, "rb")
    except OSError:  # a folder in its place: fdopen raises and leaves the descriptor open
        os.close(fd)
        raise
    with file as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError("not a regular file")
        return handle.read(MAX_RECORD_BYTES).decode("utf-8", errors="replace")


def _headers(text: str) -> dict[str, str]:
    """The ``Name`` and ``Version`` headers of a core-metadata file (the part before the body)."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        if sep and key in ("Name", "Version") and key not in found:
            found[key] = value.strip()
    return found


def packages(folder: str) -> tuple[list[Package], list[Skip]]:
    """The distributions recorded in ``folder``, sorted by record name. A missing folder holds
    none; one reached through a symlink to a missing folder, or a record that cannot be read or
    names no name or version, is an unfinished check at ``folder``, never dropped silently."""
    try:
        names = sorted(os.listdir(folder))
    except FileNotFoundError:
        if _dangling_link_on(folder):
            return [], [Skip(PYPI, folder, SkipReason.CHECK_ERROR, detail=_DANGLING, site="discovery.dangling-link")]
        return [], []
    except OSError as exc:
        return [], [
            Skip(
                PYPI,
                folder,
                SkipReason.CHECK_ERROR,
                detail=f"unreadable ({type(exc).__name__})",
                site="discovery.unreadable-folder",
            )
        ]
    found: list[Package] = []
    problems: list[Skip] = []
    for name in names:
        if name.endswith(".dist-info"):
            path = os.path.join(folder, name, "METADATA")
        elif name.endswith(".egg-info"):
            entry = os.path.join(folder, name)
            path = os.path.join(entry, "PKG-INFO") if _isdir(entry) else entry
        else:
            continue
        try:
            headers = _headers(_read_record(path))
        except OSError as exc:
            problems.append(
                Skip(
                    PYPI,
                    folder,
                    SkipReason.CHECK_ERROR,
                    detail=f"{name}: {type(exc).__name__}",
                    site="discovery.unreadable-record",
                )
            )
            continue
        if "Name" not in headers or "Version" not in headers:
            problems.append(
                Skip(
                    PYPI,
                    folder,
                    SkipReason.CHECK_ERROR,
                    detail=f"{name}: no name or version",
                    site="discovery.record-no-name-or-version",
                )
            )
            continue
        tags = _wheel_tags(os.path.join(folder, name)) if name.endswith(".dist-info") else None
        found.append(Package(headers["Name"], headers["Version"], folder, name, tags))
    return found, problems


def _wheel_tags(record: str) -> frozenset[tuple[str, str, str]] | None:
    """The tags a ``.dist-info`` record's ``WHEEL`` file claims, or None when it has no such file,
    it cannot be read, or its tags cannot: the check then dates the package without them, never
    as older (#230)."""
    try:
        text = _read_record(os.path.join(record, "WHEEL"))
    except OSError:
        return None
    values = []
    for line in text.splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        if sep and key == "Tag":
            values.append(value)
    return pypi.record_tags(values)


# --- local installs -----------------------------------------------------------------


class LocalInstallRefusedError(Exception):
    """A record's local-install claim failed verification. The message names the step, in
    fixed text, never the claim's content."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


def local_install(package: Package, outside: Collection[str]) -> LocalInstall | None:
    """The verified local install ``package``'s ``direct_url.json`` claims, or None when it
    makes no such claim (no file, or a VCS or archive install). ``outside`` holds the resolved
    environment prefixes and package folders of the run.

    Raises :class:`LocalInstallRefusedError` unless all four steps hold: the file is PEP 610 data
    with ``dir_info`` and a local folder; that folder exists; it is not in ``outside`` or
    inside one of them; and a project file there names the distribution (contracts §10.6).
    """
    try:
        text = direct_url.read(os.path.join(package.folder, package.record))
        claim = None if text is None else direct_url.parse(text)
    except DirectUrlError as exc:
        raise LocalInstallRefusedError(
            f"the file could not be read: {exc}", site="discovery.file-could-not-read"
        ) from exc
    if claim is None or claim.kind is not Kind.DIR:
        return None
    if claim.local_folder is None:
        raise LocalInstallRefusedError(
            "its URL is not an absolute file:// path", site="discovery.url-not-absolute-file-path"
        )
    folder = real_place(claim.local_folder)
    if folder is None or not os.path.isdir(folder):
        raise LocalInstallRefusedError("the path it names is not a folder", site="discovery.path-names-not-folder")
    if _inside(folder, outside):
        raise LocalInstallRefusedError(
            "the folder it names is inside an environment of this run",
            site="discovery.folder-names-inside-environment-run",
        )
    if package.key not in _project_names(folder):
        raise LocalInstallRefusedError(
            "no project file in the folder names the distribution", site="discovery.no-project-file-folder-names"
        )
    return LocalInstall(folder, claim.editable)


def real_place(path: str) -> str | None:
    """``path`` with its symlinks resolved, or None when ``realpath`` cannot do it: before Python
    3.13 it recurses once per link of a chain and raises on a link it may not read (macOS honours
    a link's own mode). A path on disk can be either, and neither may end a check."""
    try:
        return os.path.realpath(path)
    except (OSError, RecursionError):
        return None


def _inside(folder: str, tops: Collection[str]) -> bool:
    """Whether ``folder`` is one of ``tops`` or below one: by name, then by file identity up its
    real parents, since macOS gives one folder spellings ``realpath`` keeps (another case,
    ``/System/Volumes/Data``, ``/.vol/<device>/<inode>``). A parent that cannot be read is not
    known to be outside."""
    if any(_under(folder, top) for top in tops):
        return True
    identities = {_identity(top) for top in tops} - {None}
    path, below = folder, None
    while True:
        here = _identity(path)
        if here is None or here in identities:
            return True
        if here == below:  # the root is its own parent
            return False
        path, below = os.path.join(path, ".."), here


def _identity(path: str) -> tuple[int, int] | None:
    try:
        found = os.stat(path)
    except OSError:
        return None
    return found.st_dev, found.st_ino


def _project_names(folder: str) -> set[str]:
    """The PEP 503 names ``folder``'s project files give. A file that cannot be read or parsed,
    or a value that is not a valid name, gives none: the claim is refused, never an error."""
    found: list[object] = []
    for name, names_in in (("pyproject.toml", _pyproject_names), ("setup.cfg", _setup_cfg_names)):
        try:
            text = _read_record(os.path.join(folder, name))
        except OSError:
            continue
        if _within_project_limits(text):
            found += names_in(text)
    return {normalize_pypi_name(n) for n in found if isinstance(n, str) and matches(Field.PYPI_NAME, n)}


def _within_project_limits(text: str) -> bool:
    # Only a newline ends a line for both parsers; splitlines would also split on the U+2028 a
    # quoted TOML key can hold, so one long line would pass as many short ones.
    return len(text) <= MAX_PROJECT_FILE_CHARS and all(len(line) <= MAX_PROJECT_LINE_CHARS for line in text.split("\n"))


def _pyproject_names(text: str) -> list[object]:
    try:
        data = tomllib.loads(text)
    except (ValueError, RecursionError):  # TOMLDecodeError, a too-long integer, too deep nesting
        return []
    tool = data.get("tool")
    tables = (data.get("project"), tool.get("poetry") if isinstance(tool, dict) else None)
    return [table.get("name") for table in tables if isinstance(table, dict)]


def _setup_cfg_names(text: str) -> list[object]:
    # Raw: the plain parser raises on a "%" in the value read. No default section: its keys would
    # read as [metadata]'s own.
    parser = configparser.RawConfigParser(default_section="\x00no default section")
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    return [parser.get("metadata", "name", fallback=None)]
