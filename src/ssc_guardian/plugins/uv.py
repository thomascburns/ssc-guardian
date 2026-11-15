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

"""The uv plug-in: setup and reporting only (plan §1, §3.1, §8 fact 9).

Guardian writes a rolling ``exclude-newer`` window, ``exclude-newer = "P<n>D"``, at the top
level of the per-user uv config (``$XDG_CONFIG_HOME/uv/uv.toml``, else
``~/.config/uv/uv.toml``), and verifies it the way pip's is verified: a missing, weaker,
stale or overridden window fails with "run protect again". ``UV_EXCLUDE_NEWER`` overrides
the file; ``UV_CONFIG_FILE`` and ``UV_NO_CONFIG`` stop uv reading it; ``exclude-newer-package``
(or ``UV_EXCLUDE_NEWER_PACKAGE``) exempts packages from it. These are checked first, so
``protect`` never writes a window that cannot apply. A ``[pip]`` copy of the
key, which ``uv pip`` prefers, is verified and written too. uv is never run; installs go
through pip in v1.0 (N18), so the plug-in neither discovers nor installs.

``check --envs`` alone (``protect`` reads and writes only the per-user file) also reads, read
only, what uv lets beat that file (owner rulings, plan §10.4): a project's ``uv.toml`` or
``pyproject.toml`` ``[tool.uv]`` found as uv searches (:func:`find_projects`), judged by
:func:`project_problems`, and an index other than PyPI's in the user, system or project file
or in a ``UV_`` index variable (:func:`other_indexes`), since the cooldown only holds for
files from PyPI. No user setting can lock these out, so they are reported, never written.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

from ssc_guardian.discovery import Roots
from ssc_guardian.findings import Ecosystem, IncompleteCheckError, Scope, SkipReason
from ssc_guardian.plugin import (
    CodeExecution,
    CooldownSetting,
    Discovery,
    InstallPlan,
    Item,
    PluginName,
    Requirement,
    TrustedAge,
)
from ssc_guardian.plugins.pip import Verdict, fixed_date, is_pypi
from ssc_guardian.settings import ConfigFileError, atomic_write, read_text

KEY = "exclude-newer"
PACKAGE_KEY = "exclude-newer-package"  # per-package dates; Guardian's own checks hold those rules
OVERRIDING_VARIABLES = ("UV_EXCLUDE_NEWER", "UV_EXCLUDE_NEWER_PACKAGE", "UV_CONFIG_FILE", "UV_NO_CONFIG")
# uv's settings that name where packages come from (top level, and in [pip] for `uv pip`):
# `index` is a list of tables, each with its `url`; the others are a URL or a list of them.
INDEX_KEYS = ("index", "index-url", "extra-index-url", "find-links")
# uv's variables that add or replace an index (docs.astral.sh/uv/reference/environment/), and
# how each separates its values: UV_FIND_LINKS by commas, the others by spaces.
INDEX_VARIABLES = {
    "UV_DEFAULT_INDEX": None,
    "UV_EXTRA_INDEX_URL": None,
    "UV_FIND_LINKS": ",",
    "UV_INDEX": None,
    "UV_INDEX_URL": None,
}
NAMED_INDEX_VARIABLES = frozenset({"UV_INDEX", "UV_DEFAULT_INDEX"})
PROJECT_FILES = ("uv.toml", "pyproject.toml")  # in one folder, uv.toml wins (uv's own order)
_DATE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:Z|[+-][0-9]{2}:[0-9]{2}))?", re.ASCII
)
_PROGRAM_PLACES = (".local/bin/uv", ".cargo/bin/uv")
_SYSTEM_PROGRAMS = ("opt/homebrew/bin/uv", "usr/local/bin/uv")
_ISO_DAYS = re.compile(r"P([0-9]{1,5})D", re.ASCII)
_ISO_WEEKS = re.compile(r"P([0-9]{1,4})W", re.ASCII)
_FRIENDLY = re.compile(r"([0-9]{1,5}) *(days?|weeks?)", re.ASCII)
_KEY_LINE = re.compile(r"""\s*(?:exclude-newer|"exclude-newer"|'exclude-newer')\s*=""")


def config_path(roots: Roots) -> str:
    """uv's per-user config file, where uv itself looks for it."""
    xdg = roots.environ.get("XDG_CONFIG_HOME", "")
    base = xdg if xdg.startswith("/") else os.path.join(roots.home, ".config")
    return os.path.join(base, "uv", "uv.toml")


def system_paths(roots: Roots) -> tuple[str, ...]:
    """The system-level config uv reads beneath the user file, as uv finds it (``uv-dirs``):
    the first ``<dir>/uv/uv.toml`` that exists in ``XDG_CONFIG_DIRS`` (``/etc/xdg`` when unset
    or empty), else ``/etc/uv/uv.toml``; none with ``UV_NO_SYSTEM_CONFIG``."""
    if roots.environ.get("UV_NO_SYSTEM_CONFIG"):
        return ()
    dirs = [d for d in roots.environ.get("XDG_CONFIG_DIRS", "").split(os.pathsep) if d.startswith("/")]
    for folder in dirs or [roots.system("etc/xdg")]:
        candidate = os.path.join(folder, "uv", "uv.toml")
        if os.path.lexists(candidate):
            return (candidate,)
    fallback = roots.system("etc/uv/uv.toml")
    return (fallback,) if os.path.lexists(fallback) else ()


def installed(roots: Roots) -> bool:
    """Whether a ``uv`` program is on ``PATH`` or in a usual place (looked at, never run)."""
    places = [os.path.join(roots.home, p) for p in _PROGRAM_PLACES]
    places += [roots.system(p) for p in _SYSTEM_PROGRAMS]
    places += [os.path.join(d, "uv") for d in roots.environ.get("PATH", "").split(os.pathsep) if d.startswith("/")]
    return any(os.path.isfile(p) for p in places)


def parse_value(text: object, place: str) -> CooldownSetting | None:
    """A window uv accepts (ISO 8601 or friendly duration, or a date) as a setting, or None."""
    if not isinstance(text, str):
        return None
    for pattern, scale in ((_ISO_DAYS, 1), (_ISO_WEEKS, 7)):
        if match := pattern.fullmatch(text):
            return CooldownSetting(place, rolling_days=int(match.group(1)) * scale)
    if match := _FRIENDLY.fullmatch(text.strip()):
        return CooldownSetting(place, rolling_days=int(match.group(1)) * (7 if match.group(2)[0] == "w" else 1))
    if not _DATE.fullmatch(text):
        return None
    try:
        return CooldownSetting(place, fixed_date=date.fromisoformat(text[:10]))
    except ValueError:
        return None


def _document(path: str) -> dict[str, Any] | None:
    text = read_text(path)
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigFileError(path, f"is not valid TOML ({exc})", site="uv.not-valid-toml") from exc


def _pip_copy(doc: Mapping[str, Any]) -> bool:
    """Whether the file has a ``[pip]`` copy of the key (which Guardian then writes too)."""
    pip = doc.get("pip")
    return isinstance(pip, dict) and KEY in pip


def _copies(doc: Mapping[str, Any]) -> list[object]:
    """The file's values for the key: top level, and ``[pip]``, which ``uv pip`` prefers."""
    pip = doc.get("pip")
    found = [doc[KEY]] if KEY in doc else []
    return found + ([pip[KEY]] if isinstance(pip, dict) and KEY in pip else [])


@dataclass(frozen=True)
class UvAssessment:
    place: str
    verdict: Verdict
    why: str  # text output only
    current: str | None
    wanted: CooldownSetting

    @property
    def protected(self) -> bool:
        return self.verdict is Verdict.PROTECTED


def assess(roots: Roots, *, cooldown_days: int, tolerance: int, today: date) -> UvAssessment:
    place = config_path(roots)
    wanted = CooldownSetting(place, rolling_days=cooldown_days)

    def verdict(kind: Verdict, why: str, current: str | None = None) -> UvAssessment:
        return UvAssessment(place, kind, why, current, wanted)

    doc = _document(place) or {}
    copies = _copies(doc)
    shown = ", ".join(str(c) for c in copies) or None
    # Checked first, whatever the file holds: protect must never write a window that cannot apply.
    for name in OVERRIDING_VARIABLES:
        if roots.environ.get(name):
            return verdict(Verdict.OVERRIDDEN, f"{name} overrides {place}; unset it, then run protect uv again", shown)
    for where, document in ((place, doc), *((p, _document(p) or {}) for p in system_paths(roots))):
        pip_table = document.get("pip")
        if PACKAGE_KEY in document or (isinstance(pip_table, dict) and PACKAGE_KEY in pip_table):
            why = f"{where} sets {PACKAGE_KEY}, which exempts packages from the window; remove it, then run protect uv"
            return verdict(Verdict.OVERRIDDEN, why, shown)
        # A system [pip] window is the field `uv pip` prefers: the user file's top level cannot beat it.
        if where != place and isinstance(pip_table, dict) and KEY in pip_table and not _pip_copy(doc):
            why = f"{where} sets [pip] {KEY}, which uv pip prefers to {place}; remove it, then run protect uv"
            return verdict(Verdict.OVERRIDDEN, why, shown)
    if not copies:
        return verdict(Verdict.MISSING, f"{place} sets no exclude-newer window; run protect uv")
    for copy in copies:
        setting = parse_value(copy, place)
        if setting is None:
            return verdict(Verdict.UNREADABLE, f"{place} sets a window Guardian cannot read; run protect uv", shown)
        if setting.rolling_days is not None and setting.rolling_days < cooldown_days:
            why = f"{place} holds {setting.rolling_days} days, under the {cooldown_days}-day cooldown; run protect uv"
            return verdict(Verdict.WEAKER, why, shown)
        if setting.fixed_date is not None:
            newest = fixed_date(today, cooldown_days)
            if setting.fixed_date > newest:
                return verdict(Verdict.WEAKER, f"{place} accepts uploads after {newest}; run protect uv", shown)
            if (newest - setting.fixed_date).days > tolerance:
                return verdict(Verdict.STALE, f"{place} holds a date over {tolerance} days old; run protect uv", shown)
    return verdict(Verdict.PROTECTED, f"protected ({shown})", shown)


def _index_values(key: str, value: object) -> list[object]:
    """The source locations one setting names: each ``url`` of an ``index`` table (a table
    without one gives itself, which is never PyPI), else the value or each item of a list."""
    items = value if isinstance(value, list) else [value]
    if key == "index":
        return [item.get("url") if isinstance(item, dict) else item for item in items]
    return items


def index_settings(where: str, doc: Mapping[str, Any]) -> list[str]:
    """Each index setting in one uv settings table (a ``uv.toml``, or ``[tool.uv]``) that names
    anything but PyPI's own index, top level and ``[pip]``, as text naming ``where``."""
    found: list[str] = []
    pip = doc.get("pip")
    for prefix, table in (("", doc), ("[pip] ", pip if isinstance(pip, dict) else {})):
        for key in INDEX_KEYS:
            if key in table and not all(is_pypi(v) for v in _index_values(key, table[key])):
                found.append(f"{where} sets {prefix}{key}")
    return found


def _variable_values(name: str, value: str) -> list[str]:
    """The locations one ``UV_`` index variable names; in ``UV_INDEX`` and ``UV_DEFAULT_INDEX``,
    which take uv's ``NAME=URL`` index form, a named index gives its URL."""
    parts = [p for p in (q.strip() for q in value.split(INDEX_VARIABLES[name])) if p]
    if name not in NAMED_INDEX_VARIABLES:
        return parts
    return [p.split("=", 1)[1] if "=" in p.split("://", 1)[0] else p for p in parts]


def other_indexes(roots: Roots, into: list[str] | None = None) -> list[str]:
    """Where uv is given a source other than PyPI's index outside any project: the user file,
    the system file beneath it, and the ``UV_`` index variables, each as text naming the place.
    A file that cannot be read or parsed is an unfinished check, raised once every other file
    has been read; nothing is written. Each place is also added to ``into`` as it is found, so
    a caller keeps what the readable files hold when one fails."""
    found = into if into is not None else []
    failure: ConfigFileError | RecursionError | None = None
    for where in (config_path(roots), *system_paths(roots)):
        try:  # every file is read, so one that fails never hides the next
            found += index_settings(where, _document(where) or {})
        except (ConfigFileError, RecursionError) as exc:  # RecursionError: tomllib on a deeply nested file
            failure = failure or exc
    if failure is not None:
        raise failure
    return found + index_variables(roots)


def index_variables(roots: Roots) -> list[str]:
    """The ``UV_`` index variables naming anything but PyPI's index. They need no file, so a
    file that cannot be read never hides them."""
    found: list[str] = []
    for name in sorted(INDEX_VARIABLES):
        value = roots.environ.get(name)
        if value and not all(is_pypi(v) for v in _variable_values(name, value)):
            found.append(f"{name} is set")
    return found


@dataclass(frozen=True)
class Project:
    """The project configuration uv uses in a folder: the file, and its uv settings (a whole
    ``uv.toml``, or the ``[tool.uv]`` table of a ``pyproject.toml``)."""

    place: str
    settings: Mapping[str, Any]


def find_projects(
    start: str, roots: Roots, failed: list[ConfigFileError] | None = None, into: list[Project] | None = None
) -> list[Project]:
    """The project configuration uv may use for a command run in ``start``, nearest first, as
    uv searches (``FilesystemOptions::find``): ``start`` and then each parent, a ``uv.toml``
    first in each folder, else a ``pyproject.toml`` with a ``[tool.uv]`` table; one without
    that table is passed over. Inside the home folder the search stops at it (owner ruling,
    plan §10.4); uv itself goes on to ``/``, whose folders above a home only an administrator
    writes. Outside it, the search stops at ``/`` (``roots.root``).

    Fail closed where uv cannot be copied: uv passes over a ``[tool.uv]`` its own rules reject
    (an unknown key, a wrongly typed value) and uses the file further up, so a
    ``pyproject.toml`` match does not end the search: every candidate up to the first
    ``uv.toml``, where uv stops even on a file it rejects, is returned and judged. A parent a
    valid ``pyproject.toml`` overrides may then be reported too; never the reverse.

    Read only. A ``uv.toml`` that cannot be read or parsed stops the search, as it stops uv,
    and is raised. A ``pyproject.toml`` that cannot be, which uv warns about and passes over,
    goes into ``failed`` (raised when no list is given) and the search goes on; the caller
    reports each one as an unfinished check. Each project is also added to ``into`` as it is
    found, so a caller judges what was found before the search failed. Workspaces are not
    followed."""
    stops = {os.path.realpath(roots.home), os.path.realpath(roots.root)}
    folder = os.path.realpath(start)
    found = into if into is not None else []
    while True:
        for name in PROJECT_FILES:
            place = os.path.join(folder, name)
            try:
                try:
                    doc = _document(place)
                except RecursionError as exc:  # tomllib on a deeply nested file; uv.toml stops the search
                    if name == "uv.toml":
                        raise
                    raise ConfigFileError(
                        place, "is nested too deeply to read", site="uv.project-nested-too-deeply"
                    ) from exc
                if doc is None:
                    continue
                if name == "uv.toml":
                    found.append(Project(place, doc))  # uv stops here; pyproject.toml beside it is ignored
                    return found
                tool = doc.get("tool", {})
                table = tool.get("uv") if isinstance(tool, dict) else None
                if not isinstance(tool, dict) or (table is not None and not isinstance(table, dict)):
                    raise ConfigFileError(
                        place, "has a [tool] or [tool.uv] that is not a table", site="uv.project-tool-uv-not-table"
                    )
            except ConfigFileError as exc:
                if name == "uv.toml" or failed is None:
                    raise
                failed.append(exc)
                continue
            if table is not None:
                found.append(Project(place, table))
        parent = os.path.dirname(folder)
        if folder in stops or parent == folder:
            return found
        folder = parent


def project_problems(project: Project, *, cooldown_days: int, today: date) -> list[str]:
    """What in a project's uv settings leaves uv unprotected there, each as text naming the
    file; none when it is safe. The user file's rules apply (plan §3.1): a window weaker than
    the cooldown or a date after it, a value Guardian cannot read (a removed window), and
    ``exclude-newer-package``, top level or ``[pip]``, plus any index other than PyPI's. A
    window equal to or stricter than the cooldown passes, an older fixed date included: it
    does not go stale here, because nothing Guardian writes refreshes it."""
    place, settings = project.place, project.settings
    found: list[str] = []
    pip_table = settings.get("pip")
    if PACKAGE_KEY in settings or (isinstance(pip_table, dict) and PACKAGE_KEY in pip_table):
        found.append(f"{place} sets {PACKAGE_KEY}, which exempts packages from the window")
    for copy in _copies(settings):
        setting = parse_value(copy, place)
        if setting is None:
            found.append(f"{place} sets an {KEY} Guardian cannot read, in place of the user window")
        elif setting.rolling_days is not None and setting.rolling_days < cooldown_days:
            found.append(f"{place} holds {setting.rolling_days} days, under the {cooldown_days}-day cooldown")
        elif setting.fixed_date is not None and setting.fixed_date > fixed_date(today, cooldown_days):
            found.append(f"{place} accepts uploads after {fixed_date(today, cooldown_days)}")
    found += [f"{text}, an index other than PyPI's" for text in index_settings(place, settings)]
    return found


def project_line(cooldown_days: int) -> str:
    """The line for a project's ``pyproject.toml``, which takes precedence over the user file."""
    return f'[tool.uv]\n{KEY} = "P{cooldown_days}D"'


def with_value(text: str, value: str) -> str:
    """``text`` with the top-level window, and any ``[pip]`` copy, set to ``value``; a
    top-level line is added at the top when there is none. Everything else is kept."""
    quoted = f'{KEY} = "{value}"\n'
    lines = text.splitlines(keepends=True)
    section: str | None = None
    top_set = False
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("[["):
            section = stripped.strip("[] ")
        elif stripped.startswith("[["):
            section = "array"
        if _KEY_LINE.match(line) and section in (None, "pip"):
            out.append(quoted)
            top_set = top_set or section is None
            continue
        out.append(line)
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    return "".join(out if top_set else [quoted, *out])


def _without_key(doc: Mapping[str, Any]) -> dict[str, Any]:
    trimmed = {k: v for k, v in doc.items() if k != KEY}
    if isinstance(trimmed.get("pip"), dict):
        trimmed["pip"] = {k: v for k, v in trimmed["pip"].items() if k != KEY}
    return trimmed


class UvPlugin:
    """uv: cooldown setup and reporting only (N18)."""

    name = PluginName.UV
    ecosystem = Ecosystem.PYPI
    code_execution = CodeExecution.NEVER  # Guardian never installs through uv

    def discover(self, scope: Scope) -> Discovery:
        raise IncompleteCheckError(
            SkipReason.NOT_AVAILABLE, site="uv.discover-not-available"
        )  # pip's discovery covers uv's environments

    def trusted_age(self, item: Item) -> TrustedAge:
        raise IncompleteCheckError(SkipReason.NOT_AVAILABLE, site="uv.trusted-age-not-available")

    def plan_install(self, target: str, requirements: tuple[Requirement, ...]) -> InstallPlan:
        raise IncompleteCheckError(
            SkipReason.NOT_AVAILABLE, site="uv.plan-install-not-available"
        )  # uv does not install in v1.0

    def apply(self, plan: InstallPlan) -> None:
        raise IncompleteCheckError(SkipReason.NOT_AVAILABLE, site="uv.apply-not-available")

    def installer_cooldown(self, place: str) -> CooldownSetting:
        """The top-level window in the uv config at ``place``; no value when it sets none."""
        doc = _document(place) or {}
        if KEY not in doc:
            return CooldownSetting(place)
        setting = parse_value(doc[KEY], place)
        if setting is None:
            raise ConfigFileError(
                place, f"{KEY} is in a form Guardian cannot read", site="uv.form-guardian-cannot-read"
            )
        return setting

    def write_cooldown(self, setting: CooldownSetting) -> None:
        """Write the rolling window into the uv config, keeping everything else, atomically.
        The new text is read back first; a file that is not valid TOML is never rewritten."""
        if setting.rolling_days is None:
            raise ValueError("uv gets the rolling window; a setting with no value would remove the cooldown")
        value = f"P{setting.rolling_days}D"
        target = os.path.realpath(setting.place)  # a symlinked uv.toml (dotfiles) stays a link
        before = _document(target) or {}
        text = with_value(read_text(target) or "", value)
        try:
            after = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigFileError(setting.place, "the new text did not read back", site="uv.new-text-not-toml") from exc
        if _without_key(after) != _without_key(before) or any(c != value for c in _copies(after)) or KEY not in after:
            raise ConfigFileError(
                setting.place,
                "the new text did not read back as written; edit it by hand",
                site="uv.new-text-did-not-read-back",
            )
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        atomic_write(target, text)
