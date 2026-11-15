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

"""The pip plug-in: the effective pip and its own cooldown (plan §3.1, §8 facts 1-4, 47).

**The effective pip** is the one ``python -m pip`` would load: the first pip in the
interpreter's search order (:attr:`~ssc_guardian.discovery.Environment.search_order`), read
from its ``dist-info`` record on disk and never run. Older pips behind it are reported
(``hidden-pip``).

**``pip.conf`` forms, by pip version.** Guardian writes one key, ``uploaded-prior-to``, in
``[global]`` and ``[install]`` of ``sys.prefix/pip.conf``, and never writes a form any pip
in the search order rejects (an older pip behind the loaded one runs whenever the per-user
folder is off):

- pip 26.1 and later: the rolling form ``P<n>D`` (``P21D``), which pip turns into "now minus
  n days" on every run (facts 3, 47).
- pip 26.0: a fixed datetime, ``YYYY-MM-DDT00:00:00+00:00`` (today minus the cooldown). This
  pip exits 2 on any other form, even read from a site file under ``--isolated`` (fact 2),
  so a ``P<n>D`` is never written for it. A fixed date goes stale: one older than the
  tolerance (a third of the cooldown, rounded up, at least a day; ``fixed_date_tolerance_days``
  can only lower it) fails until ``protect`` refreshes it.
- pip 25.3 and older: no such option; the key is silently ignored (fact 1). Nothing is
  written; the installation fails with "upgrade pip or exclude this installation".

**What pip reads** (fact 4, pip ``configuration.py``): global files, then the per-user files
(skipped when ``PIP_CONFIG_FILE`` names a file that exists), then ``sys.prefix/pip.conf``,
then ``PIP_CONFIG_FILE``, later files winning; ``PIP_CONFIG_FILE`` set to the null device
loads no file at all (fact 39). Within them an ``[install]`` value beats a ``[global]`` one,
and ``PIP_UPLOADED_PRIOR_TO`` beats every file. Writing both sections of the site file puts
it past every global and per-user file, so only the variable and ``PIP_CONFIG_FILE`` can
overrule it; those are checked first, and such a setting is reported as overridden, never
as protected, and never written as if the write would take effect.

**Where pip installs from** (``check --envs`` only; ``protect`` neither reads nor writes it).
The cooldown only holds for files from PyPI, so an ``index-url``, ``extra-index-url`` or
``find-links`` in a file pip reads, or exported as a ``PIP_`` variable, that names anything but
PyPI's own index is reported (:func:`other_indexes`). No user setting can lock it out: a
project or site file and a variable beat the per-user files (owner ruling, plan §10.4).
"""

from __future__ import annotations

import configparser
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum

from ssc_guardian import discovery
from ssc_guardian.discovery import Environment, Roots
from ssc_guardian.findings import Checked, Ecosystem, IncompleteCheckError, Scope, Skip, SkipReason
from ssc_guardian.pep440 import Version, parse, try_parse
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
from ssc_guardian.settings import ConfigFileError, atomic_write, read_text

KEY = "uploaded-prior-to"
ENV_FILE = "PIP_CONFIG_FILE"
ROLLING_SINCE = parse("26.1")
FIXED_SINCE = parse("26.0")
_ROLLING = re.compile(r"P([0-9]{1,5})D", re.ASCII)
_FIXED = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?", re.ASCII
)
_SECTIONS = ("global", "install")  # pip install reads [global], then its own section
# Where pip install looks for files. pip looks a key up as "--" + key, so --index-url's other
# long name, --pypi-url, sets the index too (pip cmdoptions.index_url).
INDEX_KEYS = ("index-url", "pypi-url", "extra-index-url", "find-links")
# Files pip reads on every install, whose own --index-url lines move it to another index. They
# are reported whenever set and never followed (owner ruling of 2026-11-10, plan §10.4).
FILE_KEYS = ("constraint", "requirement")


def _other_source(key: str, value: str) -> bool:
    """Whether ``key`` set to ``value`` gives pip a source other than PyPI's index: any file
    key, or an index key with a part that is not PyPI's URL (pip splits on whitespace)."""
    return key in FILE_KEYS or not all(is_pypi(part) for part in value.split())


PYPI_INDEX = frozenset({"https://pypi.org/simple", "https://pypi.org/simple/"})


def is_pypi(value: object) -> bool:
    """Whether ``value`` is PyPI's own index URL, exactly (with or without the trailing slash);
    anything else, a mirror or a value that is not a string included, is never taken as PyPI."""
    return isinstance(value, str) and value in PYPI_INDEX


class Form(StrEnum):
    ROLLING = "rolling"  # P<n>D: pip 26.1 and later
    FIXED = "fixed"  # a datetime: pip 26.0 and later


def form_for(pip_version: Version) -> Form | None:
    """The form this pip accepts, or None for a pip that ignores the setting (25.3 and older).
    A pre-release of 26.1 sorts below 26.1, so it gets the fixed form."""
    if pip_version >= ROLLING_SINCE:
        return Form.ROLLING
    if pip_version >= FIXED_SINCE:
        return Form.FIXED
    return None


def tolerance_days(cooldown_days: int, setting: int | None) -> int:
    """How old a fixed date may grow: a third of the cooldown, rounded up, at least one day;
    ``fixed_date_tolerance_days`` can only lower it (plan §3.1)."""
    computed = max(1, math.ceil(cooldown_days / 3))
    return computed if setting is None else min(computed, setting)


def fixed_date(today: date, cooldown_days: int) -> date:
    """The date a fixed-date install accepts uploads before: never later than today minus the
    cooldown."""
    return today - timedelta(days=cooldown_days)


def value_text(setting: CooldownSetting) -> str:
    """The text written for ``setting``: ``P<n>D`` or a UTC midnight datetime."""
    if setting.rolling_days is not None:
        return f"P{setting.rolling_days}D"
    if setting.fixed_date is not None:
        return f"{setting.fixed_date.isoformat()}T00:00:00+00:00"
    raise ValueError("a cooldown setting with no value would read as removing the cooldown")


def parse_value(text: str, place: str) -> CooldownSetting | None:
    """``text`` as a setting at ``place``, or None for a form Guardian cannot read (and pip
    26.0 rejects). A fixed datetime is taken at its UTC date."""
    rolling = _ROLLING.fullmatch(text)
    if rolling:
        return CooldownSetting(place, rolling_days=int(rolling.group(1)))
    if not _FIXED.fullmatch(text):  # only forms every pip 26.x parses, on Python 3.9 too
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    day = moment.astimezone(UTC).date() if moment.tzinfo is not None else moment.date()
    return CooldownSetting(place, fixed_date=day)


# --- the effective pip ----------------------------------------------------------------


@dataclass(frozen=True)
class Pip:
    version: str
    folder: str


def all_pips(env: Environment) -> list[Pip]:
    """Every pip in the interpreter's search order, first to last, from ``dist-info`` records;
    no pip is ever run."""
    found: list[Pip] = []
    for folder in env.search_order:
        records, problems = discovery.packages(folder)
        here = [Pip(p.version, folder) for p in records if p.key == "pip"]
        # Two pip records in one folder (a leftover of an interrupted install): which code is on
        # disk cannot be told from the records, so the check cannot finish.
        if problems or len(here) > 1:
            raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="pip.all-pips-check-error")
        found += here
    return found


def pips(env: Environment, found: list[Pip] | None = None) -> tuple[Pip | None, tuple[Pip, ...]]:
    """The pip ``python -m pip`` loads (the first in search order) and the older ones hidden
    behind it."""
    found = all_pips(env) if found is None else found
    if not found:
        return None, ()
    return found[0], tuple(p for p in found[1:] if _older(p, found[0]))


def _older(pip: Pip, loaded: Pip) -> bool:
    mine, theirs = try_parse(pip.version), try_parse(loaded.version)
    return mine is None or theirs is None or mine < theirs


# --- what pip reads -------------------------------------------------------------------


@dataclass(frozen=True)
class Sources:
    """The configuration pip reads besides ``sys.prefix/pip.conf`` (fact 4)."""

    global_files: tuple[str, ...]
    user_files: tuple[str, ...]
    env_file: str | None
    env_value: tuple[str, str] | None  # the variable's name and value
    index_values: tuple[tuple[str, str], ...] = ()  # each PIP_ index variable's name and value

    @classmethod
    def of(cls, roots: Roots) -> Sources:
        """pip's file places on macOS (pip ``appdirs``, its vendored ``platformdirs``): the
        system support folder, Homebrew's ``share`` and ``XDG_DATA_DIRS``; per-user the legacy
        file, then ``XDG_DATA_HOME`` or the support folder if it exists, else ``~/.config``.
        A ``PIP_`` variable matches the key as pip normalizes it (``PIP_Uploaded_Prior_To``);
        an empty one, which pip drops, does not count."""
        env = roots.environ
        data_dirs = [d for d in env.get("XDG_DATA_DIRS", "").split(os.pathsep) if d.startswith("/")]
        global_files = [
            roots.system("Library/Application Support/pip/pip.conf"),
            roots.system("opt/homebrew/share/pip/pip.conf"),
            roots.system("usr/local/share/pip/pip.conf"),
            *(os.path.join(d, "pip", "pip.conf") for d in data_dirs),
        ]
        support = os.path.join(roots.home, "Library", "Application Support", "pip")
        data_home = env.get("XDG_DATA_HOME", "")
        if data_home.startswith("/"):
            support = os.path.join(data_home, "pip")
        new_user = support if os.path.isdir(support) else os.path.join(roots.home, ".config", "pip")
        values = [(k, v) for k, v in env.items() if k.startswith("PIP_") and _normal(k[4:]) == KEY and v]
        keys = (*INDEX_KEYS, *FILE_KEYS)
        indexes = [(k, v) for k, v in env.items() if k.startswith("PIP_") and _normal(k[4:]) in keys and v]
        return cls(
            global_files=tuple(global_files),
            user_files=(os.path.join(roots.home, ".pip", "pip.conf"), os.path.join(new_user, "pip.conf")),
            env_file=env.get(ENV_FILE) or None,
            env_value=values[-1] if values else None,
            index_values=tuple(sorted(indexes)),
        )

    def files(self, site_conf: str) -> list[str]:
        """The files ``pip install`` reads for the installation whose own file is ``site_conf``,
        in pip's order (later wins): none when ``PIP_CONFIG_FILE`` is the null device; the
        per-user files are skipped when it names a file that exists. pip merges by file name,
        so a repeated one keeps its first place."""
        if self.env_file == os.devnull:
            return []
        user = () if self.env_file and os.path.exists(self.env_file) else self.user_files
        files = [*self.global_files, *user, site_conf, *([self.env_file] if self.env_file else [])]
        return list(dict.fromkeys(files))

    def outside_override(self, site_conf: str) -> str | None:
        """What would overrule ``site_conf`` (``sys.prefix/pip.conf``) whatever it holds, once
        it sets the key in ``[global]`` and ``[install]`` (later than every global and
        per-user file): the variable, ``PIP_CONFIG_FILE`` set to the null device (no file is
        read), or a ``PIP_CONFIG_FILE`` that sets the key. pip merges by file name, so a
        ``PIP_CONFIG_FILE`` naming the site file or a global file keeps that file's place."""
        if self.env_value is not None:
            return self.env_value[0]
        if self.env_file == os.devnull:
            return f"{ENV_FILE} (the null device: pip reads no configuration file)"
        if self.env_file in (site_conf, *self.global_files):
            return None
        # Even an empty value counts: pip merges each section across files first and drops
        # empty values only after, so an empty one in a later file erases the site file's.
        conf = (read_conf(self.env_file) or {}) if self.env_file is not None else {}
        if any(KEY in conf.get(section, {}) for section in _SECTIONS):
            return self.env_file
        return None


def _normal(name: str) -> str:
    return name.lower().replace("_", "-").removeprefix("--")


def read_conf(path: str) -> dict[str, dict[str, str]] | None:
    """A pip configuration file as ``{section: {key: value}}`` with pip's key spelling (each
    section with the ``[DEFAULT]`` values it inherits, as pip reads it), or None if it does
    not exist. A file pip cannot parse is an unfinished check."""
    text = read_text(path)
    return None if text is None else read_conf_text(text, path)


def read_conf_text(text: str, place: str, *, default_section: str = "DEFAULT") -> dict[str, dict[str, str]]:
    parser = configparser.RawConfigParser(default_section=default_section)
    try:
        parser.read_string(text, source=place)
    except configparser.Error as exc:
        raise ConfigFileError(
            place,
            f"is not a valid pip configuration file ({type(exc).__name__})",
            site="pip.not-valid-pip-configuration-file",
        ) from exc
    return {s: {_normal(k): v for k, v in parser.items(s)} for s in parser.sections()}


def _own(text: str, place: str) -> dict[str, dict[str, str]]:
    """Each section's own keys, ``[DEFAULT]`` read as an ordinary section (nothing inherited)."""
    return read_conf_text(text, place, default_section="\x00no default section")


def site_value(path: str) -> str | None:
    """The value ``sys.prefix/pip.conf`` gives ``pip install``: ``[install]`` over ``[global]``."""
    return site_value_of(read_conf(path) or {})


def effective_origin(site_conf: str, sources: Sources) -> tuple[str | None, str | None]:
    """The value ``pip install`` would use and where it comes from (a file, or the variable's
    name), in pip's own order: files, later winning, ``[install]`` over ``[global]``, then
    ``PIP_UPLOADED_PRIOR_TO``."""
    merged: dict[str, tuple[str, str]] = {}
    for path in sources.files(site_conf):
        conf = read_conf(path) or {}
        for section in _SECTIONS:
            if KEY in conf.get(section, {}):  # an empty value still overwrites: pip drops it after merging
                merged[section] = (conf[section][KEY], path)
    value, origin = None, None
    for section in ("global", "install"):  # [install] beats [global]; an empty merged value is dropped
        if merged.get(section, ("", ""))[0]:
            value, origin = merged[section]
    if sources.env_value is not None:
        origin, value = sources.env_value
    return value, origin


def other_indexes(site_conf: str, sources: Sources, into: list[str] | None = None) -> list[str]:
    """Where ``pip install`` for the installation whose own file is ``site_conf`` is given a
    source other than PyPI's index, each as text naming the place: an index setting, or a
    ``constraint`` or ``requirement`` file (whose own ``--index-url`` lines pip obeys; never
    followed), in ``[global]`` or ``[install]`` of any file pip reads, or the same as a
    ``PIP_`` variable. Each
    value is split on whitespace, as pip splits it, and every part must be PyPI's own URL; an
    empty value, which pip drops, sets nothing. Every file is read in full, so a file pip
    cannot parse is an unfinished check, never a pass, raised once every other file has been
    read; nothing is written. Each place is also added to ``into`` as it is found, so a caller
    keeps what the readable files hold when one fails."""
    found = into if into is not None else []
    failure: ConfigFileError | None = None
    for path in sources.files(site_conf):
        try:  # every file is read, so one that fails never hides the next
            conf = read_conf(path) or {}
        except ConfigFileError as exc:
            failure = failure or exc
            continue
        for section in _SECTIONS:
            for key in (*INDEX_KEYS, *FILE_KEYS):
                value = conf.get(section, {}).get(key, "")
                if value and _other_source(key, value):
                    found.append(f"{path} sets {key} in [{section}]")
    if failure is not None:
        raise failure
    return list(dict.fromkeys(found + index_variables(sources)))


def index_variables(sources: Sources) -> list[str]:
    """The ``PIP_`` index variables naming anything but PyPI's index, and the constraint and
    requirement variables. They need no file, so a file that cannot be read never hides them."""
    return [f"{name} is set" for name, value in sources.index_values if _other_source(_normal(name[4:]), value)]


# --- the verdict ----------------------------------------------------------------------


class Verdict(StrEnum):
    PROTECTED = "protected"
    NO_PIP = "no-pip"  # nothing that reads the setting
    OLD_PIP = "old-pip"
    MISSING = "missing"
    UNREADABLE = "unreadable"  # a form Guardian cannot read; pip 26.0 rejects it too
    REJECTED = "rejected"  # a P<n>D that a pip in the search order (below 26.1, or unreadable) rejects
    WEAKER = "weaker"
    STALE = "stale"
    SHADOWED = "shadowed"  # a global or per-user [install] value beats the file's [global] one
    OVERRIDDEN = "overridden"  # something outside the file overrules it: protect cannot fix it
    # A source other than PyPI's index (check --envs only): the cooldown does not hold for its
    # files, and protect, which writes only the cooldown, cannot fix it.
    OTHER_INDEX = "other-index"


@dataclass(frozen=True)
class Assessment:
    """One installation's pip cooldown, against the settings."""

    env: Environment
    verdict: Verdict
    why: str  # text output only
    pip: Pip | None = None
    hidden: tuple[Pip, ...] = ()
    current: str | None = None  # the site file's value as written
    wanted: CooldownSetting | None = None  # what protect writes; None when nothing can be written

    @property
    def protected(self) -> bool:
        return self.verdict in (Verdict.PROTECTED, Verdict.NO_PIP)


def assess(env: Environment, *, cooldown_days: int, tolerance: int, today: date, sources: Sources) -> Assessment:
    """Check ``env``'s own pip cooldown against the settings: missing, weaker, stale or
    overridden fails with "run protect again"; a pip that ignores the setting fails with
    "upgrade pip or exclude this installation".

    The form is the one every pip in the search order accepts: a pip 26.0.x behind a newer
    one still runs whenever the per-user folder is off (``-s``, ``-I``), and it stops on
    ``P<n>D`` (fact 2). An override from outside the file is checked first, whatever the file
    holds, so ``protect`` never reports a write that cannot take effect."""
    found = all_pips(env)
    loaded, hidden = pips(env, found)
    if loaded is None:
        return Assessment(env, Verdict.NO_PIP, "no pip in this environment", None, hidden)
    version = try_parse(loaded.version)
    form = form_for(version) if version is not None else None
    if form is None:
        why = f"pip {loaded.version} ignores the cooldown setting: upgrade pip or exclude this installation"
        return Assessment(env, Verdict.OLD_PIP, why, loaded, hidden)
    # A pip whose version cannot be read might reject P<n>D, so it gets the fixed form too.
    if any((v := try_parse(p.version)) is None or form_for(v) is Form.FIXED for p in found):
        form = Form.FIXED
    place = env.pip_conf
    if form is Form.ROLLING:
        wanted = CooldownSetting(place, rolling_days=cooldown_days)
    else:
        wanted = CooldownSetting(place, fixed_date=fixed_date(today, cooldown_days))

    def verdict(kind: Verdict, why: str, current: str | None) -> Assessment:
        return Assessment(env, kind, why, loaded, hidden, current, wanted)

    current = site_value(place)
    outside = sources.outside_override(place)
    if outside is not None:
        why = f"{outside} overrides {place}; remove it, then run protect again"
        return verdict(Verdict.OVERRIDDEN, why, current)
    if current is None:
        return verdict(Verdict.MISSING, f"{place} sets no cooldown; run protect", None)
    setting = parse_value(current, place)
    if setting is None:
        return verdict(Verdict.UNREADABLE, f"{place} sets a form pip may reject; run protect again", current)
    if setting.rolling_days is not None:
        if form is Form.FIXED:
            why = f"pip {loaded.version} rejects {current} and stops; run protect again"
            return verdict(Verdict.REJECTED, why, current)
        if setting.rolling_days < cooldown_days:
            why = f"{place} holds {setting.rolling_days} days, under the {cooldown_days}-day cooldown"
            return verdict(Verdict.WEAKER, f"{why}; run protect again", current)
    elif setting.fixed_date is not None:
        newest = fixed_date(today, cooldown_days)
        if setting.fixed_date > newest:
            why = f"{place} accepts uploads up to {setting.fixed_date}, after {newest}; run protect again"
            return verdict(Verdict.WEAKER, why, current)
        if (newest - setting.fixed_date).days > tolerance:
            why = f"{place} holds a fixed date over {tolerance} days old; run protect again"
            return verdict(Verdict.STALE, why, current)
    value, origin = effective_origin(place, sources)
    if origin != place or value != current:
        return verdict(Verdict.SHADOWED, f"{origin} overrides {place}'s [global] value; run protect again", current)
    return verdict(Verdict.PROTECTED, f"protected ({current})", current)


# --- writing --------------------------------------------------------------------------


class Access(StrEnum):
    WRITABLE = "writable"
    ADMINISTRATOR = "administrator"  # owned by root: Guardian never uses sudo (R2-C13)
    NOT_WRITABLE = "not-writable"
    # A symlink: its target may be shared by environments whose pips need different forms, or
    # be the per-user file every pip reads, so Guardian never writes through it.
    LINKED = "linked"


def access(path: str) -> Access:
    """Whether Guardian can write ``path`` (a new file next to it, renamed over it). A
    symlinked ``pip.conf`` is never written: a person sets the key at its target."""
    if os.path.islink(path):
        return Access.LINKED
    folder = os.path.dirname(path)
    if os.access(folder, os.W_OK):
        return Access.WRITABLE
    try:
        owner = os.stat(folder).st_uid
    except OSError:
        return Access.NOT_WRITABLE
    return Access.ADMINISTRATOR if owner == 0 else Access.NOT_WRITABLE


def with_value(text: str, value: str) -> str:
    """``text`` with the key set to ``value`` in ``[global]`` and ``[install]`` (added where
    missing, so no global or per-user ``[install]`` value can beat it); its continuation
    lines are dropped. The key in any other section (``[download]``, ``[DEFAULT]``, which the
    explicit values beat) and everything else, comments included, is kept as written."""
    line_for = f"{KEY} = {value}\n"
    out: list[str] = []
    section: str | None = None
    header_at: dict[str, int] = {}
    set_in: set[str] = set()
    skipping = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if skipping and line[:1] in (" ", "\t") and stripped:
            continue  # a continuation of the value being replaced
        skipping = False
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            out.append(line)
            header_at.setdefault(section, len(out))
            continue
        name = re.split(r"[=:]", line, maxsplit=1)[0] if re.search(r"[=:]", line) else ""
        if section in _SECTIONS and stripped[:1] not in ("#", ";") and _normal(name.strip()) == KEY:
            if section not in set_in:  # a second spelling of the key in one section is dropped
                out.append(line_for)
            set_in.add(section)
            skipping = True
            continue
        out.append(line)
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    for wanted in _SECTIONS:
        if wanted in set_in:
            continue
        if wanted in header_at:
            at = header_at[wanted]
            out.insert(at, line_for)
            header_at = {s: n + 1 if n >= at else n for s, n in header_at.items()}
        else:
            out.append(("\n" if out else "") + f"[{wanted}]\n" + line_for)
    return "".join(out)


class PipPlugin:
    """pip, for ``check --envs``, ``protect`` and ``install --venv`` (``commands/install.py``)."""

    name = PluginName.PIP
    ecosystem = Ecosystem.PYPI
    code_execution = CodeExecution.NEVER  # wheels only (plan §2.3)

    def __init__(self, roots: Roots) -> None:
        self._roots = roots

    def discover(self, scope: Scope) -> Discovery:
        """Every installed package in every environment at or under ``scope``'s paths, the only
        places it reads (#255); reads files only."""
        found = discovery.survey(self._roots, scope.paths)
        items: list[Item] = []
        checked: list[Checked] = []
        skipped: list[Skip] = list(found.skipped)
        skipped += [
            Skip(Ecosystem.PYPI, place, SkipReason.CHECK_ERROR, detail=discovery.NO_ENVIRONMENT, site="pip.empty-path")
            for place in found.empty
        ]
        for env in found.environments:
            for folder in env.search_order:
                records, problems = discovery.packages(folder)
                skipped += problems
                items += [Item(Ecosystem.PYPI, p.name, p.version, folder) for p in records]
                if not problems:
                    checked.append(Checked(Ecosystem.PYPI, folder))
        return Discovery(tuple(dict.fromkeys(items)), tuple(dict.fromkeys(checked)), tuple(dict.fromkeys(skipped)))

    def trusted_age(self, item: Item) -> TrustedAge:
        raise IncompleteCheckError(
            SkipReason.NOT_AVAILABLE, site="pip.trusted-age-not-available"
        )  # the core reads PyPI (policy.py)

    def plan_install(self, target: str, requirements: tuple[Requirement, ...]) -> InstallPlan:
        """The locked-down check step and the binding; runs no package code, writes nothing."""
        from ssc_guardian.commands import install  # imported here: install imports this module

        return install.plan_install(self._roots, target, requirements)

    def apply(self, plan: InstallPlan) -> None:
        """The install step for exactly ``plan``'s bound files."""
        from ssc_guardian.commands import install  # imported here: install imports this module

        install.apply_plan(self._roots, plan)

    def installer_cooldown(self, place: str) -> CooldownSetting:
        """The cooldown ``place`` (a ``pip.conf``) gives ``pip install``; no value when it sets
        none. A form Guardian cannot read is an unfinished check, never a default."""
        current = site_value(place)
        if current is None:
            return CooldownSetting(place)
        setting = parse_value(current, place)
        if setting is None:
            raise ConfigFileError(
                place, f"{KEY} is in a form Guardian cannot read", site="pip.form-guardian-cannot-read"
            )
        return setting

    def write_cooldown(self, setting: CooldownSetting) -> None:
        """Write ``setting`` into its ``pip.conf``, keeping everything else, atomically. The
        new text is read back first; a file pip could not parse is never rewritten."""
        value = value_text(setting)
        if os.path.islink(setting.place):
            raise ConfigFileError(
                setting.place, "is a symlink; set the key at its target by hand", site="pip.symlink-set-key-target-hand"
            )
        target = setting.place
        existing = read_text(target) or ""
        text = with_value(existing, value)
        after = read_conf_text(text, target)
        both = all(after.get(s, {}).get(KEY) == value for s in _SECTIONS)
        # Each section's own keys, [DEFAULT] as a section of its own: an [install] section
        # Guardian adds inherits [DEFAULT] values, which is not a change to the file.
        own_before, own_after = _own(existing, target), _own(text, target)
        if _without_key(own_after) != _without_key(own_before) or not both:
            raise ConfigFileError(
                setting.place, "the new text did not read back as written", site="pip.new-text-did-not-read"
            )
        atomic_write(target, text)


def site_value_of(conf: Mapping[str, Mapping[str, str]]) -> str | None:
    """The value one parsed file gives ``pip install``: ``[install]`` over ``[global]``; an
    empty value, which pip drops, gives none."""
    found = None
    for section in _SECTIONS:
        found = conf.get(section, {}).get(KEY) or found
    return found


def _without_key(conf: Mapping[str, Mapping[str, str]]) -> dict[str, dict[str, str]]:
    """The file without the key in the sections Guardian writes, and without those sections
    when only the key was in them."""
    trimmed = {s: {k: v for k, v in vs.items() if k != KEY or s not in _SECTIONS} for s, vs in conf.items()}
    return {s: values for s, values in trimmed.items() if values or s not in _SECTIONS}
