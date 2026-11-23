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

"""The Python feed rules: age, compromise against ``block_on``, known vulnerabilities, KEV,
and the replacement search (plan §3.1, §2.4, §10.3).

Settings arrive as plain values in :class:`Rules`; reading and layering them belongs to the
settings code. :func:`gather_pypi` reads the feeds for a set of names once; then
:func:`evaluate_packages` turns those facts into findings for each installed package:

- **Compromise.** Indicators are graded strong or weak. OSV ``MAL-`` records and GitHub
  malware advisories are one lineage (OpenSSF), so they never count as two signals; PyPI's
  quarantine is another. ``block_on`` (``strong``, ``any``, ``never``; default ``strong``)
  decides which level is a violation.
- **Known vulnerability.** Every non-withdrawn, non-malware advisory that names the version
  blocks. A package version gets one finding listing every advisory (D14). An advisory with
  no CVE, GHSA, MAL or PYSEC ID is a malformed-name violation of its own (D4). KEV adds the
  ``actively-exploited`` label; when KEV cannot be reached the label is missing and a
  ``kev-unavailable`` warning says so.
- **Cooldown.** A version's age starts at its first upload to PyPI; for an installed package
  (``check --envs``) it starts at the upload of the newest file that could be the one
  installed (:func:`installed_upload`), since a new file can join an old release. A version
  younger than the cooldown is a violation. An unknown age is an unfinished check (exit 2),
  never a pass.
  A verified local install that PyPI has no release for has no upload to count from: that one
  fact is excused, as the out-of-scope skip ``local-install``, and every other rule still
  applies (contracts §10.6).
- **Replacement.** Each violation names the newest version that passes every rule and can be
  installed now, and, when a newer passing version is still in its cooldown (or none can be
  installed yet), the date one becomes eligible. For a venv, a version counts only through a
  wheel that fits that venv's Python and this Mac (:func:`installs`); a file whose tags or
  Requires-Python cannot be read never fits.

A feed that failed leaves the check unfinished (exit 2), except GitHub's malware advisories
when OSV answered: the OpenSSF lineage is still covered, so the run carries a
``degraded-feed`` warning instead. GitHub's rate limit is the exception to that exception: it
stops the run (exit 2) and names its reset time (plan §2.3).
"""

from __future__ import annotations

import platform
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from enum import StrEnum

from ssc_guardian.direct_url import LocalInstall
from ssc_guardian.feeds import Advisory, Match, github_advisories, merge, osv, pypi
from ssc_guardian.feeds.kev import Kev, KevStatus
from ssc_guardian.findings import (
    Ecosystem,
    Finding,
    FindingField,
    IncompleteCheckError,
    Label,
    Option,
    OptionKind,
    Rule,
    Skip,
    SkipReason,
    Verb,
    install_command,
    make_finding,
    malformed,
)
from ssc_guardian.grammars import Field, MalformedValueError, matches, normalize_pypi_name
from ssc_guardian.net import Client, FeedError, RateLimitError
from ssc_guardian.overrides import longest_days
from ssc_guardian.pep440 import Operator, Specifier, Version, canonical, parse, try_parse

PYPI = Ecosystem.PYPI
MAX_COOLDOWN_DAYS = 3650  # far past any real setting; keeps every date computable


class BlockOn(StrEnum):
    """Which compromise level blocks (plan §10.3)."""

    STRONG = "strong"
    ANY = "any"
    NEVER = "never"


DEFAULT_BLOCK_ON = BlockOn.STRONG


class Strength(StrEnum):
    NONE = "none"
    WEAK = "weak"
    STRONG = "strong"


class Indicator(StrEnum):
    REGISTRY_QUARANTINED = "registry-quarantined"  # PyPI's PEP 792 quarantine (strong)
    NAMED_VERSION = "named-version"  # a malware record names this version (strong)
    WHOLE_PACKAGE = "whole-package"  # a malware record names every version (strong)
    LINEAGES_AGREE = "lineages-agree"  # both lineages fired (strong)
    UNREADABLE_RANGE = "unreadable-range"  # a malware record names versions Guardian cannot read (strong)
    UNVERSIONED = "unversioned"  # a malware record names the package but no version (weak)


class Lineage(StrEnum):
    OPENSSF = "openssf-malicious-packages"  # OSV MAL- records and GitHub malware advisories
    PYPI_REGISTRY = "pypi-registry"


@dataclass(frozen=True)
class Compromise:
    strength: Strength
    indicators: tuple[Indicator, ...]
    advisories: tuple[Advisory, ...]  # the malware records that fired

    @property
    def confirmed(self) -> bool:
        """Confirmed malware: the 7-day override limit applies (plan §2.4)."""
        return self.strength is Strength.STRONG


def grade_compromise(malware: Iterable[Advisory], *, quarantined: bool, name: str, version: Version) -> Compromise:
    """Grade the compromise indicators for one version of ``name`` (PEP 503 form)."""
    indicators: list[Indicator] = [Indicator.REGISTRY_QUARANTINED] if quarantined else []
    fired = [(a, m) for a in malware if a.malicious and (m := a.match(name, version)) is not None]
    matches = {m for _, m in fired}
    if Match.VERSION in matches:
        indicators.append(Indicator.NAMED_VERSION)
    if Match.WHOLE_PACKAGE in matches:
        indicators.append(Indicator.WHOLE_PACKAGE)
    if Match.UNREADABLE in matches:
        indicators.append(Indicator.UNREADABLE_RANGE)
    if quarantined and fired:
        indicators.append(Indicator.LINEAGES_AGREE)
    if indicators:
        strength = Strength.STRONG
    elif fired:
        indicators, strength = [Indicator.UNVERSIONED], Strength.WEAK
    else:
        strength = Strength.NONE
    return Compromise(strength, tuple(indicators), merge(tuple(a for a, _ in fired)))


def blocks(strength: Strength, block_on: BlockOn) -> bool:
    """Whether a compromise of ``strength`` is a violation under ``block_on``."""
    if strength is Strength.NONE or block_on is BlockOn.NEVER:
        return False
    return block_on is BlockOn.ANY or strength is Strength.STRONG


def max_override_days(*, confirmed_malware: bool, kev_listed: bool) -> int:
    """The longest expiry an override may have: 7 days for confirmed malware or a KEV-listed
    vulnerability, otherwise 90 (plan §2.4). The limits are the overrides' own, defined once."""
    return longest_days(Rule.COMPROMISE if confirmed_malware else Rule.KNOWN_VULNERABILITY, kev_listed=kev_listed)


# --- age ---------------------------------------------------------------------------


def cooldown_start(uploaded: datetime) -> date:
    """The first whole day after an upload: its UTC date, or the next day if the upload was
    not at midnight. Counting days from here never makes a version eligible early."""
    moment = uploaded.astimezone(UTC)
    day = moment.date()
    return day if moment.time() == time(0) else day + timedelta(days=1)


def eligible_on(started: date, cooldown_days: int) -> date:
    return started + timedelta(days=cooldown_days)


def cooldown_met(started: date, cooldown_days: int, today: date) -> bool:
    """No cooldown is always met; otherwise the whole days counted from ``started`` must be in."""
    return cooldown_days == 0 or today >= eligible_on(started, cooldown_days)


@dataclass(frozen=True)
class Rules:
    """The settings these rules need, as plain values (layering is the settings code's job)."""

    cooldown_days: int
    today: date
    block_on: BlockOn = DEFAULT_BLOCK_ON

    def __post_init__(self) -> None:
        if type(self.cooldown_days) is not int or not 0 <= self.cooldown_days <= MAX_COOLDOWN_DAYS:
            raise ValueError(f"a cooldown is a whole number of days from 0 to {MAX_COOLDOWN_DAYS}")
        if type(self.today) is not date or not isinstance(self.block_on, BlockOn):
            raise TypeError("today is a date and block_on a BlockOn")


# --- facts ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PypiFacts:
    """What the feeds said about a set of PyPI names (each in PEP 503 form).

    ``unknown_fixes`` is what :func:`evaluate_package` learned from them: the IDs of the
    known-vulnerability findings whose fixed-version check could not finish (:func:`fix_unknown`), so an
    override on one is not applied (plan §2.4, #253)."""

    osv: Mapping[str, tuple[Advisory, ...]]
    github_malware: Mapping[str, tuple[Advisory, ...]]
    projects: Mapping[str, pypi.Project]
    pypi_failures: Mapping[str, str]
    github_failure: str | None = None
    github_rate_limit: RateLimitError | None = None
    unknown_fixes: set[str] = field(default_factory=set, compare=False)


def gather_pypi(client: Client, names: Iterable[str]) -> PypiFacts:
    """Read OSV, GitHub's malware advisories and PyPI for ``names``, each name once.

    OSV failing raises :class:`~ssc_guardian.net.FeedError`: without it neither known
    vulnerabilities nor the OpenSSF lineage can be checked. Any other GitHub failure is
    recorded: OSV still covers that lineage. A GitHub rate limit is recorded too, but it stops
    the run (plan §2.3): :func:`evaluate_packages` raises it after its findings. A PyPI
    failure is recorded per name; evaluating that name then leaves the check unfinished. A name
    that fails its grammar is not looked up; :func:`evaluate_packages` reports it.
    """
    wanted = sorted({normalize_pypi_name(name) for name in names if matches(Field.PYPI_NAME, name)})
    records = osv.query(client, wanted)
    rate_limit: RateLimitError | None = None
    try:
        malware, github_failure = github_advisories.malware(client, wanted), None
    except RateLimitError as exc:
        malware, github_failure, rate_limit = {}, str(exc), exc
    except FeedError as exc:
        malware, github_failure = {}, str(exc)
    projects: dict[str, pypi.Project] = {}
    failures: dict[str, str] = {}
    for name in wanted:
        try:
            projects[name] = pypi.project(client, name)
        except FeedError as exc:
            failures[name] = str(exc)
    return PypiFacts(records, malware, projects, failures, github_failure, rate_limit)


# --- what installs ---------------------------------------------------------------------

_REQUIRES_CLAUSE = re.compile(r"\s*(~=|==|!=|<=|>=|<|>)\s*(\S+)\s*", re.ASCII)
_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+)*", re.ASCII)
_PYTHON_TAG = re.compile(r"(py|cp)([0-9])(0|[1-9][0-9]{0,2})?", re.ASCII)  # pip matches tags as text: no 012
_MACOS_TAG = re.compile(r"macosx_(0|[1-9][0-9]{0,3})_(0|[1-9][0-9]{0,3})_(.+)", re.ASCII)
_ARM64 = "arm64"
_X86_64 = "x86_64"
_UNIVERSAL2 = "universal2"
_COMPAT_MACOS = (10, 16)  # what macOS 11 and later report with SYSTEM_VERSION_COMPAT=1 or to an old-SDK build
_FORMATS = {
    _ARM64: frozenset({_ARM64, _UNIVERSAL2}),
    _X86_64: frozenset({_X86_64, "intel", "fat64", "fat32", _UNIVERSAL2, "universal"}),
}


@dataclass(frozen=True)
class Host:
    """The Mac a venv runs on: its macOS version and architecture, None when not known.

    The architecture is the one Guardian runs as, not the venv's: for a venv run under Rosetta an
    ``x86_64``-only wheel does not count, and an ``arm64``-only one counts though pip refuses it.
    """

    macos: tuple[int, int] | None
    arch: str | None

    @classmethod
    def current(cls) -> Host:
        found = re.match(r"([0-9]{1,4})(?:\.([0-9]{1,4}))?", platform.mac_ver()[0])
        macos = (int(found[1]), int(found[2] or 0)) if found else None
        return cls(macos, platform.machine() or None)


@dataclass(frozen=True)
class Target:
    """Where a replacement must install: a venv's Python version on a host. A free-threaded venv
    is read as its ``X.Y``, so its wheels are matched as the standard build's."""

    python: tuple[int, int]
    host: Host


def _padded(python: tuple[int, int], length: int) -> tuple[int, ...]:
    return (python + (0,) * length)[:length]


def _clause_fits(clause: str, python: tuple[int, int]) -> bool | None:
    found = _REQUIRES_CLAUSE.fullmatch(clause)
    if found is None:
        return None
    operator, text = found.groups()
    stem = text.removesuffix(".*")
    version = try_parse(stem)
    if version is None:
        return None
    if stem != text:
        if operator not in (Operator.EQ, Operator.NE) or _RELEASE.fullmatch(stem) is None:
            return None
        same = _padded(python, len(version.release)) == version.release
        return same if operator == Operator.EQ else not same
    running = parse(".".join(str(part) for part in python))
    if operator == "~=":
        if len(version.release) < 2:
            return None
        series = version.release[:-1]
        return running >= version and _padded(python, len(series)) == series
    if operator == Operator.NE:
        return True
    return Specifier(Operator(operator), version).contains(running)


def requires_python_fits(raw: object, python: tuple[int, int]) -> bool | None:
    """Whether a file's Requires-Python admits ``python``: True when PyPI gives none, None when
    it cannot be read (not a string, or any clause unreadable).

    Only the venv's ``X.Y`` is known, so it is compared as ``X.Y.0``: ``<3.12.1`` admits 3.12 and
    ``>=3.12.1`` does not. A plain ``!=`` names one patch release, never the series, so it always
    admits: ``cryptography`` excludes 3.9.0 and 3.9.1, and installs on Apple's 3.9.6.
    """
    if raw is None:
        return True
    if not isinstance(raw, str):
        return None
    answers = [_clause_fits(clause, python) for clause in raw.split(",")]
    return None if None in answers else all(answers)


def _python_tag_fits(tag: str, abi: str, python: tuple[int, int]) -> bool:
    """pip's rule for CPython: ``pyX`` or ``pyXk`` (k up to the minor) with no ABI; ``cpXY`` with
    no ABI or its own; ``cpXk`` (k up to the minor) with the stable ABI, which began at 3.2."""
    major, minor = python
    found = _PYTHON_TAG.fullmatch(tag)
    if found is None or int(found[2]) != major:
        return False
    built = int(found[3]) if found[3] else None
    if found[1] == "py":
        return abi == "none" and (built is None or built <= minor)
    if built is None or built > minor:
        return False
    if abi == "abi3":
        return (major, built) >= (3, 2)
    return built == minor and abi in ("none", tag)


def _platform_tag_fits(tag: str, abi: str, host: Host) -> bool:
    """``any`` (pip pairs it only with no ABI), or a macOS tag pip takes on ``host``. Every other
    platform, and every macOS tag on a host of unknown version or architecture, does not fit."""
    if tag == "any":
        return abi == "none"
    found = _MACOS_TAG.fullmatch(tag)
    if found is None or host.macos is None or host.arch not in _FORMATS:
        return False
    major, minor, binary = int(found[1]), int(found[2]), found[3]
    host_major, host_minor = host.macos
    if major >= 11:
        return minor == 0 and major <= host_major and binary in _FORMATS[host.arch]
    if major != 10 or minor < 4:
        return False
    if host_major >= 11:
        # Every 10.x wheel runs on an Intel Mac; on arm64 only a universal2 one holds arm64 code.
        wanted = _FORMATS[_X86_64] if host.arch == _X86_64 else frozenset({_UNIVERSAL2})
        return minor <= 16 and binary in wanted
    return minor <= host_minor and binary in _FORMATS[host.arch]


def installs(file: pypi.DistFile, target: Target) -> bool:
    """Whether ``file`` is a wheel pip would take for ``target``. A file whose tags or
    Requires-Python cannot be read never does: that is a fact about the file, not a failed check."""
    if file.tags is None or requires_python_fits(file.requires_python, target.python) is not True:
        return False
    return any(
        _python_tag_fits(python, abi, target.python) and _platform_tag_fits(tag, abi, target.host)
        for python, abi, tag in file.tags
    )


@dataclass(frozen=True)
class Installed:
    """What ``check --envs`` read about the file a package was installed from: the tags its
    record's ``WHEEL`` file claims, None when it claims none Guardian can read."""

    tags: frozenset[tuple[str, str, str]] | None = None


def _python_may_fit(tag: str, abi: str, python: tuple[int, int]) -> bool:
    """Whether a wheel's Python tag could be one pip took for ``python``: False only for a
    ``py``/``cp`` tag of another major version or a later minor one, or a version-bound ABI
    (not ``abi3`` or ``none``) for another minor one. A free-threaded ``cpXYt`` ABI and an
    interpreter Guardian does not read (PyPy, GraalPy) could be."""
    found = _PYTHON_TAG.fullmatch(tag)
    if found is None:
        return True
    major, minor = python
    built = int(found[3]) if found[3] else None
    if int(found[2]) != major or (built is not None and built > minor):
        return False
    return built is None or found[1] == "py" or abi in ("abi3", "none") or built == minor


def _platform_may_fit(tag: str, host: Host) -> bool:
    """Whether a wheel's platform tag could be one pip took on ``host``: False only, on a Mac
    of known version, for a platform that is not macOS or a macOS later than the host's.
    Either architecture could be: a venv's Python may run under Rosetta, or Guardian may.
    ``10.16`` is macOS 11 or later seen in compatibility mode, so the version is not known."""
    if tag == "any" or host.macos is None or host.macos == _COMPAT_MACOS:
        return True
    found = _MACOS_TAG.fullmatch(tag)
    if found is None:
        return False
    major, minor = int(found[1]), int(found[2])
    host_major, host_minor = host.macos
    if major >= 11:
        return major <= host_major
    return host_major >= 11 or (major == 10 and minor <= host_minor)


def _may_install(file: pypi.DistFile, target: Target) -> bool:
    """Whether ``file`` could have been installed in ``target``: :func:`installs` turned
    fail-closed, for dating what is there. Only a fact that surely rules a file out does: an
    sdist, or a wheel whose tags cannot be read, could have been. Requires-Python is not read:
    the venv's patch release is not known, and the file's uploader wrote it."""
    if file.tags is None:
        return True
    return any(
        _python_may_fit(python, abi, target.python) and _platform_may_fit(tag, target.host)
        for python, abi, tag in file.tags
    )


def _version_unknown(host: Host) -> bool:
    """Whether ``host``'s macOS version is unknown: unread, or ``10.16`` in compatibility mode."""
    return host.macos is None or host.macos == _COMPAT_MACOS


_NEWEST_MACOS = (9999, 0)  # past any macOS a wheel tag can name: every version pip takes on some Mac


def _may_install_on_unknown_mac(file: pypi.DistFile, target: Target) -> bool:
    """Whether ``file`` could install in ``target`` on a Mac of unknown version (None, or
    ``10.16`` in compatibility mode) though :func:`installs` cannot say it does (#253): the
    version is its only obstacle. Its Requires-Python and a Python tag fit as :func:`installs`
    reads them, paired with a macOS tag pip takes on some version of this Mac's architecture
    (either one when that is not known either). On a Mac of known version, never:
    :func:`installs` decides. A wheel for another platform, or only for the other architecture,
    never could."""
    host = target.host
    if not _version_unknown(host):
        return False
    if file.tags is None or requires_python_fits(file.requires_python, target.python) is not True:
        return False
    arches = (host.arch,) if host.arch in _FORMATS else tuple(_FORMATS)
    return any(
        _python_tag_fits(python, abi, target.python) and _platform_tag_fits(tag, abi, Host(_NEWEST_MACOS, arch))
        for python, abi, tag in file.tags
        for arch in arches
    )


def installed_upload(
    release: pypi.Release, installed: Installed, target: Target | None
) -> tuple[datetime | None, bool]:
    """When the installed file of ``release`` was uploaded, failing closed toward younger
    (#230), and whether that cannot be known.

    PyPI lets a new file join an old release, so the release's first upload says nothing about
    the file installed. In a venv (``target``) every file that could have been installed there
    counts (:func:`_may_install`); the record's ``WHEEL`` file is not trusted, since whoever
    uploaded the wheel wrote it. Elsewhere the files whose tags equal the ones ``WHEEL`` claims
    count, with the sdists (a wheel built here from one carries the same tags); with no such
    file, every file counts. Yanked files count: an exact pin installs one. The newest upload
    among them is the date, never earlier than the release's first upload. It cannot be known
    when a counted file has no upload time or no file has one; it is then a lower bound."""
    files = release.files
    if target is not None:
        counted = [f for f in files if _may_install(f, target)]
    else:
        matched = [f for f in files if installed.tags is not None and f.tags == installed.tags]
        counted = [*matched, *(f for f in files if f.sdist and f not in matched)] if matched else list(files)
    counted = counted or list(files)
    known = [f.uploaded for f in counted if f.uploaded is not None]
    first = release.first_upload
    newest = max([*known, *([first] if first is not None else [])], default=None)
    return newest, newest is None or len(known) < len(counted)


def _first_upload_for(release: pypi.Release, target: Target | None) -> datetime | None:
    """When ``target`` could first see ``release``: its earliest wheel that is not yanked and
    fits. With no target, any wheel fits."""
    if target is None:
        return release.first_wheel_upload
    return min((f.uploaded for f in release.files if f.uploaded and not f.yanked and installs(f, target)), default=None)


def _first_unknown_upload_for(release: pypi.Release, target: Target) -> datetime | None:
    """:func:`_first_upload_for`, counting the wheels that could install on a Mac of unknown
    version (:func:`_may_install_on_unknown_mac`)."""
    fits = (f for f in release.files if not f.yanked and _may_install_on_unknown_mac(f, target))
    return min((f.uploaded for f in fits if f.uploaded), default=None)


# --- evaluation ------------------------------------------------------------------------


def _affects(advisory: Advisory, name: str, version: Version) -> bool:
    return not advisory.malicious and advisory.match(name, version) is not None


def _fixed(release: pypi.Release, name: str, advisories: tuple[Advisory, ...], current: Version) -> bool:
    """Whether ``release`` of ``name`` could replace ``current``: a final release other than it,
    named by no vulnerability advisory and by no malware record at all (even a weak one)."""
    version = release.version
    if version == current or version.is_prerelease:
        return False
    if any(_affects(a, name, version) for a in advisories):
        return False
    return grade_compromise(advisories, quarantined=False, name=name, version=version).strength is Strength.NONE


def _past_cooldown(uploaded: datetime | None, rules: Rules) -> bool:
    return uploaded is not None and cooldown_met(cooldown_start(uploaded), rules.cooldown_days, rules.today)


def fix_unknown(
    project: pypi.Project,
    advisories: tuple[Advisory, ...],
    *,
    current: Version,
    rules: Rules,
    target: Target | None,
) -> bool:
    """Whether the fixed-version check for ``current`` cannot finish (#253): on a Mac of unknown
    version (``target``'s host is None, or ``10.16`` in compatibility mode), no fixed version
    passes every rule through a wheel :func:`installs` takes, and one does through a macOS wheel
    that could install there (:func:`_may_install_on_unknown_mac`). Its age counts from that
    wheel, as :func:`replacements` counts it.

    Fail-closed toward "the vulnerability counts": such a fix may install, so "no fix" would
    keep an override past a fix that exists; it may not, so :func:`replacements` offers no
    command for it. On a Mac of known version, or with no ``target``, the check always finishes.
    """
    if target is None or not _version_unknown(target.host):
        return False
    if not project.found or project.status is pypi.ProjectStatus.QUARANTINED:
        return False
    fixed = [r for r in project.releases.values() if _fixed(r, project.name, advisories, current)]
    if any(_past_cooldown(_first_upload_for(r, target), rules) for r in fixed):
        return False
    return any(_past_cooldown(_first_unknown_upload_for(r, target), rules) for r in fixed)


def replacements(
    project: pypi.Project,
    advisories: tuple[Advisory, ...],
    *,
    item: str,
    current: Version,
    rules: Rules,
    venv: str | None,
    target: Target | None = None,
) -> tuple[Option, ...]:
    """The best replacement for ``current`` that passes every rule (plan §3.1).

    A candidate is a final release (no pre-release or dev release) with a wheel on PyPI that
    is not yanked (``install`` takes wheels only; its age counts from that wheel's upload, since
    ``install`` cannot see the release before then), named by no vulnerability advisory and by no
    malware record at all (even a weak one), in a project PyPI has not quarantined. The newest
    one past its cooldown is named with its ``install`` command (only for a venv: ``install``
    serves no base installation). The newest candidate still in its cooldown is added with its eligible date when it is
    newer than that one; when nothing can be installed yet, the earliest eligible date wins.

    With a ``target``, only wheels that fit it count, for the candidate and for its age (plan
    §2.4: a fix ends an override only if it installs in the venv). A wheel that only could fit
    a Mac of unknown version never counts: :func:`fix_unknown` says so instead (#253).
    """
    if not project.found or project.status is pypi.ProjectStatus.QUARANTINED:
        return ()
    ready: pypi.Release | None = None
    waiting: list[tuple[date, pypi.Release]] = []
    for release in sorted(project.releases.values(), key=lambda r: r.version, reverse=True):
        uploaded = _first_upload_for(release, target)
        if uploaded is None or not _fixed(release, project.name, advisories, current):
            continue
        started = cooldown_start(uploaded)
        if cooldown_met(started, rules.cooldown_days, rules.today):
            ready = release
            break
        waiting.append((eligible_on(started, rules.cooldown_days), release))
    options: list[Option] = []
    if ready is not None and venv is not None:
        text = ready.version.text
        options.append(Option(OptionKind.REPLACE, item=item, version=text, command=install_command(venv, item, text)))
    if waiting:
        # waiting is newest first, so on equal dates the lower index (the newer version) wins
        index = 0 if ready is not None else min(range(len(waiting)), key=lambda i: (waiting[i][0], i))
        when, release = waiting[index]
        options.append(Option(OptionKind.REPLACE, item=item, version=release.version.text, eligible_on=when))
    return tuple(options)


_PERSON_OPTIONS = (Option(OptionKind.REMOVE), Option(OptionKind.EXCEPTION, person_command=Verb.OVERRIDE_ADD))


def quarantined_project(
    project: pypi.Project, *, place: str | None, item: str, version: str | None, block_on: BlockOn
) -> Finding | None:
    """PyPI's quarantine of ``project`` as its ``compromise`` finding, found before a version is
    chosen (plan §3.1 step 6, #228), or None when the project is not quarantined or
    ``block_on`` lets a strong compromise through.

    The quarantine covers the whole project, and PyPI lists no files for a quarantined one, so
    a request often has no version to evaluate; ``install`` asks here before it says so: a
    quarantined project is a compromise (exit 1) however it is requested, never "PyPI has no
    released wheel" or "no release" (exit 2); 1 wins over 2. The finding names the version asked
    for, if any, with the ``registry-quarantined`` label; it offers no replacement (the
    project has none) and no evidence: the quarantine is a fact about the registry, not an
    advisory, so no override releases it."""
    if project.status is not pypi.ProjectStatus.QUARANTINED or not blocks(Strength.STRONG, block_on):
        return None
    return make_finding(
        Rule.COMPROMISE,
        PYPI,
        place=place,
        item=item,
        version=version,
        labels=[Label.REGISTRY_QUARANTINED],
        options=_PERSON_OPTIONS,
        site="policy.quarantined-project",
    )


def _evidence(
    advisories: Iterable[Advisory], *, place: str | None, item: str, version: str, into: list[Finding]
) -> tuple[str, ...]:
    """The advisories' IDs; each advisory with none Guardian may show becomes a malformed-name
    violation of its own (D4), so it is never dropped."""
    ids: set[str] = set()
    for advisory in advisories:
        try:
            ids.update(advisory.evidence())
        except MalformedValueError as exc:
            into.append(
                malformed(FindingField.EVIDENCE, exc.value, ecosystem=PYPI, place=place, item=item, version=version)
            )
    return tuple(sorted(ids))


def evaluate_package(
    facts: PypiFacts,
    kev: Kev,
    *,
    place: str | None,
    item: str,
    version: str,
    venv: str | None,
    rules: Rules,
    into: list[Finding],
    target: Target | None = None,
    local: LocalInstall | None = None,
    skips: list[Skip] | None = None,
    installed: Installed | None = None,
) -> None:
    """Apply the feed rules to one installed package, appending its findings to ``into``.

    Findings are appended as they are found, so a check that cannot finish (a feed failure,
    an unknown age) still keeps them: the error is raised after them.

    ``local`` is the package's verified local install. It replaces one missing fact: when PyPI
    has no release for this version, a ``local-install`` skip goes to ``skips`` in place of
    the unknown age. Without ``skips`` there is nowhere to list the waiver, so there is none.

    ``installed`` says the package is on disk, so its age is its installed file's
    (:func:`installed_upload`); without it, the age is the release's first upload.

    A known-vulnerability finding whose fixed-version check cannot finish (:func:`fix_unknown`)
    has its ID added to ``facts.unknown_fixes``: only its overrides read that check.
    """
    name, current = normalize_pypi_name(item), parse(version)
    if name not in facts.osv:
        raise FeedError(f"the feeds were not read for {name}", site="policy.feeds-not-read")
    project = facts.projects.get(name)
    advisories = merge(facts.osv[name], facts.github_malware.get(name, ()))
    options = (
        replacements(project, advisories, item=item, current=current, rules=rules, venv=venv, target=target)
        if project
        else ()
    ) + _PERSON_OPTIONS

    quarantined = project is not None and project.status is pypi.ProjectStatus.QUARANTINED
    compromise = grade_compromise(advisories, quarantined=quarantined, name=name, version=current)
    if blocks(compromise.strength, rules.block_on):
        evidence = _evidence(compromise.advisories, place=place, item=item, version=version, into=into)
        labels = [Label.REGISTRY_QUARANTINED] if Indicator.REGISTRY_QUARANTINED in compromise.indicators else []
        into.append(
            make_finding(
                Rule.COMPROMISE,
                PYPI,
                place=place,
                item=item,
                version=version,
                evidence=evidence,
                labels=labels,
                options=options,
                site="policy.compromise",
            )
        )

    vulnerable = [a for a in advisories if _affects(a, name, current)]
    if vulnerable:
        evidence = _evidence(vulnerable, place=place, item=item, version=version, into=into)
        status = kev.status(evidence)
        if status is KevStatus.UNAVAILABLE:
            into.append(make_finding(Rule.KEV_UNAVAILABLE, PYPI, place=place, item=item, version=version))
        if evidence:
            labels = [Label.ACTIVELY_EXPLOITED] if status is KevStatus.LISTED else []
            finding = make_finding(
                Rule.KNOWN_VULNERABILITY,
                PYPI,
                place=place,
                item=item,
                version=version,
                evidence=evidence,
                labels=labels,
                options=options,
                site="policy.known-vulnerability",
            )
            into.append(finding)
            if project is not None and fix_unknown(project, advisories, current=current, rules=rules, target=target):
                facts.unknown_fixes.add(finding.id)

    if project is None:
        raise FeedError(facts.pypi_failures.get(name, f"PyPI was not read for {name}"), site="policy.pypi-not-read")
    release = project.release(current)
    if release is None and local is not None and skips is not None:
        how = "editable install" if local.editable else "local install"
        detail = f"{item} {version}: {how} from {local.folder}; upload age not checked"
        skips.append(Skip(PYPI, place, SkipReason.LOCAL_INSTALL, detail=detail))
        return
    if release is None:
        uploaded, unknown = None, True
    elif installed is None:
        uploaded = release.first_upload
        unknown = uploaded is None
    else:
        uploaded, unknown = installed_upload(release, installed, target)
    # A known upload already inside the cooldown is a violation, even when a later one is unknown.
    if uploaded is not None and not cooldown_met(cooldown_start(uploaded), rules.cooldown_days, rules.today):
        into.append(
            make_finding(
                Rule.COOLDOWN, PYPI, place=place, item=item, version=version, options=options, site="policy.cooldown"
            )
        )
    elif unknown:
        # The normalized name and the version as installed (grammar-checked by the caller) name
        # the distribution, never file content (#298); ``1.0.0`` stays ``1.0.0``, as pip shows it (#284).
        raise IncompleteCheckError(
            SkipReason.UNKNOWN_AGE, detail=f"{name} {version}", site="policy.evaluate-package-unknown-age"
        )


def evaluate_packages(
    facts: PypiFacts,
    kev: Kev,
    packages: Iterable[tuple[str, str]],
    *,
    place: str | None,
    venv: str | None,
    rules: Rules,
    into: list[Finding],
    target: Target | None = None,
    local: Mapping[tuple[str, str], LocalInstall] | None = None,
    skips: list[Skip] | None = None,
    installed: Mapping[tuple[str, str], Installed] | None = None,
) -> None:
    """:func:`evaluate_package` for each ``(item, version)``, every one of them, even after one
    fails; then the first failure is raised, so the check is unfinished but keeps every finding.

    A malformed name or version is a malformed-name violation of its own, and the others are
    still checked. Two spellings of one package version are evaluated once, under the first.
    GitHub's advisories failing while OSV answered adds the ``degraded-feed`` warning; a GitHub
    rate limit instead leaves the check unfinished (``rate-limit``, exit 2, plan §2.3).
    ``local`` holds the verified local installs by normalized name and canonical version.
    ``installed``, keyed the same way, says the packages are on disk (``check --envs``): each is
    then dated by its installed file, one with no entry as one whose file Guardian cannot name.
    """
    if facts.github_failure is not None and facts.github_rate_limit is None:
        into.append(make_finding(Rule.DEGRADED_FEED, PYPI))
    failure: IncompleteCheckError | None = facts.github_rate_limit
    seen: set[tuple[str, str]] = set()
    for item, version in packages:
        if not matches(Field.PYPI_NAME, item):
            into.append(malformed(FindingField.ITEM, item, ecosystem=PYPI, place=place, version=version))
            continue
        if not matches(Field.PEP440_VERSION, version):
            into.append(malformed(FindingField.VERSION, version, ecosystem=PYPI, place=place, item=item))
            continue
        # Two spellings of one package version are one package: the first is kept (D18).
        key = (normalize_pypi_name(item), canonical(version))
        if key in seen:
            continue
        seen.add(key)
        try:
            evaluate_package(
                facts,
                kev,
                place=place,
                item=item,
                version=version,
                venv=venv,
                rules=rules,
                into=into,
                target=target,
                local=local.get(key) if local else None,
                skips=skips,
                installed=installed.get(key, Installed()) if installed is not None else None,
            )
        except IncompleteCheckError as exc:
            failure = failure or exc
    if failure is not None:
        raise failure
