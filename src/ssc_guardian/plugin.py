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

"""The ecosystem plug-in protocol (plan §2.3, N15, R1-C4).

One plug-in per ecosystem or installer; v1.0 has pip, uv (setup and reporting)
and GitHub Actions. The interface is internal in v1.0. Each function states
what it guarantees. Rules, feeds, overrides, exit codes and output belong to
the shared core: a plug-in reports facts, never verdicts.

Failure contract for every function: a function that cannot establish its
facts raises :class:`~ssc_guardian.findings.IncompleteCheckError` with an
in-scope reason; it never returns a partial answer as if complete, and never
guesses. A value that fails its field grammar raises
:class:`~ssc_guardian.grammars.MalformedValueError` (the data shapes below do this on
construction); the core reports it as a malformed-name violation (exit 1) and lists
the interrupted check as unfinished. Any other exception is an unfinished check (exit 2).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import Protocol

from ssc_guardian.findings import Checked, Ecosystem, Scope, Skip, item_field, version_field
from ssc_guardian.grammars import Field, check


def _freeze(obj: object, fields: tuple[tuple[str, type], ...]) -> None:
    """Store each list field of a frozen dataclass as a tuple of the named type."""
    for name, kind in fields:
        values = tuple(getattr(obj, name))
        if not all(isinstance(v, kind) for v in values):
            raise TypeError(f"{type(obj).__name__}.{name} holds only {kind.__name__}")
        object.__setattr__(obj, name, values)


def _exact_date(value: date | None) -> None:
    if value is not None and type(value) is not date:
        raise TypeError("a date field holds a datetime.date, not a datetime")


class PluginName(StrEnum):
    PIP = "pip"
    UV = "uv"
    GITHUB_ACTIONS = "github-actions"


class CodeExecution(StrEnum):
    """Whether package code can run during an install (plan §2.3)."""

    NEVER = "never"  # Guardian guarantees it (pip with wheels only).
    CAN_BE_TURNED_OFF = "can-be-turned-off"  # Guardian turns it off (npm --ignore-scripts).
    ALWAYS = "always"  # Guardian checks before the build and says build code will run (Cargo).


class AgeSource(StrEnum):
    """Where a trusted age comes from."""

    REGISTRY_UPLOAD = "registry-upload"  # the registry's own upload time (PyPI)
    ACTIVITY_LOG = "activity-log"  # GitHub's activity log: the commit reached a publisher branch
    IMMUTABLE_RELEASE = "immutable-release"  # an immutable GitHub release pointing at the commit
    PERSON_DATE = "person-date"  # a person's date; it can only make the start later
    LOCK_FIRST_SEEN = "lock-first-seen"  # first-seen date recorded in the lock file


@dataclass(frozen=True)
class Item:
    """An installed or declared item: name and version at one place, all grammar-checked."""

    ecosystem: Ecosystem
    name: str
    version: str
    place: str

    def __post_init__(self) -> None:
        if not isinstance(self.ecosystem, Ecosystem):
            raise TypeError("an Ecosystem names the item's ecosystem")
        check(item_field(self.ecosystem), self.name)
        check(version_field(self.ecosystem), self.version)
        check(Field.PATH, self.place)


@dataclass(frozen=True)
class Discovery:
    """What :meth:`EcosystemPlugin.discover` found, plus every place it covered or could not read."""

    items: tuple[Item, ...]
    checked: tuple[Checked, ...]
    skipped: tuple[Skip, ...]

    def __post_init__(self) -> None:
        _freeze(self, (("items", Item), ("checked", Checked), ("skipped", Skip)))


@dataclass(frozen=True)
class TrustedAge:
    """When an item's cooldown starts, and the source of that date."""

    started: date
    source: AgeSource

    def __post_init__(self) -> None:
        if type(self.started) is not date:
            raise TypeError("a trusted age starts on a datetime.date")
        if not isinstance(self.source, AgeSource):
            raise TypeError("a trusted age names an AgeSource")


@dataclass(frozen=True)
class Requirement:
    """One requested item. ``version`` None is a loose request (newest version that meets every rule)."""

    ecosystem: Ecosystem
    name: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ecosystem, Ecosystem):
            raise TypeError("an Ecosystem names the item's ecosystem")
        check(item_field(self.ecosystem), self.name)
        if self.version is not None:
            check(version_field(self.ecosystem), self.version)


class DigestAlgorithm(StrEnum):
    """Digest algorithms a planned file may be bound with, and their hex lengths.

    The npm paper test added SHA-512: npm lock files record ``integrity`` as
    SHA-512 (docs/contracts.md). Weaker algorithms are never accepted.
    """

    SHA256 = "sha256"
    SHA512 = "sha512"

    @property
    def hex_length(self) -> int:
        return 64 if self is DigestAlgorithm.SHA256 else 128


@dataclass(frozen=True)
class PlannedFile:
    """One file an install or pin will use, bound to the digest the core checks."""

    item: Item
    url: str
    algorithm: DigestAlgorithm
    digest: str  # lowercase hex

    def __post_init__(self) -> None:
        if not isinstance(self.item, Item) or not isinstance(self.algorithm, DigestAlgorithm):
            raise TypeError("a planned file names an Item and a DigestAlgorithm")
        if not self.url.startswith("https://") or any(ch.isspace() or not ch.isprintable() for ch in self.url):
            raise ValueError("a planned file is fetched over HTTPS from a URL with no spaces or controls")
        if len(self.digest) != self.algorithm.hex_length or any(ch not in "0123456789abcdef" for ch in self.digest):
            raise ValueError(f"a planned file carries a lowercase hex {self.algorithm.value} digest")


@dataclass(frozen=True)
class InstallPlan:
    """Exactly what :meth:`EcosystemPlugin.apply` will write, and nothing more.

    ``items`` is the full resolved set the core checks. ``files`` binds each
    downloaded file to its digest (pip wheels); a pin has none, because the
    commit SHA in the item's version is the binding. ``also_writes`` names every
    file outside ``target`` that :meth:`EcosystemPlugin.apply` writes (a pin's
    lock file); the confirmation shows each one (D16).
    """

    target: str
    items: tuple[Item, ...]
    files: tuple[PlannedFile, ...] = ()
    also_writes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        check(Field.PATH, self.target)
        _freeze(self, (("items", Item), ("files", PlannedFile), ("also_writes", str)))
        for path in self.also_writes:
            check(Field.PATH, path)
        if self.target in self.also_writes or len(set(self.also_writes)) != len(self.also_writes):
            raise ValueError("also_writes names each other file once, and not the target")


@dataclass(frozen=True)
class CooldownSetting:
    """The installer's own cooldown at one place, as read from disk.

    ``rolling_days`` and ``fixed_date`` are both None when no setting is present.
    """

    place: str
    rolling_days: int | None = None
    fixed_date: date | None = None

    def __post_init__(self) -> None:
        check(Field.PATH, self.place)
        _exact_date(self.fixed_date)
        if self.rolling_days is not None and type(self.rolling_days) is not int:
            raise TypeError("a rolling cooldown is a whole number of days")
        if self.rolling_days is not None and self.fixed_date is not None:
            raise ValueError("a cooldown setting is rolling or a fixed date, not both")
        if self.rolling_days is not None and self.rolling_days < 0:
            raise ValueError("a rolling cooldown is not negative")


class EcosystemPlugin(Protocol):
    """The typed interface every ecosystem plug-in implements."""

    @property
    def name(self) -> PluginName:
        """The plug-in's fixed name."""
        ...

    @property
    def ecosystem(self) -> Ecosystem:
        """The ecosystem whose items this plug-in reports."""
        ...

    @property
    def code_execution(self) -> CodeExecution:
        """Declares code execution at install.

        Guarantee: a constant for the plug-in's lifetime. ``NEVER`` means
        :meth:`plan_install` and :meth:`apply` run no package code at all;
        ``CAN_BE_TURNED_OFF`` means both always turn it off; ``ALWAYS`` means the
        core states before :meth:`apply` that build code will run.
        """
        ...

    def discover(self, scope: Scope) -> Discovery:
        """Discover installed or declared items within ``scope``.

        Guarantees: reads files only and never runs a program it finds (plan
        §2.3, #233); reports every place it covered in ``checked`` and every
        place it could not read in ``skipped`` with an in-scope reason; names
        each place with its symlinks resolved, as the core does for path
        arguments, so one place has one finding ID; never returns an item from
        outside ``scope``, judged by the resolved place, and lists a place that
        resolves outside ``scope`` in ``skipped`` as ``CHECK_ERROR``, under the
        path where it was found inside ``scope``, so it is
        never passed over silently; changes nothing.
        """
        ...

    def trusted_age(self, item: Item) -> TrustedAge:
        """When ``item``'s cooldown starts.

        Guarantees: uses only the sources :class:`AgeSource` names, in the plan's
        order (T2): the earliest registry or GitHub-recorded date; else a person's
        date (which can only make the start later); else the lock file's first-seen date;
        raises ``IncompleteCheckError(UNKNOWN_AGE)`` rather than guess; changes
        nothing.
        """
        ...

    def plan_install(self, target: str, requirements: tuple[Requirement, ...]) -> InstallPlan:
        """Plan the install or pin of ``requirements`` into ``target``.

        Guarantees: runs no package code; resolves the full set that
        :meth:`apply` would write, each file bound to its digest; writes
        nothing. A plug-in that does not install (uv) raises
        ``IncompleteCheckError(NOT_AVAILABLE)``.
        """
        ...

    def apply(self, plan: InstallPlan) -> None:
        """Install or pin exactly ``plan``.

        Guarantees: called by the core only after every check on the plan has
        passed and the user has confirmed; writes only the files in ``plan``
        into ``plan.target`` and the files ``plan.also_writes`` names, nothing
        else; on any failure raises and reports what, if anything, was written.
        """
        ...

    def write_cooldown(self, setting: CooldownSetting) -> None:
        """Write the installer's own cooldown setting at ``setting.place`` (``protect``, D16).

        Guarantees: called by the core only after the user has seen and confirmed
        the change; writes only that setting, in that one file, and never runs
        the installer; refuses a setting with no value (it would read as
        removing the cooldown); on any failure raises and reports what, if
        anything, was written.
        """
        ...

    def installer_cooldown(self, place: str) -> CooldownSetting:
        """Read the installer's own cooldown setting at ``place``.

        Guarantees: reads files only and never runs the installer; reports a
        missing setting as a :class:`CooldownSetting` with no value, never as a
        default; changes nothing.
        """
        ...
