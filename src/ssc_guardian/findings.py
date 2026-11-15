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

"""Result model: findings, checked and skipped lists, finding IDs and the exit aggregator.

Plan §2.1 (skipped is never clean) and §2.2 (JSON contract, exit codes). Every
value a finding carries is a fixed template (an enum member) or a string that
matches its field grammar; construction fails otherwise. Free text that a person
wrote lives only in fields the JSON renderer never reads.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import KW_ONLY, InitVar, dataclass, field
from datetime import date
from enum import IntEnum, StrEnum
from types import FrameType

from ssc_guardian import pep440
from ssc_guardian.grammars import Field, MalformedValueError, check, matches, normalize_pypi_name

TOOL_NAME = "ssc-guardian"


class Ecosystem(StrEnum):
    PYPI = "pypi"
    GITHUB_ACTIONS = "github-actions"


class Installer(StrEnum):
    PIP = "pip"
    UV = "uv"


class Verb(StrEnum):
    CHECK = "check"
    PROTECT = "protect"
    INSTALL = "install"
    PIN = "pin"
    ACKNOWLEDGE = "acknowledge"
    OVERRIDE_ADD = "override add"

    @property
    def person_only(self) -> bool:
        """Exception commands: never ``--yes``, never in JSON (plan §2.1, R2-K3)."""
        return self in _PERSON_VERBS


_PERSON_VERBS = frozenset({Verb.ACKNOWLEDGE, Verb.OVERRIDE_ADD})


class Level(StrEnum):
    VIOLATION = "violation"
    WARNING = "warning"
    NOTICE = "notice"


class Rule(StrEnum):
    """Rule names. Each rule has one fixed level, so a warning can never fail a run."""

    # Violations (exit 1).
    COOLDOWN = "cooldown"
    COMPROMISE = "compromise"
    KNOWN_VULNERABILITY = "known-vulnerability"
    DENY_LIST = "deny-list"
    UNPROTECTED = "unprotected"
    MALFORMED_NAME = "malformed-name"
    MOVING_REFERENCE = "moving-reference"
    UNVERIFIED_PIN = "unverified-pin"
    IMPOSTOR_COMMIT = "impostor-commit"
    YOUNG_REPOSITORY = "young-repository"
    NESTED_MOVING_REFERENCE = "nested-moving-reference"
    NESTING_LIMIT = "nesting-limit"
    NESTING_LOOP = "nesting-loop"
    UNRELEASED_PIN_ADVISORY = "unreleased-pin-advisory"
    # Warnings (never fail).
    UNPUSHED_COMMIT = "unpushed-commit"
    DEGRADED_FEED = "degraded-feed"
    KEV_UNAVAILABLE = "kev-unavailable"
    UNPINNED_IMAGE = "unpinned-image"
    MOVED_RELEASE_TAG = "moved-release-tag"
    # Notices.
    COOLDOWN_WAIT = "cooldown-wait"
    FIRST_USE_PUBLISHER = "first-use-publisher"
    WEAKENED_SETTING = "weakened-setting"
    HIDDEN_PIP = "hidden-pip"
    CI_OVERRIDES = "ci-overrides"

    @property
    def level(self) -> Level:
        return _RULE_LEVELS.get(self, Level.VIOLATION)


_RULE_LEVELS = {
    Rule.UNPUSHED_COMMIT: Level.WARNING,
    Rule.DEGRADED_FEED: Level.WARNING,
    Rule.KEV_UNAVAILABLE: Level.WARNING,
    Rule.UNPINNED_IMAGE: Level.WARNING,
    Rule.MOVED_RELEASE_TAG: Level.WARNING,
    Rule.COOLDOWN_WAIT: Level.NOTICE,
    Rule.FIRST_USE_PUBLISHER: Level.NOTICE,
    Rule.WEAKENED_SETTING: Level.NOTICE,
    Rule.HIDDEN_PIP: Level.NOTICE,
    Rule.CI_OVERRIDES: Level.NOTICE,
}


class Label(StrEnum):
    ACTIVELY_EXPLOITED = "actively-exploited"
    REGISTRY_QUARANTINED = "registry-quarantined"


class FindingField(StrEnum):
    """Names a finding's field in a malformed-name violation."""

    PLACE = "place"
    ITEM = "item"
    VERSION = "version"
    EVIDENCE = "evidence"
    VIA = "via"


class ExitCode(IntEnum):
    RULES_MET = 0
    VIOLATION = 1
    INCOMPLETE = 2


class SkipReason(StrEnum):
    """Why an area was not checked. In-scope reasons make the run incomplete (exit 2)."""

    # In scope: the check could not finish.
    FEED_FAILURE = "feed-failure"
    UNKNOWN_AGE = "unknown-age"
    UNSUPPORTED_YAML = "unsupported-yaml"
    RATE_LIMIT = "rate-limit"
    DEFAULT_BRANCH_UNREADABLE = "default-branch-unreadable"
    CHECK_ERROR = "check-error"
    NOT_AVAILABLE = "not-available"
    # Out of scope: listed, never counted as clean, exit code unchanged.
    FILTERED = "filtered"
    DEFAULT_SCOPE = "default-scope"
    LATER_RELEASE = "later-release"
    DEEPER_THAN_ONE_LEVEL = "deeper-than-one-level"
    LOCAL_INSTALL = "local-install"

    @property
    def in_scope(self) -> bool:
        return self not in _OUT_OF_SCOPE


_OUT_OF_SCOPE = frozenset(
    {
        SkipReason.FILTERED,
        SkipReason.DEFAULT_SCOPE,
        SkipReason.LATER_RELEASE,
        SkipReason.DEEPER_THAN_ONE_LEVEL,
        SkipReason.LOCAL_INSTALL,
    }
)


class OptionKind(StrEnum):
    REPLACE = "replace"
    PROTECT = "protect"
    REMOVE = "remove"
    EXCEPTION = "exception"


class OverrideCategory(StrEnum):
    NOT_EXPLOITABLE = "not-exploitable"
    NO_FIX_AVAILABLE = "no-fix-available"
    DEFERRED_UPGRADE = "deferred-upgrade"
    ACCEPTED_RISK = "accepted-risk"


class LimitName(StrEnum):
    """References for overrides that release a limit rather than an advisory."""

    NESTING_DEPTH = "nesting-depth"
    NESTED_REFERENCE_COUNT = "nested-reference-count"
    NESTING_LOOP = "nesting-loop"
    NESTED_MOVING_REFERENCE = "nested-moving-reference"


_ITEM_FIELDS = {Ecosystem.PYPI: Field.PYPI_NAME, Ecosystem.GITHUB_ACTIONS: Field.ACTION}
_VERSION_FIELDS = {Ecosystem.PYPI: Field.PEP440_VERSION, Ecosystem.GITHUB_ACTIONS: Field.GIT_REF}


def item_field(ecosystem: Ecosystem) -> Field:
    return _ITEM_FIELDS[ecosystem]


def version_field(ecosystem: Ecosystem) -> Field:
    return _VERSION_FIELDS[ecosystem]


def finding_item_field(rule: Rule | None, ecosystem: Ecosystem) -> Field:
    """The grammar of a finding's ``item``: its ecosystem's, except that an ``unpinned-image``
    warning names a Docker image (owner's ruling, 2026-11-09, #127; contracts §6)."""
    if rule is Rule.UNPINNED_IMAGE and ecosystem is Ecosystem.GITHUB_ACTIONS:
        return Field.DOCKER_IMAGE
    return item_field(ecosystem)


def _finding_item_spelling(rule: Rule, ecosystem: Ecosystem | None, item: str | None) -> str | None:
    """A finding's item in its one spelling (D18). A Docker image is kept as written: its tag is
    case-sensitive and its path lowercase by grammar."""
    if ecosystem is not None and finding_item_field(rule, ecosystem) is Field.DOCKER_IMAGE:
        return item
    return _id_spelling(ecosystem, item)


def _id_spelling(ecosystem: Ecosystem | None, item: str | None) -> str | None:
    """The one spelling of a valid ``item`` that its ecosystem treats as the same name (D18).

    PyPI: the PEP 503 name (``Requests`` and ``requests`` are one package). An Action: the
    owner and repository lowercased, as GitHub matches them; a path inside the repository
    is case-sensitive and kept as given.
    """
    if item is None or ecosystem is None:
        return item
    if ecosystem is Ecosystem.PYPI:
        return normalize_pypi_name(item)
    if ecosystem is Ecosystem.GITHUB_ACTIONS:
        owner, repo, *path = item.split("/")
        return "/".join([owner.lower(), repo.lower(), *path])
    raise ValueError(f"no finding-ID spelling is defined for {ecosystem.value}")


def _id_version(ecosystem: Ecosystem | None, version: str | None) -> str | None:
    """The one spelling of a valid ``version`` (D18). PyPI: the PEP 440 normalized form with
    trailing zero release parts dropped (``1.0``, ``1.0.0`` and ``v1.0`` are one version). A
    Git ref is case-sensitive and kept as given."""
    if version is None or ecosystem is not Ecosystem.PYPI:
        return version
    return pep440.canonical(version)


# --- fix commands -----------------------------------------------------------


def install_command(venv: str, name: str, version: str) -> tuple[str, ...]:
    requirement = f"{check(Field.PYPI_NAME, name)}=={check(Field.PEP440_VERSION, version)}"
    return (TOOL_NAME, Verb.INSTALL.value, "--venv", check(Field.PATH, venv), requirement)


def pin_command(action: str, ref: str) -> tuple[str, ...]:
    return (TOOL_NAME, Verb.PIN.value, f"{check(Field.ACTION, action)}@{check(Field.GIT_REF, ref)}")


def protect_command(place: str, installer: Installer | None = None) -> tuple[str, ...]:
    """``protect [pip|uv] --path PLACE``: the fix acts on exactly the place that was reported (#255)."""
    installer_part = (installer.value,) if installer else ()
    return (TOOL_NAME, Verb.PROTECT.value, *installer_part, "--path", check(Field.PATH, place))


def _fix_command_parts(argv: tuple[str, ...]) -> tuple[Verb, str | None, str | None] | None:
    """The verb, item and version of a fix command, or None for anything but the three shapes
    the constructors above build (never an exception command)."""
    match argv:
        case ("ssc-guardian", "install", "--venv", venv, requirement):
            name, sep, version = requirement.partition("==")
            if sep and matches(Field.PATH, venv) and _pypi_pair_ok(name, version):
                return Verb.INSTALL, name, version
        case ("ssc-guardian", "pin", spec):
            action, sep, ref = spec.rpartition("@")
            if sep and matches(Field.ACTION, action) and matches(Field.GIT_REF, ref):
                return Verb.PIN, action, ref
        case ("ssc-guardian", "protect", "--path", place) if matches(Field.PATH, place):
            return Verb.PROTECT, None, None
        case ("ssc-guardian", "protect", installer, "--path", place) if installer in {
            i.value for i in Installer
        } and matches(Field.PATH, place):
            return Verb.PROTECT, None, None
    return None


def _pypi_pair_ok(name: str, version: str) -> bool:
    return matches(Field.PYPI_NAME, name) and matches(Field.PEP440_VERSION, version)


_FIX_VERB = {Ecosystem.PYPI: Verb.INSTALL, Ecosystem.GITHUB_ACTIONS: Verb.PIN}


# --- result model -----------------------------------------------------------


def _required_date(value: object) -> None:
    """A required date: present, and a date rather than a datetime."""
    if type(value) is not date:
        raise TypeError("a required date field holds a datetime.date")


def _enum(value: object, kind: type) -> None:
    # The exact type: isinstance would accept an object that forges __class__, and its fake
    # value would reach JSON.
    if type(value) is not kind:
        raise TypeError(f"expected a {kind.__name__}, got {type(value).__name__}")


def _optional_enum(value: object, kind: type) -> None:
    if value is not None:
        _enum(value, kind)


def _exact_date(value: date | None) -> None:
    """A date, not a datetime (a subclass whose isoformat would break the date grammar)."""
    if value is not None and type(value) is not date:
        raise TypeError("a date field holds a datetime.date, not a datetime")


@dataclass(frozen=True)
class Option:
    """One way to resolve a finding.

    ``REPLACE`` names a version and, once it is eligible, the command that
    installs or pins it. ``PROTECT`` carries the ``protect`` command.
    ``REMOVE`` is the user's decision and has no command. ``EXCEPTION`` goes to
    a person: ``person_command`` (``acknowledge`` or ``override add``) and
    ``person_target`` appear in text output only.
    """

    kind: OptionKind
    item: str | None = None
    version: str | None = None
    command: tuple[str, ...] | None = None
    eligible_on: date | None = None
    person_command: Verb | None = None
    person_target: str | None = None

    def __post_init__(self) -> None:
        _enum(self.kind, OptionKind)
        _optional_enum(self.person_command, Verb)
        if self.command is not None:
            object.__setattr__(self, "command", tuple(self.command))
        _exact_date(self.eligible_on)
        has_command = self.command is not None
        parts = _fix_command_parts(self.command) if self.command is not None else None
        if has_command and parts is None:
            raise ValueError("an option command must be built by install_command, pin_command or protect_command")
        if self.kind is OptionKind.REPLACE:
            if self.item is None or self.version is None:
                raise ValueError("a replace option names an item and a version")
            if parts is not None and (parts[0] is Verb.PROTECT or parts[1:] != (self.item, self.version)):
                raise ValueError("a replace option's command installs or pins exactly its item and version")
            if has_command == (self.eligible_on is not None):
                raise ValueError("a replace option has a command once eligible, or a date before that: one of the two")
        elif self.item is not None or self.version is not None or self.eligible_on is not None:
            raise ValueError(f"a {self.kind} option names no item, version or date")
        if self.kind is OptionKind.PROTECT and (parts is None or parts[0] is not Verb.PROTECT):
            raise ValueError("a protect option carries the protect command")
        if self.kind in {OptionKind.REMOVE, OptionKind.EXCEPTION} and has_command:
            raise ValueError(f"a {self.kind} option has no command")
        if (self.person_command is not None) != (self.kind is OptionKind.EXCEPTION):
            raise ValueError("only an exception option names a person's command")
        if self.person_command is not None and not self.person_command.person_only:
            raise ValueError("an exception option names acknowledge or override add")
        if (self.person_target is not None) != (self.person_command is Verb.ACKNOWLEDGE):
            raise ValueError("acknowledge names its repository; override add takes no target")
        if self.person_target is not None:
            check(Field.OWNER_REPO, self.person_target)

    def validate_for(self, ecosystem: Ecosystem) -> None:
        if self.kind is OptionKind.PROTECT and ecosystem is not Ecosystem.PYPI:
            raise ValueError("protect fixes Python environments only")
        if self.person_command is Verb.ACKNOWLEDGE and ecosystem is not Ecosystem.GITHUB_ACTIONS:
            raise ValueError("acknowledge accepts GitHub Action repositories only")
        if self.kind is OptionKind.REPLACE and self.command is not None:
            parts = _fix_command_parts(self.command)
            if parts is None or parts[0] is not _FIX_VERB[ecosystem]:
                raise ValueError(f"a {ecosystem.value} replacement uses {_FIX_VERB[ecosystem].value}")
        if self.item is not None:
            check(item_field(ecosystem), self.item)
        if self.version is not None:
            check(version_field(ecosystem), self.version)


def _via_spelling(step: str) -> str:
    action, _, ref = step.rpartition("@")
    return f"{_id_spelling(Ecosystem.GITHUB_ACTIONS, action)}@{ref}"


def _canonical_id(*parts: str | list[str] | None) -> str:
    payload = json.dumps(list(parts), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()[:32]


@dataclass(frozen=True)
class Finding:
    """One rule result at one place. Build it with :func:`make_finding`.

    A violation names its ``site``, a fixed ID for the place that builds it, for its negative test
    (issue #164); like a skip's, it is not a field and reaches no output."""

    rule: Rule
    ecosystem: Ecosystem | None
    place: str | None = None
    item: str | None = None
    version: str | None = None
    evidence: tuple[str, ...] = ()
    labels: tuple[Label, ...] = ()
    options: tuple[Option, ...] = ()
    malformed_field: FindingField | None = None
    malformed_value: str | None = None  # the rejected raw value: text output only
    # The outer Actions, outermost first, through which a nested finding was reached (T5, D14).
    via: tuple[str, ...] = ()
    # Free text for text output only (a weakened setting's key and values): never in JSON or the ID.
    detail: str | None = None
    _: KW_ONLY
    site: InitVar[str | None] = None

    def __post_init__(self, site: str | None) -> None:
        for name in ("evidence", "labels", "options", "via"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        _enum(self.rule, Rule)
        _optional_enum(self.ecosystem, Ecosystem)
        _optional_enum(self.malformed_field, FindingField)
        for label in self.labels:
            _enum(label, Label)
        for option in self.options:
            _enum(option, Option)
        if (self.rule is Rule.MALFORMED_NAME) != (self.malformed_field is not None):
            raise ValueError("a malformed-name finding, and only one, names the malformed field")
        if (self.malformed_field is None) != (self.malformed_value is None):
            raise ValueError("a malformed value comes only with the malformed field it belongs to")
        if self.via and self.ecosystem is not Ecosystem.GITHUB_ACTIONS:
            raise ValueError("only a GitHub Actions finding is reached through outer Actions")
        bad = _first_malformed(
            self.ecosystem, self.place, self.item, self.version, self.evidence, self.via, rule=self.rule
        )
        if bad is not None:
            raise MalformedValueError(bad[1], bad[2], site="findings.malformed-field")
        # Store each step as a plain str: a subclass could change what output reads from it.
        object.__setattr__(self, "via", tuple(str.__str__(step) for step in self.via))
        for option in self.options:
            if self.ecosystem is None:
                raise ValueError("an option needs the finding's ecosystem")
            option.validate_for(self.ecosystem)
            # The fix acts on exactly what was reported, never on more (#255).
            if option.kind is OptionKind.PROTECT and option.command is not None and option.command[-1] != self.place:
                raise ValueError("a protect option's --path is its finding's place")
        if site is not None:
            record_site(site, self)  # also stands for a refusal being handled, as below
        else:
            _built_from(self)  # a finding built from a refusal, such as malformed-name from a bad value

    @property
    def level(self) -> Level:
        return self.rule.level

    @property
    def id(self) -> str:
        """Deterministic: rule + place + ecosystem + item + version (plan §2.2, N23), plus the
        outer-Action chain, so one inner reference reached through two outer Actions gives
        two IDs (D14).

        The item, its version, and each Action in the chain, is hashed in its ecosystem's one
        spelling, so two spellings of one name or version give one ID (D18). A malformed-name finding also hashes the
        field and the rejected value, so two different malformed values at one place get
        different IDs.
        """
        return _canonical_id(
            self.rule.value,
            self.place,
            self.ecosystem.value if self.ecosystem else None,
            _finding_item_spelling(self.rule, self.ecosystem, self.item),
            _id_version(self.ecosystem, self.version),
            self.malformed_field.value if self.malformed_field else None,
            self.malformed_value,
            [_via_spelling(step) for step in self.via],
        )


def _first_malformed(
    ecosystem: Ecosystem | None,
    place: str | None,
    item: str | None,
    version: str | None,
    evidence: Iterable[str],
    via: Iterable[str] = (),
    *,
    rule: Rule | None = None,
) -> tuple[FindingField, Field, object] | None:
    if place is not None and not matches(Field.PATH, place):
        return FindingField.PLACE, Field.PATH, place
    if ecosystem is None and (item is not None or version is not None):
        raise ValueError("an item or version needs an ecosystem")
    if ecosystem is not None:
        grammar = finding_item_field(rule, ecosystem)
        if item is not None and not matches(grammar, item):
            return FindingField.ITEM, grammar, item
        if version is not None and not matches(version_field(ecosystem), version):
            return FindingField.VERSION, version_field(ecosystem), version
    for advisory in evidence:
        if not matches(Field.ADVISORY_ID, advisory):
            return FindingField.EVIDENCE, Field.ADVISORY_ID, advisory
    for step in via:
        if not matches(Field.ACTION_STEP, step):
            return FindingField.VIA, Field.ACTION_STEP, step
    return None


def make_finding(
    rule: Rule,
    ecosystem: Ecosystem | None,
    *,
    place: str | None = None,
    item: str | None = None,
    version: str | None = None,
    evidence: Iterable[str] = (),
    labels: Iterable[Label] = (),
    options: Iterable[Option] = (),
    via: Iterable[str] = (),
    detail: str | None = None,
    site: str | None = None,
) -> Finding:
    """Build a finding; a value that fails its grammar gives a malformed-name violation instead.

    The violation keeps the values that did match, drops the rejected one (and
    the evidence, options and detail, which may repeat it) and never guesses a repair.
    ``site`` names the place that builds a violation (issue #164); it reaches no output.
    """
    evidence, via = tuple(evidence), tuple(via)
    bad = _first_malformed(ecosystem, place, item, version, evidence, via, rule=rule)
    if bad is None:
        return Finding(
            rule,
            ecosystem,
            place,
            item,
            version,
            evidence,
            tuple(labels),
            tuple(options),
            via=via,
            detail=detail,
            site=site,
        )
    # The violation's item has its ecosystem's grammar: an item of another grammar (a Docker
    # image) is dropped, even one that happens to read as an Action (``library/alpine``).
    own_grammar = ecosystem is None or finding_item_field(rule, ecosystem) is item_field(ecosystem)
    kept = item if own_grammar and bad[0] is not FindingField.ITEM else None
    return malformed(bad[0], bad[2], ecosystem=ecosystem, place=place, item=kept, version=version, via=via)


def _raw_text(raw: object) -> str:
    """A rejected value as stable text: strings as they are, other simple values by ``repr``,
    anything else by type name (a default ``repr`` holds a memory address, which would make
    the finding ID change between runs)."""
    if isinstance(raw, str):
        return raw
    if raw is None or isinstance(raw, int | float | bytes):
        return repr(raw)
    return f"<{type(raw).__name__}>"


def malformed(
    which: FindingField,
    raw: object,
    *,
    ecosystem: Ecosystem | None,
    place: str | None = None,
    item: str | None = None,
    version: str | None = None,
    via: Iterable[str] = (),
) -> Finding:
    """A malformed-name violation for ``which``; every value that fails its grammar is left out.

    A valid outer-Action chain is kept, so a malformed item reached through two outer
    Actions still gives two findings with two IDs (D14).
    """

    def keep(value: str | None, grammar: Field | None) -> str | None:
        return value if value is not None and grammar is not None and matches(grammar, value) else None

    return Finding(
        Rule.MALFORMED_NAME,
        ecosystem,
        place=keep(place, Field.PATH),
        item=keep(item, item_field(ecosystem) if ecosystem else None),
        version=keep(version, version_field(ecosystem) if ecosystem else None),
        malformed_field=which,
        malformed_value=_raw_text(raw),
        via=_valid_via(ecosystem, via),
        site="findings.malformed-name",
    )


def _valid_via(ecosystem: Ecosystem | None, via: Iterable[str]) -> tuple[str, ...]:
    steps = tuple(via)
    if ecosystem is not Ecosystem.GITHUB_ACTIONS or not all(matches(Field.ACTION_STEP, s) for s in steps):
        return ()
    return steps


_FINDING_FIELDS = {
    Field.PATH: FindingField.PLACE,
    Field.ADVISORY_ID: FindingField.EVIDENCE,
    Field.PEP440_VERSION: FindingField.VERSION,
    Field.GIT_REF: FindingField.VERSION,
    Field.SHA: FindingField.VERSION,
    Field.PYPI_NAME: FindingField.ITEM,
    Field.OWNER_REPO: FindingField.ITEM,
    Field.ACTION: FindingField.ITEM,
    Field.ACTION_STEP: FindingField.VIA,
    Field.DOCKER_IMAGE: FindingField.ITEM,
}


def malformed_from(
    exc: MalformedValueError, *, ecosystem: Ecosystem | None, place: str | None = None
) -> Finding | None:
    """The malformed-name violation for a grammar mismatch raised anywhere inside a check.

    None for a field that is not part of a finding (a date, an override ID): there is no
    finding field to name, so the caller reports only the unfinished check (exit 2).
    """
    which = _FINDING_FIELDS.get(exc.field)
    return malformed(which, exc.value, ecosystem=ecosystem, place=place) if which is not None else None


@dataclass(frozen=True)
class Checked:
    ecosystem: Ecosystem
    place: str | None = None

    def __post_init__(self) -> None:
        _enum(self.ecosystem, Ecosystem)
        if self.place is not None:
            check(Field.PATH, self.place)


@dataclass(frozen=True)
class Skip:
    """An area not checked. An in-scope one built by hand is a refusal: it names its ``site``
    for its negative test (issue #131), which is not a field and reaches no output.

    ``made_from`` is the refusal the skip is built from, when it is not the one being handled
    (``ConfigFileError.skip``, or a failure kept to be listed later): the skip stands for it
    (issue #164). Like ``site``, it is not a field."""

    ecosystem: Ecosystem | None
    place: str | None
    reason: SkipReason
    detail: str | None = None  # text output only (for example an exception's type name)
    _: KW_ONLY
    site: InitVar[str | None] = None
    made_from: InitVar[BaseException | None] = None

    def __post_init__(self, site: str | None, made_from: BaseException | None) -> None:
        _optional_enum(self.ecosystem, Ecosystem)
        _enum(self.reason, SkipReason)
        if self.place is not None:
            check(Field.PATH, self.place)
        if self.reason.in_scope:
            record_site(site, self, made_from=() if made_from is None else (made_from,))

    @property
    def in_scope(self) -> bool:
        return self.reason.in_scope


@dataclass(frozen=True)
class OverrideRecord:
    """An applied or expired override as output shows it (plan §2.2: ID, item, rule, reference,
    category, expiry). ``reason`` is free text a person wrote and appears in text output only."""

    id: str
    ecosystem: Ecosystem
    item: str
    version: str
    rule: Rule
    reference: str
    category: OverrideCategory
    expiry: date
    reason: str = ""

    def __post_init__(self) -> None:
        _required_date(self.expiry)
        _enum(self.ecosystem, Ecosystem)
        _enum(self.rule, Rule)
        _enum(self.category, OverrideCategory)
        check(Field.OVERRIDE_ID, self.id)
        check(item_field(self.ecosystem), self.item)
        check(version_field(self.ecosystem), self.version)
        # T5's override names the inner reference exactly as written (D13, Q2); every other
        # rule takes an advisory ID or a limit name.
        if self.rule is Rule.NESTED_MOVING_REFERENCE:
            check(Field.ACTION_STEP, self.reference)
        elif self.reference not in {name.value for name in LimitName}:
            check(Field.ADVISORY_ID, self.reference)


@dataclass(frozen=True)
class Summary:
    violations: int
    warnings: int
    notices: int
    checked: int
    skipped_in_scope: int
    skipped_out_of_scope: int


@dataclass(frozen=True)
class Result:
    command: Verb
    findings: tuple[Finding, ...] = ()
    checked: tuple[Checked, ...] = ()
    skipped: tuple[Skip, ...] = ()
    overrides_applied: tuple[OverrideRecord, ...] = ()
    overrides_expired: tuple[OverrideRecord, ...] = ()

    def __post_init__(self) -> None:
        _enum(self.command, Verb)
        # Freeze every list as a tuple and check its element type: a one-shot iterator would
        # be used up by the summary, leaving the exit code to read an empty list (exit 0).
        for name, kind in _RESULT_FIELDS:
            values = tuple(getattr(self, name))
            if not all(isinstance(v, kind) for v in values):
                raise TypeError(f"Result.{name} holds only {kind.__name__}")
            object.__setattr__(self, name, values)
        # Equal findings are one fact (one Action used in two jobs of a workflow) and are kept
        # once. Two different findings with one ID would be merged by anything that tracks by
        # ID, and fixing one would hide the other; refuse the result, so the run is unfinished
        # (D14).
        kept: dict[str, Finding] = {}
        for finding in self.findings:
            if kept.setdefault(finding.id, finding) != finding:
                raise DuplicateFindingIdError(finding.id, site="findings.duplicate-finding-id")
        object.__setattr__(self, "findings", tuple(kept.values()))

    @property
    def exit_code(self) -> ExitCode:
        return aggregate_exit_code(self.findings, self.skipped)

    @property
    def summary(self) -> Summary:
        levels = [f.level for f in self.findings]
        return Summary(
            violations=levels.count(Level.VIOLATION),
            warnings=levels.count(Level.WARNING),
            notices=levels.count(Level.NOTICE),
            checked=len(self.checked),
            skipped_in_scope=sum(s.in_scope for s in self.skipped),
            skipped_out_of_scope=sum(not s.in_scope for s in self.skipped),
        )


_RESULT_FIELDS: tuple[tuple[str, type], ...] = (
    ("findings", Finding),
    ("checked", Checked),
    ("skipped", Skip),
    ("overrides_applied", OverrideRecord),
    ("overrides_expired", OverrideRecord),
)


def aggregate_exit_code(findings: Iterable[Finding], skipped: Iterable[Skip]) -> ExitCode:
    """0 every rule met; 1 at least one violation; 2 a check could not finish. 1 wins over 2.

    Out-of-scope skips never change the code; an in-scope skip is never "all rules met".
    """
    if any(f.level is Level.VIOLATION for f in findings):
        return ExitCode.VIOLATION
    if any(s.in_scope for s in skipped):
        return ExitCode.INCOMPLETE
    return ExitCode.RULES_MET


@dataclass(eq=False)
class Built:
    """One refusal built while a test's ``refuses`` block runs (issues #117, #148, #164).

    ``owner`` is what was built: the refusal exception, the in-scope ``Skip``, the violation
    ``Finding``, or None for an exit 2 set by hand. ``carried`` holds the exceptions being handled
    when it was built, with their causes, and the refusal a skip names as ``made_from``: a refusal
    built from another stands for it, so when it reaches the result, so does that one. ``reached``
    is set when the rendered result lists the ``Skip`` or ``Finding`` (a result a test holds is
    read by ``refuses``) or the exit 2 is returned; whether an exception reached the test is read from its
    traceback by ``refuses``. ``site`` is None for a forward that passes on a refusal recorded
    where it was first built (``UnsupportedYamlError``'s ``recorded``)."""

    site: str | None
    owner: object
    carried: tuple[BaseException, ...]
    reached: bool = False


# The refusals built while a test's ``refuses`` block runs (issues #117, #148); None otherwise.
# Every refusal names its site, a fixed ID such as "pin.bad-sha", and records it when it is
# built: a refusal class, an in-scope ``Skip`` built by hand, an exit 2 set by hand through
# ``incomplete_exit`` (issue #131), and a violation ``Finding`` (issue #164). Outside a test
# nothing is set, so recording does nothing: a site never reaches a message, an exit code or any
# output.
_SITES: ContextVar[list[Built] | None] = ContextVar("ssc_guardian_refusal_sites", default=None)
_CALLER = object()  # record_site's default owner: the object whose constructor called it


def _handled() -> tuple[BaseException, ...]:
    """The exception being handled now, if any, with its causes and contexts."""
    chain: list[BaseException] = []
    exc = sys.exc_info()[1]
    while exc is not None and all(exc is not seen for seen in chain):
        chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    return tuple(chain)


def _constructing(caller: FrameType | None) -> object:
    """The exception ``caller``, a refusal class's ``__init__``, is building, or None."""
    owner = caller.f_locals.get("self") if caller is not None else None
    return owner if isinstance(owner, BaseException) else None


def record_site(site: str | None, owner: object = _CALLER, *, made_from: tuple[BaseException, ...] = ()) -> None:
    """Note that the refusal ``site`` was built, if a test is recording; otherwise do nothing.

    ``owner`` is the refusal built. A refusal class's ``__init__`` may leave it out: the
    exception it is building is then read from its frame, only while a test records.
    ``made_from`` holds the refusals this one was built from: it stands for them."""
    built = _SITES.get()
    if built is None or site is None:
        return
    if owner is _CALLER:
        owner = _constructing(sys._getframe(1))
    built.append(Built(site, owner, _handled() + made_from))


def _forward(owner: BaseException) -> None:
    """A refusal built with no site, as a forward of one already recorded: it takes over a
    record just made with no owner (``models._refuse`` records, then builds the error), or is
    noted so that the refusal it was built from reaches the result through it."""
    built = _SITES.get()
    if built is None:
        return
    last = built[-1] if built else None
    if last is not None and last.owner is None and not last.reached:
        last.owner = owner
    else:
        built.append(Built(None, owner, _handled()))


def _built_from(owner: Finding) -> None:
    """A finding built while a refusal is handled stands for it, as a skip does: noted, so the
    refusal reaches the result when the finding does."""
    built = _SITES.get()
    handled = _handled() if built is not None else ()
    if built is not None and handled:
        built.append(Built(None, owner, handled))


def reach(listed: Iterable[object]) -> None:
    """Mark the records of ``listed``, skips or findings, as reaching the result: the result a
    command returns lists them, and it is rendered (``render``). Building a ``Result`` or listing
    one in a collector is not enough: either can be thrown away (issue #164)."""
    built = _SITES.get()
    if built is None:
        return
    for record in built:
        if any(record.owner is item for item in listed):
            record.reached = True


def incomplete_exit(*, site: str) -> int:
    """Exit 2 set by hand, outside a ``Result``: records the refusal ``site`` and returns the code,
    which is the result, so the record has reached it."""
    built = _SITES.get()
    if built is not None:
        built.append(Built(site, None, _handled(), reached=True))
    return int(ExitCode.INCOMPLETE)


class IncompleteCheckError(Exception):
    """Raised by a check that cannot finish. Only in-scope reasons are allowed, so a
    failure can never be reported as an out-of-scope skip (which would keep exit 0).

    ``site`` names the refusal for its negative test (issue #117) and goes into no output."""

    def __init__(self, reason: SkipReason, *, site: str | None = None) -> None:
        if not reason.in_scope:
            raise ValueError(f"{reason} is an out-of-scope reason; a failed check is in scope")
        super().__init__(reason.value)
        self.reason = reason
        if site is not None:
            record_site(site, self)
        else:
            _forward(self)


class DuplicateFindingIdError(IncompleteCheckError, ValueError):
    """Two different findings in one ``Result`` share an ID (D14): the result is refused, so the
    run is unfinished (exit 2) rather than one finding hiding the other. The message names the
    shared ID; the type name is what ``cli.handler-failed`` shows. Still a ``ValueError``."""

    def __init__(self, finding_id: str, *, site: str | None = None) -> None:
        self.finding_id = finding_id
        super().__init__(SkipReason.CHECK_ERROR, site=site)

    def __str__(self) -> str:
        return f"two different findings share one ID: {self.finding_id}"


def _reason_of(exc: IncompleteCheckError) -> object:
    """The error's reason, or None if reading it fails (a subclass that never set it, or a
    property that raises): reading it must not let the failure escape the collector."""
    try:
        return exc.reason
    except KeyboardInterrupt:
        raise
    except BaseException:
        return None


@dataclass
class Collector:
    """Gathers one command's result. A check counts as checked only if it finishes."""

    command: Verb
    findings: list[Finding] = field(default_factory=list)
    checked: list[Checked] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    overrides_applied: list[OverrideRecord] = field(default_factory=list)
    overrides_expired: list[OverrideRecord] = field(default_factory=list)

    @contextmanager
    def check(self, ecosystem: Ecosystem, place: str | None = None) -> Iterator[bool]:
        """Run one check. Any exception records an in-scope skip, so a failed check
        never gives exit 0; findings it added before failing are kept.

        Yields True, or False for a malformed ``place``: that is a malformed-name violation
        recorded here, before the check runs, and the check is listed as unfinished. The body
        should then skip its work (``if not ok``); anything it raises is ignored, and anything
        it adds to this collector is dropped, so a body that ignores the flag adds nothing for
        that place.
        """
        if place is not None and not matches(Field.PATH, place):
            self.findings.append(malformed(FindingField.PLACE, place, ecosystem=ecosystem))
            self._skip(
                Skip(
                    ecosystem,
                    None,
                    SkipReason.CHECK_ERROR,
                    detail="MalformedValueError",
                    site="findings.malformed-place",
                )
            )
            # The collector's lists are the result's fields; restored, not truncated, so a body
            # that reassigns a slice cannot drop the finding above either.
            kept = {name: (getattr(self, name), list(getattr(self, name))) for name, _ in _RESULT_FIELDS}
            try:
                yield False
            except KeyboardInterrupt:
                raise
            except BaseException:  # already recorded as unfinished
                pass
            for name, (held, before) in kept.items():
                held[:] = before
                setattr(self, name, held)
            return
        try:
            yield True
        except IncompleteCheckError as exc:
            # Re-checked here: the constructor's check can be bypassed (a reassigned attribute,
            # a subclass), and an out-of-scope reason would turn a failed check into exit 0.
            reason = _reason_of(exc)
            if isinstance(reason, SkipReason) and reason.in_scope:
                self._skip(Skip(ecosystem, place, reason, site="findings.incomplete-check"))
            else:
                self._skip(
                    Skip(
                        ecosystem,
                        place,
                        SkipReason.CHECK_ERROR,
                        detail=type(exc).__name__,
                        site="findings.reason-out-of-scope",
                    )
                )
        except MalformedValueError as exc:
            # A malformed value is a violation (exit 1), never just an unfinished check;
            # the check it interrupted is still listed as unfinished.
            finding = malformed_from(exc, ecosystem=ecosystem, place=place)
            self.findings.extend([finding] if finding is not None else [])
            self._skip(
                Skip(
                    ecosystem, place, SkipReason.CHECK_ERROR, detail=type(exc).__name__, site="findings.malformed-value"
                )
            )
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # every failure but Ctrl-C, sys.exit() included, is an in-scope skip
            self._skip(
                Skip(ecosystem, place, SkipReason.CHECK_ERROR, detail=type(exc).__name__, site="findings.check-raised")
            )
        else:
            self.checked.append(Checked(ecosystem, place))

    def _skip(self, skip: Skip) -> None:
        """List ``skip``, the check that failed. It reaches the result, and the refusal it was
        built from with it, only when the result this collector gives is rendered or held by a
        test (issue #164)."""
        self.skipped.append(skip)

    def result(self) -> Result:
        return Result(
            self.command,
            tuple(self.findings),
            tuple(self.checked),
            tuple(self.skipped),
            tuple(self.overrides_applied),
            tuple(self.overrides_expired),
        )


@dataclass(frozen=True)
class Scope:
    """What a run checks: the ecosystems left after the scope and filters, and the
    places it is narrowed to. Filters narrow what is checked; they never relax a rule."""

    ecosystems: frozenset[Ecosystem]
    paths: tuple[str, ...] = ()
    repo: str | None = None

    def __post_init__(self) -> None:
        for path in self.paths:
            check(Field.PATH, path)
        if self.repo is not None:
            check(Field.PATH, self.repo)
