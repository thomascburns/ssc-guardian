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

"""Overrides: the one exception system (plan §2.4, R1-B5, R2-K4; contracts §10.4).

An override releases one rule for one exact item and version, for one reference
(an advisory ID or a limit name), until its expiry: at most 90 days from the day it
was written, at most 7 for confirmed malware or a KEV-listed vulnerability. There is
no grace period. Loading is fail-closed: one malformed entry and the whole file
releases nothing. Every run re-checks each override against current facts, and an
unknown fact means not applied: if KEV cannot be reached, or the "fixed version
passes" check cannot finish, the vulnerability counts.

``pypi`` overrides live only in the workstation's ``overrides.toml``,
``github-actions`` overrides only in the repository's ``.ssc-guardian-overrides.toml``.
The file is rewritten whole and atomically by ``override add``; comments are not kept.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum

from ssc_guardian.findings import (
    Ecosystem,
    Finding,
    Label,
    LimitName,
    OverrideCategory,
    OverrideRecord,
    Rule,
    _canonical_id,
    item_field,
)
from ssc_guardian.findings import _id_spelling as item_spelling
from ssc_guardian.findings import _id_version as version_spelling
from ssc_guardian.grammars import Field, matches
from ssc_guardian.settings import (
    FORMAT,
    ConfigFileError,
    FileKind,
    MalformedEntryError,
    atomic_write,
    date_value,
    free_text,
    only_keys,
    parse_document,
    read_text,
    tables,
    text_value,
    toml_string,
    workstation_dir,
)

REPOSITORY_OVERRIDES_FILE = ".ssc-guardian-overrides.toml"
WORKSTATION_OVERRIDES_FILE = "overrides.toml"
HEADER = "# Written by ssc-guardian override add. Comments in this file are not kept.\n"
MAX_DAYS = 90
SHORT_DAYS = 7  # confirmed malware or a KEV-listed vulnerability
QUARANTINED_WHY = "PyPI has quarantined this package"
PARTLY_COVERED_WHY = "the finding's other advisories have no override that applies"

_ADVISORY_REFERENCES: Mapping[Rule, tuple[str, ...]] = {
    Rule.KNOWN_VULNERABILITY: ("CVE-", "GHSA-", "PYSEC-"),
    Rule.COMPROMISE: ("MAL-", "GHSA-"),
    Rule.UNRELEASED_PIN_ADVISORY: ("GHSA-",),
}
_LIMIT_REFERENCES: Mapping[Rule, frozenset[str]] = {
    Rule.NESTING_LIMIT: frozenset({LimitName.NESTING_DEPTH.value, LimitName.NESTED_REFERENCE_COUNT.value}),
    Rule.NESTING_LOOP: frozenset({LimitName.NESTING_LOOP.value}),
}
# T5's inner moving reference: the reference is the inner ACTION@REF exactly as written, and
# the override's item and version are the outer Action and its exact commit (D13, Q2).
_STEP_REFERENCE_RULES = frozenset({Rule.NESTED_MOVING_REFERENCE})
# The rules each ecosystem's overrides may release (§10.4).
OVERRIDABLE: Mapping[Ecosystem, tuple[Rule, ...]] = {
    Ecosystem.PYPI: (Rule.KNOWN_VULNERABILITY, Rule.COMPROMISE),
    Ecosystem.GITHUB_ACTIONS: (
        Rule.KNOWN_VULNERABILITY,
        Rule.COMPROMISE,
        Rule.UNRELEASED_PIN_ADVISORY,
        Rule.NESTED_MOVING_REFERENCE,
        Rule.NESTING_LIMIT,
        Rule.NESTING_LOOP,
    ),
}
KEV_RULES = frozenset({Rule.KNOWN_VULNERABILITY, Rule.UNRELEASED_PIN_ADVISORY})

_FILE_ECOSYSTEM = {FileKind.WORKSTATION: Ecosystem.PYPI, FileKind.REPOSITORY: Ecosystem.GITHUB_ACTIONS}


def utc_today() -> date:
    """Today as the UTC date, for writing ``created`` and checking expiry: every machine and CI
    runner agrees on it, so an entry written east of UTC is never "after today" elsewhere."""
    return datetime.now(UTC).date()


def overrides_path(kind: FileKind, *, repository_root: str | None = None, home: str | None = None) -> str:
    if kind is FileKind.WORKSTATION:
        return os.path.join(workstation_dir(home), WORKSTATION_OVERRIDES_FILE)
    if repository_root is None:
        raise ValueError("the repository's overrides file needs the repository root")
    return os.path.join(repository_root, REPOSITORY_OVERRIDES_FILE)


def file_kind(ecosystem: Ecosystem) -> FileKind:
    """The file an ecosystem's overrides live in."""
    return FileKind.WORKSTATION if ecosystem is Ecosystem.PYPI else FileKind.REPOSITORY


def references_for(rule: Rule) -> str:
    """The references a rule's override takes, in words (for prompts and messages)."""
    if rule in _LIMIT_REFERENCES:
        return " or ".join(sorted(_LIMIT_REFERENCES[rule]))
    if rule in _STEP_REFERENCE_RULES:
        return "the inner reference exactly as written, OWNER/REPO[/PATH]@REF"
    return "an advisory ID starting " + ", ".join(_ADVISORY_REFERENCES[rule])


def reference_problem(rule: Rule, reference: str) -> str | None:
    """Why ``reference`` cannot go with ``rule``, or None if it can."""
    if rule in _STEP_REFERENCE_RULES:
        return (
            None if matches(Field.ACTION_STEP, reference) else f"a {rule.value} override names {references_for(rule)}"
        )
    if rule in _LIMIT_REFERENCES:
        return None if reference in _LIMIT_REFERENCES[rule] else f"a {rule.value} override names {references_for(rule)}"
    prefixes = _ADVISORY_REFERENCES.get(rule)
    if prefixes is None:
        return f"rule {rule.value} cannot be overridden"
    if not (matches(Field.ADVISORY_ID, reference) and reference.startswith(prefixes)):
        return f"a {rule.value} override names {references_for(rule)}"
    return None


def longest_days(rule: Rule, *, kev_listed: bool | None = False) -> int:
    """How long after ``created`` an override for ``rule`` may last."""
    if rule is Rule.COMPROMISE or (rule in KEV_RULES and kev_listed):
        return SHORT_DAYS
    return MAX_DAYS


def rule_problem(ecosystem: Ecosystem, rule: Rule) -> str | None:
    if rule not in OVERRIDABLE[ecosystem]:
        return f"rule {rule.value} cannot be overridden for {ecosystem.value}"
    return None


@dataclass(frozen=True)
class Override:
    """One override entry, checked on construction (except ``created`` against today, which
    the loader checks)."""

    ecosystem: Ecosystem
    item: str
    version: str
    rule: Rule
    reference: str
    category: OverrideCategory
    created: date
    expiry: date
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.ecosystem, Ecosystem) or not isinstance(self.rule, Rule):
            raise MalformedEntryError(
                "ecosystem or rule is not one of the known values", site="overrides.ecosystem-rule-not-one-known"
            )
        if not isinstance(self.category, OverrideCategory):
            raise MalformedEntryError(
                "category is not one of the known values", site="overrides.category-not-one-known-values"
            )
        if not matches(item_field(self.ecosystem), self.item):
            raise MalformedEntryError(
                f"item is not a valid {item_field(self.ecosystem).value}", site="overrides.item-not-valid"
            )
        # An Action's override names the exact commit, never a tag (D13).
        version_grammar = Field.PEP440_VERSION if self.ecosystem is Ecosystem.PYPI else Field.SHA
        if not matches(version_grammar, self.version):
            raise MalformedEntryError(
                f"version is not a valid {version_grammar.value}", site="overrides.version-not-valid"
            )
        problem = rule_problem(self.ecosystem, self.rule) or reference_problem(self.rule, self.reference)
        if problem is not None:
            raise MalformedEntryError(problem, site="overrides.entry-problem")
        date_value(self.created, "created")
        date_value(self.expiry, "expiry")
        if self.expiry < self.created:
            raise MalformedEntryError("expiry is before created", site="overrides.expiry-before-created")
        limit = longest_days(self.rule)
        if (self.expiry - self.created).days > limit:  # never overflows near the end of the calendar
            raise MalformedEntryError(
                f"expiry is more than {limit} days after created", site="overrides.expiry-more-than"
            )
        free_text(self.reason, "reason", required=True)

    @property
    def id(self) -> str:
        """32 hex (D6) over what the override releases, with the item and version in their one
        spelling (D18): ``1.0`` and ``1.0.0`` are one override. Computed, never stored."""
        return _canonical_id(
            self.ecosystem.value,
            item_spelling(self.ecosystem, self.item),
            version_spelling(self.ecosystem, self.version),
            self.rule.value,
            self.reference,
        )

    def record(self) -> OverrideRecord:
        return OverrideRecord(
            self.id,
            self.ecosystem,
            self.item,
            self.version,
            self.rule,
            self.reference,
            self.category,
            self.expiry,
            self.reason,
        )

    def covers(self, finding: Finding) -> bool:
        """Whether ``finding`` is this override's item and version, each in its one spelling
        (D18), as the finding ID compares them; an Action's commit SHA is matched exactly."""
        return (
            finding.ecosystem is self.ecosystem
            and finding.rule is self.rule
            and finding.version is not None
            and version_spelling(self.ecosystem, finding.version) == version_spelling(self.ecosystem, self.version)
            and finding.item is not None
            and item_spelling(self.ecosystem, finding.item) == item_spelling(self.ecosystem, self.item)
        )


# --- loading ----------------------------------------------------------------

_ENTRY_KEYS = ("ecosystem", "item", "version", "rule", "reference", "category", "created", "expiry", "reason")


def parse_overrides(text: str, *, kind: FileKind, place: str | None, today: date) -> tuple[Override, ...]:
    """Every entry of one overrides file. One malformed entry makes the whole file release
    nothing: :class:`ConfigFileError` names the file and the entry."""
    try:
        return _parse_overrides(text, kind, today)
    except MalformedEntryError as exc:
        raise ConfigFileError(place, str(exc), site="overrides.malformed-entry") from exc


def _parse_overrides(text: str, kind: FileKind, today: date) -> tuple[Override, ...]:
    doc = parse_document(text, {"override"})
    entries: list[Override] = []
    ids: set[str] = set()
    for n, raw in enumerate(tables(doc.get("override", []), "override"), start=1):
        where = f"override {n}"
        only_keys(raw, _ENTRY_KEYS, where)
        missing = [key for key in _ENTRY_KEYS if key not in raw]
        if missing:
            raise MalformedEntryError(f"{where} has no {missing[0]}", site="overrides.entry-missing-key")
        try:
            ecosystem = Ecosystem(text_value(raw["ecosystem"], f"{where} ecosystem"))
            rule = Rule(text_value(raw["rule"], f"{where} rule"))
            category = OverrideCategory(text_value(raw["category"], f"{where} category"))
        except ValueError as exc:
            raise MalformedEntryError(f"{where}: {exc}", site="overrides.unknown-enum-value") from None
        if ecosystem is not _FILE_ECOSYSTEM[kind]:
            raise MalformedEntryError(
                f"{where} is a {ecosystem.value} override, which belongs in the other overrides file",
                site="overrides.override-which-belongs-other-overrides",
            )
        try:
            entry = Override(
                ecosystem,
                text_value(raw["item"], f"{where} item"),
                text_value(raw["version"], f"{where} version"),
                rule,
                text_value(raw["reference"], f"{where} reference"),
                category,
                date_value(raw["created"], f"{where} created"),
                date_value(raw["expiry"], f"{where} expiry"),
                text_value(raw["reason"], f"{where} reason"),
            )
        except MalformedEntryError as exc:
            raise MalformedEntryError(f"{where}: {exc}", site="overrides.bad-entry-value") from None
        if entry.created > today:
            raise MalformedEntryError(f"{where}: created is after today", site="overrides.created-after-today")
        if entry.id in ids:
            raise MalformedEntryError(
                f"{where} repeats an earlier override (same id {entry.id})",
                site="overrides.repeats-earlier-override-same-id",
            )
        ids.add(entry.id)
        entries.append(entry)
    return tuple(entries)


def load_overrides(path: str, *, kind: FileKind, today: date) -> tuple[Override, ...]:
    """The overrides at ``path``; none if the file does not exist."""
    text = read_text(path)
    return () if text is None else parse_overrides(text, kind=kind, place=path, today=today)


# --- the per-run re-check ---------------------------------------------------


class Status(StrEnum):
    APPLIED = "applied"
    EXPIRED = "expired"  # listed under overrides.expired
    NOT_APPLIED = "not-applied"  # the finding counts; the stderr note says why


@dataclass(frozen=True)
class Facts:
    """Today's facts about one reference. None means the fact could not be established."""

    kev_listed: bool | None = None  # the advisory is in CISA's KEV catalog
    fix_passes: bool | None = None  # a fixed version passes every rule and installs


UNKNOWN = Facts()


@dataclass(frozen=True)
class Decision:
    override: Override
    status: Status
    why: str  # text output only


def evaluate(override: Override, *, today: date, facts: Facts = UNKNOWN) -> Decision:
    """Whether ``override`` applies today (plan §2.4, R2-K4). No grace period; unknown means
    not applied."""

    def decide(status: Status, why: str) -> Decision:
        return Decision(override, status, why)

    if today > override.expiry:
        return decide(Status.EXPIRED, f"expired on {override.expiry.isoformat()}")
    if override.rule in KEV_RULES:
        if facts.kev_listed is None:
            return decide(Status.NOT_APPLIED, "KEV could not be reached, so the vulnerability counts")
        if facts.kev_listed and today > override.created + timedelta(days=SHORT_DAYS):
            return decide(Status.EXPIRED, f"{override.reference} is KEV-listed and the override is over 7 days old")
    if override.rule is Rule.KNOWN_VULNERABILITY:
        if facts.fix_passes is None:
            return decide(Status.NOT_APPLIED, "the fixed-version check did not finish, so the vulnerability counts")
        if facts.fix_passes:
            return decide(Status.EXPIRED, "a fixed version passes every rule and installs")
    return decide(Status.APPLIED, f"applies until {override.expiry.isoformat()}")


@dataclass(frozen=True)
class Release:
    """What the overrides do to one finding."""

    released: bool
    applied: tuple[OverrideRecord, ...] = ()
    expired: tuple[OverrideRecord, ...] = ()
    not_applied: tuple[Decision, ...] = ()


def alias_groups(evidence: Iterable[str], groups: Iterable[Iterable[str]] | None = None) -> tuple[frozenset[str], ...]:
    """The advisories behind ``evidence``, as one set of IDs each. ``groups`` come from the
    caller that built the finding, one per advisory (its ID and aliases), never guessed from
    ID shapes. Each is cut to the IDs ``evidence`` lists, and an ID in no group is an advisory
    of its own, so with no groups every ID needs its own override."""
    listed = set(evidence)
    given = [group for group in (frozenset(g) & listed for g in groups or ()) if group]
    grouped = frozenset().union(*given)
    return (*given, *(frozenset({i}) for i in sorted(listed - grouped)))


def aliases_of(reference: str, groups: Iterable[Iterable[str]]) -> frozenset[str]:
    """``reference`` and every ID of each advisory it names: the IDs today's facts about it are
    read over (KEV lists CVEs, so a GHSA override's KEV status is its advisory's CVE's)."""
    return frozenset({reference}).union(*(g for g in map(frozenset, groups) if reference in g))


def _named_id(rule: Rule, group: frozenset[str]) -> str:
    """The ID a note names an advisory by: its first that ``override add`` accepts for ``rule``,
    else its first (#94)."""
    return min((i for i in group if i.startswith(_ADVISORY_REFERENCES.get(rule, ()))), default=min(group))


def release(
    finding: Finding,
    overrides: Iterable[Override],
    *,
    today: date,
    facts: Mapping[str, Facts] | None = None,
    references: Iterable[str] | None = None,
    groups: Iterable[Iterable[str]] | None = None,
) -> Release:
    """Release ``finding`` only if every advisory it carries (unless ``references`` names a
    limit or an inner reference) has an override that applies today (D14: one finding lists
    every advisory). An override names its advisory by any one of its IDs (§10.4): ``groups``
    are the advisories' IDs, one group each (:func:`alias_groups`). ``facts`` maps a reference
    to today's facts; a missing one is unknown. A ``registry-quarantined`` finding is never
    released (#87), and an override on an advisory finding that another advisory keeps is
    reported as not applied (#89)."""
    if references is None:
        wanted = finding.evidence
    elif finding.rule in _LIMIT_REFERENCES or finding.rule in _STEP_REFERENCE_RULES:
        if groups is not None:
            # A limit or an inner reference has no aliases: one override never releases two.
            raise ValueError("groups name an advisory's IDs; a limit or an inner reference has none")
        wanted = tuple(references)
    else:
        # An advisory finding is released by all its advisories or not at all (D14).
        raise ValueError("references names a limit; an advisory finding is released by its own evidence")
    known = facts or {}
    decisions = [
        evaluate(o, today=today, facts=known.get(o.reference, UNKNOWN))
        for o in overrides
        if o.covers(finding) and o.reference in wanted
    ]
    # A quarantine is a fact about the registry, not an advisory: no override names it (#70),
    # and one that would otherwise apply is reported as not applied, never dropped (#87).
    quarantined = Label.REGISTRY_QUARANTINED in finding.labels
    if quarantined:
        decisions = [
            Decision(d.override, Status.NOT_APPLIED, QUARANTINED_WHY) if d.status is Status.APPLIED else d
            for d in decisions
        ]
    applied = {d.override.reference for d in decisions if d.status is Status.APPLIED}
    uncovered = [group for group in alias_groups(wanted, groups) if not group & applied]
    released = bool(wanted) and not quarantined and not uncovered
    # An override that releases nothing because another advisory has none that applies is
    # reported, never dropped (#89). A limit finding names its limits, not advisories.
    if applied and uncovered and references is None:
        why = f"{PARTLY_COVERED_WHY}: " + ", ".join(sorted({_named_id(finding.rule, group) for group in uncovered}))
        decisions = [
            Decision(d.override, Status.NOT_APPLIED, why) if d.status is Status.APPLIED else d for d in decisions
        ]
    return Release(
        released,
        applied=tuple(d.override.record() for d in decisions if released and d.status is Status.APPLIED),
        expired=tuple(d.override.record() for d in decisions if d.status is Status.EXPIRED),
        not_applied=tuple(d for d in decisions if d.status is Status.NOT_APPLIED),
    )


# --- writing ----------------------------------------------------------------


def dump_overrides(overrides: Iterable[Override]) -> str:
    lines = [HEADER, f"format = {FORMAT}\n"]
    for o in overrides:
        lines += [
            "\n[[override]]\n",
            f"ecosystem = {toml_string(o.ecosystem.value)}\n",
            f"item = {toml_string(o.item)}\n",
            f"version = {toml_string(o.version)}\n",
            f"rule = {toml_string(o.rule.value)}\n",
            f"reference = {toml_string(o.reference)}\n",
            f"category = {toml_string(o.category.value)}\n",
            f"created = {o.created.isoformat()}\n",
            f"expiry = {o.expiry.isoformat()}\n",
            f"reason = {toml_string(o.reason)}\n",
        ]
    return "".join(lines)


def with_entry(existing: Sequence[Override], new: Override) -> tuple[tuple[Override, ...], Override | None] | None:
    """The file's entries with ``new`` added, and the entry it replaces (same ID), if any.
    None if an identical entry is already there: nothing to write. Never two entries with one ID."""
    for n, old in enumerate(existing):
        if old.id == new.id:
            if old == new:
                return None
            return (*existing[:n], new, *existing[n + 1 :]), old
    return (*existing, new), None


def write_overrides(path: str, overrides: Sequence[Override], *, kind: FileKind, today: date) -> None:
    """Rewrite the file whole and atomically. The text is read back first, so a write can never
    leave a file that would release something other than ``overrides``."""
    text = dump_overrides(overrides)
    if parse_overrides(text, kind=kind, place=path, today=today) != tuple(overrides):
        raise ConfigFileError(
            path, "the overrides did not read back as written", site="overrides.overrides-did-not-read-back"
        )
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, mode=0o700, exist_ok=True)
    atomic_write(path, text)
