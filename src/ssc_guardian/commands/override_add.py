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

"""``ssc-guardian override add``: a person writes one override entry (plan §2.1, §2.4;
contracts §10.4).

It refuses ``--yes`` and ``--json`` (the frame does that, D2) and works only with a
person at a terminal. It asks for each field on stderr, checks each answer at once,
shows the entry and the file it will write, and writes only on a yes; for confirmed
malware or a KEV-listed vulnerability a second, stronger warning asks the person to
type the reference ID. Declined, or no answer: nothing written, exit 2 (D15). An
entry identical to one already in the file writes nothing; one with the same ID
replaces it. The file is rewritten atomically.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, timedelta
from typing import TYPE_CHECKING, TextIO, TypeVar

from ssc_guardian.findings import (
    Ecosystem,
    OverrideCategory,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    item_field,
    record_site,
)
from ssc_guardian.grammars import Field, matches
from ssc_guardian.overrides import (
    KEV_RULES,
    OVERRIDABLE,
    Override,
    file_kind,
    load_overrides,
    longest_days,
    overrides_path,
    reference_problem,
    references_for,
    rule_problem,
    utc_today,
    with_entry,
    write_overrides,
)
from ssc_guardian.render import strip_controls
from ssc_guardian.settings import ConfigFileError, MalformedEntryError, find_repository_root, free_text

if TYPE_CHECKING:
    from ssc_guardian.cli import Request

T = TypeVar("T")
TRIES = 3

# Whether an advisory is in CISA's KEV catalog; None when that cannot be established.
KevLookup = Callable[[str], bool | None]


def _kev_unknown(reference: str) -> bool | None:
    return None  # the default when no lookup is injected; the CLI injects KevCatalogLookup (#42)


class _StopError(Exception):
    """Ends the command with nothing written."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


@dataclass
class _Terminal:
    """Asks on stderr. A line that cannot be shown (stderr closed, broken, or None when fd 2
    was closed at start) never raises (contracts §3); once one is lost, the next question
    stops with nothing written, since the person may not have seen what they would answer."""

    stdin: TextIO
    stderr: TextIO | None
    lost: bool = False

    def say(self, line: str) -> None:
        self._show(line + "\n")

    def ask(self, question: str) -> str:
        self._show(question + " ")
        if self.lost:
            raise _StopError("the question could not be shown", site="override_add.question-not-shown")
        answer = self.stdin.readline()
        if not answer:
            raise _StopError("no answer", site="override_add.no-answer")
        return answer.rstrip("\r\n")

    def field(self, question: str, parse: Callable[[str], T]) -> T:
        """Ask until ``parse`` accepts the answer, at most three times."""
        for _ in range(TRIES):
            try:
                return parse(self.ask(question).strip())
            except ValueError as exc:
                self.say(f"  not accepted: {strip_controls(exc)}")
        raise _StopError(f"no accepted answer after {TRIES} tries", site="override_add.no-accepted-answer-after")

    def _show(self, text: str) -> None:
        from ssc_guardian import cli  # imported here: cli imports this handler

        if not cli._show(self.stderr, text):
            self.lost = True


def _choice(kind: Callable[[str], T], values: list[str]) -> Callable[[str], T]:
    def parse(answer: str) -> T:
        if answer not in values:
            raise ValueError(f"answer one of: {', '.join(values)}")
        return kind(answer)

    return parse


def _grammar(grammar: Field) -> Callable[[str], str]:
    def parse(answer: str) -> str:
        if not matches(grammar, answer):
            raise ValueError(f"not a valid {grammar.value}")
        return answer

    return parse


def _expiry(today: date, limit: int) -> Callable[[str], date]:
    def parse(answer: str) -> date:
        if not matches(Field.DATE, answer):
            raise ValueError("write the date as YYYY-MM-DD")
        expiry = date.fromisoformat(answer)
        if expiry < today:
            raise ValueError("the date is in the past")
        if expiry > today + timedelta(days=limit):
            raise ValueError(f"at most {limit} days from today ({(today + timedelta(days=limit)).isoformat()})")
        return expiry

    return parse


def _reason(answer: str) -> str:
    try:
        return free_text(answer, "the reason", required=True)
    except MalformedEntryError as exc:
        raise ValueError(str(exc)) from None


@dataclass(frozen=True)
class OverrideAdd:
    """The ``override add`` handler, with its streams, clock and places injectable for tests."""

    stdin: TextIO | None = None
    stderr: TextIO | None = None
    cwd: str | None = None
    home: str | None = None
    today: date | None = None
    kev_lookup: KevLookup = _kev_unknown

    def __call__(self, request: Request) -> Result:
        term = _Terminal(self.stdin or sys.stdin, self.stderr or sys.stderr)
        if not term.stdin.isatty():
            term.say("ssc-guardian: override add needs a person at a terminal; nothing written.")
            return _stopped("no terminal")
        try:
            return self._run(term, self.today or utc_today())
        except _StopError as stop:
            term.say(f"ssc-guardian: {strip_controls(stop)}; nothing written.")
            return _stopped(str(stop))
        except ConfigFileError as exc:
            term.say(f"ssc-guardian: {strip_controls(exc)}; fix the file by hand. Nothing written.")
            return _stopped("malformed overrides file")

    def _target(self, ecosystem: Ecosystem) -> str:
        kind = file_kind(ecosystem)
        root = None
        if ecosystem is Ecosystem.GITHUB_ACTIONS:
            root = find_repository_root(self.cwd or os.getcwd())
            if root is None:
                raise _StopError(
                    "a github-actions override is written in a repository, and this is not one",
                    site="override_add.github-actions-override-written-repository",
                )
        return overrides_path(kind, repository_root=root, home=self.home)

    def _run(self, term: _Terminal, today: date) -> Result:
        term.say("Writing one override. Each answer is checked as you give it.")
        ecosystem = term.field("Ecosystem (pypi, github-actions):", _choice(Ecosystem, [e.value for e in Ecosystem]))
        path = self._target(ecosystem)
        kind = file_kind(ecosystem)
        existing = load_overrides(path, kind=kind, today=today)
        actions = ecosystem is Ecosystem.GITHUB_ACTIONS
        item = term.field(
            "Action (OWNER/REPO[/PATH]):" if actions else "Package name:", _grammar(item_field(ecosystem))
        )
        version = term.field(
            "Exact commit SHA (40 hex):" if actions else "Exact version:",
            _grammar(Field.SHA if actions else Field.PEP440_VERSION),
        )

        def parse_rule(answer: str) -> Rule:
            try:
                rule = Rule(answer)
            except ValueError:
                raise ValueError(f"answer one of: {', '.join(r.value for r in OVERRIDABLE[ecosystem])}") from None
            problem = rule_problem(ecosystem, rule)
            if problem is not None:
                raise ValueError(problem)
            return rule

        rule = term.field(f"Rule ({', '.join(r.value for r in OVERRIDABLE[ecosystem])}):", parse_rule)

        def parse_reference(answer: str) -> str:
            problem = reference_problem(rule, answer)
            if problem is not None:
                raise ValueError(problem)
            return answer

        reference = term.field(f"Reference ({references_for(rule)}):", parse_reference)
        category = term.field(
            f"Category ({', '.join(c.value for c in OverrideCategory)}):",
            _choice(OverrideCategory, [c.value for c in OverrideCategory]),
        )
        kev = self.kev_lookup(reference) if rule in KEV_RULES else False
        limit = longest_days(rule, kev_listed=kev)
        expiry = term.field(f"Expiry (YYYY-MM-DD, at most {limit} days from today):", _expiry(today, limit))
        reason = term.field("Reason (one line, shown in text output only):", _reason)
        try:
            entry = Override(ecosystem, item, version, rule, reference, category, today, expiry, reason)
        except MalformedEntryError as exc:
            raise _StopError(str(exc), site="override_add.entry-refused") from None

        change = with_entry(existing, entry)
        if change is None:
            term.say(f"This override is already in {strip_controls(path)}; nothing to write.")
            return Result(Verb.OVERRIDE_ADD)
        entries, replaced = change
        self._show(term, entry, replaced, path)
        if rule in KEV_RULES and kev is None:
            term.say(
                f"KEV status of {reference} is unknown: if it is KEV-listed, this override ends "
                f"7 days after {today.isoformat()}."
            )
        if term.ask("Write this override? [y/N]").strip().lower() not in {"y", "yes"}:
            raise _StopError("declined", site="override_add.declined")
        if rule is Rule.COMPROMISE or kev:
            what = "is confirmed malware" if rule is Rule.COMPROMISE else "is in CISA's Known Exploited Vulnerabilities"
            term.say(
                f"WARNING: {reference} {what}. This override lets {item} {version} pass Guardian "
                f"until {expiry.isoformat()}."
            )
            if term.ask(f"Type {reference} to confirm:").strip() != reference:
                raise _StopError("not confirmed", site="override_add.not-confirmed")
        # The file is rewritten whole: if it changed while the person answered, writing now
        # would drop someone else's entries, so stop rather than merge silently.
        if load_overrides(path, kind=kind, today=today) != existing:
            raise _StopError(
                f"{path} changed while you answered; run override add again",
                site="override_add.changed-while-you-answered-run",
            )
        write_overrides(path, entries, kind=kind, today=today)
        term.say(f"Written to {strip_controls(path)}.")
        return Result(Verb.OVERRIDE_ADD)

    @staticmethod
    def _show(term: _Terminal, entry: Override, replaced: Override | None, path: str) -> None:
        term.say(f"Override for {strip_controls(path)}:")
        for name, value in (
            ("ecosystem", entry.ecosystem.value),
            ("item", entry.item),
            ("version", entry.version),
            ("rule", entry.rule.value),
            ("reference", entry.reference),
            ("category", entry.category.value),
            ("created", entry.created.isoformat()),
            ("expiry", entry.expiry.isoformat()),
            ("reason", strip_controls(entry.reason)),
            ("id", entry.id),
        ):
            term.say(f"  {name}: {value}")
        if replaced is not None:
            term.say("  replaces the entry with this id:")
            for name, value in (
                ("item", replaced.item),
                ("category", replaced.category.value),
                ("created", replaced.created.isoformat()),
                ("expiry", replaced.expiry.isoformat()),
                ("reason", strip_controls(replaced.reason)),
            ):
                term.say(f"    {name}: {value}")


def _stopped(detail: str) -> Result:
    """Nothing written: exit 2 (D15)."""
    return Result(
        Verb.OVERRIDE_ADD,
        skipped=(Skip(None, None, SkipReason.CHECK_ERROR, detail=detail, site="override_add.stopped"),),
    )


handle = OverrideAdd()
