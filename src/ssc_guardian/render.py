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

"""Text and JSON renderers, both built from the same :class:`~ssc_guardian.findings.Result` (plan §2.2).

JSON carries only enum values and grammar-checked strings, and never reads a
field that holds free text (override reasons, the raw value of a malformed
name, a finding's or skip's detail, exception commands). Text output strips
control characters from every value it prints, and colours only a terminal
that has not set ``NO_COLOR``.
"""

from __future__ import annotations

import json
import shlex
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TextIO

from ssc_guardian.findings import (
    TOOL_NAME,
    Checked,
    ExitCode,
    Finding,
    FindingField,
    Level,
    Option,
    OptionKind,
    OverrideRecord,
    Result,
    Skip,
    SkipReason,
    Verb,
    reach,
)
from ssc_guardian.grammars import Field, check, path_problem

FORMAT_VERSION = "1.0"

# Every JSON object's exact key set. A key added or removed is a contract change.
CONTRACT: Mapping[str, frozenset[str]] = {
    "result": frozenset(
        {"format_version", "tool", "command", "exit_code", "summary", "findings", "checked", "skipped", "overrides"}
    ),
    "tool": frozenset({"name", "version", "commit"}),
    "summary": frozenset({"violations", "warnings", "notices", "checked", "skipped_in_scope", "skipped_out_of_scope"}),
    "finding": frozenset(
        {
            "id",
            "rule",
            "level",
            "ecosystem",
            "place",
            "item",
            "version",
            "evidence",
            "labels",
            "options",
            "malformed_field",
            "via",
        }
    ),
    "option": frozenset(
        {"kind", "item", "version", "command", "eligible_on", "requires_user_approval", "requires_person"}
    ),
    "checked": frozenset({"ecosystem", "place"}),
    "skipped": frozenset({"ecosystem", "place", "reason", "in_scope"}),
    "overrides": frozenset({"applied", "expired"}),
    "override": frozenset({"id", "ecosystem", "item", "version", "rule", "reference", "category", "expiry"}),
}


@dataclass(frozen=True)
class ToolInfo:
    version: str
    commit: str | None = None

    def __post_init__(self) -> None:
        check(Field.PEP440_VERSION, self.version)
        if self.commit is not None:
            check(Field.SHA, self.commit)


# --- JSON -------------------------------------------------------------------


def _option_json(option: Option) -> dict[str, Any]:
    return {
        "kind": option.kind.value,
        "item": option.item,
        "version": option.version,
        "command": list(option.command) if option.command is not None else None,
        "eligible_on": option.eligible_on.isoformat() if option.eligible_on else None,
        "requires_user_approval": option.kind is OptionKind.REMOVE,
        "requires_person": option.kind is OptionKind.EXCEPTION,
    }


def _finding_json(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "rule": finding.rule.value,
        "level": finding.level.value,
        "ecosystem": finding.ecosystem.value if finding.ecosystem else None,
        "place": finding.place,
        "item": finding.item,
        "version": finding.version,
        "evidence": list(finding.evidence),
        "labels": [label.value for label in finding.labels],
        "options": [_option_json(o) for o in finding.options],
        "malformed_field": finding.malformed_field.value if finding.malformed_field else None,
        "via": list(finding.via),
    }


def _override_json(record: OverrideRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "ecosystem": record.ecosystem.value,
        "item": record.item,
        "version": record.version,
        "rule": record.rule.value,
        "reference": record.reference,
        "category": record.category.value,
        "expiry": record.expiry.isoformat(),
    }


def to_json_obj(result: Result, tool: ToolInfo) -> dict[str, Any]:
    """The JSON contract as a Python object. Refuses the exception commands' results."""
    if result.command.person_only:
        raise ValueError(f"{result.command.value} output is text only")
    summary = result.summary
    shown = {
        "format_version": FORMAT_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool.version, "commit": tool.commit},
        "command": result.command.value,
        "exit_code": int(result.exit_code),
        "summary": {
            "violations": summary.violations,
            "warnings": summary.warnings,
            "notices": summary.notices,
            "checked": summary.checked,
            "skipped_in_scope": summary.skipped_in_scope,
            "skipped_out_of_scope": summary.skipped_out_of_scope,
        },
        "findings": [_finding_json(f) for f in result.findings],
        "checked": [{"ecosystem": c.ecosystem.value, "place": c.place} for c in result.checked],
        "skipped": [
            {
                "ecosystem": s.ecosystem.value if s.ecosystem else None,
                "place": s.place,
                "reason": s.reason.value,
                "in_scope": s.in_scope,
            }
            for s in result.skipped
        ],
        "overrides": {
            "applied": [_override_json(r) for r in result.overrides_applied],
            "expired": [_override_json(r) for r in result.overrides_expired],
        },
    }
    _rendered(result)
    return shown


def to_json(result: Result, tool: ToolInfo) -> str:
    return json.dumps(to_json_obj(result, tool), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


# --- text -------------------------------------------------------------------

# Controls, format characters (bidi), line separators, surrogates (from undecodable
# bytes), private-use and unassigned code points.
_STRIPPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})


def strip_controls(value: object) -> str:
    """``value`` as text with every character in ``_STRIPPED_CATEGORIES`` removed."""
    return "".join(ch for ch in str(value) if unicodedata.category(ch) not in _STRIPPED_CATEGORIES)


def escape_controls(value: object) -> str:
    """Shows every character outside printable ASCII as a ``\\uXXXX`` (or ``\\UXXXXXXXX``) escape.

    Used for the raw value of a malformed name: every grammar is ASCII-only, so a value that
    is malformed only because of an invisible or lookalike character (a Cyrillic "е" in
    "requests") must not print as a valid-looking name.
    """
    return "".join(_escape(ch) for ch in str(value))


def _escape(ch: str) -> str:
    if ch == "\\":
        return "\\\\"  # a literal backslash is doubled, so it cannot imitate an escape
    if " " <= ch <= "~":
        return ch
    return f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}"


def use_color(stream: TextIO, environ: Mapping[str, str]) -> bool:
    """Colour only on a terminal, and never when ``NO_COLOR`` is set to a non-empty value."""
    if environ.get("NO_COLOR", ""):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


_COLOURS = {Level.VIOLATION: "\033[31m", Level.WARNING: "\033[33m", Level.NOTICE: "\033[36m"}
_RESET = "\033[0m"

_SKIP_TEXT = {
    SkipReason.FEED_FAILURE: "a feed could not be read",
    SkipReason.UNKNOWN_AGE: "the age could not be established",
    SkipReason.UNSUPPORTED_YAML: "the file uses YAML Guardian does not read",
    SkipReason.RATE_LIMIT: "the GitHub rate limit was reached",
    SkipReason.DEFAULT_BRANCH_UNREADABLE: "the default branch's settings could not be read",
    SkipReason.CHECK_ERROR: "the check failed",
    SkipReason.NOT_AVAILABLE: "this check is not available in this build",
    SkipReason.FILTERED: "excluded by the scope or a filter",
    SkipReason.LATER_RELEASE: "not covered until a later release",
    SkipReason.DEEPER_THAN_ONE_LEVEL: "not checked: deeper than one level",
    SkipReason.LOCAL_INSTALL: "installed from a local folder; the upload age was not checked",
}

_EXIT_TEXT = {
    ExitCode.RULES_MET: "exit 0: every rule met in what was checked.",
    ExitCode.VIOLATION: "exit 1: at least one violation.",
    ExitCode.INCOMPLETE: "exit 2: a check could not finish. Skipped is unknown, not safe.",
}


def _join(*values: object) -> str:
    return " ".join(strip_controls(v) for v in values if v is not None and v != "")


def _command_text(argv: tuple[str, ...] | list[str]) -> str:
    """A command as the shell reads it, so a path with a space copies and pastes correctly."""
    return shlex.join(strip_controls(word) for word in argv)


def _option_text(option: Option) -> str:
    if option.kind is OptionKind.REPLACE:
        target = _join(option.item, option.version)
        if option.command is not None:
            return f"fix: {target}: {_command_text(option.command)}"
        when = f" (eligible on {option.eligible_on.isoformat()})" if option.eligible_on else ""
        return f"fix: {target}{when}"
    if option.kind is OptionKind.PROTECT:
        return f"fix: {_command_text(option.command or ())}"
    if option.kind is OptionKind.REMOVE:
        return "option: remove it (your decision; Guardian has no remove command)"
    words = [TOOL_NAME, *(option.person_command.value.split() if option.person_command else [])]
    return f"needs a person: {_command_text((*words, *([option.person_target] if option.person_target else [])))}"


def _malformed_why(finding: Finding, command: Verb) -> str | None:
    """What a person can do about a malformed value (D3, D5); text output only."""
    if finding.malformed_field is FindingField.PLACE and finding.malformed_value is not None:
        return f"{path_problem(finding.malformed_value)}; rename or move the folder or file"
    if command is Verb.INSTALL and finding.malformed_field in (FindingField.ITEM, FindingField.VERSION):
        return "install takes NAME or NAME==VERSION, for example requests or requests==2.32.3"
    return None


def _finding_text(finding: Finding, command: Verb, color: bool) -> list[str]:
    level = finding.level.value.upper()
    if color:
        level = f"{_COLOURS[finding.level]}{level}{_RESET}"
    lines = [f"{level} {_join(finding.rule.value, finding.ecosystem, finding.item, finding.version)}"]
    if finding.place is not None:
        lines.append(f"  place: {strip_controls(finding.place)}")
    if finding.via:
        lines.append(f"  via: {' -> '.join(strip_controls(step) for step in finding.via)}")
    detail = strip_controls(finding.detail or "").strip()
    if detail:
        lines.append(f"  detail: {detail}")
    if finding.malformed_field is not None:
        lines.append(f"  malformed {finding.malformed_field.value}: {escape_controls(finding.malformed_value)}")
        why = _malformed_why(finding, command)
        if why is not None:
            lines.append(f"  why: {why}")
    if finding.evidence:
        lines.append(f"  evidence: {', '.join(strip_controls(e) for e in finding.evidence)}")
    if finding.labels:
        lines.append(f"  labels: {', '.join(label.value for label in finding.labels)}")
    lines += [f"  {_option_text(o)}" for o in finding.options]
    lines.append(f"  id: {finding.id}")
    return lines


def _place_text(entry: Checked | Skip) -> str:
    return _join(entry.ecosystem or "all ecosystems", entry.place)


def _override_text(record: OverrideRecord) -> list[str]:
    head = _join(
        record.id, record.ecosystem, record.item, record.version, record.rule, record.reference, record.category
    )
    lines = [f"  {head}, expires {record.expiry.isoformat()}"]
    if record.reason:
        lines.append(f"    reason: {strip_controls(record.reason)}")
    return lines


def _count(n: int, noun: str) -> str:
    """``1 violation``, ``0 violations``, ``2 violations``: the singular only for exactly one (#303)."""
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def to_text(result: Result, tool: ToolInfo, *, color: bool = False) -> str:
    s = result.summary
    counts = ", ".join(
        _count(n, noun) for n, noun in ((s.violations, "violation"), (s.warnings, "warning"), (s.notices, "notice"))
    )
    lines = [
        f"{TOOL_NAME} {result.command.value}: {counts}; "
        f"{s.checked} checked, {s.skipped_in_scope} skipped in scope, {s.skipped_out_of_scope} out of scope"
    ]
    for finding in result.findings:
        lines += ["", *_finding_text(finding, result.command, color)]
    if result.checked:
        lines += ["", "Checked:"] + [f"  {_place_text(c)}" for c in result.checked]
    if result.skipped:
        lines += ["", "Skipped (unknown, not safe):"]
        for skip in result.skipped:
            scope = "in scope" if skip.in_scope else "out of scope"
            detail = f" ({strip_controls(skip.detail)})" if skip.detail else ""
            lines.append(f"  {_place_text(skip)}: {_SKIP_TEXT[skip.reason]}{detail} [{scope}]")
    overrides = (("Overrides applied:", result.overrides_applied), ("Overrides expired:", result.overrides_expired))
    for title, records in overrides:
        if records:
            lines += ["", title]
            for record in records:
                lines += _override_text(record)
    commit = f" ({tool.commit})" if tool.commit else ""
    lines += ["", f"{TOOL_NAME} {tool.version}{commit}, {_EXIT_TEXT[result.exit_code]}"]
    _rendered(result)
    return "\n".join(lines) + "\n"


def _rendered(result: Result) -> None:
    """The result is shown, so the refusals it lists reached it (issue #164): a ``Result`` that
    is built and then thrown away is never rendered. Records nothing outside a test."""
    reach((*result.skipped, *result.findings))
