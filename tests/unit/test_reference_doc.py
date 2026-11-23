# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``docs/reference.md`` restates the code, and ``docs/contracts.md`` keeps its numbering (#326).

The reference is the user's page; ``docs/contracts.md`` is the frozen design record it
summarizes. Every table in the reference is checked here against the code it restates, so the
reference cannot drift: a value it names that the code does not have, or a value of the code it
omits, is a problem. Each table is found by the first cell of its header row.

- Commands: the verbs, the ``--yes`` and ``--json`` cells (from the parser and ``Verb.person_only``),
  and every ``--flag`` the page names against every long option ``cli.build_parser()`` has.
- Exit codes against ``ExitCode`` and the text footer; rules against ``Rule`` and their levels;
  skip reasons against ``SkipReason``, their scope and their text; the JSON value sets against
  their enums; the JSON key table against ``render.CONTRACT``.
- The JSON example parses, holds every kind of object, and each object has exactly the keys
  ``render.CONTRACT`` names, with values from the enums and a summary that counts its lists.
- Grammars against ``grammars``; settings keys, files and ranges against ``settings``; the
  overridable rules against ``overrides``; the lock-file keys against ``lockfile``.
- Each section links the contracts section it summarizes, by an anchor that exists.
- ``docs/contracts.md`` keeps its eleven ``## `` headings, says it is the design record, has a
  legend for its codes, and no longer repeats the symlinked-folders phrase; the README points at
  the reference, and its quick start, settings and usage patterns send users to the reference,
  not the record, for the output and file formats (#327).

Each check is a function that returns the problems it finds: the real files give none, and a
planted copy gives at least one. The checks read files only and give the same result on a re-run.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable, Iterable
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, grammars, lockfile, overrides, render, settings
from ssc_guardian.findings import (
    Ecosystem,
    ExitCode,
    FindingField,
    Label,
    Level,
    LimitName,
    OptionKind,
    OverrideCategory,
    Rule,
    SkipReason,
    Verb,
)

# doc_content: these tests read docs/reference.md, docs/contracts.md and README.md.
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
REFERENCE = REPO / "docs" / "reference.md"
CONTRACTS = REPO / "docs" / "contracts.md"
README = REPO / "README.md"

# docs/contracts.md's section headings when #326 began. Source docstrings cite these numbers, so
# they never change (the record is frozen).
CONTRACTS_HEADINGS = [
    "## 1. What the checkpoint covers, and what this record does not yet hold",
    "## 2. Commands (plan §2.1)",
    "## 3. Exit codes (plan §2.2)",
    "## 4. Result model (fixed templates)",
    "## 5. JSON format version 1.0",
    "## 6. Field grammars (plan §3.2, R1-K7)",
    "## 7. Plug-in protocol (plan §2.3)",
    "## 8. npm paper test (2026-11-02)",
    "## 9. Owner decisions at the checkpoint (2026-11-02)",
    "## 10. Settings and override files (plan §2.4; issue #3)",
    "## 11. Lock file: `.ssc-guardian.lock` (plan §3.2 T2 and T4; issue #28)",
]
REPEATED_PHRASE = "following symlinked folders under P, following symlinked folders,"

FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
SPAN = re.compile(r"`([^`]+)`")
LONG_OPTION = re.compile(r"(?<![\w-])--[a-z][a-z-]*")
SEPARATOR_CELL = re.compile(r"^:?-+:?$")
CONTRACTS_LINK = re.compile(r"\]\(contracts\.md#([^)\s]+)\)")
# The README sections that name the output or file formats, and the first of the two documents
# each links for them must be the reference (#327).
README_FORMAT_SECTIONS = ("Quick start", "Settings", "Usage patterns")
FORMAT_LINK = re.compile(r"\]\(docs/(reference|contracts)\.md(?:#[^)\s]*)?\)")

Rows = list[list[str]]


# --- reading the documents -----------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _prose(text: str) -> str:
    """*text* with its fenced code blocks blanked, so a sample's lines are never a table row."""
    kept: list[str] = []
    fence = ""
    for line in text.splitlines():
        match = FENCE.match(line)
        if fence:
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
                fence = ""
            kept.append("")
        elif match:
            fence = match.group(1)
            kept.append("")
        else:
            kept.append(line)
    return "\n".join(kept)


def _cells(line: str) -> list[str]:
    inner = line.strip()[1:]
    if inner.endswith("|") and not inner.endswith("\\|"):
        inner = inner[:-1]
    return [cell.replace("\\|", "|").strip() for cell in re.split(r"(?<!\\)\|", inner)]


def tables(text: str) -> list[Rows]:
    """Each Markdown table of *text*'s prose: its header row first, the separator row left out."""
    found: list[Rows] = []
    current: Rows = []
    for line in _prose(text).splitlines():
        if line.lstrip().startswith("|"):
            cells = _cells(line)
            if not all(SEPARATOR_CELL.match(cell) for cell in cells):
                current.append(cells)
        elif current:
            found.append(current)
            current = []
    if current:
        found.append(current)
    return found


def table(text: str, first_header: str) -> Rows:
    """The rows (header left out) of the one table whose header row starts with *first_header*."""
    matching = [t for t in tables(text) if t[0][0] == first_header]
    assert len(matching) == 1, f"{len(matching)} tables start with {first_header!r}"
    return matching[0][1:]


def spans(cell: str) -> list[str]:
    return SPAN.findall(cell)


def first_span(cell: str) -> str:
    found = spans(cell)
    return found[0] if found else cell


def _section(text: str, heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert match, f"no section {heading!r}"
    return match.group(1)


def _names(members: Iterable[Enum]) -> set[str]:
    return {str(member.value) for member in members}


def _set_problems(what: str, shown: Iterable[str], expected: Iterable[str]) -> list[str]:
    listed = list(shown)
    problems = [f"{what}: {name!r} is listed twice" for name in sorted(set(listed)) if listed.count(name) > 1]
    problems += [f"{what}: {name!r} is not in the code" for name in sorted(set(listed) - set(expected))]
    problems += [f"{what}: {name!r} is missing" for name in sorted(set(expected) - set(listed))]
    return problems


# --- the parser ----------------------------------------------------------------------


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _all_parsers(parser: argparse.ArgumentParser) -> list[argparse.ArgumentParser]:
    found = [parser]
    for child in _subparsers(parser).values():
        found += _all_parsers(child)
    return found


def _long_options(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for p in _all_parsers(parser)
        for action in p._actions
        for option in action.option_strings
        if option.startswith("--")
    }


def _verb_parser(parser: argparse.ArgumentParser, verb: Verb) -> argparse.ArgumentParser:
    words = verb.value.split()
    for word in words:
        parser = _subparsers(parser)[word]
    return parser


def _flag_cell(verb: Verb, verb_parser: argparse.ArgumentParser, flag: str) -> str:
    """What the Commands table must say about *flag* for *verb*: the exception commands parse it
    only to refuse it (exit 2); another command accepts it if its parser has it."""
    if verb.person_only:
        return "refused (exit 2)"
    has = any(flag in action.option_strings for action in verb_parser._actions)
    return "accepted" if has else "not accepted"


# --- the checks ----------------------------------------------------------------------


def command_problems(text: str) -> list[str]:
    parser = cli.build_parser()
    rows = table(text, "Command")
    problems = _set_problems("commands", [first_span(r[0]) for r in rows], _names(Verb))
    for row in rows:
        name = first_span(row[0])
        if name not in _names(Verb):
            continue
        verb = Verb(name)
        verb_parser = _verb_parser(parser, verb)
        for flag, cell in (("--yes", row[2]), ("--json", row[3])):
            expected = _flag_cell(verb, verb_parser, flag)
            if cell != expected:
                problems.append(f"{name} {flag}: the table says {cell!r}, the code {expected!r}")
    return problems


def flag_problems(text: str) -> list[str]:
    """Every long option the page names exists in the parser, and every one the parser has is named."""
    named = set(LONG_OPTION.findall(text))
    options = _long_options(cli.build_parser())
    problems = [f"{flag} is not an option of ssc-guardian" for flag in sorted(named - options)]
    problems += [f"{flag} is not named" for flag in sorted(options - named)]
    return problems


def exit_code_problems(text: str) -> list[str]:
    rows = table(text, "Code")
    problems = _set_problems("exit codes", [r[0] for r in rows], {str(int(code)) for code in ExitCode})
    for row in rows:
        if row[0] in {str(int(code)) for code in ExitCode}:
            expected = render._EXIT_TEXT[ExitCode(int(row[0]))]
            if spans(row[2]) != [expected]:
                problems.append(f"exit {row[0]}: the footer is {expected!r}, the table says {row[2]!r}")
    return problems


def rule_problems(text: str) -> list[str]:
    rows = table(text, "Rule")
    problems = _set_problems("rules", [first_span(r[0]) for r in rows], _names(Rule))
    for row in rows:
        name = first_span(row[0])
        if name in _names(Rule) and row[1] != Rule(name).level.value:
            problems.append(f"{name}: level {row[1]!r}, the code {Rule(name).level.value!r}")
    return problems


def skip_reason_problems(text: str) -> list[str]:
    rows = table(text, "Reason")
    problems = _set_problems("skip reasons", [first_span(r[0]) for r in rows], _names(SkipReason))
    for row in rows:
        name = first_span(row[0])
        if name not in _names(SkipReason):
            continue
        reason = SkipReason(name)
        scope = "in scope" if reason.in_scope else "out of scope"
        if row[1] != scope:
            problems.append(f"{name}: scope {row[1]!r}, the code {scope!r}")
        if row[2] != render._SKIP_TEXT[reason]:
            problems.append(f"{name}: text {row[2]!r}, the code {render._SKIP_TEXT[reason]!r}")
    return problems


VALUE_SETS: dict[str, set[str]] = {
    "`command`": {verb.value for verb in Verb if not verb.person_only},
    "`level`": _names(Level),
    "`ecosystem`": _names(Ecosystem),
    "`labels`": _names(Label),
    "`malformed_field`": _names(FindingField),
    "option `kind`": _names(OptionKind),
    "override `category`": _names(OverrideCategory),
    "limit names": _names(LimitName),
}


def value_set_problems(text: str) -> list[str]:
    rows = table(text, "Value set")
    problems = _set_problems("value sets", [r[0] for r in rows], VALUE_SETS)
    for row in rows:
        if row[0] in VALUE_SETS:
            problems += _set_problems(row[0], spans(row[1]), VALUE_SETS[row[0]])
    return problems


def json_key_problems(text: str) -> list[str]:
    rows = table(text, "Object")
    problems = _set_problems("JSON objects", [r[0] for r in rows], render.CONTRACT)
    for row in rows:
        if row[0] in render.CONTRACT:
            problems += _set_problems(f"{row[0]} keys", spans(row[1]), render.CONTRACT[row[0]])
    return problems


def json_example(text: str) -> Any:
    """The one ``json`` fenced block of the JSON output section, parsed."""
    blocks = re.findall(r"^```json\n(.*?)^```", _section(text, "JSON output"), re.M | re.S)
    assert len(blocks) == 1, f"{len(blocks)} json blocks"
    return json.loads(blocks[0])


def _keys(what: str, obj: Any, kind: str) -> list[str]:
    if not isinstance(obj, dict):
        return [f"{what} is not an object"]
    return _set_problems(f"{what} keys", obj, render.CONTRACT[kind])


def example_problems(doc: Any) -> list[str]:
    """Each object of the example has exactly its contract keys, every kind of object appears,
    the values come from the enums, and the summary counts the lists."""
    problems = _keys("result", doc, "result")
    if problems:
        return problems
    problems += _keys("tool", doc["tool"], "tool")
    problems += _keys("summary", doc["summary"], "summary")
    problems += _keys("overrides", doc["overrides"], "overrides")
    if problems:
        return problems
    findings, checked, skipped = doc["findings"], doc["checked"], doc["skipped"]
    options = [o for f in findings if isinstance(f, dict) for o in f.get("options", [])]
    records = [*doc["overrides"]["applied"], *doc["overrides"]["expired"]]
    for kind, objects in (
        ("finding", findings),
        ("option", options),
        ("checked", checked),
        ("skipped", skipped),
        ("override", records),
    ):
        if not objects:
            problems.append(f"the example shows no {kind} object")
        for number, obj in enumerate(objects):
            problems += _keys(f"{kind} {number}", obj, kind)
    if problems:
        return problems
    if doc["format_version"] != render.FORMAT_VERSION or doc["tool"]["name"] != "ssc-guardian":
        problems.append("format_version or tool name differs from the code")
    if doc["command"] not in VALUE_SETS["`command`"]:
        problems.append(f"command {doc['command']!r}")
    for finding in findings:
        if finding["rule"] not in _names(Rule) or finding["level"] != Rule(finding["rule"]).level.value:
            problems.append(f"finding {finding['rule']!r} has level {finding['level']!r}")
        problems += [f"option kind {o['kind']!r}" for o in finding["options"] if o["kind"] not in _names(OptionKind)]
    for skip in skipped:
        if skip["reason"] not in _names(SkipReason) or skip["in_scope"] != SkipReason(skip["reason"]).in_scope:
            problems.append(f"skip {skip['reason']!r} in_scope {skip['in_scope']!r}")
    problems += [
        f"ecosystem {o['ecosystem']!r}"
        for o in (*findings, *checked, *skipped, *records)
        if o["ecosystem"] not in _names(Ecosystem)
    ]
    problems += [f"label {label!r}" for f in findings for label in f["labels"] if label not in _names(Label)]
    problems += [
        f"malformed_field {f['malformed_field']!r}"
        for f in findings
        if f["malformed_field"] is not None and f["malformed_field"] not in _names(FindingField)
    ]
    for record in records:
        if record["category"] not in _names(OverrideCategory):
            problems.append(f"override category {record['category']!r}")
        known = record["ecosystem"] in _names(Ecosystem)
        allowed = overrides.OVERRIDABLE.get(Ecosystem(record["ecosystem"]), ()) if known else ()
        if record["rule"] not in {r.value for r in allowed}:
            problems.append(f"override rule {record['rule']!r}")
    levels = [f["level"] for f in findings]
    counts = {
        "violations": levels.count("violation"),
        "warnings": levels.count("warning"),
        "notices": levels.count("notice"),
        "checked": len(checked),
        "skipped_in_scope": sum(1 for s in skipped if s["in_scope"]),
        "skipped_out_of_scope": sum(1 for s in skipped if not s["in_scope"]),
    }
    problems += [
        f"summary {k} is {doc['summary'][k]}, the lists give {v}" for k, v in counts.items() if doc["summary"][k] != v
    ]
    expected_exit = 1 if counts["violations"] else 2 if counts["skipped_in_scope"] else 0
    if doc["exit_code"] != expected_exit:
        problems.append(f"exit_code {doc['exit_code']}, the lists give {expected_exit}")
    return problems


def grammar_problems(text: str) -> list[str]:
    rows = table(text, "Grammar")
    problems = _set_problems("grammars", [first_span(r[0]) for r in rows], _names(grammars.Field))
    for row in rows:
        name = first_span(row[0])
        if name in _names(grammars.Field):
            longest = grammars._GRAMMARS[grammars.Field(name)][1]
            if row[2] != str(longest):
                problems.append(f"{name}: max length {row[2]!r}, the code {longest}")
    return problems


def settings_problems(text: str) -> list[str]:
    files = {
        settings.SETTINGS_FILE,
        settings.WORKSTATION_SETTINGS_FILE,
        overrides.REPOSITORY_OVERRIDES_FILE,
        overrides.WORKSTATION_OVERRIDES_FILE,
    }
    problems = _set_problems("settings files", [first_span(r[0]) for r in table(text, "File")], files)
    rows = table(text, "Key")
    problems += _set_problems("settings keys", [first_span(r[0]) for r in rows], _names(settings.Key))
    for row in rows:
        name = first_span(row[0])
        if name not in _names(settings.Key):
            continue
        key = settings.Key(name)
        if key in settings._RANGES:
            low, high = settings._RANGES[key]
            if not re.search(rf"(?<!\d){low}–{high}(?!\d)", row[1]):
                problems.append(f"{name}: the range is {low}–{high}, the table says {row[1]!r}")
        elif spans(row[1]) != [b.value for b in settings.BlockOn]:
            problems.append(f"{name}: the values are not {[b.value for b in settings.BlockOn]}")
        built_in = settings.BUILT_IN.get(key)
        shown = "none" if built_in is None else f"`{getattr(built_in, 'value', built_in)}`"
        if row[2] != shown:
            problems.append(f"{name}: built-in {row[2]!r}, the code {shown!r}")
        if key is settings.Key.BLOCK_ON:
            stricter = " < ".join(
                f"`{b.value}`" for b in sorted(settings.BlockOn, key=lambda b: settings._BLOCK_ON_RANK[b])
            )
        else:
            stricter = "larger" if key in settings._LARGER_IS_STRICTER else "smaller"
        if row[3] != stricter:
            problems.append(f"{name}: stricter is {row[3]!r}, the code {stricter!r}")
    return problems


def override_problems(text: str) -> list[str]:
    rows = table(text, "Overridable rule")
    overridable = {rule.value for rules in overrides.OVERRIDABLE.values() for rule in rules}
    problems = _set_problems("overridable rules", [first_span(r[0]) for r in rows], overridable)
    for row in rows:
        name = first_span(row[0])
        if name not in overridable:
            continue
        rule = Rule(name)
        ecosystems = {e.value for e, rules in overrides.OVERRIDABLE.items() if rule in rules}
        problems += _set_problems(f"{name} ecosystems", spans(row[1]), ecosystems)
        if rule in overrides._ADVISORY_REFERENCES:
            references: Iterable[str] = overrides._ADVISORY_REFERENCES[rule]
        elif rule in overrides._LIMIT_REFERENCES:
            references = overrides._LIMIT_REFERENCES[rule]
        else:
            references = ["ACTION@REF"] if rule in overrides._STEP_REFERENCE_RULES else []
        problems += _set_problems(f"{name} references", spans(row[2]), references)
        days, kev_days = overrides.longest_days(rule), overrides.longest_days(rule, kev_listed=True)
        wanted = f"{days} days" + (f"; {kev_days} if KEV-listed" if kev_days != days else "")
        if row[3] != wanted:
            problems.append(f"{name}: longest expiry {row[3]!r}, the code {wanted!r}")
    return problems


def lock_problems(text: str) -> list[str]:
    rows = table(text, "Lock key")
    names = [first_span(r[0]) for r in rows]
    problems = [] if names == list(lockfile._ENTRY_KEYS) else [f"lock keys {names}, the code {lockfile._ENTRY_KEYS}"]
    sources = [r[1] for r in rows if first_span(r[0]) == "trusted_source"]
    if not sources or spans(sources[0]) != [s.value for s in lockfile.TRUSTED_SOURCES]:
        problems.append(f"trusted_source values differ from {[s.value for s in lockfile.TRUSTED_SOURCES]}")
    return problems


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lowercased, punctuation but hyphens dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def contracts_link_problems(text: str, contracts: str) -> list[str]:
    """Each link into docs/contracts.md names a heading there, and each section links one."""
    anchors = {_slug(h) for h in re.findall(r"^#{2,3} (.+)$", _prose(contracts), re.M)}
    problems = [f"contracts.md#{a} names no heading" for a in CONTRACTS_LINK.findall(text) if a not in anchors]
    for heading in re.findall(r"^## (.+)$", _prose(text), re.M):
        if not CONTRACTS_LINK.search(_section(text, heading)):
            problems.append(f"section {heading!r} links no contracts section")
    return problems


def contracts_record_problems(contracts: str) -> list[str]:
    """The record keeps its headings, says it is the design record, has a legend that covers the
    codes it uses, and no longer repeats the symlinked-folders phrase."""
    problems: list[str] = []
    headings = re.findall(r"^## .+$", _prose(contracts), re.M)
    if headings != CONTRACTS_HEADINGS:
        problems.append(f"the ## headings changed: {headings}")
    flat = " ".join(contracts.split())
    if "This is the design record." not in flat or "[docs/reference.md](reference.md)" not in flat:
        problems.append("the header does not say it is the design record behind docs/reference.md")
    if REPEATED_PHRASE in flat:
        problems.append("the symlinked-folders phrase is still repeated")
    legend = table(contracts, "Codes")
    codes = " ".join(row[0] for row in legend)
    rows = [row[0] for row in legend]
    for marker in ("D1–", "Q1–", "B1,", "N6,", "N8,", "N-4", "L1–", "T1–", "R1-K…", "R2-K…", "FC-…", "M1–", "fact N"):
        if not any(row.startswith(marker) or f" {marker}" in row for row in rows):
            problems.append(f"the legend has no row for {marker.rstrip('–,…')}")
    for prefix, high in re.findall(r"\b([A-Z])1–\1(\d+)\b", codes):
        used = [int(n) for n in re.findall(rf"\b{prefix}(\d+)\b", contracts)]
        if used and max(used) > int(high):
            problems.append(f"{prefix}{max(used)} is used but the legend ends at {prefix}{high}")
    return problems


def readme_problems(readme: str) -> list[str]:
    link = "[docs/reference.md](docs/reference.md)"
    problems = [
        f"README.md {heading!r} does not link docs/reference.md"
        for heading in ("Commands", "About these documents")
        if link not in _section(readme, heading)
    ]
    for heading in README_FORMAT_SECTIONS:
        targets = FORMAT_LINK.findall(_section(readme, heading))
        if not targets or targets[0] != "reference":
            problems.append(f"README.md {heading!r} does not send users to docs/reference.md for the formats")
    return problems


# --- tests ---------------------------------------------------------------------------


def _planted_row(text: str, first_header: str, row: str) -> str:
    """*text* with *row* added after the header and separator of the table starting *first_header*."""
    match = re.search(rf"^\| {re.escape(first_header)} \|.*\n\|[-| ]+\|\n", text, re.M)
    assert match, first_header
    return text[: match.end()] + row + "\n" + text[match.end() :]


def test_reference_exit_codes_match_the_code() -> None:
    text = _read(REFERENCE)
    assert exit_code_problems(text) == []
    # Negative: an exit code the code does not have, and a footer that is not the code's.
    assert exit_code_problems(_planted_row(text, "Code", "| 3 | Something else. | `exit 3: no.` |")) == [
        "exit codes: '3' is not in the code"
    ]
    changed = text.replace("`exit 1: at least one violation.`", "`exit 1: a violation.`")
    assert changed != text
    assert len(exit_code_problems(changed)) == 1


def test_reference_skip_reasons_match_the_code() -> None:
    text = _read(REFERENCE)
    assert skip_reason_problems(text) == []
    # Edge case: the removal note names default-scope, which is no table row and no reason.
    assert "`default-scope`" in text and "default-scope" not in _names(SkipReason)
    # Negative control: a planted unknown reason fails.
    planted = _planted_row(text, "Reason", "| `no-such-reason` | in scope | something |")
    assert skip_reason_problems(planted) == ["skip reasons: 'no-such-reason' is not in the code"]
    # A reason left out, or given the wrong scope, fails too.
    without = re.sub(r"^\| `local-install` \|.*\n", "", text, flags=re.M)
    assert skip_reason_problems(without) == ["skip reasons: 'local-install' is missing"]
    wrong = text.replace("| `filtered` | out of scope |", "| `filtered` | in scope |")
    assert wrong != text
    assert len(skip_reason_problems(wrong)) == 1


def test_reference_rules_and_value_sets_match_the_code() -> None:
    text = _read(REFERENCE)
    assert rule_problems(text) == []
    assert value_set_problems(text) == []
    assert json_key_problems(text) == []
    # Negative: a rule at the wrong level, a label the code lacks, a key render.py does not emit.
    assert len(rule_problems(text.replace("| `hidden-pip` | notice |", "| `hidden-pip` | warning |"))) == 1
    planted = text.replace("`actively-exploited`, `registry-quarantined`", "`actively-exploited`, `no-such-label`")
    assert planted != text
    assert len(value_set_problems(planted)) == 2
    assert json_key_problems(
        text.replace("| checked | `ecosystem`, `place` |", "| checked | `ecosystem`, `path` |")
    ) == [
        "checked keys: 'path' is not in the code",
        "checked keys: 'place' is missing",
    ]


def test_reference_json_example_has_every_key() -> None:
    doc = json_example(_read(REFERENCE))
    assert example_problems(doc) == []
    # Negative: a key removed from a finding, a key added to an option, an object kind missing.
    removed = json.loads(json.dumps(doc))
    del removed["findings"][0]["via"]
    assert example_problems(removed) == ["finding 0 keys: 'via' is missing"]
    added = json.loads(json.dumps(doc))
    added["findings"][0]["options"][0]["note"] = "x"
    assert example_problems(added) == ["option 0 keys: 'note' is not in the code"]
    no_skip = json.loads(json.dumps(doc))
    no_skip["skipped"] = []
    assert "the example shows no skipped object" in example_problems(no_skip)
    # Data integrity: a summary that does not count the lists fails.
    miscounted = json.loads(json.dumps(doc))
    miscounted["summary"]["violations"] += 1
    assert len(example_problems(miscounted)) == 1
    # Error path: a value outside its enum fails, in each enum-backed field.
    for planted, expected in (
        (lambda d: d["findings"][0].update(ecosystem="npm"), "ecosystem 'npm'"),
        (lambda d: d["findings"][0]["labels"].append("odd"), "label 'odd'"),
        (lambda d: d["findings"][0].update(malformed_field="name"), "malformed_field 'name'"),
        (lambda d: d["overrides"]["expired"][0].update(category="other"), "override category 'other'"),
        (lambda d: d["overrides"]["expired"][0].update(rule="cooldown"), "override rule 'cooldown'"),
    ):
        wrong = json.loads(json.dumps(doc))
        planted(wrong)
        assert example_problems(wrong) == [expected]


def test_reference_flags_exist_in_the_cli() -> None:
    text = _read(REFERENCE)
    assert flag_problems(text) == []
    assert command_problems(text) == []
    # Error path: a flag the parser lacks fails, and so does a flag the page leaves out.
    assert flag_problems(text + "\nRun `ssc-guardian check --no-such-flag`.\n") == [
        "--no-such-flag is not an option of ssc-guardian"
    ]
    assert flag_problems(text.replace("--envs", "--Envs")) == ["--envs is not named"]
    # The --yes and --json cells follow the parser and the person-only commands.
    wrong = text.replace("| not accepted | accepted |", "| accepted | accepted |")
    assert wrong != text
    assert command_problems(wrong) == ["check --yes: the table says 'accepted', the code 'not accepted'"]


def test_reference_grammars_settings_overrides_and_lock_match_the_code() -> None:
    text = _read(REFERENCE)
    assert grammar_problems(text) == []
    assert settings_problems(text) == []
    assert override_problems(text) == []
    assert lock_problems(text) == []
    # Negative: a wrong max length, a range the code does not use, a reference a rule does not
    # take, lock keys out of order.
    assert len(grammar_problems(text.replace("| 1024 |", "| 2048 |"))) == 1
    assert len(settings_problems(text.replace("whole days, 0–3650", "whole days, 0–365"))) == 1
    # A settings file the code does not read, and a block_on value it does not have, fail.
    assert settings_problems(text.replace(f"`{settings.SETTINGS_FILE}`", "`.guardian.toml`", 1)) == [
        "settings files: '.guardian.toml' is not in the code",
        f"settings files: '{settings.SETTINGS_FILE}' is missing",
    ]
    no_any = re.sub(r"^(\| `block_on` \|[^|]*)`any`", r"\1`all`", text, flags=re.M)
    assert no_any != text
    assert len(settings_problems(no_any)) == 1
    # Edge case: a range that only contains the right one (1–100 holds 1–10) fails too.
    assert (
        len(settings_problems(text.replace("| 1–10; it can only be lowered", "| 1–100; it can only be lowered"))) == 1
    )
    assert len(override_problems(text.replace("an advisory ID: `MAL-` or `GHSA-`", "an advisory ID: `MAL-`"))) == 1
    swapped = re.sub(r"^(\| `sha` \|.*\n)(\| `tag` \|.*\n)", r"\2\1", text, flags=re.M)
    assert swapped != text
    assert len(lock_problems(swapped)) == 1


def test_reference_links_the_contracts_sections() -> None:
    text, contracts = _read(REFERENCE), _read(CONTRACTS)
    assert contracts_link_problems(text, contracts) == []
    # Negative: an anchor that names no heading, and a section with no link.
    planted = text.replace("contracts.md#3-exit-codes-plan-22", "contracts.md#3-exit-codes")
    assert contracts_link_problems(planted, contracts) == [
        "contracts.md#3-exit-codes names no heading",
    ]
    assert contracts_link_problems(text + "\n## Extra\n\nNo link.\n", contracts) == [
        "section 'Extra' links no contracts section"
    ]


def test_contracts_numbering_unchanged() -> None:
    contracts = _read(CONTRACTS)
    assert contracts_record_problems(contracts) == []
    # Edge case: a renumbered or renamed section fails.
    renumbered = contracts.replace("## 6. Field grammars", "## 6. Grammars")
    assert renumbered != contracts
    assert len(contracts_record_problems(renumbered)) == 1
    # The repetition coming back fails, and so does a code the legend's range does not reach.
    repeated = contracts.replace("following symlinked folders under P,", REPEATED_PHRASE, 1)
    assert repeated != contracts
    assert contracts_record_problems(repeated) == ["the symlinked-folders phrase is still repeated"]
    assert contracts_record_problems(contracts + "\nSee D19.\n") == ["D19 is used but the legend ends at D18"]
    # A removed legend row fails, even when another row still holds its letters, and so does a
    # header that no longer says it is the design record.
    no_l = re.sub(r"^\| L1–L3 \|.*\n", "", contracts, flags=re.M)
    assert no_l != contracts
    assert contracts_record_problems(no_l) == ["the legend has no row for L1"]
    no_header = contracts.replace("**This is the design record.**", "**This is a record.**")
    assert no_header != contracts
    assert contracts_record_problems(no_header) == [
        "the header does not say it is the design record behind docs/reference.md"
    ]


def test_readme_points_at_the_reference() -> None:
    readme = _read(README)
    assert readme_problems(readme) == []
    without = readme.replace("[docs/reference.md](docs/reference.md)", "docs/reference.md")
    assert readme_problems(without) == [
        "README.md 'Commands' does not link docs/reference.md",
        "README.md 'About these documents' does not link docs/reference.md",
        "README.md 'Usage patterns' does not send users to docs/reference.md for the formats",
    ]
    # Negative: a format link sent back to docs/contracts.md fails, one section at a time.
    for heading, anchor in (("Quick start", "json-output"), ("Settings", "settings-files")):
        old = f"](docs/reference.md#{anchor})"
        assert readme.count(old) == 1, old
        planted = readme.replace(old, "](docs/contracts.md)")
        assert readme_problems(planted) == [
            f"README.md {heading!r} does not send users to docs/reference.md for the formats"
        ]


CHECKS: tuple[Callable[[], Any], ...] = (
    lambda: command_problems(_read(REFERENCE)),
    lambda: flag_problems(_read(REFERENCE)),
    lambda: exit_code_problems(_read(REFERENCE)),
    lambda: rule_problems(_read(REFERENCE)),
    lambda: skip_reason_problems(_read(REFERENCE)),
    lambda: value_set_problems(_read(REFERENCE)),
    lambda: json_key_problems(_read(REFERENCE)),
    lambda: example_problems(json_example(_read(REFERENCE))),
    lambda: grammar_problems(_read(REFERENCE)),
    lambda: settings_problems(_read(REFERENCE)),
    lambda: override_problems(_read(REFERENCE)),
    lambda: lock_problems(_read(REFERENCE)),
    lambda: contracts_link_problems(_read(REFERENCE), _read(CONTRACTS)),
    lambda: contracts_record_problems(_read(CONTRACTS)),
    lambda: readme_problems(_read(README)),
)


def test_checks_are_idempotent() -> None:
    # Integration: the parser is built in-process each run; two runs give the same result and
    # change no file.
    before = {path: path.read_bytes() for path in (REFERENCE, CONTRACTS, README)}
    first = [check() for check in CHECKS]
    second = [check() for check in CHECKS]
    assert first == second == [[] for _ in CHECKS]
    assert {path: path.read_bytes() for path in before} == before
