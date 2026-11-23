# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Text and JSON renderers: no free text in JSON, control characters stripped (issue #2)."""

from __future__ import annotations

import io
import json
import re
from dataclasses import replace
from typing import Any

import pytest

from ssc_guardian.findings import (
    Checked,
    Ecosystem,
    ExitCode,
    FindingField,
    Label,
    Level,
    LimitName,
    OptionKind,
    OverrideCategory,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    make_finding,
)
from ssc_guardian.grammars import Field, MalformedValueError, matches
from ssc_guardian.render import (
    _SKIP_TEXT,
    CONTRACT,
    FORMAT_VERSION,
    ToolInfo,
    escape_controls,
    strip_controls,
    to_json,
    to_text,
    use_color,
)
from ssc_guardian.settings import FileKind, LayerSource, Settings, parse_settings
from tests.refusal_sites import refuses
from tests.samples import INJECTION, VENV, full_result

pytestmark = pytest.mark.unit

TOOL = ToolInfo("1.0.0.dev0", "0123456789abcdef0123456789abcdef01234567")


def _enum(*enums: Any) -> Any:
    values = {m.value for enum in enums for m in enum}
    return lambda v: v in values


def _grammar(*fields: Field) -> Any:
    return lambda v: any(matches(f, v) for f in fields)


def _command_word(value: str) -> bool:
    if value in {"ssc-guardian", "install", "pin", "protect", "--venv", "--path", "pip", "uv"} or matches(
        Field.PATH, value
    ):
        return True
    name, sep, version = value.partition("==")
    if sep:
        return matches(Field.PYPI_NAME, name) and matches(Field.PEP440_VERSION, version)
    action, sep, ref = value.rpartition("@")
    return bool(sep) and matches(Field.ACTION, action) and matches(Field.GIT_REF, ref)


_ITEM = _grammar(Field.PYPI_NAME, Field.ACTION)
_VERSION = _grammar(Field.PEP440_VERSION, Field.GIT_REF)
# Each JSON string, by its key path, and the one template set or grammar it must match.
KEY_RULES: dict[str, Any] = {
    ".format_version": lambda v: v == FORMAT_VERSION,
    ".tool.name": lambda v: v == "ssc-guardian",
    ".tool.version": _grammar(Field.PEP440_VERSION),
    ".tool.commit": _grammar(Field.SHA),
    ".command": lambda v: v in {verb.value for verb in Verb if not verb.person_only},
    ".findings[].id": lambda v: re.fullmatch(r"[0-9a-f]{32}", v) is not None,
    ".findings[].rule": _enum(Rule),
    ".findings[].level": _enum(Level),
    ".findings[].ecosystem": _enum(Ecosystem),
    ".findings[].place": _grammar(Field.PATH),
    ".findings[].item": _ITEM,
    ".findings[].version": _VERSION,
    ".findings[].evidence[]": _grammar(Field.ADVISORY_ID),
    ".findings[].labels[]": _enum(Label),
    ".findings[].malformed_field": _enum(FindingField),
    ".findings[].via[]": lambda v: "@" in v and _grammar(Field.ACTION)(v.rpartition("@")[0]),
    ".findings[].options[].kind": _enum(OptionKind),
    ".findings[].options[].item": _ITEM,
    ".findings[].options[].version": _VERSION,
    ".findings[].options[].command[]": _command_word,
    ".findings[].options[].eligible_on": _grammar(Field.DATE),
    ".checked[].ecosystem": _enum(Ecosystem),
    ".checked[].place": _grammar(Field.PATH),
    ".skipped[].ecosystem": _enum(Ecosystem),
    ".skipped[].place": _grammar(Field.PATH),
    ".skipped[].reason": _enum(SkipReason),
}
for _kind in ("applied", "expired"):
    KEY_RULES.update(
        {
            f".overrides.{_kind}[].id": _grammar(Field.OVERRIDE_ID),
            f".overrides.{_kind}[].ecosystem": _enum(Ecosystem),
            f".overrides.{_kind}[].item": _ITEM,
            f".overrides.{_kind}[].version": _VERSION,
            f".overrides.{_kind}[].rule": _enum(Rule),
            f".overrides.{_kind}[].reference": lambda v: matches(Field.ADVISORY_ID, v) or _enum(LimitName)(v),
            f".overrides.{_kind}[].category": _enum(OverrideCategory),
            f".overrides.{_kind}[].expiry": _grammar(Field.DATE),
        }
    )


def _strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _strings(v, f"{path}.{k}")]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, f"{path}[]")]
    return []


def test_every_json_string_matches_its_own_key_rule() -> None:
    doc = json.loads(to_json(full_result(), TOOL))
    strings = _strings(doc)
    assert {p for p, _ in strings} <= set(KEY_RULES)
    bad = [(p, v) for p, v in strings if not KEY_RULES[p](v)]
    assert bad == []


def test_instruction_like_override_reason_never_reaches_json() -> None:
    result = full_result()
    assert result.overrides_applied[0].reason == INJECTION
    output = to_json(result, TOOL)
    assert "Ignore all previous" not in output
    assert "instructions" not in output
    assert INJECTION in to_text(result, TOOL)  # a person still sees it


def test_malformed_raw_value_never_reaches_json() -> None:
    output = to_json(full_result(), TOOL)
    assert "bad" not in output
    assert "\\u001b" not in output


def test_exception_commands_never_in_json() -> None:
    result = full_result()
    output = to_json(result, TOOL)
    assert "acknowledge" not in output
    assert "override add" not in output
    assert '"add"' not in output
    text = to_text(result, TOOL)
    assert "needs a person: ssc-guardian override add" in text
    assert "needs a person: ssc-guardian acknowledge someone/new-action" in text
    for verb in (Verb.ACKNOWLEDGE, Verb.OVERRIDE_ADD):
        with pytest.raises(ValueError, match="text only"):
            to_json(Result(verb), TOOL)


def test_exception_and_removal_options_carry_no_command() -> None:
    doc = json.loads(to_json(full_result(), TOOL))
    options = [o for f in doc["findings"] for o in f["options"]]
    person = [o for o in options if o["requires_person"]]
    removal = [o for o in options if o["requires_user_approval"]]
    assert len(person) == 2
    assert len(removal) == 1
    assert all(o["command"] is None for o in person + removal)


def test_text_strips_control_characters() -> None:
    hostile = "/Users/dev/x\x1b[2J\x1b]0;pwned\x07‮evil y\r\n"
    assert strip_controls(hostile) == "/Users/dev/x[2J]0;pwnedevily"
    result = Result(
        Verb.CHECK,
        findings=(make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="ok\x1b[31m‮", version="1"),),
        skipped=(Skip(Ecosystem.PYPI, None, SkipReason.CHECK_ERROR, detail="Err\x1b[0m\x07"),),
    )
    text = to_text(result, TOOL)
    assert re.search(r"[\x00-\x08\x0b-\x1f\x7f\x80-\x9f‪-‮⁦-⁩  ]", text) is None


def test_override_reason_is_stripped_in_text() -> None:
    result = full_result()
    record = result.overrides_applied[0]
    hostile = type(record)(**{**record.__dict__, "reason": "fine\x1b[2J\nINJECTED LINE"})
    text = to_text(Result(Verb.CHECK, overrides_applied=(hostile,)), TOOL)
    assert "\x1b" not in text
    assert "reason: fine[2JINJECTED LINE" in text


def test_colour_only_on_a_terminal_and_never_with_no_color() -> None:
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    assert use_color(Tty(), {}) is True
    assert use_color(Tty(), {"NO_COLOR": ""}) is True  # the NO_COLOR convention: empty means unset
    assert use_color(Tty(), {"NO_COLOR": "1"}) is False
    assert use_color(io.StringIO(), {}) is False
    result = full_result()
    assert "\x1b[" in to_text(result, TOOL, color=True)
    assert "\x1b[" not in to_text(result, TOOL, color=False)


def test_empty_findings_render_identically_in_text_and_json() -> None:
    result = Result(
        Verb.CHECK,
        checked=(Checked(Ecosystem.PYPI, VENV),),
        skipped=(Skip(Ecosystem.GITHUB_ACTIONS, None, SkipReason.FILTERED),),
    )
    doc = json.loads(to_json(result, TOOL))
    text = to_text(result, TOOL)
    s = doc["summary"]
    assert doc["exit_code"] == 0
    assert doc["findings"] == []
    assert (
        f"{s['violations']} violations, {s['warnings']} warnings, {s['notices']} notices; "
        f"{s['checked']} checked, {s['skipped_in_scope']} skipped in scope, {s['skipped_out_of_scope']} out of scope"
    ) in text
    for entry in doc["checked"]:
        assert f"  {entry['ecosystem']} {entry['place']}" in text
    for entry in doc["skipped"]:
        assert f"  {entry['ecosystem']}: excluded by the scope or a filter [out of scope]" in text
    assert "exit 0: every rule met" in text
    # Nothing at all: still the same facts on both sides.
    empty = Result(Verb.CHECK)
    assert json.loads(to_json(empty, TOOL))["summary"] == dict.fromkeys(CONTRACT["summary"], 0)
    assert "0 violations, 0 warnings, 0 notices; 0 checked" in to_text(empty, TOOL)


def _each_level(n: int) -> Result:
    """``n`` violations, ``n`` warnings and ``n`` notices (issue #303)."""
    rules = (Rule.COOLDOWN, Rule.DEGRADED_FEED, Rule.COOLDOWN_WAIT)
    return Result(
        Verb.CHECK, findings=tuple(make_finding(r, Ecosystem.PYPI, item=f"pkg{i}") for r in rules for i in range(n))
    )


def _summary_line(result: Result) -> str:
    return to_text(result, TOOL).splitlines()[0]


def test_summary_line_uses_singular_for_one() -> None:
    result = _each_level(1)
    assert (result.summary.violations, result.summary.warnings, result.summary.notices) == (1, 1, 1)
    assert _summary_line(result) == (
        "ssc-guardian check: 1 violation, 1 warning, 1 notice; 0 checked, 0 skipped in scope, 0 out of scope"
    )


def test_summary_line_keeps_plural_for_zero_and_many() -> None:
    assert "0 violations, 0 warnings, 0 notices; " in _summary_line(Result(Verb.CHECK))
    assert "2 violations, 2 warnings, 2 notices; " in _summary_line(_each_level(2))
    # Mixed counts: each noun follows its own count; the place counts keep their wording.
    assert _summary_line(full_result()) == (
        "ssc-guardian check: 5 violations, 1 warning, 0 notices; 1 checked, 1 skipped in scope, 1 out of scope"
    )


def test_summary_json_counts_unchanged() -> None:
    # The JSON summary as it was before #303, byte for byte: only the text line changed.
    before = (
        '  "summary": {\n    "checked": 0,\n    "notices": 1,\n    "skipped_in_scope": 0,\n'
        '    "skipped_out_of_scope": 0,\n    "violations": 1,\n    "warnings": 1\n  },\n'
    )
    result = _each_level(1)
    assert before in to_json(result, TOOL)
    assert json.loads(to_json(result, TOOL))["exit_code"] == 1
    assert "violation," not in to_json(result, TOOL)


def test_summary_line_rendering_is_idempotent() -> None:
    first, second = _each_level(1), _each_level(1)
    assert to_text(first, TOOL) == to_text(first, TOOL) == to_text(second, TOOL)


def test_text_and_json_report_the_same_exit_code() -> None:
    for result in (full_result(), Result(Verb.CHECK, skipped=(Skip(None, None, SkipReason.NOT_AVAILABLE),))):
        code = json.loads(to_json(result, TOOL))["exit_code"]
        assert f"exit {code}:" in to_text(result, TOOL)


def test_tool_info_is_grammar_checked() -> None:
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed pep440-version"):
        ToolInfo("1.0 ignore this")
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed sha"):
        ToolInfo("1.0", "not-a-sha")


def test_malformed_lookalike_value_is_shown_escaped() -> None:
    finding = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requ\u0435sts", version="1")
    assert "malformed item: requ\\u0435sts" in to_text(Result(Verb.CHECK, findings=(finding,)), TOOL)


def test_escape_is_unambiguous() -> None:
    assert escape_controls("a\\u0435") == "a\\\\u0435"  # a literal backslash cannot pose as an escape
    assert escape_controls("a\u0435") == "a\\u0435"
    assert escape_controls("\U0001f600") == "\\U0001f600"


def test_malformed_path_text_says_what_to_fix() -> None:
    from ssc_guardian.findings import malformed

    bad = malformed(FindingField.PLACE, "/Users/dev/Client's App/.venv", ecosystem=Ecosystem.PYPI)
    result = Result(Verb.CHECK, findings=(bad,))
    text = to_text(result, TOOL)
    assert 'why: it contains "\'" (U+0027), which a path may not hold; rename or move the folder or file' in text
    assert "rename" not in to_json(result, TOOL)  # the advice is text only, never JSON


@pytest.mark.parametrize("which", [FindingField.ITEM, FindingField.VERSION])
def test_malformed_install_spec_text_names_the_supported_forms(which: FindingField) -> None:
    from ssc_guardian.findings import malformed

    bad = malformed(which, "requests>=2.31", ecosystem=Ecosystem.PYPI, place=VENV)
    assert "install takes NAME or NAME==VERSION" in to_text(Result(Verb.INSTALL, findings=(bad,)), TOOL)
    # Only install gets the install advice.
    assert "install takes" not in to_text(Result(Verb.CHECK, findings=(bad,)), TOOL)


_WORKSTATION_FILE = "/Users/me/.config/ssc-guardian/config.toml"
_REPOSITORY_FILE = "/repo/.ssc-guardian.toml"


def _weakened_result() -> Result:
    """A repository file weaker than the workstation's in two keys and one rule (no file sets a
    scope since #255)."""
    workstation = parse_settings(
        'format = 1\n[defaults]\ncooldown_days = 21\nblock_on = "any"\n',
        kind=FileKind.WORKSTATION,
        source=LayerSource.WORKSTATION,
        place=_WORKSTATION_FILE,
        home="/Users/me",
    )
    repository = parse_settings(
        'format = 1\n[defaults]\ncooldown_days = 3\nblock_on = "never"\n'
        '[rules]\n"github-actions:actions/checkout" = { cooldown_days = 2 }\n',
        kind=FileKind.REPOSITORY,
        source=LayerSource.REPOSITORY,
        place=_REPOSITORY_FILE,
    )
    return Result(Verb.CHECK, findings=Settings.of(workstation, repository).notices())


def test_weakened_notice_names_key_and_values_in_text_only() -> None:
    result = _weakened_result()
    # One notice per weaker file and item: the file's defaults are one, its rule another.
    assert [(f.rule, f.place, f.item) for f in result.findings] == [
        (Rule.WEAKENED_SETTING, _REPOSITORY_FILE, None),
        (Rule.WEAKENED_SETTING, _REPOSITORY_FILE, "actions/checkout"),
    ]
    text = to_text(result, TOOL)
    assert ("  detail: cooldown_days 3, applied 21; block_on never, applied any\n") in text
    assert "  detail: cooldown_days 2, applied 21\n" in text
    # Negative: the JSON, the IDs and the exit code are exactly those of the same notices with no detail.
    bare = Result(Verb.CHECK, findings=tuple(replace(f, detail=None) for f in result.findings))
    assert to_json(result, TOOL) == to_json(bare, TOOL)
    assert [f.id for f in result.findings] == [f.id for f in bare.findings]
    assert result.exit_code is bare.exit_code is ExitCode.RULES_MET
    for word in ("detail", "applied 21", "cooldown_days", "block_on", "scope.ecosystems"):
        assert word not in to_json(result, TOOL)


def test_detail_with_control_characters_is_stripped() -> None:
    hostile = "cooldown_days 3\x1b[2J\x1b]0;pwned\x07‮, applied 21\r \nINJECTED LINE"
    notice = make_finding(Rule.WEAKENED_SETTING, None, place=_REPOSITORY_FILE, detail=hostile)
    result = Result(Verb.CHECK, findings=(notice,))
    text = to_text(result, TOOL)
    assert re.search("[\x00-\x08\x0b-\x1f\x7f\x80-\x9f‪-‮⁦-⁩  ]", text) is None
    assert "  detail: cooldown_days 3[2J]0;pwned, applied 21INJECTED LINE\n" in text
    assert "INJECTED" not in to_json(result, TOOL)


@pytest.mark.parametrize("detail", [None, "", "\x1b\x07\r\n", "   "])
def test_empty_detail_prints_nothing(detail: str | None) -> None:
    notice = make_finding(Rule.WEAKENED_SETTING, None, place=_REPOSITORY_FILE, detail=detail)
    text = to_text(Result(Verb.CHECK, findings=(notice,)), TOOL)
    assert "detail" not in text
    assert text == to_text(Result(Verb.CHECK, findings=(replace(notice, detail=None),)), TOOL)


def test_rendering_twice_is_identical() -> None:
    first, second = _weakened_result(), _weakened_result()
    assert first == second
    assert to_text(first, TOOL) == to_text(first, TOOL) == to_text(second, TOOL)
    assert to_json(first, TOOL) == to_json(first, TOOL) == to_json(second, TOOL)


def test_via_chain_is_shown_in_text_and_json() -> None:
    result = full_result()
    nested = next(f for f in result.findings if f.via)
    assert f"via: {nested.via[0]}" in to_text(result, TOOL)
    doc = json.loads(to_json(result, TOOL))
    assert next(f for f in doc["findings"] if f["id"] == nested.id)["via"] == list(nested.via)
    assert all(f["via"] == [] for f in doc["findings"] if f["id"] != nested.id)


def test_local_install_skip_is_out_of_scope_in_json_and_its_detail_is_text_only() -> None:
    detail = "my-tool 1.0: editable install from /Users/me/tool; upload age not checked"
    skip = Skip(Ecosystem.PYPI, VENV, SkipReason.LOCAL_INSTALL, detail=detail)
    result = Result(Verb.CHECK, checked=(Checked(Ecosystem.PYPI, VENV),), skipped=(skip,))
    doc = json.loads(to_json(result, TOOL))
    assert doc["skipped"] == [{"ecosystem": "pypi", "place": VENV, "reason": "local-install", "in_scope": False}]
    assert doc["summary"]["skipped_out_of_scope"] == 1 and doc["summary"]["skipped_in_scope"] == 0
    assert doc["exit_code"] == 0 and doc["format_version"] == FORMAT_VERSION == "1.0"
    assert "/Users/me/tool" not in to_json(result, TOOL)
    text = to_text(result, TOOL)
    assert f"{VENV}: installed from a local folder; the upload age was not checked ({detail}) [out of scope]" in text


@pytest.mark.parametrize("reason", list(SkipReason))
def test_every_skip_reason_has_a_text_line(reason: SkipReason) -> None:
    assert to_text(Result(Verb.CHECK, skipped=(Skip(Ecosystem.PYPI, VENV, reason),)), TOOL)


def test_every_skip_reason_has_a_label() -> None:
    # #282: each reason renders its own line, and the renderer holds no label for a reason the
    # enum lacks (such as the removed `default-scope`).
    assert set(_SKIP_TEXT) == set(SkipReason)
    assert "outside the default scope" not in _SKIP_TEXT.values()
    for reason in SkipReason:
        text = to_text(Result(Verb.CHECK, skipped=(Skip(Ecosystem.PYPI, VENV, reason),)), TOOL)
        assert _SKIP_TEXT[reason] in text


def test_render_is_idempotent_on_re_run() -> None:
    skipped = tuple(Skip(Ecosystem.PYPI, VENV, reason) for reason in SkipReason)
    result = Result(Verb.CHECK, checked=(Checked(Ecosystem.PYPI, VENV),), skipped=skipped)
    assert to_text(result, TOOL) == to_text(result, TOOL)
    assert to_json(result, TOOL) == to_json(result, TOOL)
