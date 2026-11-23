# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Tests for the fail-closed YAML reader (plan §3.2, R1-K7; issue #8)."""

from __future__ import annotations

import re
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from ssc_guardian import yaml_subset as y
from ssc_guardian.findings import Collector, Ecosystem, ExitCode, IncompleteCheckError, SkipReason, Verb
from ssc_guardian.plugins.actions.models import workflow_from
from tests.refusal_sites import Refuses, refuses

pytestmark = pytest.mark.unit

SOURCE = "/repo/.github/workflows/wf.yml"


def _parse(body: str) -> object:
    return y.to_python(y.parse(textwrap.dedent(body).lstrip("\n"), SOURCE))


def _refusal(body: str) -> y.UnsupportedYamlError:
    with pytest.raises(y.UnsupportedYamlError, match=re.escape(f"{SOURCE}:")) as info:
        y.parse(textwrap.dedent(body).lstrip("\n"), SOURCE)
    return info.value


def _assert_refused(body: str, line: int, form: str) -> y.UnsupportedYamlError:
    err = _refusal(body)
    assert (err.line, err.form) == (line, form), str(err)
    assert err.source == SOURCE
    assert str(err).startswith(f"{SOURCE}:{line}: {form}: ")
    return err


def test_anchor_and_alias_refuse_file_with_line() -> None:
    _assert_refused(
        """
        defaults: &base
          shell: bash
        """,
        1,
        "anchor",
    )
    _assert_refused(
        """
        a: 1
        steps:
          - *shared
        """,
        3,
        "alias",
    )
    _assert_refused("- &item value\n", 1, "anchor")
    _assert_refused("&key name: value\n", 1, "anchor")
    _assert_refused("on: [push, *other]\n", 1, "alias")


def test_tag_and_compact_map_refuse_file() -> None:
    _assert_refused("version: !!str 3\n", 1, "tag")
    _assert_refused("a:\n  b: !custom x\n", 2, "tag")
    with refuses("yaml_subset.brace-value"):
        _assert_refused("permissions: {}\n", 1, "compact map")
    _assert_refused("with: {a: b}\n", 1, "compact map")
    _assert_refused("include:\n  - { os: linux }\n", 2, "compact map")
    with refuses("yaml_subset.compact-map-inside-compact-list"):
        _assert_refused("on: [push, {a: b}]\n", 1, "compact map")
    with refuses("yaml_subset.key-value-pair-inside-compact"):
        _assert_refused("on: [push, a: b]\n", 1, "compact map")
    with refuses("yaml_subset.compact-list-inside-compact-list"):
        _assert_refused("on: [[push]]\n", 1, "nested compact form")
    with refuses("yaml_subset.compact-list-does-not-close"):
        _assert_refused("on: [push,\n  pull_request]\n", 1, "multi-line compact list")
    with refuses("yaml_subset.value-starts-reserved-character"):
        _assert_refused("? key\n: value\n", 1, "unrecognised line")
    with refuses("yaml_subset.merges-mapping-alias"):
        _assert_refused("<<: base\n", 1, "merge key")


def test_multiple_documents_refuse_file() -> None:
    with refuses("yaml_subset.second-document-start"):
        _assert_refused("a: 1\n---\nb: 2\n", 2, "multiple documents")
    _assert_refused("---\na: 1\n---\n", 3, "multiple documents")
    with refuses("yaml_subset.content-after-document-end"):
        _assert_refused("a: 1\n...\nb: 2\n", 3, "multiple documents")
    with refuses("yaml_subset.directive"):
        _assert_refused("%YAML 1.2\n---\na: 1\n", 1, "directive")
    # One leading "---", a closing "..." and comments after it are a single document.
    assert _parse("# head\n---\na: 1\n...\n# tail\n") == {"a": "1"}


def test_duplicate_key_anywhere_refuses_file() -> None:
    err = _assert_refused(
        """
        jobs:
          build:
            steps:
              - uses: actions/checkout@v4
                uses: evil/action@main
        """,
        5,
        "duplicate key",
    )
    assert "line 4" in err.detail
    with refuses("yaml_subset.already-set-line"):
        _assert_refused("a: 1\nb: 2\na: 3\n", 3, "duplicate key")
    # Compared after decoding: plain, single- and double-quoted spellings and escapes are one key.
    _assert_refused("uses: a\n'uses': b\n", 2, "duplicate key")
    _assert_refused('"uses": a\nuses: b\n', 2, "duplicate key")
    _assert_refused('uses: a\n"\\x75ses": b\n', 2, "duplicate key")
    _assert_refused('run: a\n"r\\u0075n": b\n', 2, "duplicate key")
    # The same key in two different mappings is not a duplicate.
    assert _parse("a:\n  x: 1\nb:\n  x: 2\n") == {"a": {"x": "1"}, "b": {"x": "2"}}


def test_uses_line_inside_run_block_is_not_an_action() -> None:
    value = _parse(
        """
        steps:
          - name: Build
            run: |
              uses: evil/action@main
              - uses: evil/other@main
              x: &anchor [a, {b: c}]
            # a comment after the block
          - uses: actions/checkout@v4
        """
    )
    assert value == {
        "steps": [
            {"name": "Build", "run": "uses: evil/action@main\n- uses: evil/other@main\nx: &anchor [a, {b: c}]\n"},
            {"uses": "actions/checkout@v4"},
        ]
    }
    # Folded text is text too.
    assert _parse("run: >\n  uses: a/b@c\n") == {"run": "uses: a/b@c\n"}


@pytest.mark.parametrize(
    ("indicator", "expected"),
    [
        ("|", "a\n  b\n\nc\n"),
        ("|-", "a\n  b\n\nc"),
        ("|+", "a\n  b\n\nc\n\n\n"),
        (">", "a\n  b\n\nc\n"),
        (">-", "a\n  b\n\nc"),
        (">+", "a\n  b\n\nc\n\n\n"),
        ("|2", "a\n  b\n\nc\n"),
        ("|2-", "a\n  b\n\nc"),
        ("|-2", "a\n  b\n\nc"),
        ("|+2", "a\n  b\n\nc\n\n\n"),
        ("| # comment", "a\n  b\n\nc\n"),
    ],
)
def test_block_scalar_modifiers(indicator: str, expected: str) -> None:
    text = f"key: {indicator}\n  a\n    b\n\n  c\n\n\nnext: x\n"
    value = y.parse(text, SOURCE)
    assert y.to_python(value) == {"key": expected, "next": "x"}
    assert isinstance(value, y.MappingNode)
    node = value.entries[0].value
    assert isinstance(node, y.ScalarNode) and node.line == 1
    assert node.style is (y.ScalarStyle.FOLDED if indicator.startswith(">") else y.ScalarStyle.LITERAL)


def test_block_scalar_folding_and_indentation_edges() -> None:
    # Folding joins lines with a space, keeps a break per empty line, and keeps more-indented lines.
    assert _parse("k: >\n  one\n  two\n\n  three\n    four\n  five\n") == {"k": "one two\nthree\n  four\nfive\n"}
    # An indentation indicator keeps leading spaces a detected indentation would drop.
    assert _parse("k: |1\n   two spaces\n") == {"k": "  two spaces\n"}
    # A block in a list item, and one at the end of the file with no final line break.
    assert _parse("- |\n  text\n- x\n") == ["text\n", "x"]
    assert _parse("k: |-\n  last") == {"k": "last"}
    # With no final line break, the last line has no break to keep (as libyaml reads it).
    for text, expected in [
        ("k: |\n  last", "last"),
        ("k: >\n  a\n  b", "a b"),
        ("k: |+\n  last\n\n  ", "last\n\n"),
        ("k: |+\n  last\n\n", "last\n\n"),
        ("k: |\n  a\n    ", "a\n  "),
    ]:
        assert y.to_python(y.parse(text, SOURCE)) == {"k": expected}, text
    with (
        refuses("yaml_subset.text-blocks-first-line-starts"),
        pytest.raises(y.UnsupportedYamlError, match="a text block's first line starts with a tab") as info,
    ):
        y.parse("run: |\n  \tq\n", SOURCE)
    assert (info.value.line, info.value.form) == (2, "tab indentation")
    # An empty block, then the next key.
    assert _parse("k: |\nnext: x\n") == {"k": "", "next": "x"}
    # A blank line deeper than the first content line is refused (YAML would mis-indent it).
    # (parse directly: dedent would empty the blank line)
    with (
        refuses("yaml_subset.text-blocks-blank-line-deeper"),
        pytest.raises(y.UnsupportedYamlError, match="a text block's blank line is deeper than its first line") as info,
    ):
        y.parse("k: |\n      \n  text\n", SOURCE)
    assert (info.value.line, info.value.form) == (3, "invalid indentation")
    with refuses("yaml_subset.malformed-text-block-indicator"):
        _assert_refused("k: |x\n  a\n", 1, "unrecognised line")
    _assert_refused("k: |#c\n  a\n", 1, "unrecognised line")


def test_empty_file_and_blank_values() -> None:
    assert y.parse("", SOURCE) is None
    assert y.parse("# only a comment\n\n   \n", SOURCE) is None
    assert y.parse("---\n", SOURCE) is None
    assert _parse("a:\nb: ''\nc: \"\"\nd: []\ne: # comment\n") == {"a": "", "b": "", "c": "", "d": [], "e": ""}
    node = y.parse("a:\n", SOURCE)
    assert isinstance(node, y.MappingNode)
    assert node.entries[0].value == y.ScalarNode("", 1, y.ScalarStyle.PLAIN)
    # Every scalar stays text: no numbers, booleans or nulls are made up.
    assert _parse("on: push\nv: 3.10\nb: true\nn: null\nt: ~\n") == {
        "on": "push",
        "v": "3.10",
        "b": "true",
        "n": "null",
        "t": "~",
    }


def test_invalid_indentation_raises_with_line() -> None:
    with refuses("yaml_subset.deeper-than-value-before"):
        _assert_refused("a:\n  b: '1'\n    c: 2\n", 3, "invalid indentation")
    _assert_refused("a:\n  b: [1]\n    c: 2\n", 3, "invalid indentation")
    with refuses("yaml_subset.mapping-invalid-indentation"):
        _assert_refused("a:\n    b: 1\n  c: 2\n", 3, "invalid indentation")
    _assert_refused("a:\n  - 'x'\n   - y\n", 3, "invalid indentation")
    with refuses("yaml_subset.sequence-invalid-indentation"):
        _assert_refused("a:\n  - b: 1\n   - y\n", 3, "invalid indentation")
    with refuses("yaml_subset.outside-documents-top-level-column"):
        _assert_refused("  a: 1\nb: 2\n", 2, "invalid indentation")
    with refuses("yaml_subset.list-item-where-key-expected"):
        _assert_refused("a: 1\n- b\n", 2, "invalid indentation")
    _assert_refused("a:\n\tb: 1\n", 2, "tab indentation")
    with refuses("yaml_subset.tab-after-list-dash"):
        _assert_refused("a:\n  -\tb\n", 2, "tab indentation")
    # libyaml refuses a tab before a comment or on a blank line too, so the reader does.
    with (
        refuses("yaml_subset.yaml-indentation-must-use-spaces"),
        pytest.raises(y.UnsupportedYamlError, match="YAML indentation must use spaces") as info,
    ):
        y.parse("a: 1\n\t# c\nb: 2\n", SOURCE)
    assert (info.value.line, info.value.form) == (2, "tab indentation")
    with (
        refuses("yaml_subset.yaml-indentation-must-use-spaces"),
        pytest.raises(y.UnsupportedYamlError, match="YAML indentation must use spaces") as info,
    ):
        y.parse("a: 1\n \t\nb: 2\n", SOURCE)
    assert (info.value.line, info.value.form) == (2, "tab indentation")
    # A plain value continued on a deeper line is outside the subset.
    with refuses("yaml_subset.value-continues-deeper-line-column"):
        _assert_refused("if: a &&\n  b\n", 2, "multi-line plain value")
    _assert_refused("a:\n  b: 1\n    c: 2\n", 3, "multi-line plain value")
    _assert_refused("- a\n  b\n", 2, "multi-line plain value")
    _assert_refused("k: |\n    a\n  b\n", 3, "invalid indentation")


@pytest.mark.parametrize(
    ("body", "line", "form", "detail", "site"),
    [
        (
            "a: 1\n[b]: 2\n",
            2,
            "nested compact form",
            "a compact form where a key was expected",
            refuses("yaml_subset.compact-form-where-key-expected"),
        ),
        (
            "a: 1\n{b}: 2\n",
            2,
            "compact map",
            "a compact form where a key was expected",
            refuses("yaml_subset.compact-form-where-key-expected"),
        ),
        (
            "on: [push #c]\n",
            1,
            "multi-line compact list",
            "a compact list does not close on its line",
            refuses("yaml_subset.compact-list-comment-before-close"),
        ),
        (
            "on: ['a' 'b']\n",
            1,
            "unrecognised line",
            "compact list items must be separated by commas",
            refuses("yaml_subset.compact-list-items-must-separated"),
        ),
        (
            "on: [a, , b]\n",
            1,
            "unrecognised line",
            "an empty item in a compact list",
            refuses("yaml_subset.empty-item-compact-list"),
        ),
        (
            "on: [, a]\n",
            1,
            "unrecognised line",
            "an empty item in a compact list",
            refuses("yaml_subset.empty-item-compact-list"),
        ),
        ("a: 1\n: x\n", 2, "unrecognised line", "a key with no name", refuses("yaml_subset.key-no-name")),
        ("- : x\n", 1, "unrecognised line", "a key with no name", refuses("yaml_subset.key-no-name")),
        (
            "@a: 1\n",
            1,
            "unrecognised line",
            "a key starts with a reserved character: '@a'",
            refuses("yaml_subset.key-starts-reserved-character"),
        ),
        (
            "a: 1\n|b: 2\n",
            2,
            "unrecognised line",
            "a key starts with a reserved character: '|b'",
            refuses("yaml_subset.key-starts-reserved-character"),
        ),
        ("- \tb\n", 1, "tab indentation", "a tab after a list dash", refuses("yaml_subset.tab-after-list-dash-indent")),
        (
            "a:\n  |\n    x\n",
            2,
            "unrecognised line",
            "a text block must follow a key or a list dash",
            refuses("yaml_subset.text-block-must-follow-key"),
        ),
        ("--- x\n", 1, "unrecognised line", "content on the '---' line", refuses("yaml_subset.unrecognised-line")),
        (
            "a: 1\n... x\n",
            2,
            "unrecognised line",
            "content on the '...' line",
            refuses("yaml_subset.unrecognised-line"),
        ),
    ],
)
def test_a_line_outside_the_subset_is_refused_by_name(
    body: str, line: int, form: str, detail: str, site: Refuses
) -> None:
    with (
        site,
        pytest.raises(y.UnsupportedYamlError, match=re.escape(f"{SOURCE}:{line}: {form}: {detail}") + r"\Z") as info,
    ):
        y.parse(body, SOURCE)
    assert (info.value.line, info.value.form, info.value.source) == (line, form, SOURCE)


def _entry(text: str) -> None:
    """Hand the parser's entry step one line, as its two callers do after they have checked it."""
    y._Parser([text], last_break=True)._entry(text, 0, 1, [], {})


# Backstops no file reaches (owner's ruling, 2026-11-08): _split_key hands on a key only when the
# line holds one, never one that opens with a compact form or has text after its closing quote,
# and both callers of _entry check the line first. Each check is called directly, so a change to
# _split_key or a caller cannot make it a silent pass.
@pytest.mark.parametrize(
    ("step", "form", "detail", "site"),
    [
        (
            lambda: y._decode_key('"a" b', 1),
            "unrecognised line",
            "text after a quoted key: '\"a\" b'",
            refuses("yaml_subset.text-after-quoted-key"),
        ),
        (
            lambda: y._decode_key("'a' b ", 1),
            "unrecognised line",
            "text after a quoted key: \"'a' b\"",
            refuses("yaml_subset.text-after-quoted-key"),
        ),
        (
            lambda: y._decode_key("[a]", 1),
            "nested compact form",
            "a compact form used as a key",
            refuses("yaml_subset.compact-form-used-key"),
        ),
        (
            lambda: y._decode_key("{a}", 1),
            "compact map",
            "a compact form used as a key",
            refuses("yaml_subset.compact-form-used-key"),
        ),
        (
            lambda: y._decode_key("'a", 1),
            "multi-line quoted key",
            "a quoted key does not close on its line",
            refuses("yaml_subset.quoted-key-does-not-close"),
        ),
        (
            lambda: _entry("plain"),
            "unrecognised line",
            "a line that is neither a key nor a list item",
            refuses("yaml_subset.entry-line-neither-key-nor-list"),
        ),
    ],
)
def test_a_backstop_behind_the_key_split_still_refuses(
    step: Callable[[], object], form: str, detail: str, site: Refuses
) -> None:
    with site, pytest.raises(y._RefusalError) as info:
        step()
    assert (info.value.line, info.value.form, info.value.detail) == (1, form, detail)


def test_quoted_values_and_escapes() -> None:
    assert _parse("""a: 'it''s # not a comment'\nb: "tab\\tend"\nc: "\\u00e9\\x41\\U0001F600" # c\n""") == {
        "a": "it's # not a comment",
        "b": "tab\tend",
        "c": "\u00e9A\U0001f600",
    }
    with refuses("yaml_subset.double-quoted-escape"):
        _assert_refused('a: "\\q"\n', 1, "unsupported escape")
    _assert_refused('a: "\\ud800"\n', 1, "unsupported escape")
    # A quoted value that does not close on its line continues on the next (#203; it was refused).
    assert _parse("a: 'open\n  close'\n") == {"a": "open close"}
    with refuses("yaml_subset.unexpected-text-after-value"):
        _assert_refused('a: "x" y\n', 1, "unrecognised line")
    with refuses("yaml_subset.comment-must-separated-value-space"):
        _assert_refused('a: "x"# c\n', 1, "unrecognised line")


def test_plain_values_lists_and_comments() -> None:
    value = _parse(
        """
        # leading comment
        name: CI   # trailing comment
        url: https://example.com/a#frag
        on:
          push:
            branches: [main, "release/*", 'v1']
        list:
        - a
        - b: 1
          c: 2
        -
          d: 3
        - - x
          - y
        last: done
        """
    )
    assert value == {
        "name": "CI",
        "url": "https://example.com/a#frag",
        "on": {"push": {"branches": ["main", "release/*", "v1"]}},
        "list": ["a", {"b": "1", "c": "2"}, {"d": "3"}, ["x", "y"]],
        "last": "done",
    }
    with refuses("yaml_subset.inside-plain-value-compact-map"):
        _assert_refused("a: b: c\n", 1, "unrecognised line")
    with refuses("yaml_subset.list-same-line-key"):
        _assert_refused("a: - b\n", 1, "unrecognised line")
    _assert_refused("a: @b\n", 1, "unrecognised line")
    with refuses("yaml_subset.trailing-comma-compact-list"):
        _assert_refused("on: [a,]\n", 1, "unrecognised line")
    # In a compact list '?' and ':' are indicators whatever follows ([?x] is a compact map).
    with refuses("yaml_subset.compact-list-item-starts"):
        _assert_refused("on: [a, ?x]\n", 1, "unrecognised line")
    _assert_refused("on: [:c]\n", 1, "unrecognised line")
    with refuses("yaml_subset.bracket-inside-compact-list-item"):
        _assert_refused("on: [x}y]\n", 1, "nested compact form")
    _assert_refused("on: [a, -\tb]\n", 1, "unrecognised line")
    _assert_refused("on: [a b c d] x\n", 1, "unrecognised line")
    with refuses("yaml_subset.mapping-line-neither-key-nor-list"):
        _assert_refused("a: 1\njust text\n", 2, "unrecognised line")
    with refuses("yaml_subset.key-longer-than-1024-characters"):
        _assert_refused("k" * 1025 + ": v\n", 1, "unrecognised line")  # libyaml's 1024-character key limit
    assert _parse("k" * 1024 + ": v\n") == {"k" * 1024: "v"}
    _assert_refused("'" + "k" * 1021 + "'  : v\n", 1, "unrecognised line")  # counted up to the colon


def test_characters_and_encoding_are_checked(tmp_path: Path) -> None:
    with refuses("yaml_subset.not-allowed-subset"):
        err = _assert_refused("a: 1\nb: x\x07\n", 2, "disallowed character")
    assert str(err) == f"{SOURCE}:2: disallowed character: U+0007 is not allowed in this subset"
    err = _assert_refused("a: 1\u2028uses: evil/x@main\n", 1, "disallowed character")
    assert str(err) == f"{SOURCE}:1: disallowed character: U+2028 is not allowed in this subset"
    err = _assert_refused("a: 1\x85b: 2\n", 1, "disallowed character")
    assert str(err) == f"{SOURCE}:1: disallowed character: U+0085 is not allowed in this subset"
    # A BOM after the start: libyaml skips one at the start of any line, so it could hide a key.
    err = _assert_refused("steps:\n  - name: x\n\ufeff    uses: evil/a@main\n", 3, "disallowed character")
    assert str(err) == f"{SOURCE}:3: disallowed character: U+FEFF is not allowed in this subset"
    # CR and CRLF line breaks and a byte-order mark are read as YAML reads them.
    assert y.to_python(y.parse("\ufeffa: 1\r\nb: 2\rc: 3", SOURCE)) == {"a": "1", "b": "2", "c": "3"}
    bad = tmp_path / "wf.yml"
    for data in (b"a: 1\nb: \xff\n", b"a: 1\rb: \xff\r", b"a: 1\r\nb: \xff\r\n"):
        bad.write_bytes(data)
        with (
            refuses("yaml_subset.file-not-utf-8"),
            pytest.raises(y.UnsupportedYamlError, match="the file is not UTF-8") as info,
        ):
            y.load(str(bad))
        assert (info.value.source, info.value.line, info.value.form) == (str(bad), 2, "encoding")


def test_paragraph_separator_refuses_the_file() -> None:
    # #144 item 6: U+2029 (PS) is a line break to some readers and not to others, as U+2028 is,
    # so a step the runner sees could hide inside what this reader takes as one value.
    with refuses("yaml_subset.not-allowed-subset"):
        err = _assert_refused("a: 1\u2029uses: evil/x@main\n", 1, "disallowed character")
    assert str(err) == f"{SOURCE}:1: disallowed character: U+2029 is not allowed in this subset"
    # Its neighbours on either side are ordinary text, so the refusal is of PS itself.
    assert _parse("a: x\u2027y\u202az\n") == {"a": "x\u2027y\u202az"}


def test_document_marker_inside_a_text_block_ends_it() -> None:
    _assert_refused("a: |\n  text\n---\nb: 1\n", 3, "multiple documents")


def test_nesting_depth_is_bounded() -> None:
    deep = "".join(f"{'  ' * i}k{i}:\n" for i in range(80)) + f"{'  ' * 80}v: 1\n"
    with refuses("yaml_subset.nesting-too-deep"):
        _assert_refused(deep, 65, "nesting too deep")


def test_refusal_is_an_unfinished_check_exit_2(tmp_path: Path) -> None:
    path = tmp_path / "wf.yml"
    path.write_text("a: &x 1\n")
    err = _refusal("a: &x 1\n")
    assert isinstance(err, IncompleteCheckError)
    assert err.reason is SkipReason.UNSUPPORTED_YAML

    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.GITHUB_ACTIONS, str(path)):
        y.load(str(path))
    result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.reason, s.place) for s in result.skipped] == [(SkipReason.UNSUPPORTED_YAML, str(path))]
    assert result.checked == ()


# --- Quoted values over several lines (issue #203) -------------------------------------------
# Folded as YAML 1.2.2 §6.5 (line folding) and §7.3 (flow scalars) define. Each input is written
# out exactly (no dedent), so the white space the folding reads is what the test shows.


def _value(text: str) -> object:
    return y.to_python(y.parse(text, SOURCE))


def _refused(text: str, line: int, form: str) -> y.UnsupportedYamlError:
    """As :func:`_assert_refused`, for ``text`` exactly as written."""
    with pytest.raises(y.UnsupportedYamlError, match=re.escape(f"{SOURCE}:{line}: {form}: ")) as info:
        y.parse(text, SOURCE)
    assert (info.value.line, info.value.form, info.value.source) == (line, form, SOURCE)
    return info.value


def test_multiline_single_quoted_value_folds_lines() -> None:
    # The shape of actions/download-artifact v8.0.2's action.yml, line 18 on.
    text = (
        "inputs:\n"
        "  merge-multiple:\n"
        "    description: 'When multiple artifacts are matched, this changes the behavior.  \n"
        "      If true, the downloaded artifacts will be in the same directory.\n"
        "      If false, they''re extracted into individual named directories.'\n"
        "    required: false\n"
    )
    node = y.parse(text, SOURCE)
    assert y.to_python(node) == {
        "inputs": {
            "merge-multiple": {
                "description": "When multiple artifacts are matched, this changes the behavior. "
                "If true, the downloaded artifacts will be in the same directory. "
                "If false, they're extracted into individual named directories.",
                "required": "false",
            }
        }
    }
    # The value's line is the line where it starts; its style is kept.
    assert isinstance(node, y.MappingNode)
    inputs = node.entries[0].value
    assert isinstance(inputs, y.MappingNode)
    merge = inputs.entries[0].value
    assert isinstance(merge, y.MappingNode)
    description = merge.entries[0].value
    assert description == y.ScalarNode(
        "When multiple artifacts are matched, this changes the behavior. "
        "If true, the downloaded artifacts will be in the same directory. "
        "If false, they're extracted into individual named directories.",
        3,
        y.ScalarStyle.SINGLE_QUOTED,
    )
    assert merge.entries[1] == y.Entry("required", 6, y.ScalarNode("false", 6, y.ScalarStyle.PLAIN))
    # In a list item, as the only value of a document, and on the line after its key (deeper
    # than the key, though not as deep as the quote: YAML counts from the key).
    assert _value("- 'a\n  b'\n- c\n") == ["a b", "c"]
    assert _value("'a\nb'\n") == "a b"
    assert _value("k:\n  'a\n b'\n") == {"k": "a b"}
    # A single quote has no escapes: a backslash at the end of a line is text and folds.
    assert _value("k: 'a\\\n  b'\n") == {"k": "a\\ b"}


def test_multiline_double_quoted_value_folds_and_escaped_break_joins() -> None:
    assert _value('k: "one\n  two \\t\n  three"\n') == {"k": "one two \t three"}
    # A backslash at the end of a line joins the lines with nothing between them, and keeps
    # the white space before it; the next line's leading white space is still dropped.
    assert _value('k: "abc\\\n    def"\n') == {"k": "abcdef"}
    assert _value('k: "abc \\\n    def"\n') == {"k": "abc def"}
    # White space written by an escape is text, so it is kept at the end of a folded line.
    assert _value('k: "a\\t\n  b"\n') == {"k": "a\t b"}
    assert _value('k: "a\\ \n  b"\n') == {"k": "a  b"}
    # CRLF and CR line breaks fold as LF does, an escaped break before them included.
    assert _value("a: 'x\r\n  y'\r\nb: 1\r\n") == {"a": "x y", "b": "1"}
    assert _value('a: "x\\\r\n  y"\r\n') == {"a": "xy"}
    assert _value("a: 'x\r\r  y'\rb: 1\r") == {"a": "x\ny", "b": "1"}
    # Escapes on a later line decode as on the first.
    assert _value('k: "x\n  \\u00e9\\x41\\"q\\""\n') == {"k": 'x \u00e9A"q"'}
    with refuses("yaml_subset.double-quoted-escape"):
        _refused('k: "x\n  \\q"\n', 2, "unsupported escape")


def test_multiline_quoted_empty_line_becomes_newline() -> None:
    assert _value("k: 'a\n\n  b'\n") == {"k": "a\nb"}
    assert _value("k: 'a\n\n\n  b'\n") == {"k": "a\n\nb"}
    # A line of only spaces is empty at any indentation, and a quote may open or close a line.
    assert _value('k: "a\n        \n \n  b"\n') == {"k": "a\n\nb"}
    assert _value("k: '\n  a\n  '\n") == {"k": " a "}
    # After an escaped break, each empty line is a line feed too.
    assert _value('k: "a\\\n\n  b"\n') == {"k": "a\nb"}


def test_multiline_quoted_matches_yaml_spec_examples() -> None:
    # Example 7.5, Double Quoted Line Breaks, exactly as the spec writes it.
    assert (
        _value('"folded \nto a space,\t\n \nto a line feed, or \t\\\n \\ \tnon-content"\n')
        == "folded to a space,\nto a line feed, or \t \tnon-content"
    )
    # Examples 6.8 (Flow Folding), 7.6 (Double Quoted Lines) and 7.9 (Single Quoted Lines) put
    # a tab in a line's leading white space, which YAML allows and this reader refuses (#203
    # Approach step 2). With that tab a space, they read as the spec says.
    assert _value('"\n  foo\t\n \n   bar\n\n  baz\n"\n') == " foo\nbar\nbaz "
    assert (
        _value('" 1st non-empty\n\n 2nd non-empty \n 3rd non-empty "\n')
        == " 1st non-empty\n2nd non-empty 3rd non-empty "
    )
    assert (
        _value("' 1st non-empty\n\n 2nd non-empty\t\n 3rd non-empty '\n")
        == " 1st non-empty\n2nd non-empty 3rd non-empty "
    )
    with refuses("yaml_subset.quoted-value-line-tab"):
        _refused('" 1st non-empty\n\n 2nd non-empty \n\t3rd non-empty "\n', 4, "tab indentation")
    _refused("' 1st non-empty\n\n 2nd non-empty\t\n\t3rd non-empty '\n", 4, "tab indentation")
    _refused('"\n  foo\t\n \n  \tbar\n\n  baz\n"\n', 4, "tab indentation")


def test_unclosed_quote_at_end_of_file_refuses(tmp_path: Path) -> None:
    with refuses("yaml_subset.quoted-value-does-not-close"):
        err = _refused("a: 'open\n  more\n", 1, "unclosed quoted value")
    assert str(err) == (
        f"{SOURCE}:1: unclosed quoted value: "
        "a quoted value opened on this line does not close before the end of the file"
    )
    _refused('a: 1\nb: "open\n\n  more', 2, "unclosed quoted value")
    _refused("- 'open\n", 1, "unclosed quoted value")
    # The whole file is refused, and the check is unfinished (exit 2).
    path = tmp_path / "action.yml"
    path.write_text("name: x\ndescription: 'open\n  never closed\n  runs:\n    using: node20\n")
    collector = Collector(Verb.CHECK)
    with refuses("yaml_subset.quoted-value-does-not-close"):
        with collector.check(Ecosystem.GITHUB_ACTIONS, str(path)):
            y.load(str(path))
        result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.reason, s.place) for s in result.skipped] == [(SkipReason.UNSUPPORTED_YAML, str(path))]
    assert result.checked == ()


def test_continuation_not_deeper_than_key_refuses() -> None:
    with refuses("yaml_subset.quoted-value-line-not-deeper"):
        err = _refused("a:\n  b: 'x\n  y'\n", 3, "invalid indentation")
    assert err.detail == "a quoted value continues at column 2, not deeper than its key or dash at 2"
    _refused("a: 'x\ny'\n", 2, "invalid indentation")
    _refused("a: 'x\n'\n", 2, "invalid indentation")  # the closing line too
    _refused("- 'x\ny'\n", 2, "invalid indentation")
    _refused("- k: 'x\n  y'\n", 2, "invalid indentation")  # the key is at column 2
    assert _value("- k: 'x\n   y'\n") == [{"k": "x y"}]
    # A deeper line after the closing quote is still refused, as after a one-line value.
    with refuses("yaml_subset.deeper-than-value-before"):
        _refused("a: 'x\n  y'\n  b: 1\n", 3, "invalid indentation")


def test_text_after_closing_quote_on_continuation_refuses() -> None:
    with refuses("yaml_subset.unexpected-text-after-value"):
        err = _refused("a: 'x\n  y' z\nb: 1\n", 2, "unrecognised line")
    assert err.detail == "unexpected text after a value: 'z'"
    with refuses("yaml_subset.comment-must-separated-value-space"):
        _refused('a: "x\n  y"# c\n', 2, "unrecognised line")
    # Spaces and a comment may follow the closing quote.
    assert _value("a: 'x\n  y'   # a comment\nb: 1\n") == {"a": "x y", "b": "1"}


def test_multiline_quoted_key_and_compact_list_still_refuse() -> None:
    with refuses("yaml_subset.multi-line-quoted-key"):
        _refused("a: 1\n'b\n  c': 2\n", 2, "multi-line quoted key")
    with refuses("yaml_subset.quoted-key-spans-lines"):
        _refused("- 'b\n  c': 2\n", 1, "multi-line quoted key")
    _refused('"b\n c": 2\n', 1, "multi-line quoted key")
    _refused("a: 'b\n  c': 2\n", 1, "multi-line quoted key")
    with refuses("yaml_subset.compact-list-quoted-item-does-not-close"):
        _refused("on: ['a,\n  b']\n", 1, "multi-line compact list")
    with refuses("yaml_subset.compact-list-does-not-close"):
        _refused("on: [a,\n  b]\n", 1, "multi-line compact list")
    # Multi-line plain values stay refused.
    with refuses("yaml_subset.value-continues-deeper-line-column"):
        _refused("a: x\n  y\n", 2, "multi-line plain value")


def test_tab_or_document_marker_in_continuation_refuses() -> None:
    with refuses("yaml_subset.quoted-value-line-tab"):
        _refused("a: 'x\n\ty'\n", 2, "tab indentation")
    _refused("a: 'x\n  \ty'\n", 2, "tab indentation")
    _refused("a: 'x\n \t\n  y'\n", 2, "tab indentation")  # on an empty line too
    # A tab after the line's first character is text.
    assert _value("a: 'x\n  y\tz'\n") == {"a": "x y\tz"}
    with refuses("yaml_subset.document-marker-inside-quoted-value"):
        err = _refused("'x\n---\ny'\n", 2, "document marker")
    assert err.detail == "a line starting '---' at column 0 inside a quoted value"
    _refused("'x\n...\ny'\n", 2, "document marker")
    _refused("a: 'x\n--- y'\n", 2, "document marker")
    _refused("'x\n...y'\n", 2, "document marker")
    # Deeper than column 0 it is text.
    assert _value("'x\n --- y'\n") == "x --- y"


def test_uses_line_inside_multiline_quote_is_text() -> None:
    text = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: 'Build\n"
        "          uses: evil/action@main\n"
        "          - uses: evil/other@main\n"
        "          # not a comment\n"
        "          x: &anchor [a, {b: c}]'\n"
        "      - uses: actions/checkout@v4\n"
    )
    value = y.to_python(y.parse(text, SOURCE))
    assert value == {
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Build uses: evil/action@main - uses: evil/other@main "
                        "# not a comment x: &anchor [a, {b: c}]"
                    },
                    {"uses": "actions/checkout@v4"},
                ],
            }
        },
    }
    workflow = workflow_from(y.parse(text, SOURCE), SOURCE)
    assert [s.uses.raw for job in workflow.jobs for s in job.steps if s.uses is not None] == ["actions/checkout@v4"]


def test_multiline_quoted_read_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "action.yml"
    data = b"description: 'a\n  b'\ninputs:\n  x:\n    description: \"c\\\n      d\n\n      e\"\n"
    path.write_bytes(data)
    first = y.load(str(path))
    second = y.load(str(path))
    assert first == second
    assert y.to_python(first) == {"description": "a b", "inputs": {"x": {"description": "cd\ne"}}}
    assert path.read_bytes() == data  # read-only


# --- a refusal echoes at most ECHO_LIMIT characters of the file (#230, L3-6) ----------------

_LONG = 100_000  # the audit's nested action.yml tail was 900,000 characters
_KEY = 1000  # a key is refused past 1024 characters before its text is read


@pytest.mark.parametrize(
    ("body", "site"),
    [
        (f'a: "x" {"y" * _LONG}\n', refuses("yaml_subset.unexpected-text-after-value")),
        (f"@{'y' * _KEY}: 1\n", refuses("yaml_subset.key-starts-reserved-character")),
        (f"{'k' * _KEY}: 1\n{'k' * _KEY}: 2\n", refuses("yaml_subset.already-set-line")),
        (f"a: |{'y' * _LONG}\n", refuses("yaml_subset.malformed-text-block-indicator")),
        (f"a: &{'y' * _LONG}\n", refuses("yaml_subset.reserved-indicator")),
        (f"%{'y' * _LONG}\n", refuses("yaml_subset.directive")),
    ],
    ids=["after-value", "reserved-key", "duplicate-key", "block-indicator", "anchor", "directive"],
)
def test_refusal_echo_is_capped(body: str, site: Refuses) -> None:
    with site:
        err = _refusal(body)
    shown = str(err)
    assert len(err.detail) < y.ECHO_LIMIT + 100 and len(shown) < len(SOURCE) + y.ECHO_LIMIT + 150, shown
    assert (
        "more characters" in shown and "y" * (y.ECHO_LIMIT + 1) not in shown and "k" * (y.ECHO_LIMIT + 1) not in shown
    )
    # The same file, the same message: nothing carries over.
    with site:
        assert str(_refusal(body)) == shown


def test_backstop_echo_is_capped() -> None:
    # No file reaches this check (see the backstops above), so it is called directly.
    with refuses("yaml_subset.text-after-quoted-key"), pytest.raises(y._RefusalError) as info:
        y._decode_key('"a" ' + "y" * _KEY, 1)
    assert len(info.value.detail) < y.ECHO_LIMIT + 100 and "more characters" in info.value.detail


def test_short_refusal_echo_is_whole() -> None:
    with refuses("yaml_subset.unexpected-text-after-value"):
        err = _refusal('a: "x" tail\n')
    assert err.detail == "unexpected text after a value: 'tail'"
