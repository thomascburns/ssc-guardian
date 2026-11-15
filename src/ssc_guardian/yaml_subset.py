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

"""A narrow, fail-closed YAML reader for workflow files (plan §3.2, R1-K7, R2-K5, N21).

The subset: block style (mappings and lists by indentation), plain values on
one line, quoted values on one line or over several (issue #203), comments, text
blocks (``|`` and ``>`` with their chomping and indentation modifiers) and
compact lists of simple values on one line (``[main]``, ``["a", 'b']``).
Everything else refuses the whole file: anchors, aliases, tags, compact maps,
nested compact forms, multiple documents, duplicate keys anywhere (compared
after decoding, so ``"a"`` and ``a`` are one key; keys are text, so ``true`` and
``True`` are two), directives, explicit ``?`` keys, merge keys, multi-line plain
values, multi-line quoted keys, multi-line compact lists, tab indentation,
characters YAML does not allow, line breaks other than CR and LF, and any line
shape this reader does not recognise.

A quoted value that spans lines is folded as YAML 1.2.2 §6.5 and §7.3 define:
white space at the end of a line and at the start of the next is dropped, a
single line break becomes one space, and each empty line between becomes one
line feed; in double quotes a ``\\`` at the end of a line joins the lines with
nothing between them and keeps the white space before it. Each line after the
first must be deeper than the key or list dash that owns the value, may not hold
a tab in its leading white space, and may not start a ``---`` or ``...`` at
column 0; after the closing quote only spaces and a comment may follow, and a
quote still open at the end of the file refuses it. Text inside the quotes is
text: a line in them that looks like ``uses:`` or a comment is part of the
value. The value's line is the line where it starts.

A refusal raises :class:`UnsupportedYamlError`, an
:class:`~ssc_guardian.findings.IncompleteCheckError` with reason
``unsupported-yaml`` (exit 2), naming the file and line. The reader never
guesses: it builds a value only from a form it reads exactly.

Every scalar is kept as text, with its line and style; nothing is converted to a
number, a boolean or null, so ``on`` stays ``on`` and ``"3.10"`` stays
``3.10``. An absent value (``key:`` with nothing under it) is an empty plain
scalar. Text-block content is text: a ``uses:`` line inside ``run: |`` is never
read as YAML. Reading is read-only and the result is the same on every run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from ssc_guardian.findings import IncompleteCheckError, SkipReason, record_site

# A text block indicator: | or > with optional chomping and indentation modifiers, either order.
_BLOCK_INDICATOR = re.compile(r"[|>](?:([1-9])([+-])?|([+-])([1-9])?)?")
# Characters that cannot start a plain value here (indicators not handled as a form of their own).
_RESERVED_START = set("@`%,]}")
# YAML's printable set, less NEL, LS and PS (line breaks to some readers and not to others) and
# U+FEFF after the start (libyaml, which GitHub's parser follows, skips it at the start of any
# line): either way a line the runner sees could hide inside what this reader takes as text.
_DISALLOWED = re.compile(r"[^\t\n\r\x20-\x7e\xa0-\u2027\u202a-\ud7ff\ue000-\ufefe\uff00-\ufffd\U00010000-\U0010ffff]")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
# YAML 1.2 double-quoted escapes (spec §5.7), plus \x, \u and \U handled below.
_DOUBLE_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}
_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
# Deeper nesting than any workflow needs; refused rather than left to Python's recursion limit.
_MAX_DEPTH = 64


class UnsupportedYamlError(IncompleteCheckError):
    """A form outside the subset: the whole file is refused (``unsupported-yaml``, exit 2).

    ``source`` names the file, ``line`` the 1-based line, ``form`` the refused
    form and ``detail`` what was found; the message carries all four.
    """

    def __init__(
        self, source: str, line: int, form: str, detail: str, *, site: str | None = None, recorded: bool = False
    ) -> None:
        # recorded: the site was recorded where the refusal was first built (_RefusalError or
        # models._refuse), so this forward does not record it again.
        super().__init__(SkipReason.UNSUPPORTED_YAML, site=None if recorded else site)
        self.args = (f"{source}:{line}: {form}: {detail}",)
        self.source = source
        self.line = line
        self.form = form
        self.detail = detail


class ScalarStyle(StrEnum):
    PLAIN = "plain"
    SINGLE_QUOTED = "single-quoted"
    DOUBLE_QUOTED = "double-quoted"
    LITERAL = "literal"  # |
    FOLDED = "folded"  # >


@dataclass(frozen=True)
class ScalarNode:
    """One value as text. ``line`` is where it starts (a text block: its indicator's line)."""

    value: str
    line: int
    style: ScalarStyle


@dataclass(frozen=True)
class SequenceNode:
    items: tuple[Node, ...]
    line: int


@dataclass(frozen=True)
class Entry:
    """One ``key: value`` pair; ``line`` is the key's line."""

    key: str
    line: int
    value: Node


@dataclass(frozen=True)
class MappingNode:
    """A mapping in file order. Keys are unique after decoding (a duplicate refuses the file)."""

    entries: tuple[Entry, ...]
    line: int

    def get(self, key: str) -> Entry | None:
        return next((e for e in self.entries if e.key == key), None)


Node = ScalarNode | SequenceNode | MappingNode


def to_python(node: Node | None) -> object:
    """The plain value: dicts, lists and strings (None for an empty document)."""
    if node is None:
        return None
    if isinstance(node, ScalarNode):
        return node.value
    if isinstance(node, SequenceNode):
        return [to_python(item) for item in node.items]
    return {e.key: to_python(e.value) for e in node.entries}


ECHO_LIMIT = 80  # characters of the file a refusal shows: enough to find the text, never a hostile line whole


def _shown(text: str) -> str:
    """``text`` as a refusal shows it: quoted, cut to :data:`ECHO_LIMIT` characters with the rest
    counted, so a line of any length is echoed at a bounded length (#230)."""
    if len(text) <= ECHO_LIMIT:
        return repr(text)
    return f"{text[:ECHO_LIMIT]!r} and {len(text) - ECHO_LIMIT} more characters"


class _RefusalError(Exception):
    """A refusal at one line; :func:`parse` turns it into :class:`UnsupportedYamlError`."""

    def __init__(self, line: int, form: str, detail: str, *, site: str | None = None) -> None:
        super().__init__(form)
        self.line = line
        self.form = form
        self.detail = detail
        self.site = site
        record_site(site)


# ---------------------------------------------------------------------------
# Pieces of one line
# ---------------------------------------------------------------------------


def _strip_comment(text: str) -> str:
    """Remove a trailing comment from text that holds no quotes."""
    for i, ch in enumerate(text):
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip(" \t")
    return text.rstrip(" \t")


def _quoted_line(text: str, i: int, quote: str, line: int, out: list[str]) -> tuple[int | None, bool]:
    """Decode one line of a quoted value, from ``text[i]``, onto ``out``.

    Returns (index after the closing quote, False) when the value closes on this line, or
    (None, escaped) when the line ends first; ``escaped`` is True when a double-quoted line ends
    with ``\\`` (an escaped line break). On a line that ends with an unescaped break, the white
    space written at its end is dropped (folding, YAML 1.2.2 §6.5); white space from an escape
    (``\\t``, ``\\ ``) is text and is kept.
    """
    trailing = -1  # where the run of literal white space at the end of ``out`` starts; -1: none
    while i < len(text):
        ch = text[i]
        if ch == quote:
            if quote == "'" and text[i + 1 : i + 2] == "'":
                out.append("'")
                trailing = -1
                i += 2
                continue
            return i + 1, False
        if quote == '"' and ch == "\\":
            if i + 1 >= len(text):
                return None, True
            esc = text[i + 1]
            if esc in _DOUBLE_ESCAPES:
                out.append(_DOUBLE_ESCAPES[esc])
                trailing = -1
                i += 2
                continue
            width = _HEX_ESCAPES.get(esc, 0)
            digits = text[i + 2 : i + 2 + width]
            if width and re.fullmatch(rf"[0-9A-Fa-f]{{{width}}}", digits):
                code = int(digits, 16)
                if code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF:
                    out.append(chr(code))
                    trailing = -1
                    i += 2 + width
                    continue
            raise _RefusalError(
                line, "unsupported escape", f"\\{esc} in a double-quoted value", site="yaml_subset.double-quoted-escape"
            )
        if ch in " \t":
            if trailing < 0:
                trailing = len(out)
        else:
            trailing = -1
        out.append(ch)
        i += 1
    if trailing >= 0:
        del out[trailing:]
    return None, False


def _read_quoted(text: str, start: int, line: int) -> tuple[str, int] | None:
    """Decode the quoted value at ``text[start]`` that closes on its line: (value, index after the
    closing quote). None when the line ends before the quote closes."""
    out: list[str] = []
    end, _ = _quoted_line(text, start + 1, text[start], line, out)
    return None if end is None else ("".join(out), end)


def _after_value(text: str, i: int, line: int) -> None:
    """After a quoted value or compact list, only spaces and a comment may follow."""
    rest = text[i:]
    if rest.strip(" \t") and not rest.lstrip(" \t").startswith("#"):
        raise _RefusalError(
            line,
            "unrecognised line",
            f"unexpected text after a value: {_shown(rest.strip())}",
            site="yaml_subset.unexpected-text-after-value",
        )
    if rest.strip(" \t") and rest[:1] not in (" ", "\t"):
        raise _RefusalError(
            line,
            "unrecognised line",
            "a comment must be separated from a value by a space",
            site="yaml_subset.comment-must-separated-value-space",
        )


def _check_indicators(token: str, where: str, line: int) -> None:
    for mark, form in (("&", "anchor"), ("*", "alias"), ("!", "tag")):
        if token.startswith(mark):
            raise _RefusalError(
                line, form, f"{_shown(token.split()[0])} {where}", site="yaml_subset.reserved-indicator"
            )


def _decode_key(raw: str, line: int) -> str:
    raw = raw.strip(" \t")
    if raw[:1] in ("'", '"'):
        read = _read_quoted(raw, 0, line)
        if read is None:  # _split_key hands on only a quoted key that closes on its line
            raise _RefusalError(
                line,
                "multi-line quoted key",
                "a quoted key does not close on its line",
                site="yaml_subset.quoted-key-does-not-close",
            )
        value, end = read
        if raw[end:].strip(" \t"):
            raise _RefusalError(
                line,
                "unrecognised line",
                f"text after a quoted key: {_shown(raw)}",
                site="yaml_subset.text-after-quoted-key",
            )
        return value
    _check_indicators(raw, "on a key", line)
    if raw[:1] in ("[", "{"):
        form = "compact map" if raw[0] == "{" else "nested compact form"
        raise _RefusalError(line, form, "a compact form used as a key", site="yaml_subset.compact-form-used-key")
    if not raw:
        raise _RefusalError(line, "unrecognised line", "a key with no name", site="yaml_subset.key-no-name")
    if raw[:1] in _RESERVED_START or raw[:1] in "|>" or raw.startswith(("? ", "?\t")) or raw == "?":
        raise _RefusalError(
            line,
            "unrecognised line",
            f"a key starts with a reserved character: {_shown(raw)}",
            site="yaml_subset.key-starts-reserved-character",
        )
    if raw == "<<":
        raise _RefusalError(
            line, "merge key", "'<<' merges a mapping from an alias", site="yaml_subset.merges-mapping-alias"
        )
    return raw


def _split_key(text: str, line: int) -> tuple[str, str] | None:
    """Split ``key: value`` at the first mapping colon outside quotes; None if there is none.

    A line that opens with ``{`` or ``[`` is a compact form, never a key: its
    reader refuses it by name. Nor is one that opens a quote it does not close:
    that is a quoted value that spans lines, or a multi-line key its caller refuses.
    """
    if text[:1] in ("{", "["):
        return None
    if text[:1] in ("'", '"'):
        read = _read_quoted(text, 0, line)
        if read is None:
            return None
        j = read[1]
        while text[j : j + 1] in (" ", "\t"):
            j += 1
        if text[j : j + 1] == ":" and text[j + 1 : j + 2] in ("", " ", "\t"):
            return text[:j], text[j + 1 :]  # the key's text runs to the colon, as libyaml counts it
        return None
    for i, ch in enumerate(text):
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return None
        if ch == ":" and text[i + 1 : i + 2] in ("", " ", "\t"):
            return text[:i], text[i + 1 :]
    return None


def _compact_list(text: str, line: int) -> tuple[ScalarNode, ...]:
    """Read a one-line compact list of simple values starting at ``text[0] == '['``."""
    items: list[ScalarNode] = []
    i = 1
    expecting_item = True
    while i < len(text):
        while text[i : i + 1] in (" ", "\t"):
            i += 1
        if i >= len(text):
            break
        ch = text[i]
        if ch == "]":
            if items and expecting_item:
                raise _RefusalError(
                    line,
                    "unrecognised line",
                    "a trailing comma in a compact list",
                    site="yaml_subset.trailing-comma-compact-list",
                )
            _after_value(text, i + 1, line)
            return tuple(items)
        if not expecting_item:
            if ch != ",":
                raise _RefusalError(
                    line,
                    "unrecognised line",
                    "compact list items must be separated by commas",
                    site="yaml_subset.compact-list-items-must-separated",
                )
            expecting_item = True
            i += 1
            continue
        if ch == "[":
            raise _RefusalError(
                line,
                "nested compact form",
                "a compact list inside a compact list",
                site="yaml_subset.compact-list-inside-compact-list",
            )
        if ch == "{":
            raise _RefusalError(
                line,
                "compact map",
                "a compact map inside a compact list",
                site="yaml_subset.compact-map-inside-compact-list",
            )
        _check_indicators(text[i:], "inside a compact list", line)
        if ch in ("'", '"'):
            read = _read_quoted(text, i, line)
            if read is None:
                raise _RefusalError(
                    line,
                    "multi-line compact list",
                    "a quoted item in a compact list does not close on its line",
                    site="yaml_subset.compact-list-quoted-item-does-not-close",
                )
            value, i = read
            style = ScalarStyle.SINGLE_QUOTED if ch == "'" else ScalarStyle.DOUBLE_QUOTED
            items.append(ScalarNode(value, line, style))
        else:
            j = i
            while j < len(text) and text[j] not in ",]":
                if text[j] == ":" and text[j + 1 : j + 2] in (" ", "\t", ",", "]", ""):
                    raise _RefusalError(
                        line,
                        "compact map",
                        "a key: value pair inside a compact list",
                        site="yaml_subset.key-value-pair-inside-compact",
                    )
                if text[j] in "[{}":
                    raise _RefusalError(
                        line,
                        "nested compact form",
                        "a bracket inside a compact list item",
                        site="yaml_subset.bracket-inside-compact-list-item",
                    )
                if text[j] == "#" and text[j - 1] in " \t":
                    raise _RefusalError(
                        line,
                        "multi-line compact list",
                        "a compact list does not close on its line",
                        site="yaml_subset.compact-list-comment-before-close",
                    )
                j += 1
            value = text[i:j].strip(" \t")
            if not value:
                raise _RefusalError(
                    line,
                    "unrecognised line",
                    "an empty item in a compact list",
                    site="yaml_subset.empty-item-compact-list",
                )
            if (
                value[0] in _RESERVED_START
                or value[0] in "|>#?:"
                or (value[0] == "-" and value[1:2] in ("", " ", "\t"))
            ):
                raise _RefusalError(
                    line,
                    "unrecognised line",
                    f"a compact list item starts with {value[0]!r}",
                    site="yaml_subset.compact-list-item-starts",
                )
            items.append(ScalarNode(value, line, ScalarStyle.PLAIN))
            i = j
        expecting_item = False
    raise _RefusalError(
        line,
        "multi-line compact list",
        "a compact list does not close on its line",
        site="yaml_subset.compact-list-does-not-close",
    )


def _is_dash(text: str) -> bool:
    return text == "-" or text.startswith(("- ", "-\t"))


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Line:
    index: int  # 0-based; the line number is index + 1
    indent: int
    text: str  # the line after its indentation


class _Parser:
    def __init__(self, lines: list[str], *, last_break: bool) -> None:
        self.lines = lines
        self.last_break = last_break  # whether the last line ends with a line break
        self.i = 0
        self.content_seen = False
        self.started = False  # a "---" was seen
        self.ended = False  # a "..." was seen
        self.depth = 0

    # -- lines -------------------------------------------------------------

    def _peek(self) -> _Line | None:
        """The next line holding content, skipping blank lines, comments and document markers."""
        while self.i < len(self.lines):
            line = self.lines[self.i]
            text = line.lstrip(" ")
            indent = len(line) - len(text)
            lineno = self.i + 1
            if text[:1] == "\t":  # on a blank or comment line too: libyaml refuses those
                raise _RefusalError(
                    lineno,
                    "tab indentation",
                    "YAML indentation must use spaces",
                    site="yaml_subset.yaml-indentation-must-use-spaces",
                )
            if not text.strip(" \t") or text.startswith("#"):
                self.i += 1
                continue
            # "---" or "..." alone (or before a comment) at column 0 is a document marker;
            # "---abc" would be a plain value and falls through.
            if indent == 0 and text[:3] in ("---", "...") and text[3:4] in ("", " ", "\t"):
                marker = text[:3]
                if _strip_comment(text[3:]):
                    raise _RefusalError(
                        lineno,
                        "unrecognised line",
                        f"content on the {marker!r} line",
                        site="yaml_subset.unrecognised-line",
                    )
                if marker == "---":
                    if self.content_seen or self.started or self.ended:
                        raise _RefusalError(
                            lineno,
                            "multiple documents",
                            "a second '---' document start",
                            site="yaml_subset.second-document-start",
                        )
                    self.started = True
                else:
                    self.ended = True
                self.i += 1
                continue
            if self.ended:
                raise _RefusalError(
                    lineno,
                    "multiple documents",
                    "content after the '...' document end",
                    site="yaml_subset.content-after-document-end",
                )
            if indent == 0 and text.startswith("%"):
                raise _RefusalError(lineno, "directive", _shown(text.split()[0]), site="yaml_subset.directive")
            self.content_seen = True
            return _Line(self.i, indent, text)
        return None

    def _take(self, line: _Line) -> int:
        """Consume ``line`` (just peeked); return its line number."""
        self.i = line.index + 1
        return line.index + 1

    def _no_deeper_than(self, col: int, *, plain: bool) -> None:
        """After a one-line value owned by column ``col``, a deeper line would continue it."""
        nxt = self._peek()
        if nxt is not None and nxt.indent > col:
            if plain:
                raise _RefusalError(
                    nxt.index + 1,
                    "multi-line plain value",
                    f"a value continues on a deeper line (column {nxt.indent})",
                    site="yaml_subset.value-continues-deeper-line-column",
                )
            raise _RefusalError(
                nxt.index + 1,
                "invalid indentation",
                f"a line at column {nxt.indent} is deeper than the value before it",
                site="yaml_subset.deeper-than-value-before",
            )

    # -- structure ---------------------------------------------------------

    def document(self) -> Node | None:
        first = self._peek()
        if first is None:
            return None
        root = self._node_at(first, owner_col=-1)
        rest = self._peek()
        if rest is not None:
            raise _RefusalError(
                rest.index + 1,
                "invalid indentation",
                f"a line at column {rest.indent} is outside the document's top level (column {first.indent})",
                site="yaml_subset.outside-documents-top-level-column",
            )
        return root

    def _enter(self, line: int) -> None:
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise _RefusalError(
                line, "nesting too deep", f"more than {_MAX_DEPTH} levels", site="yaml_subset.nesting-too-deep"
            )

    def _node_at(self, line: _Line, *, owner_col: int) -> Node:
        """The node that starts on ``line``, on a line of its own (not after a key or dash)."""
        if _is_dash(line.text):
            return self._sequence(line.indent)
        if _split_key(line.text, line.index + 1) is not None:
            return self._mapping(line.indent)
        lineno = self._take(line)
        if line.text[:1] in ("|", ">"):
            raise _RefusalError(
                lineno,
                "unrecognised line",
                "a text block must follow a key or a list dash",
                site="yaml_subset.text-block-must-follow-key",
            )
        return self._inline(line.text, lineno, owner_col=owner_col)

    def _nested(self, owner_col: int, owner_line: int, *, list_at_owner: bool) -> Node:
        """The value on the lines after a key or dash that has none on its own line."""
        nxt = self._peek()
        if nxt is not None and nxt.indent > owner_col:
            return self._node_at(nxt, owner_col=owner_col)
        if list_at_owner and nxt is not None and nxt.indent == owner_col and _is_dash(nxt.text):
            return self._sequence(owner_col)  # key:\n- item  (a list at its key's column)
        return ScalarNode("", owner_line, ScalarStyle.PLAIN)

    def _mapping(self, col: int, first: tuple[str, int] | None = None) -> MappingNode:
        """A mapping at column ``col``; ``first`` is its first entry when it follows a dash."""
        start = first[1] if first is not None else (self._peek() or _Line(0, 0, "")).index + 1
        self._enter(start)
        entries: list[Entry] = []
        seen: dict[str, int] = {}
        if first is not None:
            self._entry(first[0], col, first[1], entries, seen)
        while (line := self._peek()) is not None and line.indent >= col:
            lineno = line.index + 1
            if line.indent > col:
                raise _RefusalError(
                    lineno,
                    "invalid indentation",
                    f"column {line.indent} where a key at {col} was expected",
                    site="yaml_subset.mapping-invalid-indentation",
                )
            if _is_dash(line.text):
                raise _RefusalError(
                    lineno,
                    "invalid indentation",
                    "a list item where a key was expected",
                    site="yaml_subset.list-item-where-key-expected",
                )
            if line.text[0] in ("{", "["):
                form = "compact map" if line.text[0] == "{" else "nested compact form"
                raise _RefusalError(
                    lineno,
                    form,
                    "a compact form where a key was expected",
                    site="yaml_subset.compact-form-where-key-expected",
                )
            if _split_key(line.text, lineno) is None:
                if line.text[0] in ("'", '"') and _read_quoted(line.text, 0, lineno) is None:
                    raise _RefusalError(
                        lineno,
                        "multi-line quoted key",
                        "a quoted key does not close on its line",
                        site="yaml_subset.multi-line-quoted-key",
                    )
                raise _RefusalError(
                    lineno,
                    "unrecognised line",
                    "a line that is neither a key nor a list item",
                    site="yaml_subset.mapping-line-neither-key-nor-list",
                )
            self._take(line)
            self._entry(line.text, col, lineno, entries, seen)
        self.depth -= 1
        return MappingNode(tuple(entries), start)

    def _entry(self, text: str, col: int, lineno: int, entries: list[Entry], seen: dict[str, int]) -> None:
        split = _split_key(text, lineno)
        if split is None:  # callers check first; kept so a change there cannot read a wrong key
            raise _RefusalError(
                lineno,
                "unrecognised line",
                "a line that is neither a key nor a list item",
                site="yaml_subset.entry-line-neither-key-nor-list",
            )
        raw_key, rest = split
        if len(raw_key) > 1024:  # libyaml's limit for a key on one line
            raise _RefusalError(
                lineno,
                "unrecognised line",
                "a key longer than 1024 characters",
                site="yaml_subset.key-longer-than-1024-characters",
            )
        key = _decode_key(raw_key, lineno)
        if key in seen:
            raise _RefusalError(
                lineno,
                "duplicate key",
                f"{_shown(key)} already set at line {seen[key]}",
                site="yaml_subset.already-set-line",
            )
        seen[key] = lineno
        value = rest.lstrip(" \t")
        if not value or value.startswith("#"):
            node = self._nested(col, lineno, list_at_owner=True)
        elif _is_dash(value):
            raise _RefusalError(
                lineno, "unrecognised line", "a list on the same line as its key", site="yaml_subset.list-same-line-key"
            )
        else:
            node = self._inline(value, lineno, owner_col=col)
        entries.append(Entry(key, lineno, node))

    def _sequence(self, col: int, first: tuple[str, int] | None = None) -> SequenceNode:
        """A list at column ``col``; ``first`` is its first item's line when it follows a dash."""
        start = first[1] if first is not None else (self._peek() or _Line(0, 0, "")).index + 1
        self._enter(start)
        items: list[Node] = []
        if first is not None:
            items.append(self._item(first[0], col, first[1]))
        while (line := self._peek()) is not None and line.indent >= col:
            lineno = line.index + 1
            if line.indent > col:
                raise _RefusalError(
                    lineno,
                    "invalid indentation",
                    f"column {line.indent} where an item at {col} was expected",
                    site="yaml_subset.sequence-invalid-indentation",
                )
            if not _is_dash(line.text):
                break  # a key at the list's column ends a list that sits at its key's column
            self._take(line)
            items.append(self._item(line.text, col, lineno))
        self.depth -= 1
        return SequenceNode(tuple(items), start)

    def _item(self, text: str, col: int, lineno: int) -> Node:
        """One list item; ``text`` starts with its dash at column ``col``."""
        if text.startswith("-\t"):
            raise _RefusalError(
                lineno, "tab indentation", "a tab after a list dash", site="yaml_subset.tab-after-list-dash"
            )
        rest = text[1:]
        inner = rest.lstrip(" ")
        if not inner or inner.startswith("#"):
            return self._nested(col, lineno, list_at_owner=False)
        if inner[0] == "\t":
            raise _RefusalError(
                lineno, "tab indentation", "a tab after a list dash", site="yaml_subset.tab-after-list-dash-indent"
            )
        inner_col = col + 1 + len(rest) - len(inner)
        if _is_dash(inner):
            return self._sequence(inner_col, first=(inner, lineno))
        if _split_key(inner, lineno) is not None:
            return self._mapping(inner_col, first=(inner, lineno))
        return self._inline(inner, lineno, owner_col=col)

    def _inline(self, value: str, lineno: int, *, owner_col: int) -> Node:
        """A value on the same line as its key or dash (or alone on its line)."""
        _check_indicators(value, "on a value", lineno)
        head = value[0]
        node: Node
        if head == "{":
            raise _RefusalError(lineno, "compact map", "a '{...}' value", site="yaml_subset.brace-value")
        if head == "[":
            node = SequenceNode(_compact_list(value, lineno), lineno)
        elif head in ("'", '"'):
            text, last, end, last_line = self._quoted(value, lineno, owner_col)
            rest = last[end:].lstrip(" \t")
            if last_line != lineno and rest[:1] == ":" and rest[1:2] in ("", " ", "\t"):
                raise _RefusalError(
                    lineno,
                    "multi-line quoted key",
                    "a quoted key spans lines",
                    site="yaml_subset.quoted-key-spans-lines",
                )
            _after_value(last, end, last_line)
            style = ScalarStyle.SINGLE_QUOTED if head == "'" else ScalarStyle.DOUBLE_QUOTED
            node = ScalarNode(text, lineno, style)
        elif head in ("|", ">"):
            node = self._text_block(_strip_comment(value), lineno, owner_col)
        elif head in _RESERVED_START or (head in "?:" and value[1:2] in ("", " ", "\t")):
            raise _RefusalError(
                lineno,
                "unrecognised line",
                f"a value starts with the reserved character {head!r}",
                site="yaml_subset.value-starts-reserved-character",
            )
        else:
            plain = _strip_comment(value)
            if re.search(r":(?:[ \t]|$)", plain):
                raise _RefusalError(
                    lineno,
                    "unrecognised line",
                    "a ': ' inside a plain value (a compact map?)",
                    site="yaml_subset.inside-plain-value-compact-map",
                )
            node = ScalarNode(plain, lineno, ScalarStyle.PLAIN)
        self._no_deeper_than(owner_col, plain=isinstance(node, ScalarNode) and node.style is ScalarStyle.PLAIN)
        return node

    def _quoted(self, first: str, lineno: int, owner_col: int) -> tuple[str, str, int, int]:
        """A quoted value starting at ``first[0]`` on line ``lineno``, on that line or over several.

        Returns (value, the line it closes on, the index after its closing quote, that line's
        number). The lines after the first are read as raw text, never as YAML, and are folded
        as YAML 1.2.2 §6.5 and §7.3 define; any form this reader does not read exactly refuses.
        """
        quote = first[0]
        out: list[str] = []
        end, escaped = _quoted_line(first, 1, quote, lineno, out)
        last, last_line, empty = first, lineno, 0
        while end is None:
            if last_line >= len(self.lines):
                raise _RefusalError(
                    lineno,
                    "unclosed quoted value",
                    "a quoted value opened on this line does not close before the end of the file",
                    site="yaml_subset.quoted-value-does-not-close",
                )
            last = self.lines[last_line]  # the line after line number last_line (0-based index)
            last_line += 1
            self.i = last_line
            body = last.lstrip(" \t")
            indent = len(last) - len(body)
            if "\t" in last[:indent]:
                raise _RefusalError(
                    last_line,
                    "tab indentation",
                    "a tab in the leading white space of a quoted value's line",
                    site="yaml_subset.quoted-value-line-tab",
                )
            if not body:
                empty += 1  # a line of nothing or only spaces is an empty line, at any indentation
                continue
            if indent == 0 and body.startswith(("---", "...")):
                raise _RefusalError(
                    last_line,
                    "document marker",
                    f"a line starting {body[:3]!r} at column 0 inside a quoted value",
                    site="yaml_subset.document-marker-inside-quoted-value",
                )
            if indent <= owner_col:
                raise _RefusalError(
                    last_line,
                    "invalid indentation",
                    f"a quoted value continues at column {indent}, not deeper than its key or dash at {owner_col}",
                    site="yaml_subset.quoted-value-line-not-deeper",
                )
            # One break between two lines is a space; each empty line between is a line feed. An
            # escaped break adds nothing of its own (YAML 1.2.2 §7.3.1).
            out.append("\n" * empty if empty or escaped else " ")
            empty = 0
            end, escaped = _quoted_line(last, indent, quote, last_line, out)
        return "".join(out), last, end, last_line

    def _text_block(self, indicator: str, lineno: int, owner_col: int) -> ScalarNode:
        """A ``|`` or ``>`` block; its content is text and is never read as YAML."""
        match = _BLOCK_INDICATOR.fullmatch(indicator)
        if match is None:
            raise _RefusalError(
                lineno,
                "unrecognised line",
                f"malformed text block indicator {_shown(indicator)}",
                site="yaml_subset.malformed-text-block-indicator",
            )
        digit = match.group(1) or match.group(4)
        chomp = match.group(2) or match.group(3) or ""
        folded = indicator[0] == ">"
        indent = owner_col + int(digit) if digit else None
        if indent is None:
            # The first content line fixes the indentation; a blank line before it may not be deeper.
            widest = 0
            for k in range(self.i, len(self.lines)):
                line = self.lines[k]
                if line.strip(" "):
                    first = len(line) - len(line.lstrip(" "))
                    if first > owner_col:
                        if line[first] == "\t":
                            raise _RefusalError(
                                k + 1,
                                "tab indentation",
                                "a text block's first line starts with a tab",
                                site="yaml_subset.text-blocks-first-line-starts",
                            )
                        if widest > first:
                            raise _RefusalError(
                                k + 1,
                                "invalid indentation",
                                "a text block's blank line is deeper than its first line",
                                site="yaml_subset.text-blocks-blank-line-deeper",
                            )
                        indent = first
                    break
                widest = max(widest, len(line))
        # Each line of the block: its text after the indentation, or "" for an empty line
        # (a content line is never empty: it holds a character at or past the indentation).
        body: list[str] = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if not line.strip(" "):
                body.append(line[indent:] if indent is not None else "")
            elif indent is not None and len(line) - len(line.lstrip(" ")) >= indent:
                body.append(line[indent:])
            else:
                break
            self.i += 1
        last_break = self.i < len(self.lines) or self.last_break
        style = ScalarStyle.FOLDED if folded else ScalarStyle.LITERAL
        return ScalarNode(_block_value(body, folded=folded, chomp=chomp, last_break=last_break), lineno, style)


def _block_value(body: list[str], *, folded: bool, chomp: str, last_break: bool) -> str:
    """A text block's value from its lines, "" marking an empty line (YAML 1.2 §8.1, as libyaml reads it).

    ``last_break`` is False when the block's last line ends the file with no line break.
    """
    chunks: list[str] = []
    k = 0
    breaks: list[str] = []
    while k < len(body) and not body[k]:
        breaks.append("\n")
        k += 1
    line_break = ""
    while k < len(body):
        text = body[k]
        chunks.extend(breaks)
        leading_non_space = text[:1] not in (" ", "\t")
        chunks.append(text)
        line_break = "\n"
        k += 1
        breaks = []
        while k < len(body) and not body[k]:
            breaks.append("\n")
            k += 1
        if k == len(body):
            break
        if folded and leading_non_space and body[k][:1] not in (" ", "\t"):
            if not breaks:
                chunks.append(" ")
        else:
            chunks.append(line_break)
    if not last_break and body:
        if body[-1]:
            line_break = ""  # the last content line has no break to keep
        else:
            breaks.pop()  # nor has the last empty line
    if chomp != "-":
        chunks.append(line_break)
    if chomp == "+":
        chunks.extend(breaks)
    return "".join(chunks)


def parse(text: str, source: str) -> Node | None:
    """Read ``text`` (the content of ``source``); None for an empty document.

    Raises :class:`UnsupportedYamlError` naming ``source`` and the line for any
    form outside the subset.
    """
    text = text.removeprefix("\ufeff")
    bad = _DISALLOWED.search(text)
    if bad is not None:
        line = len(_LINE_BREAK.findall(text, 0, bad.start())) + 1
        raise UnsupportedYamlError(
            source,
            line,
            "disallowed character",
            f"U+{ord(bad.group()):04X} is not allowed in this subset",
            site="yaml_subset.not-allowed-subset",
        )
    lines = _LINE_BREAK.split(text)
    last_break = lines[-1] == ""
    if last_break:
        lines.pop()
    try:
        return _Parser(lines, last_break=last_break).document()
    except _RefusalError as r:
        raise UnsupportedYamlError(source, r.line, r.form, r.detail, site=r.site, recorded=True) from None


def load(path: str) -> Node | None:
    """Read the file at ``path`` (read-only). A file that is not UTF-8 is refused at the line it fails."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        line = len(re.findall(rb"\r\n|\r|\n", data[: exc.start])) + 1
        raise UnsupportedYamlError(
            path, line, "encoding", "the file is not UTF-8", site="yaml_subset.file-not-utf-8"
        ) from None
    return parse(text, path)
