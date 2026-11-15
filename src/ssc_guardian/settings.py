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

"""Settings files, stricter wins and the deny list (plan §2.4; contracts §10.1-§10.3).

The repository's ``.ssc-guardian.toml`` and the workstation's
``~/.config/ssc-guardian/config.toml`` share one shape. Loading is all or nothing:
a malformed file is an unfinished check (exit 2) and nothing in it applies; it
never falls back to defaults. Across layers the stricter value wins, every value a
layer would have weakened is reported, and built-in defaults are only the fallback
when no layer sets a value. A rule names its ecosystem (``pypi:requests``); an
unprefixed one is refused, never guessed. A deny entry blocks whatever any other
layer says. Writes are atomic: a temporary file in the same folder, renamed.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
import tempfile
import tomllib
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date
from enum import StrEnum
from typing import Any

from ssc_guardian.findings import (
    Ecosystem,
    Finding,
    IncompleteCheckError,
    Rule,
    Skip,
    SkipReason,
    item_field,
    make_finding,
    record_site,
)
from ssc_guardian.findings import _id_spelling as item_spelling  # the one spelling of a name (D18)
from ssc_guardian.grammars import Field, matches

SETTINGS_FILE = ".ssc-guardian.toml"
WORKSTATION_SETTINGS_FILE = "config.toml"
FORMAT = 1
MAX_FILE_BYTES = 1024 * 1024
MAX_NOTE_LENGTH = 500


def workstation_dir(home: str | None = None) -> str:
    """Always ``~/.config/ssc-guardian``: ``XDG_CONFIG_HOME`` is not read, so there is one place
    to protect."""
    return os.path.join(home if home is not None else os.path.expanduser("~"), ".config", "ssc-guardian")


def find_repository_root(start: str) -> str | None:
    """The Git top level that holds ``start``, found by looking for ``.git`` on disk (Guardian
    never runs ``git``), or None outside a repository."""
    here = os.path.abspath(start)
    while True:
        if os.path.lexists(os.path.join(here, ".git")):
            return here
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


class FileKind(StrEnum):
    """Which pair of files a file belongs to; each holds different entries (§10.1)."""

    REPOSITORY = "repository"
    WORKSTATION = "workstation"


class LayerSource(StrEnum):
    WORKSTATION = "workstation"
    REPOSITORY = "repository"
    DEFAULT_BRANCH = "default-branch"  # the default branch's copy, read in CI (§10.5)
    COMMAND_LINE = "command-line"


class BlockOn(StrEnum):
    """Which compromise verdicts block. Strictness: never < strong < any."""

    NEVER = "never"
    STRONG = "strong"
    ANY = "any"


_BLOCK_ON_RANK = {BlockOn.NEVER: 0, BlockOn.STRONG: 1, BlockOn.ANY: 2}


class Key(StrEnum):
    COOLDOWN_DAYS = "cooldown_days"
    BLOCK_ON = "block_on"
    FIXED_DATE_TOLERANCE_DAYS = "fixed_date_tolerance_days"
    YOUNG_REPOSITORY_DAYS = "young_repository_days"
    MIN_STARS = "min_stars"
    NESTING_DEPTH = "nesting_depth"
    NESTED_REFERENCE_LIMIT = "nested_reference_limit"


Value = int | BlockOn

_RANGES = {
    Key.COOLDOWN_DAYS: (0, 3650),
    Key.FIXED_DATE_TOLERANCE_DAYS: (1, 3650),
    # T3 thresholds can only be raised and T5 limits only lowered, from their built-in values.
    Key.YOUNG_REPOSITORY_DAYS: (90, 36500),
    Key.MIN_STARS: (50, 10_000_000),
    Key.NESTING_DEPTH: (1, 10),
    Key.NESTED_REFERENCE_LIMIT: (1, 500),
}
_LARGER_IS_STRICTER = frozenset({Key.COOLDOWN_DAYS, Key.YOUNG_REPOSITORY_DAYS, Key.MIN_STARS})

# The fallback when no layer sets a value. The fixed-date tolerance has none: #5 computes it
# from the cooldown, and a setting can only lower it.
BUILT_IN: Mapping[Key, Value] = {
    Key.COOLDOWN_DAYS: 21,
    Key.BLOCK_ON: BlockOn.STRONG,
    Key.YOUNG_REPOSITORY_DAYS: 90,
    Key.MIN_STARS: 50,
    Key.NESTING_DEPTH: 10,
    Key.NESTED_REFERENCE_LIMIT: 500,
}


def _rank(key: Key, value: Value) -> int:
    """Higher is stricter."""
    if key is Key.BLOCK_ON:
        return _BLOCK_ON_RANK[BlockOn(str(value))]
    return int(value) if key in _LARGER_IS_STRICTER else -int(value)


class ConfigFileError(IncompleteCheckError):
    """A settings or overrides file that cannot be used: the check is unfinished (exit 2) and
    nothing in the file applies."""

    def __init__(self, place: str | None, problem: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.place = place
        self.problem = problem

    def __str__(self) -> str:
        return f"{self.place or 'default branch'}: {self.problem}"

    def skip(self, ecosystem: Ecosystem | None) -> Skip:
        """The in-scope skip that names this file, built from this refusal; the problem goes to
        text output only."""
        place = self.place if self.place is not None and matches(Field.PATH, self.place) else None
        return Skip(
            ecosystem, place, SkipReason.CHECK_ERROR, detail=self.problem, site="settings.file-unusable", made_from=self
        )


class MalformedEntryError(ValueError):
    """One problem inside a file; the loader names the file."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


ItemKey = tuple[Ecosystem, str]  # an ecosystem and the item's one spelling


@dataclass(frozen=True)
class Acknowledgment:
    """A person's acceptance of a young or little-used Action repository (T3; written by #10)."""

    repository: str
    repository_id: int
    date: date
    note: str = ""


@dataclass(frozen=True)
class StartDate:
    """A person's start date for one commit (T2); it can only make the start later."""

    action: str
    sha: str
    date: date


@dataclass(frozen=True)
class Layer:
    """What one file (or the command line) sets. A value it does not set is absent."""

    source: LayerSource
    place: str | None = None
    defaults: Mapping[Key, Value] = field(default_factory=dict)
    rules: Mapping[ItemKey, int] = field(default_factory=dict)  # per-item cooldown_days
    deny: frozenset[ItemKey] = frozenset()
    acknowledgments: tuple[Acknowledgment, ...] = ()
    start_dates: tuple[StartDate, ...] = ()
    # Keys held at their built-in value beneath a CI default branch (B1): they take part in
    # stricter-wins but are never reported as weakened, since no file set them.
    floor: frozenset[Key] = frozenset()

    def value(self, key: Key, ecosystem: Ecosystem | None = None, item: str | None = None) -> Value | None:
        """This layer's value for ``key``: its ``[rules]`` entry for the item, else its default."""
        if key is Key.COOLDOWN_DAYS and ecosystem is not None and item is not None:
            rule = self.rules.get((ecosystem, item_spelling(ecosystem, item) or item))
            if rule is not None:
                return rule
        return self.defaults.get(key)


# --- reading ----------------------------------------------------------------


def read_text(path: str) -> str | None:
    """A file's text, or None if it does not exist. Too large, not UTF-8 or unreadable is an error."""
    try:
        # Non-blocking, so a FIFO or device in the file's place cannot hang the run.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        # A symlink to a missing target is a broken file, never an absent one: falling back to
        # defaults would silently drop the person's settings or overrides.
        if _dangling_link_on(path):
            raise ConfigFileError(
                path,
                "is reached through a symlink to a missing file or folder",
                site="settings.reached-through-symlink-missing-file",
            ) from None
        return None
    except OSError as exc:
        raise ConfigFileError(path, f"could not be read ({type(exc).__name__})", site="settings.open-failed") from exc
    try:
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ConfigFileError(path, "is not a regular file", site="settings.not-regular-file")
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ConfigFileError(path, f"could not be read ({type(exc).__name__})", site="settings.read-failed") from exc
    return decode(data, path)


def _dangling_link_on(path: str) -> bool:
    """Whether ``path`` or a folder above it is a symlink whose target is missing (a dotfiles
    volume that is not mounted): the file is then unreadable, not absent."""
    here = os.path.abspath(path)
    while True:
        if os.path.islink(here) and not os.path.exists(here):
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def decode(data: bytes, place: str | None) -> str:
    if len(data) > MAX_FILE_BYTES:
        raise ConfigFileError(place, f"is larger than {MAX_FILE_BYTES} bytes", site="settings.larger-than-limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigFileError(place, "is not UTF-8", site="settings.not-utf8") from exc


def parse_document(text: str, allowed: Iterable[str]) -> dict[str, Any]:
    """The TOML document, with ``format = 1`` and no key outside ``allowed``."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise MalformedEntryError(f"is not valid TOML ({exc})", site="settings.not-valid-toml") from exc
    if doc.get("format") != FORMAT or type(doc.get("format")) is not int:
        raise MalformedEntryError(f"must start with format = {FORMAT}", site="settings.must-start-format")
    only_keys(doc, {"format", *allowed}, "the file")
    return doc


def only_keys(table: Mapping[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        raise MalformedEntryError(f"unknown key {unknown[0]!r} in {where}", site="settings.unknown-key")


def table(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise MalformedEntryError(f"{where} is not a table", site="settings.not-table")
    return value


def tables(value: object, where: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise MalformedEntryError(f"{where} is not a list of tables", site="settings.not-list-tables")
    return value


def text_value(value: object, where: str, grammar: Field | None = None) -> str:
    if not isinstance(value, str):
        raise MalformedEntryError(f"{where} is not a string", site="settings.not-string")
    if grammar is not None and not matches(grammar, value):
        raise MalformedEntryError(f"{where} is not a valid {grammar.value}", site="settings.text-value-not-valid")
    return value


def whole_number(value: object, where: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise MalformedEntryError(
            f"{where} is not a whole number from {low} to {high}", site="settings.not-whole-number"
        )
    return value


def date_value(value: object, where: str) -> date:
    if type(value) is not date:
        raise MalformedEntryError(f"{where} is not a date (YYYY-MM-DD, unquoted)", site="settings.not-date-yyyy-mm-dd")
    return value


_FREE_TEXT_REFUSED = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def free_text(value: object, where: str, *, required: bool) -> str:
    """A person's note or reason: one line of at most 500 characters, no control characters."""
    text = text_value(value, where)
    if required and not text.strip():
        raise MalformedEntryError(f"{where} is empty", site="settings.free-text-is-empty")
    if len(text) > MAX_NOTE_LENGTH:
        raise MalformedEntryError(
            f"{where} is longer than {MAX_NOTE_LENGTH} characters", site="settings.free-text-too-long"
        )
    if any(unicodedata.category(ch) in _FREE_TEXT_REFUSED for ch in text):
        raise MalformedEntryError(
            f"{where} holds a control, format or line-break character", site="settings.holds-control-format-line-break"
        )
    return text


def parse_item(entry: object, where: str) -> ItemKey:
    """``pypi:NAME`` or ``github-actions:ACTION`` in its one spelling. No prefix is refused."""
    text = text_value(entry, where)
    prefix, sep, name = text.partition(":")
    if not sep:
        raise MalformedEntryError(
            f"{where} {text!r} does not name its ecosystem (pypi: or github-actions:)",
            site="settings.does-not-name-ecosystem-pypi",
        )
    try:
        ecosystem = Ecosystem(prefix)
    except ValueError:
        raise MalformedEntryError(
            f"{where} {text!r} names an unknown ecosystem", site="settings.names-unknown-ecosystem"
        ) from None
    if not matches(item_field(ecosystem), name):
        raise MalformedEntryError(
            f"{where} {text!r} is not a valid {item_field(ecosystem).value}", site="settings.parse-item-not-valid"
        )
    return ecosystem, item_spelling(ecosystem, name) or name


def _code(line: str) -> str:
    """``line`` without its comment: up to the first ``#`` outside a quoted string."""
    quote: str | None = None
    escaped = False
    for at, ch in enumerate(line):
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[:at]
    return line


def _lines_of(text: str, entry: str) -> list[int]:
    """The lines whose code, outside comments, holds ``entry`` as a quoted string: none for an
    entry spelled with escapes, several when it is written more than once. TOML ends a line only
    at a line feed, so no other line-break character moves the count."""
    quoted = (f'"{entry}"', f"'{entry}'")
    lines = enumerate(text.split("\n"), start=1)
    return [number for number, line in lines if any(q in _code(line) for q in quoted)]


def _misplaced_pypi(kind: FileKind, item: ItemKey, entry: str, where: str, text: str) -> str | None:
    """Why a ``pypi:`` entry cannot be in a repository file, or None. It is refused, never
    ignored and never applied: the commands that check Python packages read only
    ``config.toml`` (§10.1), so the entry would do nothing while its author believes it holds."""
    if kind is not FileKind.REPOSITORY or item[0] is not Ecosystem.PYPI:
        return None
    lines = _lines_of(text, entry)
    at = f"line{'s' if len(lines) > 1 else ''} {', '.join(map(str, lines))}: " if lines else ""
    return (
        f"{at}{where} {entry!r} is a pypi entry, which only ~/.config/ssc-guardian/{WORKSTATION_SETTINGS_FILE} "
        f"applies; move it to {WORKSTATION_SETTINGS_FILE}"
    )


_SCOPE_KEYS = ("venv_folders", "ecosystems")  # the [scope] keys before #255, venv_folders named first


def _scope_refused(scope: object, text: str) -> str:
    """Why a file holding ``[scope]`` is malformed, naming its line. What a command reads or
    writes comes only from its arguments (owner's rulings of 2026-11-13, #255): a setting that
    named venv folders or narrowed the ecosystems would either widen a run or be ignored while
    its author believes it holds, so it is refused with the argument that replaces it."""
    keys = [key for key in _SCOPE_KEYS if isinstance(scope, dict) and key in scope]
    key = keys[0] if keys else None
    where = f"scope.{key}" if key else "[scope]"
    lines = _scope_lines(text, key) or _scope_lines(text, None)
    at = f"line {lines[0]}: " if lines else ""
    instead = (
        "pass --path PATH (repeatable) to check or protect"
        if key != "ecosystems"
        else "choose the ecosystems with --envs, --repo or --ecosystem, and the places with --path PATH"
    )
    why = "a command acts only on what its arguments name"
    return f"{at}{where} is no longer read: {why}; remove [scope] and {instead}"


def _scope_lines(text: str, key: str | None) -> list[int]:
    """The lines whose code, outside comments, sets ``key`` (``key =``, ``scope.key =`` or in an
    inline table), or, with no key, opens ``[scope]`` or sets ``scope``. TOML ends a line only at
    a line feed, as for ``_lines_of``."""
    pattern = _SCOPE_HEADER if key is None else re.compile(rf"(?:^|[\s.{{,]){key}\s*=")
    return [n for n, line in enumerate(text.split("\n"), start=1) if pattern.search(_code(line))]


_SCOPE_HEADER = re.compile(r"^\s*(?:\[\s*scope\s*\]|scope\s*[.=])")


_DEFAULT_KEYS = frozenset(k.value for k in Key)


def parse_settings(
    text: str,
    *,
    kind: FileKind,
    source: LayerSource,
    place: str | None,
    home: str | None = None,
) -> Layer:
    """One settings file as a layer. Any problem raises :class:`ConfigFileError` naming ``place``."""
    try:
        return _parse_settings(text, kind, source, place, home)
    except MalformedEntryError as exc:
        raise ConfigFileError(place, str(exc), site="settings.malformed-entry") from exc


def _parse_settings(text: str, kind: FileKind, source: LayerSource, place: str | None, home: str | None) -> Layer:
    allowed = {"defaults", "scope", "rules", "deny", "start_date"}
    if kind is FileKind.REPOSITORY:
        allowed.add("acknowledgment")
    doc = parse_document(text, allowed)

    defaults: dict[Key, Value] = {}
    section = table(doc.get("defaults", {}), "[defaults]")
    only_keys(section, _DEFAULT_KEYS, "[defaults]")
    for name, raw in section.items():
        key = Key(name)
        if key is Key.BLOCK_ON:
            try:
                defaults[key] = BlockOn(text_value(raw, "block_on"))
            except ValueError:
                raise MalformedEntryError(
                    "block_on is not never, strong or any", site="settings.block-not-never-strong-any"
                ) from None
        else:
            defaults[key] = whole_number(raw, name, *_RANGES[key])

    if "scope" in doc:  # refused, never ignored: settings never change what a command reads (#255)
        raise MalformedEntryError(_scope_refused(doc["scope"], text), site="settings.scope-refused")

    rules: dict[ItemKey, int] = {}
    for name, raw in table(doc.get("rules", {}), "[rules]").items():
        item = parse_item(name, "rule")
        misplaced = _misplaced_pypi(kind, item, name, "rule", text)
        if misplaced is not None:
            raise MalformedEntryError(misplaced, site="settings.repository-pypi-rule")
        entry = table(raw, f"rule {name!r}")
        only_keys(entry, {"cooldown_days"}, f"rule {name!r}")
        if "cooldown_days" not in entry:
            raise MalformedEntryError(f"rule {name!r} sets nothing", site="settings.sets-nothing")
        if item in rules:
            raise MalformedEntryError(
                f"rule {name!r} names an item another rule names", site="settings.names-item-another-rule-names"
            )
        rules[item] = whole_number(entry["cooldown_days"], f"rule {name!r} cooldown_days", *_RANGES[Key.COOLDOWN_DAYS])

    deny_list = doc.get("deny", [])
    if not isinstance(deny_list, list):
        raise MalformedEntryError("deny is not a list", site="settings.deny-not-list")
    deny_items: list[ItemKey] = []
    for entry in deny_list:
        item = parse_item(entry, "deny entry")
        misplaced = _misplaced_pypi(kind, item, str(entry), "deny entry", text)
        if misplaced is not None:
            raise MalformedEntryError(misplaced, site="settings.repository-pypi-deny-entry")
        deny_items.append(item)
    deny = frozenset(deny_items)

    acknowledgments: list[Acknowledgment] = []
    seen: set[str] = set()
    for n, raw in enumerate(tables(doc.get("acknowledgment", []), "acknowledgment"), start=1):
        where = f"acknowledgment {n}"
        only_keys(raw, {"repository", "repository_id", "date", "note"}, where)
        for required in ("repository", "repository_id", "date"):
            if required not in raw:
                raise MalformedEntryError(f"{where} has no {required}", site="settings.acknowledgment-missing-key")
        repository = text_value(raw["repository"], f"{where} repository", Field.OWNER_REPO)
        if repository.lower() in seen:
            raise MalformedEntryError(
                f"{where} repeats repository {repository}", site="settings.acknowledgment-repeats-repository"
            )
        seen.add(repository.lower())
        acknowledgments.append(
            Acknowledgment(
                repository,
                whole_number(raw["repository_id"], f"{where} repository_id", 1, 2**63 - 1),
                date_value(raw["date"], f"{where} date"),
                free_text(raw.get("note", ""), f"{where} note", required=False),
            )
        )

    start_dates: list[StartDate] = []
    commits: set[tuple[str, str]] = set()
    for n, raw in enumerate(tables(doc.get("start_date", []), "start_date"), start=1):
        where = f"start_date {n}"
        only_keys(raw, {"action", "sha", "date"}, where)
        for required in ("action", "sha", "date"):
            if required not in raw:
                raise MalformedEntryError(f"{where} has no {required}", site="settings.start-date-missing-key")
        action = text_value(raw["action"], f"{where} action", Field.ACTION)
        sha = text_value(raw["sha"], f"{where} sha", Field.SHA)
        commit = (item_spelling(Ecosystem.GITHUB_ACTIONS, action) or action, sha)
        if commit in commits:
            raise MalformedEntryError(f"{where} repeats {action}@{sha}", site="settings.start-date-repeats")
        commits.add(commit)
        start_dates.append(StartDate(action, sha, date_value(raw["date"], f"{where} date")))

    return Layer(
        source,
        place,
        defaults,
        rules,
        deny,
        tuple(acknowledgments),
        tuple(start_dates),
    )


def load_settings(
    path: str, *, kind: FileKind, source: LayerSource | None = None, home: str | None = None
) -> Layer | None:
    """The settings file at ``path`` as a layer, or None if it does not exist (it sets nothing)."""
    text = read_text(path)
    if text is None:
        return None
    if source is None:
        source = LayerSource.REPOSITORY if kind is FileKind.REPOSITORY else LayerSource.WORKSTATION
    return parse_settings(text, kind=kind, source=source, place=path, home=home)


# --- stricter wins ----------------------------------------------------------


@dataclass(frozen=True)
class Weakened:
    """A value a layer set that the applied value overrules because it was weaker (§10.3)."""

    key: Key
    source: LayerSource
    place: str | None
    ecosystem: Ecosystem | None
    item: str | None
    value: Value
    applied: Value


@dataclass(frozen=True)
class Settings:
    """The layers that apply to one command, merged by stricter wins (§10.3).

    ``ci`` marks a run in CI, where acknowledgments count from the default branch only.
    """

    layers: tuple[Layer, ...] = ()
    ci: bool = False

    @classmethod
    def of(cls, *layers: Layer | None, ci: bool = False) -> Settings:
        return cls(tuple(layer for layer in layers if layer is not None), ci)

    def value(self, key: Key, ecosystem: Ecosystem | None = None, item: str | None = None) -> Value | None:
        """The stricter of the values the layers set; the built-in default only if none sets one."""
        values = [v for layer in self.layers if (v := layer.value(key, ecosystem, item)) is not None]
        if not values:
            return BUILT_IN.get(key)
        return max(values, key=lambda v: _rank(key, v))

    def cooldown_days(self, ecosystem: Ecosystem, item: str) -> int:
        return int(self.value(Key.COOLDOWN_DAYS, ecosystem, item) or 0)

    @property
    def block_on(self) -> BlockOn:
        return BlockOn(str(self.value(Key.BLOCK_ON) or BlockOn.STRONG))

    def denied(self, ecosystem: Ecosystem, item: str) -> bool:
        """A deny entry in any layer denies the item, whatever any other layer says. An Action
        repository's entry (``owner/repo``) also denies every Action under a path in it, since
        their code comes from the same repository; an entry with a path denies only that path."""
        spelling = item_spelling(ecosystem, item) or item
        names = {spelling}
        if ecosystem is Ecosystem.GITHUB_ACTIONS:
            names.add("/".join(spelling.split("/")[:2]))
        return any((ecosystem, name) in layer.deny for layer in self.layers for name in names)

    @property
    def acknowledgments(self) -> tuple[Acknowledgment, ...]:
        """Locally the repository's; in CI the default branch's only, so a change cannot
        acknowledge its own new Action (§10.5)."""
        source = LayerSource.DEFAULT_BRANCH if self.ci else LayerSource.REPOSITORY
        return tuple(a for layer in self.layers if layer.source is source for a in layer.acknowledgments)

    def start_date(self, action: str, sha: str) -> date | None:
        """The latest person's date for the commit across the layers (later is stricter).

        It counts from every layer, the change's own file in CI included, so a caller (#9) must
        only ever move a start later with it: take the later of this and the trusted date
        (plan T2: a person's date can only make the start later), never use it in place of one.
        """
        spelling = item_spelling(Ecosystem.GITHUB_ACTIONS, action)
        dates = [
            s.date
            for layer in self.layers
            for s in layer.start_dates
            if s.sha == sha and item_spelling(Ecosystem.GITHUB_ACTIONS, s.action) == spelling
        ]
        return max(dates, default=None)

    @property
    def weakened(self) -> tuple[Weakened, ...]:
        """Every value a layer set that a stricter layer overruled."""
        found: list[Weakened] = []
        for key in Key:
            applied = self.value(key)
            for layer in self.layers:
                mine = layer.defaults.get(key) if key not in layer.floor else None
                if applied is not None and mine is not None and _rank(key, mine) < _rank(key, applied):
                    found.append(Weakened(key, layer.source, layer.place, None, None, mine, applied))
        default = self.value(Key.COOLDOWN_DAYS)
        items = dict.fromkeys(item for layer in self.layers for item in layer.rules)
        for ecosystem, item in items:
            applied = self.cooldown_days(ecosystem, item)
            for layer in self.layers:
                mine = layer.value(Key.COOLDOWN_DAYS, ecosystem, item)
                if mine is None or int(mine) >= applied:
                    continue
                if (ecosystem, item) not in layer.rules and Key.COOLDOWN_DAYS in layer.floor:
                    continue
                # A layer's default is already reported above, unless a rule moved the applied value.
                if (ecosystem, item) in layer.rules or applied != default:
                    found.append(Weakened(Key.COOLDOWN_DAYS, layer.source, layer.place, ecosystem, item, mine, applied))
        return tuple(found)

    def notices(self) -> tuple[Finding, ...]:
        """One ``weakened-setting`` notice per weaker file and item (exit unchanged). Its text-only
        detail names every weakened key of that file and item, the file's value and the applied
        value (§10.3)."""
        weaker = [
            (w.place, w.ecosystem, w.item, f"{w.key.value} {w.value}, applied {w.applied}") for w in self.weakened
        ]
        # Grouped by finding ID, so one file and item is one notice, never two findings with one ID.
        # Within one Settings only: a command-line layer read by two Settings in one run (check
        # --envs and --repo) would give two place-null notices with different details.
        grouped: dict[str, tuple[Finding, list[str]]] = {}
        for place, ecosystem, item, part in weaker:
            notice = make_finding(
                Rule.WEAKENED_SETTING,
                ecosystem,
                place=place if place is not None and matches(Field.PATH, place) else None,
                item=item,
            )
            parts = grouped.setdefault(notice.id, (notice, []))[1]
            if part not in parts:
                parts.append(part)
        # A malformed-name violation (a value that failed its grammar) carries no detail.
        return tuple(
            replace(notice, detail="; ".join(parts)) if notice.rule is Rule.WEAKENED_SETTING else notice
            for notice, parts in grouped.values()
        )


def with_built_in_floor(layer: Layer | None) -> Layer:
    """In CI, the default branch's layer with the built-in defaults beneath its own values, so
    a change can only tighten: a value the default branch does not set is still held at the
    built-in default (owner ruling on #3, contracts §10.5)."""
    layer = layer if layer is not None else Layer(LayerSource.DEFAULT_BRANCH)
    return replace(
        layer,
        defaults={**BUILT_IN, **layer.defaults},
        floor=frozenset(BUILT_IN) - frozenset(layer.defaults),
    )


def workstation_settings(home: str | None = None, command_line: Layer | None = None) -> Settings:
    """What ``check --envs``, ``protect`` and ``install`` read: the workstation config only."""
    path = os.path.join(workstation_dir(home), WORKSTATION_SETTINGS_FILE)
    return Settings.of(load_settings(path, kind=FileKind.WORKSTATION, home=home), command_line)


# --- writing ----------------------------------------------------------------


def toml_string(value: str) -> str:
    """A TOML basic string: printable ASCII as is, everything else escaped."""
    out = []
    for ch in value:
        if ch in '"\\':
            out.append("\\" + ch)
        elif " " <= ch <= "~":
            out.append(ch)
        elif ord(ch) <= 0xFFFF:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(f"\\U{ord(ch):08X}")
    return '"' + "".join(out) + '"'


def atomic_write(path: str, text: str) -> None:
    """Write ``text`` to a temporary file in the same folder, flush it to disk, then rename it
    over ``path``, so a reader sees the old file or the new one, never a partial one. An
    existing file keeps its permissions; a new one gets 0644."""
    folder = os.path.dirname(path) or "."
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        mode = 0o644
    fd, temporary = tempfile.mkstemp(dir=folder, prefix=".ssc-guardian-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def append_acknowledgment(path: str, acknowledgment: Acknowledgment) -> bool:
    """Append one acknowledgment to the repository's settings file, keeping its comments.

    Idempotent: False (nothing written) if the same repository and ID are already there. The
    same repository with another ID is refused; a person edits that by hand. The new text is
    parsed again before it is written, so a write can never leave a malformed file.
    """
    existing = read_text(path) or ""
    layer = (
        parse_settings(existing, kind=FileKind.REPOSITORY, source=LayerSource.REPOSITORY, place=path)
        if existing
        else None
    )
    for known in layer.acknowledgments if layer else ():
        if known.repository.lower() == acknowledgment.repository.lower():
            if known.repository_id == acknowledgment.repository_id:
                return False
            raise ConfigFileError(
                path,
                f"already acknowledges {known.repository} with another ID; edit it by hand",
                site="settings.another-id-edit-hand",
            )
    head = existing if existing else f"format = {FORMAT}\n"
    if not head.endswith("\n"):
        head += "\n"
    block = (
        "\n[[acknowledgment]]\n"
        f"repository = {toml_string(acknowledgment.repository)}\n"
        f"repository_id = {acknowledgment.repository_id}\n"
        f"date = {acknowledgment.date.isoformat()}\n"
        f"note = {toml_string(acknowledgment.note)}\n"
    )
    written = parse_settings(head + block, kind=FileKind.REPOSITORY, source=LayerSource.REPOSITORY, place=path)
    if acknowledgment not in written.acknowledgments:
        raise ConfigFileError(
            path, "the appended acknowledgment did not read back", site="settings.appended-acknowledgment-did-not-read"
        )
    atomic_write(path, head + block)
    return True
