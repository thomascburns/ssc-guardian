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

"""The lock file, ``.ssc-guardian.lock`` (plan §3.2 T2 and T4; contracts §11).

One entry per approved Action commit: the Action, its SHA, the source tag, the day
``pin`` first recorded it, and when its cooldown starts with that date's source. T4
trusts the file, so reading is all or nothing: one entry that fails its grammar, an
unknown or missing key, or a duplicate commit, and nothing in the file is used. A file
written by a newer format is refused with the version named.

This module only turns entries into text and text into entries. ``pin`` (#9) is the only
writer: it rewrites the file whole and atomically, so comments are not kept.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from ssc_guardian.findings import Ecosystem
from ssc_guardian.findings import _id_spelling as item_spelling
from ssc_guardian.grammars import Field, MalformedValueError, check
from ssc_guardian.plugin import AgeSource, TrustedAge
from ssc_guardian.settings import (
    FORMAT,
    ConfigFileError,
    MalformedEntryError,
    date_value,
    only_keys,
    parse_document,
    read_text,
    tables,
    text_value,
    toml_string,
)

LOCK_FILE = ".ssc-guardian.lock"
HEADER = "# Written by ssc-guardian pin. Comments in this file are not kept.\n"
# registry-upload is PyPI's; a person's date stays in .ssc-guardian.toml and is applied every
# run (L1). lock-first-seen means no earlier date was found.
TRUSTED_SOURCES = (AgeSource.ACTIVITY_LOG, AgeSource.IMMUTABLE_RELEASE, AgeSource.LOCK_FIRST_SEEN)


def lock_path(repository_root: str) -> str:
    return os.path.join(repository_root, LOCK_FILE)


def _grammar(field: Field, value: object, where: str) -> str:
    try:
        return check(field, value)
    except MalformedValueError:
        raise MalformedEntryError(f"{where} is not a valid {field.value}", site="lockfile.field-not-valid") from None


def _date(value: object, where: str) -> date:
    day = date_value(value, where)
    _grammar(Field.DATE, day.isoformat(), where)
    return day


@dataclass(frozen=True)
class LockEntry:
    """One approved Action commit, checked on construction."""

    action: str
    sha: str
    tag: str
    first_seen: date
    trusted: date
    trusted_source: AgeSource

    def __post_init__(self) -> None:
        _grammar(Field.ACTION, self.action, "action")
        _grammar(Field.SHA, self.sha, "sha")
        _grammar(Field.GIT_REF, self.tag, "tag")
        _date(self.first_seen, "first_seen")
        _date(self.trusted, "trusted")
        if not isinstance(self.trusted_source, AgeSource) or self.trusted_source not in TRUSTED_SOURCES:
            raise MalformedEntryError(
                "trusted_source is not " + ", ".join(s.value for s in TRUSTED_SOURCES),
                site="lockfile.trusted-source-not",
            )
        if self.trusted_source is AgeSource.LOCK_FIRST_SEEN and self.trusted != self.first_seen:
            raise MalformedEntryError(
                "trusted_source lock-first-seen needs trusted equal to first_seen",
                site="lockfile.trusted-source-lock-first-seen",
            )

    @property
    def key(self) -> tuple[str, str]:
        """The commit this entry approves: the Action in its one spelling (D18) and the SHA."""
        return item_spelling(Ecosystem.GITHUB_ACTIONS, self.action) or self.action, self.sha

    def trusted_age(self) -> TrustedAge:
        return TrustedAge(self.trusted, self.trusted_source)


# --- reading ----------------------------------------------------------------

_ENTRY_KEYS = ("action", "sha", "tag", "first_seen", "trusted", "trusted_source")


def parse_lock(text: str, *, place: str | None) -> tuple[LockEntry, ...]:
    """Every entry of the lock file. One malformed entry, or a newer format, and nothing in the
    file is used: :class:`ConfigFileError` names the file and the problem (exit 2)."""
    try:
        return _parse_lock(text)
    except MalformedEntryError as exc:
        raise ConfigFileError(place, str(exc), site="lockfile.malformed-entry") from exc


def _parse_lock(text: str) -> tuple[LockEntry, ...]:
    if not text.strip():
        return ()
    # parse_document accepts only format 1, so a newer file is named here first.
    try:
        version = tomllib.loads(text).get("format")
    except tomllib.TOMLDecodeError:
        version = None
    if type(version) is int and version > FORMAT:
        raise MalformedEntryError(
            f"was written by a newer ssc-guardian (lock format {version}); this build reads lock format {FORMAT}",
            site="lockfile.written-newer-ssc-guardian-lock",
        )
    doc = parse_document(text, {"pin"})
    entries: list[LockEntry] = []
    seen: set[tuple[str, str]] = set()
    for n, raw in enumerate(tables(doc.get("pin", []), "pin"), start=1):
        where = f"pin {n}"
        only_keys(raw, _ENTRY_KEYS, where)
        missing = [key for key in _ENTRY_KEYS if key not in raw]
        if missing:
            raise MalformedEntryError(f"{where} has no {missing[0]}", site="lockfile.entry-missing-key")
        try:
            source = AgeSource(text_value(raw["trusted_source"], f"{where} trusted_source"))
        except ValueError as exc:
            raise MalformedEntryError(f"{where}: {exc}", site="lockfile.bad-trusted-source") from None
        try:
            entry = LockEntry(
                text_value(raw["action"], f"{where} action"),
                text_value(raw["sha"], f"{where} sha"),
                text_value(raw["tag"], f"{where} tag"),
                date_value(raw["first_seen"], f"{where} first_seen"),
                date_value(raw["trusted"], f"{where} trusted"),
                source,
            )
        except MalformedEntryError as exc:
            raise MalformedEntryError(f"{where}: {exc}", site="lockfile.bad-entry-value") from None
        if entry.key in seen:
            raise MalformedEntryError(
                f"{where} repeats an earlier entry for {entry.action}@{entry.sha}",
                site="lockfile.repeats-earlier-entry",
            )
        seen.add(entry.key)
        entries.append(entry)
    return tuple(entries)


def load_lock(path: str) -> tuple[LockEntry, ...]:
    """The entries of the lock file at ``path``; none if the file does not exist."""
    text = read_text(path)
    return () if text is None else parse_lock(text, place=path)


# --- writing ----------------------------------------------------------------


def canonical(entries: Iterable[LockEntry]) -> tuple[LockEntry, ...]:
    """``entries`` in the file's order. A second entry for one commit is refused."""
    ordered = sorted(entries, key=lambda e: (e.key[0], e.action, e.sha))
    for before, after in zip(ordered, ordered[1:], strict=False):
        if before.key == after.key:
            raise MalformedEntryError(
                f"two entries for {after.action}@{after.sha}", site="lockfile.two-entries-one-key"
            )
    return tuple(ordered)


def dump_lock(entries: Iterable[LockEntry]) -> str:
    """The lock file's one canonical text for ``entries``, in any order. Touches no disk; the
    text is read back first, so it can never hold anything but ``entries``."""
    ordered = canonical(entries)
    lines = [HEADER, f"format = {FORMAT}\n"]
    for e in ordered:
        lines += [
            "\n[[pin]]\n",
            f"action = {toml_string(e.action)}\n",
            f"sha = {toml_string(e.sha)}\n",
            f"tag = {toml_string(e.tag)}\n",
            f"first_seen = {e.first_seen.isoformat()}\n",
            f"trusted = {e.trusted.isoformat()}\n",
            f"trusted_source = {toml_string(e.trusted_source.value)}\n",
        ]
    text = "".join(lines)
    if _parse_lock(text) != ordered:
        raise MalformedEntryError(
            "the lock entries did not read back as written", site="lockfile.lock-entries-did-not-read"
        )
    return text
