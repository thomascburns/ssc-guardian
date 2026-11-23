# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The lock file: its strict reader and canonical writer (issue #28, contracts §11)."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.findings import SkipReason
from ssc_guardian.lockfile import HEADER, LockEntry, dump_lock, load_lock, parse_lock
from ssc_guardian.plugin import AgeSource, TrustedAge
from ssc_guardian.settings import ConfigFileError, MalformedEntryError
from tests.refusal_sites import Refuses, refuses

pytestmark = pytest.mark.unit

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
OTHER_SHA = "0123456789abcdef0123456789abcdef01234567"
PLACE = "/repo/.ssc-guardian.lock"


def _entry(**changes: Any) -> LockEntry:
    base = LockEntry(
        "actions/checkout",
        SHA,
        "v4.2.2",
        date(2026, 11, 3),
        date(2026, 10, 28),
        AgeSource.ACTIVITY_LOG,
    )
    return replace(base, **changes)


def _pin(**changes: str) -> str:
    keys = {
        "action": '"actions/checkout"',
        "sha": f'"{SHA}"',
        "tag": '"v4.2.2"',
        "first_seen": "2026-11-03",
        "trusted": "2026-10-28",
        "trusted_source": '"activity-log"',
        **changes,
    }
    return "\n[[pin]]\n" + "".join(f"{k} = {v}\n" for k, v in keys.items() if v)


def _refused(text: str) -> str:
    with pytest.raises(ConfigFileError, match=re.escape(f"{PLACE}: ")) as caught:
        parse_lock(text, place=PLACE)
    assert caught.value.reason is SkipReason.CHECK_ERROR  # exit 2, never a pass
    assert caught.value.place == PLACE
    return caught.value.problem


def test_round_trip_is_byte_identical() -> None:
    entries = [
        _entry(),
        _entry(action="github/codeql-action/init", sha=OTHER_SHA, tag=OTHER_SHA),
        _entry(sha=OTHER_SHA, trusted=date(2026, 11, 3), trusted_source=AgeSource.LOCK_FIRST_SEEN),
    ]
    text = dump_lock(entries)
    assert text.startswith(HEADER + "format = 1\n")
    assert dump_lock(parse_lock(text, place=PLACE)) == text
    # Canonical: the same entries in any order give the same bytes.
    assert dump_lock(reversed(entries)) == text
    assert dump_lock(entries) == text


def test_unknown_key_is_refused() -> None:
    assert "unknown key 'note'" in _refused("format = 1\n" + _pin(note='"x"'))
    assert "unknown key 'extra'" in _refused('format = 1\nextra = "x"\n' + _pin())


def test_missing_key_is_refused() -> None:
    with refuses("lockfile.entry-missing-key"):
        assert "pin 1 has no first_seen" in _refused("format = 1\n" + _pin(first_seen=""))


def test_duplicate_entry_is_refused() -> None:
    # One commit is one entry, whatever its tag or dates; owner and repository case do not
    # make another Action (D18).
    with refuses("lockfile.repeats-earlier-entry"):
        assert (
            _refused("format = 1\n" + _pin() + _pin()) == f"pin 2 repeats an earlier entry for actions/checkout@{SHA}"
        )
    second = _pin(action='"Actions/Checkout"', tag='"v4"', trusted="2026-10-01")
    assert _refused("format = 1\n" + _pin() + second) == f"pin 2 repeats an earlier entry for Actions/Checkout@{SHA}"
    with (
        refuses("lockfile.two-entries-one-key"),
        pytest.raises(MalformedEntryError, match="two entries for actions/checkout@"),
    ):
        dump_lock([_entry(), _entry(action="ACTIONS/checkout", tag="v4")])


def test_several_commits_of_one_action_are_kept() -> None:
    # L3: blue and green pipelines may run two approved commits of one Action.
    entries = parse_lock("format = 1\n" + _pin() + _pin(sha=f'"{OTHER_SHA}"'), place=PLACE)
    assert [e.sha for e in entries] == [SHA, OTHER_SHA]


@pytest.mark.parametrize(
    "sha",
    [
        SHA.upper(),  # forged: uppercase hex
        SHA[:-1],  # 39 characters
        SHA + "0",  # 41 characters
        SHA[:-1] + "g",  # not hex
        SHA + "\\n",  # a trailing newline
        "v4.2.2",  # a tag where the commit belongs
    ],
)
def test_malformed_sha_is_refused(sha: str) -> None:
    problem = _refused("format = 1\n" + _pin(sha=f'"{sha}"'))
    assert problem == "pin 1: sha is not a valid sha"
    with (
        refuses("grammars.malformed-value"),
        refuses("lockfile.field-not-valid"),
        pytest.raises(MalformedEntryError, match="sha is not a valid sha"),
    ):
        _entry(sha=sha.replace("\\n", "\n"))


@pytest.mark.parametrize(
    ("key", "value", "field"),
    [
        ("action", '"actions/../checkout"', "action"),
        ("action", '"-owner/repo"', "action"),
        ("tag", '"v4..2"', "git-ref"),
        ("tag", '"refs/heads/main.lock"', "git-ref"),
    ],
)
def test_malformed_value_is_refused(key: str, value: str, field: str) -> None:
    assert _refused("format = 1\n" + _pin(**{key: value})) == f"pin 1: {key} is not a valid {field}"


@pytest.mark.parametrize("value", ['"2026-11-03"', "2026-11-03T10:00:00", "20261103"])
def test_date_must_be_a_toml_date(value: str) -> None:
    with refuses("lockfile.bad-entry-value"), refuses("settings.not-date-yyyy-mm-dd"):
        assert "first_seen is not a date" in _refused("format = 1\n" + _pin(first_seen=value))


@pytest.mark.parametrize(
    ("source", "said", "site"),
    [
        ('"registry-upload"', "trusted_source is not activity-log", refuses("lockfile.trusted-source-not")),
        ('"person-date"', "trusted_source is not activity-log", refuses("lockfile.trusted-source-not")),
        ('"tomorrow"', "is not a valid AgeSource", refuses("lockfile.bad-trusted-source")),
        ("1", "trusted_source is not a string", refuses("settings.not-string")),
    ],
)
def test_refused_trusted_source(source: str, said: str, site: Refuses) -> None:
    with site, refuses("lockfile.malformed-entry"):
        assert said in _refused("format = 1\n" + _pin(trusted_source=source))


def test_lock_first_seen_needs_trusted_equal_to_first_seen() -> None:
    # L1: the lock file never vouches for a date earlier than its own first sighting.
    with refuses("lockfile.trusted-source-lock-first-seen"):
        problem = _refused("format = 1\n" + _pin(trusted_source='"lock-first-seen"'))
    assert problem == "pin 1: trusted_source lock-first-seen needs trusted equal to first_seen"
    entry = _entry(trusted=date(2026, 11, 3), trusted_source=AgeSource.LOCK_FIRST_SEEN)
    assert entry.trusted_age() == TrustedAge(date(2026, 11, 3), AgeSource.LOCK_FIRST_SEEN)


def test_one_bad_entry_voids_the_whole_file() -> None:
    problem = _refused("format = 1\n" + _pin() + _pin(sha=f'"{OTHER_SHA}"', tag='"-x"'))
    assert problem == "pin 2: tag is not a valid git-ref"


def test_newer_format_version_is_refused() -> None:
    with refuses("lockfile.written-newer-ssc-guardian-lock"):
        problem = _refused("format = 2\n" + _pin(note='"a key format 2 added"'))
    assert problem == "was written by a newer ssc-guardian (lock format 2); this build reads lock format 1"


@pytest.mark.parametrize(
    "text", ["# no format line\n", "format = 0\n", "format = true\n", 'format = "1"\n', "format = 1.0\n", "[[pin]]\n"]
)
def test_format_other_than_one_is_malformed(text: str) -> None:
    with refuses("settings.must-start-format"):
        assert "format = 1" in _refused(text)


@pytest.mark.parametrize("text", ["", "\n  \n", "format = 1\n", HEADER + "format = 1\n"])
def test_empty_lock_file_reads_as_no_entries(text: str) -> None:
    assert parse_lock(text, place=PLACE) == ()
    assert dump_lock([]) == HEADER + "format = 1\n"


def test_not_toml_is_refused() -> None:
    assert "not valid TOML" in _refused("format = 1\n[[pin]\n")


def test_load_lock(tmp_path: Path) -> None:
    path = tmp_path / ".ssc-guardian.lock"
    assert load_lock(str(path)) == ()  # missing: no entries
    path.write_text(dump_lock([_entry()]), encoding="utf-8")
    assert load_lock(str(path)) == (_entry(),)
    path.write_bytes(b"format = 1\n\xff\n")
    with refuses("settings.not-utf8"), pytest.raises(ConfigFileError, match="not UTF-8"):
        load_lock(str(path))
