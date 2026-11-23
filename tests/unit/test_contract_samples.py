# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The settings sample in ``docs/contracts.md`` §10.2 loads with Guardian's own parser (issue #198).

The sample is read from the document itself, never a copy, so an edit that breaks it fails here.
It shows both files' keys at once, each kind-specific part marked in a comment: ``config.toml
only`` (the ``pypi:`` deny entry and rule, #229; ``venv_folders`` left with ``[scope]`` in #255)
and ``.ssc-guardian.toml only`` (``[[acknowledgment]]``). The other kind refuses those parts
(§10.2), so each file is the sample without the parts the other kind refuses.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from collections import Counter
from pathlib import Path

import pytest

from ssc_guardian.findings import Ecosystem, SkipReason
from ssc_guardian.settings import ConfigFileError, FileKind, Layer, LayerSource, parse_settings
from tests.refusal_sites import Refuses, refuses

pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

CONTRACTS = Path(__file__).resolve().parents[2] / "docs" / "contracts.md"

_SOURCE = {FileKind.REPOSITORY: LayerSource.REPOSITORY, FileKind.WORKSTATION: LayerSource.WORKSTATION}
_PLACE = {
    FileKind.REPOSITORY: "/repo/.ssc-guardian.toml",
    FileKind.WORKSTATION: "/Users/me/.config/ssc-guardian/config.toml",
}
_PYPI_DENY = (Ecosystem.PYPI, "example-bad")
_ACTION_DENY = (Ecosystem.GITHUB_ACTIONS, "example/bad-action")
_PYPI_RULE = (Ecosystem.PYPI, "requests")
_ACTION_RULE = (Ecosystem.GITHUB_ACTIONS, "actions/checkout")


def _sample() -> str:
    """The one TOML block in §10.2 of the contracts document."""
    text = CONTRACTS.read_text(encoding="utf-8")
    section = re.search(r"^### 10\.2 .*?(?=^### )", text, re.M | re.S)
    assert section is not None, "docs/contracts.md has no §10.2"
    blocks: list[str] = re.findall(r"```toml\n(.*?)```", section.group(0), re.S)
    assert len(blocks) == 1, "§10.2 must hold exactly one TOML sample"
    return blocks[0]


def _for(kind: FileKind, sample: str) -> str:
    """The sample as one kind of file: without the lines or tables marked for the other kind."""
    other = "config.toml only" if kind is FileKind.REPOSITORY else ".ssc-guardian.toml only"
    kept: list[str] = []
    dropping = False
    for line in sample.splitlines():
        if line.startswith("["):
            dropping = other in line
        if dropping or (not line.startswith("[") and other in line):
            continue
        kept.append(line)
    return "\n".join(kept) + "\n"


def _load(kind: FileKind, text: str) -> Layer:
    return parse_settings(text, kind=kind, source=_SOURCE[kind], place=_PLACE[kind], home="/Users/me")


@pytest.mark.parametrize("kind", [FileKind.REPOSITORY, FileKind.WORKSTATION])
def test_contracts_settings_sample_loads(kind: FileKind) -> None:
    """The §10.2 sample parses with Guardian's settings parser, its deny list at the top level."""
    sample = _sample()
    assert "deny" in tomllib.loads(sample), "the sample's deny list must come before the first table"
    text = _for(kind, sample)
    # Counted, not looked up: a dropped line identical to a kept one (a blank line) still counts.
    left = Counter(text.splitlines())
    dropped: list[str] = []
    for line in sample.splitlines():
        if left[line]:
            left[line] -= 1
        else:
            dropped.append(line)
    assert not +left, "the file holds a line the sample does not"
    first_words = [line.split()[0] if line.strip() else "" for line in dropped]
    if kind is FileKind.REPOSITORY:
        assert first_words == ['"pypi:example-bad",', '"pypi:requests"']
    else:
        assert first_words == [
            "[[acknowledgment]]",
            "repository",
            "repository_id",
            "date",
            "note",
            "",
        ]

    layer = _load(kind, text)

    if kind is FileKind.REPOSITORY:  # pypi entries belong in config.toml only (#229)
        assert layer.deny == {_ACTION_DENY}
        assert layer.rules == {_ACTION_RULE: 7}
    else:
        assert layer.deny == {_PYPI_DENY, _ACTION_DENY}
        assert layer.rules == {_PYPI_RULE: 30, _ACTION_RULE: 7}
    assert len(layer.start_dates) == 1
    assert len(layer.acknowledgments) == (1 if kind is FileKind.REPOSITORY else 0)
    assert "scope" not in tomllib.loads(sample)  # no setting chooses what a command reads (#255)


@pytest.mark.parametrize(
    ("kind", "site", "said"),
    [
        (FileKind.REPOSITORY, refuses("settings.repository-pypi-rule"), "rule 'pypi:requests' is a pypi entry"),
        (FileKind.WORKSTATION, refuses("settings.unknown-key"), "unknown key 'acknowledgment'"),
    ],
)
def test_whole_sample_is_refused_by_each_kind(kind: FileKind, site: Refuses, said: str) -> None:
    """Error path: the marked parts really belong to one kind; the other refuses the whole sample."""
    with (
        site,
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(said)),
    ):
        _load(kind, _sample())


def test_deny_under_rules_is_rejected() -> None:
    """Error path: the old placement, ``deny`` after ``[rules]``, reads as a rule and is refused."""
    lines = _for(FileKind.REPOSITORY, _sample()).splitlines()
    starts = [n for n, line in enumerate(lines) if line.startswith("deny = [")]
    assert len(starts) == 1, "the sample must hold one deny list"
    end = next(n for n in range(starts[0], len(lines)) if lines[n].rstrip().endswith("]"))
    deny = lines[starts[0] : end + 1]
    del lines[starts[0] : end + 1]
    # Put it back after the last [rules] entry, where the sample had it before #198.
    at = next(n for n, line in enumerate(lines) if line.startswith("[rules]")) + 1
    while at < len(lines) and lines[at].startswith('"'):
        at += 1
    misplaced = "\n".join([*lines[:at], "", *deny, *lines[at:]]) + "\n"
    assert "deny" in tomllib.loads(misplaced)["rules"], "the deny list did not move under [rules]"

    with (
        refuses("settings.does-not-name-ecosystem-pypi"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match="does not name its ecosystem"),
    ):
        _load(FileKind.REPOSITORY, misplaced)


def test_sample_check_is_idempotent_on_re_run() -> None:
    """Idempotency: loading the sample twice gives equal layers and leaves the document unchanged."""
    before = hashlib.sha256(CONTRACTS.read_bytes()).hexdigest()
    first = _load(FileKind.REPOSITORY, _for(FileKind.REPOSITORY, _sample()))
    second = _load(FileKind.REPOSITORY, _for(FileKind.REPOSITORY, _sample()))
    assert first == second
    assert hashlib.sha256(CONTRACTS.read_bytes()).hexdigest() == before


def _skip_reason_table(text: str) -> tuple[set[str], set[str]]:
    """The in-scope and out-of-scope columns of the contracts document's skip reason table."""
    table = re.search(r"^\*\*Skip reasons:\*\*\n\n\| In scope .*?\n\|---\|---\|\n\| (.*?) \| (.*?) \|$", text, re.M)
    assert table is not None, "docs/contracts.md has no skip reason table"
    return set(re.findall(r"`([^`]+)`", table.group(1))), set(re.findall(r"`([^`]+)`", table.group(2)))


def _table_matches_the_enum(text: str) -> bool:
    in_scope, out_of_scope = _skip_reason_table(text)
    return (in_scope, out_of_scope) == (
        {r.value for r in SkipReason if r.in_scope},
        {r.value for r in SkipReason if not r.in_scope},
    )


def test_skip_reason_table_matches_the_enum() -> None:
    # #282: the published table and SkipReason stay equal, column by column.
    text = CONTRACTS.read_text(encoding="utf-8")
    assert _table_matches_the_enum(text)
    # Error path: a planted table that still names `default-scope` is rejected.
    planted = text.replace("| `filtered`, `later-release`", "| `filtered`, `default-scope`, `later-release`", 1)
    assert planted != text
    assert not _table_matches_the_enum(planted)
