# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""T3 (wrong publisher), the deny list and ``acknowledge`` (issue #10).

GitHub is the in-process fixture from ``test_nested_and_advisories``; no test reaches the
network.
"""

from __future__ import annotations

import io
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import settings as settings_module
from ssc_guardian.cli import Request
from ssc_guardian.commands.acknowledge import Acknowledge
from ssc_guardian.findings import ExitCode, OptionKind, Result, Rule, Verb
from ssc_guardian.plugins.actions import publisher
from ssc_guardian.plugins.actions.resolver import Repository
from ssc_guardian.settings import FileKind, LayerSource, Settings, load_settings, parse_settings
from tests.refusal_sites import refuses
from tests.unit.test_nested_and_advisories import (
    NODE_ACTION,
    TODAY,
    GitHub,
    check,
    composite,
    listed,
    make_repo,
    only,
    rules,
    sha,
)

pytestmark = pytest.mark.unit

NEW = "someone/new-action"
NEW_ID = 61


class Tty(io.StringIO):
    """A person at a terminal, answering from the text given."""

    def isatty(self) -> bool:
        return True


def created(days_ago: int) -> str:
    return f"{(TODAY - timedelta(days=days_ago)).isoformat()}T12:00:00Z"


def acknowledge(root: Path, github: GitHub, answer: str = "y\n") -> tuple[Result, str]:
    err = io.StringIO()
    handler = Acknowledge(
        stdin=Tty(answer),
        stderr=err,
        cwd=str(root),
        home=str(root.parent / "home"),
        today=TODAY,
        client=github.client(),
    )
    return handler(Request(Verb.ACKNOWLEDGE, repository=NEW)), err.getvalue()


BASE = Repository(NEW, NEW_ID, "main", TODAY - timedelta(days=400), 5000, 10)


def repository(**changes: Any) -> Repository:
    return replace(BASE, **changes)


def settings_of(text: str) -> Settings:
    layer = parse_settings(text, kind=FileKind.REPOSITORY, source=LayerSource.REPOSITORY, place="/r/.ssc-guardian.toml")
    return Settings.of(layer)


def test_young_repository_first_use_blocks_until_acknowledged(tmp_path: Path) -> None:
    # Created 89 days ago blocks; 90 days ago is old enough.
    for days, blocked in ((89, True), (90, False)):
        github = GitHub()
        github.publisher(NEW, NEW_ID, created=created(days), files={(sha(1), "action.yml"): NODE_ACTION})
        root = make_repo(tmp_path / str(days), f"{NEW}@{sha(1)}")  # no lock entry: first use
        result, err = check(root, github)
        notice = only(result, Rule.FIRST_USE_PUBLISHER)
        assert (notice.item, notice.place) == (NEW, str(root))
        assert f"first use of {NEW} in this repository: created" in err and f"({days} days ago), 5000 stars" in err
        assert (Rule.YOUNG_REPOSITORY in rules(result)) is blocked
    github = GitHub()
    github.publisher(NEW, NEW_ID, created=created(10), files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path / "young", f"{NEW}@{sha(1)}", lock=[listed(NEW, sha(1), "v1")])
    with refuses("publisher.young-repository"):
        result, err = check(root, github)
    young = only(result, Rule.YOUNG_REPOSITORY)
    (exception, _) = young.options
    assert (exception.kind, exception.person_command, exception.person_target) == (
        OptionKind.EXCEPTION,
        Verb.ACKNOWLEDGE,
        NEW,
    )
    assert result.exit_code is ExitCode.VIOLATION
    assert f"ssc-guardian acknowledge {NEW}" in err
    # Pinned in the lock file, it still blocks every run; a person's acknowledgment lifts it.
    code, said = acknowledge(root, github)
    assert code.exit_code is ExitCode.RULES_MET, said
    assert "created" in said and "10 days ago" in said and f"repository ID: {NEW_ID}" in said
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET and rules(result) == []


def test_little_used_repository_blocks(tmp_path: Path) -> None:
    for stars, blocked in ((49, True), (50, False)):
        github = GitHub()
        github.publisher(NEW, NEW_ID, stars=stars, files={(sha(1), "action.yml"): NODE_ACTION})
        root = make_repo(tmp_path / str(stars), f"{NEW}@{sha(1)}", lock=[listed(NEW, sha(1), "v1")])
        result, err = check(root, github)
        assert (result.exit_code is ExitCode.VIOLATION) is blocked
        assert (rules(result) == [Rule.YOUNG_REPOSITORY]) is blocked
        assert (f"{stars} stars, under 50" in err) is blocked


def test_a_nested_young_repository_blocks_too(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(
        "someone/outer", 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"{NEW}@{sha(2)}")}
    )
    github.publisher(NEW, NEW_ID, created=created(5), tags={"v1": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"someone/outer@{sha(1)}", lock=[listed("someone/outer", sha(1), "v1")])
    result, _ = check(root, github)
    assert rules(result) == [Rule.YOUNG_REPOSITORY]  # no first-use notice: no workflow names it
    assert only(result, Rule.YOUNG_REPOSITORY).item == NEW


def test_changed_repository_id_voids_acknowledgment(tmp_path: Path) -> None:
    # Repo-jacking: the name now answers with another repository's ID.
    github = GitHub()
    github.publisher(NEW, NEW_ID + 1, created=created(3), files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{NEW}@{sha(1)}", lock=[listed(NEW, sha(1), "v1")])
    text = f'format = 1\n\n[[acknowledgment]]\nrepository = "{NEW}"\nrepository_id = {NEW_ID}\ndate = 2026-10-01\n'
    (root / ".ssc-guardian.toml").write_text(text)
    result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION and rules(result) == [Rule.YOUNG_REPOSITORY]
    assert f"records repository ID {NEW_ID}, but GitHub now gives {NEW} ID {NEW_ID + 1}: it is void" in err
    # acknowledge will not replace it: a person edits the entry by hand.
    with refuses("acknowledge.name-may-now-belong-another"):
        outcome, said = acknowledge(root, github)
    assert outcome.exit_code is ExitCode.INCOMPLETE and "the name may now belong to another repository" in said
    assert (root / ".ssc-guardian.toml").read_text() == text
    # The same ID as GitHub gives today is a valid acknowledgment.
    assert publisher.assess(repository(id=NEW_ID), today=TODAY, settings=settings_of(text)).acknowledged
    assert not publisher.assess(repository(id=NEW_ID + 1), today=TODAY, settings=settings_of(text)).acknowledged


def test_thresholds_cannot_be_lowered(tmp_path: Path) -> None:
    for key, value in (("young_repository_days", 89), ("min_stars", 49)):
        github = GitHub()
        github.publisher(NEW, NEW_ID, files={(sha(1), "action.yml"): NODE_ACTION})
        root = make_repo(tmp_path / key, f"{NEW}@{sha(1)}", lock=[listed(NEW, sha(1), "v1")])
        (root / ".ssc-guardian.toml").write_text(f"format = 1\n[defaults]\n{key} = {value}\n")
        result, err = check(root, github)
        assert result.exit_code is ExitCode.INCOMPLETE  # a malformed file applies nothing, never the default
        assert f"{key} is not a whole number from" in err
    # Raised values apply, and across files the stricter one wins.
    github = GitHub()
    github.publisher(NEW, NEW_ID, created=created(110), stars=900, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path / "raised", f"{NEW}@{sha(1)}", lock=[listed(NEW, sha(1), "v1")])
    home = tmp_path / "raised" / "home"
    (home / ".config" / "ssc-guardian").mkdir(parents=True)
    (home / ".config" / "ssc-guardian" / "config.toml").write_text(
        "format = 1\n[defaults]\nyoung_repository_days = 120\n"
    )
    (root / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nyoung_repository_days = 100\nmin_stars = 1000\n")
    result, err = check(root, github, home=home)
    assert Rule.YOUNG_REPOSITORY in rules(result) and Rule.WEAKENED_SETTING in rules(result)
    assert "created 110 days ago, under 120" in err and "900 stars, under 1000" in err


OWN = publisher.OWN_REPOSITORY


def own_young(name: str = OWN, repo_id: int | None = None) -> Repository:
    """A repository created yesterday with no stars: T3 blocks it unless it is exempt."""
    the_id = publisher.OWN_REPOSITORY_ID if repo_id is None else repo_id
    assert the_id is not None
    return repository(name=name, id=the_id, created=TODAY - timedelta(days=1), stars=0)


def test_own_repository_exempt_by_exact_name_and_id() -> None:
    # The public repository's numeric ID is recorded in code (#233), so the default applies it.
    own_id = publisher.OWN_REPOSITORY_ID
    assert type(own_id) is int and own_id > 0
    assert own_id == 1455613272  # thomascburns/ssc-guardian, read from GitHub (#233); catches a typo
    assessment = publisher.assess(own_young(), today=TODAY, settings=Settings())
    assert assessment.young and assessment.little_used  # T3 would block it ...
    assert assessment.exempt and not assessment.blocked  # ... but it is Guardian's own
    assert publisher.is_own_repository(own_young())


def test_same_name_other_id_is_not_exempt() -> None:
    # The negative control: a planted repository with the exact name and another ID
    # (repo-jacking) is never exempt.
    own_id = publisher.OWN_REPOSITORY_ID
    assert own_id is not None
    for other_id in (own_id + 1, own_id - 1, 1):
        planted = own_young(repo_id=other_id)
        assert not publisher.is_own_repository(planted)
        assessment = publisher.assess(planted, today=TODAY, settings=Settings())
        assert not assessment.exempt and assessment.blocked


def test_other_name_same_id_is_not_exempt() -> None:
    # The ID alone exempts nothing, nor does the name in another letter case.
    for name in ("someone/ssc-guardian", "thomascburns/ssc-guardian-fork", "ThomasCBurns/ssc-guardian"):
        other = own_young(name=name)
        assert not publisher.is_own_repository(other)
        assert publisher.assess(other, today=TODAY, settings=Settings()).blocked


def test_exemption_is_idempotent_on_re_run(tmp_path: Path) -> None:
    own_id = publisher.OWN_REPOSITORY_ID
    assert own_id is not None
    cases = (own_young(), own_young(repo_id=own_id + 1))
    first = [publisher.assess(r, today=TODAY, settings=Settings()) for r in cases]
    second = [publisher.assess(r, today=TODAY, settings=Settings()) for r in cases]
    assert first == second and [a.blocked for a in first] == [False, True]
    # Through the real check: the same verdict on every run, and nothing written.
    github = GitHub()
    github.publisher(OWN, own_id, created=created(1), stars=0, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OWN}@{sha(1)}", lock=[listed(OWN, sha(1), "v1")])
    before = sorted(p.relative_to(root) for p in root.rglob("*"))
    runs = [check(root, github) for _ in range(2)]
    assert runs[0] == runs[1]
    assert runs[0][0].exit_code is ExitCode.RULES_MET and Rule.YOUNG_REPOSITORY not in rules(runs[0][0])
    assert sorted(p.relative_to(root) for p in root.rglob("*")) == before


def test_missing_metadata_is_not_exempt(tmp_path: Path) -> None:
    own_id = publisher.OWN_REPOSITORY_ID
    assert own_id is not None
    # No recorded ID: nothing is exempt, so the exemption never rests on the name alone.
    assert not publisher.is_own_repository(own_young(), None)
    assert publisher.assess(own_young(), today=TODAY, settings=Settings(), own_id=None).blocked
    # GitHub's record of the repository has no ID: the check refuses it and never passes.
    github = GitHub()
    github.publisher(OWN, own_id, created=created(1), stars=0, files={(sha(1), "action.yml"): NODE_ACTION})
    del github.routes[f"/repos/{OWN}"][1]["id"]
    root = make_repo(tmp_path, f"{OWN}@{sha(1)}", lock=[listed(OWN, sha(1), "v1")])
    with refuses("resolver.sent-repository-id-not-positive"):
        result, _ = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE


def test_deny_list_blocks_named_action(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(
        "bad/action",
        71,
        tags={"v1": sha(1)},
        files={(sha(1), "sub/action.yml"): NODE_ACTION, (sha(1), "action.yml"): NODE_ACTION},
    )
    github.publisher(
        "someone/outer", 11, tags={"v1": sha(2)}, files={(sha(2), "action.yml"): composite(f"bad/action@{sha(1)}")}
    )
    root = make_repo(
        tmp_path,
        f"Bad/Action/sub@{sha(1)}",
        f"someone/outer@{sha(2)}",
        lock=[listed("bad/action/sub", sha(1), "v1"), listed("someone/outer", sha(2), "v1")],
    )
    # An acknowledgment changes nothing: a deny entry blocks whatever any other layer says.
    (root / ".ssc-guardian.toml").write_text(
        'format = 1\ndeny = ["github-actions:bad/action"]\n\n[[acknowledgment]]\nrepository = "bad/action"\n'
        "repository_id = 71\ndate = 2026-10-01\n"
    )
    with refuses("publisher.denied-action"):
        result, _ = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    denied = [f for f in result.findings if f.rule is Rule.DENY_LIST]
    assert [(f.item, f.via) for f in denied] == [("Bad/Action/sub", ()), ("bad/action", (f"someone/outer@{sha(2)}",))]
    assert all(o.kind is OptionKind.REMOVE for f in denied for o in f.options)


def test_acknowledge_records_the_numeric_id_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    github = GitHub()
    github.publisher(NEW, NEW_ID, created=created(10))
    root = make_repo(tmp_path, f"{NEW}@v1")
    settings_file = root / ".ssc-guardian.toml"
    settings_file.write_text("# kept\nformat = 1\n")
    writes: list[str] = []
    real = settings_module.atomic_write

    def recording(path: str, text: str) -> None:
        writes.append(path)
        real(path, text)

    monkeypatch.setattr(settings_module, "atomic_write", recording)
    # Declined: nothing written (exit 2).
    with refuses("acknowledge.not-confirmed"):
        outcome, said = acknowledge(root, github, answer="n\n")
    assert outcome.exit_code is ExitCode.INCOMPLETE and "not confirmed; nothing written" in said
    assert writes == [] and settings_file.read_text() == "# kept\nformat = 1\n"
    # Confirmed: one atomic write, the comment kept, the numeric ID recorded.
    outcome, said = acknowledge(root, github)
    assert outcome.exit_code is ExitCode.RULES_MET and outcome.checked[0].place == str(root)
    assert writes == [str(settings_file)]
    first = settings_file.read_text()
    assert first.startswith("# kept\n")
    layer = load_settings(str(settings_file), kind=FileKind.REPOSITORY)
    assert layer is not None
    (entry,) = layer.acknowledgments
    assert (entry.repository, entry.repository_id, entry.date) == (NEW, NEW_ID, TODAY)
    assert type(entry.repository_id) is int
    # Again: idempotent, nothing written.
    outcome, said = acknowledge(root, github)
    assert outcome.exit_code is ExitCode.RULES_MET and "already acknowledged" in said
    assert writes == [str(settings_file)] and settings_file.read_text() == first


def test_acknowledge_needs_a_repository_and_a_terminal(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(NEW, NEW_ID)
    outside = tmp_path.resolve() / "outside"
    outside.mkdir()
    handler = Acknowledge(stdin=Tty("y\n"), stderr=io.StringIO(), cwd=str(outside), client=github.client())
    assert handler(Request(Verb.ACKNOWLEDGE, repository=NEW)).exit_code is ExitCode.INCOMPLETE
    root = make_repo(tmp_path, f"{NEW}@v1")
    err = io.StringIO()
    handler = Acknowledge(stdin=io.StringIO("y\n"), stderr=err, cwd=str(root), client=github.client())
    assert handler(Request(Verb.ACKNOWLEDGE, repository=NEW)).exit_code is ExitCode.INCOMPLETE
    assert "needs a person at a terminal" in err.getvalue() and github.seen == []
    assert not (root / ".ssc-guardian.toml").exists()
