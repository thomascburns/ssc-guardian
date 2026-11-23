# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``moved-release-tag``: a release tag the lock file recorded now names another commit (#201).

``check --repo`` compares the tag each outer pinned commit was recorded under with the tags list
T6 already reads. Only a release tag (three release parts after an optional ``v``) is compared:
a major or line tag moves by design. GitHub is the in-process fixture of the Actions tests, so
no test reaches the network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ssc_guardian.commands.check_repo import is_release_tag
from ssc_guardian.findings import ExitCode, Level, Rule, SkipReason
from tests.refusal_sites import refuses
from tests.unit.test_nested_and_advisories import NODE_ACTION, Advisory, GitHub, check, listed, make_repo, sha

pytestmark = pytest.mark.unit

ACTION = "someone/tool"
RECORDED, NOW = sha(0x28), sha(0x66)  # the commit the lock file recorded; the one the tag names now
WORKFLOW = Path(".github") / "workflows" / "ci.yml"


def _github(tags: dict[str, str]) -> GitHub:
    """The publisher with ``tags``; both commits hold an Action."""
    github = GitHub()
    github.publisher(
        ACTION, 31, tags=tags, files={(RECORDED, "action.yml"): NODE_ACTION, (NOW, "action.yml"): NODE_ACTION}
    )
    return github


def _repo(tmp_path: Path, tag: str) -> Path:
    """A workflow pinned to RECORDED, which the lock file records under ``tag``."""
    return make_repo(tmp_path, f"{ACTION}@{RECORDED} # {tag}", lock=[listed(ACTION, RECORDED, tag)])


@pytest.mark.parametrize("tag", ["0.28.0", "v4.2.2"])
def test_moved_release_tag_warns_with_both_commits(tmp_path: Path, tag: str) -> None:
    root = _repo(tmp_path / "moved", tag)
    result, err = check(root, _github({tag: NOW}))
    assert result.exit_code is ExitCode.RULES_MET, err  # a warning alone never fails a run
    (finding,) = result.findings
    assert (finding.rule, finding.level, finding.item, finding.version) == (
        Rule.MOVED_RELEASE_TAG,
        Level.WARNING,
        ACTION,
        RECORDED,
    )
    assert finding.place == str(root / WORKFLOW)
    assert finding.detail == f"release tag {tag} was recorded for {RECORDED}; it names {NOW} today"
    assert f"release tag {tag} names {NOW} today, not {RECORDED}" in err

    # Negative control: the same setup with the tag left on the recorded commit warns of nothing.
    control = _repo(tmp_path / "control", tag)
    result, err = check(control, _github({tag: RECORDED}))
    assert result.exit_code is ExitCode.RULES_MET and result.findings == (), err
    assert "release tag" not in err


def test_major_and_line_tags_never_warn(tmp_path: Path) -> None:
    for tag in ("v4", "4", "v4.1", "4.1", "stable", "latest"):
        root = _repo(tmp_path / tag, tag)
        result, err = check(root, _github({tag: NOW}))
        assert result.exit_code is ExitCode.RULES_MET and result.findings == (), (tag, err)
    # Which tags are compared: three release parts or more, after an optional v.
    for tag in ("0.28.0", "v4.2.2", "V1.2.3", "v1.0.0-rc1", "1.2.3.4"):
        assert is_release_tag(tag), tag
    for tag in ("v4", "4", "v4.1", "4.1", "stable", "latest", "main", "V", RECORDED):
        assert not is_release_tag(tag), tag


def test_deleted_or_unmoved_tag_adds_nothing(tmp_path: Path) -> None:
    # Deleted: the recorded tag is gone from the publisher's list; a deletion is not a move.
    deleted = _repo(tmp_path / "deleted", "0.28.0")
    result, err = check(deleted, _github({"0.29.0": NOW}))
    assert result.exit_code is ExitCode.RULES_MET and result.findings == (), err
    # Unmoved: the tag still names the recorded commit, while another tag moved.
    unmoved = _repo(tmp_path / "unmoved", "0.28.0")
    result, err = check(unmoved, _github({"0.28.0": RECORDED, "0.29.0": NOW}))
    assert result.exit_code is ExitCode.RULES_MET and result.findings == (), err
    # A commit recorded as its own tag (a bare SHA) has no release tag to compare.
    bare = make_repo(tmp_path / "bare", f"{ACTION}@{RECORDED}", lock=[listed(ACTION, RECORDED)])
    result, err = check(bare, _github({"0.28.0": NOW}))
    assert result.exit_code is ExitCode.RULES_MET and result.findings == (), err
    # Control: the same lock entry with the tag moved does warn, so the cases above are not vacuous.
    moved = _repo(tmp_path / "moved", "0.28.0")
    result, _ = check(moved, _github({"0.28.0": NOW}))
    assert [f.rule for f in result.findings] == [Rule.MOVED_RELEASE_TAG]


def test_tags_request_failure_is_exit_2_never_a_pass(tmp_path: Path) -> None:
    github = _github({"0.28.0": NOW})
    github.routes[f"/repos/{ACTION}/tags?per_page=100"] = (500, {"message": "Server Error"})
    root = _repo(tmp_path, "0.28.0")
    with refuses("net.feed-answered-http-error"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE, err  # unfinished, never a pass
    assert result.findings == () and result.checked == ()
    assert [(s.place, s.reason) for s in result.skipped] == [(str(root), SkipReason.FEED_FAILURE)]
    assert github.count(f"/repos/{ACTION}/tags") == 1  # asked once, as before; never asked again
    assert github.count("/advisories") == 0


def test_warning_never_replaces_a_refusal(tmp_path: Path) -> None:
    # An advisory for the release the pin was recorded under: T6's violation stands, exit 1, and
    # the move is reported beside it.
    github = _github({"0.28.0": NOW})
    github.advisories.append(Advisory("GHSA-69fq-xp46-6x23", ACTION, "<= 0.34.2", "0.35.0"))
    root = _repo(tmp_path, "0.28.0")
    with refuses("advisories.advisory-hit"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION, err
    assert sorted((f.rule, f.level) for f in result.findings) == [
        (Rule.KNOWN_VULNERABILITY, Level.VIOLATION),
        (Rule.MOVED_RELEASE_TAG, Level.WARNING),
    ]
    # T1 and T4: a use by the moved tag stays moving-reference, and the moved commit, which the
    # lock file does not list, stays unverified-pin; neither gains the warning.
    for uses, rule in [(f"{ACTION}@0.28.0", Rule.MOVING_REFERENCE), (f"{ACTION}@{NOW}", Rule.UNVERIFIED_PIN)]:
        other = make_repo(tmp_path / rule.value, uses, lock=[listed(ACTION, RECORDED, "0.28.0")])
        with refuses("resolver.reference-not-pinned"):
            result, err = check(other, _github({"0.28.0": NOW}))
        assert result.exit_code is ExitCode.VIOLATION, err
        assert [f.rule for f in result.findings] == [rule], err
