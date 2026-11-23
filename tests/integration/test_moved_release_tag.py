# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``moved-release-tag`` end to end through the real ``check --repo`` and ``pin`` handlers (#201).

The warning reads only what each run already reads (the lock file and the publisher's tags
list): it sends no request a run did not send before, never changes the exit code, and ``pin``
writes exactly what it writes without it. The control for each is the same run with the
comparison turned off (``is_release_tag`` answering no). GitHub is a fixture; nothing reaches the
network.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from ssc_guardian.cli import Request
from ssc_guardian.commands import check_repo
from ssc_guardian.commands.pin import Pin
from ssc_guardian.findings import ExitCode, Level, Result, Rule, Verb
from ssc_guardian.lockfile import LOCK_FILE, load_lock
from ssc_guardian.render import ToolInfo, to_json_obj, to_text
from tests.unit.test_nested_and_advisories import NODE_ACTION, GitHub, check, listed, make_repo, sha
from tests.unit.test_pinning import TODAY, FakeGitHub, github_routes, push

pytestmark = pytest.mark.integration

ACTION = "someone/tool"
TAG = "0.28.0"
RECORDED, NOW = sha(0x28), sha(0x66)
WORKFLOW = Path(".github") / "workflows" / "ci.yml"


def _github() -> GitHub:
    """``check --repo``'s GitHub: the release tag has moved from RECORDED to NOW."""
    github = GitHub()
    github.publisher(ACTION, 31, tags={TAG: NOW}, files={(RECORDED, "action.yml"): NODE_ACTION})
    return github


def _repo(tmp_path: Path, tag: str = TAG, *, action: str = ACTION) -> Path:
    """A workflow pinned to ``action``@RECORDED, which the lock file records under ``tag``."""
    return make_repo(tmp_path, f"{action}@{RECORDED} # {tag}", lock=[listed(action, RECORDED, tag)])


def _snapshot(folder: Path) -> dict[str, str]:
    return {
        str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


def _pin(root: Path, github: FakeGitHub, ref: str = TAG) -> tuple[Result, str]:
    """``pin ACTION@REF --yes`` on the day NOW was pushed: a pin of NOW is inside its cooldown."""
    err = io.StringIO()
    handler = Pin(
        stdin=io.StringIO(""),
        stderr=err,
        cwd=str(root),
        home=str(root.parent / "home"),
        today=TODAY,
        client=github.client(),
    )
    return handler(Request(Verb.PIN, action=ACTION, ref=ref, yes=True)), err.getvalue()


def _pin_github(tags: dict[str, str] | None = None) -> FakeGitHub:
    routes = github_routes(
        ACTION,
        tags={TAG: NOW} if tags is None else tags,
        activity=[push(RECORDED, "2025-06-01T00:00:00Z"), push(NOW, f"{TODAY.isoformat()}T00:00:00Z")],
        history={RECORDED: "behind", NOW: "behind"},
    )
    return FakeGitHub(routes)


def test_check_repo_warns_and_exits_zero_on_a_moved_release_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = _github()
    root = _repo(tmp_path / "moved")
    result, err = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET, err
    assert [(f.rule, f.level) for f in result.findings] == [(Rule.MOVED_RELEASE_TAG, Level.WARNING)]
    (shown,) = to_json_obj(result, ToolInfo("1.0.0"))["findings"]
    assert (shown["rule"], shown["level"], shown["item"], shown["version"]) == (
        "moved-release-tag",
        "warning",
        ACTION,
        RECORDED,
    )
    text = to_text(result, ToolInfo("1.0.0"))
    assert f"WARNING moved-release-tag github-actions {ACTION} {RECORDED}\n" in text
    assert f"  detail: release tag {TAG} was recorded for {RECORDED}; it names {NOW} today\n" in text

    # Control: the same run with the comparison off sends exactly the same requests.
    control = _github()
    monkeypatch.setattr(check_repo, "is_release_tag", lambda tag: False)
    result, err = check(_repo(tmp_path / "control"), control)
    assert result.exit_code is ExitCode.RULES_MET and result.findings == (), err
    assert github.seen == control.seen
    assert github.count(f"/repos/{ACTION}/tags") == 1


def test_pin_of_moved_tag_warns_before_the_cooldown_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    github = _pin_github()
    root = _repo(tmp_path / "moved")
    workflow = (root / WORKFLOW).read_bytes()
    result, err = _pin(root, github)
    assert result.exit_code is ExitCode.RULES_MET, err
    assert [(f.rule, f.level, f.item, f.version) for f in result.findings] == [
        (Rule.MOVED_RELEASE_TAG, Level.WARNING, ACTION, RECORDED),
        (Rule.COOLDOWN_WAIT, Level.NOTICE, ACTION, NOW),
    ]
    warning = f"Warning: {ACTION}: release tag {TAG} names {NOW} today, not {RECORDED}, the commit the lock file"
    assert warning in err
    assert err.index(warning) < err.index("inside its 21-day cooldown")
    # Data integrity: the workflow is unchanged, and the lock file gains the waiting commit only.
    assert (root / WORKFLOW).read_bytes() == workflow
    assert {(e.sha, e.tag) for e in load_lock(str(root / LOCK_FILE))} == {(RECORDED, TAG), (NOW, TAG)}

    # Control: the same pin with the comparison off writes the same bytes and sends the same requests.
    control_github = _pin_github()
    control = _repo(tmp_path / "control")
    monkeypatch.setattr(check_repo, "is_release_tag", lambda tag: False)
    control_result, control_err = _pin(control, control_github)
    assert [f.rule for f in control_result.findings] == [Rule.COOLDOWN_WAIT], control_err
    assert _snapshot(root) == _snapshot(control)
    assert github.seen == control_github.seen


def test_pin_compares_only_a_moved_release_tag_of_the_same_repository(tmp_path: Path) -> None:
    # Controls for pin (#201 review): a moved major tag, an unmoved release tag, and the same tag
    # name recorded for another repository's Action each give no warning.
    major = _repo(tmp_path / "major", "v4")
    result, err = _pin(major, _pin_github({"v4": NOW}), "v4")
    assert [f.rule for f in result.findings] == [Rule.COOLDOWN_WAIT], err
    assert "release tag" not in err

    unmoved = _repo(tmp_path / "unmoved")
    result, err = _pin(unmoved, _pin_github({TAG: RECORDED}))
    assert result.exit_code is ExitCode.RULES_MET and result.findings == (), err
    assert "Nothing to write" in err and "release tag" not in err

    other = _repo(tmp_path / "other", action="other/tool")
    result, err = _pin(other, _pin_github())
    assert Rule.MOVED_RELEASE_TAG not in [f.rule for f in result.findings], err
    assert Rule.COOLDOWN_WAIT in [f.rule for f in result.findings]
    assert "release tag" not in err


def test_pin_of_a_recorded_commit_whose_tag_moved_warns_through_the_shared_check(tmp_path: Path) -> None:
    # pin ACTION@RECORDED, the commit the lock file lists under the release tag that has since
    # moved: pin's pre-write check, shared with check --repo (#126), warns once; the pin is
    # written as before, since the warning never refuses.
    root = make_repo(tmp_path, f"{ACTION}@{TAG}", lock=[listed(ACTION, RECORDED, TAG)])
    result, err = _pin(root, _pin_github(), RECORDED)
    assert result.exit_code is ExitCode.RULES_MET, err
    assert [(f.rule, f.item, f.version) for f in result.findings] == [(Rule.MOVED_RELEASE_TAG, ACTION, RECORDED)]
    assert f"{ACTION}: release tag {TAG} names {NOW} today, not {RECORDED}" in err
    assert f"uses: {ACTION}@{RECORDED} # {TAG}" in (root / WORKFLOW).read_text()


def test_moved_release_tag_is_idempotent_on_re_run(tmp_path: Path) -> None:
    # check --repo writes nothing in the repository (only its cache of files at a commit, under
    # home): two runs give the same result and leave every repository file as it was.
    root = _repo(tmp_path / "check")
    before = _snapshot(root)
    first, second = check(root, _github()), check(root, _github())
    assert first == second
    assert [f.rule for f in first[0].findings] == [Rule.MOVED_RELEASE_TAG]
    assert _snapshot(root) == before

    # pin: the second run finds the waiting commit recorded, writes nothing, and warns again.
    pinned = _repo(tmp_path / "pin")
    runs = [_pin(pinned, _pin_github()) for _ in range(2)]
    after_first = _snapshot(pinned)
    third = _pin(pinned, _pin_github())
    assert _snapshot(pinned) == after_first
    assert runs[0][0].findings == runs[1][0].findings == third[0].findings
    assert [f.rule for f in third[0].findings] == [Rule.MOVED_RELEASE_TAG, Rule.COOLDOWN_WAIT]
    assert "Nothing to write" in runs[1][1] and "Nothing to write" in third[1]
