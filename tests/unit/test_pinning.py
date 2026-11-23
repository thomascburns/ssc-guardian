# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""T1, T2 and T4: the resolver, the cooldown clock and ``pin``'s checks (issue #9).

GitHub is a fixture: :class:`FakeGitHub` answers the client's requests in process, so no test
reaches the network.
"""

from __future__ import annotations

import io
import json
import os
import re
import unicodedata
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import yaml_subset
from ssc_guardian.cli import Request
from ssc_guardian.commands import check_repo as check_repo_module
from ssc_guardian.commands import pin as pin_module
from ssc_guardian.commands.pin import Pin, Source, prune, read_sources, rewrite
from ssc_guardian.findings import (
    Ecosystem,
    ExitCode,
    FindingField,
    IncompleteCheckError,
    Level,
    Result,
    Rule,
    SkipReason,
    Verb,
)
from ssc_guardian.lockfile import LOCK_FILE, LockEntry, canonical, dump_lock, load_lock
from ssc_guardian.net import Client, FeedError, Response
from ssc_guardian.plugin import AgeSource, TrustedAge
from ssc_guardian.plugins.actions import advisories, clock, nested, resolver
from ssc_guardian.plugins.actions.models import UsesKind, UsesReference, action_from
from ssc_guardian.yaml_subset import UnsupportedYamlError
from tests.refusal_sites import refuses
from tests.unit.test_nested_and_advisories import NODE_ACTION, Advisory, GitHub, listed, make_repo
from tests.unit.test_nested_and_advisories import check as check_repo

pytestmark = pytest.mark.unit

TODAY = date(2026, 11, 3)
NEW = "11bd71901bbe5b1630ceea73d27597364c9af683"
OLD = "b4ffde65f46336ab88eb53be808477a3936bae11"
IMPOSTOR = "0e58ed8671d6b60d0890c21b07f8835ace038e67"
CACHE = "1bd1e32a3bdc45362d1e726936510720a7c30a57"
WORKFLOW = "/repo/.github/workflows/ci.yml"
ADVISORIES = "/advisories"  # every query GitHub's advisories API is asked (T6)

CI = """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: setup
        uses: "actions/setup-python@v5"  # python
      - run: |
          echo uses: actions/checkout@v4
      - uses: Actions/Checkout@v3 # older
"""


# --- fixtures -------------------------------------------------------------------------


class FakeGitHub:
    """Answers GET requests to api.github.com from a route table; anything else is a 404. Every
    advisories query gets the ``/advisories`` route's answer (T6, #126)."""

    def __init__(self, routes: dict[str, tuple[Any, ...]]) -> None:
        self.routes = routes
        self.seen: list[str] = []

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        parts = urllib.parse.urlsplit(request.full_url)
        assert (parts.scheme, parts.hostname, request.get_method()) == ("https", "api.github.com", "GET")
        key = parts.path + (f"?{parts.query}" if parts.query else "")
        self.seen.append(key)
        route = self.routes.get(key) or (self.routes.get(parts.path) if parts.path == ADVISORIES else None)
        status, body, *headers = route or (404, {"message": "Not Found"})
        return Response(status, headers[0] if headers else {}, json.dumps(body).encode(), request.full_url)

    def client(self) -> Client:
        return Client(transport=self)


def push(sha: str, when: str, *, ref: str = "refs/heads/main", kind: str = "push") -> dict[str, str]:
    return {"activity_type": kind, "ref": ref, "after": sha, "before": "0" * 40, "timestamp": when}


def github_routes(
    repo: str = "actions/checkout",
    *,
    default: str = "main",
    tags: dict[str, str] | None = None,
    branches: dict[str, str] | None = None,
    activity: list[dict[str, Any]] | None = None,
    history: dict[str, str] | None = None,
    releases: list[dict[str, Any]] | None = None,
) -> dict[str, tuple[Any, ...]]:
    """One publisher repository as GitHub's API shows it. ``history`` maps a SHA to the
    comparison status of ``<default>...<sha>``; a SHA it leaves out is unknown (404). GitHub's
    advisories name none of its versions (T6) unless a test replaces ``/advisories``."""
    base = f"/repos/{repo}"
    routes: dict[str, tuple[Any, ...]] = {
        base: (
            200,
            {
                "id": 1234,
                "default_branch": default,
                "stargazers_count": 7000,
                "forks_count": 2000,
                "created_at": "2019-07-23T14:06:46Z",
            },
        ),
        f"{base}/tags?per_page=100": (200, [{"name": n, "commit": {"sha": s}} for n, s in (tags or {}).items()]),
        f"{base}/activity?per_page=100": (200, activity or []),
        f"{base}/releases?per_page=100": (200, releases or []),
        ADVISORIES: (200, []),
    }
    for kind, refs in (("tags", tags), ("heads", branches)):
        for name, sha in (refs or {}).items():
            body = {"ref": f"refs/{kind}/{name}", "object": {"type": "commit", "sha": sha}}
            routes[f"{base}/git/ref/{kind}/{name}"] = (200, body)
    for sha, status in (history or {}).items():
        routes[f"{base}/compare/{default}...{sha}?per_page=1"] = (200, {"status": status})
    return routes


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A Git repository with one workflow, its symlinks resolved (``/private/var`` on macOS)."""
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(CI)
    return root


def run_pin(
    root: Path,
    spec: str,
    routes: dict[str, tuple[Any, ...]],
    *,
    yes: bool = True,
    home: Path | None = None,
    today: date = TODAY,
) -> tuple[Result, str]:
    action, _, ref = spec.rpartition("@")
    err = io.StringIO()
    handler = Pin(
        stdin=io.StringIO("y\n"),  # not a terminal: only --yes confirms
        stderr=err,
        cwd=str(root),
        home=str(home or root / "home"),
        today=today,
        client=FakeGitHub(routes).client(),
    )
    return handler(Request(Verb.PIN, action=action, ref=ref, yes=yes)), err.getvalue()


def rules(result: Result) -> list[Rule]:
    return [f.rule for f in result.findings]


def workflow(root: Path) -> str:
    return (root / ".github" / "workflows" / "ci.yml").read_text()


# --- the Test Plan --------------------------------------------------------------------


def test_tag_or_branch_reference_is_a_violation() -> None:
    def ref(raw: str, step: int) -> UsesReference:
        return UsesReference.read(raw, file=WORKFLOW, line=7 + step, job="build", step=step)

    references = [
        ref("actions/checkout@v4", 0),
        ref("actions/setup-python@main", 1),
        ref(f"actions/cache@{CACHE}", 2),
        ref("./local-action", 3),
        ref("docker://alpine:3", 4),
        UsesReference.read("octo/flows/.github/workflows/ci.yml@v1", file=WORKFLOW, line=30, job="call", step=None),
    ]
    listed = [LockEntry("actions/cache", CACHE, "v4.2.0", TODAY, TODAY, AgeSource.LOCK_FIRST_SEEN)]
    with refuses("resolver.reference-not-pinned"):  # moving-reference, chosen by a variable
        findings = resolver.reference_findings(references, listed)
    assert [(f.rule, f.item, f.version) for f in findings] == [
        (Rule.MOVING_REFERENCE, "actions/checkout", "v4"),
        (Rule.MOVING_REFERENCE, "actions/setup-python", "main"),
        (Rule.MOVING_REFERENCE, "octo/flows/.github/workflows/ci.yml", "v1"),
    ]
    assert findings[0].options[0].command == ("ssc-guardian", "pin", "actions/checkout@v4")
    assert all(f.level is Level.VIOLATION and f.place == WORKFLOW for f in findings)
    assert Result(Verb.CHECK, findings=findings).exit_code is ExitCode.VIOLATION


def test_sha_missing_from_lock_file_is_unverified_pin() -> None:
    pinned = UsesReference.read(f"Actions/Checkout@{NEW}", file=WORKFLOW, line=7, job="build", step=0)
    other = LockEntry("actions/checkout", OLD, "v4.1.1", TODAY, TODAY, AgeSource.LOCK_FIRST_SEEN)
    with refuses("resolver.reference-not-pinned"):  # unverified-pin, at the same call
        (finding,) = resolver.reference_findings([pinned], [other])
    assert (finding.rule, finding.item, finding.version) == (Rule.UNVERIFIED_PIN, "Actions/Checkout", NEW)
    assert finding.options[0].command == ("ssc-guardian", "pin", f"Actions/Checkout@{NEW}")
    # Listed under another spelling of the same Action (D18): verified.
    listed = LockEntry("actions/checkout", NEW, "v4.2.2", TODAY, TODAY, AgeSource.LOCK_FIRST_SEEN)
    assert resolver.reference_findings([pinned], [other, listed]) == ()
    assert resolver.reference_findings([pinned], []) == (finding,)  # an empty lock file verifies nothing


def test_impostor_commit_is_refused_by_pin(repo: Path) -> None:
    # A fork-network commit: GitHub serves it under the publisher's name, but no tag, branch
    # event or default-branch history of the publisher contains it.
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")], history={})
    routes["/repos/actions/checkout/compare/main..." + IMPOSTOR + "?per_page=1"] = (200, {"status": "diverged"})
    with refuses("pin.impostor-commit"):
        result, err = run_pin(repo, f"actions/checkout@{IMPOSTOR}", routes)
    assert result.exit_code is ExitCode.VIOLATION
    assert rules(result) == [Rule.IMPOSTOR_COMMIT]
    assert "impostor commit suspected" in err
    assert not (repo / LOCK_FILE).exists()
    assert workflow(repo) == CI


def test_own_repository_is_not_exempt_from_t4(repo: Path) -> None:
    routes = github_routes("thomascburns/ssc-guardian", tags={"v1.0.0": NEW}, history={NEW: "behind"})
    result, err = run_pin(repo, f"thomascburns/ssc-guardian@{IMPOSTOR}", routes)
    assert result.exit_code is ExitCode.VIOLATION
    assert rules(result) == [Rule.IMPOSTOR_COMMIT]
    assert not (repo / LOCK_FILE).exists()
    # The same repository's genuine commit is accepted by the same rule.
    result, _ = run_pin(repo, f"thomascburns/ssc-guardian@{NEW}", routes)
    assert Rule.IMPOSTOR_COMMIT not in rules(result)


def test_commit_inside_cooldown_is_eligible_not_failed(repo: Path) -> None:
    begins = TrustedAge(date(2026, 10, 20), AgeSource.ACTIVITY_LOG)
    kwargs = {"place": str(repo), "action": "actions/checkout", "sha": NEW, "version": "v4.2.2"}
    waiting = clock.cooldown_wait(begins, 14, date(2026, 11, 2), **kwargs)  # the day before
    assert waiting is not None
    assert (waiting.rule, waiting.level) == (Rule.COOLDOWN_WAIT, Level.NOTICE)
    assert waiting.options[0].eligible_on == date(2026, 11, 3)
    assert waiting.options[0].command is None
    assert Result(Verb.CHECK, findings=(waiting,)).exit_code is ExitCode.RULES_MET
    assert clock.cooldown_wait(begins, 14, date(2026, 11, 3), **kwargs) is None  # eligible on the day

    # pin records a waiting commit, so its clock runs, and leaves the workflow alone.
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2026-10-30T09:00:00Z")])
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.RULES_MET
    # The first pin of a publisher in the repository is also T3's notice (#126).
    assert rules(result) == [Rule.COOLDOWN_WAIT, Rule.FIRST_USE_PUBLISHER]
    assert "eligible on 2026-11-20" in err
    (entry,) = load_lock(str(repo / LOCK_FILE))
    assert (entry.trusted, entry.trusted_source, entry.first_seen) == (
        date(2026, 10, 30),
        AgeSource.ACTIVITY_LOG,
        TODAY,
    )
    assert workflow(repo) == CI


def test_persons_date_cannot_make_start_earlier(repo: Path) -> None:
    trusted = TrustedAge(date(2026, 10, 20), AgeSource.ACTIVITY_LOG)
    assert clock.start(trusted, date(2026, 10, 1)) == trusted
    assert clock.start(trusted, None) == trusted
    assert clock.start(trusted, date(2026, 10, 25)) == TrustedAge(date(2026, 10, 25), AgeSource.PERSON_DATE)

    # Through the settings file: a commit inside its cooldown stays inside it, however early
    # the person's date; taking the earlier date would make it eligible and write the pin.
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2026-10-30T09:00:00Z")])
    entry = f'[[start_date]]\naction = "actions/checkout"\nsha = "{NEW}"\ndate = 2020-01-01\n'
    (repo / ".ssc-guardian.toml").write_text("format = 1\n\n" + entry)
    early, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert rules(early) == [Rule.COOLDOWN_WAIT, Rule.FIRST_USE_PUBLISHER]
    assert "eligible on 2026-11-20" in err
    assert workflow(repo) == CI


def test_persons_later_date_makes_pin_wait(repo: Path) -> None:
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    entry = f'[[start_date]]\naction = "actions/checkout"\nsha = "{NEW}"\ndate = 2026-11-01\n'
    (repo / ".ssc-guardian.toml").write_text("format = 1\n\n" + entry)
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert rules(result) == [Rule.COOLDOWN_WAIT, Rule.FIRST_USE_PUBLISHER]
    assert "eligible on 2026-11-22" in err
    # The lock file keeps GitHub's date; the person's date is applied on top every run (L1).
    (recorded,) = load_lock(str(repo / LOCK_FILE))
    assert (recorded.trusted, recorded.trusted_source) == (date(2024, 10, 23), AgeSource.ACTIVITY_LOG)
    assert workflow(repo) == CI


def test_commit_never_on_a_branch_warns(repo: Path) -> None:
    # Only a tag names it: T4 accepts it, T2 warns and starts the clock today.
    routes = github_routes(tags={"v4.2.2": NEW}, history={NEW: "diverged"})
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.RULES_MET
    assert rules(result) == [Rule.UNPUSHED_COMMIT, Rule.COOLDOWN_WAIT, Rule.FIRST_USE_PUBLISHER]
    assert result.findings[0].level is Level.WARNING
    assert "never seen on a branch" in err
    (entry,) = load_lock(str(repo / LOCK_FILE))
    assert (entry.trusted, entry.trusted_source) == (TODAY, AgeSource.LOCK_FIRST_SEEN)


def test_resolver_error_on_missing_tag_exits_two(repo: Path) -> None:
    routes = github_routes(tags={"v4.2.2": NEW})
    result, err = run_pin(repo, "actions/checkout@v9", routes)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [s.reason.value for s in result.skipped] == ["check-error"]
    assert "actions/checkout has no tag or branch v9" in err
    assert not (repo / LOCK_FILE).exists()
    assert workflow(repo) == CI
    with (
        refuses("resolver.no-tag-branch"),
        pytest.raises(resolver.RefNotFoundError, match="actions/checkout has no tag or branch v9"),
    ):
        resolver.resolve(FakeGitHub(routes).client(), "actions/checkout", "v9")


# --- the resolver ---------------------------------------------------------------------


def test_annotated_tag_is_followed_and_always_fetched_again() -> None:
    tag_object = "c" * 40
    routes = github_routes()
    routes["/repos/actions/checkout/git/ref/tags/v4"] = (
        200,
        {"ref": "refs/tags/v4", "object": {"type": "tag", "sha": tag_object}},
    )
    routes[f"/repos/actions/checkout/git/tags/{tag_object}"] = (200, {"object": {"type": "commit", "sha": NEW}})
    fake = FakeGitHub(routes)
    client = fake.client()
    assert resolver.resolve(client, "actions/checkout", "v4") == resolver.Resolved("v4", NEW, True)
    routes[f"/repos/actions/checkout/git/tags/{tag_object}"] = (200, {"object": {"type": "commit", "sha": OLD}})
    assert resolver.resolve(client, "actions/checkout", "v4").sha == OLD  # the tag moved: never cached
    assert fake.seen.count("/repos/actions/checkout/git/ref/tags/v4") == 2


def test_branch_resolves_when_no_tag_has_the_name() -> None:
    routes = github_routes(branches={"main": NEW})
    assert resolver.resolve(FakeGitHub(routes).client(), "actions/checkout", "main") == resolver.Resolved(
        "main", NEW, False
    )


def test_a_ref_prefix_match_is_not_the_ref() -> None:
    # GitHub answers a prefix with a list of matching refs; that is not the tag asked for.
    routes = github_routes()
    routes["/repos/actions/checkout/git/ref/tags/v4"] = (
        200,
        [{"ref": "refs/tags/v4.2.2", "object": {"type": "commit", "sha": NEW}}],
    )
    with (
        refuses("resolver.no-tag-branch"),
        pytest.raises(resolver.RefNotFoundError, match="actions/checkout has no tag or branch v4"),
    ):
        resolver.resolve(FakeGitHub(routes).client(), "actions/checkout", "v4")


def test_a_path_action_is_looked_up_in_its_repository() -> None:
    routes = github_routes("github/codeql-action", tags={"v3.27.0": NEW})
    client = FakeGitHub(routes).client()
    assert resolver.resolve(client, "github/codeql-action/init", "v3.27.0").sha == NEW
    assert resolver.repository(client, "github/codeql-action/init").name == "github/codeql-action"


def test_malformed_answers_are_unfinished_checks_not_passes() -> None:
    routes = github_routes()
    routes["/repos/actions/checkout/git/ref/tags/v4"] = (200, {"ref": "refs/tags/v4", "object": {"sha": "nope"}})
    with refuses("resolver.value-not-text"), pytest.raises(FeedError, match="sent an object type that is not text"):
        resolver.resolve(FakeGitHub(routes).client(), "actions/checkout", "v4")
    routes["/repos/actions/checkout/git/ref/tags/v4"] = (
        200,
        {"ref": "refs/tags/v4", "object": {"type": "commit", "sha": "nope"}},
    )
    with (
        refuses("resolver.not-commit-sha"),
        pytest.raises(FeedError, match="sent a ref's SHA that is not a commit SHA"),
    ):
        resolver.resolve(FakeGitHub(routes).client(), "actions/checkout", "v4")
    routes["/repos/actions/checkout/tags?per_page=100"] = (200, {"not": "a list"})
    with refuses("resolver.sent-list-not-list"), pytest.raises(FeedError, match="sent a list that is not a list"):
        resolver.tags(FakeGitHub(routes).client(), "actions/checkout")
    routes["/repos/actions/checkout"] = (200, {"id": 1, "default_branch": "-x"})
    with (
        refuses("resolver.sent-default-branch-not-valid"),
        pytest.raises(FeedError, match="sent a default branch that is not a valid name"),
    ):
        resolver.repository(FakeGitHub(routes).client(), "actions/checkout")


def test_pages_follow_next_only_on_the_api() -> None:
    first = "/repos/actions/checkout/tags?per_page=100"
    second = "/repos/actions/checkout/tags?per_page=100&page=2"
    routes = github_routes()
    routes[first] = (
        200,
        [{"name": "v1", "commit": {"sha": OLD}}],
        {"link": f'<https://api.github.com{second}>; rel="next"'},
    )
    routes[second] = (200, [{"name": "v2", "commit": {"sha": NEW}}])
    assert resolver.tags(FakeGitHub(routes).client(), "actions/checkout") == {"v1": OLD, "v2": NEW}
    routes[first] = (200, [], {"link": '<https://evil.example/x>; rel="next"'})
    with (
        refuses("resolver.sent-next-page-outside-api"),
        pytest.raises(FeedError, match="sent a next page outside the API"),
    ):
        resolver.tags(FakeGitHub(routes).client(), "actions/checkout")


def test_verification_needs_one_publisher_fact() -> None:
    routes = github_routes(history={OLD: "behind", NEW: "identical", IMPOSTOR: "diverged"})
    client = FakeGitHub(routes).client()
    repository = resolver.repository(client, "actions/checkout")
    assert resolver.verify(client, repository, OLD, {}, None).verified  # default-branch history
    assert resolver.verify(client, repository, NEW, {}, None).pushed
    tagged = resolver.verify(client, repository, IMPOSTOR, {"v9": IMPOSTOR}, None)
    assert (tagged.verified, tagged.pushed, tagged.tags) == (True, False, ("v9",))
    assert resolver.verify(client, repository, IMPOSTOR, {"v9": OLD}, date(2026, 1, 1)).verified  # activity log
    assert not resolver.verify(client, repository, IMPOSTOR, {"v9": OLD}, None).verified
    assert not resolver.verify(client, repository, CACHE, {}, None).verified  # unknown to GitHub: 404


# --- the clock ------------------------------------------------------------------------


def test_activity_log_counts_branch_moves_only_and_takes_the_earliest() -> None:
    events = [
        push(NEW, "2026-10-02T10:00:00Z"),
        push(NEW, "2026-09-30T23:30:00-02:00", kind="pr_merge"),  # 2026-10-01 in UTC
        push(NEW, "2026-01-01T00:00:00Z", ref="refs/tags/v4"),  # not a branch
        push(NEW, "2026-01-02T00:00:00Z", kind="branch_deletion"),
        push(OLD, "2025-01-01T00:00:00Z"),
    ]
    routes = github_routes(activity=events)
    assert clock.on_branch(FakeGitHub(routes).client(), "actions/checkout", NEW) == date(2026, 10, 1)
    assert clock.on_branch(FakeGitHub(routes).client(), "actions/checkout", CACHE) is None
    routes["/repos/actions/checkout/activity?per_page=100"] = (200, [push(NEW, "2026-10-02 10:00:00")])
    with (
        refuses("clock.time-no-zone"),
        pytest.raises(FeedError, match="sent an activity time with no time zone"),
    ):  # a time with no zone is not guessed
        clock.on_branch(FakeGitHub(routes).client(), "actions/checkout", NEW)


def test_immutable_release_dates_the_commit_its_tag_names() -> None:
    releases = [
        {"tag_name": "v4.2.2", "immutable": True, "draft": False, "published_at": "2026-10-10T08:00:00Z"},
        {"tag_name": "v4.2.1", "immutable": True, "draft": False, "published_at": "2026-09-01T08:00:00Z"},
        {"tag_name": "v4.2.2", "immutable": False, "draft": False, "published_at": "2026-01-01T08:00:00Z"},
        {"tag_name": "v4.2.2", "immutable": True, "draft": True, "published_at": None},
    ]
    client = FakeGitHub(github_routes(releases=releases)).client()
    tags = {"v4.2.2": NEW, "v4.2.1": OLD}
    assert clock.immutable_release(client, "actions/checkout", NEW, tags) == date(2026, 10, 10)
    assert clock.immutable_release(client, "actions/checkout", CACHE, tags) is None


def test_recorded_age_is_the_earliest_github_date_else_first_seen() -> None:
    assert clock.recorded_age(date(2026, 10, 2), date(2026, 10, 1), TODAY) == TrustedAge(
        date(2026, 10, 1), AgeSource.IMMUTABLE_RELEASE
    )
    assert clock.recorded_age(date(2026, 10, 2), None, TODAY) == TrustedAge(date(2026, 10, 2), AgeSource.ACTIVITY_LOG)
    assert clock.recorded_age(None, None, TODAY) == TrustedAge(TODAY, AgeSource.LOCK_FIRST_SEEN)


# --- pin's own rules --------------------------------------------------------------------


def test_rewrite_changes_only_the_uses_values(repo: Path) -> None:
    (source,) = read_sources(str(repo))
    changed = rewrite(source, "actions/checkout", NEW, "v4.2.2")
    assert changed is not None
    assert changed.text == CI.replace(
        "      - uses: actions/checkout@v4\n", f"      - uses: actions/checkout@{NEW} # v4.2.2\n"
    ).replace("      - uses: Actions/Checkout@v3 # older\n", f"      - uses: Actions/Checkout@{NEW} # v4.2.2\n")
    assert "echo uses: actions/checkout@v4" in changed.text  # a run block is never a reference
    assert rewrite(source, "actions/cache", NEW, "v4") is None
    # A bare SHA keeps no comment; the line ending of each line is kept.
    crlf = source.__class__(source.path, CI.replace("\n", "\r\n"), source.reader, source.references)
    bare = rewrite(crlf, "actions/setup-python", CACHE, CACHE)
    assert bare is not None
    assert f"        uses: actions/setup-python@{CACHE}\r\n" in bare.text
    assert bare.text.count("\r\n") == CI.count("\n")


def test_prune_keeps_used_pinned_and_one_previous_commit() -> None:
    def entry(action: str, sha: str, day: int) -> LockEntry:
        seen = TODAY - timedelta(days=day)
        return LockEntry(action, sha, sha, seen, seen, AgeSource.LOCK_FIRST_SEEN)

    used, older, oldest, other = (
        entry("actions/checkout", NEW, 1),
        entry("actions/checkout", OLD, 5),
        entry("actions/checkout", IMPOSTOR, 9),
        entry("actions/cache", CACHE, 3),
    )
    kept = prune([used, older, oldest, other], {used.key}, used.key)
    assert set(kept) == {used, older, other}  # each Action keeps its most recent previous commit
    waiting = entry("actions/checkout", "d" * 40, 0)
    kept = prune([used, older, waiting], {used.key}, waiting.key, {used.key}, lambda e: e is waiting)
    assert set(kept) == {used, older, waiting}  # a waiting commit just pinned never counts as the previous one


def test_rollback_target_is_the_commit_the_workflows_used(repo: Path) -> None:
    # The 2025 sequence: a moved tag's commit is recorded while it waits (never used); a later
    # pin of a genuine release must keep the commit the workflows ran as the rollback target,
    # however recent the waiting commit's first-seen date.
    genuine, moved, release = OLD, IMPOSTOR, NEW
    entries = [
        LockEntry("actions/checkout", genuine, "v1", date(2025, 1, 15), date(2024, 3, 12), AgeSource.ACTIVITY_LOG),
        LockEntry("actions/checkout", moved, "v1", date(2025, 3, 11), date(2025, 3, 11), AgeSource.LOCK_FIRST_SEEN),
    ]
    (repo / LOCK_FILE).write_text(dump_lock(entries))
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        CI.replace("actions/checkout@v4", f"actions/checkout@{genuine} # v1")
    )
    routes = github_routes(tags={"v1.3.1": release}, activity=[push(release, "2025-03-20T10:00:00Z")])
    result, err = run_pin(repo, "actions/checkout@v1.3.1", routes, today=date(2025, 5, 1))
    assert result.exit_code is ExitCode.RULES_MET
    assert {e.sha for e in load_lock(str(repo / LOCK_FILE))} == {release, genuine}
    assert f"remove actions/checkout@{moved}" in err


def test_repinning_a_listed_commit_keeps_its_recorded_tag(repo: Path) -> None:
    listed = LockEntry("actions/checkout", NEW, "v4.2.2", TODAY, date(2024, 10, 23), AgeSource.ACTIVITY_LOG)
    (repo / LOCK_FILE).write_text(dump_lock([listed]))
    routes = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, _ = run_pin(repo, "actions/checkout@v4", routes)
    assert result.exit_code is ExitCode.RULES_MET
    assert f"actions/checkout@{NEW} # v4.2.2" in workflow(repo)
    assert load_lock(str(repo / LOCK_FILE)) == (listed,)


def test_prune_keeps_one_rollback_and_one_waiting_commit_and_is_stable() -> None:
    def entry(sha: str, seen: date) -> LockEntry:
        return LockEntry("actions/checkout", sha, sha, seen, seen, AgeSource.LOCK_FIRST_SEEN)

    rollback, in_use, waiting = (
        entry(OLD, date(2026, 1, 5)),
        entry(NEW, date(2026, 2, 5)),
        entry(CACHE, date(2026, 3, 5)),
    )
    hotfix = entry("d" * 40, date(2026, 3, 9))
    still = {waiting.key}

    def waits(e: LockEntry) -> bool:
        return e.key in still

    other = LockEntry("actions/cache", "e" * 40, "v4", TODAY, TODAY, AgeSource.LOCK_FIRST_SEEN)
    every = [rollback, in_use, waiting, other]
    # An unrelated pin keeps each Action's rollback target and its waiting commit.
    kept = prune(every, {in_use.key}, other.key, {in_use.key}, waits)
    assert set(kept) == set(every)
    assert prune(kept, {in_use.key}, other.key, {in_use.key}, waits) == kept  # a re-run changes nothing

    # Rolling back to the older commit keeps the one the workflows ran, and stays stable.
    kept = prune(every, {rollback.key}, rollback.key, {in_use.key}, waits)
    assert set(kept) == set(every)
    assert prune(kept, {rollback.key}, rollback.key, {rollback.key}, waits) == kept

    # A hotfix pinned after a commit started waiting keeps the waiting commit and its clock.
    kept = prune([rollback, in_use, waiting, hotfix], {hotfix.key}, hotfix.key, {in_use.key}, waits)
    assert set(kept) == {in_use, waiting, hotfix}

    # Once its cooldown has passed, a commit that waited and was never used gives way to the
    # rollback target.
    still.clear()
    kept = prune([rollback, in_use, waiting, hotfix], {hotfix.key}, hotfix.key, {in_use.key}, waits)
    assert set(kept) == {in_use, hotfix}


def test_the_commit_just_pinned_takes_a_slot_of_its_own() -> None:
    def entry(sha: str, seen: date) -> LockEntry:
        return LockEntry("actions/checkout", sha, sha, seen, seen, AgeSource.LOCK_FIRST_SEEN)

    in_use, rollback = entry(NEW, date(2026, 1, 5)), entry(OLD, date(2026, 2, 5))
    first, second = entry(CACHE, date(2026, 3, 5)), entry(IMPOSTOR, date(2026, 3, 9))
    waits = {first.key, second.key}

    def waiting(e: LockEntry) -> bool:
        return e.key in waits

    other = LockEntry("actions/cache", "e" * 40, "v4", TODAY, TODAY, AgeSource.LOCK_FIRST_SEEN)
    # A second commit pinned while the first still waits replaces it: two unused entries at most.
    kept = prune([in_use, rollback, first, second], {in_use.key}, second.key, {in_use.key}, waiting)
    assert set(kept) == {in_use, rollback, second}
    again = prune([*kept, other], {in_use.key}, other.key, {in_use.key}, waiting)
    assert set(again) == {*kept, other}  # an unrelated pin afterwards keeps the same entries

    # An eligible pin of an Action no workflow uses is its rollback target; one waiting commit stays.
    kept = prune([rollback, first, in_use], set(), in_use.key, set(), waiting)
    assert set(kept) == {in_use, first}
    assert prune([*kept, other], set(), other.key, set(), waiting) == canonical([*kept, other])


def test_symlinked_workflow_or_lock_file_is_refused(repo: Path) -> None:
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    outside = repo.parent / f"{repo.name}-outside.yml"
    outside.write_text(CI)
    try:
        (repo / ".github" / "workflows" / "linked.yml").symlink_to(outside)
        with refuses("pin.symlink-lies-outside-repository-pin"):
            result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
        assert result.exit_code is ExitCode.INCOMPLETE
        linked = repo / ".github" / "workflows" / "linked.yml"
        message = f"{linked} is a symlink or lies outside the repository; pin writes only the repository's files"
        assert f"ssc-guardian: {message}; nothing written.\n" in err and outside.read_text() == CI
        (repo / ".github" / "workflows" / "linked.yml").unlink()
        (repo / LOCK_FILE).symlink_to(outside)
        with refuses("pin.symlink-pin-writes-only-repositorys"):
            result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
        assert result.exit_code is ExitCode.INCOMPLETE
        message = f"{repo / LOCK_FILE} is a symlink; pin writes only the repository's own lock file"
        assert f"ssc-guardian: {message}; nothing written.\n" in err
        assert (repo / LOCK_FILE).is_symlink() and outside.read_text() == CI
        assert workflow(repo) == CI
    finally:
        outside.unlink()


def test_local_action_outside_its_folder_is_refused(repo: Path) -> None:
    (repo / ".github" / "workflows" / "ci.yml").write_text(CI + "      - uses: ./../elsewhere\n")
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    with refuses("pin.leaves-folder-pin-reads-only"):
        result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.INCOMPLETE
    line = CI.count("\n") + 1
    ci = repo / ".github" / "workflows" / "ci.yml"
    message = f"{ci}:{line}: ./../elsewhere leaves its folder; pin reads only this repository"
    assert f"ssc-guardian: {message}; nothing written.\n" in err
    assert workflow(repo) == CI + "      - uses: ./../elsewhere\n"
    assert not (repo / LOCK_FILE).exists()


class _Person(io.StringIO):
    """A terminal whose person, while reading the change, edits a workflow and then says yes."""

    def __init__(self, edit: Path) -> None:
        super().__init__("y\n")
        self.edit = edit

    def isatty(self) -> bool:
        # Asked once the change is shown, after pin read every file: the person edits now.
        self.edit.write_text(self.edit.read_text() + "# edited\n")
        return True


def test_a_file_changed_while_confirming_writes_nothing(repo: Path) -> None:
    other = repo / ".github" / "workflows" / "other.yml"
    other.write_text(CI.replace("actions/checkout@v4", "actions/cache@v4"))
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    err = io.StringIO()
    handler = Pin(
        stdin=_Person(other),
        stderr=err,
        cwd=str(repo),
        home=str(repo / "home"),
        today=TODAY,
        client=FakeGitHub(routes).client(),
    )
    result = handler(Request(Verb.PIN, action="actions/checkout", ref="v4.2.2", yes=False))
    assert result.exit_code is ExitCode.INCOMPLETE
    assert "a file changed while you read the change" in err.getvalue()
    assert not (repo / LOCK_FILE).exists()
    assert workflow(repo) == CI


def test_a_failed_write_names_what_was_written(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ssc_guardian.commands import pin

    real = pin.atomic_write

    def failing(path: str, text: str) -> None:
        if path.endswith("ci.yml"):
            raise OSError("disk full")
        real(path, text)

    monkeypatch.setattr(pin, "atomic_write", failing)
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert f"disk full; written so far: {repo / LOCK_FILE}." in err
    assert workflow(repo) == CI


def test_no_terminal_and_no_yes_writes_nothing(repo: Path) -> None:
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes, yes=False)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert "not confirmed; nothing written. Add --yes" in err
    assert not (repo / LOCK_FILE).exists()
    assert workflow(repo) == CI


def test_no_terminal_and_no_yes_shows_the_plan_before_refusing(repo: Path) -> None:
    # #284: without a terminal the plan is still shown, once, so a script sees what --yes would do.
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    refused, err = run_pin(repo, "actions/checkout@v4.2.2", routes, yes=False)
    assert refused.exit_code is ExitCode.INCOMPLETE
    assert not (repo / LOCK_FILE).exists() and workflow(repo) == CI
    # The --yes record of the same run is the plan the refusal showed.
    _, record = run_pin(repo, "actions/checkout@v4.2.2", routes, yes=True)
    plan, _, _ = record.partition("Confirmed in advance (--yes).\n")
    assert "Guardian will pin actions/checkout to" in plan
    assert err == plan + "ssc-guardian: not confirmed; nothing written. Add --yes to confirm in advance.\n"
    assert err.count("Guardian will pin") == 1 and "Proceed?" not in err


def test_malformed_lock_file_is_never_written_over(repo: Path) -> None:
    (repo / LOCK_FILE).write_text("format = 1\n[[pin]]\naction = 1\n")
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert (repo / LOCK_FILE).read_text() == "format = 1\n[[pin]]\naction = 1\n"
    assert workflow(repo) == CI
    assert "nothing written" in err


def test_unreadable_workflow_stops_pin(repo: Path) -> None:
    (repo / ".github" / "workflows" / "bad.yml").write_text("a: &anchor 1\n")
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, _ = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert [s.reason.value for s in result.skipped] == ["unsupported-yaml"]
    assert not (repo / LOCK_FILE).exists()


def test_local_actions_are_read_and_pinned_too(repo: Path) -> None:
    local = repo / ".github" / "actions" / "setup"
    local.mkdir(parents=True)
    (local / "action.yml").write_text(
        "name: setup\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
    )
    (repo / ".github" / "workflows" / "ci.yml").write_text(CI + "      - uses: ./.github/actions/setup\n")
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, _ = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.RULES_MET
    assert f"uses: actions/checkout@{NEW} # v4.2.2" in (local / "action.yml").read_text()


def test_pin_never_asks_github_with_a_post(repo: Path) -> None:
    # FakeGitHub asserts every request is an HTTPS GET to api.github.com.
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, _ = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.RULES_MET
    assert [c.ecosystem for c in result.checked] == [Ecosystem.GITHUB_ACTIONS]


# --- only the lock file changes: already pinned, or used by no workflow (#211) ----------

# The workflow after a person pinned actions/checkout by hand, in both its spellings.
PINNED_CI = CI.replace("actions/checkout@v4", f"actions/checkout@{NEW} # v4.2.2").replace(
    "Actions/Checkout@v3 # older", f"Actions/Checkout@{NEW} # v4.2.2"
)


def pinned_by_hand(root: Path) -> dict[str, tuple[Any, ...]]:
    """Write the hand-pinned workflow; GitHub shows v4.2.2 naming NEW, pushed long ago."""
    (root / ".github" / "workflows" / "ci.yml").write_text(PINNED_CI)
    return github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])


def test_pin_of_already_pinned_commit_says_workflows_already_pin_it(repo: Path) -> None:
    result, err = run_pin(repo, "actions/checkout@v4.2.2", pinned_by_hand(repo))
    assert result.exit_code is ExitCode.RULES_MET
    said = f"  Every workflow in {repo} that uses actions/checkout already pins {NEW}; only the lock file changes.\n"
    assert said in err
    assert "No workflow" not in err
    (entry,) = load_lock(str(repo / LOCK_FILE))
    assert (entry.action, entry.sha, entry.tag) == ("actions/checkout", NEW, "v4.2.2")
    assert workflow(repo) == PINNED_CI  # the workflows already pin it: none is rewritten


def test_pin_with_no_workflow_using_the_action_keeps_no_workflow_line(repo: Path) -> None:
    routes = github_routes("actions/cache", tags={"v4.2.0": CACHE}, activity=[push(CACHE, "2024-10-23T14:46:00Z")])
    result, err = run_pin(repo, "actions/cache@v4.2.0", routes)
    assert result.exit_code is ExitCode.RULES_MET
    assert f"  No workflow in {repo} uses actions/cache; only the lock file changes.\n" in err
    assert "already pins" not in err
    (entry,) = load_lock(str(repo / LOCK_FILE))
    assert (entry.action, entry.sha) == ("actions/cache", CACHE)
    assert workflow(repo) == CI


def test_already_pinned_confirmation_value_cannot_add_a_line(tmp_path: Path) -> None:
    # The line's values are the repository, the Action and the commit. The Action and the commit
    # are checked against their grammars; the repository's folder name here carries a line break
    # and an escape sequence. The line strips each value as it goes in (contracts §5, #147), and
    # behind that the path grammar refuses such a folder before any confirmation is built: no
    # line is shown, so none can be split, and nothing is written.
    root = tmp_path.resolve() / "re\npo\x1b[2K"
    (root / ".git").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    routes = pinned_by_hand(root)
    with refuses("findings.malformed-place"):  # the folder fails the path grammar
        result, err = run_pin(root, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.VIOLATION
    assert [(f.rule, f.malformed_field) for f in result.findings] == [(Rule.MALFORMED_NAME, FindingField.PLACE)]
    assert "Every workflow" not in err and "\x1b" not in err
    assert not any(line.startswith("po") for line in err.splitlines())  # no value split a line
    assert not (root / LOCK_FILE).exists()
    assert (root / ".github" / "workflows" / "ci.yml").read_text() == PINNED_CI


def test_declined_already_pinned_confirmation_writes_nothing(repo: Path) -> None:
    routes = pinned_by_hand(repo)
    with refuses("pin.not-confirmed"):  # no terminal and no --yes
        result, err = run_pin(repo, "actions/checkout@v4.2.2", routes, yes=False)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert "not confirmed; nothing written. Add --yes" in err
    assert not (repo / LOCK_FILE).exists()
    assert workflow(repo) == PINNED_CI


def test_pin_rerun_after_write_says_nothing_to_write(repo: Path) -> None:
    routes = pinned_by_hand(repo)
    first, _ = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert first.exit_code is ExitCode.RULES_MET
    lock = (repo / LOCK_FILE).read_text()
    again, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert again.exit_code is ExitCode.RULES_MET
    recorded = f"actions/checkout@{NEW} is recorded in {repo / LOCK_FILE}"
    assert f"Nothing to write: {recorded} and every workflow pin is current.\n" in err
    assert "Guardian will pin" not in err
    assert (repo / LOCK_FILE).read_text() == lock
    assert workflow(repo) == PINNED_CI


# --- T3, T6 and the deny list: one evaluation for pin and check --repo (#126) -------------

CHANGED_FILES = "tj-actions/changed-files"
V45 = "45" * 20  # the commit v45.0.7 names, synthetic
V46 = "46" * 20  # the commit v46.0.1 names, synthetic
GHSA = "GHSA-mrrh-fwg8-r2c3"  # no CVE alias, so no KEV lookup is needed


def changed_files_github(*advisories: Advisory, created: str = "2019-07-23T14:06:46Z", stars: int = 5000) -> GitHub:
    """tj-actions/changed-files on GitHub: v45.0.7 and v46.0.1, both pushed long ago, and
    the advisories given (matched on GitHub's side by version, as the API does)."""
    github = GitHub(advisories=list(advisories))
    github.publisher(
        CHANGED_FILES,
        77,
        created=created,
        stars=stars,
        tags={"v45.0.7": V45, "v46.0.1": V46},
        files={(V45, "action.yml"): NODE_ACTION},
    )
    pushes = [push(V45, "2025-03-01T00:00:00Z"), push(V46, "2025-03-20T00:00:00Z")]
    github.routes[f"/repos/{CHANGED_FILES}/activity?per_page=100"] = (200, pushes)
    return github


def pin_with(root: Path, spec: str, github: GitHub) -> tuple[Result, str]:
    action, _, ref = spec.rpartition("@")
    err = io.StringIO()
    handler = Pin(
        stdin=io.StringIO(),
        stderr=err,
        cwd=str(root),
        home=str(root.parent / "home"),
        today=TODAY,
        client=github.client(),
    )
    return handler(Request(Verb.PIN, action=action, ref=ref, yes=True)), err.getvalue()


def violations(result: Result) -> set[tuple[Rule, str | None, str | None, tuple[str, ...]]]:
    """A result's violations, without their places: ``pin`` reports at the repository,
    ``check --repo`` at the workflow that uses the pin."""
    return {(f.rule, f.item, f.version, f.evidence) for f in result.findings if f.level is Level.VIOLATION}


def test_shared_evaluation_matches_check_repo_on_the_same_pin(tmp_path: Path) -> None:
    young = f"{(TODAY - timedelta(days=30)).isoformat()}T12:00:00Z"
    github = changed_files_github(Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", "46.0.1"), created=young, stars=10)
    settings = f'format = 1\ndeny = ["github-actions:{CHANGED_FILES}"]\n'

    # pin refuses v45.0.7 and writes nothing.
    pinning = make_repo(tmp_path / "pin", f"{CHANGED_FILES}@v45")
    (pinning / ".ssc-guardian.toml").write_text(settings)
    before = (pinning / ".github" / "workflows" / "ci.yml").read_bytes()
    refused, err = pin_with(pinning, f"{CHANGED_FILES}@v45.0.7", github)
    assert refused.exit_code is ExitCode.VIOLATION
    assert not (pinning / LOCK_FILE).exists()
    assert (pinning / ".github" / "workflows" / "ci.yml").read_bytes() == before
    assert "Guardian will pin" not in err  # the change is never shown

    # check --repo on the repository as pin would have left it gives the same violations.
    pinned = make_repo(tmp_path / "check", f"{CHANGED_FILES}@{V45}", lock=[listed(CHANGED_FILES, V45, "v45.0.7")])
    (pinned / ".ssc-guardian.toml").write_text(settings)
    checked, _ = check_repo(pinned, github)
    assert checked.exit_code is ExitCode.VIOLATION
    assert (
        violations(refused)
        == violations(checked)
        == {
            (Rule.DENY_LIST, CHANGED_FILES, V45, ()),
            (Rule.YOUNG_REPOSITORY, CHANGED_FILES, None, ()),
            (Rule.KNOWN_VULNERABILITY, CHANGED_FILES, V45, (GHSA,)),
        }
    )


@pytest.mark.parametrize(
    ("created", "expiry", "released"),
    [("2026-10-20", "2026-12-31", True), ("2026-08-20", "2026-11-02", False)],
    ids=["valid", "expired"],
)
def test_override_releases_an_advisory_in_pin_as_in_check_repo(
    tmp_path: Path, created: str, expiry: str, released: bool
) -> None:
    # No fixed version is named, so the "a fix passes" fact cannot end the override (§10.4).
    github = changed_files_github(Advisory(GHSA, CHANGED_FILES, "<= 45.0.7"))
    override = (
        f'format = 1\n[[override]]\necosystem = "github-actions"\nitem = "{CHANGED_FILES}"\nversion = "{V45}"\n'
        f'rule = "known-vulnerability"\nreference = "{GHSA}"\ncategory = "accepted-risk"\n'
        f'created = {created}\nexpiry = {expiry}\nreason = "reviewed; no fix yet"\n'
    )
    pinning = make_repo(tmp_path / "pin", f"{CHANGED_FILES}@v45")
    (pinning / ".ssc-guardian-overrides.toml").write_text(override)
    pinned = make_repo(tmp_path / "check", f"{CHANGED_FILES}@{V45}", lock=[listed(CHANGED_FILES, V45, "v45.0.7")])
    (pinned / ".ssc-guardian-overrides.toml").write_text(override)

    by_pin, _ = pin_with(pinning, f"{CHANGED_FILES}@v45.0.7", github)
    by_check, _ = check_repo(pinned, github)
    for result in (by_pin, by_check):
        assert (Rule.KNOWN_VULNERABILITY in rules(result)) is not released
        assert [r.reference for r in result.overrides_applied] == ([GHSA] if released else [])
        assert [r.reference for r in result.overrides_expired] == ([] if released else [GHSA])
    assert by_pin.exit_code is (ExitCode.RULES_MET if released else ExitCode.VIOLATION)
    assert (pinning / LOCK_FILE).exists() is released
    if released:
        (entry,) = load_lock(str(pinning / LOCK_FILE))
        assert (entry.action, entry.sha, entry.tag) == (CHANGED_FILES, V45, "v45.0.7")
        assert f"uses: {CHANGED_FILES}@{V45} # v45.0.7" in (pinning / ".github" / "workflows" / "ci.yml").read_text()


# --- nothing to write is not nothing to check (#227, RR1) ---------------------------------
# pin's only run of the deny list, T3 and T6 used to come after its "Nothing to write" return,
# so an Action already pinned and recorded passed (exit 0) whatever those rules said.


def recorded(tmp_path: Path, settings: str | None = None) -> Path:
    """A repository whose workflow already pins v45.0.7 and whose lock file records it, its
    cooldown long passed: ``pin`` of v45.0.7 has nothing to write."""
    root = make_repo(
        tmp_path,
        f"{CHANGED_FILES}@{V45} # v45.0.7",
        lock=[listed(CHANGED_FILES, V45, "v45.0.7", day=TODAY - timedelta(days=400))],
    )
    if settings is not None:
        (root / ".ssc-guardian.toml").write_text(settings)
    return root


def files_of(root: Path) -> dict[str, bytes]:
    """Every file in the repository and its bytes: what a refused pin must leave as it was."""
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def assert_refused_unwritten(result: Result, err: str, root: Path, before: dict[str, bytes]) -> None:
    assert result.exit_code is ExitCode.VIOLATION
    assert f"ssc-guardian: {CHANGED_FILES}@{V45} breaks a rule check --repo applies; nothing written." in err
    assert "Nothing to write" not in err  # the refusal is the answer, not "every pin is current"
    assert "Guardian will pin" not in err
    assert files_of(root) == before


def test_pin_nothing_to_write_is_idempotent_on_re_run(tmp_path: Path) -> None:
    root = recorded(tmp_path)
    before = files_of(root)
    for _ in range(2):
        result, err = pin_with(root, f"{CHANGED_FILES}@v45.0.7", changed_files_github())
        assert result.exit_code is ExitCode.RULES_MET
        assert f"Nothing to write: {CHANGED_FILES}@{V45} is recorded in {root / LOCK_FILE}" in err
        assert not [f for f in result.findings if f.level is Level.VIOLATION]
        assert files_of(root) == before


def test_pin_nothing_to_write_still_refuses_a_denied_action(tmp_path: Path) -> None:
    root = recorded(tmp_path, f'format = 1\ndeny = ["github-actions:{CHANGED_FILES}"]\n')
    before = files_of(root)
    with refuses("publisher.denied-action"):
        result, err = pin_with(root, f"{CHANGED_FILES}@v45.0.7", changed_files_github())
    assert violations(result) == {(Rule.DENY_LIST, CHANGED_FILES, V45, ())}
    assert_refused_unwritten(result, err, root, before)


def test_pin_nothing_to_write_still_reports_an_advisory(tmp_path: Path) -> None:
    root = recorded(tmp_path)
    before = files_of(root)
    github = changed_files_github(Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", "46.0.1"))
    with refuses("advisories.advisory-hit"):
        result, err = pin_with(root, f"{CHANGED_FILES}@v45.0.7", github)
    assert violations(result) == {(Rule.KNOWN_VULNERABILITY, CHANGED_FILES, V45, (GHSA,))}
    assert_refused_unwritten(result, err, root, before)


def test_pin_nothing_to_write_still_blocks_a_young_repository(tmp_path: Path) -> None:
    root = recorded(tmp_path)
    before = files_of(root)
    young = f"{(TODAY - timedelta(days=10)).isoformat()}T12:00:00Z"
    with refuses("publisher.young-repository"):
        result, err = pin_with(root, f"{CHANGED_FILES}@v45.0.7", changed_files_github(created=young))
    assert violations(result) == {(Rule.YOUNG_REPOSITORY, CHANGED_FILES, None, ())}
    assert_refused_unwritten(result, err, root, before)


def test_pin_nothing_to_write_with_an_unfinished_check_exits_two(tmp_path: Path) -> None:
    # A check that cannot finish is exit 2, never 0 (contracts §3); nothing is written.
    root = recorded(tmp_path)
    before = files_of(root)
    github = changed_files_github()
    github.advisory_answer = (500, {"message": "Server Error"})
    with refuses("net.feed-answered-http-error"):  # T6's advisories request, not another cause
        result, err = pin_with(root, f"{CHANGED_FILES}@v45.0.7", github)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [s.reason for s in result.skipped] == [SkipReason.FEED_FAILURE]
    assert "Nothing to write" not in err
    assert "answered HTTP 500; nothing written." in err
    assert files_of(root) == before


def test_pin_nothing_to_write_violation_wins_over_an_unfinished_check(tmp_path: Path) -> None:
    # 1 wins over 2 (contracts §3): a denied Action exits 1 although T6 could not finish.
    root = recorded(tmp_path, f'format = 1\ndeny = ["github-actions:{CHANGED_FILES}"]\n')
    before = files_of(root)
    github = changed_files_github()
    github.advisory_answer = (500, {"message": "Server Error"})
    with refuses("publisher.denied-action"), refuses("net.feed-answered-http-error"):
        result, err = pin_with(root, f"{CHANGED_FILES}@v45.0.7", github)
    assert result.exit_code is ExitCode.VIOLATION
    assert (Rule.DENY_LIST, CHANGED_FILES, V45, ()) in violations(result)
    assert [s.reason for s in result.skipped] == [SkipReason.FEED_FAILURE]  # still listed (contracts §3)
    assert "Nothing to write" not in err
    assert files_of(root) == before


# --- Docker images, and the accounting check (#127) -----------------------------------

DIGEST = "0123456789abcdef" * 4  # 64 lowercase hex
ACTION_FILE = "/repo/tools/run/action.yml"


def docker(raw: str, step: int = 0) -> UsesReference:
    return UsesReference.read(raw, file=WORKFLOW, line=9 + step, job="build", step=step)


def docker_action(image: str, using: str = "docker") -> str:
    return f"name: d\nruns:\n  using: {using}\n  image: {image}\n"


def test_docker_reference_without_digest_is_unpinned_image() -> None:
    references = [
        docker("docker://alpine:latest", 0),
        docker("docker://alpine:3.20", 1),
        docker("docker://ghcr.io/owner/image", 2),  # no tag at all: Docker reads "latest"
        docker("docker://alpine:latest", 3),  # used twice in one file: one finding
        UsesReference.read("actions/checkout@v4", file=WORKFLOW, line=20, job="build", step=4),
        UsesReference.read("./local-action", file=WORKFLOW, line=21, job="build", step=5),
    ]
    assert [ref.kind.value for ref in references[:3]] == ["docker"] * 3
    found = resolver.image_findings(references)
    assert [(f.rule, f.level, f.place, f.item, f.version, f.via) for f in found] == [
        (Rule.UNPINNED_IMAGE, Level.WARNING, WORKFLOW, image, None, ())
        for image in ("alpine:latest", "alpine:3.20", "ghcr.io/owner/image")
    ]
    assert Result(Verb.CHECK, findings=found).exit_code is ExitCode.RULES_MET  # a warning


def test_docker_reference_with_digest_gives_no_finding() -> None:
    for image in (f"alpine@sha256:{DIGEST}", f"ghcr.io/owner/image:3.20@sha256:{DIGEST}"):
        assert resolver.image_pinned(image)
        assert resolver.image_findings([docker(f"docker://{image}")]) == ()


def test_malformed_docker_digest_is_not_pinned() -> None:
    # 63 hex, or a digest written as a tag: never pinned, and never echoed (malformed-name, exit 1).
    for image in (f"alpine@sha256:{DIGEST[:63]}", f"alpine:sha256:{DIGEST}", f"alpine:sha256-{DIGEST}x@sha256:"):
        assert not resolver.image_pinned(image)
        (finding,) = resolver.image_findings([docker(f"docker://{image}")])
        assert (finding.rule, finding.malformed_field, finding.item, finding.place) == (
            Rule.MALFORMED_NAME,
            FindingField.ITEM,
            None,
            WORKFLOW,
        )
        assert Result(Verb.CHECK, findings=(finding,)).exit_code is ExitCode.VIOLATION
    # A tag that merely looks like a digest is a tag: unpinned.
    (tagged,) = resolver.image_findings([docker(f"docker://alpine:sha256-{DIGEST}")])
    assert (tagged.rule, tagged.item) == (Rule.UNPINNED_IMAGE, f"alpine:sha256-{DIGEST}")


def test_docker_action_image_is_read_from_metadata() -> None:
    metadata = action_from(yaml_subset.parse(docker_action("docker://ghcr.io/x/y:latest"), ACTION_FILE), ACTION_FILE)
    (image,) = metadata.references
    assert (image.kind, image.raw, image.image, image.file, image.line, image.job, image.step) == (
        UsesKind.DOCKER,
        "docker://ghcr.io/x/y:latest",
        "ghcr.io/x/y:latest",
        ACTION_FILE,
        4,
        None,
        None,
    )
    assert metadata.image == image
    (finding,) = resolver.image_findings(metadata.references)
    assert (finding.rule, finding.place, finding.item) == (Rule.UNPINNED_IMAGE, ACTION_FILE, "ghcr.io/x/y:latest")
    # Read whatever ``using`` says, as steps are: a spelling the runner accepts cannot hide it.
    assert action_from(yaml_subset.parse(docker_action("docker://a:1", "Docker"), "/a.yml"), "/a.yml").references
    # A Dockerfile in the Action's own repository is built from the commit read: no reference.
    for dockerfile in ("Dockerfile", "./docker/Dockerfile"):
        built = action_from(yaml_subset.parse(docker_action(dockerfile), ACTION_FILE), ACTION_FILE)
        assert (built.image, built.references, resolver.image_findings(built.references)) == (None, (), ())
    # A value that names no image (empty, or not one value) is read as before, so pin is unchanged.
    for odd in (" ''", "\n    a: 1", "\n    - x"):
        text = f"name: d\nruns:\n  using: node20\n  main: x.js\n  image:{odd}\n"
        assert action_from(yaml_subset.parse(text, ACTION_FILE), ACTION_FILE).references == ()
    # A Docker reference with no step belongs to an Action's metadata, never to a job.
    with pytest.raises(ValueError, match="names its step"):
        UsesReference("docker://a:1", UsesKind.DOCKER, WORKFLOW, 3, "build", None)


def test_accounting_names_each_reference_no_check_handled() -> None:
    root = "/repo"
    pinned = UsesReference.read(f"actions/cache@{CACHE}", file=WORKFLOW, line=7, job="build", step=0)
    image = docker("docker://alpine:latest", 1)
    digest = docker(f"docker://alpine@sha256:{DIGEST}", 2)
    local = UsesReference.read("./tools/setup", file=WORKFLOW, line=12, job="build", step=3)
    outer = [advisories.Pin(WORKFLOW, "actions/cache", CACHE, ())]
    found = list(resolver.image_findings([image]))
    unread = [local]
    walk = nested.Walk()
    via = (f"actions/cache@{CACHE}",)
    inner_local = UsesReference.read("./inner", file="o/r/action.yml@x", line=5, job=None, step=0)
    walk.read.append((WORKFLOW, via, inner_local))
    sources: list[Source] = []

    def missed(*refs: UsesReference) -> list[tuple[str | None, str]]:
        return check_repo_module.unaccounted(root, sources, refs, unread, outer, walk, found)

    # A pin checked, an image named by its finding, an image pinned by digest, a listed local
    # Action: all accounted for. A local reference inside another repository's Action is not.
    (only,) = missed(pinned, image, digest, local)
    assert only == (WORKFLOW, f"actions/cache@{CACHE} -> ./inner: {check_repo_module._UNACCOUNTED}")
    walk.read.clear()
    assert missed(pinned, image, digest, local) == []
    # Drop any one result and the reference it accounted for is named: fail-closed. An image no
    # grammar has passed is named by its line only, never echoed.
    assert [d for _, d in missed(docker("docker://alpine:3.20", 4))] == [
        f"a reference (line 13): {check_repo_module._UNACCOUNTED}"
    ]
    other = UsesReference.read(f"actions/checkout@{NEW}", file=WORKFLOW, line=30, job="build", step=5)
    assert len(missed(other)) == 1
    unread.clear()
    assert len(missed(local)) == 1
    # Read twice, named once; reading it again gives the same answer.
    assert missed(other, other) == missed(other) == missed(other)


# --- exact names, as GitHub's runner reads them, not as a Mac's disk does (#143) ------

EVIL = "name: e\nruns:\n  using: composite\n  steps:\n    - uses: evil/x@main\n"
NFC = unicodedata.normalize("NFC", "café")
NFD = unicodedata.normalize("NFD", NFC)


def _also_listed(monkeypatch: pytest.MonkeyPatch, folder: Path, *names: str) -> None:
    """``folder`` lists ``names`` too, as GitHub's case-sensitive runner would hold them beside
    their twins; a Mac's disk cannot hold both, so the listing is injected, never skipped."""
    real = os.listdir

    def listdir(path: str) -> list[str]:
        found = real(path)
        return [*found, *names] if os.fspath(path) == str(folder) else found

    monkeypatch.setattr(os, "listdir", listdir)


def mac_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    """``os.path.lexists`` and ``os.path.exists`` answer as a Mac's case-insensitive disk does,
    on any disk, so a decoy test fails on Linux CI too if Guardian goes back to asking them."""

    def folding(real: Any) -> Any:
        def answer(path: Any) -> bool:
            folder, name = os.path.split(os.fspath(path))
            try:
                names = os.listdir(folder or ".")
            except OSError:
                return bool(real(path))
            return bool(real(path)) or any(n.casefold() == name.casefold() for n in names)

        return answer

    monkeypatch.setattr(os.path, "lexists", folding(os.path.lexists))
    monkeypatch.setattr(os.path, "exists", folding(os.path.exists))


def _uses_local(repo: Path, raw: str) -> Path:
    ci = repo / ".github" / "workflows" / "ci.yml"
    ci.write_text(CI + f"      - uses: {raw}\n")
    return ci


def test_local_action_metadata_is_matched_with_exact_case(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ci = _uses_local(repo, "./act")
    act = repo / "act"
    act.mkdir()
    (act / "Action.yml").write_text(NODE_ACTION)  # the decoy: no 'action.yml' to GitHub's runner
    (act / "action.yaml").write_text(EVIL)  # what the runner runs
    mac_disk(monkeypatch)
    assert os.path.lexists(act / "action.yml")  # the disk answers for the decoy
    sources = read_sources(str(repo))
    assert [s.path for s in sources] == [str(ci), str(act / "action.yaml")]
    assert [r.raw for r in sources[1].references] == ["evil/x@main"]
    # Only the decoy: the runner finds no metadata, so neither does Guardian (check --repo then
    # lists the Action as unread, exit 2), although a Mac's disk answers for 'action.yml'.
    (act / "action.yaml").unlink()
    assert [s.path for s in read_sources(str(repo))] == [str(ci)]
    ref = UsesReference.read("./act", file=str(ci), line=1, job="build", step=0)
    assert pin_module._local_action(str(repo), ref) is None
    # A file where the folder should be is no Action folder either.
    (act / "Action.yml").unlink()
    act.rmdir()
    act.write_text("not a folder\n")
    assert pin_module._local_action(str(repo), ref) is None


@pytest.mark.parametrize(
    ("where", "uses", "twins"),
    [
        ("act", "./act", ("ACTION.yml", "action.yml")),  # two metadata files
        ("", "./act", ("ACT", "act")),  # two folders on a local Action's path
        (".github/workflows", None, ("CI.yml", "ci.yml")),  # two workflows
    ],
)
def test_names_colliding_by_case_refuse(
    repo: Path, monkeypatch: pytest.MonkeyPatch, where: str, uses: str | None, twins: tuple[str, str]
) -> None:
    if uses is not None:
        _uses_local(repo, uses)
        (repo / "act").mkdir()
        (repo / "act" / "action.yml").write_text(NODE_ACTION)
    folder = repo / where if where else repo
    _also_listed(monkeypatch, folder, twins[0])
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    said = f"{folder} holds '{twins[0]}' and '{twins[1]}', names that differ only in letter case"
    with refuses("pin.names-differ-only-in-case-or-form"), pytest.raises(IncompleteCheckError, match=re.escape(said)):
        read_sources(str(repo))
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert f"ssc-guardian: {said};" in err and "nothing written." in err
    assert {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == before  # pin writes nothing on exit 2


@pytest.mark.parametrize("local", [False, True])
def test_names_colliding_by_unicode_form_refuse(repo: Path, monkeypatch: pytest.MonkeyPatch, local: bool) -> None:
    assert NFC != NFD
    if local:  # a local Action's folder, written NFC in the workflow
        _uses_local(repo, f"./{NFC}")
        (repo / NFC).mkdir()
        (repo / NFC / "action.yml").write_text(NODE_ACTION)
        folder, ours = repo, NFC
    else:  # a workflow
        folder, ours = repo / ".github" / "workflows", f"{NFC}.yml"
        (folder / ours).write_text(CI)
    other = unicodedata.normalize("NFD", ours)
    _also_listed(monkeypatch, folder, other)
    first, second = sorted((ours, other))
    said = f"{folder} holds '{first}' and '{second}', names that differ only in Unicode form"
    with refuses("pin.names-differ-only-in-case-or-form"), pytest.raises(IncompleteCheckError, match=re.escape(said)):
        read_sources(str(repo))
    # check --repo lists the refused file (or the workflow using the refused Action) by name and
    # still reports the workflow's own moving references: 1 wins over 2 (#146).
    with refuses("pin.names-differ-only-in-case-or-form"):
        result, err = check_repo(repo, GitHub())
    assert result.exit_code is ExitCode.VIOLATION
    assert said in err
    places = {s.place for s in result.skipped if s.in_scope}
    ci = str(repo / ".github" / "workflows" / "ci.yml")
    # A name outside the path grammar is listed with no place, never echoed.
    assert places == ({ci, str(repo)} if local else {None, str(repo)})


@pytest.mark.parametrize("name", ["deploy.YML", "deploy.Yaml"])
def test_workflow_extension_in_another_case_is_not_read_and_refuses(repo: Path, name: str) -> None:
    odd = repo / ".github" / "workflows" / name
    odd.write_text(CI)
    said = f"{odd}: a workflow's extension is .yml or .yaml only when letter case is ignored"
    with refuses("pin.workflow-extension-in-another-case"), pytest.raises(IncompleteCheckError, match=re.escape(said)):
        read_sources(str(repo))
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
    assert result.exit_code is ExitCode.INCOMPLETE and f"ssc-guardian: {said};" in err
    assert workflow(repo) == CI and odd.read_text() == CI and not (repo / LOCK_FILE).exists()


@pytest.mark.parametrize(("github", "workflows"), [(".github", "Workflows"), (".GitHub", "workflows")])
def test_workflows_folder_under_another_case_refuses(tmp_path: Path, github: str, workflows: str) -> None:
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / github / workflows).mkdir(parents=True)
    (root / github / workflows / "ci.yml").write_text(CI)
    parent, part, other = (
        (root / github, "workflows", workflows) if workflows != "workflows" else (root, ".github", github)
    )
    said = f"{parent} holds '{other}' where GitHub reads '{part}'"
    with (
        refuses("pin.workflows-folder-under-another-case"),
        pytest.raises(IncompleteCheckError, match=re.escape(said)),
    ):
        read_sources(str(root))
    result, err = check_repo(root, GitHub())
    assert result.exit_code is ExitCode.INCOMPLETE and said in err


def test_docker_image_prefix_case(repo: Path) -> None:
    # GitHub's documentation does not say the runner reads 'Docker://' as an image, so the file
    # is refused (exit 2), never read as naming nothing (owner's ruling, #143).
    for prefix in ("Docker://", "DOCKER://", "dOCKER://"):
        with (
            refuses("models.image-prefix-in-another-case"),
            pytest.raises(UnsupportedYamlError, match="docker:// in another letter case"),
        ):
            action_from(yaml_subset.parse(docker_action(f"{prefix}alpine:latest"), ACTION_FILE), ACTION_FILE)
    (finding,) = resolver.image_findings(
        action_from(yaml_subset.parse(docker_action("docker://alpine:latest"), ACTION_FILE), ACTION_FILE).references
    )
    assert (finding.rule, finding.item) == (Rule.UNPINNED_IMAGE, "alpine:latest")
    # Through check --repo: a local Docker Action with the prefix in another case is unfinished.
    _uses_local(repo, "./act")
    (repo / "act").mkdir()
    (repo / "act" / "action.yml").write_text(docker_action("Docker://alpine:latest"))
    result, err = check_repo(repo, GitHub())
    # The refused Action is listed by name; the workflow's own moving references still count (#146).
    assert result.exit_code is ExitCode.VIOLATION
    assert [(s.place, s.reason.value) for s in result.skipped if s.reason.in_scope] == [
        (str(repo / "act" / "action.yml"), "unsupported-yaml"),
        (str(repo), "check-error"),
    ]
    assert "docker:// in another letter case" in err


# --- pin stops on the first file it cannot read; check --repo reads each (#146) --------


def test_pin_still_stops_on_the_first_unreadable_file(repo: Path) -> None:
    unreadable = repo / ".github" / "workflows" / "z.yml"
    unreadable.write_text("a: &x 1\n")  # an anchor: outside the YAML subset
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    with pytest.raises(UnsupportedYamlError, match=re.escape(f"{unreadable}:1:")):
        read_sources(str(repo))
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    for _ in range(2):  # and again: re-running writes nothing either
        result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
        assert result.exit_code is ExitCode.INCOMPLETE
        assert f"ssc-guardian: {unreadable}:1:" in err and "nothing written." in err
        assert {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == before
    # check --repo's reading lists the file and still reads the other workflow.
    reading = pin_module.read_each(str(repo))
    assert [s.path for s in reading.sources] == [str(repo / ".github" / "workflows" / "ci.yml")]
    assert [(u.place, type(u.error)) for u in reading.unread] == [(str(unreadable), UnsupportedYamlError)]


def test_pin_still_stops_on_a_malformed_overrides_file(repo: Path) -> None:
    # #166: check --repo lists a malformed overrides file and goes on; pin still stops before it
    # writes, so it never pins on a file whose overrides it could not read.
    overrides = repo / ".ssc-guardian-overrides.toml"
    overrides.write_text("format = 1\n[[override]]\nitem = 5\n")
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    for _ in range(2):  # and again: re-running writes nothing either
        with refuses("overrides.malformed-entry"):
            result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
        assert result.exit_code is ExitCode.INCOMPLETE
        # Today's stop, unchanged: the repository is unfinished and stderr names the file.
        assert [(s.place, s.reason.value) for s in result.skipped if s.reason.in_scope] == [(str(repo), "check-error")]
        assert f"{overrides}: " in err and "nothing written" in err
        assert not (repo / LOCK_FILE).exists() and workflow(repo) == CI
        assert {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == before


# --- #144: each safety decision has a test that fails when the decision is weakened ----------


def test_compare_ahead_is_an_impostor(repo: Path) -> None:
    # A fork commit built on the default branch's tip compares "ahead" of it, the usual
    # impostor; only "identical" and "behind" put a commit in that history (T4).
    routes = github_routes(
        tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")], history={IMPOSTOR: "ahead"}
    )
    result, err = run_pin(repo, f"actions/checkout@{IMPOSTOR}", routes)
    assert result.exit_code is ExitCode.VIOLATION
    assert rules(result) == [Rule.IMPOSTOR_COMMIT]
    assert "impostor commit suspected" in err and "Nothing written." in err
    assert not (repo / LOCK_FILE).exists()
    assert workflow(repo) == CI
    # The control: the same commit compared "behind" the tip is in that history and is pinned.
    routes[f"/repos/actions/checkout/compare/main...{IMPOSTOR}?per_page=1"] = (200, {"status": "behind"})
    result, _ = run_pin(repo, f"actions/checkout@{IMPOSTOR}", routes)
    assert Rule.IMPOSTOR_COMMIT not in rules(result)


BRANCHY = "someone/branchy"
BRANCH_COMMIT = "ab" * 20  # on the branch named v9.9.9; no tag names it


def _branchy_github() -> GitHub:
    """An Action whose advisory covers every release below 2.0.0, with a branch named like a
    later release: GitHub's advisories match versions on their side, as the API does."""
    github = GitHub(advisories=[Advisory(GHSA, BRANCHY, "< 2.0.0")])
    github.publisher(BRANCHY, 88, tags={"v1.0.0": "cd" * 20})
    head = {"ref": "refs/heads/v9.9.9", "object": {"type": "commit", "sha": BRANCH_COMMIT}}
    github.routes[f"/repos/{BRANCHY}/git/ref/heads/v9.9.9"] = (200, head)
    pushed = [push(BRANCH_COMMIT, "2025-03-01T00:00:00Z", ref="refs/heads/v9.9.9")]
    github.routes[f"/repos/{BRANCHY}/activity?per_page=100"] = (200, pushed)
    return github


@pytest.mark.parametrize("ref", [BRANCH_COMMIT, "v9.9.9"], ids=["bare-sha", "branch"])
def test_bare_sha_and_branch_pins_get_unreleased_pin_advisory(tmp_path: Path, ref: str) -> None:
    # T6 in pin: a commit no release tag names has no version, so any advisory for the Action
    # cannot be ruled out. A branch named like a release must not lend the commit that version:
    # asked as v9.9.9, outside the advisory's range, GitHub would clear it and pin would write.
    github = _branchy_github()
    root = make_repo(tmp_path, f"{BRANCHY}@v1")
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result, err = pin_with(root, f"{BRANCHY}@{ref}", github)
    assert result.exit_code is ExitCode.VIOLATION
    assert violations(result) == {(Rule.UNRELEASED_PIN_ADVISORY, BRANCHY, BRANCH_COMMIT, (GHSA,))}
    assert github.asked() == {BRANCHY}  # by name alone: no version is sent for the commit
    assert f"cannot rule out {GHSA}; pin to a released version" in err
    assert "Guardian will pin" not in err
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before  # nothing written


def test_yaml_extension_workflow_is_read(tmp_path: Path) -> None:
    # GitHub runs a .yaml workflow as it runs a .yml one, so check --repo reads it: its moving
    # reference is a violation (exit 1), never an unread file or a pass.
    github = GitHub()
    github.publisher("t1/moving", 101)
    root = make_repo(tmp_path, "t1/moving@v1")
    ci = root / ".github" / "workflows" / "ci.yaml"
    (root / ".github" / "workflows" / "ci.yml").rename(ci)
    for _ in range(2):  # and again: the same answer
        result, _ = check_repo(root, github)
        assert result.exit_code is ExitCode.VIOLATION
        assert [(f.rule, f.place) for f in result.findings if f.level is Level.VIOLATION] == [
            (Rule.MOVING_REFERENCE, str(ci))
        ]
        assert [s for s in result.skipped if s.reason.in_scope] == []
    assert [s.path for s in read_sources(str(root))] == [str(ci)]


def test_symlink_to_a_file_inside_the_repository_stops(repo: Path) -> None:
    # A workflow that is a symlink stops pin (exit 2) even when it points inside the repository:
    # writing through it would change a file pin never read as a workflow.
    routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    inside = repo / "templates" / "ci.yml"
    inside.parent.mkdir()
    inside.write_text(CI)
    linked = repo / ".github" / "workflows" / "linked.yml"
    linked.symlink_to(inside)
    for _ in range(2):  # and again: re-running writes nothing either
        with refuses("pin.symlink-lies-outside-repository-pin"):
            result, err = run_pin(repo, "actions/checkout@v4.2.2", routes)
        assert result.exit_code is ExitCode.INCOMPLETE
        message = f"{linked} is a symlink or lies outside the repository; pin writes only the repository's files"
        assert f"ssc-guardian: {message}; nothing written.\n" in err
        assert linked.is_symlink() and inside.read_text() == CI and workflow(repo) == CI
        assert not (repo / LOCK_FILE).exists()
