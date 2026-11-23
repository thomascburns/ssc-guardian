# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Negative tests for the Actions refusals: advisories, the cooldown clock, the resolver (issue #11)."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.findings import ExitCode
from ssc_guardian.net import FeedError
from ssc_guardian.plugins.actions import advisories, clock, resolver
from ssc_guardian.plugins.actions.advisories import Pin
from ssc_guardian.plugins.actions.resolver import RefNotFoundError, Repository
from tests.refusal_sites import Refuses, refuses
from tests.unit.test_nested_and_advisories import (
    NODE_ACTION,
    OUTER,
    Advisory,
    GitHub,
    check,
    listed,
    make_repo,
    sha,
)

pytestmark = pytest.mark.unit

GHSA = "GHSA-mrrh-fwg8-r2c3"
PINS = [Pin("/w.yml", OUTER, sha(1), ("v1.0.0",))]
REPO = f"/repos/{OUTER}"


def exact(message: str) -> str:
    """A `match=` pattern for exactly `message`."""
    return f"^{re.escape(message)}$"


# --- advisories: the boundary first -----------------------------------------------------


def _fetch(answer: tuple[Any, ...]) -> tuple[advisories.ActionAdvisory, ...]:
    """``advisories.fetch`` for one pin, GitHub giving ``answer`` to every advisories request."""
    return advisories.fetch(GitHub(advisory_answer=answer).client(), PINS)


def test_next_page_link_off_the_advisories_api_is_refused() -> None:
    off = {"link": '<https://evil.example/advisories?type=reviewed>; rel="next"'}
    with (
        refuses("advisories.githubs-next-page-link-leaves"),
        pytest.raises(FeedError, match=exact("GitHub's next-page link leaves the advisories API")),
    ):
        _fetch((200, [], off))
    # Another path on api.github.com is off the advisories API too.
    other = {"link": '<https://api.github.com/repos/someone/outer/tags?per_page=100>; rel="next"'}
    with (
        refuses("advisories.githubs-next-page-link-leaves"),
        pytest.raises(FeedError, match=exact("GitHub's next-page link leaves the advisories API")),
    ):
        _fetch((200, [], other))


def test_next_page_link_off_the_advisories_api_stops_check_with_exit_two(tmp_path: Path) -> None:
    github = GitHub(advisory_answer=(200, [], {"link": '<https://evil.example/x>; rel="next"'}))
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE  # never a pass
    assert result.findings == ()
    assert "GitHub's next-page link leaves the advisories API" in err
    assert github.count("/advisories") == 1  # the link was never followed


def test_next_page_link_the_client_refuses_is_refused() -> None:
    link = {"link": '<https://api.github.com/advisories?after=a b>; rel="next"'}
    with (
        refuses("advisories.githubs-next-page-link-not"),
        refuses("net.refused-url"),
        pytest.raises(FeedError, match=exact("GitHub's next-page link is not a URL Guardian sends")),
    ):
        _fetch((200, [], link))


@pytest.mark.parametrize(
    ("body", "said", "site"),
    [
        ({"a": 1}, "GitHub sent advisories that are not a list", refuses("advisories.github-sent-advisories-not-list")),
        ([5], "GitHub sent an advisory that is not an object", refuses("advisories.github-sent-advisory-not-object")),
        (
            [{}],
            "GitHub sent an advisory without its ID or vulnerabilities",
            refuses("advisories.github-sent-advisory-without-id"),
        ),
        (
            [{"ghsa_id": "", "vulnerabilities": []}],
            "GitHub sent an advisory without its ID or vulnerabilities",
            refuses("advisories.github-sent-advisory-without-id"),
        ),
        (
            [{"ghsa_id": GHSA, "vulnerabilities": {}}],
            "GitHub sent an advisory without its ID or vulnerabilities",
            refuses("advisories.github-sent-advisory-without-id"),
        ),
        (
            [{"ghsa_id": GHSA, "vulnerabilities": [5]}],
            f"GitHub sent {GHSA} with a vulnerability that is not an object",
            refuses("advisories.vulnerability-not-object"),
        ),
    ],
)
def test_advisory_answer_of_the_wrong_shape_is_refused(body: Any, said: str, site: Refuses) -> None:
    with site, pytest.raises(FeedError, match=exact(said)):
        _fetch((200, body))


@pytest.mark.parametrize("name", [5, None, "not an action", "../x"])
def test_advisory_for_an_action_with_an_invalid_name_is_refused(name: object) -> None:
    body = Advisory(GHSA, OUTER, "< 2").body()
    body["vulnerabilities"][0]["package"]["name"] = name
    with (
        refuses("advisories.action-whose-name-not-valid"),
        pytest.raises(FeedError, match=exact(f"GitHub sent {GHSA} for an Action whose name is not valid")),
    ):
        _fetch((200, [body]))


def test_full_page_of_advisories_without_a_next_link_is_refused() -> None:
    full = [Advisory(f"GHSA-{n:04d}-aaaa-aaaa", OUTER, "< 2").body() for n in range(advisories.PER_PAGE)]
    with (
        refuses("advisories.github-sent-full-page-advisories"),
        pytest.raises(FeedError, match=exact("GitHub sent a full page of advisories without a next-page link")),
    ):
        _fetch((200, full))


def test_too_many_pages_of_advisories_is_refused() -> None:
    # Every page names a next one on the advisories API, so the walk runs into its cap.
    github = GitHub(advisory_answer=(200, [], {"link": '<https://api.github.com/advisories?page=2>; rel="next"'}))
    with (
        refuses("advisories.github-sent-too-many-pages"),
        pytest.raises(FeedError, match=exact("GitHub sent too many pages of advisories")),
    ):
        advisories.fetch(github.client(), PINS)
    assert github.count("/advisories") == advisories.MAX_PAGES


# --- the cooldown clock -------------------------------------------------------------------


def _activity(timestamp: object) -> GitHub:
    github = GitHub()
    event = {"activity_type": "push", "ref": "refs/heads/main", "after": sha(1), "timestamp": timestamp}
    github.routes[f"{REPO}/activity?per_page=100"] = (200, [event])
    return github


def _release(published: object) -> GitHub:
    github = GitHub()
    release = {"immutable": True, "draft": False, "tag_name": "v1.0.0", "published_at": published}
    github.routes[f"{REPO}/releases?per_page=100"] = (200, [release])
    return github


def test_activity_time_that_is_not_text_is_refused() -> None:  # clock.py:48
    with (
        refuses("clock.time-not-string"),
        pytest.raises(FeedError, match=exact("api.github.com sent an activity time that is not a time")),
    ):
        clock.on_branch(_activity(1741718520).client(), OUTER, sha(1))
    with (
        refuses("clock.time-not-string"),
        pytest.raises(FeedError, match=exact("api.github.com sent a release time that is not a time")),
    ):
        clock.immutable_release(_release(None).client(), OUTER, sha(1), {"v1.0.0": sha(1)})


def test_activity_time_that_cannot_be_read_is_refused() -> None:  # clock.py:52
    with (
        refuses("clock.time-not-iso"),
        pytest.raises(FeedError, match=exact("api.github.com sent an activity time that is not a time")),
    ):
        clock.on_branch(_activity("last Tuesday").client(), OUTER, sha(1))
    with (
        refuses("clock.time-not-iso"),
        pytest.raises(FeedError, match=exact("api.github.com sent a release time that is not a time")),
    ):
        clock.immutable_release(_release("2025-13-40T00:00:00Z").client(), OUTER, sha(1), {"v1.0.0": sha(1)})


def test_activity_time_with_no_time_zone_is_refused() -> None:  # clock.py:54
    with (
        refuses("clock.time-no-zone"),
        pytest.raises(FeedError, match=exact("api.github.com sent an activity time with no time zone")),
    ):
        clock.on_branch(_activity("2025-03-11T18:42:00").client(), OUTER, sha(1))
    with (
        refuses("clock.time-no-zone"),
        pytest.raises(FeedError, match=exact("api.github.com sent a release time with no time zone")),
    ):
        clock.immutable_release(_release("2025-03-11T18:42:00").client(), OUTER, sha(1), {"v1.0.0": sha(1)})
    # The same time with its zone is read.
    assert clock.on_branch(_activity("2025-03-11T18:42:00Z").client(), OUTER, sha(1)) == date(2025, 3, 11)


def test_activity_event_that_is_not_an_object_is_refused() -> None:
    github = GitHub()
    github.routes[f"{REPO}/activity?per_page=100"] = (200, [["push"]])
    with (
        refuses("clock.api-github-com-sent-activity"),
        pytest.raises(FeedError, match=exact("api.github.com sent an activity event that is not an object")),
    ):
        clock.on_branch(github.client(), OUTER, sha(1))


def test_release_that_is_not_an_object_is_refused() -> None:
    github = GitHub()
    github.routes[f"{REPO}/releases?per_page=100"] = (200, ["v1.0.0"])
    with (
        refuses("clock.api-github-com-sent-release"),
        pytest.raises(FeedError, match=exact("api.github.com sent a release that is not an object")),
    ):
        clock.immutable_release(github.client(), OUTER, sha(1), {"v1.0.0": sha(1)})


# --- the resolver: repository identity first ----------------------------------------------


def _repository(**changed: object) -> GitHub:
    """A publisher whose ``/repos`` answer has ``changed`` in place of the good values."""
    github = GitHub()
    github.publisher(OUTER, 11)
    body = dict(github.routes[REPO][1], **changed)
    github.routes[REPO] = (200, body)
    return github


def test_missing_repository_is_ref_not_found() -> None:
    github = GitHub()  # every unknown route is a 404
    with (
        refuses("resolver.github-no-repository"),
        pytest.raises(RefNotFoundError, match=exact("GitHub has no repository someone/missing")),
    ):
        resolver.repository(github.client(), "someone/missing/path")
    assert github.seen == ["/repos/someone/missing"]


@pytest.mark.parametrize("body", [[{"id": 11}], "someone/outer", None])
def test_repository_details_that_are_not_an_object_are_refused(body: object) -> None:
    github = GitHub()
    github.routes[REPO] = (200, body)
    with (
        refuses("resolver.sent-repository-details-not-object"),
        pytest.raises(FeedError, match=exact("api.github.com sent repository details that are not an object")),
    ):
        resolver.repository(github.client(), OUTER)


@pytest.mark.parametrize("repo_id", [0, -11, "11", 11.0, True, None])
def test_repository_id_that_is_not_a_positive_number_is_refused(repo_id: object) -> None:
    with (
        refuses("resolver.sent-repository-id-not-positive"),
        pytest.raises(FeedError, match=exact("api.github.com sent a repository ID that is not a positive number")),
    ):
        resolver.repository(_repository(id=repo_id).client(), OUTER)


@pytest.mark.parametrize("created", ["2019-07-23T14:06:46", "yesterday", 1563890806, None])
def test_creation_time_that_is_not_a_time_with_a_zone_is_refused(created: object) -> None:
    said = "api.github.com sent a creation time that is not a time with a time zone"
    with refuses("resolver.sent-creation-time-not-time"), pytest.raises(FeedError, match=exact(said)):
        resolver.repository(_repository(created_at=created).client(), OUTER)


@pytest.mark.parametrize(("field", "what"), [("stargazers_count", "a star count"), ("forks_count", "a fork count")])
@pytest.mark.parametrize("count", [-1, "5000", 5.0, True, None])
def test_count_that_is_not_a_whole_number_is_refused(field: str, what: str, count: object) -> None:
    with (
        refuses("resolver.not-whole-number"),
        pytest.raises(FeedError, match=exact(f"api.github.com sent {what} that is not a whole number")),
    ):
        resolver.repository(_repository(**{field: count}).client(), OUTER)


def _tag_ref(target: object) -> GitHub:
    github = GitHub()
    github.routes[f"{REPO}/git/ref/tags/v1"] = (200, {"ref": "refs/tags/v1", "object": target})
    return github


@pytest.mark.parametrize("target", [None, sha(1), [{"type": "commit", "sha": sha(1)}]])
def test_ref_with_no_object_is_refused(target: object) -> None:
    with (
        refuses("resolver.sent-ref-no-object"),
        pytest.raises(FeedError, match=exact("api.github.com sent a ref with no object")),
    ):
        resolver.resolve(_tag_ref(target).client(), OUTER, "v1")


@pytest.mark.parametrize("kind", ["tree", "blob"])
def test_ref_to_something_other_than_a_commit_is_refused(kind: str) -> None:
    github = _tag_ref({"type": kind, "sha": sha(1)})
    with (
        refuses("resolver.ref-not-a-commit"),
        pytest.raises(FeedError, match=exact(f"someone/outer v1 points at a {kind}, not a commit")),
    ):
        resolver.resolve(github.client(), OUTER, "v1")


@pytest.mark.parametrize("body", [{}, {"object": None}, {"object": "commit"}, [sha(2)]])
def test_annotated_tag_with_no_object_is_refused(body: object) -> None:
    github = _tag_ref({"type": "tag", "sha": sha(1)})
    github.routes[f"{REPO}/git/tags/{sha(1)}"] = (200, body)
    with (
        refuses("resolver.sent-tag-no-object"),
        pytest.raises(FeedError, match=exact("api.github.com sent a tag with no object")),
    ):
        resolver.resolve(github.client(), OUTER, "v1")


def test_chain_of_too_many_annotated_tags_is_refused() -> None:
    github = _tag_ref({"type": "tag", "sha": sha(1)})
    for n in range(1, resolver.MAX_TAG_DEPTH + 1):
        github.routes[f"{REPO}/git/tags/{sha(n)}"] = (200, {"object": {"type": "tag", "sha": sha(n + 1)}})
    said = f"someone/outer v1 is a chain of more than {resolver.MAX_TAG_DEPTH} tags"
    with refuses("resolver.tag-chain-too-long"), pytest.raises(FeedError, match=exact(said)):
        resolver.resolve(github.client(), OUTER, "v1")
    assert github.count(f"{REPO}/git/tags/") == resolver.MAX_TAG_DEPTH
    # A shorter chain is followed to its commit.
    github.routes[f"{REPO}/git/tags/{sha(resolver.MAX_TAG_DEPTH - 1)}"] = (
        200,
        {"object": {"type": "commit", "sha": sha(9)}},
    )
    assert resolver.resolve(github.client(), OUTER, "v1").sha == sha(9)


@pytest.mark.parametrize("item", [5, "v1.0.0", {"name": "v1.0.0", "commit": sha(1)}, {"name": "v1.0.0"}])
def test_tag_that_is_not_an_object_is_refused(item: object) -> None:
    github = GitHub()
    github.routes[f"{REPO}/tags?per_page=100"] = (200, [item])
    with (
        refuses("resolver.sent-tag-not-object"),
        pytest.raises(FeedError, match=exact("api.github.com sent a tag that is not an object")),
    ):
        resolver.tags(github.client(), OUTER)


@pytest.mark.parametrize("body", [["identical"], "identical", None])
def test_comparison_that_is_not_an_object_is_refused(body: object) -> None:
    github = GitHub()
    github.routes[f"{REPO}/compare/main...{sha(1)}?per_page=1"] = (200, body)
    repo = Repository(OUTER, 11, "main", date(2019, 7, 23), 5000, 300)
    with (
        refuses("resolver.sent-comparison-not-object"),
        pytest.raises(FeedError, match=exact("api.github.com sent a comparison that is not an object")),
    ):
        resolver.in_default_branch(github.client(), repo, sha(1))
