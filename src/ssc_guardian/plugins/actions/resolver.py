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

"""Tag-to-commit lookup and the impostor-commit check (plan §3.2 T1 and T4).

- **T1 Moving tag.** A workflow reference must be a 40-hex commit SHA; a tag or branch is a
  ``moving-reference`` violation whose fix is ``pin`` (:func:`reference_findings`). A tag is
  resolved to its commit by asking GitHub every time; the answer is never cached, because a
  tag can move.
- **Docker images.** A ``docker://`` reference is pinned only by a ``@sha256:`` digest; any
  other form is an ``unpinned-image`` warning naming the file and the image
  (:func:`image_findings`).
- **T4 Impostor commit.** A pinned SHA must be listed in the lock file, else
  ``unverified-pin``. ``pin`` lists a commit only if one of three facts from the publisher's
  own repository vouches for it (:func:`verify`): a publisher tag points at it, the activity
  log shows it reaching a publisher branch, or it is in the default branch's history. A
  commit reachable only through a fork, which GitHub serves under the publisher's name, has
  none of the three. No repository is exempt, Guardian's own included.

Every read is a GET to ``api.github.com`` through :class:`~ssc_guardian.net.Client`. A failed
or unexpected answer raises :class:`~ssc_guardian.net.FeedError` (exit 2), never a guess. A
list that runs past its page limit is read only that far, which can only find fewer facts,
so a commit is refused rather than accepted.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime

from ssc_guardian.findings import Ecosystem, Finding, Option, OptionKind, Rule, SkipReason, make_finding, pin_command
from ssc_guardian.findings import _id_spelling as item_spelling
from ssc_guardian.grammars import Field, matches
from ssc_guardian.lockfile import LockEntry
from ssc_guardian.net import GITHUB_API, Client, FeedError
from ssc_guardian.plugins.actions.models import UsesKind, UsesReference

API = f"https://{GITHUB_API}"
ACCEPT = "application/vnd.github+json"
PER_PAGE = 100
MAX_PAGES = 10
PAGE_LIMIT = 8 * 1024 * 1024
# Annotated tags may point at other tags; more levels than this is refused, not followed.
MAX_TAG_DEPTH = 5
_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
# Compare statuses that put the head commit in the base branch's history.
_IN_HISTORY = frozenset({"identical", "behind"})


class RefNotFoundError(FeedError):
    """The publisher's repository, or the tag or branch named in it, does not exist (exit 2)."""

    def __init__(self, message: str, *, site: str | None = None) -> None:
        super().__init__(message, SkipReason.CHECK_ERROR, site=site)


def is_sha(ref: str) -> bool:
    return matches(Field.SHA, ref)


def commit_key(action: str, sha: str) -> tuple[str, str]:
    """A commit as the lock file keys it (:attr:`LockEntry.key`): the Action in its one
    spelling (D18) and the SHA."""
    return item_spelling(Ecosystem.GITHUB_ACTIONS, action) or action, sha


def repository_of(action: str) -> str:
    """``owner/repo`` of an Action, a path inside the repository dropped."""
    return "/".join(action.split("/")[:2])


def quote(value: str) -> str:
    return urllib.parse.quote(value, safe="/")


# --- reading the publisher's repository -------------------------------------------


def get_json(client: Client, url: str, *, allow: frozenset[int] = frozenset()) -> tuple[int, object]:
    response = client.get(url, accept=ACCEPT, limit=PAGE_LIMIT, allow=allow)
    return response.status, (response.json() if 200 <= response.status < 300 else None)


def pages(client: Client, url: str, *, max_pages: int = MAX_PAGES) -> Iterator[list[object]]:
    """Each page of a GitHub list, following ``rel="next"`` while it stays on ``api.github.com``."""
    for _ in range(max_pages):
        response = client.get(url, accept=ACCEPT, limit=PAGE_LIMIT)
        page = response.json()
        if not isinstance(page, list):
            raise FeedError(f"{GITHUB_API} sent a list that is not a list", site="resolver.sent-list-not-list")
        yield page
        found = _NEXT.search(response.headers.get("link", ""))
        if found is None:
            return
        url = found.group(1)
        if not url.startswith(f"{API}/"):
            raise FeedError(
                f"{GITHUB_API} sent a next page outside the API", site="resolver.sent-next-page-outside-api"
            )


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise FeedError(f"{GITHUB_API} sent {what} that is not text", site="resolver.value-not-text")
    return value


def _sha(value: object, what: str) -> str:
    text = _text(value, what)
    if not is_sha(text):
        raise FeedError(f"{GITHUB_API} sent {what} that is not a commit SHA", site="resolver.not-commit-sha")
    return text


@dataclass(frozen=True)
class Repository:
    """A publisher's repository: its name, GitHub's numeric ID and its default branch, and
    for T3 the UTC day GitHub's servers created it (plan §8 fact 33), its stars and forks."""

    name: str
    id: int
    default_branch: str
    created: date
    stars: int
    forks: int


def _count(value: object, what: str) -> int:
    if type(value) is not int or value < 0:
        raise FeedError(f"{GITHUB_API} sent {what} that is not a whole number", site="resolver.not-whole-number")
    return value


def _created(value: object) -> date:
    """The UTC day of the repository's ``created_at`` (``2019-08-07T13:20:40Z``)."""
    if isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            moment = None
        if moment is not None and moment.tzinfo is not None:
            return moment.astimezone(UTC).date()
    raise FeedError(
        f"{GITHUB_API} sent a creation time that is not a time with a time zone",
        site="resolver.sent-creation-time-not-time",
    )


def repository(client: Client, action: str) -> Repository:
    """The Action's repository, from one ``/repos`` request (T1, T3 and T4 share it)."""
    name = repository_of(action)
    status, body = get_json(client, f"{API}/repos/{quote(name)}", allow=frozenset({404}))
    if status == 404:
        raise RefNotFoundError(f"GitHub has no repository {name}", site="resolver.github-no-repository")
    if not isinstance(body, dict):
        raise FeedError(
            f"{GITHUB_API} sent repository details that are not an object",
            site="resolver.sent-repository-details-not-object",
        )
    repo_id, branch = body.get("id"), body.get("default_branch")
    if type(repo_id) is not int or repo_id <= 0:
        raise FeedError(
            f"{GITHUB_API} sent a repository ID that is not a positive number",
            site="resolver.sent-repository-id-not-positive",
        )
    if not isinstance(branch, str) or not matches(Field.GIT_REF, branch):
        raise FeedError(
            f"{GITHUB_API} sent a default branch that is not a valid name",
            site="resolver.sent-default-branch-not-valid",
        )
    created = _created(body.get("created_at"))
    stars = _count(body.get("stargazers_count"), "a star count")
    forks = _count(body.get("forks_count"), "a fork count")
    return Repository(name, repo_id, branch, created, stars, forks)


@dataclass(frozen=True)
class Resolved:
    """What a reference names today: its commit, and whether it is a tag or a branch."""

    ref: str
    sha: str
    is_tag: bool


def _ref(client: Client, repo: str, kind: str, name: str) -> tuple[str, str] | None:
    """The object a ``refs/<kind>/<name>`` points at, as (type, SHA); None if there is none."""
    status, body = get_json(client, f"{API}/repos/{quote(repo)}/git/ref/{kind}/{quote(name)}", allow=frozenset({404}))
    if status == 404:
        return None
    # GitHub answers a prefix with a list of matches; only the exact ref counts.
    if not isinstance(body, dict) or body.get("ref") != f"refs/{kind}/{name}":
        return None
    target = body.get("object")
    if not isinstance(target, dict):
        raise FeedError(f"{GITHUB_API} sent a ref with no object", site="resolver.sent-ref-no-object")
    return _text(target.get("type"), "an object type"), _sha(target.get("sha"), "a ref's SHA")


def resolve(client: Client, action: str, ref: str) -> Resolved:
    """The commit ``ref`` names in the Action's repository today: a tag first, then a branch.
    Always asked again (T1); an annotated tag is followed to its commit.

    Raises :class:`RefNotFoundError` (exit 2) when the repository has neither.
    """
    repo = repository_of(action)
    found = _ref(client, repo, "tags", ref)
    is_tag = found is not None
    if found is None:
        found = _ref(client, repo, "heads", ref)
    if found is None:
        raise RefNotFoundError(f"{repo} has no tag or branch {ref}", site="resolver.no-tag-branch")
    kind, sha = found
    for _ in range(MAX_TAG_DEPTH):
        if kind == "commit":
            return Resolved(ref, sha, is_tag)
        if kind != "tag":
            raise FeedError(f"{repo} {ref} points at a {kind}, not a commit", site="resolver.ref-not-a-commit")
        _, body = get_json(client, f"{API}/repos/{quote(repo)}/git/tags/{sha}")
        target = body.get("object") if isinstance(body, dict) else None
        if not isinstance(target, dict):
            raise FeedError(f"{GITHUB_API} sent a tag with no object", site="resolver.sent-tag-no-object")
        kind, sha = _text(target.get("type"), "an object type"), _sha(target.get("sha"), "a tag's SHA")
    raise FeedError(f"{repo} {ref} is a chain of more than {MAX_TAG_DEPTH} tags", site="resolver.tag-chain-too-long")


def tags(client: Client, action: str) -> dict[str, str]:
    """The publisher's tags and the commit each points at today (annotated tags followed)."""
    found: dict[str, str] = {}
    url = f"{API}/repos/{quote(repository_of(action))}/tags?per_page={PER_PAGE}"
    for page in pages(client, url):
        for item in page:
            commit = item.get("commit") if isinstance(item, dict) else None
            if not isinstance(item, dict) or not isinstance(commit, dict):
                raise FeedError(f"{GITHUB_API} sent a tag that is not an object", site="resolver.sent-tag-not-object")
            name = _text(item.get("name"), "a tag name")
            if matches(Field.GIT_REF, name):  # a tag no reference could name is of no use
                found[name] = _sha(commit.get("sha"), "a tag's SHA")
    return found


def in_default_branch(client: Client, repo: Repository, sha: str) -> bool:
    """Whether ``sha`` is in the history of the repository's default branch.

    Compares ``<default branch>...<sha>``: "identical" or "behind" puts the commit in that
    history. A commit GitHub cannot relate to the branch (404, 422) is not in it.
    """
    url = f"{API}/repos/{quote(repo.name)}/compare/{quote(repo.default_branch)}...{sha}?per_page=1"
    status, body = get_json(client, url, allow=frozenset({404, 422}))
    if status in {404, 422}:
        return False
    if not isinstance(body, dict):
        raise FeedError(
            f"{GITHUB_API} sent a comparison that is not an object", site="resolver.sent-comparison-not-object"
        )
    return _text(body.get("status"), "a comparison status") in _IN_HISTORY


# --- T4 ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Verification:
    """The facts T4 found for one commit.

    ``tags`` are the publisher tags pointing at it; ``on_branch`` is the earliest day the
    activity log shows it reaching a publisher branch (None if it does not);
    ``in_default_branch`` is None when not asked, because an earlier fact already vouched
    for the commit and the commit was seen on a branch.
    """

    sha: str
    tags: tuple[str, ...]
    on_branch: date | None
    in_default_branch: bool | None

    @property
    def verified(self) -> bool:
        """A publisher tag, the activity log or the default branch vouches for the commit."""
        return bool(self.tags) or self.on_branch is not None or bool(self.in_default_branch)

    @property
    def pushed(self) -> bool:
        """Whether the commit was ever seen on a publisher branch (else T2's warning)."""
        return self.on_branch is not None or bool(self.in_default_branch)


def verify(
    client: Client, repo: Repository, sha: str, all_tags: dict[str, str], on_branch: date | None
) -> Verification:
    """T4 for ``sha``, from the repository's tags today and the activity log's answer.

    The default branch is asked only when the activity log has not shown the commit on a
    branch, so a commit with neither gets T2's never-pushed warning.
    """
    pointing = tuple(sorted(name for name, target in all_tags.items() if target == sha))
    history = None if on_branch is not None else in_default_branch(client, repo, sha)
    return Verification(sha, pointing, on_branch, history)


# --- T1 and T4 on a workflow's references ---------------------------------------------


def reference_findings(references: Iterable[UsesReference], entries: Iterable[LockEntry]) -> tuple[Finding, ...]:
    """T1 and T4 for each reference to another repository's Action or reusable workflow.

    A tag or branch is ``moving-reference``; a SHA the lock file does not list is
    ``unverified-pin``. Each names ``pin`` with the reference as written as its fix. Local
    and Docker references are not Action pins and give nothing here.
    """
    listed = {entry.key for entry in entries}
    found: list[Finding] = []
    for ref in references:
        if ref.kind not in (UsesKind.ACTION, UsesKind.REUSABLE_WORKFLOW) or ref.action is None or ref.ref is None:
            continue
        if not is_sha(ref.ref):
            rule = Rule.MOVING_REFERENCE
        elif commit_key(ref.action, ref.ref) not in listed:
            rule = Rule.UNVERIFIED_PIN
        else:
            continue
        fix = Option(OptionKind.REPLACE, ref.action, ref.ref, command=pin_command(ref.action, ref.ref))
        found.append(
            make_finding(
                rule,
                Ecosystem.GITHUB_ACTIONS,
                place=ref.file,
                item=ref.action,
                version=ref.ref,
                options=(fix,),
                site="resolver.reference-not-pinned",
            )
        )
    return tuple(found)


# --- Docker images ----------------------------------------------------------------------


def image_pinned(image: str) -> bool:
    """Whether a Docker image is pinned: only a ``@sha256:`` digest of 64 lowercase hex pins
    one, and the ``docker-image`` grammar allows it only at the image's end. A tag can move."""
    return matches(Field.DOCKER_IMAGE, image) and "@sha256:" in image


def image_finding(ref: UsesReference, *, place: str, via: tuple[str, ...] = ()) -> Finding | None:
    """``unpinned-image`` (a warning) naming ``place`` and the image of a Docker reference not
    pinned by digest; None for one that is, or for a reference that is not Docker.

    The image reaches the finding only through the ``docker-image`` grammar (contracts §6): one
    that fails it is a ``malformed-name`` violation: never the finding's item and never in JSON
    (text output shows the rejected value escaped, contracts §5).
    """
    image = ref.image
    if image is None or image_pinned(image):
        return None
    return make_finding(Rule.UNPINNED_IMAGE, Ecosystem.GITHUB_ACTIONS, place=place, item=image, via=via)


def image_findings(references: Iterable[UsesReference]) -> tuple[Finding, ...]:
    """:func:`image_finding` for each Docker reference, at the file that holds it; one image
    used twice in a file is one finding."""
    found: dict[str, Finding] = {}
    for ref in references:
        finding = image_finding(ref, place=ref.file)
        if finding is not None:
            found.setdefault(finding.id, finding)
    return tuple(found.values())
