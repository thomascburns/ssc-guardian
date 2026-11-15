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

"""Nested Actions (plan §3.2 T5; contracts §4, §10.2, §10.4).

- **Read at the pinned outer commit.** A composite Action's ``runs.steps`` and a reusable
  workflow's jobs are fetched from GitHub at the outer commit and cached by repository ID and
  SHA (:class:`~ssc_guardian.net.ShaCache`), so an unchanged repository fetches them once.
- **Pinned inner references get T3, T4 and T6.** T4 is checked here: a publisher tag, the
  activity log or the default branch's history must vouch for the inner commit, else
  ``impostor-commit`` (exit 1). GitHub is asked again on every run and the answer is never
  cached, so a run on a warm cache and a run on a fresh CI runner agree (plan §2.3, §10.4
  2026-11-09). T3 and T6 run on :attr:`Walk.repositories` and :attr:`Walk.nodes`.
- **An inner moving reference** (a tag or branch) is ``nested-moving-reference`` (exit 1),
  reached through ``via``, with three fixes: a version of the outer Action that pins the inner
  one by commit, another Action, or a person's override for that exact outer commit and inner
  reference (at most 90 days, D13). Where the reference points today is resolved again on
  every run and checked like a pin: T6 under every publisher tag naming that commit (#142),
  and every level below it.
- **Limits.** One combined depth of ``nesting_depth`` levels below the workflow file (built-in
  10; a workflow's own references are level 1), across reusable workflows and composite
  Actions; at most ``nested_reference_limit`` unique nested references (``ACTION@REF``) per
  run (built-in 500). Past a limit the run fails, ``nesting-limit`` (exit 1); a loop (an Action
  commit reached again inside its own chain) is ``nesting-loop`` (exit 1). The exception is a
  person's override for the outer Action's exact commit, naming the limit; with one that
  applies today the walk goes on past that limit. Both limits can only be lowered (their
  settings ranges end at the built-in values).
- **Cut step 3 is not in effect:** every level is read, so nothing is listed as
  ``deeper-than-one-level``.

A Docker reference inside another repository's Action (a composite step's ``docker://``, or
a Docker Action's ``runs.image``) is pinned only by digest, else ``unpinned-image`` (a
warning), reached through ``via``. A local (``./``) reference there is not followed: it names
whatever the calling workflow checked out, not a commit Guardian can read, so ``check --repo``
lists it as not checked (:attr:`Walk.read` holds every reference the walk read, for that
accounting).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ssc_guardian import yaml_subset
from ssc_guardian.findings import (
    Ecosystem,
    Finding,
    IncompleteCheckError,
    LimitName,
    Option,
    OptionKind,
    OverrideRecord,
    Rule,
    SkipReason,
    Verb,
    make_finding,
)
from ssc_guardian.net import Client, FeedError, ShaCache
from ssc_guardian.plugins.actions import clock, resolver
from ssc_guardian.plugins.actions.models import (
    ActionMetadata,
    UsesKind,
    UsesReference,
    Workflow,
    action_from,
    workflow_from,
)
from ssc_guardian.plugins.actions.publisher import repository_key
from ssc_guardian.plugins.actions.resolver import API, Repository, commit_key, is_sha, quote
from ssc_guardian.settings import MAX_FILE_BYTES

GHA = Ecosystem.GITHUB_ACTIONS
ACTION_FILES = ("action.yml", "action.yaml")
RAW = "application/vnd.github.raw"
_REMOTE = (UsesKind.ACTION, UsesKind.REUSABLE_WORKFLOW)
# Cache keys that no path inside a repository can take (an Action path has no ':').
_ABSENT = ":absent:"
# ":verified" held a T4 result in versions before the 2026-11-09 ruling (plan §10.4). Nothing
# reads it now, so an entry left on disk vouches for nothing; never reuse the key.
# A walk visits each chain once; more chains than this is refused rather than followed.
MAX_VISITS = 20_000


class TooManyChainsError(IncompleteCheckError):
    """The nested references form more chains than Guardian follows (exit 2)."""

    def __init__(self, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)

    def __str__(self) -> str:
        return f"the nested Actions form more than {MAX_VISITS} chains; Guardian does not follow them all"


class Commits:
    """GitHub's answers about Action commits for one run: repositories, tags and T4 for a
    commit are asked once per run and never kept between runs; only files at a commit are
    cached, by repository ID and SHA."""

    def __init__(self, client: Client, cache: ShaCache | None = None) -> None:
        self.client = client
        self.cache = cache
        self._repositories: dict[str, Repository] = {}
        self._tags: dict[str, dict[str, str]] = {}
        # One answer per run for a commit reached through several chains.
        self._references: dict[tuple[str, str, UsesKind], tuple[UsesReference, ...]] = {}
        # T4 per commit for this run only: never read from or written to the cache.
        self._verified: dict[tuple[str, str], tuple[str, ...] | None] = {}
        self._resolved: dict[tuple[str, str], resolver.Resolved] = {}

    def repository(self, action: str) -> Repository:
        key = repository_key(resolver.repository_of(action))
        if key not in self._repositories:
            self._repositories[key] = resolver.repository(self.client, action)
        return self._repositories[key]

    def tags(self, action: str) -> dict[str, str]:
        """The publisher repository's tags list (tag name to commit), asked of GitHub once per
        run per repository and shared by every call on this ``Commits`` that needs it: T4 for an
        inner pinned commit (:meth:`verify`), the tags T6 asks about (:meth:`release_tags`, for
        outer pins in ``check --repo`` and ``pin``'s pre-write check, and for inner moving
        references), and in ``pin`` the outer commit's T4 (``resolver.verify``) and its release
        dating (``clock.immutable_release``), which read a copy of it. Never cached between
        runs."""
        key = repository_key(resolver.repository_of(action))
        if key not in self._tags:
            self._tags[key] = resolver.tags(self.client, action)
        return self._tags[key]

    def release_tags(self, action: str, sha: str, *recorded: str) -> tuple[str, ...]:
        """The tags T6 asks about for the commit ``sha`` (#142): every publisher tag naming it
        today, from the repository's tags list (:meth:`tags`: asked once per run, and the same
        list :meth:`verify`'s T4 reads for an inner pinned commit and ``pin`` reads for its outer
        commit's T4), and each tag it was ``recorded`` under (the lock file's tag, the tag ``pin``
        writes, or an inner tag as written). Which of them name a release is
        :attr:`advisories.Pin.versions`'s call. A failed tags request raises (exit 2), never a
        pass."""
        named = {name for name, target in self.tags(action).items() if target == sha}
        return tuple(sorted(named | {tag for tag in recorded if tag != sha}))

    # The cache holds only files at a commit (and their absence), which never change.
    def _get(self, repo: Repository, sha: str, key: str) -> bytes | None:
        return self.cache.get(repo.id, sha, key) if self.cache is not None else None

    def _put(self, repo: Repository, sha: str, key: str, data: bytes) -> None:
        if self.cache is None:
            return
        try:
            self.cache.put(repo.id, sha, key, data)
        except OSError:  # a cache that cannot be written only costs requests next run
            return

    def file(self, action: str, sha: str, path: str) -> str | None:
        """The text of ``path`` in the Action's repository at ``sha``; None if it has none."""
        repo = self.repository(action)
        if self._get(repo, sha, _ABSENT + path) is not None:
            return None
        data = self._get(repo, sha, path)
        if data is None:
            url = f"{API}/repos/{quote(repo.name)}/contents/{quote(path)}?ref={sha}"
            response = self.client.get(url, accept=RAW, limit=MAX_FILE_BYTES, allow=frozenset({404}))
            if response.status == 404:
                self._put(repo, sha, _ABSENT + path, b"")
                return None
            data = response.body
            self._put(repo, sha, path, data)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise FeedError(
                f"{repo.name}/{path} at {sha} is not UTF-8", SkipReason.CHECK_ERROR, site="nested.not-utf-8"
            ) from None

    def references(self, action: str, sha: str, kind: UsesKind) -> tuple[UsesReference, ...]:
        """Every ``uses:`` in the Action's metadata, or the reusable workflow, at ``sha``."""
        key = (*commit_key(action, sha), kind)
        if key not in self._references:
            self._references[key] = self._read_references(action, sha, kind)
        return self._references[key]

    def _read_references(self, action: str, sha: str, kind: UsesKind) -> tuple[UsesReference, ...]:
        repo = resolver.repository_of(action)
        inside = action.split("/")[2:]
        reader: Callable[[yaml_subset.Node | None, str], Workflow | ActionMetadata]
        if kind is UsesKind.REUSABLE_WORKFLOW:
            candidates, reader = ["/".join(inside)], workflow_from
        else:
            candidates, reader = ["/".join([*inside, name]) for name in ACTION_FILES], action_from
        for path in candidates:
            text = self.file(action, sha, path)
            if text is not None:
                label = f"{repo}/{path}@{sha}"
                return reader(yaml_subset.parse(text, label), label).references
        raise FeedError(
            f"{repo} has no {' or '.join(candidates)} at {sha}", SkipReason.CHECK_ERROR, site="nested.no-metadata-file"
        )

    def resolve(self, action: str, ref: str) -> resolver.Resolved:
        """Where a tag or branch points today: asked once per run, never cached between runs."""
        key = (repository_key(resolver.repository_of(action)), ref)
        if key not in self._resolved:
            self._resolved[key] = resolver.resolve(self.client, action, ref)
        return self._resolved[key]

    def verify(self, action: str, sha: str) -> tuple[str, ...] | None:
        """T4 for an inner commit: the publisher's tags naming it (the versions T6 asks about),
        or None when no publisher fact vouches for it (impostor commit suspected). Asked of
        GitHub once per run, on every run (plan §10.4, 2026-11-09)."""
        key = commit_key(action, sha)
        if key not in self._verified:
            self._verified[key] = self._verify(action, sha)
        return self._verified[key]

    def _verify(self, action: str, sha: str) -> tuple[str, ...] | None:
        repo = self.repository(action)
        all_tags = self.tags(action)
        pointing = tuple(sorted(name for name, target in all_tags.items() if target == sha))
        if not pointing:
            activity = clock.on_branch(self.client, action, sha)
            if not resolver.verify(self.client, repo, sha, all_tags, activity).verified:
                return None
        return pointing


@dataclass(frozen=True)
class Node:
    """One reference to another repository's commit, as the walk reached it.

    ``place`` is the file that holds the outermost reference; ``via`` the outer steps,
    outermost first (empty for a workflow's own reference); ``ref`` is as written and ``sha``
    the commit it names (resolved today for a moving reference); ``tags`` are the tags naming
    that commit, whose versions T6 sends.
    """

    place: str
    action: str
    ref: str
    sha: str
    kind: UsesKind
    via: tuple[str, ...]
    level: int
    tags: tuple[str, ...] = ()

    @property
    def step(self) -> str:
        """This node as a ``via`` step: the Action and the commit it was read at."""
        return f"{self.action}@{self.sha}"


# Whether an override releases a limit at this outer step today (its record), else None.
LimitRelease = Callable[[str, LimitName], OverrideRecord | None]


def _no_release(step: str, limit: LimitName) -> OverrideRecord | None:
    return None


@dataclass
class Walk:
    """What a walk found. Filled as it goes, so a walk that stops early keeps what it found."""

    findings: list[Finding] = field(default_factory=list)
    nodes: list[Node] = field(default_factory=list)  # every inner reference reached
    repositories: dict[str, str] = field(default_factory=dict)  # one spelling -> as first written
    applied: list[OverrideRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unique: set[tuple[str, str]] = field(default_factory=set)
    # Every reference read at a commit, as (place, via, reference), via ending at that commit:
    # what ``check --repo``'s accounting holds the findings and nodes above to.
    read: list[tuple[str, tuple[str, ...], UsesReference]] = field(default_factory=list)


def _is_remote(ref: UsesReference) -> bool:
    return ref.kind in _REMOTE and ref.action is not None and ref.ref is not None


def _one_spelling(references: Iterable[UsesReference]) -> list[UsesReference]:
    """The remote references at one commit, each once: two spellings of one Action at one ref
    are one reference, the first spelling kept (D18, contracts §3's note for #10)."""
    kept: dict[tuple[UsesKind, str, str], UsesReference] = {}
    for ref in references:
        if _is_remote(ref) and ref.action is not None and ref.ref is not None:
            kept.setdefault((ref.kind, *commit_key(ref.action, ref.ref)), ref)
    return list(kept.values())


# A person's override can release each of T5's three findings (contracts §10.4), so each offers
# that exception in JSON, as ``known-vulnerability`` does (#151).
_OVERRIDE = (Option(OptionKind.EXCEPTION, person_command=Verb.OVERRIDE_ADD),)


def _limit(rule: Rule, ref: UsesReference, node: Node, *, site: str) -> Finding:
    """A limit's finding; ``site`` names the place in :func:`walk` that reached it (issue #164)."""
    return make_finding(
        rule,
        GHA,
        place=node.place,
        item=ref.action,
        version=ref.ref,
        options=_OVERRIDE,
        via=(*node.via, node.step),
        site=site,
    )


def walk(
    top: Iterable[UsesReference],
    *,
    commits: Commits,
    depth: int,
    limit: int,
    released: LimitRelease = _no_release,
    into: Walk | None = None,
) -> Walk:
    """T5 below every pinned reference in ``top`` (a workflow's own references, level 1).

    ``released`` says whether an override lets the walk past a limit at an outer step. A
    failed request stops the walk with what it found kept in ``into``.
    """
    result = into if into is not None else Walk()
    stack: list[tuple[Node, tuple[tuple[str, str], ...]]] = []
    for ref in top:
        if ref.kind in _REMOTE and ref.action is not None and ref.ref is not None and is_sha(ref.ref):
            node = Node(ref.file, ref.action, ref.ref, ref.ref, ref.kind, (), 1)
            stack.append((node, (commit_key(ref.action, ref.ref),)))
    stack.reverse()  # the first reference is walked first
    visits = 0

    def release(step: str, name: LimitName) -> bool:
        record = released(step, name)
        if record is not None and record not in result.applied:
            result.applied.append(record)
        return record is not None

    while stack:
        node, chain = stack.pop()
        visits += 1
        if visits > MAX_VISITS:
            raise TooManyChainsError(site="nested.too-many-chains")
        children: list[tuple[Node, tuple[tuple[str, str], ...]]] = []
        references = commits.references(node.action, node.sha, node.kind)
        via = (*node.via, node.step)
        remote = _one_spelling(references)
        # Every other reference is handled here and now; a remote one counts as read when the
        # loop below reaches it, so one a limit stops the walk before is never read, as below.
        result.read += [(node.place, via, ref) for ref in references if not _is_remote(ref)]
        for ref in references:
            image = resolver.image_finding(ref, place=node.place, via=via)
            if image is not None and image not in result.findings:
                result.findings.append(image)
        for ref in remote:
            if ref.action is None or ref.ref is None:  # never: _one_spelling keeps remote references only
                continue
            result.read.append((node.place, via, ref))
            level = node.level + 1
            if level > depth and not release(node.step, LimitName.NESTING_DEPTH):
                result.findings.append(_limit(Rule.NESTING_LIMIT, ref, node, site="nested.depth-limit"))
                result.notes.append(
                    f"{' -> '.join(via)} -> {ref.raw}: deeper than {depth} levels below the workflow file"
                )
                continue
            key = (repository_key(ref.action), ref.ref)
            if key not in result.unique:
                result.unique.add(key)
                # Past the limit, each further reference needs an override for its own outer commit.
                if len(result.unique) > limit and not release(node.step, LimitName.NESTED_REFERENCE_COUNT):
                    result.findings.append(_limit(Rule.NESTING_LIMIT, ref, node, site="nested.reference-count-limit"))
                    result.notes.append(f"more than {limit} unique nested references; the walk stopped there")
                    return result
            result.repositories.setdefault(repository_key(resolver.repository_of(ref.action)), ref.action)
            child = _inner(ref, ref.action, ref.ref, node, via, level, commits, result)
            if child is None:
                continue
            result.nodes.append(child)
            if commit_key(child.action, child.sha) in chain:
                result.findings.append(_limit(Rule.NESTING_LOOP, ref, node, site="nested.loop"))
                result.notes.append(f"{' -> '.join(via)} -> {ref.raw}: a loop back to a commit already in the chain")
                continue
            # Each inner commit once below one outer commit: a tag and a pin naming one commit
            # (in any spelling) would otherwise give two chains whose findings share IDs.
            if any(commit_key(c.action, c.sha) == commit_key(child.action, child.sha) for c, _ in children):
                continue
            children.append((child, (*chain, commit_key(child.action, child.sha))))
        stack.extend(reversed(children))
    return result


def _inner(
    ref: UsesReference,
    action: str,
    written: str,
    node: Node,
    via: tuple[str, ...],
    level: int,
    commits: Commits,
    result: Walk,
) -> Node | None:
    """The node for one inner reference (``action@written``) after T4 (pinned) or T5's
    moving-reference rule; None for an impostor commit, which is not read further."""
    chain = " -> ".join(via)
    if is_sha(written):
        tags = commits.verify(action, written)
        if tags is None:
            result.findings.append(
                make_finding(
                    Rule.IMPOSTOR_COMMIT,
                    GHA,
                    place=node.place,
                    item=action,
                    version=written,
                    via=via,
                    site="nested.impostor-commit",
                )
            )
            result.notes.append(
                f"{chain} -> {ref.raw}: impostor commit suspected (no publisher tag, branch or "
                "default-branch history names it)"
            )
            return None
        return Node(node.place, action, written, written, ref.kind, via, level, tags)
    result.findings.append(
        make_finding(
            Rule.NESTED_MOVING_REFERENCE,
            GHA,
            place=node.place,
            item=action,
            version=written,
            options=_OVERRIDE,
            via=via,
            site="nested.moving-reference",
        )
    )
    result.notes.append(
        f"{chain} -> {ref.raw}: an inner moving reference. Fixes: a version of {node.action} that pins "
        f"{action} by commit; another Action; or a person's override for {node.step} and {ref.raw} "
        "(ssc-guardian override add, at most 90 days)"
    )
    resolved = commits.resolve(action, written)
    # Asked like a pinned commit: every tag naming the commit it names today (#142).
    tags = commits.release_tags(action, resolved.sha, *((written,) if resolved.is_tag else ()))
    return Node(node.place, action, written, resolved.sha, ref.kind, via, level, tags)
