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

"""The GitHub Actions part of ``check``: T1-T6 on one repository's workflows (plan §2.1,
§3.2; contracts §10.1, §10.4, §10.5).

``check --repo [DIR]`` checks DIR, which must be a Git top level (anything else is unfinished,
exit 2, so a mistyped CI gate never passes); plain ``check`` and ``check --ecosystem github-actions``
check the repository the current folder is in (outside one, see :mod:`.check_envs`). Every
workflow in ``.github/workflows`` and every local Action it uses is read (never run), with the
repository's settings, overrides and lock file and the workstation's ``config.toml``; in CI the
default branch's settings, overrides and acknowledgments (§10.5). The dependency files at the
repository's top level that v1.1 reads (plan §3.3) are listed as ``later-release`` skips.

**--path (#146).** ``--path`` selects workflows (any file read that lies inside a path); every
local Action and local reusable workflow a selected file reaches is read and checked with it,
at any depth, whatever the path (owner's ruling of 2026-11-10; plan §2.1: a filter narrows what
is checked and never relaxes a rule). Only the files nothing selected reaches are ``filtered``.
A relative ``--path`` is made absolute against the current folder (contracts §2).

**One file at a time (#146).** Each workflow and local Action is read on its own: a file the
reader refuses (outside the YAML subset, unreadable, a symlink, a malformed ``uses:`` value) is
an in-scope skip naming that file (a YAML refusal gives its line), and every other file is still
checked, so a finding still gives exit 1 (1 wins over 2). A refusal about the ``.github`` or
workflows folder itself (missing under another case, or not a folder: a dangling link is never
"no workflows") stops the check (exit 2). A malformed settings or lock file is an in-scope
``check-error`` skip naming that file, nothing in it applies, and the check stops (exit 2;
contracts §10.1, §11.3): they change what is checked. A malformed overrides file releases
nothing and the run goes on (#166): it is an in-scope ``check-error`` skip naming the file (in
CI, the default branch's copy is a ``default-branch-unreadable`` skip with no place), no
override in it applies, never a partial or default set, and every workflow is still checked, so
a finding still gives exit 1 (1 wins over 2). ``pin`` keeps stopping on the first file it
cannot read, a malformed overrides file included, before it writes.

1. **T1 and T4.** A tag or branch is ``moving-reference``; a SHA the lock file does not list
   is ``unverified-pin``; each names ``pin`` as its fix.
2. **T2.** A pinned commit still inside its cooldown is ``cooldown-wait`` ("eligible on"),
   exit 0.
3. **T5.** Inner references, read at each pinned commit (:mod:`.nested`).
4. **T3 and the deny list,** for every Action repository reached, outer and nested
   (:mod:`.publisher`).
5. **T6.** One batched advisory request for every pin read (:mod:`.advisories`). With the
   tags list T6 reads, a pinned commit whose lock entry records a release tag (three release
   parts) that names another commit today is ``moved-release-tag``, a warning (#201).
6. **Overrides** in the repository's file (the default branch's in CI) release
   ``known-vulnerability``, ``unreleased-pin-advisory``, ``nested-moving-reference`` and the
   T5 limits, each re-checked against today's facts (§10.4); a deny entry and a young
   repository are never overridden.

Steps 4 to 6 are :func:`evaluate`, which ``pin`` calls too on the commit it is about to write
(#126), so the two commands never keep separate copies of these checks.

A ``docker://`` reference, in a workflow or in an Action's metadata (a step, or a Docker
Action's ``runs.image``), is pinned only by a ``@sha256:`` digest, else ``unpinned-image`` (a
warning naming the file and the image). A local Action (``uses: ./PATH``) whose ``action.yml``
or ``action.yaml`` is not in the repository (one an earlier step checks out at run time) is not
read: it is listed as a ``check-error`` skip naming the file and the reference (exit 2).

**Accounting (#127).** After the checks run, every ``uses:`` reference read, in the
workflows, the local Actions and the nested Actions, must have ended in a check, a finding or
a listed skip (:func:`unaccounted`): a remote reference among the pins checked or named by a
finding, a Docker image pinned or named by its ``unpinned-image`` finding, a local reference
whose file was read or that is listed as skipped. One that did not, a kind no check handles
included, is listed as a ``check-error`` skip and the check is unfinished (exit 2), so a
reference is never dropped unseen. The accounting reads only this run's own results and writes
nothing, so a re-run gives the same report.

A failed request leaves the check unfinished (exit 2) after the other steps have run on what
was read, so every violation found is still reported (1 wins over 2). What each finding means
and how to fix it goes to stderr (text only).
"""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path

from ssc_guardian.ci_context import Fetch, load_repository_context
from ssc_guardian.commands.pin import Source, Unread, read_each
from ssc_guardian.commands.pin import _local_action as local_action_file
from ssc_guardian.feeds.kev import Kev, KevStatus
from ssc_guardian.findings import (
    Checked,
    Collector,
    Ecosystem,
    Finding,
    IncompleteCheckError,
    Label,
    LimitName,
    Option,
    OptionKind,
    OverrideRecord,
    Rule,
    Skip,
    SkipReason,
    Verb,
    make_finding,
    malformed_from,
    pin_command,
)
from ssc_guardian.grammars import Field, MalformedValueError, matches
from ssc_guardian.lockfile import LockEntry, load_lock, lock_path
from ssc_guardian.net import Client, FeedError, ShaCache, find_token
from ssc_guardian.overrides import Facts, Override, Release, aliases_of, release, utc_today
from ssc_guardian.pep440 import try_parse
from ssc_guardian.plugins.actions import advisories, clock, nested, publisher, resolver
from ssc_guardian.plugins.actions.models import UsesKind, UsesReference
from ssc_guardian.plugins.actions.resolver import ACCEPT, API, PAGE_LIMIT, RefNotFoundError, commit_key, is_sha
from ssc_guardian.settings import ConfigFileError, Key, Settings
from ssc_guardian.yaml_subset import UnsupportedYamlError

GHA = Ecosystem.GITHUB_ACTIONS
_REMOTE = (UsesKind.ACTION, UsesKind.REUSABLE_WORKFLOW)
_KEV_FACT = {KevStatus.LISTED: True, KevStatus.NOT_LISTED: False, KevStatus.UNAVAILABLE: None}
_ADVISORY_RULES = frozenset({Rule.KNOWN_VULNERABILITY, Rule.UNRELEASED_PIN_ADVISORY})
_PYPI_FILES = frozenset({"uv.lock", "pyproject.toml"})
_UNACCOUNTED = "no check, finding or listed skip accounts for this reference, so it was not checked"


def cache_dir(home: str | None) -> Path:
    """Where content addressed by a commit is kept between runs (plan §2.3)."""
    return Path(home if home is not None else os.path.expanduser("~")) / ".cache" / "ssc-guardian" / "actions"


def github_fetch(client: Client) -> Fetch:
    """``ci_context``'s fetch function, through the run's client (GET only)."""

    def fetch(path: str) -> tuple[int, bytes]:
        response = client.get(f"{API}{path}", accept=ACCEPT, limit=PAGE_LIMIT)
        return response.status, response.body

    return fetch


def merged(references: Iterable[UsesReference]) -> list[UsesReference]:
    """Each remote reference once per file: two spellings of one Action at one ref are one
    reference, the first spelling kept (D18, contracts §3's note for #10)."""
    kept: dict[tuple[str, UsesKind, str, str], UsesReference] = {}
    for ref in references:
        if ref.kind in _REMOTE and ref.action is not None and ref.ref is not None:
            kept.setdefault((ref.file, ref.kind, *commit_key(ref.action, ref.ref)), ref)
    return list(kept.values())


def later_release(root: str) -> list[tuple[Ecosystem | None, str]]:
    """The files at ``root``'s top level that a later release reads (plan §3.3), with their
    ecosystem: PyPI dependency files, and the pre-commit config (none of its own)."""
    found: list[tuple[Ecosystem | None, str]] = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        if name in _PYPI_FILES or fnmatchcase(name, "requirements*.txt"):
            found.append((Ecosystem.PYPI, path))
        elif name == ".pre-commit-config.yaml":
            found.append((None, path))
    return found


def _within(path: str, folder: str) -> bool:
    return os.path.commonpath([path, folder]) == folder


def _place(path: str) -> str | None:
    """A file as a skip's place: None when it fails the path grammar, never echoed."""
    return path if matches(Field.PATH, path) else None


def _reason(exc: Exception) -> SkipReason:
    """A refused file's skip reason: the refusal's own (``unsupported-yaml``) when it is an
    in-scope one, else ``check-error``, so a refused file is never an out-of-scope skip."""
    reason = getattr(exc, "reason", None) if isinstance(exc, IncompleteCheckError) else None
    return reason if isinstance(reason, SkipReason) and reason.in_scope else SkipReason.CHECK_ERROR


def _unread_detail(exc: Exception) -> str:
    """What a refused file's skip says (text output only): the line and the form refused, the
    problem with a file, else a fixed phrase; the full message goes to stderr. A file's own
    name is never repeated here, so one outside the path grammar is never echoed."""
    if isinstance(exc, UnsupportedYamlError):
        return f"line {exc.line}: {exc.form}"
    if isinstance(exc, ConfigFileError):
        return exc.problem
    if isinstance(exc, MalformedValueError):
        return f"a value in it is malformed ({exc.field.value})"
    return "refused; the reason is on stderr"


# --- --path (#146) --------------------------------------------------------------------


def _local_target(root: str, ref: UsesReference) -> str | None:
    """The file a local reference names in this repository: a local Action's metadata, or a
    local reusable workflow's file; None for any other reference."""
    if ref.kind is not UsesKind.LOCAL:
        return None
    if ref.step is not None:
        return local_action_file(root, ref)
    parts = [p for p in ref.raw[2:].split("/") if p and p != "."]
    return os.path.join(root, *parts)


def selected(
    root: str,
    sources: Sequence[Source],
    paths: Sequence[str],
    *,
    unread: Iterable[str] = (),
    refused: AbstractSet[tuple[str, str]] = frozenset(),
) -> frozenset[str]:
    """The files ``check --repo`` checks: with no ``paths``, every file; else each file inside a
    path and every local Action or local reusable workflow those files reach, at any depth,
    whatever the path (owner's ruling of 2026-11-10; plan §2.1: a filter never relaxes a rule).

    ``unread`` are the files that could not be read: one inside a path or reached is in the
    answer, so it is listed in scope. ``refused`` holds the local references (file,
    ``./PATH``) whose lookup was refused; they are listed by their own skip and not followed."""
    files = [*(s.path for s in sources), *unread]
    if not paths:
        return frozenset(files)
    by_path = {s.path: s for s in sources}
    todo = [f for f in files if any(_within(f, p) for p in paths)]
    chosen = set(todo)
    while todo:
        source = by_path.get(todo.pop())
        for ref in source.references if source is not None else ():
            if (ref.file, ref.raw) in refused:
                continue
            target = _local_target(root, ref)
            if target is not None and target not in chosen:
                chosen.add(target)
                todo.append(target)
    return frozenset(chosen)


# --- accounting (#127) ----------------------------------------------------------------


def unread_local_actions(
    root: str, references: Iterable[UsesReference], *, refused: AbstractSet[tuple[str, str]] = frozenset()
) -> list[UsesReference]:
    """The local Actions (a step's ``uses: ./PATH``) with no metadata file in the repository,
    each once per file: Guardian cannot read them, so they are listed, never dropped. One in
    ``refused`` (its lookup was refused) is listed by its own skip already."""
    unread: dict[tuple[str, str], UsesReference] = {}
    for ref in references:
        if ref.kind is not UsesKind.LOCAL or ref.step is None or (ref.file, ref.raw) in refused:
            continue
        if local_action_file(root, ref) is None:
            unread.setdefault((ref.file, ref.raw), ref)
    return list(unread.values())


def _remote_key(place: str, via: tuple[str, ...], action: str, version: str) -> tuple[str, tuple[str, ...], str, str]:
    return (place, via, *commit_key(action, version))


def unaccounted(
    root: str,
    sources: Sequence[Source],
    references: Sequence[UsesReference],
    unread: Sequence[UsesReference],
    outer: Sequence[advisories.Pin],
    walk: nested.Walk,
    found: Sequence[Finding],
    *,
    failed: AbstractSet[str] = frozenset(),
    refused: AbstractSet[tuple[str, str]] = frozenset(),
) -> list[tuple[str | None, str]]:
    """Each reference read that ended in no check, finding or listed skip, as a skip's place
    and text; empty when every one is accounted for.

    Fail-closed: a reference counts only when this run's own results show it handled, so one
    of a kind no check handles, or one a handler dropped, is returned. ``references`` are the
    workflows' and local Actions' own; ``walk`` holds those read in nested Actions. A local
    reference whose file is listed as not read (``failed``), or whose lookup was refused and
    listed (``refused``), counts as listed. Reads, never writes, so a re-run gives the same answer.
    """
    read = {s.path for s in sources} | set(failed)
    listed = {(r.file, r.raw) for r in unread} | set(refused)
    checked = {_remote_key(p.place, p.via, p.action, p.version) for p in outer}
    checked |= {_remote_key(n.place, n.via, n.action, n.ref) for n in walk.nodes}
    named = {
        _remote_key(f.place, f.via, f.item, f.version)
        for f in found
        if f.ecosystem is GHA
        and f.rule is not Rule.UNPINNED_IMAGE
        and f.place is not None
        and f.item is not None
        and f.version is not None
    }
    missed: dict[tuple[str | None, str], None] = {}

    def account(ref: UsesReference, place: str, via: tuple[str, ...]) -> bool:
        if ref.kind in _REMOTE and ref.action is not None and ref.ref is not None:
            key = _remote_key(place, via, ref.action, ref.ref)
            return key in checked or key in named
        if ref.kind is UsesKind.DOCKER:
            # Pinned by digest, or its own finding (unpinned-image, or malformed-name) was kept.
            image = resolver.image_finding(ref, place=place, via=via)
            return image is None or image in found
        if ref.kind is UsesKind.LOCAL and not via:
            if ref.step is None:  # a local reusable workflow: read with the workflows
                parts = [p for p in ref.raw[2:].split("/") if p and p != "."]
                return os.path.join(root, *parts) in read
            if (ref.file, ref.raw) in listed:  # asked first: a refused lookup would refuse again
                return True
            target = local_action_file(root, ref)
            return target is not None and target in read
        return False  # a local reference inside another repository's Action, or a kind no check handles

    for ref in references:
        if not account(ref, ref.file, ()):
            missed.setdefault((_place(ref.file), f"{_named(ref)}: {_UNACCOUNTED}"), None)
    for place, via, ref in walk.read:
        if not account(ref, place, via):
            missed.setdefault((_place(place), f"{' -> '.join(via)} -> {_named(ref)}: {_UNACCOUNTED}"), None)
    return list(missed)


def _named(ref: UsesReference) -> str:
    """A reference as a skip's text names it: as written when it is remote (both halves
    grammar-checked) or local (its ``./PATH``), once however often it is used; any other kind by
    its line alone, so a value no grammar has passed (a Docker image) never reaches output."""
    return ref.raw if ref.kind in (*_REMOTE, UsesKind.LOCAL) else f"a reference (line {ref.line})"


class _NotARepositoryError(IncompleteCheckError):
    def __init__(self, root: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.root = root

    def __str__(self) -> str:
        return "is not the top level of a Git repository (no .git there); name the repository's own folder"


@dataclass
class Run:
    """One check as it goes: findings before overrides, and what failed. ``check --repo``
    keeps one per repository; ``pin`` keeps one for the pin it plans."""

    root: str
    today: date
    settings: Settings
    entries: tuple[LockEntry, ...]
    notes: list[str]
    found: list[Finding] = field(default_factory=list)
    applied: list[OverrideRecord] = field(default_factory=list)
    expired: list[OverrideRecord] = field(default_factory=list)
    failure: IncompleteCheckError | None = None
    fixes: dict[str, bool | None] = field(default_factory=dict)  # finding ID -> fix passes today
    groups: dict[str, tuple[tuple[str, ...], ...]] = field(default_factory=dict)  # finding ID -> IDs per advisory

    def step(self, action: Callable[[], None]) -> None:
        """Run one step; a failure is kept for the end, so the other steps still run."""
        try:
            action()
        except MalformedValueError as exc:
            bad = malformed_from(exc, ecosystem=GHA, place=self.root)
            self.found.extend([bad] if bad is not None else [])
            self.failure = self.failure or IncompleteCheckError(
                SkipReason.CHECK_ERROR, site="check_repo.step-check-error"
            )
        except IncompleteCheckError as exc:
            self.notes.append(f"{self.root}: {exc}")
            self.failure = self.failure or exc

    def entry(self, action: str, sha: str) -> LockEntry | None:
        key = commit_key(action, sha)
        return next((e for e in self.entries if e.key == key), None)

    def recorded(self, action: str, ref: str) -> tuple[str, ...]:
        """The tag one outer reference was recorded under: a pinned commit's tag from the lock
        file (none for a bare SHA), else the reference as written."""
        if not is_sha(ref):
            return (ref,)
        entry = self.entry(action, ref)
        return (entry.tag,) if entry is not None and entry.tag != ref else ()

    @staticmethod
    def tags(pin: advisories.Pin, commits: nested.Commits) -> tuple[str, ...]:
        """The tags T6 asks about for one outer pin (#142): for a pinned commit, every publisher
        tag naming it today and the tag it was recorded under (the lock file's, or the one
        ``pin`` is about to write), since that tag records how the commit was asked for and a
        major tag (``v4``) names no release; a moving reference as written."""
        if not is_sha(pin.version):
            return pin.tags
        return commits.release_tags(pin.action, pin.version, *pin.tags)


def evaluate(
    run: Run,
    outer: Sequence[advisories.Pin],
    commits: nested.Commits,
    overrides: tuple[Override, ...],
    *,
    reach: Callable[[], nested.Walk] = nested.Walk,
) -> list[Finding]:
    """The deny list, T3 and T6 (plan §3.2) on the ``outer`` pins and the nested pins ``reach``
    finds below them, with ``moved-release-tag`` for an outer pin (#201), then the overrides:
    the findings no override releases, in the order found.

    ``check --repo`` and ``pin`` both call it, so neither keeps its own copy of these checks and
    a check added here reaches both (#126). ``reach`` runs after the outer pins' deny check:
    ``check --repo``'s T2 and T5; ``pin`` reaches no nested pin (T5 stays ``check --repo``'s
    job). A failed request is kept in ``run.failure`` while the other checks run on what was
    read; the caller raises it after reporting what was found, so it is never a pass.
    """
    run.found += publisher.deny_findings(((p.place, p.action, p.version, p.via) for p in outer), run.settings)
    walk = reach()
    run.found += publisher.deny_findings(((n.place, n.action, n.ref, n.via) for n in walk.nodes), run.settings)
    _publishers(outer, walk, commits, run)
    kev = Kev(commits.client)
    run.step(lambda: _advisories(outer, walk, commits, kev, run))
    return _release(run, overrides, kev)


@dataclass(frozen=True)
class CheckRepo:
    """The repository part of ``check``, with its places, clock and GitHub client injectable."""

    home: str | None = None
    environ: Mapping[str, str] | None = None
    today: date | None = None
    client: Client | None = None
    cache: ShaCache | None = None

    def run(self, root: str, paths: tuple[str, ...], collector: Collector, notes: list[str]) -> None:
        """Check the repository at ``root`` into ``collector``; ``paths`` select the workflows."""
        with collector.check(GHA, root) as ok:
            if ok:
                try:
                    if not os.path.lexists(os.path.join(root, ".git")):
                        # A mistyped folder, or a subfolder, has no workflows and the wrong settings:
                        # never a pass (the CLI's rule for a scope that checks nothing, §2).
                        raise _NotARepositoryError(root, site="check_repo.not-a-repository")
                    self._check(root, paths, collector, notes)
                except ConfigFileError as exc:
                    # A malformed settings or lock file: the skip names the file (contracts
                    # §10.1, §11.3) and nothing in it applies; the check stops, unfinished. A
                    # malformed overrides file never comes here: it is listed and the check goes on.
                    collector.skipped.append(exc.skip(GHA))
                    notes.append(str(exc))
                    raise
                except IncompleteCheckError as exc:
                    notes.append(f"{root}: {exc}")
                    raise

    def _check(self, root: str, paths: tuple[str, ...], collector: Collector, notes: list[str]) -> None:
        today = self.today or utc_today()
        environ = self.environ if self.environ is not None else os.environ
        client = self.client or Client(find_token(environ))
        context = load_repository_context(
            root, environ=environ, fetch=github_fetch(client), today=today, home=self.home
        )
        collector.findings += context.notices
        unusable = context.overrides_unusable
        if unusable is not None:
            # A malformed overrides file releases nothing (§10.1): listed, and every workflow is
            # still checked with no override, so a finding still gives exit 1 (1 wins over 2).
            collector.skipped.append(unusable.skip(GHA))
            notes.append(str(unusable))
        run = Run(root, today, context.settings, load_lock(lock_path(root)), notes)
        reading = read_each(root)
        sources = reading.sources
        refused = {(u.place, u.reference.raw) for u in reading.unread if u.reference is not None}
        chosen = selected(
            root, sources, paths, unread=[u.place for u in reading.unread if u.reference is None], refused=refused
        )
        kept = [s for s in sources if s.path in chosen]
        collector.skipped += [Skip(GHA, _place(s.path), SkipReason.FILTERED) for s in sources if s not in kept]
        collector.skipped += [
            Skip(ecosystem, _place(path), SkipReason.LATER_RELEASE)
            for ecosystem, path in later_release(root)
            if not paths or any(_within(path, p) for p in paths)
        ]
        failed, listed = self._unread(reading.unread, chosen, collector, notes)
        if listed:  # kept for the end: every other file is still checked, and a finding wins
            notes.append(f"{root}: a file was not read; each is listed as skipped")
            run.failure = IncompleteCheckError(SkipReason.CHECK_ERROR, site="check_repo.files-not-all-read")
        references = [r for s in kept for r in s.references]
        unread = unread_local_actions(root, references, refused=refused)
        collector.skipped += [
            Skip(
                GHA,
                _place(ref.file),
                SkipReason.CHECK_ERROR,
                detail=f"{ref.raw}: no action.yml or action.yaml there in the repository, so it was not read",
                site="check_repo.unread-local-action",
            )
            for ref in unread
        ]
        top = merged(references)

        run.found += resolver.reference_findings(top, run.entries)
        run.found += resolver.image_findings(references)
        outer = [
            advisories.Pin(r.file, r.action, r.ref, run.recorded(r.action, r.ref))
            for r in top
            if r.action is not None and r.ref is not None
        ]
        commits = nested.Commits(client, self.cache or ShaCache(cache_dir(self.home)))
        walk = nested.Walk()

        def reach() -> nested.Walk:
            run.step(lambda: self._cooldowns(top, run))
            run.step(lambda: self._walk(top, commits, context.overrides, run, walk))
            run.found += walk.findings
            run.notes += walk.notes
            run.applied += [r for r in walk.applied if r not in run.applied]
            return walk

        collector.findings += evaluate(run, outer, commits, context.overrides, reach=reach)
        collector.overrides_applied += [r for r in run.applied if r not in collector.overrides_applied]
        collector.overrides_expired += [r for r in run.expired if r not in collector.overrides_expired]
        missed = unaccounted(root, sources, references, unread, outer, walk, run.found, failed=failed, refused=refused)
        collector.skipped += [
            Skip(GHA, place, SkipReason.CHECK_ERROR, detail=detail, site="check_repo.unaccounted-reference")
            for place, detail in missed
        ]
        if unread or missed:
            notes.append(f"{root}: a uses: reference was not checked; each is listed as skipped")
            run.failure = run.failure or IncompleteCheckError(
                SkipReason.CHECK_ERROR, site="check_repo.references-not-all-checked"
            )
        if run.failure is not None:
            raise run.failure
        # Each --path value that matched a workflow source is reported as checked; one that
        # matched none (a typo) stays unreported, which the CLI makes an unfinished check (§3).
        collector.checked += [
            Checked(GHA, p) for p in dict.fromkeys(paths) if p != root and any(_within(s.path, p) for s in kept)
        ]

    @staticmethod
    def _unread(
        unread: Sequence[Unread], chosen: AbstractSet[str], collector: Collector, notes: list[str]
    ) -> tuple[frozenset[str], bool]:
        """List each file, or local Action used in a file, that could not be read: in scope when
        the file is selected (exit 2; a finding elsewhere still wins), else ``filtered``. Returns
        the selected files not read, whose references then count as listed, and whether any
        in-scope skip was added."""
        failed: set[str] = set()
        skips: dict[Skip, None] = {}
        for item in unread:
            place = _place(item.place)
            if item.place not in chosen:
                if item.reference is None:
                    skips[Skip(GHA, place, SkipReason.FILTERED)] = None
                continue
            exc = item.error
            if isinstance(exc, MalformedValueError):
                # A malformed value is a violation (contracts §3), and the file is unfinished.
                bad = malformed_from(exc, ecosystem=GHA, place=place)
                collector.findings.extend([bad] if bad is not None else [])
            notes.append(f"{item.place}: {exc}" if isinstance(exc, MalformedValueError) else str(exc))
            if item.reference is not None:
                detail = f"{item.reference.raw}: its metadata could not be looked up, so it was not read"
                skip = Skip(
                    GHA,
                    place,
                    SkipReason.CHECK_ERROR,
                    detail=detail,
                    site="check_repo.local-action-refused",
                    made_from=exc,
                )
            else:
                failed.add(item.place)
                skip = Skip(
                    GHA, place, _reason(exc), detail=_unread_detail(exc), site="check_repo.file-not-read", made_from=exc
                )
            skips[skip] = None
        collector.skipped += list(skips)
        return frozenset(failed), any(s.in_scope for s in skips)

    # --- T2 -------------------------------------------------------------------------

    @staticmethod
    def _cooldowns(top: list[UsesReference], run: Run) -> None:
        for ref in top:
            if ref.action is None or ref.ref is None or not is_sha(ref.ref):
                continue
            entry = run.entry(ref.action, ref.ref)
            if entry is None:
                continue
            begins = clock.start(entry.trusted_age(), run.settings.start_date(ref.action, ref.ref))
            cooldown = run.settings.cooldown_days(GHA, ref.action)
            wait = clock.cooldown_wait(
                begins, cooldown, run.today, place=ref.file, action=ref.action, sha=ref.ref, version=entry.tag
            )
            if wait is not None:
                run.found.append(wait)
                run.notes.append(
                    f"{ref.file}:{ref.line}: {ref.raw} is inside its {cooldown}-day cooldown: eligible on "
                    f"{clock.eligible_on(begins, cooldown).isoformat()}"
                )

    # --- T5 -------------------------------------------------------------------------

    def _walk(
        self,
        top: list[UsesReference],
        commits: nested.Commits,
        overrides: tuple[Override, ...],
        run: Run,
        into: nested.Walk,
    ) -> None:
        def released(step: str, limit: LimitName) -> OverrideRecord | None:
            outcome = _release_at(step, Rule.NESTING_LIMIT, (limit.value,), overrides, run.today)
            if outcome is None:
                return None
            run.expired += [r for r in outcome.expired if r not in run.expired]
            return outcome.applied[0] if outcome.released and outcome.applied else None

        nested.walk(
            top,
            commits=commits,
            depth=int(run.settings.value(Key.NESTING_DEPTH) or 0),
            limit=int(run.settings.value(Key.NESTED_REFERENCE_LIMIT) or 0),
            released=released,
            into=into,
        )


# --- T3 -----------------------------------------------------------------------------


def _publishers(outer: Sequence[advisories.Pin], walk: nested.Walk, commits: nested.Commits, run: Run) -> None:
    named = {publisher.repository_key(resolver.repository_of(p.action)): p.action for p in outer if p.action}
    reached = {**walk.repositories, **named}
    pinned = {publisher.repository_key(resolver.repository_of(e.action)) for e in run.entries}
    for key, action in sorted(reached.items()):
        first_use = key in named and key not in pinned

        def one(action: str = action, first_use: bool = first_use) -> None:
            assessment = publisher.assess(commits.repository(action), today=run.today, settings=run.settings)
            run.found += publisher.findings(assessment, place=run.root, first_use=first_use)
            run.notes += publisher.describe(assessment, first_use=first_use)

        run.step(one)


# --- T6 -----------------------------------------------------------------------------


def _advisories(
    outer: Sequence[advisories.Pin], walk: nested.Walk, commits: nested.Commits, kev: Kev, run: Run
) -> None:
    pins: dict[tuple[str, str, str, tuple[str, ...]], advisories.Pin] = {}
    for pin in outer:
        # Asked here, inside the step: a failed tags request is kept as the run's failure (exit 2).
        pin = dataclasses.replace(pin, tags=Run.tags(pin, commits))
        run.found += _moved(pin, commits, run)
        pins.setdefault((pin.place, *commit_key(pin.action, pin.version), pin.via), pin)
    for node in walk.nodes:
        pin = advisories.Pin(node.place, node.action, node.ref, node.tags, node.via)
        pins.setdefault((pin.place, *commit_key(pin.action, pin.version), pin.via), pin)
    if not pins:
        return
    listed = list(pins.values())
    for hit in advisories.match(listed, advisories.fetch(commits.client, listed)):
        run.found += _hit(hit, commits, kev, run)


def is_release_tag(tag: str) -> bool:
    """Whether ``tag`` names one exact release, which by near-universal convention is never
    moved: PEP 440 after an optional leading ``v``, with at least three release parts
    (``0.28.0``, ``v4.2.2``). A major tag (``v4``) or a line tag (``v4.1``) moves with every
    release by design, and ``stable`` or ``latest`` names no version, so none of them is
    compared (#201). Narrower than T6's :func:`advisories.is_version` (two parts) on purpose."""
    version = try_parse(tag)
    return version is not None and len(version.release) >= 3


def moved_release_tag(place: str | None, action: str, recorded: str, tag: str, now: str) -> Finding:
    """The ``moved-release-tag`` warning (#201): the release ``tag``, recorded in the lock file
    for the commit ``recorded``, names the commit ``now`` today. Its version is the recorded
    commit; the tag and both commits are in its text-only detail."""
    return make_finding(
        Rule.MOVED_RELEASE_TAG,
        GHA,
        place=place,
        item=action,
        version=recorded,
        detail=f"release tag {tag} was recorded for {recorded}; it names {now} today",
    )


def moved_note(action: str, tag: str, recorded: str, now: str) -> str:
    """What a moved release tag means, for stderr (text only)."""
    return (
        f"{action}: release tag {tag} names {now} today, not {recorded}, the commit the lock file "
        "recorded under it; a release tag is not expected to move, so this may be a compromise"
    )


def _moved(pin: advisories.Pin, commits: nested.Commits, run: Run) -> list[Finding]:
    """``moved-release-tag`` for one outer pinned commit whose lock entry records a release tag
    that names another commit today (#201). Reads the tags list :meth:`Run.tags` has just read
    (``Commits`` asks once per run), so it sends no request of its own. A tag absent from the
    list (deleted, or past the pages the list reads) is not a move; a nested pin records no tag.
    A warning: never an exit code. ``pin``'s pre-write check runs it too, on the commit it pins."""
    if pin.via or not is_sha(pin.version):
        return []
    entry = run.entry(pin.action, pin.version)
    if entry is None or not is_release_tag(entry.tag):
        return []
    now = commits.tags(pin.action).get(entry.tag)
    if now is None or now == entry.sha:
        return []
    run.notes.append(f"{pin.place}: {moved_note(pin.action, entry.tag, entry.sha, now)}")
    return [moved_release_tag(pin.place, pin.action, pin.version, entry.tag, now)]


def _hit(hit: advisories.Hit, commits: nested.Commits, kev: Kev, run: Run) -> list[Finding]:
    pin = hit.pin
    status = kev.status(hit.evidence)
    found: list[Finding] = []
    if status is KevStatus.UNAVAILABLE:
        found.append(
            make_finding(Rule.KEV_UNAVAILABLE, GHA, place=pin.place, item=pin.action, version=pin.version, via=pin.via)
        )
    options: list[Option] = []
    fix: bool | None = None
    if hit.rule is Rule.KNOWN_VULNERABILITY:
        # No fixed version Guardian can pin (none named, or a nested pin, whose fix is a new
        # release of the outer Action): an override can apply.
        fix = False
        if hit.patched is not None and not pin.via:
            option, fix = _fix(pin.action, hit.patched, commits, run)
            options += [option] if option is not None else []
    options.append(Option(OptionKind.EXCEPTION, person_command=Verb.OVERRIDE_ADD))
    labels = [Label.ACTIVELY_EXPLOITED] if status is KevStatus.LISTED else []
    finding = advisories.finding(hit, labels=labels, options=options)
    run.fixes[finding.id] = fix
    run.groups[finding.id] = tuple(a.evidence() for a in hit.advisories)
    found.append(finding)
    run.notes.append(advisories.describe(hit))
    return found


def _fix(action: str, patched: str, commits: nested.Commits, run: Run) -> tuple[Option | None, bool | None]:
    """The fixed version's ``pin`` once its cooldown has passed, else the day it does
    (T2); and whether it passes today. A fixed version that names no tag has nothing to pin
    (None, False); one that cannot be dated is unknown (None, None), and an override is
    then not applied."""
    for tag in dict.fromkeys((patched if patched.startswith("v") else f"v{patched}", patched)):
        try:
            resolved = commits.resolve(action, tag)
            if not resolved.is_tag:
                continue
            entry = run.entry(action, resolved.sha)
            if entry is not None:
                age = entry.trusted_age()
            else:
                activity = clock.on_branch(commits.client, action, resolved.sha)
                published = clock.immutable_release(commits.client, action, resolved.sha, {tag: resolved.sha})
                age = clock.recorded_age(activity, published, run.today)
        except RefNotFoundError:
            continue
        except FeedError as exc:
            run.notes.append(f"the fixed version {action}@{tag} could not be dated: {exc}")
            return None, None
        begins = clock.start(age, run.settings.start_date(action, resolved.sha))
        when = clock.eligible_on(begins, run.settings.cooldown_days(GHA, action))
        if run.today >= when:
            return Option(OptionKind.REPLACE, action, tag, command=pin_command(action, tag)), True
        run.notes.append(f"the fix {action}@{tag} is eligible on {when.isoformat()} (T2 cooldown)")
        return Option(OptionKind.REPLACE, action, tag, eligible_on=when), False
    run.notes.append(f"the fixed version {patched} of {action} names no tag in its repository")
    return None, False


# --- overrides ----------------------------------------------------------------------


def _release(run: Run, overrides: tuple[Override, ...], kev: Kev) -> list[Finding]:
    """The findings no override releases today; applied and expired ones are recorded."""
    kept: list[Finding] = []
    for finding in run.found:
        outcome: Release | None = None
        if overrides and finding.rule in _ADVISORY_RULES:
            fix, groups = run.fixes.get(finding.id), run.groups.get(finding.id, ())
            # KEV lists CVEs: an override's KEV status is read over its advisory's IDs.
            facts = {ref: Facts(_KEV_FACT[kev.status(aliases_of(ref, groups))], fix) for ref in finding.evidence}
            outcome = release(finding, overrides, today=run.today, facts=facts, groups=groups)
        elif overrides and finding.via and finding.item is not None and finding.version is not None:
            references = {
                Rule.NESTED_MOVING_REFERENCE: (f"{finding.item}@{finding.version}",),
                Rule.NESTING_LOOP: (LimitName.NESTING_LOOP.value,),
                # Past a limit with an override that applies, the walk went on; only an
                # expired one is left to list.
                Rule.NESTING_LIMIT: (LimitName.NESTING_DEPTH.value, LimitName.NESTED_REFERENCE_COUNT.value),
            }.get(finding.rule)
            if references is not None:
                outcome = _release_at(finding.via[-1], finding.rule, references, overrides, run.today)
        if outcome is not None:
            run.applied += [r for r in outcome.applied if r not in run.applied]
            run.expired += [r for r in outcome.expired if r not in run.expired]
            run.notes += [f"override {d.override.id} not applied: {d.why}" for d in outcome.not_applied]
            if outcome.released:
                continue
        kept.append(finding)
    return kept


def _release_at(
    step: str, rule: Rule, references: tuple[str, ...], overrides: tuple[Override, ...], today: date
) -> Release | None:
    """What the overrides do for ``rule`` at one outer step (``ACTION@SHA``): T5's overrides
    name the outer Action and its exact commit (D13). None when the step names no commit."""
    action, _, sha = step.rpartition("@")
    if not is_sha(sha) or not overrides:
        return None
    key = make_finding(rule, GHA, item=action, version=sha)
    return release(key, overrides, today=today, references=references)
