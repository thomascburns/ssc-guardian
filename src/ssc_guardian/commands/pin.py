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

"""``ssc-guardian pin OWNER/REPO[/PATH]@REF``: verify an Action commit, record it in the lock
file, then write the pin (plan §2.1, §3.2 T1 to T4 and T6; contracts §11; D15, D16).

1. **T1.** A tag or branch is resolved to its commit by asking GitHub now; a 40-hex SHA is
   used as given and recorded as its own tag (§11.4 L3).
2. **T4.** The commit must be vouched for by a publisher tag, the activity log or the default
   branch's history; otherwise "impostor commit suspected" (exit 1) and nothing is written.
   Guardian's own repository is not exempt.
3. **T2.** A commit new to the lock file gets its start date: the earliest GitHub-recorded
   date, else today as its first-seen date. A commit already listed keeps its entry
   unchanged. A person's date can only make the start later. Inside the cooldown, ``pin``
   records the commit in the lock file, so its first-seen clock runs, leaves the workflows as
   they are and reports "eligible on <date>" (exit 0). A commit never seen on a publisher
   branch gets a warning. A release tag (three release parts) that the lock file records
   under another commit is ``moved-release-tag``, a warning given before the cooldown message
   (#201). Pinning a commit the lock file lists under a release tag that has since moved gets
   the same warning from the pre-write check in step 4, which ``check --repo`` shares; that
   check runs only when ``pin`` has something to write, so a run with nothing to write gives
   no warning that the commit it pins is listed under a release tag that has since moved.
4. **T3, T6 and the deny list.** Before the change is shown, the commit ``pin`` will record
   (eligible or still waiting) gets the checks ``check --repo`` runs on a pin, through the
   same function (``check_repo.evaluate``, #126); a run with nothing to write asks nothing
   more. A denied Action, an advisory for the version, or a young or little-used repository
   nobody acknowledged refuses the whole command (exit 1) with nothing written. A person's
   override, read from the repository's overrides file, and an ``acknowledge`` record release
   a finding exactly as they do for ``check --repo``; nothing releases the deny list. A failed
   request is exit 2 with nothing written, never a pass. The Action's own nested references
   stay ``check --repo``'s job (T5).
5. Once eligible, every reference to the Action in the repository's workflows, and in the
   local Actions they use, becomes ``ACTION@SHA # TAG``.
6. The lock file keeps the entries a workflow still uses and, for each Action, a rollback
   target (the previous commit) and the newest commit still waiting out its cooldown;
   ``pin`` drops the rest (L3). Which commit a workflow uses is read from the workflows,
   never stored.

``pin`` is the only writer of the lock file. Every change is shown first, on stderr, and
written only on confirmation (``cli.confirm``); ``--yes`` confirms in advance and still prints
the change. Declined, or no terminal: nothing written, exit 2 (D15). The lock file is written
first, then each workflow, each atomically (``settings.atomic_write``) and read back; a file
that changed while the person read the change stops the command with nothing written. A
re-run writes nothing.
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, TextIO

from ssc_guardian import yaml_subset
from ssc_guardian.findings import (
    Collector,
    Ecosystem,
    IncompleteCheckError,
    Level,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    make_finding,
)
from ssc_guardian.grammars import MalformedValueError
from ssc_guardian.lockfile import LockEntry, canonical, dump_lock, lock_path, parse_lock
from ssc_guardian.net import Client, find_token
from ssc_guardian.overrides import REPOSITORY_OVERRIDES_FILE, Override, load_overrides, utc_today
from ssc_guardian.plugin import InstallPlan, Item
from ssc_guardian.plugins.actions import advisories, clock, nested, resolver
from ssc_guardian.plugins.actions.models import (
    ActionMetadata,
    UsesKind,
    UsesReference,
    Workflow,
    action_from,
    workflow_from,
)
from ssc_guardian.plugins.actions.publisher import repository_key
from ssc_guardian.render import strip_controls
from ssc_guardian.settings import (
    SETTINGS_FILE,
    WORKSTATION_SETTINGS_FILE,
    FileKind,
    Settings,
    atomic_write,
    find_repository_root,
    load_settings,
    read_text,
    workstation_dir,
)

if TYPE_CHECKING:
    from ssc_guardian.cli import Request

GHA = Ecosystem.GITHUB_ACTIONS
WORKFLOWS = (".github", "workflows")
ACTION_FILES = ("action.yml", "action.yaml")
# One ``uses:`` line as pin rewrites it: the key, a plain or quoted value, an optional comment.
_USES_LINE = re.compile(
    r"(?P<head>[ \t]*(?:-[ \t]+)?uses:[ \t]+)(?P<quote>[\"']?)(?P<raw>[^\"'#\s]+)(?P=quote)(?P<tail>[ \t]*(?:#.*)?)"
)
_LINE_BREAK = re.compile(r"(\r\n|\r|\n)")


class _StopError(IncompleteCheckError):
    """Ends the command with nothing written (exit 2); the message says why."""

    def __init__(self, message: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.message = message

    def __str__(self) -> str:
        return self.message


Reader = Callable[[yaml_subset.Node | None, str], Workflow | ActionMetadata]


@dataclass(frozen=True)
class Source:
    """One workflow or local Action file, as read: its text and every ``uses:`` in it."""

    path: str
    text: str
    reader: Reader
    references: tuple[UsesReference, ...]


def _references(reader: Reader, text: str, path: str) -> tuple[UsesReference, ...]:
    return reader(yaml_subset.parse(text, path), path).references


def _inside(root: str, path: str) -> bool:
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(path)]) == real_root


def _listing(folder: str) -> list[str] | None:
    """The names in ``folder`` as the file system stores them, sorted; None when there is no
    such folder. Any other failure stops the command (exit 2)."""
    try:
        return sorted(os.listdir(folder))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _StopError(f"{folder} could not be read ({type(exc).__name__})", site="pin.could-not-read") from exc


def _folded(name: str) -> str:
    """``name`` as a Mac's disk compares it: letter case and Unicode form ignored."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", name).casefold())


def _refuse_collisions(folder: str, names: Iterable[str], wanted: Iterable[str]) -> None:
    """Stop (exit 2) when ``folder`` holds two names that differ only in letter case or Unicode
    form, one of them a name in ``wanted``. GitHub's runner keeps both as different files, a Mac
    keeps one, so Guardian cannot say which file it reads; nothing is guessed (#143)."""
    groups: dict[str, list[str]] = {}
    for name in names:
        groups.setdefault(_folded(name), []).append(name)
    for name in wanted:
        group = groups.get(_folded(name), [])
        if len(group) > 1:
            first, second = group[0], group[1]
            same_form = unicodedata.normalize("NFC", first) == unicodedata.normalize("NFC", second)
            how = "Unicode form" if same_form else "letter case"
            raise _StopError(
                f"{folder} holds '{first}' and '{second}', names that differ only in {how}; GitHub's "
                "runner reads them as different files and a Mac's disk as one, so Guardian cannot say "
                "which one it would check",
                site="pin.names-differ-only-in-case-or-form",
            )


def _exact(folder: str, name: str) -> str | None:
    """``folder/name`` when ``folder`` lists ``name`` exactly; None otherwise, also when only
    another case or Unicode form of it is there, since GitHub's runner would not find that."""
    names = _listing(folder)
    if names is None:
        return None
    _refuse_collisions(folder, names, (name,))
    return os.path.join(folder, name) if name in names else None


def _local_action(root: str, ref: UsesReference) -> str | None:
    """The metadata file of a local Action (``uses: ./PATH``) in this repository, or None
    when the repository has none there (an Action checked out at run time).

    Each folder on the path and the metadata file name are matched exactly, as on GitHub's
    runner: ``Action.yml`` is not ``action.yml`` (#143)."""
    parts = [p for p in ref.raw[2:].split("/") if p and p != "."]
    if ".." in parts:
        raise _StopError(
            f"{ref.file}:{ref.line}: {ref.raw} leaves its folder; pin reads only this repository",
            site="pin.leaves-folder-pin-reads-only",
        )
    folder = root
    for part in parts:
        found = _exact(folder, part)
        if found is None or not os.path.isdir(found):
            return None
        folder = found
    names = _listing(folder)
    if names is None:
        return None
    _refuse_collisions(folder, names, ACTION_FILES)
    return next((os.path.join(folder, name) for name in ACTION_FILES if name in names), None)


def _workflows_folder(root: str) -> str | None:
    """``.github/workflows``, each name matched exactly; None when there is none. A folder
    there only under another case or Unicode form stops the command (exit 2): a Mac's disk can
    hold GitHub's workflows under that name, and they would go unread. So does a dangling link or
    a file in place of either folder: it is never read as "no workflows" (#146)."""
    folder = root
    for part in WORKFLOWS:
        names = _listing(folder)
        if names is None:
            return None
        _refuse_collisions(folder, names, (part,))
        if part not in names:
            other = next((n for n in names if _folded(n) == _folded(part)), None)
            if other is not None:
                raise _StopError(
                    f"{folder} holds '{other}' where GitHub reads '{part}'; Guardian cannot say "
                    "whether the workflows in it run, so they are not checked",
                    site="pin.workflows-folder-under-another-case",
                )
            return None
        folder = os.path.join(folder, part)
        try:
            os.stat(folder)
        except FileNotFoundError:
            # Listed but not there: a link to a missing place. A file there is refused by the
            # listing that follows ("could not be read"); neither is ever "no workflows".
            raise _StopError(
                f"{folder} is a link to a missing place, so the workflows it should hold cannot be read",
                site="pin.workflows-link-target-missing",
            ) from None
        except OSError:
            pass  # a link loop or a denied folder: the listing that follows names it (exit 2)
    return folder


@dataclass(frozen=True)
class Unread:
    """A file ``check --repo`` could not read (``reference`` None), or a local Action used in
    a file it read whose metadata it could not look up; ``place`` is that file."""

    place: str
    error: IncompleteCheckError | MalformedValueError
    reference: UsesReference | None = None


@dataclass(frozen=True)
class Reading:
    """``check --repo``'s read: the files read, and each file or local Action it could not."""

    sources: tuple[Source, ...]
    unread: tuple[Unread, ...]


def read_sources(root: str) -> tuple[Source, ...]:
    """Every workflow in ``.github/workflows`` and every local Action they reach, read once.

    Every name is matched exactly, as GitHub's runner matches it, never through a Mac's disk,
    which ignores letter case and Unicode form (#143): a workflow is a file whose name ends in
    ``.yml`` or ``.yaml``, and a local Action's metadata is ``action.yml``, else
    ``action.yaml``. Two names in one folder that differ only in case or Unicode form, a
    workflow whose extension is written in another case (``ci.YML``, which GitHub's
    documentation does not say the runner reads), or a workflows folder only under another
    case stops the command (exit 2), so no file stands in for another and none is dropped.

    A file outside the repository (through a symlink), unreadable, or outside the YAML subset
    stops the command (exit 2): which commits the repository uses is read, never guessed.
    ``pin`` must stop on the first such file before it writes; ``check --repo`` reads each file
    on its own instead (:func:`read_each`).
    """
    return _read(root, None)


def read_each(root: str) -> Reading:
    """As :func:`read_sources`, for ``check --repo`` (#146): a file it refuses, or a local Action
    whose metadata it cannot look up, is listed in ``unread`` and every other file is still
    read. A refusal about the ``.github`` or workflows folder itself still stops the check."""
    unread: list[Unread] = []
    sources = _read(root, unread)
    return Reading(sources, tuple(unread))


def _read(root: str, unread: list[Unread] | None) -> tuple[Source, ...]:
    """The files read; ``unread`` None stops on the first file that fails (``pin``)."""
    queue: list[tuple[str, Reader]] = []
    folder = _workflows_folder(root)
    names = _listing(folder) if folder is not None else None
    if folder is not None and names is not None:
        like = [name for name in names if name.casefold().endswith((".yml", ".yaml"))]
        if unread is None:  # pin: any collision stops the command first, as before #146
            _refuse_collisions(folder, names, like)
        for name in like:
            path = os.path.join(folder, name)
            try:
                _refuse_collisions(folder, names, (name,))
                if not name.endswith((".yml", ".yaml")):
                    raise _StopError(
                        f"{path}: a workflow's extension is .yml or .yaml only when letter case is "
                        "ignored; GitHub's documentation does not say the runner reads it, so it is "
                        "not checked",
                        site="pin.workflow-extension-in-another-case",
                    )
            except IncompleteCheckError as exc:
                if unread is None:
                    raise
                unread.append(Unread(path, exc))
                continue
            queue.append((path, workflow_from))
    sources: list[Source] = []
    seen: set[str] = set()
    while queue:
        path, reader = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        try:
            source = _source(root, path, reader)
        except (IncompleteCheckError, MalformedValueError) as exc:
            if unread is None:
                raise
            unread.append(Unread(path, exc))
            continue
        sources.append(source)
        for ref in source.references:
            if ref.kind is UsesKind.LOCAL and ref.step is not None:
                try:
                    local = _local_action(root, ref)
                except IncompleteCheckError as exc:
                    if unread is None:
                        raise
                    unread.append(Unread(path, exc, ref))
                    continue
                if local is not None:
                    queue.append((local, action_from))
    return tuple(sources)


def _source(root: str, path: str, reader: Reader) -> Source:
    if os.path.islink(path) or not _inside(root, path):
        raise _StopError(
            f"{path} is a symlink or lies outside the repository; pin writes only the repository's files",
            site="pin.symlink-lies-outside-repository-pin",
        )
    text = read_text(path)
    if text is None:
        raise _StopError(f"{path} disappeared while it was read", site="pin.disappeared-while-read")
    return Source(path, text, reader, _references(reader, text, path))


def _remote(ref: UsesReference) -> bool:
    return ref.kind in (UsesKind.ACTION, UsesKind.REUSABLE_WORKFLOW) and ref.action is not None


def used_commits(references: Iterable[UsesReference]) -> set[tuple[str, str]]:
    """The commits these references pin, keyed as the lock file keys them."""
    return {
        resolver.commit_key(r.action, r.ref)
        for r in references
        if _remote(r) and r.action is not None and r.ref is not None and resolver.is_sha(r.ref)
    }


def pinned_value(action: str, sha: str, tag: str) -> str:
    """The ``uses:`` value of a pin: the commit, with its tag kept as a comment (T1)."""
    return f"{action}@{sha}" + ("" if tag == sha else f" # {tag}")


@dataclass(frozen=True)
class Rewrite:
    """One file's new text, the lines that change, and its references afterwards."""

    source: Source
    text: str
    lines: tuple[str, ...]
    references: tuple[UsesReference, ...]


def rewrite(source: Source, action: str, sha: str, tag: str) -> Rewrite | None:
    """``source`` with every reference to ``action`` (in its one spelling) pinned to ``sha``;
    None when none needs to change. Each reference keeps its own spelling of the Action.

    Only the value on each ``uses:`` line changes. A line that is not a plain ``uses: VALUE``
    (with optional quotes and comment) stops the command, and the new text must read back
    with the same references in the same places, so a rewrite can never change anything else.
    """
    spelling = resolver.commit_key(action, sha)[0]
    targets = {
        ref.line: ref
        for ref in source.references
        if _remote(ref) and ref.ref != sha and resolver.commit_key(ref.action or "", sha)[0] == spelling
    }
    if not targets:
        return None
    parts = _LINE_BREAK.split(source.text)  # text, break, text, break, ...
    shown: list[str] = []
    for number, ref in sorted(targets.items()):
        index = 2 * (number - 1)
        line = _USES_LINE.fullmatch(parts[index]) if index < len(parts) else None
        if line is None or line.group("raw") != ref.raw:
            raise _StopError(
                f"{source.path}:{number}: pin rewrites only a plain 'uses: VALUE' line",
                site="pin.pin-rewrites-only-plain-uses",
            )
        value = pinned_value(ref.action or action, sha, tag)
        parts[index] = line.group("head") + value
        shown.append(f"  {strip_controls(source.path)}:{number}: {strip_controls(ref.raw)} -> {strip_controls(value)}")
    text = "".join(parts)
    after = _references(source.reader, text, source.path)
    expected = [
        (r.kind, r.line, r.job, r.step, f"{r.action}@{sha}" if r.line in targets else r.raw) for r in source.references
    ]
    if [(r.kind, r.line, r.job, r.step, r.raw) for r in after] != expected:
        # The handler adds "; nothing written." to every stop (#151).
        raise _StopError(f"{source.path} did not read back as pin rewrote it", site="pin.did-not-read-back-pin")
    return Rewrite(source, text, tuple(shown), after)


def prune(
    entries: Iterable[LockEntry],
    used: AbstractSet[tuple[str, str]],
    keep: tuple[str, str],
    used_before: AbstractSet[tuple[str, str]] = frozenset(),
    waiting: Callable[[LockEntry], bool] = lambda entry: False,
) -> tuple[LockEntry, ...]:
    """The entries to keep (§11.4 L3): those a workflow uses, and for each Action at most two
    unused ones, newest first-seen date first.

    - **The rollback target:** the commit just pinned if no workflow uses it and it is past its
      cooldown, else the commit the workflows used before this pin, else the newest entry past
      its cooldown.
    - **The waiting commit:** the commit just pinned if it is still inside its cooldown
      (``waiting``), else the newest other such entry, kept so its first-seen clock is not
      restarted.

    Neither slot can take the other's place, so a waiting commit, which was never used, never
    displaces the rollback target; and since the result holds at most one entry of each kind,
    a second run with the same workflows on the same day keeps the same entries. A commit
    recorded while it waited and never used is dropped once its cooldown has passed and
    another rollback target exists.
    """
    entries = tuple(entries)
    kept = [e for e in entries if e.key in used]

    def newest(candidates: Iterable[LockEntry]) -> LockEntry | None:
        return max(candidates, key=lambda e: (e.first_seen, e.trusted, e.sha), default=None)

    extra: list[LockEntry] = []
    for action in dict.fromkeys(e.key[0] for e in entries):
        unused = [e for e in entries if e.key[0] == action and e not in kept]
        pinned = next((e for e in unused if e.key == keep), None)
        wait = pinned if pinned is not None and waiting(pinned) else None
        rollback = pinned if pinned is not None and wait is None else None
        rollback = rollback or newest(e for e in unused if e.key in used_before and e is not wait)
        rollback = rollback or newest(e for e in unused if not waiting(e))
        wait = wait or newest(e for e in unused if waiting(e) and e is not rollback)
        extra += [e for e in (rollback, wait) if e is not None]
    return canonical([*kept, *extra])


@dataclass(frozen=True)
class _Change:
    """What ``pin`` will write once confirmed, and the texts it read, to detect a change."""

    plan: InstallPlan
    lock: str
    lock_read: str | None
    lock_text: str | None  # None: the lock file stays as it is
    rewrites: tuple[Rewrite, ...]
    lines: tuple[str, ...]
    sources: tuple[Source, ...]  # every file whose pins decided the change


@dataclass(frozen=True)
class Pin:
    """The ``pin`` handler, with its streams, places, clock and GitHub client injectable."""

    stdin: TextIO | None = None
    stderr: TextIO | None = None
    cwd: str | None = None
    home: str | None = None
    today: date | None = None
    client: Client | None = None
    environ: Mapping[str, str] | None = None

    def __call__(self, request: Request) -> Result:
        from ssc_guardian import cli  # imported here: cli imports this handler

        err = self.stderr or sys.stderr
        collector = Collector(Verb.PIN)
        root = find_repository_root(self.cwd or os.getcwd())
        if root is None or request.action is None or request.ref is None:
            why = (
                "pin works inside a Git repository, and this is not one"
                if root is None
                else "name the version to pin: OWNER/REPO[/PATH]@TAG or OWNER/REPO[/PATH]@SHA"
            )
            _say(err, [f"ssc-guardian: {why}; nothing written."])
            collector.skipped.append(
                Skip(GHA, None, SkipReason.CHECK_ERROR, detail=why, site="pin.no-repository-or-version")
            )
            return collector.result()
        change: _Change | None = None
        with collector.check(GHA, root) as ok:
            if ok:
                try:
                    change = self._plan(request.action, request.ref, root, collector, err)
                except IncompleteCheckError as exc:
                    _say(err, [f"ssc-guardian: {strip_controls(exc)}; nothing written."])
                    raise
        if change is None:
            return collector.result()
        text = "\n".join(change.lines)
        if request.yes:
            _say(err, [text, "Confirmed in advance (--yes)."])  # the record D15 asks for
        if not cli.confirm(text, verb=Verb.PIN, yes=request.yes, stdin=self.stdin or sys.stdin, stdout=err):
            _say(err, ["ssc-guardian: not confirmed; nothing written. Add --yes to confirm in advance."])
            collector.skipped.append(
                Skip(
                    GHA, root, SkipReason.CHECK_ERROR, detail="not confirmed; nothing written", site="pin.not-confirmed"
                )
            )
            return collector.result()
        _apply(change, collector, err)
        return collector.result()

    def _settings(self, root: str) -> Settings:
        workstation = os.path.join(workstation_dir(self.home), WORKSTATION_SETTINGS_FILE)
        return Settings.of(
            load_settings(workstation, kind=FileKind.WORKSTATION, home=self.home),
            load_settings(os.path.join(root, SETTINGS_FILE), kind=FileKind.REPOSITORY),
        )

    def _plan(self, action: str, ref: str, root: str, collector: Collector, err: TextIO) -> _Change | None:
        today = self.today or utc_today()
        settings = self._settings(root)
        overrides = load_overrides(os.path.join(root, REPOSITORY_OVERRIDES_FILE), kind=FileKind.REPOSITORY, today=today)
        lock = lock_path(root)
        if os.path.islink(lock):
            raise _StopError(
                f"{lock} is a symlink; pin writes only the repository's own lock file",
                site="pin.symlink-pin-writes-only-repositorys",
            )
        lock_read = read_text(lock)
        entries = parse_lock(lock_read, place=lock) if lock_read is not None else ()
        sources = read_sources(root)
        client = self.client or Client(find_token(self.environ))

        repo = resolver.repository(client, action)
        # One tags list per run (#142): this copy serves T4 and the release dating here, and T6 in
        # the pre-write check reads the same list through ``commits.release_tags``; asked once.
        commits = nested.Commits(client)
        all_tags = dict(commits.tags(action))
        if resolver.is_sha(ref):
            sha, tag = ref, ref
        else:
            resolved = resolver.resolve(client, action, ref)
            sha = resolved.sha
            tag = ref if resolved.is_tag else sha  # a branch gives no version: recorded as a bare SHA
            if resolved.is_tag:
                all_tags[ref] = sha  # what the tag names now, whatever the list said
        activity = clock.on_branch(client, action, sha)
        verification = resolver.verify(client, repo, sha, all_tags, activity)
        if not verification.verified:
            collector.findings.append(
                make_finding(
                    Rule.IMPOSTOR_COMMIT, GHA, place=root, item=action, version=sha, site="pin.impostor-commit"
                )
            )
            _say(
                err,
                [
                    f"ssc-guardian: impostor commit suspected: {strip_controls(action)}@{strip_controls(sha)} is "
                    f"not named by a tag of {strip_controls(repo.name)}, not shown on its branches by the activity "
                    f"log, and not in the history of {strip_controls(repo.default_branch)}. It may come from a "
                    "fork. Nothing written."
                ],
            )
            return None
        if not verification.pushed:
            collector.findings.append(clock.unpushed(root, action, sha))
            _say(
                err,
                [
                    f"Warning: {strip_controls(action)}@{strip_controls(sha)} was never seen on a branch of "
                    f"{strip_controls(repo.name)}."
                ],
            )
        if tag != sha:
            _moved(root, action, tag, sha, entries, collector, err)

        key = resolver.commit_key(action, sha)
        entry = next((e for e in entries if e.key == key), None)
        new = entry is None
        if entry is None:
            release = clock.immutable_release(client, action, sha, all_tags)
            age = clock.recorded_age(activity, release, today)
            entry = LockEntry(action, sha, tag, today, age.started, age.source)
        begins = clock.start(entry.trusted_age(), settings.start_date(action, sha))
        cooldown = settings.cooldown_days(GHA, action)
        wait = clock.cooldown_wait(begins, cooldown, today, place=root, action=action, sha=sha, version=ref)

        rewrites: list[Rewrite] = []
        if wait is not None:
            collector.findings.append(wait)
            when = clock.eligible_on(begins, cooldown).isoformat()
            _say(
                err,
                [
                    f"{strip_controls(action)}@{strip_controls(sha)} is inside its {cooldown}-day cooldown (from "
                    f"{begins.started.isoformat()}, {begins.source.value}): eligible on {when}. The workflows stay "
                    f"as they are; run ssc-guardian pin {strip_controls(action)}@{strip_controls(ref)} on or after "
                    "that day."
                ],
            )
        else:
            # A commit already listed keeps its recorded tag, so the comment and the lock file agree.
            rewrites = [r for s in sources if (r := rewrite(s, action, sha, entry.tag)) is not None]
        rewritten = {r.source.path: r.references for r in rewrites}
        used = used_commits(r for s in sources for r in rewritten.get(s.path, s.references))
        used_before = used_commits(r for s in sources for r in s.references)

        def still_waiting(listed: LockEntry) -> bool:
            listed_start = clock.start(listed.trusted_age(), settings.start_date(listed.action, listed.sha))
            return today < clock.eligible_on(listed_start, settings.cooldown_days(GHA, listed.action))

        kept = prune([*entries, entry] if new else entries, used, key, used_before, still_waiting)
        lock_changed = kept != canonical(entries)
        # The deny list, T3 and T6 run before "nothing to write" is decided (#227): a commit
        # already pinned and recorded is still checked, so pin never says 0 for one they refuse.
        planned = advisories.Pin(root, action, sha, () if entry.tag == sha else (entry.tag,))
        if _refused(planned, today, settings, overrides, entries, commits, collector, err):
            return None
        if not lock_changed and not rewrites:
            current = "." if wait is not None else " and every workflow pin is current."
            recorded = f"{strip_controls(action)}@{strip_controls(sha)} is recorded in {strip_controls(lock)}"
            _say(err, [f"Nothing to write: {recorded}{current}"])
            return None

        # Each value is stripped as it goes in (contracts §5), so none can add a line (#147).
        shown_action, shown_sha, shown_tag, shown_lock = (strip_controls(v) for v in (action, sha, tag, lock))
        lines = [f"Guardian will pin {shown_action} to {shown_sha}" + ("" if tag == sha else f" ({shown_tag})") + ":"]
        if new:
            lines.append(
                f"  {shown_lock}: add {shown_action}@{shown_sha} (tag {shown_tag}; cooldown starts "
                f"{entry.trusted.isoformat()}, {entry.trusted_source.value})"
            )
        lines += [
            f"  {shown_lock}: remove {strip_controls(e.action)}@{strip_controls(e.sha)} (tag {strip_controls(e.tag)}): "
            "no workflow uses it"
            for e in canonical(entries)
            if e not in kept
        ]
        for r in rewrites:
            lines += r.lines
        if wait is None and not rewrites:
            # No rewrite either because every reference to the Action already names this commit
            # (a pin recorded by hand, #211) or because none refers to it at all.
            if key in used:
                lines.append(
                    f"  Every workflow in {strip_controls(root)} that uses {shown_action} already pins "
                    f"{shown_sha}; only the lock file changes."
                )
            else:
                lines.append(
                    f"  No workflow in {strip_controls(root)} uses {shown_action}; only the lock file changes."
                )
        plan = InstallPlan(root, (Item(GHA, action, sha, root),), also_writes=(lock,))
        return _Change(
            plan, lock, lock_read, dump_lock(kept) if lock_changed else None, tuple(rewrites), tuple(lines), sources
        )


def _moved(
    root: str, action: str, tag: str, sha: str, entries: Iterable[LockEntry], collector: Collector, err: TextIO
) -> None:
    """``moved-release-tag`` (#201): the release tag being pinned, which names ``sha`` today, is
    recorded in the lock file under another commit of the same repository. One warning per
    recorded Action commit (lock entry), before the cooldown message; it reads only the lock file and the tag
    already resolved, sends no request, writes nothing and never changes the exit code."""
    from ssc_guardian.commands import check_repo  # imported here: check_repo imports this module

    if not check_repo.is_release_tag(tag):
        return
    repository = repository_key(resolver.repository_of(action))
    moved: dict[tuple[str, str], LockEntry] = {}
    for e in entries:
        if e.tag == tag and e.sha != sha and repository_key(resolver.repository_of(e.action)) == repository:
            moved.setdefault(e.key, e)
    for e in moved.values():
        collector.findings.append(check_repo.moved_release_tag(root, e.action, e.sha, tag, sha))
        _say(err, [f"Warning: {strip_controls(check_repo.moved_note(e.action, tag, e.sha, sha))}."])


def _refused(
    planned: advisories.Pin,
    today: date,
    settings: Settings,
    overrides: tuple[Override, ...],
    entries: tuple[LockEntry, ...],
    commits: nested.Commits,
    collector: Collector,
    err: TextIO,
) -> bool:
    """The deny list, T3 and T6 on the commit about to be written, as ``check --repo`` runs them
    (#126): True when a violation is left after the overrides, so nothing is written (exit 1).
    T6 asks under every publisher tag naming the commit and the tag about to be written (#142),
    from the tags list ``commits`` already holds. A failed request raises (exit 2, nothing
    written) after what was found is reported, so it is never a pass."""
    from ssc_guardian.commands import check_repo  # imported here: check_repo imports this module

    run = check_repo.Run(planned.place, today, settings, entries, [])
    found = check_repo.evaluate(run, [planned], commits, overrides)
    collector.findings += found
    collector.overrides_applied += run.applied
    collector.overrides_expired += run.expired
    _say(err, [strip_controls(note) for note in run.notes])  # one line each, whatever a value in it holds
    if run.failure is not None:
        raise run.failure
    if not any(f.level is Level.VIOLATION for f in found):
        return False
    refused = f"{strip_controls(planned.action)}@{strip_controls(planned.version)}"
    _say(err, [f"ssc-guardian: {refused} breaks a rule check --repo applies; nothing written."])
    return True


def _apply(change: _Change, collector: Collector, err: TextIO) -> None:
    """Write the lock file, then each workflow, after checking that none changed since it was
    read. Every file is written atomically and read back; a failure names what was written."""
    root = change.plan.target
    if read_text(change.lock) != change.lock_read or any(read_text(s.path) != s.text for s in change.sources):
        _say(err, ["ssc-guardian: a file changed while you read the change; run pin again. Nothing written."])
        collector.skipped.append(
            Skip(
                GHA,
                root,
                SkipReason.CHECK_ERROR,
                detail="changed while confirming",
                site="pin.changed-while-confirming",
            )
        )
        return
    writes = [(change.lock, change.lock_text)] if change.lock_text is not None else []
    writes += [(r.source.path, r.text) for r in change.rewrites]
    # D16: only the lock file named in also_writes, and files inside the target. Every file is
    # checked before the first write, so a refusal leaves everything as it was. Reading refuses a
    # file outside the repository first (pin.symlink-lies-outside-repository-pin); this is the
    # backstop behind it (#151).
    outside = [path for path, _ in writes if path not in change.plan.also_writes and not _inside(root, path)]
    if outside:
        _say(err, [f"ssc-guardian: {strip_controls(outside[0])} is not part of the pin's plan (D16); nothing written."])
        collector.skipped.append(
            Skip(GHA, root, SkipReason.CHECK_ERROR, detail="not part of the plan", site="pin.write-outside-plan")
        )
        return
    written: list[str] = []
    for path, text in writes:
        try:
            atomic_write(path, text)
            if read_text(path) != text:
                raise OSError("did not read back as written")
        except Exception as exc:  # report what was written; the run is unfinished (exit 2)
            done = ", ".join(strip_controls(w) for w in written) or "nothing"
            _say(err, [f"ssc-guardian: {strip_controls(path)}: {strip_controls(exc)}; written so far: {done}."])
            collector.skipped.append(
                Skip(
                    GHA,
                    root,
                    SkipReason.CHECK_ERROR,
                    detail=f"not written ({type(exc).__name__})",
                    site="pin.not-written",
                )
            )
            return
        written.append(path)
    _say(err, [f"Written: {strip_controls(path)}" for path in written])


def _say(err: TextIO | None, lines: list[str]) -> None:
    """Write each message's own lines through ``cli._say``. Every value in a message was stripped
    of line breaks and controls as it went in (#147), so no value adds a line; each line is
    stripped again there. A closed, broken or missing stderr never changes the exit code, even
    after a completed write (contracts §3, #227)."""
    from ssc_guardian import cli  # imported here: cli imports this handler

    for line in lines:
        for part in line.splitlines() or [""]:
            cli._say(err, part)


handle = Pin()
