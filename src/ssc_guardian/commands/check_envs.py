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

"""``ssc-guardian check``: the Python environments (``check --envs``, plan §3.1, N10).

Reads every environment's package records on disk and never runs a found program. For each
environment it applies the protection rule (the installer's own cooldown, verified against
the settings: missing, weaker, stale or overridden is ``unprotected``, exit 1, fix
``protect``), and what beats that cooldown which ``protect`` cannot fix: an index other than
PyPI's in a file pip or uv reads or an exported variable, and a project's uv file around a
venv (owner rulings, plan §10.4: ``unprotected`` naming the place, no ``protect`` option);
for each package folder the cooldown, compromise, known-vulnerability and deny
rules, naming the best replacement or the date one becomes eligible (``policy.py``). Only the
workstation files are read (§10.1): ``config.toml`` and ``overrides.toml``, whose overrides
are re-checked against today's facts. Why each installation is unprotected, why an override
was not applied, and why a local-install claim was refused, goes to stderr, never into JSON.

What is read is decided only by the arguments (owner's rulings of 2026-11-13, #255): the
Python environments at or under each ``--path`` (``discovery.survey``), and uv's user config
only when a ``--path`` names it or a folder above it. A ``--path`` that does not exist, cannot
be read or holds nothing checked is an unfinished check there (exit 2), never a pass.

The GitHub Actions area is :mod:`.check_repo`: ``--repo DIR`` checks DIR; ``check --path P``
without ``--envs`` checks the workflows under P in the repository the current folder is in
(plan §2.1). Outside a repository that area is an unfinished check (exit 2), never a pass;
``--envs`` leaves it out. No setting changes what is checked.
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, TextIO

from ssc_guardian import discovery, pep440, policy
from ssc_guardian.commands import check_repo
from ssc_guardian.direct_url import DIRECT_URL, LocalInstall
from ssc_guardian.discovery import Roots
from ssc_guardian.feeds import merge
from ssc_guardian.feeds.kev import Kev, KevStatus
from ssc_guardian.findings import (
    Collector,
    Ecosystem,
    Finding,
    FindingField,
    IncompleteCheckError,
    Installer,
    Option,
    OptionKind,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    make_finding,
    malformed,
    protect_command,
)
from ssc_guardian.grammars import Field, MalformedValueError, matches, normalize_pypi_name
from ssc_guardian.net import Client, TokenError, find_token
from ssc_guardian.overrides import (
    Facts,
    Override,
    aliases_of,
    file_kind,
    load_overrides,
    overrides_path,
    release,
    utc_today,
)
from ssc_guardian.plugins import pip, uv
from ssc_guardian.settings import (
    ConfigFileError,
    Key,
    Settings,
    find_repository_root,
    workstation_settings,
)

if TYPE_CHECKING:
    from ssc_guardian.cli import Request

PYPI = Ecosystem.PYPI
GHA = Ecosystem.GITHUB_ACTIONS
_ADVISORY_RULES = frozenset({Rule.KNOWN_VULNERABILITY, Rule.COMPROMISE})
_KEV_FACT = {KevStatus.LISTED: True, KevStatus.NOT_LISTED: False, KevStatus.UNAVAILABLE: None}


def protect_option(installer: Installer, place: str) -> Option:
    """``protect`` for exactly the reported place: ``protect [pip|uv] --path PLACE`` (#255)."""
    return Option(OptionKind.PROTECT, command=protect_command(place, installer))


_NOT_BY_PROTECT = frozenset({pip.Verdict.OLD_PIP, pip.Verdict.OVERRIDDEN, pip.Verdict.OTHER_INDEX})
_REMOVE_INDEX = "the cooldown does not hold for its files; remove it, then run check again"


def unprotected(place: str, verdict: pip.Verdict, installer: Installer, *, writable: bool = True) -> Finding:
    """The ``unprotected`` violation. Its fix is ``protect`` only where running it fixes it: not
    for a pip that ignores the setting (upgrade pip, or below Python 3.10 recreate the venv or
    use a newer Python, or leave the installation out of the paths named), an override
    from outside the file (remove it), or a file Guardian cannot write (an administrator)."""
    fixable = writable and verdict not in _NOT_BY_PROTECT
    options = (protect_option(installer, place),) if fixable else ()
    return make_finding(Rule.UNPROTECTED, PYPI, place=place, options=options, site="check_envs.unprotected")


def writable(env: discovery.Environment, access: Callable[[str], pip.Access] = pip.access) -> pip.Access:
    """Whether Guardian may write ``env``'s ``pip.conf``. Apple's Python lives in a signed bundle
    (Xcode or the Command Line Tools), which only an administrator changes, whoever owns it."""
    return pip.Access.ADMINISTRATOR if env.source is discovery.Source.APPLE else access(env.pip_conf)


def hidden_pips(assessment: pip.Assessment) -> list[Finding]:
    return [
        make_finding(Rule.HIDDEN_PIP, PYPI, place=hidden.folder, item="pip", version=hidden.version)
        for hidden in assessment.hidden
    ]


def cooldown_of(settings: Settings) -> tuple[int, int]:
    """The default cooldown and the fixed-date tolerance it gives (plan §3.1)."""
    cooldown = int(settings.value(Key.COOLDOWN_DAYS) or 0)
    setting = settings.value(Key.FIXED_DATE_TOLERANCE_DAYS)
    return cooldown, pip.tolerance_days(cooldown, int(setting) if setting is not None else None)


@dataclass(frozen=True)
class CheckEnvs:
    """The ``check`` handler, with its places, clock, network client and stderr injectable."""

    home: str | None = None
    environ: Mapping[str, str] | None = None
    root: str = "/"
    today: date | None = None
    client: Client | None = None
    stderr: TextIO | None = None
    access: Callable[[str], pip.Access] = pip.access
    cwd: str | None = None
    host: policy.Host | None = None

    def __call__(self, request: Request) -> Result:
        collector = Collector(Verb.CHECK)
        scope = request.scope
        if scope is None:
            raise ValueError("check needs a scope")
        notes: list[str] = []
        root: str | None = None
        if GHA in scope.ecosystems:
            root = scope.repo or find_repository_root(self.cwd or os.getcwd())
        held: list[str] = []
        if PYPI in scope.ecosystems:
            held = self._envs(scope.paths, collector, notes, alone=GHA not in scope.ecosystems)
        if GHA in scope.ecosystems:
            self._repository(root, scope.paths, collector, notes)
        # A held-back place the Actions side did not report gets the handler's own reason (#284).
        collector.skipped += [_no_environment(place) for place in held if not _reported(GHA, place, collector)]
        # Each distinct line once (#284): one stop, such as GitHub's rate limit, ends many requests.
        _say(self.stderr or sys.stderr, [f"ssc-guardian: {note}" for note in dict.fromkeys(notes)])
        return collector.result()

    def roots(self) -> Roots:
        environ = self.environ if self.environ is not None else os.environ
        return Roots(self.home if self.home is not None else os.path.expanduser("~"), environ, self.root)

    def _repository(self, root: str | None, paths: tuple[str, ...], collector: Collector, notes: list[str]) -> None:
        """The GitHub Actions area: ``--repo``'s folder, else the repository holding the
        current folder. Outside one it is an unfinished check (exit 2), so a run that asks for
        Actions, by naming no ecosystem or by ``--ecosystem github-actions``, never passes
        without them (#255)."""
        if root is None:
            why = "not inside a Git repository"
            skip = Skip(GHA, None, SkipReason.CHECK_ERROR, detail=why, site="check_envs.no-repository")
            collector.skipped.append(skip)
            notes.append(f"GitHub Actions: {why}; run check inside one, check --repo DIR, or add --envs")
            return
        roots = self.roots()
        check_repo.CheckRepo(roots.home, roots.environ, self.today, self.client).run(root, paths, collector, notes)

    def _envs(self, paths: tuple[str, ...], collector: Collector, notes: list[str], *, alone: bool = True) -> list[str]:
        """The Python environments at or under ``paths``. ``alone``: no other area is checked, so a
        named path where no environment is found is unfinished here. With GitHub Actions in scope
        too, that area may report it, so those places are returned instead, held back for the
        caller to report once that area has run (#284); ``cli._with_coverage`` stays the backstop."""
        roots = self.roots()
        today = self.today or utc_today()
        try:
            settings = workstation_settings(roots.home)
        except ConfigFileError as exc:
            collector.skipped.append(exc.skip(PYPI))  # nothing in the file applies, no defaults either
            notes.append(str(exc))
            return []
        overrides = load_workstation_overrides(roots, today, collector, notes)  # on every run (§10.1)
        cooldown, tolerance = cooldown_of(settings)
        found = discovery.survey(roots, paths)  # only what the paths name (#255)
        collector.findings += [malformed(FindingField.PLACE, raw, ecosystem=PYPI) for raw in found.malformed]
        collector.skipped += found.skipped
        # uv's user config is read only when a --path names it or a folder above it.
        uv_paths = discovery.holding(paths, uv.config_path(roots))
        read_uv_config = bool(uv_paths) and uv.installed(roots)
        escaped = discovery.resolves_outside(paths, uv.config_path(roots)) if read_uv_config else None
        if escaped is not None:  # a link out of the named paths: never read (#255)
            read_uv_config = False
            collector.skipped.append(
                Skip(
                    PYPI,
                    uv.config_path(roots),
                    SkipReason.CHECK_ERROR,
                    detail=f"resolves outside the named paths, to {escaped}",
                    site="check_envs.uv-config-outside",
                )
            )
            why = "outside the named paths; name that file with --path"
            notes.append(f"{uv.config_path(roots)} leads to {escaped}, {why}")
        # A named path that holds nothing checked is unfinished at that place, never a pass.
        empty = [
            place
            for place in found.empty
            if not ((read_uv_config or escaped is not None) and place in uv_paths)  # uv's file reports it
        ]
        held = [] if alone else empty
        collector.skipped += [_no_environment(place) for place in empty] if alone else []

        sources = pip.Sources.of(roots)
        for env in found.environments:
            with collector.check(PYPI, env.prefix) as ok:
                if not ok:
                    continue
                assessment: pip.Assessment | None = None
                read: list[str] = []  # what the index reading found before any failure
                try:  # a pip reads its index settings; no pip, nothing to read them
                    assessment = pip.assess(
                        env, cooldown_days=cooldown, tolerance=tolerance, today=today, sources=sources
                    )
                    collector.findings += hidden_pips(assessment)
                    others = pip.other_indexes(env.pip_conf, sources, read) if assessment.pip is not None else []
                except Exception as exc:  # unfinished (exit 2); what is known still counts
                    if assessment is None and _has_pip(env, None):  # the index reading never ran
                        with suppress(Exception):  # keeps what it finds; exc is raised below
                            pip.other_indexes(env.pip_conf, sources, read)
                    variables = pip.index_variables(sources) if _has_pip(env, assessment) else []
                    self._pip_finding(env, assessment, list(dict.fromkeys(read + variables)), collector, notes)
                    notes += [str(exc)] if isinstance(exc, ConfigFileError) else []
                    raise
                self._pip_finding(env, assessment, others, collector, notes)
        if read_uv_config:
            place = uv.config_path(roots)
            with collector.check(PYPI, place) as ok:
                if ok:
                    state: uv.UvAssessment | None = None
                    read_uv: list[str] = []  # what the index reading found before any failure
                    try:  # assess stops at the first override, maybe before it reads the system file
                        state = uv.assess(roots, cooldown_days=cooldown, tolerance=tolerance, today=today)
                        others = uv.other_indexes(roots, read_uv)
                    except Exception as exc:  # unfinished (exit 2); what is known still counts
                        if state is None:  # the index reading never ran
                            with suppress(Exception):  # keeps what it finds; exc is raised below
                                uv.other_indexes(roots, read_uv)
                        known = list(dict.fromkeys(read_uv + uv.index_variables(roots)))
                        self._uv_finding(place, state, known, collector, notes)
                        notes += [str(exc)] if isinstance(exc, ConfigFileError) else []
                        raise
                    self._uv_finding(place, state, others, collector, notes)
        if uv.installed(roots):
            self._uv_projects(roots, found.environments, cooldown, today, collector, notes)

        self._packages(found.environments, settings, today, collector, notes, roots, overrides)
        collector.findings += settings.notices()
        return held

    def _pip_finding(
        self,
        env: discovery.Environment,
        assessment: pip.Assessment | None,
        others: list[str],
        collector: Collector,
        notes: list[str],
    ) -> None:
        """One ``unprotected`` finding for ``env``'s pip, whatever the reasons: a weak cooldown,
        an index other than PyPI's, or both. ``protect`` is its fix only when it fixes every
        reason, so never when an index is among them. ``assessment`` is None when the
        cooldown could not be judged: then only an index variable gives the finding."""
        weak = assessment is not None and not assessment.protected
        if not weak and not others:
            return
        verdict = pip.Verdict.OTHER_INDEX if others or assessment is None else assessment.verdict
        can_write = writable(env, self.access) is pip.Access.WRITABLE
        collector.findings.append(unprotected(env.prefix, verdict, Installer.PIP, writable=can_write))
        notes += [f"{env.prefix}: {assessment.why}"] if assessment is not None and weak else []
        notes += [f"{env.prefix}: pip is given an index other than PyPI's: {o}; {_REMOVE_INDEX}" for o in others]

    @staticmethod
    def _uv_finding(
        place: str, state: uv.UvAssessment | None, others: list[str], collector: Collector, notes: list[str]
    ) -> None:
        """One ``unprotected`` finding for the per-user uv file, as for pip: ``protect`` is its
        fix only when there is no index other than PyPI's among the reasons. ``state`` is None
        when the file could not be judged: then only an index variable gives the finding."""
        weak = state is not None and not state.protected
        if not weak and not others:
            return
        verdict = pip.Verdict.OTHER_INDEX if others or state is None else state.verdict
        collector.findings.append(unprotected(place, verdict, Installer.UV))
        notes += [state.why] if state is not None and weak else []
        notes += [f"uv is given an index other than PyPI's: {o}; {_REMOVE_INDEX}" for o in others]

    @staticmethod
    def _uv_projects(
        roots: Roots,
        environments: list[discovery.Environment],
        cooldown: int,
        today: date,
        collector: Collector,
        notes: list[str],
    ) -> None:
        """For each venv, the project configuration uv may use in the venv's folder
        (``uv.find_projects``), which beats the per-user window: a weaker window, an exemption
        or an index other than PyPI's is ``unprotected`` for uv at that file (exit 1). Its fix
        is to edit the project's file, never ``protect``, which writes only the per-user one. A
        file that cannot be read or parsed is an in-scope ``check-error`` naming it (exit 2).
        Each file is judged once, however many venvs it governs; nothing is written. A broken
        ``pyproject.toml`` is a ``check-error`` naming it and the search goes on; a broken
        ``uv.toml`` stops the search, as it stops uv: a ``check-error`` naming it, or, for any
        other failure (``tomllib`` recursing on a deeply nested ``uv.toml``), naming the venv's
        folder. Projects found before a failure are still judged, and the run goes on: a cloned
        repository's file never ends it."""
        # Judged as the user's own files; resolved, like the paths find_projects returns.
        own = {os.path.realpath(p) for p in (uv.config_path(roots), *uv.system_paths(roots))}
        seen: set[str] = set()
        for env in environments:
            if not env.is_venv:
                continue
            folder = os.path.dirname(env.prefix)
            failed: list[ConfigFileError] = []  # pyproject.toml files uv passes over with a warning
            projects: list[uv.Project] = []
            try:
                uv.find_projects(folder, roots, failed, projects)  # what it found before a failure is kept
            except ConfigFileError as exc:  # a uv.toml that stops the search, as it stops uv
                failed.append(exc)
            except Exception as exc:
                if folder not in seen:
                    seen.add(folder)
                    why = type(exc).__name__
                    where = folder if matches(Field.PATH, folder) else None
                    skip = Skip(
                        PYPI, where, SkipReason.CHECK_ERROR, detail=why, site="check_envs.project-search-failed"
                    )
                    collector.skipped.append(skip)
                    notes.append(f"{folder}: the search for uv's project file failed ({why})")
            for error in failed:  # each an unfinished check; a file further up is still judged
                if (error.place or folder) not in seen:
                    seen.add(error.place or folder)
                    collector.skipped.append(error.skip(PYPI))
                    notes.append(str(error))
            for project in projects:
                if project.place not in seen and os.path.realpath(project.place) not in own:
                    seen.add(project.place)
                    _judge_project(project, cooldown, today, collector, notes)

    def _packages(
        self,
        environments: list[discovery.Environment],
        settings: Settings,
        today: date,
        collector: Collector,
        notes: list[str],
        roots: Roots,
        overrides: tuple[Override, ...],
    ) -> None:
        # Each folder once, however many environments see it (a per-user folder is shared).
        folders: dict[str, discovery.Environment | None] = {}
        for env in environments:
            for folder in env.search_order:
                folders[folder] = folders.get(folder) or (env if env.is_venv and folder == env.main_site else None)
        outside = {discovery.real_place(place) or place for place in (*(e.prefix for e in environments), *folders)}
        listed = {folder: discovery.packages(folder) for folder in folders}
        names = sorted({p.name for records, _ in listed.values() for p in records})
        if not names:
            for folder, (_, problems) in listed.items():
                with collector.check(PYPI, folder) as ok:
                    if not ok:
                        continue
                    _raise_problems(problems, notes)
            return
        kev: Kev | None = None
        gathered: policy.PypiFacts | None = None
        failure: IncompleteCheckError | None = None
        try:
            client = self.client or Client(find_token(roots.environ))
        except TokenError as exc:  # names the variable, never its value; the deny list still runs
            failure = IncompleteCheckError(SkipReason.CHECK_ERROR, site="check_envs.packages-check-error")
            collector.skipped.append(
                Skip(PYPI, None, SkipReason.CHECK_ERROR, detail=str(exc), site="check_envs.no-token")
            )
            notes.append(str(exc))
        else:
            kev = Kev(client)
            try:
                gathered = policy.gather_pypi(client, names)
            except IncompleteCheckError as exc:
                failure = exc
                notes.append(f"the feeds could not be read: {exc}")
        block_on = policy.BlockOn(settings.block_on.value)
        host = self.host or policy.Host.current()
        for folder, (records, problems) in listed.items():
            with collector.check(PYPI, folder) as ok:
                if not ok:
                    continue
                collector.findings += [
                    make_finding(
                        Rule.DENY_LIST,
                        PYPI,
                        place=folder,
                        item=p.name,
                        version=p.version,
                        options=(Option(OptionKind.REMOVE),),
                        site="check_envs.denied-installed",
                    )
                    for p in _one_spelling(records)
                    if matches(Field.PYPI_NAME, p.name) and settings.denied(PYPI, p.name)
                ]
                local = _local_installs(records, folder, outside, notes)  # its notes, even if the feeds failed
                if gathered is None or kev is None:
                    raise failure or IncompleteCheckError(
                        SkipReason.FEED_FAILURE, site="check_envs.packages-feed-failure"
                    )
                owner = folders[folder]
                venv, target = (owner.prefix, policy.Target(owner.python, host)) if owner else (None, None)
                self._evaluate(
                    gathered, kev, records, folder, venv, target, settings, today, block_on, collector, local
                )
                _raise_problems(problems, notes)
        self._apply_overrides(gathered, kev, today, collector, notes, roots, overrides=overrides)

    @staticmethod
    def _evaluate(
        gathered: policy.PypiFacts,
        kev: Kev,
        records: list[discovery.Package],
        folder: str,
        venv: str | None,
        target: policy.Target | None,
        settings: Settings,
        today: date,
        block_on: policy.BlockOn,
        collector: Collector,
        local: Mapping[tuple[str, str], LocalInstall],
    ) -> None:
        """The feed rules for one folder, grouped by each package's own cooldown; every group
        is evaluated before the first failure is raised."""
        groups: dict[int, list[tuple[str, str]]] = defaultdict(list)
        default = int(settings.value(Key.COOLDOWN_DAYS) or 0)
        for p in records:
            days = settings.cooldown_days(PYPI, p.name) if matches(Field.PYPI_NAME, p.name) else default
            groups[days].append((p.name, p.version))
        failure: IncompleteCheckError | None = None
        installed = _installed_files(records)
        for days, packages in sorted(groups.items()):
            rules = policy.Rules(cooldown_days=days, today=today, block_on=block_on)
            try:
                policy.evaluate_packages(
                    gathered,
                    kev,
                    packages,
                    place=folder,
                    venv=venv,
                    rules=rules,
                    into=collector.findings,
                    target=target,
                    local=local,
                    skips=collector.skipped,
                    installed=installed,
                )
            except IncompleteCheckError as exc:
                failure = failure or exc
        if failure is not None:
            raise failure

    def _apply_overrides(
        self,
        gathered: policy.PypiFacts | None,
        kev: Kev | None,
        today: date,
        collector: Collector,
        notes: list[str],
        roots: Roots,
        *,
        overrides: tuple[Override, ...] | None = None,
    ) -> None:
        """Release each advisory finding every one of whose advisories has an override that
        applies today, naming it by any of its IDs (§10.4); a fact that cannot be established
        means not applied. ``overrides`` already loaded (and any problem reported), or None to
        load the file here."""
        if overrides is None:
            overrides = load_workstation_overrides(roots, today, collector, notes)
        if not overrides:
            return
        kept: list[Finding] = []
        for finding in collector.findings:
            if finding.rule not in _ADVISORY_RULES:
                kept.append(finding)
                continue
            groups = _alias_groups(finding, gathered)
            facts = {ref: self._facts(finding, aliases_of(ref, groups), gathered, kev) for ref in finding.evidence}
            outcome = release(finding, overrides, today=today, facts=facts, groups=groups)
            collector.overrides_applied += [r for r in outcome.applied if r not in collector.overrides_applied]
            collector.overrides_expired += [r for r in outcome.expired if r not in collector.overrides_expired]
            notes += [f"override {d.override.id} not applied: {d.why}" for d in outcome.not_applied]
            if not outcome.released:
                kept.append(finding)
        collector.findings[:] = kept

    @staticmethod
    def _facts(finding: Finding, aliases: frozenset[str], gathered: policy.PypiFacts | None, kev: Kev | None) -> Facts:
        """Today's facts for one reference: KEV status over its advisory's IDs (``aliases``), and
        whether a fixed version passes every rule and installs (a replacement Guardian can
        install now). Unknown stays None: so does a fix that may install on a Mac of unknown
        version (``gathered.unknown_fixes``, #253)."""
        fix: bool | None = None
        if any(o.kind is OptionKind.REPLACE and o.command is not None for o in finding.options):
            fix = True
        elif gathered is not None and finding.id in gathered.unknown_fixes:
            fix = None  # the replacement search could not tell whether that fix installs
        elif gathered is not None and finding.item and normalize_pypi_name(finding.item) in gathered.projects:
            fix = False  # the replacement search finished and found nothing installable now
        status = kev.status(aliases) if kev is not None else KevStatus.UNAVAILABLE
        return Facts(kev_listed=_KEV_FACT[status], fix_passes=fix)


def _judge_project(project: uv.Project, cooldown: int, today: date, collector: Collector, notes: list[str]) -> None:
    """One project file: ``unprotected`` for uv at it, with no ``protect`` option, when it
    leaves uv unprotected; listed as checked otherwise."""
    with collector.check(PYPI, project.place) as ok:
        if not ok:
            return
        problems = uv.project_problems(project, cooldown_days=cooldown, today=today)
        if problems:
            collector.findings.append(unprotected(project.place, pip.Verdict.OVERRIDDEN, Installer.UV, writable=False))
            folder = os.path.dirname(project.place)
            notes += [
                f"{p}; uv prefers it to the user file in {folder}: change or remove it, then run check again"
                for p in problems
            ]


def _no_environment(place: str) -> Skip:
    """A named path that holds nothing checked: unfinished at that place, never a pass."""
    return Skip(PYPI, place, SkipReason.CHECK_ERROR, detail=discovery.NO_ENVIRONMENT, site="check_envs.empty-path")


def _reported(ecosystem: Ecosystem, place: str, collector: Collector) -> bool:
    """Whether ``ecosystem`` reported ``place``: a ``Checked`` entry or an in-scope skip at that
    place or inside it, as ``cli._with_coverage`` counts a report."""
    places = [c.place for c in collector.checked if c.ecosystem is ecosystem]
    places += [s.place for s in collector.skipped if s.ecosystem is ecosystem and s.in_scope]
    return any(p is not None and os.path.commonpath([p, place]) == place for p in places)


def _has_pip(env: discovery.Environment, assessment: pip.Assessment | None) -> bool:
    """Whether ``env`` has a pip to read the index settings; one whose records cannot be read
    is taken as present, never as absent."""
    if assessment is not None:
        return assessment.pip is not None
    try:
        return bool(pip.all_pips(env))
    except Exception:
        return True


def load_workstation_overrides(
    roots: Roots, today: date, collector: Collector, notes: list[str]
) -> tuple[Override, ...]:
    """The workstation's PyPI overrides. A file that cannot be used is an in-scope
    ``check-error`` naming it (§10.1), and releases nothing; the run goes on."""
    path = overrides_path(file_kind(PYPI), home=roots.home)
    try:
        return load_overrides(path, kind=file_kind(PYPI), today=today)
    except ConfigFileError as exc:
        collector.skipped.append(exc.skip(PYPI))  # releases nothing; findings still count
        notes.append(str(exc))
        return ()


def _alias_groups(finding: Finding, gathered: policy.PypiFacts | None) -> tuple[tuple[str, ...], ...]:
    """The IDs of each advisory the feeds named for the finding's package, one group per
    advisory, so an override names its advisory by any of them (§10.4). An advisory with none
    Guardian may show is a malformed-name finding of its own (D4) and gives no group."""
    if gathered is None or finding.item is None:
        return ()
    name = normalize_pypi_name(finding.item)
    groups: list[tuple[str, ...]] = []
    for advisory in merge(gathered.osv.get(name, ()), gathered.github_malware.get(name, ())):
        try:
            groups.append(advisory.evidence())
        except MalformedValueError:
            continue
    return tuple(groups)


def _one_spelling(records: list[discovery.Package]) -> list[discovery.Package]:
    """Two spellings of one package version are one package: the first is kept (D18, §3)."""
    kept: dict[tuple[str, str], discovery.Package] = {}
    for p in records:
        version = pep440.try_parse(p.version)
        kept.setdefault((p.key, pep440.canonical_of(version) if version else p.version), p)
    return list(kept.values())


def _installed_files(records: list[discovery.Package]) -> dict[tuple[str, str], policy.Installed]:
    """What each record says of its installed file, by normalized name and canonical version, so
    each package is dated by that file (#230). Two records of one version that disagree claim
    nothing: the package is then dated as one whose file Guardian cannot name."""
    installed: dict[tuple[str, str], policy.Installed] = {}
    for p in records:
        version = pep440.try_parse(p.version)
        if version is None:
            continue
        key = (p.key, pep440.canonical_of(version))
        seen = installed.setdefault(key, policy.Installed(p.tags))
        if seen.tags != p.tags:
            installed[key] = policy.Installed()
    return installed


def _local_installs(
    records: list[discovery.Package], folder: str, outside: set[str], notes: list[str]
) -> dict[tuple[str, str], LocalInstall]:
    """The verified local installs among ``records``, by normalized name and canonical version,
    the first verified claim of a version's two spellings kept. A refused claim changes nothing
    and adds one note. A record that fails a grammar is a malformed-name violation of its own,
    so its claim is not read."""
    local: dict[tuple[str, str], LocalInstall] = {}
    for p in records:
        version = pep440.try_parse(p.version)
        if version is None or not matches(Field.PYPI_NAME, p.name):
            continue
        try:
            claim = discovery.local_install(p, outside)
        except discovery.LocalInstallRefusedError as exc:
            notes.append(
                f"{folder}/{p.record}: {DIRECT_URL} claims a local install but {exc}; the upload age is required"
            )
            continue
        if claim is not None:
            local.setdefault((p.key, pep440.canonical_of(version)), claim)
    return local


def _raise_problems(problems: list[Skip], notes: list[str]) -> None:
    """A folder with an unreadable record is an unfinished check, after its readable records."""
    if problems:
        notes += [f"{p.place}: {p.detail}" for p in problems]
        raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="check_envs.raise-problems-check-error")


def _say(err: TextIO | None, lines: list[str]) -> None:
    """Each line to stderr through ``cli._say``: a closed or broken stream never changes the
    exit code (contracts §3)."""
    from ssc_guardian import cli  # imported here: cli imports this handler

    for line in lines:
        cli._say(err, line)


handle = CheckEnvs()
