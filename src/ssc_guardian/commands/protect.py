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

"""``ssc-guardian protect [pip|uv] --path PATH``: show, confirm, write (plan §3.1, N7, FC-9.3; D15, D16).

The settings' cooldown is the one source of truth. ``protect`` writes only Guardian's own
cooldown, and only at or under the paths its ``--path`` arguments name (owner's rulings of
2026-11-13, #255): ``uploaded-prior-to`` in the ``sys.prefix/pip.conf`` of each installation
found there, in the form that installation's pip accepts, and ``exclude-newer`` in the
per-user uv config when a ``--path`` names it or a folder above it. A named path that does not
exist, cannot be read or holds nothing to protect is an unfinished check there (exit 2). No
per-user pip file is written. A fixed-date refresh never moves the date later than today
minus the cooldown.

Every change is shown first, on stderr, and written only on confirmation (``cli.confirm``);
``--yes`` confirms in advance and still prints the change to stderr as a record. Declined, or
no terminal: nothing written, exit 2 (D15). An installation that cannot be protected by
writing (a pip that ignores the setting, an overriding variable, a ``sys.prefix`` this
user cannot write, such as a root-owned one, or Apple's signed bundle) stays ``unprotected``
(exit 1) with the reason; Guardian never uses ``sudo``.
Each write is atomic and read back; re-running ``protect`` writes nothing.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Protocol, TextIO

from ssc_guardian import discovery
from ssc_guardian.commands.check_envs import cooldown_of, hidden_pips, load_workstation_overrides, unprotected, writable
from ssc_guardian.discovery import Roots
from ssc_guardian.findings import (
    Collector,
    Ecosystem,
    FindingField,
    Installer,
    Level,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    malformed,
)
from ssc_guardian.overrides import utc_today
from ssc_guardian.plugin import CooldownSetting
from ssc_guardian.plugins import pip, uv
from ssc_guardian.render import strip_controls
from ssc_guardian.settings import ConfigFileError, workstation_settings

if TYPE_CHECKING:
    from ssc_guardian.cli import Request

PYPI = Ecosystem.PYPI


class _Writer(Protocol):
    def write_cooldown(self, setting: CooldownSetting) -> None: ...
    def installer_cooldown(self, place: str) -> CooldownSetting: ...


@dataclass(frozen=True)
class _Change:
    place: str  # the environment or the uv config, as checked
    writer: _Writer
    setting: CooldownSetting
    current: str | None

    def line(self) -> str:
        """One line of the change: the place and the value read from its file are stripped as
        they go in (#161, as #147 does), so a continuation line or a TOML ``\\n`` in the value
        cannot add a line to what the owner confirms. What is written is Guardian's own value."""
        new = pip.value_text(self.setting)
        current = strip_controls(self.current) if self.current else "(no setting)"
        return f"  {strip_controls(self.setting.place)}: {current} -> {new}"


@dataclass(frozen=True)
class Protect:
    """The ``protect`` handler, with its places, clock, streams and access check injectable."""

    home: str | None = None
    environ: Mapping[str, str] | None = None
    root: str = "/"
    today: date | None = None
    stdin: TextIO | None = None
    stderr: TextIO | None = None
    access: Callable[[str], pip.Access] = pip.access

    def __call__(self, request: Request) -> Result:
        from ssc_guardian import cli  # imported here: cli imports this handler

        paths = request.paths
        if not paths:  # the command line requires --path; a handler never widens a run without one
            raise ValueError("protect needs a named path")
        err = self.stderr or sys.stderr
        collector = Collector(Verb.PROTECT)
        environ = self.environ if self.environ is not None else os.environ
        roots = Roots(self.home if self.home is not None else os.path.expanduser("~"), environ, self.root)
        today = self.today or utc_today()
        notes: list[str] = []
        try:
            settings = workstation_settings(roots.home)
        except ConfigFileError as exc:
            collector.skipped.append(exc.skip(PYPI))
            _say(err, [f"{strip_controls(exc)}; fix the file by hand. Nothing written."])
            return collector.result()
        load_workstation_overrides(roots, today, collector, notes)  # reported, never read by the write (§10.1)
        cooldown, tolerance = cooldown_of(settings)
        changes: list[_Change] = []
        # uv's user config is written only when a --path names it or a folder above it.
        uv_paths = discovery.holding(paths, uv.config_path(roots))
        with_uv = request.installer is Installer.UV or (
            request.installer is None and bool(uv_paths) and uv.installed(roots)
        )
        if request.installer in (None, Installer.PIP):
            covered = uv_paths if with_uv else []
            changes += self._pip(roots, paths, covered, cooldown, tolerance, today, collector, notes)
        escaped = discovery.resolves_outside(paths, uv.config_path(roots)) if with_uv and uv_paths else None
        if escaped is not None:  # a link out of the named paths: never written through (#255)
            where = uv.config_path(roots)
            collector.skipped.append(
                Skip(
                    PYPI,
                    where,
                    SkipReason.CHECK_ERROR,
                    detail=f"resolves outside the named paths, to {escaped}",
                    site="protect.uv-config-outside",
                )
            )
            why = "outside the named paths; name that file with --path"
            notes.append(f"ssc-guardian: {where} leads to {escaped}, {why}")
        elif with_uv and uv_paths:
            changes += self._uv(roots, cooldown, tolerance, today, collector, notes)
        elif with_uv:  # protect uv names no path that holds the uv user config
            where = uv.config_path(roots)
            collector.skipped += [
                Skip(
                    PYPI,
                    place,
                    SkipReason.CHECK_ERROR,
                    detail=f"uv's user config ({where}) is not at or under this path",
                    site="protect.uv-config-not-named",
                )
                for place in paths
            ]
            notes.append(f"ssc-guardian: uv's user config is {where}; name it, or its folder, with --path")
        # One line each, whatever a value in it holds: a note names files and what they hold (#161).
        notes = [strip_controls(note) for note in notes]
        if not changes:
            _say(err, [*notes, _nothing_to_write(collector)])
            return collector.result()

        lines = ["Guardian will write its cooldown setting (and nothing else):", *(c.line() for c in changes)]
        if any(isinstance(c.writer, uv.UvPlugin) for c in changes):
            lines += ["A project's pyproject.toml takes precedence over the uv file; to protect one, add:"]
            lines += [f"  {line}" for line in uv.project_line(cooldown).splitlines()]
        _say(err, notes)
        change = "\n".join(lines)
        if request.yes:
            _say(err, [change, "Confirmed in advance (--yes)."])  # the record D15 asks for
        stdin = self.stdin or sys.stdin
        if not cli.confirm(change, verb=Verb.PROTECT, yes=request.yes, stdin=stdin, stdout=err):
            _say(err, ["ssc-guardian: not confirmed; nothing written. Add --yes to confirm in advance."])
            collector.skipped.append(
                Skip(
                    PYPI,
                    None,
                    SkipReason.CHECK_ERROR,
                    detail="not confirmed; nothing written",
                    site="protect.not-confirmed",
                )
            )
            return collector.result()
        self._write(changes, collector, err)
        return collector.result()

    def _pip(
        self,
        roots: Roots,
        paths: tuple[str, ...],
        covered: list[str],
        cooldown: int,
        tolerance: int,
        today: date,
        collector: Collector,
        notes: list[str],
    ) -> list[_Change]:
        found = discovery.survey(roots, paths)  # only what the paths name (#255)
        collector.findings += [malformed(FindingField.PLACE, raw, ecosystem=PYPI) for raw in found.malformed]
        collector.skipped += found.skipped
        # As check --envs (#67): a named path with no Python environment is unfinished (exit 2)
        # at that place, never "every installation is protected", unless it names the uv config
        # this run writes (``covered``).
        for place in found.empty:
            if place in covered:
                continue
            collector.skipped.append(
                Skip(PYPI, place, SkipReason.CHECK_ERROR, detail=discovery.NO_ENVIRONMENT, site="protect.empty-path")
            )
            notes.append(f"ssc-guardian: {place}: no Python environment at or under it; pip was not protected there")
        sources = pip.Sources.of(roots)
        changes: list[_Change] = []
        for env in found.environments:
            with collector.check(PYPI, env.prefix) as ok:
                if not ok:
                    continue
                state = pip.assess(env, cooldown_days=cooldown, tolerance=tolerance, today=today, sources=sources)
                collector.findings += hidden_pips(state)
                if state.protected:
                    continue
                access = writable(env, self.access)
                if state.wanted is None or state.verdict is pip.Verdict.OVERRIDDEN:
                    notes.append(f"{env.prefix}: {state.why}")
                elif access is pip.Access.ADMINISTRATOR:
                    notes.append(
                        f"{env.prefix} is owned by root or a signed Apple bundle: an administrator must set "
                        f"'{pip.KEY} = {pip.value_text(state.wanted)}' in [global] and [install] of "
                        f"{env.pip_conf} (Guardian never uses sudo)"
                    )
                elif access is pip.Access.NOT_WRITABLE:
                    notes.append(f"{env.pip_conf} cannot be written by this user")
                elif access is pip.Access.LINKED:
                    notes.append(
                        f"{env.pip_conf} is a symlink to {os.path.realpath(env.pip_conf)}; Guardian writes only an "
                        f"installation's own file: set '{pip.KEY} = {pip.value_text(state.wanted)}' in [global] "
                        "and [install] there by hand, if no other installation shares it"
                    )
                else:
                    changes.append(_Change(env.prefix, pip.PipPlugin(roots), state.wanted, state.current))
                    continue
                collector.findings.append(unprotected(env.prefix, state.verdict, Installer.PIP, writable=False))
        return changes

    def _uv(
        self, roots: Roots, cooldown: int, tolerance: int, today: date, collector: Collector, notes: list[str]
    ) -> list[_Change]:
        place = uv.config_path(roots)
        changes: list[_Change] = []
        with collector.check(PYPI, place) as ok:
            if ok:
                state = uv.assess(roots, cooldown_days=cooldown, tolerance=tolerance, today=today)
                if state.protected:
                    return changes
                if state.verdict is pip.Verdict.OVERRIDDEN:
                    notes.append(state.why)
                    collector.findings.append(unprotected(place, state.verdict, Installer.UV))
                else:
                    changes.append(_Change(place, uv.UvPlugin(), state.wanted, state.current))
        return changes

    @staticmethod
    def _write(changes: list[_Change], collector: Collector, err: TextIO) -> None:
        """Write each change, then read it back; a failure is an unfinished check at its place,
        and the message says what was already written."""
        written: list[str] = []
        for change in changes:
            try:
                change.writer.write_cooldown(change.setting)
                if change.writer.installer_cooldown(change.setting.place) != change.setting:
                    raise ConfigFileError(
                        change.setting.place, "did not read back as written", site="protect.did-not-read-back-written"
                    )
            except Exception as exc:  # each change is its own check; the others still run
                detail = f"not written ({type(exc).__name__})"
                collector.skipped.append(
                    Skip(PYPI, change.place, SkipReason.CHECK_ERROR, detail=detail, site="protect.not-written")
                )
                done = ", ".join(strip_controls(w) for w in written) or "nothing"
                where, why = strip_controls(change.setting.place), strip_controls(exc)
                _say(err, [f"ssc-guardian: {where}: {why}; written so far: {done}."])
                continue
            written.append(change.setting.place)
        _say(err, [f"Written: {strip_controls(place)}" for place in written])


def _nothing_to_write(collector: Collector) -> str:
    """The closing line when nothing is written. "Every installation ... is protected" only when
    the run reported no violation and finished every check: an installation reported
    ``unprotected`` above is never then called protected (#302)."""
    if any(skip.in_scope for skip in collector.skipped):
        return "Nothing to write."
    if not any(f.level is Level.VIOLATION for f in collector.findings):
        return "Nothing to write: every installation Guardian found and can write is protected."
    count = len({f.place for f in collector.findings if f.rule is Rule.UNPROTECTED})
    # The report (stdout, or the JSON) is written after this line: "see the report", not "above".
    if not count:
        return "Nothing to write; see the report."
    what = (
        "installation cannot be protected as it stands"
        if count == 1
        else "installations cannot be protected as they stand"
    )
    return f"Nothing to write: {count} {what}; see the report."


def _say(err: TextIO | None, lines: list[str]) -> None:
    """Each line of each message to stderr through ``cli._say``: a closed or broken stream
    never changes the exit code, even after a completed write (contracts §3)."""
    from ssc_guardian import cli  # imported here: cli imports this handler

    for line in lines:
        for part in line.splitlines() or [""]:
            cli._say(err, part)


handle = Protect()
