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

"""``ssc-guardian acknowledge OWNER/REPO``: a person accepts a young or little-used Action
repository (plan §2.1, §3.2 T3; contracts §10.2).

It refuses ``--yes`` and ``--json`` (the frame does that, D2) and works only with a person at
a terminal. It asks GitHub for the repository's numeric ID, age, stars and forks, shows them
and the file it will write, and writes only on a yes: one ``[[acknowledgment]]`` entry in the
repository's ``.ssc-guardian.toml``, appended with its comments kept
(``settings.append_acknowledgment``, atomic and read back before it is written). The entry
records the numeric ID, so a repository that later answers to the name with another ID
(repo-jacking) is no longer acknowledged. Declined, or no terminal: nothing written, exit 2
(D15). A repository already acknowledged with the same ID writes nothing (exit 0); with
another ID the command stops, and a person edits the file by hand.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, TextIO

from ssc_guardian.findings import Collector, Ecosystem, IncompleteCheckError, Result, Skip, SkipReason, Verb
from ssc_guardian.net import Client, find_token
from ssc_guardian.overrides import utc_today
from ssc_guardian.plugins.actions import publisher, resolver
from ssc_guardian.render import strip_controls
from ssc_guardian.settings import (
    SETTINGS_FILE,
    WORKSTATION_SETTINGS_FILE,
    Acknowledgment,
    FileKind,
    Settings,
    append_acknowledgment,
    find_repository_root,
    load_settings,
    workstation_dir,
)

if TYPE_CHECKING:
    from ssc_guardian.cli import Request

GHA = Ecosystem.GITHUB_ACTIONS


class _StopError(IncompleteCheckError):
    """Ends the command with nothing written (exit 2); the message says why."""

    def __init__(self, message: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.message = message

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class Acknowledge:
    """The ``acknowledge`` handler, with its streams, places, clock and GitHub client injectable."""

    stdin: TextIO | None = None
    stderr: TextIO | None = None
    cwd: str | None = None
    home: str | None = None
    today: date | None = None
    client: Client | None = None
    environ: Mapping[str, str] | None = None

    def __call__(self, request: Request) -> Result:
        err = self.stderr or sys.stderr
        stdin = self.stdin or sys.stdin
        collector = Collector(Verb.ACKNOWLEDGE)
        root = find_repository_root(self.cwd or os.getcwd())
        name = request.repository
        if root is None or name is None:
            why = (
                "acknowledge works inside a Git repository, and this is not one" if root is None else "name OWNER/REPO"
            )
            _say(err, f"ssc-guardian: {why}; nothing written.")
            collector.skipped.append(
                Skip(GHA, None, SkipReason.CHECK_ERROR, detail=why, site="acknowledge.no-repository-or-name")
            )
            return collector.result()
        if not stdin.isatty():
            _say(err, "ssc-guardian: acknowledge needs a person at a terminal; nothing written.")
            collector.skipped.append(
                Skip(GHA, None, SkipReason.CHECK_ERROR, detail="no terminal", site="acknowledge.no-terminal")
            )
            return collector.result()
        with collector.check(GHA, root) as ok:
            if ok:
                try:
                    self._acknowledge(name, root, stdin, err)
                except IncompleteCheckError as exc:
                    _say(err, f"ssc-guardian: {strip_controls(exc)}; nothing written.")
                    raise
        return collector.result()

    def _acknowledge(self, name: str, root: str, stdin: TextIO, err: TextIO) -> None:
        from ssc_guardian import cli  # imported here: cli imports this handler

        today = self.today or utc_today()
        path = os.path.join(root, SETTINGS_FILE)
        # Each value is stripped as it goes into a message (contracts §5), so none adds a line (#147).
        shown_name, shown_path, shown_root = strip_controls(name), strip_controls(path), strip_controls(root)
        if os.path.islink(path):
            raise _StopError(
                f"{shown_path} is a symlink; acknowledge writes only the repository's own settings file",
                site="acknowledge.symlink-acknowledge-writes-only-repositorys",
            )
        workstation = os.path.join(workstation_dir(self.home), WORKSTATION_SETTINGS_FILE)
        settings = Settings.of(
            load_settings(workstation, kind=FileKind.WORKSTATION, home=self.home),
            load_settings(path, kind=FileKind.REPOSITORY),
        )
        client = self.client or Client(find_token(self.environ))
        repo = resolver.repository(client, name)
        assessment = publisher.assess(repo, today=today, settings=settings)
        if assessment.acknowledged:
            _say(err, f"{shown_name} (ID {repo.id}) is already acknowledged in {shown_path}; nothing to write.")
            return
        if assessment.void is not None:
            raise _StopError(
                f"{shown_path} acknowledges {strip_controls(assessment.void.repository)} with ID "
                f"{assessment.void.repository_id}, but GitHub now gives {shown_name} ID {repo.id}: the name "
                "may now belong to another repository. Review it, and change the entry by hand if you accept "
                "the new one",
                site="acknowledge.name-may-now-belong-another",
            )
        reasons = []
        if assessment.young:
            reasons.append(f"young: created under {assessment.young_days} days ago")
        if assessment.little_used:
            reasons.append(f"little-used: under {assessment.min_stars} stars")
        status = "; ".join(reasons) if reasons else "neither young nor little-used today: no acknowledgment is needed"
        text = "\n".join(
            [
                f"Guardian will record a person's acceptance of {shown_name} in {shown_path}:",
                f"  repository ID: {repo.id} (a changed ID voids this acknowledgment)",
                f"  created {repo.created.isoformat()} ({assessment.age_days} days ago); "
                f"{repo.stars} stars; {repo.forks} forks",
                f"  {status}",
                f"Workflows in {shown_root} may then use {shown_name} although it is young or little-used.",
            ]
        )
        if not cli.confirm(text, verb=Verb.ACKNOWLEDGE, yes=False, stdin=stdin, stdout=err):
            raise _StopError("not confirmed", site="acknowledge.not-confirmed")
        if not append_acknowledgment(path, Acknowledgment(name, repo.id, today)):
            _say(err, f"{shown_name} (ID {repo.id}) was acknowledged in {shown_path} meanwhile; nothing written.")
            return
        _say(err, f"Written: {shown_path}")


def _say(err: TextIO | None, line: str) -> None:
    """Write a message's own lines through ``cli._say``; its values were stripped as they went in
    (#147). A closed, broken or missing stderr never changes the exit code, even after a
    completed write (contracts §3, #227)."""
    from ssc_guardian import cli  # imported here: cli imports this handler

    for part in line.splitlines() or [""]:
        cli._say(err, part)


handle = Acknowledge()
