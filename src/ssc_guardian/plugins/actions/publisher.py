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

"""Wrong publisher and the deny list (plan §3.2 T3; contracts §10.2, §10.3).

- **First use.** An Action repository the lock file has no entry for is new to this
  repository: a ``first-use-publisher`` notice, with the repository's age, stars and forks in
  the text output (GitHub reports no download counts for Actions, plan §8 fact 33).
- **Young or little-used blocks.** A repository GitHub's servers created fewer than
  ``young_repository_days`` ago (built-in 90) or with fewer than ``min_stars`` stars (built-in
  50) is a ``young-repository`` violation (exit 1) until a person runs ``ssc-guardian
  acknowledge OWNER/REPO``. A repository created exactly 90 days ago, or with exactly 50 stars,
  passes. Both thresholds can only be raised: a lower value makes the settings file malformed
  (N-4), and stricter wins across files.
- **Checked every run** for every Action repository a workflow reaches, outer and nested, not
  only on first use (owner ruling on #10, 2026-11-03): pinning a young repository's commit
  never lifts the block, and a changed repository ID is caught on the next run.
- **Acknowledgments** count only with the repository's numeric ID as GitHub gives it today:
  a changed ID (the name now belongs to another repository, repo-jacking) voids it. In CI only
  the default branch's acknowledgments count (§10.5).
- **Guardian's own repository** is exempt from this rule only, by exact name and numeric ID
  together. :data:`OWN_REPOSITORY_ID` holds the public repository's numeric ID (#233); with no
  ID, nothing is exempt.
- **Deny list.** A reference to a denied Action is a ``deny-list`` violation (exit 1) whatever
  any other layer, override or acknowledgment says (§10.3).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from ssc_guardian.findings import Ecosystem, Finding, Option, OptionKind, Rule, Verb, make_finding
from ssc_guardian.findings import _id_spelling as item_spelling
from ssc_guardian.plugins.actions.resolver import Repository
from ssc_guardian.settings import Acknowledgment, Key, Settings

GHA = Ecosystem.GITHUB_ACTIONS
OWN_REPOSITORY = "thomascburns/ssc-guardian"
# GitHub's numeric ID of the public repository, recorded by #233. With no ID (None), nothing
# is exempt, so the exemption can never rest on the name alone.
OWN_REPOSITORY_ID: int | None = 1455613272


def repository_key(name: str) -> str:
    """One spelling of ``owner/repo`` (D18): GitHub matches both halves in any letter case."""
    return item_spelling(GHA, name) or name


def is_own_repository(repo: Repository, own_id: int | None = OWN_REPOSITORY_ID) -> bool:
    """Exact name and numeric ID together; never the name alone."""
    return own_id is not None and repo.name == OWN_REPOSITORY and repo.id == own_id


@dataclass(frozen=True)
class Assessment:
    """T3's facts for one repository today."""

    repository: Repository
    age_days: int
    young_days: int
    min_stars: int
    acknowledged: bool
    void: Acknowledgment | None  # an acknowledgment of this name that records another ID
    exempt: bool

    @property
    def young(self) -> bool:
        return self.age_days < self.young_days

    @property
    def little_used(self) -> bool:
        return self.repository.stars < self.min_stars

    @property
    def blocked(self) -> bool:
        return (self.young or self.little_used) and not self.acknowledged and not self.exempt


def assess(repo: Repository, *, today: date, settings: Settings, own_id: int | None = OWN_REPOSITORY_ID) -> Assessment:
    """Whether ``repo`` blocks today, with the thresholds the settings apply (stricter wins)."""
    young_days = int(settings.value(Key.YOUNG_REPOSITORY_DAYS) or 0)
    min_stars = int(settings.value(Key.MIN_STARS) or 0)
    key = repository_key(repo.name)
    listed = [a for a in settings.acknowledgments if repository_key(a.repository) == key]
    acknowledged = any(a.repository_id == repo.id for a in listed)
    void = next((a for a in listed if a.repository_id != repo.id), None) if not acknowledged else None
    return Assessment(
        repo,
        (today - repo.created).days,
        young_days,
        min_stars,
        acknowledged,
        void,
        is_own_repository(repo, own_id),
    )


def findings(assessment: Assessment, *, place: str, first_use: bool) -> list[Finding]:
    """The first-use notice and the young-repository violation for one repository."""
    name = assessment.repository.name
    found: list[Finding] = []
    if first_use:
        found.append(make_finding(Rule.FIRST_USE_PUBLISHER, GHA, place=place, item=name))
    if assessment.blocked:
        options = (
            Option(OptionKind.EXCEPTION, person_command=Verb.ACKNOWLEDGE, person_target=name),
            Option(OptionKind.REMOVE),
        )
        found.append(
            make_finding(
                Rule.YOUNG_REPOSITORY, GHA, place=place, item=name, options=options, site="publisher.young-repository"
            )
        )
    return found


def describe(assessment: Assessment, *, first_use: bool) -> list[str]:
    """What the text output says about one repository (stderr; never JSON)."""
    repo = assessment.repository
    facts = (
        f"created {repo.created.isoformat()} ({assessment.age_days} days ago), {repo.stars} stars, {repo.forks} forks"
    )
    lines = [f"first use of {repo.name} in this repository: {facts}"] if first_use else []
    if assessment.void is not None:
        lines.append(
            f"the acknowledgment of {assessment.void.repository} records repository ID "
            f"{assessment.void.repository_id}, but GitHub now gives {repo.name} ID {repo.id}: it is void "
            "(the name may now belong to another repository)"
        )
    if assessment.blocked:
        why = []
        if assessment.young:
            why.append(f"created {assessment.age_days} days ago, under {assessment.young_days}")
        if assessment.little_used:
            why.append(f"{repo.stars} stars, under {assessment.min_stars}")
        lines.append(
            f"{repo.name} is young or little-used ({'; '.join(why)}): a person reviews it and runs "
            f"ssc-guardian acknowledge {repo.name}, or the workflows stop using it"
        )
    return lines


def deny_findings(references: Iterable[tuple[str, str, str, tuple[str, ...]]], settings: Settings) -> list[Finding]:
    """A ``deny-list`` violation for each (place, action, ref, via) whose Action is denied."""
    return [
        make_finding(
            Rule.DENY_LIST,
            GHA,
            place=place,
            item=action,
            version=ref,
            via=via,
            options=(Option(OptionKind.REMOVE),),
            site="publisher.denied-action",
        )
        for place, action, ref, via in references
        if settings.denied(GHA, action)
    ]
