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

"""When an Action commit's cooldown starts (plan §3.2 T2, malicious release).

The start is the earliest date GitHub recorded for the commit: the time the repository's
activity log shows it reaching one of the publisher's branches, or the publication of an
immutable release whose tag points at it. With neither, it is the day ``pin`` first recorded
the commit in the lock file. A person's date (``[[start_date]]`` in ``.ssc-guardian.toml``)
is applied on top every run and can only make the start later, never earlier.

A commit inside its cooldown is a wait, not a failure: a ``cooldown-wait`` notice saying when
it is eligible (exit 0). A commit never seen on a publisher branch gets the
``unpushed-commit`` warning. The activity log does not record tags (plan §8 fact 31), so a
commit reachable only through a tag has no activity date.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta

from ssc_guardian.findings import Ecosystem, Finding, Option, OptionKind, Rule, make_finding
from ssc_guardian.net import Client, FeedError
from ssc_guardian.plugin import AgeSource, TrustedAge
from ssc_guardian.plugins.actions.resolver import API, PER_PAGE, pages, quote, repository_of

# Activity types that move a branch to the event's ``after`` commit.
_BRANCH_MOVES = frozenset({"push", "force_push", "branch_creation", "pr_merge", "merge_queue_merge"})
RELEASE_PAGES = 3


def _day(value: object, what: str) -> date:
    """The UTC day of a GitHub timestamp (``2025-03-11T18:42:00Z``)."""
    if not isinstance(value, str):
        raise FeedError(f"api.github.com sent {what} that is not a time", site="clock.time-not-string")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise FeedError(f"api.github.com sent {what} that is not a time", site="clock.time-not-iso") from None
    if moment.tzinfo is None:
        raise FeedError(f"api.github.com sent {what} with no time zone", site="clock.time-no-zone")
    return moment.astimezone(UTC).date()


def on_branch(client: Client, action: str, sha: str) -> date | None:
    """The earliest day the activity log shows ``sha`` reaching a publisher branch, or None.

    Only events on ``refs/heads/`` whose ``after`` is the commit count: a push, force push,
    branch creation or merge that made it a branch's head.
    """
    url = f"{API}/repos/{quote(repository_of(action))}/activity?per_page={PER_PAGE}"
    earliest: date | None = None
    for page in pages(client, url):
        for event in page:
            if not isinstance(event, dict):
                raise FeedError(
                    "api.github.com sent an activity event that is not an object",
                    site="clock.api-github-com-sent-activity",
                )
            ref, after = event.get("ref"), event.get("after")
            if event.get("activity_type") not in _BRANCH_MOVES or after != sha:
                continue
            if not isinstance(ref, str) or not ref.startswith("refs/heads/"):
                continue
            day = _day(event.get("timestamp"), "an activity time")
            earliest = day if earliest is None else min(earliest, day)
    return earliest


def immutable_release(client: Client, action: str, sha: str, all_tags: Mapping[str, str]) -> date | None:
    """The earliest publication day of an immutable, published release whose tag points at ``sha``."""
    url = f"{API}/repos/{quote(repository_of(action))}/releases?per_page={PER_PAGE}"
    earliest: date | None = None
    for page in pages(client, url, max_pages=RELEASE_PAGES):
        for release in page:
            if not isinstance(release, dict):
                raise FeedError(
                    "api.github.com sent a release that is not an object", site="clock.api-github-com-sent-release"
                )
            if release.get("immutable") is not True or release.get("draft") is not False:
                continue
            tag = release.get("tag_name")
            if not isinstance(tag, str) or all_tags.get(tag) != sha:
                continue
            day = _day(release.get("published_at"), "a release time")
            earliest = day if earliest is None else min(earliest, day)
    return earliest


def recorded_age(activity: date | None, release: date | None, first_seen: date) -> TrustedAge:
    """The trusted age ``pin`` records: the earliest GitHub-recorded date, else first-seen."""
    dated = [
        TrustedAge(day, source)
        for day, source in ((activity, AgeSource.ACTIVITY_LOG), (release, AgeSource.IMMUTABLE_RELEASE))
        if day is not None
    ]
    if not dated:
        return TrustedAge(first_seen, AgeSource.LOCK_FIRST_SEEN)
    return min(dated, key=lambda age: age.started)


def start(trusted: TrustedAge, person: date | None) -> TrustedAge:
    """When the cooldown starts: ``trusted``, unless a person's date is later. A person's date
    earlier than the trusted one is ignored, so it can only make the start later."""
    if person is not None and person > trusted.started:
        return TrustedAge(person, AgeSource.PERSON_DATE)
    return trusted


def eligible_on(begins: TrustedAge, cooldown_days: int) -> date:
    """The first day the commit has waited out its cooldown."""
    return begins.started + timedelta(days=cooldown_days)


def cooldown_wait(
    begins: TrustedAge,
    cooldown_days: int,
    today: date,
    *,
    place: str | None,
    action: str,
    sha: str,
    version: str,
) -> Finding | None:
    """The ``cooldown-wait`` notice (exit 0) while ``today`` is before the eligible day; None
    from that day on. Its option names ``version`` (the tag to pin then) and the date."""
    when = eligible_on(begins, cooldown_days)
    if today >= when:
        return None
    later = Option(OptionKind.REPLACE, action, version, eligible_on=when)
    return make_finding(
        Rule.COOLDOWN_WAIT, Ecosystem.GITHUB_ACTIONS, place=place, item=action, version=sha, options=(later,)
    )


def unpushed(place: str | None, action: str, sha: str) -> Finding:
    """The ``unpushed-commit`` warning: the commit was never seen on a publisher branch."""
    return make_finding(Rule.UNPUSHED_COMMIT, Ecosystem.GITHUB_ACTIONS, place=place, item=action, version=sha)
