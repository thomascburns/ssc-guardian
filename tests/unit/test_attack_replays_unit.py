# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The feed and rule layer of the 2026 PyPI attacks Guardian is tested against (issue #196).

Each test states its clock: ``Rules.today`` is fixed at the attack day or a set number of days
after it, and every attack upload is dated on the attack's own day, so the outcome never
depends on the wall-clock date. The feeds answer in process from ``tests.unit.test_feeds``'s
``world``; nothing reaches the network. ``tests/integration/test_attack_replays.py`` replays the
same attacks through ``install --venv``, ``check --envs``, ``check --repo`` and ``pin``.

The cases (owner session of 2026-11-11, from public write-ups):

- LiteLLM 1.82.7 and 1.82.8, uploaded to PyPI with stolen credentials on 2026-03-24 from 10:39
  UTC; 1.82.8 added ``litellm_init.pth``; PYSEC-2026-2. 1.82.6 is the last clean release.
- Telnyx 4.87.1 and 4.87.2, 2026-03-27, an import-time payload; PyPI quarantined the project.
- lightning 2.6.2 and 2.6.3, 2026-04-30 (Mini Shai-Hulud, PyPI side); 2.6.1 is the last clean one.

Modelled: the time of day of each attack upload (LiteLLM 1.82.7 and 1.82.8 both at 10:39 UTC, the
write-ups' "from 10:39"; Telnyx and lightning at midnight UTC), the clean releases' upload dates
(only "older than the cooldown" matters), each project's version list, and the OSV ``MAL-``
record IDs, which are stand-ins numbered after this issue; the LiteLLM record carries
PYSEC-2026-2 as its alias.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from ssc_guardian.feeds import pypi
from ssc_guardian.findings import ExitCode, Label, OptionKind, Rule
from ssc_guardian.net import OSV_QUERYBATCH_URL
from ssc_guardian.policy import Rules
from tests.refusal_sites import Refuses, refuses
from tests.samples import VENV
from tests.unit.test_feeds import by_rule, check, page, record, world
from tests.unit.test_net import reply

pytestmark = pytest.mark.unit

COOLDOWN_DAYS = 21  # Guardian's default (settings.py Key.COOLDOWN_DAYS)
PAST_COOLDOWN = 31  # days after an attack: every attack file is past the cooldown by then

LITELLM_DAY = date(2026, 3, 24)
LITELLM_UPLOAD = "2026-03-24T10:39:00Z"
LITELLM = page("litellm", {"1.82.6": "2026-02-24T00:00:00Z", "1.82.7": LITELLM_UPLOAD, "1.82.8": LITELLM_UPLOAD})
LITELLM_MAL = record("MAL-2026-19601", aliases=("PYSEC-2026-2",), name="litellm", versions=["1.82.7", "1.82.8"])

TELNYX_DAY = date(2026, 3, 27)
TELNYX_UPLOAD = "2026-03-27T00:00:00Z"
TELNYX_QUARANTINED = page(
    "telnyx",
    {"4.87.0": "2026-03-01T00:00:00Z", "4.87.1": TELNYX_UPLOAD, "4.87.2": TELNYX_UPLOAD},
    status="quarantined",
)

LIGHTNING_DAY = date(2026, 4, 30)
LIGHTNING_UPLOAD = "2026-04-30T00:00:00Z"
LIGHTNING = page("lightning", {"2.6.1": "2026-04-01T00:00:00Z", "2.6.2": LIGHTNING_UPLOAD, "2.6.3": LIGHTNING_UPLOAD})
LIGHTNING_MAL = record("MAL-2026-19602", name="lightning", versions=["2.6.2", "2.6.3"])


def _after(day: date, days: int) -> date:
    return date.fromordinal(day.toordinal() + days)


def _rules(today: date) -> Rules:
    return Rules(cooldown_days=COOLDOWN_DAYS, today=today)


def _replacements(finding: Any) -> list[tuple[str, tuple[str, ...] | None]]:
    return [(o.version, o.command) for o in finding.options if o.kind is OptionKind.REPLACE]


def test_litellm_young_version_fails_cooldown() -> None:
    # Clock: the attack day, 2026-03-24. 1.82.8 was uploaded at 10:39 UTC that day, so its
    # cooldown counts from 2026-03-25 and ends on 2026-04-15. No MAL- record exists yet.
    transport = world({"litellm": []}, {"litellm": LITELLM})
    with refuses("policy.cooldown"):
        result = check(transport, [("litellm", "1.82.8")], _rules(LITELLM_DAY))
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.item, finding.version) == (Rule.COOLDOWN, "litellm", "1.82.8")
    # The fix is the last clean release, with its install command; 1.82.7, also young, is the
    # one named as waiting, with the date it would become eligible.
    ready, waiting = [o for o in finding.options if o.kind is OptionKind.REPLACE]
    assert (ready.version, ready.command) == ("1.82.6", ("ssc-guardian", "install", "--venv", VENV, "litellm==1.82.6"))
    assert (waiting.version, waiting.command, waiting.eligible_on) == ("1.82.7", None, date(2026, 4, 15))


def test_litellm_mal_record_blocks_after_cooldown() -> None:
    # Clock: 31 days after the attack (2026-04-24), past the cooldown, with OSV's MAL- record
    # naming 1.82.7 and 1.82.8. The feed layer, not the cooldown, refuses it.
    transport = world({"litellm": [LITELLM_MAL]}, {"litellm": LITELLM})
    with refuses("policy.compromise"):
        result = check(transport, [("litellm", "1.82.8")], _rules(_after(LITELLM_DAY, PAST_COOLDOWN)))
    assert result.exit_code is ExitCode.VIOLATION
    found = by_rule(result)
    assert set(found) == {Rule.COMPROMISE}  # no cooldown finding: the age is no longer the reason
    (finding,) = found[Rule.COMPROMISE]
    assert finding.evidence == ("MAL-2026-19601", "PYSEC-2026-2")
    # 1.82.7 is named by the record too, so the only replacement is 1.82.6.
    assert _replacements(finding) == [("1.82.6", ("ssc-guardian", "install", "--venv", VENV, "litellm==1.82.6"))]


def test_telnyx_quarantine_is_compromise_with_no_replacement() -> None:
    # Clock: 31 days after the attack (2026-04-27): past the cooldown, so only PyPI's PEP 792
    # quarantine can refuse it. A quarantined project offers no replacement at all.
    transport = world({"telnyx": []}, {"telnyx": TELNYX_QUARANTINED})
    with refuses("policy.compromise"):
        result = check(transport, [("telnyx", "4.87.2")], _rules(_after(TELNYX_DAY, PAST_COOLDOWN)))
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.item, finding.version) == (Rule.COMPROMISE, "telnyx", "4.87.2")
    assert finding.labels == (Label.REGISTRY_QUARANTINED,)
    assert finding.evidence == ()
    assert [o.kind for o in finding.options] == [OptionKind.REMOVE, OptionKind.EXCEPTION]


def test_lightning_mal_record_names_last_clean_release() -> None:
    # Clock: 31 days after the attack (2026-05-31), past the cooldown, with the MAL- record naming
    # 2.6.2 and 2.6.3: 2.6.3 is a compromise and 2.6.1 is the replacement.
    transport = world({"lightning": [LIGHTNING_MAL]}, {"lightning": LIGHTNING})
    with refuses("policy.compromise"):
        result = check(transport, [("lightning", "2.6.3")], _rules(_after(LIGHTNING_DAY, PAST_COOLDOWN)))
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.version, finding.evidence) == (Rule.COMPROMISE, "2.6.3", ("MAL-2026-19602",))
    assert [version for version, _ in _replacements(finding)] == ["2.6.1"]


@pytest.mark.parametrize(
    ("url", "case"),
    [
        # OSV is the whole check's first read: the client's own refusal ends it.
        (OSV_QUERYBATCH_URL, refuses("net.feed-retries-exhausted")),
        # PyPI's failure is kept per name; evaluating that name then refuses.
        (pypi.SIMPLE_URL + "litellm/", refuses("policy.pypi-not-read")),
    ],
    ids=["osv", "pypi"],
)
def test_unreadable_feed_is_exit_2_never_a_pass(url: str, case: Refuses) -> None:
    # Clock: the LiteLLM attack day. A feed answering 500, every retry, leaves the check
    # unfinished (exit 2), listed as a feed-failure skip, never a pass and never "checked".
    transport = world({"litellm": []}, {"litellm": LITELLM})
    transport.route(url, reply(500))
    with case:
        result = check(transport, [("litellm", "1.82.8")], _rules(LITELLM_DAY))
    assert result.exit_code is ExitCode.INCOMPLETE
    assert result.checked == ()
    assert [(s.reason.value, s.in_scope) for s in result.skipped] == [("feed-failure", True)]
    assert result.findings == ()
