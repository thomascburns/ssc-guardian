# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""OSV entries: two spellings are readable (#90); a junk tag beside a readable range is ignored (#103);
a padded listed version still counts (#105)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.cli import Request, main
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.protect import Protect
from ssc_guardian.feeds import Affected, Match, osv
from ssc_guardian.findings import ExitCode, OptionKind, Result, Rule, Verb
from ssc_guardian.net import FeedError
from ssc_guardian.pep440 import parse
from tests.refusal_sites import refuses
from tests.samples import VENV
from tests.unit.test_discovery import add_dist, fake_mac, make_venv
from tests.unit.test_feeds import OLD, REQUESTS, TODAY, by_rule, check, page, record, world
from tests.unit.test_net import Clock, Recorder, client

pytestmark = pytest.mark.unit

JUNK = ["2.1.0", "v0.1.1d"]
GIT_RANGE = {
    "type": "GIT",
    "repo": "https://github.com/executablebooks/markdown-it-py",
    "events": [{"introduced": "0"}],
}
FIXED_2_2 = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}
MARKDOWN_IT = page("markdown-it-py", {"2.1.0": OLD, "2.2.0": OLD, "4.0.0": OLD})


def _only(rec: dict[str, Any]) -> Affected:
    advisory = osv.parse_record(rec, rec["id"])
    assert advisory is not None
    (entry,) = advisory.affected
    return entry


def _duplicated_check() -> Result:
    advisory = record("PYSEC-2024-1", versions=["2.31.0", "2.31"])
    return check(world({"requests": [advisory]}, {"requests": REQUESTS}), [("requests", "2.31.0")])


def _pysec_23(vid: str = "PYSEC-2023-23") -> dict[str, Any]:
    return record(vid, name="markdown-it-py", ranges=[GIT_RANGE, FIXED_2_2], versions=JUNK)


def _markdown_it_check(rec: dict[str, Any], installed: str) -> Result:
    transport = world({"markdown-it-py": [rec]}, {"markdown-it-py": MARKDOWN_IT})
    return check(transport, [("markdown-it-py", installed)])


def test_two_spellings_of_one_version_are_readable() -> None:
    entry = _only(record("PYSEC-2014-13", versions=["0.12.01", "0.12.1"]))
    assert entry.unreadable is False
    assert len(entry.versions) == 1
    assert entry.match(parse("0.12.1")) is Match.VERSION


def test_installed_version_outside_a_duplicated_list_is_not_vulnerable() -> None:
    entry = _only(record("PYSEC-2024-1", versions=["2.0.0", "2.0", "1.0"]))
    assert entry.match(parse("2.33.1")) is None


def test_unparsable_listed_version_still_marks_the_entry_unreadable() -> None:
    entry = _only(record("PYSEC-2023-23", name="markdown-it-py", versions=["0.1.1", "v0.1.1d"]))
    assert entry.unreadable is True
    assert entry.match(parse("4.0.0")) is Match.UNREADABLE


def test_duplicated_list_offers_a_fix() -> None:
    (finding,) = by_rule(_duplicated_check())[Rule.KNOWN_VULNERABILITY]
    replace = [(o.version, o.command) for o in finding.options if o.kind is OptionKind.REPLACE and o.command]
    assert replace == [("2.32.3", ("ssc-guardian", "install", "--venv", VENV, "requests==2.32.3"))]


def test_duplicate_handling_is_idempotent_on_re_run() -> None:
    first, second = _duplicated_check(), _duplicated_check()
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert first.exit_code is second.exit_code
    for result in (first, second):
        (finding,) = by_rule(result)[Rule.KNOWN_VULNERABILITY]
        replace = tuple(o.version for o in finding.options if o.kind is OptionKind.REPLACE)
        assert replace == ("2.32.3", "2.32.4")


def test_check_envs_reports_no_false_violation_for_duplicated_spellings(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    config = Path(where.home) / ".config" / "ssc-guardian"
    config.mkdir(parents=True)
    (config / "config.toml").write_text("format = 1\n")
    folder = make_venv(Path(where.home) / "projects" / "app" / ".venv")
    add_dist(folder, "pip", "26.2.1")
    add_dist(folder, "requests", "2.33.1")
    protect = Protect(where.home, where.environ, where.root, TODAY, io.StringIO(), io.StringIO())
    protect(
        Request(Verb.PROTECT, paths=(str(Path(where.home) / "projects"),), yes=True)
    )  # an unprotected venv is a violation of its own
    advisory = record("GHSA-652x-xj99-gmcc", aliases=("CVE-2014-1829",), versions=["0.12.01", "0.12.1", "1.0"])
    transport = world(
        {"pip": [], "requests": [advisory]},
        {"pip": page("pip", {"26.2.1": OLD}), "requests": page("requests", {"2.33.1": OLD})},
    )
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client(transport, Clock()), err)
    code = main(
        ["check", "--envs", "--path", str(Path(where.home) / "projects"), "--json"],
        handlers={Verb.CHECK: handler},
        stdout=out,
        stderr=err,
    )
    doc = json.loads(out.getvalue())
    assert code == doc["exit_code"] == ExitCode.RULES_MET
    assert doc["findings"] == []


@pytest.mark.parametrize("vid", ["PYSEC-2023-23", "MAL-2024-9"])
def test_junk_tag_beside_a_readable_range_is_readable(vid: str) -> None:
    entry = _only(_pysec_23(vid))
    assert entry.unreadable is False
    assert entry.match(parse("4.0.0")) is None
    assert entry.match(parse("2.2.0")) is None
    result = _markdown_it_check(_pysec_23(vid), "4.0.0")
    assert result.findings == ()
    assert result.exit_code is ExitCode.RULES_MET


def test_version_below_the_fix_is_still_vulnerable() -> None:
    entry = _only(_pysec_23())
    assert entry.match(parse("2.1.0")) is Match.VERSION
    assert entry.match(parse("0.1.1")) is Match.VERSION
    result = _markdown_it_check(_pysec_23(), "2.1.0")
    (finding,) = by_rule(result)[Rule.KNOWN_VULNERABILITY]
    assert finding.evidence == ("PYSEC-2023-23",)
    assert [o.version for o in finding.options if o.kind is OptionKind.REPLACE and o.command] == ["4.0.0"]
    assert result.exit_code is ExitCode.VIOLATION


def test_listed_version_outside_the_range_still_matches() -> None:
    entry = _only(record("PYSEC-2024-2", fixed="2.0", versions=["3.0", "v0.1.1d"]))
    assert entry.unreadable is False
    assert entry.match(parse("3.0")) is Match.VERSION
    assert entry.match(parse("2.5")) is None


def test_junk_tag_beside_only_a_git_range_stays_unreadable() -> None:
    entry = _only(record("PYSEC-2023-23", name="markdown-it-py", ranges=[GIT_RANGE], versions=JUNK))
    assert entry.unreadable is True
    assert entry.match(parse("4.0.0")) is Match.UNREADABLE


@pytest.mark.parametrize(
    "broken",
    [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "not.a.version!"}]},
        {"type": "ECOSYSTEM", "events": []},
        {"type": "bogus", "events": [{"introduced": "0"}]},
        "not a range",
    ],
)
def test_junk_tag_beside_an_unreadable_range_stays_unreadable(broken: object) -> None:
    entry = _only(record("PYSEC-2023-23", name="markdown-it-py", ranges=[FIXED_2_2, broken], versions=JUNK))
    assert entry.unreadable is True
    assert entry.match(parse("4.0.0")) is Match.UNREADABLE
    assert entry.match(parse("2.1.0")) is Match.VERSION


@pytest.mark.parametrize("item", [2.32, None, {"version": "2.32.3"}, ["2.32.3"]])
def test_listed_item_that_is_not_a_string_stays_unreadable_beside_a_range(item: object) -> None:
    advisory = record("MAL-2024-6", fixed="1.0", versions=[item])
    entry = _only(advisory)
    assert entry.unreadable is True
    assert entry.match(parse("2.32.3")) is Match.UNREADABLE
    result = check(world({"requests": [advisory]}, {"requests": REQUESTS}), [("requests", "2.32.3")])
    assert Rule.COMPROMISE in by_rule(result)
    assert result.exit_code is ExitCode.VIOLATION


def test_junk_tag_handling_is_idempotent_on_re_run() -> None:
    assert osv.parse_record(_pysec_23(), "PYSEC-2023-23") == osv.parse_record(_pysec_23(), "PYSEC-2023-23")
    first, second = _markdown_it_check(_pysec_23(), "4.0.0"), _markdown_it_check(_pysec_23(), "4.0.0")
    for result in (first, second):
        assert result.findings == ()
        assert result.exit_code is ExitCode.RULES_MET


def test_check_envs_reports_no_false_violation_for_a_junk_tag(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    config = Path(where.home) / ".config" / "ssc-guardian"
    config.mkdir(parents=True)
    (config / "config.toml").write_text("format = 1\n")
    folder = make_venv(Path(where.home) / "projects" / "app" / ".venv")
    add_dist(folder, "pip", "26.2.1")
    add_dist(folder, "markdown-it-py", "4.0.0")
    protect = Protect(where.home, where.environ, where.root, TODAY, io.StringIO(), io.StringIO())
    protect(
        Request(Verb.PROTECT, paths=(str(Path(where.home) / "projects"),), yes=True)
    )  # an unprotected venv is a violation of its own
    transport = world(
        {"markdown-it-py": [_pysec_23()], "pip": []},
        {"markdown-it-py": page("markdown-it-py", {"4.0.0": OLD}), "pip": page("pip", {"26.2.1": OLD})},
    )
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client(transport, Clock()), err)
    code = main(
        ["check", "--envs", "--path", str(Path(where.home) / "projects"), "--json"],
        handlers={Verb.CHECK: handler},
        stdout=out,
        stderr=err,
    )
    doc = json.loads(out.getvalue())
    assert code == doc["exit_code"] == ExitCode.RULES_MET
    assert doc["findings"] == []


@pytest.mark.parametrize("listed", [["4.0.0 "], ["4.0.0\n"], [" 4.0.0"], ["\t4.0.0"], ["4.0.0 ", "v0.1.1d"]])
def test_padded_listed_version_is_that_version(listed: list[str]) -> None:
    entry = _only(record("PYSEC-2023-23", name="markdown-it-py", ranges=[FIXED_2_2], versions=listed))
    assert entry.unreadable is False
    assert entry.match(parse("4.0.0")) is Match.VERSION


def test_padded_listed_version_alone_matches_it() -> None:
    entry = _only(record("PYSEC-2023-23", name="markdown-it-py", versions=["4.0.0 "]))
    assert entry.unreadable is False
    assert entry.match(parse("4.0.0")) is Match.VERSION
    assert entry.match(parse("1.5.0")) is None


@pytest.mark.parametrize(
    ("vid", "rule"), [("PYSEC-2023-23", Rule.KNOWN_VULNERABILITY), ("MAL-2024-9", Rule.COMPROMISE)]
)
def test_padded_version_is_a_finding_through_check(vid: str, rule: Rule) -> None:
    padded = record(vid, name="markdown-it-py", ranges=[FIXED_2_2], versions=["4.0.0 "])
    result = _markdown_it_check(padded, "4.0.0")
    (finding,) = result.findings
    assert finding.rule is rule
    assert finding.evidence == (vid,)
    assert result.exit_code is ExitCode.VIOLATION


@pytest.mark.parametrize("junk", [" v0.1.1d ", "4.0 .0"])
def test_junk_tag_after_stripping_stays_junk(junk: str) -> None:
    beside = _only(record("PYSEC-2023-23", name="markdown-it-py", ranges=[FIXED_2_2], versions=[junk]))
    assert beside.unreadable is False
    assert beside.match(parse("4.0.0")) is None
    alone = _only(record("PYSEC-2023-23", name="markdown-it-py", versions=[junk]))
    assert alone.unreadable is True
    assert alone.match(parse("4.0.0")) is Match.UNREADABLE


@pytest.mark.parametrize("blank", ["   ", "\n", ""])
def test_blank_listed_string_is_junk(blank: str) -> None:
    beside = _only(record("PYSEC-2023-23", name="markdown-it-py", ranges=[FIXED_2_2], versions=[blank]))
    assert beside.versions == frozenset()
    assert beside.unreadable is False
    assert beside.match(parse("4.0.0")) is None
    alone = _only(record("PYSEC-2023-23", name="markdown-it-py", versions=[blank]))
    assert alone.unreadable is True
    assert alone.match(parse("4.0.0")) is Match.UNREADABLE


def test_junk_tag_beside_a_semver_range_is_readable() -> None:
    semver = {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
    entry = _only(record("PYSEC-2023-23", name="markdown-it-py", ranges=[semver], versions=JUNK))
    assert entry.unreadable is False
    assert entry.match(parse("1.5.0")) is Match.VERSION
    assert entry.match(parse("4.0.0")) is None


@pytest.mark.parametrize("listed", [["4.0.0 "], ["3.0", "4.0.0 "]])
@pytest.mark.parametrize("ranges", [[], [GIT_RANGE]])
@pytest.mark.parametrize(
    ("vid", "rule"), [("PYSEC-2023-23", Rule.KNOWN_VULNERABILITY), ("MAL-2024-9", Rule.COMPROMISE)]
)
def test_padded_entry_with_no_readable_range_reads_as_its_clean_spelling(
    vid: str, rule: Rule, ranges: list[dict[str, Any]], listed: list[str]
) -> None:
    padded = record(vid, name="markdown-it-py", ranges=ranges, versions=listed)
    clean = record(vid, name="markdown-it-py", ranges=ranges, versions=[x.strip() for x in listed])
    assert _only(padded) == _only(clean)
    project = {"markdown-it-py": page("markdown-it-py", {"1.5.0": OLD, "4.0.0": OLD})}
    unnamed = check(world({"markdown-it-py": [padded]}, project), [("markdown-it-py", "1.5.0")])
    assert unnamed.findings == ()
    assert unnamed.exit_code is ExitCode.RULES_MET
    named = check(world({"markdown-it-py": [padded]}, project), [("markdown-it-py", "4.0.0")])
    assert list(by_rule(named)) == [rule]
    assert named.exit_code is ExitCode.VIOLATION


# --- a bound on the advisories one run fetches (#230, L3-5) ------------------------------


def _listing(counts: dict[str, int]) -> Recorder:
    """An OSV batch answer listing ``counts[name]`` distinct advisory IDs for each name."""
    records = {name: [record(f"PYSEC-{name}-{i}", name=name) for i in range(n)] for name, n in counts.items()}
    return world(records, {})


def _fetched(transport: Recorder) -> int:
    return sum(sent.url.startswith(osv.VULN_URL) for sent in transport.sent)


def test_too_many_advisory_ids_is_a_feed_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    # The audit's probe: one answer listing more IDs than any real run, each of which would be a GET.
    transport = _listing({"requests": osv.MAX_ADVISORY_IDS + 1})
    with refuses("osv.too-many-advisory-ids"), pytest.raises(FeedError, match="more than the 10000"):
        osv.query(client(transport, Clock()), ["requests"])
    assert _fetched(transport) == 0  # refused whole, before any record is fetched: never cut short

    # The bound is per run, over every name; at the bound every record is still read.
    monkeypatch.setattr(osv, "MAX_ADVISORY_IDS", 3)
    transport = _listing({"idna": 2, "requests": 2})
    with refuses("osv.too-many-advisory-ids"), pytest.raises(FeedError, match="listed 4 advisories"):
        osv.query(client(transport, Clock()), ["idna", "requests"])
    transport = _listing({"idna": 1, "requests": 2})
    found = osv.query(client(transport, Clock()), ["idna", "requests"])
    assert [len(found[n]) for n in ("idna", "requests")] == [1, 2] and _fetched(transport) == 3
