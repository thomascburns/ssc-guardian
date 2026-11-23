# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Every KEV, OSV and PyPI feed refusal fires with its whole message (issue #11)."""

from __future__ import annotations

import re
from typing import Any

import pytest

from ssc_guardian.feeds import osv, pypi
from ssc_guardian.feeds.kev import CATALOG_URL, Kev, KevStatus, parse_catalog
from ssc_guardian.net import OSV_QUERYBATCH_URL, FeedError
from tests.refusal_sites import refuses
from tests.unit.test_feeds import REQUESTS, record
from tests.unit.test_net import Clock, Recorder, client, reply

pytestmark = pytest.mark.unit

GOOD_RECORD = {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-01"}
PROJECT_URL = pypi.SIMPLE_URL + "requests/"


# --- KEV ------------------------------------------------------------------------------------


def test_kev_catalog_that_is_not_an_object_is_refused() -> None:
    with (
        refuses("kev.kev-catalog-not-object"),
        pytest.raises(FeedError, match=re.escape("the KEV catalog is not an object")),
    ):
        parse_catalog([GOOD_RECORD])


def test_kev_catalog_whose_count_is_off_is_refused() -> None:
    with (
        refuses("kev.kev-catalogs-count-does-not"),
        pytest.raises(FeedError, match=re.escape("the KEV catalog's count does not match its records")),
    ):
        parse_catalog({"count": 2, "vulnerabilities": [GOOD_RECORD]})


@pytest.mark.parametrize(
    "bad",
    [{"cveID": "GHSA-9wx4-h78v-vm56", "dateAdded": "2024-01-01"}, {"cveID": "CVE-2024-0001", "dateAdded": "x"}, 5],
)
def test_kev_record_without_a_valid_cve_and_date_is_refused(bad: object) -> None:
    said = "the KEV catalog has a record without a valid CVE ID and date"
    with refuses("kev.kev-catalog-record-without-valid"), pytest.raises(FeedError, match=re.escape(said)):
        parse_catalog({"count": 2, "vulnerabilities": [GOOD_RECORD, bad]})


def test_kev_refusal_reaches_the_run_as_unavailable() -> None:
    transport = Recorder().route(CATALOG_URL, reply(200, {"count": 3, "vulnerabilities": []}))
    lookup = Kev(client(transport, Clock()))
    assert lookup.status(["CVE-2024-0001"]) is KevStatus.UNAVAILABLE
    assert lookup.failure == "the KEV catalog's count does not match its records"


# --- OSV ------------------------------------------------------------------------------------


def _query(batch: Any, *records: dict[str, Any]) -> dict[str, Any]:
    transport = Recorder().route(OSV_QUERYBATCH_URL, reply(200, batch))
    for rec in records:
        transport.route(osv.VULN_URL + rec["id"], reply(200, rec))
    return osv.query(client(transport, Clock()), ["requests"])


def test_osv_record_for_another_id_is_refused() -> None:
    batch = {"results": [{"vulns": [{"id": "PYSEC-2024-1"}]}]}
    transport = Recorder().route(OSV_QUERYBATCH_URL, reply(200, batch))
    transport.route(osv.VULN_URL + "PYSEC-2024-1", reply(200, record("PYSEC-2024-2", fixed="9.0")))
    with (
        refuses("osv.record-not-object"),
        pytest.raises(FeedError, match=re.escape("OSV sent a record that is not PYSEC-2024-1")),
    ):
        osv.query(client(transport, Clock()), ["requests"])


@pytest.mark.parametrize("batch", [{"results": []}, {"results": [{}, {}]}, {"results": 5}, []])
def test_osv_batch_answer_of_the_wrong_length_is_refused(batch: Any) -> None:
    with (
        refuses("osv.osvs-batch-answer-does-not"),
        pytest.raises(FeedError, match=re.escape("OSV's batch answer does not match its query")),
    ):
        _query(batch)


@pytest.mark.parametrize("result", [5, {"vulns": 5}])
def test_osv_batch_result_that_is_malformed_is_refused(result: Any) -> None:
    with (
        refuses("osv.osvs-batch-answer-malformed-result"),
        pytest.raises(FeedError, match=re.escape("OSV's batch answer has a malformed result")),
    ):
        _query({"results": [result]})


@pytest.mark.parametrize("vuln", [{"id": "bad id!"}, {"id": ""}, {"id": 5}, 5, {"id": "A" * 129}])
def test_osv_batch_advisory_with_an_unusable_id_is_refused(vuln: Any) -> None:
    with (
        refuses("osv.osvs-batch-answer-advisory-unusable"),
        pytest.raises(FeedError, match=re.escape("OSV's batch answer has an advisory with an unusable ID")),
    ):
        _query({"results": [{"vulns": [vuln]}]})


def test_osv_batch_with_too_many_pages_is_refused() -> None:
    # The Recorder repeats its last answer, so the next-page token never runs out.
    transport = Recorder().route(OSV_QUERYBATCH_URL, reply(200, {"results": [{"vulns": [], "next_page_token": "t"}]}))
    with (
        refuses("osv.osvs-batch-answer-too-many"),
        pytest.raises(FeedError, match=re.escape("OSV's batch answer has too many pages")),
    ):
        osv.query(client(transport, Clock()), ["requests"])
    assert len(transport.sent) == osv.MAX_PAGE_ROUNDS


def test_osv_record_that_does_not_name_the_listed_package_is_refused() -> None:
    unnamed = record("PYSEC-2024-3", name="-requests", fixed="9.0")
    batch = {"results": [{"vulns": [{"id": "PYSEC-2024-3"}]}]}
    said = "OSV lists PYSEC-2024-3 for requests, but its record does not name requests"
    with refuses("osv.but-record-does-not-name"), pytest.raises(FeedError, match=re.escape(said)):
        _query(batch, unnamed)


# --- PyPI -----------------------------------------------------------------------------------


def _project(page: Any) -> pypi.Project:
    transport = Recorder().route(PROJECT_URL, reply(200, page))
    return pypi.project(client(transport, Clock()), "Requests")


@pytest.mark.parametrize(
    "page",
    [[], {"files": []}, {"meta": {"api-version": "1.4"}}, {"meta": 5, "files": []}, {"meta": {}, "files": {}}],
)
def test_pypi_page_of_an_unexpected_shape_is_refused(page: Any) -> None:
    with (
        refuses("pypi.pypi-sent-unexpected-page"),
        pytest.raises(FeedError, match=re.escape("PyPI sent an unexpected page for requests")),
    ):
        _project(page)


@pytest.mark.parametrize("status", [{"status": "frozen"}, "frozen", {"status": 5}])
def test_pypi_project_status_guardian_does_not_know_is_refused(status: object) -> None:
    said = "PyPI gives requests a project status Guardian does not know"
    with refuses("pypi.project-status-guardian-does-not"), pytest.raises(FeedError, match=re.escape(said)):
        _project(dict(REQUESTS, **{"project-status": status}))


@pytest.mark.parametrize("versions", [5, "2.31.0", {"2.31.0": 1}, None])
def test_pypi_version_list_that_is_not_a_list_is_refused(versions: object) -> None:
    with (
        refuses("pypi.pypi-sent-version-list"),
        pytest.raises(FeedError, match=re.escape("PyPI sent a version list for requests that is not a list")),
    ):
        _project(dict(REQUESTS, versions=versions))
