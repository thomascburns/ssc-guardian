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

"""OSV: known vulnerabilities and ``MAL-`` malware records for PyPI (plan §3.1, §10.3, N21).

``querybatch`` lists the advisory IDs for each package name; each ID is then read once from
``/v1/vulns/{id}``, and versions are matched here with the standard-library PEP 440 order, so a
replacement version can be checked against the same records without another request. OSV
already carries the OpenSSF malicious-packages list as ``MAL-`` records (§8 fact 21). There is
no bulk download. Any failed request raises :class:`~ssc_guardian.net.FeedError` (exit 2).
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ssc_guardian.feeds import Advisory, Affected, Source, VersionRange
from ssc_guardian.grammars import Field, matches, normalize_pypi_name
from ssc_guardian.net import Client, FeedError
from ssc_guardian.pep440 import Version, try_parse

VULN_URL = "https://api.osv.dev/v1/vulns/"
ECOSYSTEM = "PyPI"
BATCH_SIZE = 1000  # OSV's limit of queries per querybatch
MAX_PAGE_ROUNDS = 20
QUERYBATCH_LIMIT = 8 * 1024 * 1024
RECORD_LIMIT = 4 * 1024 * 1024
MAX_ADVISORY_IDS = 10_000  # distinct IDs per run, each one a GET; far past any real environment's count
_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.:")


@dataclass(frozen=True)
class EventRange:
    """An OSV ``ECOSYSTEM`` range: its events in version order (None stands for ``0``)."""

    events: tuple[tuple[str, Version | None], ...]

    def contains(self, version: Version) -> bool:
        # The OSV specification's evaluation: walk the events in order.
        affected = False
        for kind, at in self.events:
            if kind == "introduced":
                affected = affected or at is None or version >= at
            elif at is not None and (version >= at if kind == "fixed" else version > at):  # fixed, last_affected
                affected = False
        return affected


def _event_order(event: tuple[str, Version | None]) -> tuple[Any, ...]:
    return (0,) if event[1] is None else (1, event[1])


def _event_range(events: object) -> tuple[EventRange | None, bool]:
    """(range, every version). None when an event holds a version that cannot be parsed."""
    if not isinstance(events, list) or not events:
        return None, False
    parsed: list[tuple[str, Version | None]] = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None, False
        ((kind, raw),) = event.items()
        if kind == "limit":  # limits bound Git ranges; ECOSYSTEM ranges carry none that matter
            continue
        if kind not in {"introduced", "fixed", "last_affected"}:
            return None, False
        if kind == "introduced" and raw == "0":
            parsed.append((kind, None))
            continue
        version = try_parse(raw)
        if version is None:
            return None, False
        parsed.append((kind, version.public))
    if not any(kind == "introduced" for kind, _ in parsed):
        return None, False  # a range with no start is not a valid OSV range
    parsed.sort(key=_event_order)
    every = all(kind == "introduced" and at is None for kind, at in parsed)
    return EventRange(tuple(parsed)), every


def _affected(entry: object) -> Affected | None:
    """One ``affected[]`` entry for a PyPI package, or None for any other ecosystem."""
    if not isinstance(entry, dict):
        return None
    package = entry.get("package")
    if not isinstance(package, dict) or package.get("ecosystem") != ECOSYSTEM:
        return None
    raw_name = package.get("name")
    if not matches(Field.PYPI_NAME, raw_name):
        return None
    name = normalize_pypi_name(str(raw_name))
    # A shape Guardian cannot read marks the entry unreadable: none of its versions can then be
    # ruled out. A GIT range is skipped, since it names commits, not versions. A listed string that
    # does not parse, even with surrounding whitespace stripped, names no version Guardian can
    # match, so it counts only with no readable range.
    raw_versions = entry.get("versions", [])
    listed = raw_versions if isinstance(raw_versions, list) else []
    parsed_versions = [try_parse(x.strip()) if isinstance(x, str) else None for x in listed]
    versions = frozenset(v for v in parsed_versions if v is not None)
    unreadable = not isinstance(raw_versions, list) or any(not isinstance(x, str) for x in listed)
    junk_listed = any(v is None for v in parsed_versions)
    ranges: list[VersionRange] = []
    every = False
    raw_ranges = entry.get("ranges", [])
    if not isinstance(raw_ranges, list):
        raw_ranges, unreadable = [], True
    for rng in raw_ranges:
        kind = rng.get("type") if isinstance(rng, dict) else None
        if kind == "GIT":
            continue
        if not isinstance(kind, str) or kind not in {"ECOSYSTEM", "SEMVER"}:
            unreadable = True
            continue
        parsed, whole = _event_range(rng.get("events"))
        if parsed is None:
            unreadable = True
            continue
        ranges.append(parsed)
        every = every or whole
    if junk_listed and not ranges:
        unreadable = True
    return Affected(name, versions, tuple(ranges), every_version=every, unreadable=unreadable)


def parse_record(data: object, expected_id: str) -> Advisory | None:
    """An OSV record as an :class:`Advisory`; None when it is withdrawn (plan §10.3)."""
    if not isinstance(data, dict) or data.get("id") != expected_id:
        raise FeedError(f"OSV sent a record that is not {expected_id}", site="osv.record-not-object")
    if data.get("withdrawn"):
        return None
    affected = data.get("affected", [])
    if not isinstance(affected, list):
        raise FeedError(f"OSV record {expected_id} has no affected list", site="osv.record-no-affected-list")
    raw_aliases = data.get("aliases")
    aliases = tuple(a for a in raw_aliases if isinstance(a, str)) if isinstance(raw_aliases, list) else ()
    return Advisory(
        id=expected_id,
        aliases=aliases,
        source=Source.OSV,
        malicious=expected_id.startswith("MAL-"),
        affected=tuple(a for a in (_affected(e) for e in affected) if a is not None),
    )


def _ids_for(client: Client, names: list[str]) -> dict[str, list[str]]:
    """Every advisory ID OSV lists for each name, following its page tokens."""
    found: dict[str, list[str]] = {name: [] for name in names}
    for start in range(0, len(names), BATCH_SIZE):
        pending: dict[str, str | None] = dict.fromkeys(names[start : start + BATCH_SIZE])
        for _ in range(MAX_PAGE_ROUNDS):
            if not pending:
                break
            order = list(pending)
            queries = []
            for name in order:
                query: dict[str, object] = {"package": {"name": name, "ecosystem": ECOSYSTEM}}
                if pending[name]:
                    query["page_token"] = pending[name]
                queries.append(query)
            answer = client.osv_querybatch({"queries": queries}, limit=QUERYBATCH_LIMIT).json()
            results = answer.get("results") if isinstance(answer, dict) else None
            if not isinstance(results, list) or len(results) != len(order):
                raise FeedError("OSV's batch answer does not match its query", site="osv.osvs-batch-answer-does-not")
            pending = {}
            for name, result in zip(order, results, strict=True):
                vulns = result.get("vulns", []) if isinstance(result, dict) else None
                if not isinstance(vulns, list):
                    raise FeedError(
                        "OSV's batch answer has a malformed result", site="osv.osvs-batch-answer-malformed-result"
                    )
                for vuln in vulns:
                    vid = vuln.get("id") if isinstance(vuln, dict) else None
                    if not isinstance(vid, str) or not vid or len(vid) > 128 or not set(vid) <= _ID_CHARS:
                        raise FeedError(
                            "OSV's batch answer has an advisory with an unusable ID",
                            site="osv.osvs-batch-answer-advisory-unusable",
                        )
                    if vid not in found[name]:
                        found[name].append(vid)
                token = result.get("next_page_token")
                if token:
                    pending[name] = str(token)
        else:
            if pending:
                raise FeedError("OSV's batch answer has too many pages", site="osv.osvs-batch-answer-too-many")
    return found


def query(client: Client, names: Iterable[str]) -> dict[str, tuple[Advisory, ...]]:
    """Every OSV advisory for each PyPI name, keyed by its PEP 503 form.

    Each ID is read once however many names list it, and each name's advisories come in ID
    order, so a re-run gives equal answers and no duplicates. Withdrawn records are left out. A
    record OSV lists for a name whose entries do not name that package is a feed failure, never
    dropped: Guardian cannot tell which versions it means.
    """
    wanted = sorted({normalize_pypi_name(name) for name in names})
    ids = _ids_for(client, wanted)
    distinct = sorted({vid for listed in ids.values() for vid in listed})
    if len(distinct) > MAX_ADVISORY_IDS:
        # Each ID is one request; an answer listing more than any real run needs is refused whole,
        # never cut short, since a dropped ID could be the advisory that matters (#230).
        raise FeedError(
            f"OSV listed {len(distinct)} advisories for this run, more than the {MAX_ADVISORY_IDS} Guardian reads",
            site="osv.too-many-advisory-ids",
        )
    records: dict[str, Advisory | None] = {}
    for vid in distinct:
        url = VULN_URL + urllib.parse.quote(vid, safe="")
        records[vid] = parse_record(client.get(url, accept="application/json", limit=RECORD_LIMIT).json(), vid)
    found: dict[str, tuple[Advisory, ...]] = {}
    for name in wanted:
        listed = [record for vid in sorted(ids[name]) if (record := records[vid]) is not None]
        for record in listed:
            if not any(entry.name == name for entry in record.affected):
                raise FeedError(
                    f"OSV lists {record.id} for {name}, but its record does not name {name}",
                    site="osv.but-record-does-not-name",
                )
        found[name] = tuple(listed)
    return found
