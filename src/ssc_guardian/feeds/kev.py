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

"""CISA's Known Exploited Vulnerabilities catalog (plan §3.1, R1-KEV-C, R2-K4).

Every known vulnerability already blocks; KEV only adds the ``actively-exploited`` label and
the 7-day override limit. A vulnerability is matched by the CVE IDs among its advisories'
aliases. The catalog is downloaded only when a vulnerability with a CVE ID is found, at most
once, and kept in memory for that run only. When it cannot be reached, :class:`Kev` reports
:attr:`KevStatus.UNAVAILABLE` for the rest of the run: the label is then missing and the caller
shows the ``kev-unavailable`` warning, and an override that KEV would limit is not applied.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from enum import StrEnum

from ssc_guardian.grammars import Field, matches
from ssc_guardian.net import Client, FeedError

CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_LIMIT = 16 * 1024 * 1024  # 1,807,090 bytes on 2026-10-24


class KevStatus(StrEnum):
    LISTED = "listed"
    NOT_LISTED = "not-listed"
    UNAVAILABLE = "unavailable"


def parse_catalog(data: object) -> dict[str, date]:
    """The catalog as ``{CVE ID: date added}``. The payload's own ``count`` must equal its
    records, and every record must carry a valid CVE ID and date, or nothing is trusted."""
    if not isinstance(data, dict):
        raise FeedError("the KEV catalog is not an object", site="kev.kev-catalog-not-object")
    records, count = data.get("vulnerabilities"), data.get("count")
    if not isinstance(records, list) or type(count) is not int or count != len(records):
        raise FeedError("the KEV catalog's count does not match its records", site="kev.kev-catalogs-count-does-not")
    catalog: dict[str, date] = {}
    for record in records:
        cve = record.get("cveID") if isinstance(record, dict) else None
        added = record.get("dateAdded") if isinstance(record, dict) else None
        if not (matches(Field.ADVISORY_ID, cve) and str(cve).startswith("CVE-") and matches(Field.DATE, added)):
            raise FeedError(
                "the KEV catalog has a record without a valid CVE ID and date",
                site="kev.kev-catalog-record-without-valid",
            )
        catalog[str(cve)] = date.fromisoformat(str(added))
    return catalog


class Kev:
    """KEV lookups for one run; the catalog is fetched on the first lookup that needs it."""

    def __init__(self, client: Client) -> None:
        self._client = client
        self._catalog: dict[str, date] | None = None
        self._failure: str | None = None

    @property
    def failure(self) -> str | None:
        """Why the catalog could not be read, once a lookup has needed it and failed."""
        return self._failure

    def status(self, advisory_ids: Iterable[str]) -> KevStatus:
        """Whether any CVE among ``advisory_ids`` is in the catalog."""
        cves = {i for i in advisory_ids if i.startswith("CVE-")}
        if not cves:
            return KevStatus.NOT_LISTED  # nothing KEV could list; no download needed
        catalog = self._load()
        if catalog is None:
            return KevStatus.UNAVAILABLE
        return KevStatus.LISTED if cves & catalog.keys() else KevStatus.NOT_LISTED

    def _load(self) -> dict[str, date] | None:
        if self._catalog is None and self._failure is None:
            try:
                response = self._client.get(CATALOG_URL, accept="application/json", limit=CATALOG_LIMIT)
                self._catalog = parse_catalog(response.json())
            except FeedError as exc:
                self._failure = str(exc)
        return self._catalog
