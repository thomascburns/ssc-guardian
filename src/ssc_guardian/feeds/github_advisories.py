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

"""GitHub's malware advisories for PyPI packages (plan §3.1, §10.3).

One ``GET /advisories?type=malware&ecosystem=pip&affects=...`` names many packages at once,
in batches that keep each URL under 7,000 bytes (GitHub refused a 26,079-byte URL with 414),
and pages are followed only while they stay on ``api.github.com``. Each advisory's
``vulnerable_version_range`` is matched here with the standard-library PEP 440 order. With
OSV's ``MAL-`` records this is one lineage, the OpenSSF malicious-packages data, so the two
never count as independent signals (plan §10.3). Requests are GET only and carry the token
(:mod:`ssc_guardian.net`).
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass

from ssc_guardian.feeds import Advisory, Affected, Source, merge
from ssc_guardian.grammars import Field, matches, normalize_pypi_name
from ssc_guardian.net import Client, FeedError
from ssc_guardian.pep440 import Operator, Specifier, Version, parse, parse_specifiers, satisfies_all

ADVISORIES_URL = "https://api.github.com/advisories"
ACCEPT = "application/vnd.github+json"
PER_PAGE = 100
MAX_PAGES = 20
MAX_URL_BYTES = 7000
PAGE_LIMIT = 8 * 1024 * 1024
_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_ZERO = parse("0")


def _url(names: list[str]) -> str:
    query = urllib.parse.urlencode({"type": "malware", "ecosystem": "pip", "per_page": str(PER_PAGE)})
    return f"{ADVISORIES_URL}?{query}&affects={','.join(urllib.parse.quote(n, safe='') for n in names)}"


def _batches(names: list[str]) -> list[list[str]]:
    batches: list[list[str]] = []
    for name in names:
        if batches and len(_url([*batches[-1], name])) <= MAX_URL_BYTES:
            batches[-1].append(name)
        else:
            batches.append([name])
    return batches


@dataclass(frozen=True)
class SpecifierRange:
    """A GitHub ``vulnerable_version_range``: every comparison must hold."""

    specifiers: tuple[Specifier, ...]

    def contains(self, version: Version) -> bool:
        return satisfies_all(version, self.specifiers)


def _affected(vulnerability: object) -> Affected | None:
    if not isinstance(vulnerability, dict):
        return None
    package = vulnerability.get("package")
    if not isinstance(package, dict) or package.get("ecosystem") != "pip":
        return None
    raw_name = package.get("name")
    if not matches(Field.PYPI_NAME, raw_name):
        return None
    name = normalize_pypi_name(str(raw_name))
    spec = vulnerability.get("vulnerable_version_range")
    if spec is None:
        return Affected(name)  # names no version: cannot rule one out
    try:
        specifiers = parse_specifiers(spec) if isinstance(spec, str) else None
    except ValueError:
        specifiers = None
    if specifiers is None:
        return Affected(name, unreadable=True)
    if all(s.operator is Operator.GE and s.version == _ZERO for s in specifiers):
        return Affected(name, every_version=True)
    return Affected(name, ranges=(SpecifierRange(specifiers),))


def parse_advisory(data: object) -> Advisory | None:
    """A GitHub advisory as an :class:`Advisory`; None when withdrawn or not malware."""
    if not isinstance(data, dict):
        raise FeedError(
            "GitHub sent an advisory that is not an object", site="github_advisories.github-sent-advisory-not-object"
        )
    ghsa_id = data.get("ghsa_id")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(ghsa_id, str) or not ghsa_id or not isinstance(vulnerabilities, list):
        raise FeedError(
            "GitHub sent an advisory without its ID or vulnerabilities",
            site="github_advisories.github-sent-advisory-without-id",
        )
    if data.get("withdrawn_at") is not None or data.get("type") != "malware":
        return None
    aliases = [data.get("cve_id")]
    identifiers = data.get("identifiers")
    aliases += [i.get("value") for i in identifiers if isinstance(i, dict)] if isinstance(identifiers, list) else []
    return Advisory(
        id=ghsa_id,
        aliases=tuple(a for a in aliases if isinstance(a, str) and a != ghsa_id),
        source=Source.GITHUB,
        malicious=True,
        affected=tuple(a for a in (_affected(v) for v in vulnerabilities) if a is not None),
    )


def _pages(client: Client, url: str) -> list[Advisory]:
    found: list[Advisory] = []
    next_url: str | None = url
    for _ in range(MAX_PAGES):
        if next_url is None:
            return found
        if not next_url.startswith(ADVISORIES_URL + "?"):
            raise FeedError(
                "GitHub's next-page link leaves the advisories API",
                site="github_advisories.githubs-next-page-link-leaves",
            )
        try:
            response = client.get(next_url, accept=ACCEPT, limit=PAGE_LIMIT)
        except ValueError as exc:  # a next-page link the client refuses
            raise FeedError(
                "GitHub's next-page link is not a URL Guardian sends",
                site="github_advisories.githubs-next-page-link-not",
            ) from exc
        page = response.json()
        if not isinstance(page, list):
            raise FeedError(
                "GitHub sent advisories that are not a list", site="github_advisories.github-sent-advisories-not-list"
            )
        found += [a for a in (parse_advisory(item) for item in page) if a is not None]
        link = _NEXT.search(response.headers.get("link", ""))
        if link is None and len(page) >= PER_PAGE:
            raise FeedError(
                "GitHub sent a full page of advisories without a next-page link",
                site="github_advisories.github-sent-full-page-advisories",
            )
        next_url = link.group(1) if link else None
    if next_url is not None:
        raise FeedError("GitHub sent too many pages of advisories", site="github_advisories.github-sent-too-many-pages")
    return found


def malware(client: Client, names: Iterable[str]) -> dict[str, tuple[Advisory, ...]]:
    """GitHub's malware advisories for each PyPI name, keyed by its PEP 503 form.

    An advisory is listed under a name only if one of its entries names that package; each
    name's advisories come in ID order, each once, so a re-run gives equal answers. An advisory
    whose entries name none of the queried packages is a feed failure, never dropped.
    """
    wanted = sorted({normalize_pypi_name(name) for name in names})
    advisories: list[Advisory] = []
    for batch in _batches(wanted):
        advisories += _pages(client, _url(batch))
    unique = merge(tuple(advisories))
    for advisory in unique:
        if not any(entry.name in wanted for entry in advisory.affected):
            raise FeedError(
                f"GitHub returned {advisory.id}, but none of its entries names a queried package",
                site="github_advisories.but-none-entries-names-queried",
            )
    return {name: tuple(a for a in unique if any(entry.name == name for entry in a.affected)) for name in wanted}
