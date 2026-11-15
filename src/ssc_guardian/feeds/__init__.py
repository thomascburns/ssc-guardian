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

"""Threat feeds (plan §3.1, §10.3) and the advisory shape they share.

The feed modules (:mod:`.osv`, :mod:`.github_advisories`, :mod:`.pypi`, :mod:`.kev`) report
facts read through :class:`ssc_guardian.net.Client`; :mod:`ssc_guardian.policy` applies the
rules. An advisory keeps no free text from a feed (no summary or details), so attacker-written
text never reaches output. A withdrawn advisory is dropped by the feed reader (plan §10.3).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Protocol

from ssc_guardian.grammars import Field, MalformedValueError, matches
from ssc_guardian.pep440 import Version


class Source(StrEnum):
    OSV = "osv"
    GITHUB = "github"


class Match(IntEnum):
    """How an advisory names a version; a higher value is a more specific claim."""

    UNVERSIONED = 1  # the advisory names the package but gives no version at all
    UNREADABLE = 2  # it names versions, but in a form Guardian cannot read: none is ruled out
    VERSION = 3  # a listed version, or a range that holds it
    WHOLE_PACKAGE = 4  # every version (OSV ``introduced: 0`` with no end; GitHub ``>= 0``)


class VersionRange(Protocol):
    def contains(self, version: Version) -> bool: ...


@dataclass(frozen=True)
class Affected:
    """What one advisory says about one package (``name`` in its PEP 503 form).

    ``unreadable`` is set when a range held a version Guardian cannot parse: such an entry
    cannot rule any version out.
    """

    name: str
    versions: frozenset[Version] = frozenset()
    ranges: tuple[VersionRange, ...] = ()
    every_version: bool = False
    unreadable: bool = False

    def match(self, version: Version) -> Match | None:
        if self.every_version:
            return Match.WHOLE_PACKAGE
        public = version.public
        if any(listed.public == public for listed in self.versions) or any(r.contains(public) for r in self.ranges):
            return Match.VERSION
        if self.unreadable:
            return Match.UNREADABLE
        if not (self.versions or self.ranges):
            return Match.UNVERSIONED
        return None


@dataclass(frozen=True)
class Advisory:
    """One advisory record as a feed served it, without its free text."""

    id: str
    aliases: tuple[str, ...]
    source: Source
    malicious: bool
    affected: tuple[Affected, ...]

    def match(self, name: str, version: Version) -> Match | None:
        """The most specific way this advisory names ``version`` of ``name`` (PEP 503 form)."""
        found = [m for a in self.affected if a.name == name and (m := a.match(version)) is not None]
        return max(found, default=None)

    def evidence(self) -> tuple[str, ...]:
        """The advisory's IDs that output may show: CVE, GHSA, MAL and PYSEC only (D4).

        IDs of any other type are dropped. An advisory with none of the four raises
        :class:`~ssc_guardian.grammars.MalformedValueError` for its own ID, so it becomes a
        malformed-name violation (exit 1) and is never dropped.
        """
        ids = sorted({i for i in (self.id, *self.aliases) if matches(Field.ADVISORY_ID, i)})
        if not ids:
            raise MalformedValueError(Field.ADVISORY_ID, self.id, site="feeds.malformed-advisory-id")
        return tuple(ids)


def merge(*groups: tuple[Advisory, ...]) -> tuple[Advisory, ...]:
    """Advisories from several answers, each ID once, in ID order (a re-run gives the same list)."""
    by_id: dict[tuple[Source, str], Advisory] = {}
    for group in groups:
        for advisory in group:
            by_id.setdefault((advisory.source, advisory.id), advisory)
    return tuple(by_id[key] for key in sorted(by_id))
