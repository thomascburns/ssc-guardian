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

"""Known vulnerabilities in Actions (plan §3.2 T6; §8 facts 28-30).

- **One batched request.** Every pin a run reads, in the workflows and nested, goes to
  GitHub's reviewed advisories for the ``actions`` ecosystem in one ``affects`` filter, as
  ``name@version``; GitHub matches the versions on its side (fact 29), ``v`` prefix included
  (checked 2026-11-03: ``tj-actions/changed-files@v45.0.7`` and ``@45.0.7`` both match
  GHSA-mrrh-fwg8-r2c3). One request holds up to 1,000 entries and stays under 7,000 bytes of
  URL (GitHub refuses a much longer one with 414, as #4's malware feed found), so only a very
  large repository needs a second.
- **Versions, not commits** (fact 30): a pin's versions are the release tags naming its
  commit (#142). For a pinned commit, outer or nested, and for the commit an inner moving
  reference names today, the tags asked about are every tag of the publisher naming the commit
  today (the repository's tags list, read once per run through ``nested.Commits.tags`` and
  shared by every call on that run's ``Commits``: this lookup, ``Commits.release_tags``; T4 for
  an inner pinned commit, ``Commits.verify``; and in ``pin`` the outer commit's T4 and release
  dating) plus the tag it was recorded or written under (the lock file's tag, the tag ``pin``
  is about to write, or an inner tag as written). An outer moving reference is asked about as
  written. Of those, a tag counts as a
  version only when it parses as PEP 440 after an optional leading ``v`` and has at least two
  release parts (``v4.1.3``, ``4.1``); a major or non-version tag (``v4``, ``stable``,
  ``latest``) names no release, so it is never sent, nor is a line tag (``v4.1``) that a
  longer plain release tag on the same commit extends (``v4.1.5``). A pin with no version is
  sent as the name alone.
- **A match** is ``known-vulnerability`` (exit 1), one finding per pin listing every advisory
  (D14), with the fixed version when every advisory names one. Where one Action is pinned at
  several versions in one run, or one advisory names several asked Actions, each pin's own match
  is read from the advisory's range; a range or version Guardian cannot read rules nothing out,
  and an answer whose ranges clear every asked version is taken as GitHub gave it: all of them.
- **No version:** if advisories exist for the Action, ``unreleased-pin-advisory``
  ("cannot rule out <IDs>; pin to a released version", exit 1). The note names every valid
  advisory ID (CVE, GHSA and so on); an advisory with none is named "an advisory GitHub listed
  without a valid ID" (#147).
- **Unfinished is never a pass:** an API error (403) or a rate limit stops the check (exit 2).

Known limit: after a tag-move compromise, advisories mark the genuine older commits that carry
the tag too; Guardian reports them and names the fix.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ssc_guardian.findings import Ecosystem, Finding, Label, Option, Rule, make_finding
from ssc_guardian.grammars import Field, MalformedValueError, matches
from ssc_guardian.net import Client, FeedError
from ssc_guardian.pep440 import Version, parse_specifiers, satisfies_all, try_parse
from ssc_guardian.plugins.actions.publisher import repository_key
from ssc_guardian.render import strip_controls

GHA = Ecosystem.GITHUB_ACTIONS
ADVISORIES_URL = "https://api.github.com/advisories"
ACCEPT = "application/vnd.github+json"
PER_PAGE = 100
MAX_PAGES = 20
MAX_AFFECTS = 1000  # plan §8 fact 29
MAX_URL_BYTES = 7000
PAGE_LIMIT = 8 * 1024 * 1024
_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
# How text names an advisory none of whose IDs passes the ``advisory-id`` grammar (D4).
UNNAMED = "an advisory GitHub listed without a valid ID"


def is_version(tag: str) -> bool:
    """Whether a tag names a release: PEP 440 after an optional leading ``v``, with at least
    two release parts. ``v4.1``, ``4.1.3`` and ``v1.0.0-rc1`` do; a major tag (``v4``, ``4``)
    names a line of releases that moves, and ``stable`` or ``latest`` no version at all."""
    version = try_parse(tag)
    return version is not None and len(version.release) >= 2


@dataclass(frozen=True)
class Pin:
    """One reference a run read. ``version`` is the finding's version (the pinned SHA, or a
    moving reference as written); ``tags`` are the tags naming the commit, of which
    :attr:`versions` are the ones T6 asks about."""

    place: str
    action: str
    version: str
    tags: tuple[str, ...]
    via: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return _action_key(self.action)

    @property
    def versions(self) -> tuple[str, ...]:
        """The tags that name a release (:func:`is_version`); empty means no version is known.

        A plain line tag (``v4.1``) is left out when a longer plain release tag naming the same
        commit extends it (``v4.1.5``, never a pre-release such as ``v4.1.0-rc.1``): the line
        tag floats with the newest patch, so read as
        4.1.0 it would flag the fixed release as vulnerable. The longer tag is the release the
        commit is, and it is still asked."""
        parsed: list[tuple[str, Version]] = []
        for tag in self.tags:
            version = try_parse(tag)
            if version is not None and is_version(tag):
                parsed.append((tag, version))

        def plain(version: Version) -> bool:
            return version.pre is None and version.post is None and version.dev is None and not version.local

        def floating(version: Version) -> bool:
            # Both must be plain releases: a pre-release (v4.1.0-rc.1) sorts before the line's
            # first release, so letting it stand for v4.1 could clear a vulnerable commit.
            return plain(version) and any(
                plain(o)
                and len(o.release) > len(version.release)
                and o.release[: len(version.release)] == version.release
                for _, o in parsed
            )

        return tuple(t for t, v in parsed if not floating(v))


def valid_ids(ids: Iterable[object]) -> tuple[str, ...]:
    """Those of ``ids`` that pass the ``advisory-id`` grammar (CVE, GHSA, MAL, PYSEC; D4),
    sorted and each once. Only these ever reach output: an ID GitHub sends is a value from the
    network, and a raw one could pose as a verdict or carry a line break."""
    return tuple(sorted({i for i in ids if isinstance(i, str) and matches(Field.ADVISORY_ID, i)}))


def advisory_name(ids: Iterable[object]) -> str:
    """How text output names one advisory: its grammar-checked IDs, else :data:`UNNAMED`."""
    return ", ".join(valid_ids(ids)) or UNNAMED


def _action_key(action: str) -> str:
    """The one spelling GitHub's advisories name an Action by: the repository, lowercased."""
    return repository_key("/".join(action.split("/")[:2]))


@dataclass(frozen=True)
class Entry:
    """What one advisory says about one Action (named in its one spelling)."""

    action: str
    vulnerable: str | None  # GitHub's ``vulnerable_version_range``, as given
    patched: str | None  # ``first_patched_version``


@dataclass(frozen=True)
class ActionAdvisory:
    id: str
    aliases: tuple[str, ...]
    entries: tuple[Entry, ...]

    def evidence(self) -> tuple[str, ...]:
        """The IDs output may show (CVE, GHSA, MAL, PYSEC; D4). None of them is a
        malformed-name violation (exit 1), never a dropped advisory."""
        ids = valid_ids((self.id, *self.aliases))
        if not ids:
            raise MalformedValueError(Field.ADVISORY_ID, self.id, site="advisories.malformed-advisory-id")
        return ids

    @property
    def name(self) -> str:
        """How text output names the advisory (:func:`advisory_name`); never the raw ``id``."""
        return advisory_name((self.id, *self.aliases))


# --- the request ----------------------------------------------------------------------


def queries(pins: Iterable[Pin]) -> list[str]:
    """What the ``affects`` filter names: ``name@version`` for each version, else the name."""
    found: set[str] = set()
    for pin in pins:
        found.update([f"{pin.key}@{tag}" for tag in pin.versions] or [pin.key])
    return sorted(found)


def url(items: Sequence[str]) -> str:
    query = urllib.parse.urlencode({"type": "reviewed", "ecosystem": "actions", "per_page": str(PER_PAGE)})
    return f"{ADVISORIES_URL}?{query}&affects={','.join(urllib.parse.quote(i, safe='') for i in items)}"


def batches(items: Sequence[str]) -> list[list[str]]:
    """``items`` in as few requests as the 1,000-entry and URL-length limits allow."""
    found: list[list[str]] = []
    for item in items:
        if found and len(found[-1]) < MAX_AFFECTS and len(url([*found[-1], item])) <= MAX_URL_BYTES:
            found[-1].append(item)
        else:
            found.append([item])
    return found


def parse_advisory(data: object) -> ActionAdvisory | None:
    """An advisory's IDs and its ``actions`` entries; None once withdrawn."""
    if not isinstance(data, dict):
        raise FeedError(
            "GitHub sent an advisory that is not an object", site="advisories.github-sent-advisory-not-object"
        )
    ghsa_id, vulnerabilities = data.get("ghsa_id"), data.get("vulnerabilities")
    if not isinstance(ghsa_id, str) or not ghsa_id or not isinstance(vulnerabilities, list):
        raise FeedError(
            "GitHub sent an advisory without its ID or vulnerabilities",
            site="advisories.github-sent-advisory-without-id",
        )
    if data.get("withdrawn_at") is not None:
        return None
    aliases = [data.get("cve_id")]
    identifiers = data.get("identifiers")
    aliases += [i.get("value") for i in identifiers if isinstance(i, dict)] if isinstance(identifiers, list) else []
    named = advisory_name((ghsa_id, *aliases))  # for the messages below: never the raw ID (D4)
    entries: list[Entry] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise FeedError(
                f"GitHub sent {named} with a vulnerability that is not an object",
                site="advisories.vulnerability-not-object",
            )
        package = vulnerability.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != "actions":
            continue
        name = package.get("name")
        if not isinstance(name, str) or not matches(Field.ACTION, name):
            raise FeedError(
                f"GitHub sent {named} for an Action whose name is not valid",
                site="advisories.action-whose-name-not-valid",
            )
        vulnerable, patched = vulnerability.get("vulnerable_version_range"), vulnerability.get("first_patched_version")
        entries.append(
            Entry(
                _action_key(name),
                vulnerable if isinstance(vulnerable, str) else None,
                patched if isinstance(patched, str) and matches(Field.GIT_REF, patched) else None,
            )
        )
    return ActionAdvisory(ghsa_id, tuple(a for a in aliases if isinstance(a, str) and a != ghsa_id), tuple(entries))


def _pages(client: Client, first: str) -> list[ActionAdvisory]:
    found: list[ActionAdvisory] = []
    next_url: str | None = first
    for _ in range(MAX_PAGES):
        if next_url is None:
            return found
        if not next_url.startswith(ADVISORIES_URL + "?"):
            raise FeedError(
                "GitHub's next-page link leaves the advisories API", site="advisories.githubs-next-page-link-leaves"
            )
        try:
            response = client.get(next_url, accept=ACCEPT, limit=PAGE_LIMIT)
        except ValueError as exc:  # a next-page link the client refuses
            raise FeedError(
                "GitHub's next-page link is not a URL Guardian sends", site="advisories.githubs-next-page-link-not"
            ) from exc
        page = response.json()
        if not isinstance(page, list):
            raise FeedError(
                "GitHub sent advisories that are not a list", site="advisories.github-sent-advisories-not-list"
            )
        found += [a for a in (parse_advisory(item) for item in page) if a is not None]
        link = _NEXT.search(response.headers.get("link", ""))
        if link is None and len(page) >= PER_PAGE:
            raise FeedError(
                "GitHub sent a full page of advisories without a next-page link",
                site="advisories.github-sent-full-page-advisories",
            )
        next_url = link.group(1) if link else None
    if next_url is not None:
        raise FeedError("GitHub sent too many pages of advisories", site="advisories.github-sent-too-many-pages")
    return found


def fetch(client: Client, pins: Iterable[Pin]) -> tuple[ActionAdvisory, ...]:
    """The reviewed advisories for every pin, each once, in ID order; nothing is asked when
    there is no pin. An advisory naming no asked Action is a feed failure, never dropped."""
    pins = tuple(pins)
    items = queries(pins)
    by_id: dict[str, ActionAdvisory] = {}
    for batch in batches(items):
        for advisory in _pages(client, url(batch)):
            by_id.setdefault(advisory.id, advisory)
    asked = {pin.key for pin in pins}
    for advisory in by_id.values():
        if not any(entry.action in asked for entry in advisory.entries):
            raise FeedError(
                f"GitHub returned {advisory.name}, but none of its entries names an asked Action",
                site="advisories.but-none-entries-names-asked",
            )
    return tuple(by_id[i] for i in sorted(by_id))


# --- matching -------------------------------------------------------------------------


def _in_range(tags: Iterable[str], vulnerable: str | None) -> bool:
    """Whether a tag falls in the range; a range or tag that cannot be read rules nothing out."""
    if vulnerable is None:
        return True
    try:
        specifiers = parse_specifiers(vulnerable)
    except ValueError:
        return True
    versions = [v for v in (try_parse(t) for t in tags) if v is not None]
    return not versions or any(satisfies_all(v, specifiers) for v in versions)


@dataclass(frozen=True)
class Hit:
    """A pin and the advisories that name it: ``known-vulnerability`` for a released pin,
    ``unreleased-pin-advisory`` for one with no version."""

    pin: Pin
    rule: Rule
    advisories: tuple[ActionAdvisory, ...]
    patched: str | None = None  # the fixed version, when every advisory names one

    @property
    def evidence(self) -> tuple[str, ...]:
        return tuple(sorted({i for a in self.advisories for i in a.evidence()}))


def _fixed(entries: Sequence[Entry]) -> str | None:
    """The newest first-patched version among ``entries``; None if one names none or cannot be read."""
    versions = []
    for entry in entries:
        version = try_parse(entry.patched) if entry.patched is not None else None
        if entry.patched is None or version is None:
            return None
        versions.append((version, entry.patched))
    return max(versions, key=lambda pair: pair[0])[1] if versions else None


def match(pins: Sequence[Pin], advisories: Iterable[ActionAdvisory]) -> list[Hit]:
    """Which pins the advisories name, one :class:`Hit` per pin, in the pins' order."""
    asked_versions: dict[str, set[str]] = {}
    name_only: set[str] = set()
    for pin in pins:
        if pin.versions:
            asked_versions.setdefault(pin.key, set()).update(pin.versions)
        else:
            name_only.add(pin.key)
    named: dict[int, list[tuple[ActionAdvisory, Entry]]] = {}
    for advisory in advisories:
        asked = [a for a in dict.fromkeys(e.action for e in advisory.entries) if a in asked_versions or a in name_only]
        # GitHub's answer says some asked item matched. It is about one exact version only when
        # the advisory names one asked Action, asked at one version and never by name alone.
        single = len(asked) == 1
        matched: dict[int, list[Entry]] = {}
        for action in asked:
            entries = [e for e in advisory.entries if e.action == action]
            group = [n for n, pin in enumerate(pins) if pin.key == action]
            exact = single and action not in name_only and len(asked_versions.get(action, ())) == 1
            for n in group:
                versions = pins[n].versions
                if not versions or exact or any(_in_range(versions, e.vulnerable) for e in entries):
                    matched[n] = entries
        if not matched and not any(a in name_only for a in asked):
            # GitHub matched one of the asked versions; which one cannot be told, so all count.
            matched = {
                n: [e for e in advisory.entries if e.action == pin.key]
                for n, pin in enumerate(pins)
                if pin.key in asked
            }
        for n, entries in matched.items():
            named.setdefault(n, []).extend((advisory, e) for e in entries)
    hits: list[Hit] = []
    for n in sorted(named):
        pin = pins[n]
        found = named[n]
        unique = tuple({a.id: a for a, _ in found}.values())
        if pin.versions:
            hits.append(Hit(pin, Rule.KNOWN_VULNERABILITY, unique, _fixed([e for _, e in found])))
        else:
            hits.append(Hit(pin, Rule.UNRELEASED_PIN_ADVISORY, unique))
    return hits


def finding(hit: Hit, *, labels: Iterable[Label] = (), options: Iterable[Option] = ()) -> Finding:
    pin = hit.pin
    return make_finding(
        hit.rule,
        GHA,
        place=pin.place,
        item=pin.action,
        version=pin.version,
        evidence=hit.evidence,
        labels=labels,
        options=options,
        via=pin.via,
        site="advisories.advisory-hit",
    )


def describe(hit: Hit) -> str:
    """What the text output says about one hit (stderr; never JSON): one line, which names the
    advisories only by their grammar-checked IDs (:func:`valid_ids`, the IDs
    :meth:`ActionAdvisory.evidence` gives), each once, and an advisory with none by
    :data:`UNNAMED`. Every other value is stripped of line breaks and controls."""
    pin = hit.pin
    where = " -> ".join(strip_controls(step) for step in (*pin.via, f"{pin.action}@{pin.version}"))
    named = valid_ids(i for a in hit.advisories for i in (a.id, *a.aliases))
    unnamed = any(not valid_ids((a.id, *a.aliases)) for a in hit.advisories)
    ids = ", ".join([*named, *([UNNAMED] if unnamed else [])])
    if hit.rule is Rule.UNRELEASED_PIN_ADVISORY:
        return f"{where}: cannot rule out {ids}; pin to a released version"
    fixed = f"; fixed in {strip_controls(hit.patched)}" if hit.patched else "; no fixed version is named"
    versions = ", ".join(strip_controls(v) for v in pin.versions)
    return f"{where} ({versions}): {ids}{fixed}"
