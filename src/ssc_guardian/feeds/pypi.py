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

"""PyPI: upload times, quarantine and file digests, from the Simple API's JSON form.

The Simple API is what pip reads, so the upload times here are the ones pip's own cooldown
compares. One ``GET https://pypi.org/simple/{name}/`` gives the project's PEP 792 status, its
PEP 700 version list and each file's upload time, SHA-256 digest, yanked state and
``requires-python`` (§8 fact 36); a wheel's tags come from its name (PEP 427). Only files served
from ``files.pythonhosted.org`` over HTTPS are kept. A project PyPI does not have is reported as
not found, never as clean; any failed request raises :class:`~ssc_guardian.net.FeedError`
(exit 2).
"""

from __future__ import annotations

import itertools
import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from ssc_guardian.grammars import normalize_pypi_name
from ssc_guardian.net import Client, FeedError
from ssc_guardian.pep440 import Version, canonical_of, try_parse

SIMPLE_URL = "https://pypi.org/simple/"
ACCEPT = "application/vnd.pypi.simple.v1+json"
FILES_HOST = "files.pythonhosted.org"
PROJECT_LIMIT = 32 * 1024 * 1024  # numpy's page was 2,828,138 bytes (2026-10-26)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TAG_PIECE = re.compile(r"[A-Za-z0-9_]+", re.ASCII)  # one tag of a PEP 425 set
_SDIST_SUFFIXES = (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz")
_WHEEL_SUFFIX = ".whl"
_WHEEL_PARTS = (5, 6)  # PEP 427: name, version, an optional build tag, then the three tags
TAG_LIMIT = 64  # the widest of 48,747 real wheels expanded to 6 (2026-11-05); keeps a hostile name cheap


class ProjectStatus(StrEnum):
    """PEP 792 project status; no status given means active."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class DistFile:
    filename: str
    url: str
    sha256: str | None
    uploaded: datetime | None  # aware, UTC
    yanked: bool
    requires_python: object = None  # as PyPI sent it; None when PyPI gives none
    tags: frozenset[tuple[str, str, str]] | None = None  # None for a non-wheel or an unreadable name

    @property
    def sdist(self) -> bool:
        """Whether the file is a source distribution: pip can build one for any Python."""
        return self.filename.endswith(_SDIST_SUFFIXES)


@dataclass(frozen=True)
class Release:
    version: Version
    files: tuple[DistFile, ...] = ()

    @property
    def yanked(self) -> bool:
        """PEP 592: a release is yanked when every one of its files is."""
        return bool(self.files) and all(f.yanked for f in self.files)

    @property
    def first_wheel_upload(self) -> datetime | None:
        """The earliest upload time of a wheel that is not yanked: when ``install`` (wheels
        only, uploaded before its cutoff) can first see the release."""
        return min(
            (f.uploaded for f in self.files if f.filename.endswith(".whl") and not f.yanked and f.uploaded),
            default=None,
        )

    @property
    def first_upload(self) -> datetime | None:
        """The earliest upload time PyPI gives for the release's files, or None."""
        return min((f.uploaded for f in self.files if f.uploaded is not None), default=None)


@dataclass(frozen=True)
class Project:
    """One PyPI project. ``found`` is False when PyPI answered 404."""

    name: str  # PEP 503 form
    found: bool
    status: ProjectStatus | None = None
    releases: dict[str, Release] = field(default_factory=dict)  # by canonical version

    def release(self, version: Version) -> Release | None:
        return self.releases.get(canonical_of(version))

    def digest(self, filename: str) -> str | None:
        """PyPI's SHA-256 for one file of the project, or None if PyPI gives none."""
        return next((f.sha256 for r in self.releases.values() for f in r.files if f.filename == filename), None)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def file_version(project: str, filename: str) -> Version | None:
    """The version a distribution file holds, read from its name; None if it cannot be read.

    Wheels and eggs carry the version as the second ``-`` part. An sdist's name may itself
    hold ``-``, so the split is tried at each ``-`` until the part before it is the project.
    """
    if filename.endswith((".whl", ".egg")):
        parts = filename.rsplit(".", 1)[0].split("-")
        return try_parse(parts[1]) if len(parts) >= 3 and _norm(parts[0]) == project else None
    suffix = next((s for s in _SDIST_SUFFIXES if filename.endswith(s)), None)
    if suffix is None:
        return None
    stem = filename[: -len(suffix)]
    for index, char in enumerate(stem):
        if char == "-" and _norm(stem[:index]) == project:
            return try_parse(stem[index + 1 :])
    return None


def wheel_tags(filename: str) -> frozenset[tuple[str, str, str]] | None:
    """The ``(python, abi, platform)`` tags a wheel's name gives (PEP 427: the last three of its
    5 or 6 ``-`` parts, each a ``.``-joined set); None for any other file or a name that cannot
    be read."""
    if not filename.endswith(_WHEEL_SUFFIX):
        return None
    parts = filename[: -len(_WHEEL_SUFFIX)].split("-")
    if len(parts) not in _WHEEL_PARTS:
        return None
    return _expand(*parts[-3:])


def _expand(python: str, abi: str, platform: str) -> frozenset[tuple[str, str, str]] | None:
    """Every ``(python, abi, platform)`` tag a compressed tag set stands for (PEP 425: each part a
    ``.``-joined set); None when that is more than :data:`TAG_LIMIT` tags."""
    pythons, abis, platforms = python.split("."), abi.split("."), platform.split(".")
    if len(pythons) * len(abis) * len(platforms) > TAG_LIMIT:
        return None
    return frozenset(itertools.product(pythons, abis, platforms))


def record_tags(lines: Iterable[str]) -> frozenset[tuple[str, str, str]] | None:
    """The tags an installed wheel's ``WHEEL`` file gives in its ``Tag`` values (PEP 427), or None
    when it gives none, any one cannot be read, or they come to more than :data:`TAG_LIMIT`.

    The file came inside the wheel, so whoever uploaded the wheel wrote it: it is a claim, not a
    fact, and is trusted only where Guardian knows nothing better (#230)."""
    tags: set[tuple[str, str, str]] = set()
    for line in lines:
        parts = line.strip().split("-")
        readable = len(parts) == 3 and all(_TAG_PIECE.fullmatch(piece) for part in parts for piece in part.split("."))
        expanded = _expand(*parts) if readable else None
        if expanded is None:
            return None
        tags |= expanded
        if len(tags) > TAG_LIMIT:
            return None
    return frozenset(tags) or None


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
        utc = moment.astimezone(UTC) if moment.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None
    # A time no upload can have (far in the future) is no time: the age is then unknown.
    return utc if utc is not None and utc.year < 9000 else None


def _file(entry: object) -> DistFile | None:
    if not isinstance(entry, dict):
        return None
    filename, url = entry.get("filename"), entry.get("url")
    if not isinstance(filename, str) or not isinstance(url, str):
        return None
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.netloc != FILES_HOST or not url.isascii():
        return None
    hashes = entry.get("hashes")
    sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
    yanked = entry.get("yanked", False)
    return DistFile(
        filename=filename,
        url=url,
        sha256=sha256 if isinstance(sha256, str) and _SHA256.fullmatch(sha256) else None,
        uploaded=_time(entry.get("upload-time")),
        yanked=bool(yanked),  # PEP 592: true, or a non-empty reason
        requires_python=entry.get("requires-python"),
        tags=wheel_tags(filename),
    )


def parse_project(data: object, name: str) -> Project:
    """A Simple API JSON page as a :class:`Project` for ``name`` (PEP 503 form)."""
    if not isinstance(data, dict) or not isinstance(data.get("meta"), dict) or not isinstance(data.get("files"), list):
        raise FeedError(f"PyPI sent an unexpected page for {name}", site="pypi.pypi-sent-unexpected-page")
    raw_status = data.get("project-status")
    raw = raw_status.get("status", "active") if isinstance(raw_status, dict) else raw_status
    try:
        status = ProjectStatus("active" if raw is None else raw)
    except ValueError:
        raise FeedError(
            f"PyPI gives {name} a project status Guardian does not know", site="pypi.project-status-guardian-does-not"
        ) from None
    files: dict[str, list[DistFile]] = {}
    versions: dict[str, Version] = {}
    listed_versions = data.get("versions", [])
    if not isinstance(listed_versions, list):
        raise FeedError(f"PyPI sent a version list for {name} that is not a list", site="pypi.pypi-sent-version-list")
    for listed in listed_versions:
        if (version := try_parse(listed)) is not None:
            versions.setdefault(canonical_of(version), version)
    for entry in data["files"]:
        dist = _file(entry)
        version = file_version(name, dist.filename) if dist is not None else None
        if dist is None or version is None:
            continue
        key = canonical_of(version)
        versions.setdefault(key, version)
        files.setdefault(key, []).append(dist)
    releases = {key: Release(version, tuple(files.get(key, ()))) for key, version in versions.items()}
    return Project(name, True, status, releases)


def project(client: Client, name: str) -> Project:
    """The PyPI project for ``name``: status, releases, upload times and digests."""
    wanted = normalize_pypi_name(name)
    url = SIMPLE_URL + urllib.parse.quote(wanted, safe="") + "/"
    response = client.get(url, accept=ACCEPT, limit=PROJECT_LIMIT, allow=frozenset({404}))
    if response.status == 404:
        return Project(wanted, False)
    return parse_project(response.json(), wanted)
