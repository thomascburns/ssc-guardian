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

"""Bind each file pip would install to PyPI's published digest (plan §3.1 step 5; facts 7, 36).

pip's ``--dry-run --report`` names, for every distribution it would install, the file's URL
and its SHA-256 (``download_info.archive_info``). A file is bound only if it is a wheel
served from ``files.pythonhosted.org`` (the files host of :class:`Endpoints`), is not a
direct reference, carries the name and version pip resolved, and its SHA-256 equals the
digest PyPI publishes for that exact file name in that project. Anything else refuses the
whole request: Guardian never installs a file it did not check and bind. The report is read
strictly; an entry or a field it does not expect is a refusal, never skipped.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from ssc_guardian.feeds import pypi
from ssc_guardian.findings import Ecosystem, IncompleteCheckError, SkipReason
from ssc_guardian.grammars import normalize_pypi_name
from ssc_guardian.pep440 import canonical_of, try_parse
from ssc_guardian.plugin import DigestAlgorithm, Item, PlannedFile

REPORT_VERSION = "1"
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Endpoints:
    """Where pip reads the index and where every bound file must come from. Always PyPI;
    only tests name a local server (the plan forbids an ``--index-url`` option, §3.1)."""

    index_url: str = "https://pypi.org/simple"
    files_origin: str = f"https://{pypi.FILES_HOST}"


PYPI_ENDPOINTS = Endpoints()


class BindingError(IncompleteCheckError):
    """A file pip would install cannot be bound to PyPI's digest: nothing is installed (exit 2)."""

    def __init__(self, message: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.message = message

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class Reported:
    """One distribution pip's report says it would install."""

    name: str
    version: str
    url: str
    sha256: str | None
    is_direct: bool
    requested: bool


def read_report(data: object) -> tuple[Reported, ...]:
    """The ``install`` entries of pip's installation report (format version 1)."""
    if not isinstance(data, dict) or data.get("version") != REPORT_VERSION or not isinstance(data.get("install"), list):
        raise BindingError(
            "pip's report is not an installation report Guardian reads",
            site="binding.pips-report-not-installation-report",
        )
    entries: list[Reported] = []
    for entry in data["install"]:
        metadata = entry.get("metadata") if isinstance(entry, dict) else None
        info = entry.get("download_info") if isinstance(entry, dict) else None
        if not isinstance(metadata, dict) or not isinstance(info, dict):
            raise BindingError(
                "pip's report has an entry without metadata or download information",
                site="binding.pips-report-entry-without-metadata",
            )
        name, version, url = metadata.get("name"), metadata.get("version"), info.get("url")
        archive = info.get("archive_info")
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not (isinstance(name, str) and isinstance(version, str) and isinstance(url, str)):
            raise BindingError(
                "pip's report has an entry without a name, version or URL",
                site="binding.pips-report-entry-without-name",
            )
        entries.append(
            Reported(
                name=name,
                version=version,
                url=url,
                sha256=sha256 if isinstance(sha256, str) else None,
                is_direct=entry.get("is_direct") is not False,
                requested=entry.get("requested") is True,
            )
        )
    return tuple(entries)


def bind(
    entries: tuple[Reported, ...],
    projects: Mapping[str, pypi.Project],
    *,
    target: str,
    endpoints: Endpoints = PYPI_ENDPOINTS,
) -> tuple[PlannedFile, ...]:
    """Each reported file bound to PyPI's digest, as the planned file :meth:`apply` installs.

    ``projects`` holds PyPI's facts for every reported name (PEP 503 form). The planned file
    names PyPI's own URL for the file, so the plan records where PyPI says it lives.
    """
    files: list[PlannedFile] = []
    seen: set[str] = set()
    for entry in entries:
        key = normalize_pypi_name(entry.name)
        if key in seen:
            raise BindingError(f"pip's report names {entry.name} twice", site="binding.report-names-twice")
        seen.add(key)
        files.append(_bound(entry, projects.get(key), target, endpoints))
    return tuple(files)


def _bound(entry: Reported, project: pypi.Project | None, target: str, endpoints: Endpoints) -> PlannedFile:
    what = f"{entry.name} {entry.version}"
    if entry.is_direct:
        raise BindingError(
            f"{what} is a direct reference, not a file from PyPI", site="binding.direct-reference-not-file-pypi"
        )
    try:
        parts = urllib.parse.urlsplit(entry.url)
    except ValueError:
        raise BindingError(f"{what}: pip's URL for it cannot be read", site="binding.pips-url-cannot-read") from None
    if f"{parts.scheme}://{parts.netloc}" != endpoints.files_origin or parts.query or parts.fragment:
        raise BindingError(
            f"{what} would come from {parts.netloc or 'an unknown place'}, not {pypi.FILES_HOST}",
            site="binding.not-from-pypi-files-host",
        )
    filename = urllib.parse.unquote(parts.path.rsplit("/", 1)[-1])
    if not filename.endswith(".whl"):
        raise BindingError(f"{what}: {filename} is not a wheel", site="binding.not-wheel")
    version, wanted = pypi.file_version(normalize_pypi_name(entry.name), filename), try_parse(entry.version)
    if version is None or wanted is None or canonical_of(version) != canonical_of(wanted):
        raise BindingError(
            f"{what}: the file {filename} does not hold that name and version",
            site="binding.does-not-hold-name-version",
        )
    if entry.sha256 is None or not _SHA256.fullmatch(entry.sha256):
        raise BindingError(
            f"{what}: pip's report gives no SHA-256 for {filename}", site="binding.pips-report-gives-no-sha"
        )
    if project is None or not project.found:
        raise BindingError(
            f"{what}: PyPI's digests for it could not be read", site="binding.pypis-digests-could-not-read"
        )
    published = _published(project, filename)
    if published is None or published.sha256 is None:
        raise BindingError(
            f"{what}: PyPI publishes no SHA-256 for {filename}", site="binding.pypi-publishes-no-sha-256"
        )
    if published.sha256 != entry.sha256:
        raise BindingError(
            f"{what}: {filename} does not match the SHA-256 PyPI publishes for it",
            site="binding.does-not-match-sha-256",
        )
    if not published.url.startswith("https://") or any(ch.isspace() or not ch.isprintable() for ch in published.url):
        # The planned file names PyPI's own URL, which it holds to these terms (#228).
        raise BindingError(
            f"{what}: PyPI's URL for {filename} is not an HTTPS URL without spaces or controls",
            site="binding.pypi-file-url-not-plain",
        )
    item = Item(Ecosystem.PYPI, entry.name, entry.version, target)
    return PlannedFile(item, published.url, DigestAlgorithm.SHA256, published.sha256)


def _published(project: pypi.Project, filename: str) -> pypi.DistFile | None:
    """The file PyPI publishes under ``filename`` with a SHA-256, in any of the project's releases."""
    return next((f for r in project.releases.values() for f in r.files if f.filename == filename and f.sha256), None)


def uploaded(planned: PlannedFile, projects: Mapping[str, pypi.Project]) -> datetime | None:
    """When PyPI says the bound file ``planned`` was uploaded (aware, UTC), or None when PyPI
    gives no time for it or the file is no longer found: the file's own age, which ``install``
    holds to its package's cooldown (#129), not its release's earliest upload."""
    project = projects.get(normalize_pypi_name(planned.item.name))
    if project is None or not project.found:
        return None
    filename = urllib.parse.unquote(urllib.parse.urlsplit(planned.url).path.rsplit("/", 1)[-1])
    published = _published(project, filename)
    if published is None or published.url != planned.url or published.sha256 != planned.digest:
        return None
    return published.uploaded
