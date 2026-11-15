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

"""PEP 610 ``direct_url.json``: what an installer recorded about where a distribution came from.

The one reader, shared by ``--version`` (:mod:`.version`, the Git commit of a Git install) and
``check --envs`` (:func:`.discovery.local_install`, a local folder). The file belongs to the
distribution, so what it says is a claim: nothing here decides that a claim is true.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ssc_guardian.findings import record_site

DIRECT_URL = "direct_url.json"

# PEP 610 data is a few hundred bytes; a larger file is not one an installer wrote.
MAX_BYTES = 64 * 1024

_FILE_URL = "file://"


class DirectUrlError(Exception):
    """``direct_url.json`` is present but is not readable PEP 610 data. The message is fixed
    text, never the file's content."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


class Kind(StrEnum):
    VCS = "vcs"
    ARCHIVE = "archive"
    DIR = "dir"


_INFO_KEYS = {"vcs_info": Kind.VCS, "archive_info": Kind.ARCHIVE, "dir_info": Kind.DIR}


@dataclass(frozen=True)
class DirectUrl:
    """One ``direct_url.json``, read but not verified."""

    url: str
    kind: Kind
    editable: bool = False  # ``dir_info.editable``; only an explicit true counts
    vcs: str | None = None
    commit_id: str | None = None

    @property
    def local_folder(self) -> str | None:
        """The percent-decoded path of a ``dir_info`` URL, or None when the URL names no folder
        on this machine: another kind, not ``file://``, a host other than ``localhost``, a
        query or fragment (an installer escapes both), or a path the file system cannot take
        (a NUL, a lone surrogate from a JSON escape). The URL is cut by hand: ``urlsplit`` drops
        tabs and newlines from it and raises on a stray ``[``."""
        if self.kind is not Kind.DIR or not self.url.startswith(_FILE_URL):
            return None
        host, slash, rest = self.url[len(_FILE_URL) :].partition("/")
        if host not in ("", "localhost") or not slash or "?" in rest or "#" in rest:
            return None
        try:
            path = os.fsdecode(urllib.parse.unquote_to_bytes("/" + rest))
        except UnicodeError:
            return None
        return None if "\0" in path else path


@dataclass(frozen=True)
class LocalInstall:
    """A local-install claim that passed verification (:func:`.discovery.local_install`)."""

    folder: str  # the project folder, symlinks resolved
    editable: bool


def read(folder: str) -> str | None:
    """The ``direct_url.json`` in the record folder ``folder`` as text, or None when there is
    no such file.

    It is opened non-blocking and read only as a regular file, so a FIFO in its place is an
    error, never a hung run. Raises :class:`DirectUrlError` for a file that is present but
    unusable.
    """
    path = os.path.join(folder, DIRECT_URL)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except (FileNotFoundError, NotADirectoryError):  # NotADirectory: an old single-file .egg-info
        return None
    except OSError as exc:
        raise DirectUrlError("it cannot be opened", site="direct_url.open-failed") from exc
    try:
        opened = os.fdopen(fd, "rb")
    except OSError as exc:  # a folder in its place: fdopen raises and leaves the descriptor open
        os.close(fd)
        raise DirectUrlError("it cannot be opened", site="direct_url.fdopen-failed") from exc
    try:
        with opened as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):  # a FIFO or a device
                raise DirectUrlError("it cannot be opened", site="direct_url.not-a-regular-file")
            data = file.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DirectUrlError("it cannot be opened", site="direct_url.read-failed") from exc
    if len(data) > MAX_BYTES:
        raise DirectUrlError("larger than PEP 610 data", site="direct_url.larger-than-pep-610-data")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DirectUrlError("not UTF-8", site="direct_url.not-utf-8") from exc


def parse(text: str) -> DirectUrl:
    """PEP 610 ``text`` as a :class:`DirectUrl`.

    Raises :class:`DirectUrlError` when ``text`` is not JSON, or a key PEP 610 requires is
    missing or has the wrong type (``url``, exactly one of ``vcs_info``, ``archive_info`` and
    ``dir_info``, and a VCS install's ``vcs`` and ``commit_id``).
    """
    try:
        data: Any = json.loads(text)
    except (ValueError, RecursionError) as exc:  # JSONDecodeError, a too-long number, too deep nesting
        raise DirectUrlError("not JSON", site="direct_url.not-json") from exc
    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        raise DirectUrlError("not PEP 610 data", site="direct_url.no-url")
    # PEP 610: exactly one of the three, an object.
    infos = [(kind, data[key]) for key, kind in _INFO_KEYS.items() if key in data]
    if len(infos) != 1 or not isinstance(infos[0][1], dict):
        raise DirectUrlError("not PEP 610 data", site="direct_url.not-one-info-object")
    kind, info = infos[0]
    if kind is not Kind.VCS:  # a wheel, an sdist, a folder or an editable
        return DirectUrl(data["url"], kind, editable=kind is Kind.DIR and info.get("editable") is True)
    vcs, commit = info.get("vcs"), info.get("commit_id")
    if not isinstance(vcs, str) or not isinstance(commit, str):
        raise DirectUrlError("not PEP 610 data", site="direct_url.vcs-info-incomplete")
    return DirectUrl(data["url"], kind, vcs=vcs, commit_id=commit)
