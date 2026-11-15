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

"""CI context: only the default branch's overrides count (plan §2.4, R1-K5, R2-K3, FC-3;
contracts §10.5).

Guardian is in CI when ``GITHUB_ACTIONS`` is exactly ``true``. It then reads the
default branch's ``.ssc-guardian.toml`` and ``.ssc-guardian-overrides.toml`` through
the GitHub API, applies the stricter of the default branch's and the change's
settings, and counts overrides and acknowledgments from the default branch only, so
a pull request cannot release its own finding. A file that a successful listing of
the branch shows is absent sets nothing; any other failure to read the copies is an
unfinished check (``default-branch-unreadable``, exit 2).

A malformed overrides file, the repository's own or the default branch's copy in CI, releases
nothing and does not stop the check (contracts §10.1, #166): the context carries no override
from it and, separately, the refusal to list (a ``check-error`` skip naming the local file, or a
``default-branch-unreadable`` skip with no place for the default branch's copy), so every
workflow is still checked and a finding still gives exit 1. A malformed settings file, local or
the default branch's copy, still stops the check (exit 2): settings change what is checked.

The fetch function is injected: this module never imports the network client.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import quote

from ssc_guardian.findings import Ecosystem, Finding, IncompleteCheckError, Rule, Skip, SkipReason, make_finding
from ssc_guardian.grammars import Field, matches
from ssc_guardian.overrides import REPOSITORY_OVERRIDES_FILE, Override, load_overrides, parse_overrides
from ssc_guardian.settings import (
    SETTINGS_FILE,
    WORKSTATION_SETTINGS_FILE,
    ConfigFileError,
    FileKind,
    Layer,
    LayerSource,
    Settings,
    decode,
    load_settings,
    parse_settings,
    with_built_in_floor,
    workstation_dir,
)

LISTING_LIMIT = 1000

# GET ``path`` (with its query) on api.github.com; returns the HTTP status and the body.
Fetch = Callable[[str], tuple[int, bytes]]


def in_ci(environ: Mapping[str, str]) -> bool:
    return environ.get("GITHUB_ACTIONS") == "true"


class DefaultBranchUnreadableError(IncompleteCheckError):
    """The default branch's copies could not be read: exit 2, never a pass."""

    def __init__(self, problem: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.DEFAULT_BRANCH_UNREADABLE, site=site)
        self.problem = problem

    def __str__(self) -> str:
        return self.problem

    def skip(self, ecosystem: Ecosystem | None) -> Skip:
        """The in-scope skip for a default-branch copy listed while the check goes on: no place,
        since the file is on the default branch, not here; the problem goes to text output only."""
        return Skip(
            ecosystem,
            None,
            SkipReason.DEFAULT_BRANCH_UNREADABLE,
            detail=self.problem,
            site="ci_context.default-branch-copy-skipped",
            made_from=self,
        )


@dataclass(frozen=True)
class DefaultBranchCopies:
    repository: str
    branch: str
    settings: str | None  # None: the listing shows the file is absent
    overrides: bytes | None  # as fetched: decoded where a malformed copy releases nothing (#166)


def _get_json(fetch: Fetch, path: str) -> Any:
    try:
        status, body = fetch(path)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # a network failure, a rate limit: never a pass
        raise DefaultBranchUnreadableError(
            f"GET {path} failed ({type(exc).__name__})", site="ci_context.get-json-failed"
        ) from exc
    if status != 200:
        raise DefaultBranchUnreadableError(f"GET {path} returned {status}", site="ci_context.get-json-status")
    try:
        return json.loads(body)
    except (ValueError, TypeError) as exc:
        raise DefaultBranchUnreadableError(
            f"GET {path} did not return JSON", site="ci_context.did-not-return-json"
        ) from exc


def _file_bytes(fetch: Fetch, repository: str, branch: str, name: str) -> bytes:
    path = f"/repos/{repository}/contents/{name}?ref={quote(branch, safe='')}"
    doc = _get_json(fetch, path)
    if not isinstance(doc, dict) or doc.get("type") != "file" or doc.get("encoding") != "base64":
        raise DefaultBranchUnreadableError(
            f"{name} on {branch} is not a file the API returns whole", site="ci_context.not-file-api-returns-whole"
        )
    content = doc.get("content")
    if not isinstance(content, str):
        raise DefaultBranchUnreadableError(f"{name} on {branch} has no content", site="ci_context.no-content")
    try:
        return base64.b64decode("".join(content.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DefaultBranchUnreadableError(
            f"{name} on {branch} is not valid base64", site="ci_context.not-valid-base64"
        ) from exc


def _file_text(fetch: Fetch, repository: str, branch: str, name: str) -> str:
    data = _file_bytes(fetch, repository, branch, name)
    try:
        return decode(data, f"{name} on {branch}")
    except ConfigFileError as exc:
        raise DefaultBranchUnreadableError(str(exc), site="ci_context.file-text-undecodable") from exc


def read_default_branch(environ: Mapping[str, str], fetch: Fetch) -> DefaultBranchCopies:
    """The default branch's settings and overrides files (§10.5).

    The branch name comes from the repository's metadata; the root listing then proves which
    of the two files exist, so "absent" is never inferred from a failed request.
    """
    repository = environ.get("GITHUB_REPOSITORY", "")
    if not matches(Field.OWNER_REPO, repository):
        raise DefaultBranchUnreadableError(
            "GITHUB_REPOSITORY is not set to OWNER/REPO", site="ci_context.github-repository-not-set-owner"
        )
    meta = _get_json(fetch, f"/repos/{repository}")
    branch = meta.get("default_branch") if isinstance(meta, dict) else None
    if not isinstance(branch, str) or not matches(Field.GIT_REF, branch):
        raise DefaultBranchUnreadableError(
            "the repository's default branch is not named", site="ci_context.repositorys-default-branch-not-named"
        )
    listing = _get_json(fetch, f"/repos/{repository}/contents/?ref={quote(branch, safe='')}")
    if not isinstance(listing, list) or not all(isinstance(e, dict) for e in listing):
        raise DefaultBranchUnreadableError(
            f"the listing of {branch} is not a list of entries", site="ci_context.not-list-entries"
        )
    # The contents API lists at most 1,000 entries; a longer root cannot prove a file absent.
    if len(listing) >= LISTING_LIMIT:
        raise DefaultBranchUnreadableError(
            f"the listing of {branch} may be truncated", site="ci_context.listing-may-be-truncated"
        )
    names = [e.get("name") for e in listing]
    if not all(isinstance(name, str) for name in names):
        raise DefaultBranchUnreadableError(
            f"the listing of {branch} has an entry with no name", site="ci_context.entry-no-name"
        )
    settings = _file_text(fetch, repository, branch, SETTINGS_FILE) if SETTINGS_FILE in names else None
    overrides = (
        _file_bytes(fetch, repository, branch, REPOSITORY_OVERRIDES_FILE)
        if REPOSITORY_OVERRIDES_FILE in names
        else None
    )
    return DefaultBranchCopies(repository, branch, settings, overrides)


@dataclass(frozen=True)
class RepositoryContext:
    """What ``check --repo`` applies: merged settings, the overrides that count, and the notices
    to report (weakened settings; locally, that CI uses only the default branch's overrides).

    ``overrides_unusable`` is the refusal of an overrides file that is malformed (§10.1): the
    caller lists its ``skip`` and goes on, and ``overrides`` is then empty, never a partial or
    default set."""

    settings: Settings
    overrides: tuple[Override, ...]
    in_ci: bool
    notices: tuple[Finding, ...]
    overrides_unusable: ConfigFileError | DefaultBranchUnreadableError | None = None


def load_repository_context(
    repository_root: str,
    *,
    environ: Mapping[str, str],
    fetch: Fetch,
    today: date,
    home: str | None = None,
    command_line: Layer | None = None,
) -> RepositoryContext:
    """Read the repository's files and the workstation config; in CI, the default branch's
    copies too. Raises :class:`ConfigFileError` for a settings file (workstation or repository)
    that cannot be used and :class:`DefaultBranchUnreadableError` when the default branch's
    copies cannot be fetched or its settings copy is malformed; a caller runs this inside
    ``Collector.check`` so either is an in-scope skip (exit 2). An overrides file that cannot be
    used (malformed, or locally one that cannot be read), the repository's or the default
    branch's copy, is not raised: it is returned as ``overrides_unusable`` with no overrides
    (§10.1)."""
    workstation = load_settings(
        os.path.join(workstation_dir(home), WORKSTATION_SETTINGS_FILE), kind=FileKind.WORKSTATION, home=home
    )
    repository = load_settings(os.path.join(repository_root, SETTINGS_FILE), kind=FileKind.REPOSITORY)
    overrides_file = os.path.join(repository_root, REPOSITORY_OVERRIDES_FILE)
    if in_ci(environ):
        copies = read_default_branch(environ, fetch)
        try:
            default = (
                parse_settings(copies.settings, kind=FileKind.REPOSITORY, source=LayerSource.DEFAULT_BRANCH, place=None)
                if copies.settings is not None
                else None
            )
        except ConfigFileError as exc:
            raise DefaultBranchUnreadableError(
                f"the default branch's copy is malformed: {exc.problem}",
                site="ci_context.default-branchs-copy-malformed",
            ) from exc
        overrides: tuple[Override, ...] = ()
        unusable: ConfigFileError | DefaultBranchUnreadableError | None = None
        try:
            if copies.overrides is not None:
                # Decoded here, not in read_default_branch: a copy that is not UTF-8 is malformed
                # (§10.1) and releases nothing, as one that does not parse. (GitHub's contents API
                # does not return a file over 1 MB whole: that copy stops in _file_bytes.)
                text = decode(copies.overrides, f"{REPOSITORY_OVERRIDES_FILE} on {copies.branch}")
                overrides = parse_overrides(text, kind=FileKind.REPOSITORY, place=None, today=today)
        except ConfigFileError as exc:
            # Releases nothing (§10.1): listed by the caller, and the check goes on.
            unusable = DefaultBranchUnreadableError(
                f"{REPOSITORY_OVERRIDES_FILE} on {copies.branch} is malformed: {exc.problem}",
                site="ci_context.default-branch-overrides-malformed",
            )
        # The change's overrides are not read at all: in CI they release nothing. The built-in
        # defaults sit beneath the default branch's values, so the change can only tighten.
        settings = Settings.of(workstation, repository, with_built_in_floor(default), command_line, ci=True)
        return RepositoryContext(settings, overrides, True, settings.notices(), unusable)
    settings = Settings.of(workstation, repository, command_line)
    try:
        overrides = load_overrides(overrides_file, kind=FileKind.REPOSITORY, today=today)
    except ConfigFileError as exc:
        # Releases nothing (§10.1): listed by the caller, and the check goes on.
        return RepositoryContext(settings, (), False, settings.notices(), exc)
    notices = settings.notices()
    if overrides:
        place = overrides_file if matches(Field.PATH, overrides_file) else None
        notices += (make_finding(Rule.CI_OVERRIDES, Ecosystem.GITHUB_ACTIONS, place=place),)
    return RepositoryContext(settings, overrides, False, notices)
