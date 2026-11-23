# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The PEP 610 reader ``--version`` and ``check --envs`` share (issue #97; contracts §2, §10.6)."""

from __future__ import annotations

import gc
import json
import os
import re
from pathlib import Path

import pytest

from ssc_guardian import direct_url, version
from ssc_guardian.direct_url import DirectUrl, DirectUrlError, Kind
from tests.refusal_sites import Refuses, refuses

pytestmark = pytest.mark.unit

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
GIT_INSTALL = json.dumps({"url": "https://example.test/repo", "vcs_info": {"vcs": "git", "commit_id": SHA}})


def _dir(url: str, **info: object) -> DirectUrl:
    return direct_url.parse(json.dumps({"url": url, "dir_info": info}))


def test_parse_reads_editable_and_plain_dir_info_as_a_local_folder() -> None:
    editable, plain = _dir("file:///Users/me/tool", editable=True), _dir("file:///Users/me/tool")
    assert (editable.kind, editable.editable, editable.local_folder) == (Kind.DIR, True, "/Users/me/tool")
    assert (plain.kind, plain.editable, plain.local_folder) == (Kind.DIR, False, "/Users/me/tool")
    assert _dir("file:///Users/me/tool", editable=False).editable is False
    assert _dir("file:///Users/me/tool", editable="yes").editable is False  # only an explicit true counts


def test_local_folder_is_none_for_vcs_archive_and_remote_urls() -> None:
    git = direct_url.parse(
        json.dumps({"url": "git+https://example.test/r", "vcs_info": {"vcs": "git", "commit_id": SHA}})
    )
    git_file = direct_url.parse(json.dumps({"url": "file:///x", "vcs_info": {"vcs": "git", "commit_id": SHA}}))
    wheel = direct_url.parse(json.dumps({"url": "file:///x/tool-1.0-py3-none-any.whl", "archive_info": {}}))
    assert (git.kind, git_file.kind, wheel.kind) == (Kind.VCS, Kind.VCS, Kind.ARCHIVE)
    assert git.local_folder is None and git_file.local_folder is None and wheel.local_folder is None
    assert _dir("https://example.test/tool").local_folder is None


@pytest.mark.parametrize(
    ("url", "folder"),
    [
        ("file:///a%20b", "/a b"),
        ("file://localhost/a/b", "/a/b"),
        ("file:///caf%C3%A9", "/café"),
        ("file:///", "/"),
    ],
)
def test_local_folder_decodes_percent_escapes(url: str, folder: str) -> None:
    assert _dir(url).local_folder == folder


@pytest.mark.parametrize(
    "url",
    [
        "file://host/x",
        "file://user@localhost/x",
        "file://localhost:80/x",
        "file://",
        "file:a/b",
        "file:/a/b",
        "FILE:///a",
        "file:///a?x=1",
        "file:///a#frag",
        "file://[bad/x",  # urlsplit raises on this one
        "file:///a%00b",  # realpath raises on a NUL
        "file:///a\ud800b",  # and on a lone surrogate, which a JSON escape can carry
        "file:///a\udc80b",
    ],
)
def test_local_folder_refuses_relative_hosted_or_unusable_paths(url: str) -> None:
    assert _dir(url).local_folder is None


def test_a_percent_escape_that_is_not_utf8_keeps_the_bytes_it_names() -> None:
    assert _dir("file:///a%ffb").local_folder == os.fsdecode(b"/a\xffb")


def test_read_answers_none_when_there_is_no_file(tmp_path: Path) -> None:
    record = tmp_path / "tool-1.0.dist-info"
    record.mkdir()
    assert direct_url.read(str(record)) is None
    assert direct_url.read(str(tmp_path / "missing.dist-info")) is None
    single_file = tmp_path / "tool-1.0.egg-info"  # an old record that is one file
    single_file.write_text("Name: tool\n")
    assert direct_url.read(str(single_file)) is None


def test_read_takes_a_file_of_exactly_the_cap(tmp_path: Path) -> None:
    (tmp_path / direct_url.DIRECT_URL).write_bytes(b" " * direct_url.MAX_BYTES)
    assert direct_url.read(str(tmp_path)) == " " * direct_url.MAX_BYTES


@pytest.mark.parametrize(
    ("planted", "text", "site"),
    [
        ("fifo", "it cannot be opened", refuses("direct_url.not-a-regular-file")),
        ("folder", "it cannot be opened", refuses("direct_url.fdopen-failed")),
        ("oversized", "larger than PEP 610 data", refuses("direct_url.larger-than-pep-610-data")),
        ("not-utf8", "not UTF-8", refuses("direct_url.not-utf-8")),
    ],
)
def test_unreadable_oversized_or_non_json_direct_url_is_an_error_not_a_guess(
    tmp_path: Path, planted: str, text: str, site: Refuses
) -> None:
    path = tmp_path / direct_url.DIRECT_URL
    if planted == "fifo":
        os.mkfifo(path)
    elif planted == "folder":
        path.mkdir()
    elif planted == "oversized":
        path.write_bytes(b" " * (direct_url.MAX_BYTES + 1))
    else:
        path.write_bytes(b'{"url": "\xff"}')
    with site, pytest.raises(DirectUrlError, match=re.escape(text)) as raised:
        direct_url.read(str(tmp_path))
    assert str(raised.value) == text


@pytest.mark.parametrize(
    ("data", "text", "site"),
    [
        ("{not json", "not JSON", refuses("direct_url.not-json")),
        ("[" * 100000, "not JSON", refuses("direct_url.not-json")),
        ('{"url": 3, "dir_info": {}}', "not PEP 610 data", refuses("direct_url.no-url")),
        ('{"dir_info": {}}', "not PEP 610 data", refuses("direct_url.no-url")),
        ('{"url": "file:///a"}', "not PEP 610 data", refuses("direct_url.not-one-info-object")),
        ('{"url": "file:///a", "dir_info": 3}', "not PEP 610 data", refuses("direct_url.not-one-info-object")),
        (
            '{"url": "file:///a", "dir_info": {}, "archive_info": {}}',
            "not PEP 610 data",
            refuses("direct_url.not-one-info-object"),
        ),
        (
            '{"url": "file:///a", "vcs_info": {"vcs": "git"}}',
            "not PEP 610 data",
            refuses("direct_url.vcs-info-incomplete"),
        ),
    ],
)
def test_text_that_is_not_pep_610_data_is_an_error_not_a_guess(data: str, text: str, site: Refuses) -> None:
    with site, pytest.raises(DirectUrlError, match=re.escape(text)) as raised:
        direct_url.parse(data)
    assert str(raised.value) == text


def test_a_folder_in_the_files_place_leaves_no_descriptor_open(tmp_path: Path) -> None:
    (tmp_path / direct_url.DIRECT_URL).mkdir()
    gc.collect()  # a descriptor another test left to the collector must not close during the count
    before = len(os.listdir("/dev/fd"))
    for _ in range(5):
        with refuses("direct_url.fdopen-failed"), pytest.raises(DirectUrlError, match="it cannot be opened"):
            direct_url.read(str(tmp_path))
    assert len(os.listdir("/dev/fd")) <= before


def test_version_reports_the_same_git_commit_through_the_shared_reader() -> None:
    assert direct_url.parse(GIT_INSTALL).commit_id == version.parse_direct_url(GIT_INSTALL) == SHA
    assert version.DirectUrlError is DirectUrlError and version.DIRECT_URL == direct_url.DIRECT_URL


def test_a_bad_git_commit_is_only_the_version_commands_concern() -> None:
    # --version refuses to guess at a short commit; the record is still a VCS install to the
    # check, which makes no local-install claim of it.
    short = json.dumps({"url": "https://example.test/r", "vcs_info": {"vcs": "git", "commit_id": "abc"}})
    assert direct_url.parse(short).kind is Kind.VCS
    with (
        refuses("version.git-commit-not-40-lowercase"),
        pytest.raises(DirectUrlError, match="^the Git commit is not 40 lowercase hex characters$"),
    ):
        version.parse_direct_url(short)
