# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``--version`` and the JSON ``tool.commit`` name the Git commit from ``direct_url.json`` (issue #7).

Each test installs a fake ``ssc-guardian`` distribution (a ``.dist-info`` folder with
``METADATA`` and, when the case has one, ``direct_url.json``) into a folder put first on
``sys.path``, so ``importlib.metadata`` finds it as it finds a real install. The dev venv does
not install the package, so without that folder there is no distribution at all.
"""

from __future__ import annotations

import errno
import inspect
import io
import json
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import IO

import pytest

from ssc_guardian import direct_url, version
from ssc_guardian.cli import build_parser, main
from ssc_guardian.findings import Checked, Ecosystem, Result, Verb
from ssc_guardian.version import DirectUrlError, VersionAction, git_commit, parse_direct_url
from tests.refusal_sites import refuses

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
VERSION = "1.2.3"
GIT_INSTALL = {
    "url": "https://github.com/example/other-repo",
    "vcs_info": {"vcs": "git", "commit_id": SHA, "requested_revision": "main"},
}
WARNING = "ssc-guardian: direct_url.json could not be read"


def install(site: Path, direct_url: str | bytes | None) -> Path:
    """A fake installed ssc-guardian in ``site``; returns its ``.dist-info`` folder."""
    info = site / f"ssc_guardian-{VERSION}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: ssc-guardian\nVersion: {VERSION}\n")
    if isinstance(direct_url, str):
        (info / "direct_url.json").write_text(direct_url)
    elif isinstance(direct_url, bytes):
        (info / "direct_url.json").write_bytes(direct_url)
    return info


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A folder first on ``sys.path``, where ``install`` puts the distribution."""
    folder = tmp_path / "site"
    folder.mkdir()
    monkeypatch.syspath_prepend(str(folder))
    return folder


def commit_and_warnings() -> tuple[str | None, list[str]]:
    warnings: list[str] = []
    return git_commit(warnings.append), warnings


def the_commit() -> str | None:
    """The installed distribution's commit, read as ``git_commit`` reads it, but with its
    refusal raised to the test: ``git_commit`` turns it into one warning line by design, so a
    ``refuses`` block wraps this call and the warning is asserted after it (#148)."""
    return version.commit_from(metadata.distribution(version.DISTRIBUTION))


def run_version_flag(site: Path) -> subprocess.CompletedProcess[str]:
    """``python -m ssc_guardian --version`` in a fresh interpreter that sees ``site`` first."""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(site), str(REPO / "src")])}
    return subprocess.run(
        [sys.executable, "-m", "ssc_guardian", "--version"], capture_output=True, text=True, env=env, check=False
    )


NAMED = "/Users/me/app"  # the one place these runs name (#255)


def run_check_json() -> tuple[int, dict[str, object], str]:
    """``check --envs --json`` in process with a handler that checks nothing and finds nothing."""

    def handler(request: object) -> Result:
        return Result(Verb.CHECK, checked=(Checked(Ecosystem.PYPI, NAMED),))

    out, err = io.StringIO(), io.StringIO()
    argv = ["check", "--envs", "--path", NAMED, "--json"]  # #255: check names what it checks
    code = main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err, environ={})
    return code, json.loads(out.getvalue()), err.getvalue()


def run_check_text() -> str:
    def handler(request: object) -> Result:
        return Result(Verb.CHECK, checked=(Checked(Ecosystem.PYPI, NAMED),))

    out = io.StringIO()
    argv = ["check", "--envs", "--path", NAMED]
    main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=io.StringIO(), environ={})
    return out.getvalue()


# --- happy path --------------------------------------------------------------


def test_version_names_git_commit_from_direct_url(site: Path) -> None:
    install(site, json.dumps(GIT_INSTALL))

    assert commit_and_warnings() == (SHA, [])
    assert commit_and_warnings() == (SHA, [])  # reading changes nothing: the same answer again

    proc = run_version_flag(site)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, f"ssc-guardian {VERSION} ({SHA})\n", "")

    code, doc, err = run_check_json()
    assert (code, err) == (0, "")
    assert doc["tool"] == {"name": "ssc-guardian", "version": VERSION, "commit": SHA}
    # --version matches the text output's footer.
    assert f"\nssc-guardian {VERSION} ({SHA}), " in run_check_text()


# --- no commit: none is reported, never invented -----------------------------


@pytest.mark.parametrize(
    "direct_url",
    [
        pytest.param(None, id="no-direct-url-json"),
        pytest.param(
            {"url": "file:///wheels/ssc_guardian-1.2.3-py3-none-any.whl", "archive_info": {"hashes": {}}},
            id="wheel",
        ),
        pytest.param({"url": "file:///src/other-repo", "dir_info": {"editable": True}}, id="editable"),
        pytest.param({"url": "file:///src/other-repo", "dir_info": {}}, id="local-folder"),
        pytest.param(
            {"url": "https://hg.example/ssc-guardian", "vcs_info": {"vcs": "hg", "commit_id": "a" * 40}},
            id="not-git",
        ),
    ],
)
def test_version_without_direct_url_names_no_commit(site: Path, direct_url: dict[str, object] | None) -> None:
    install(site, None if direct_url is None else json.dumps(direct_url))

    assert commit_and_warnings() == (None, [])

    proc = run_version_flag(site)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, f"ssc-guardian {VERSION}\n", "")

    code, doc, err = run_check_json()
    assert (code, err) == (0, "")
    assert doc["tool"] == {"name": "ssc-guardian", "version": VERSION, "commit": None}


def test_dev_venv_without_an_installed_distribution_names_no_commit_silently() -> None:
    # The dev venv imports the package from src: PackageNotFoundError is no commit, no warning.
    assert commit_and_warnings() == (None, [])
    proc = subprocess.run(
        [sys.executable, "-m", "ssc_guardian", "--version"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        check=False,
    )
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, "ssc-guardian 0+unknown\n", "")


# --- a present but unusable file: an error, not a guess ----------------------


CORRUPT = [
    pytest.param(b"{not json", id="not-json"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git", "commit_id": "' + b"\xff" * 40 + b'"}}', id="not-utf-8"),
    pytest.param(b"", id="empty"),
    pytest.param(b"[]", id="not-an-object"),
    pytest.param(b'{"vcs_info": {"vcs": "git", "commit_id": "' + SHA.encode() + b'"}}', id="no-url"),
    pytest.param(b'{"url": 5, "dir_info": {}}', id="url-not-a-string"),
    pytest.param(b'{"url": "x"}', id="no-info"),
    pytest.param(b'{"url": "x", "vcs_info": null}', id="vcs-info-null"),
    pytest.param(b'{"url": "x", "dir_info": {}, "archive_info": {}}', id="two-infos"),
    pytest.param(b'{"url": "x", "vcs_info": "git"}', id="vcs-info-not-an-object"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git"}}', id="no-commit-id"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git", "commit_id": 5}}', id="commit-id-not-a-string"),
    pytest.param(b'{"url": "x", "vcs_info": {"commit_id": "' + SHA.encode() + b'"}}', id="no-vcs"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git", "commit_id": "11bd719"}}', id="short-commit"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git", "commit_id": "' + SHA.upper().encode() + b'"}}', id="upper"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git", "commit_id": "' + b"a" * 64 + b'"}}', id="sha-256"),
    pytest.param(b'{"url": "x", "vcs_info": {"vcs": "git", "commit_id": "' + SHA.encode() + b'\\n"}}', id="newline"),
    pytest.param(json.dumps({**GIT_INSTALL, "pad": "x" * 70_000}).encode(), id="too-large"),
    pytest.param(b"[" * 5000, id="too-deep"),
]


@pytest.mark.parametrize("content", CORRUPT)
def test_corrupt_direct_url_is_an_error_not_a_guess(site: Path, content: bytes) -> None:
    install(site, content)

    commit, warnings = commit_and_warnings()
    assert commit is None
    assert len(warnings) == 1 and warnings[0].startswith(WARNING) and "\n" not in warnings[0]
    assert "11bd719" not in warnings[0]  # the file's content is never echoed

    # --version still runs: no commit, exit 0, one plain line on stderr, never a traceback.
    proc = run_version_flag(site)
    assert (proc.returncode, proc.stdout) == (0, f"ssc-guardian {VERSION}\n")
    assert proc.stderr.startswith(WARNING) and proc.stderr.count("\n") == 1

    # So does every command, and its JSON says null.
    code, doc, err = run_check_json()
    assert code == 0
    assert doc["tool"] == {"name": "ssc-guardian", "version": VERSION, "commit": None}
    assert err.startswith(WARNING) and err.count("\n") == 1


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads a file without permission")
def test_unreadable_direct_url_is_an_error_not_an_absent_file(site: Path) -> None:
    # importlib.metadata's read_text answers None for a file it may not open, as for a missing one.
    path = install(site, json.dumps(GIT_INSTALL)) / "direct_url.json"
    path.chmod(0)
    try:
        with refuses("direct_url.open-failed"), pytest.raises(DirectUrlError, match="^it cannot be opened$"):
            the_commit()
        commit, warnings = commit_and_warnings()
    finally:
        path.chmod(0o600)
    assert commit is None
    assert warnings == [f"{WARNING} (it cannot be opened); no commit is reported."]


def test_folder_in_place_of_direct_url_is_an_error(site: Path) -> None:
    (install(site, None) / "direct_url.json").mkdir()
    commit, warnings = commit_and_warnings()
    assert commit is None
    assert warnings == [f"{WARNING} (it cannot be opened); no commit is reported."]


def test_a_fifo_in_place_of_direct_url_is_an_error_not_a_hang(site: Path) -> None:
    os.mkfifo(install(site, None) / "direct_url.json")
    with refuses("direct_url.not-a-regular-file"), pytest.raises(DirectUrlError, match="^it cannot be opened$"):
        the_commit()  # must not hang the run
    commit, warnings = commit_and_warnings()
    assert commit is None
    assert warnings == [f"{WARNING} (it cannot be opened); no commit is reported."]


class _FailingRead:
    """A regular file whose read fails, as a disk error would (no file on disk can do this)."""

    def __init__(self, file: IO[bytes]) -> None:
        self._file = file

    def __enter__(self) -> _FailingRead:
        return self

    def __exit__(self, *exc: object) -> None:
        self._file.close()

    def fileno(self) -> int:
        return self._file.fileno()

    def read(self, size: int = -1) -> bytes:
        raise OSError(errno.EIO, "Input/output error")


def test_a_direct_url_that_fails_to_read_is_an_error(site: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(site, json.dumps(GIT_INSTALL))
    real_fdopen = os.fdopen
    monkeypatch.setattr(direct_url.os, "fdopen", lambda fd, mode: _FailingRead(real_fdopen(fd, "rb")))
    with refuses("direct_url.read-failed"), pytest.raises(DirectUrlError, match="^it cannot be opened$"):
        the_commit()
    commit, warnings = commit_and_warnings()
    assert commit is None
    assert warnings == [f"{WARNING} (it cannot be opened); no commit is reported."]


def test_old_single_file_egg_info_has_no_direct_url(site: Path) -> None:
    # A distribution whose metadata is one file: no direct_url.json can sit beside it.
    (site / f"ssc_guardian-{VERSION}-py3.11.egg-info").write_text(
        f"Metadata-Version: 1.1\nName: ssc-guardian\nVersion: {VERSION}\n"
    )
    assert commit_and_warnings() == (None, [])


def test_too_large_direct_url_is_refused_by_its_size(site: Path) -> None:
    # Valid PEP 610 data, padded past the limit: only the size check can refuse it (a
    # truncated read alone would also fail as "not JSON", hiding a lost size check).
    install(site, json.dumps({**GIT_INSTALL, "pad": "x" * version._MAX_BYTES}))
    with refuses("direct_url.larger-than-pep-610-data"), pytest.raises(DirectUrlError, match="larger than PEP 610"):
        the_commit()
    assert commit_and_warnings() == (None, [f"{WARNING} (larger than PEP 610 data); no commit is reported."])


def test_parse_direct_url_reports_only_a_git_commit() -> None:
    assert parse_direct_url(json.dumps(GIT_INSTALL)) == SHA
    assert parse_direct_url('{"url": "x", "dir_info": {}}') is None
    with refuses("direct_url.not-json"), pytest.raises(DirectUrlError, match="not JSON"):
        parse_direct_url("NaN-ish")


def test_version_line_matches_the_footer() -> None:
    assert version.version_line(VERSION, None) == f"ssc-guardian {VERSION}"
    assert version.version_line(VERSION, SHA) == f"ssc-guardian {VERSION} ({SHA})"


def test_version_flag_writes_to_the_streams_given_to_main(site: Path, capsys: pytest.CaptureFixture[str]) -> None:
    install(site, json.dumps(GIT_INSTALL))
    out, err = io.StringIO(), io.StringIO()
    assert main(["--version"], stdout=out, stderr=err, environ={}) == 0
    assert (out.getvalue(), err.getvalue()) == (f"ssc-guardian {VERSION} ({SHA})\n", "")
    assert capsys.readouterr() == ("", "")  # never the process's own stdout or stderr


def test_version_flag_warns_on_the_stderr_given_to_main(site: Path, capsys: pytest.CaptureFixture[str]) -> None:
    install(site, b"{not json")
    out, err = io.StringIO(), io.StringIO()
    assert main(["--version"], stdout=out, stderr=err, environ={}) == 0
    assert out.getvalue() == f"ssc-guardian {VERSION}\n"
    assert err.getvalue().startswith(WARNING) and err.getvalue().count("\n") == 1
    assert capsys.readouterr() == ("", "")


def test_version_flag_survives_a_closed_stdout_given_to_main(site: Path) -> None:
    # A closed stream raises ValueError, not OSError: the failed write still exits 0.
    install(site, json.dumps(GIT_INSTALL))
    out, err = io.StringIO(), io.StringIO()
    out.close()
    assert main(["--version"], stdout=out, stderr=err, environ={}) == 0
    assert err.getvalue() == ""


def test_version_flag_survives_a_closed_stderr(site: Path) -> None:
    # A warning that cannot be written is dropped; --version still exits 0 with its line.
    install(site, b"{not json")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(site), str(REPO / "src")])}
    proc = subprocess.run(  # fd 2 closed: Python starts with sys.stderr None
        ["/bin/sh", "-c", 'exec "$0" -m ssc_guardian --version 2>&-', sys.executable],
        stdout=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    assert (proc.returncode, proc.stdout) == (0, f"ssc-guardian {VERSION}\n")


def _default_help(action: type[VersionAction]) -> object:
    return inspect.signature(action.__init__).parameters["help"].default


def _cli_version_help() -> str | None:
    (action,) = (a for a in build_parser()._actions if "--version" in a.option_strings)
    return action.help


def test_version_action_default_help_matches_the_cli() -> None:
    # #282: one wording for one flag: the help the parser prints is VersionAction's default.
    assert _cli_version_help() == _default_help(VersionAction) == "show the version and exit"
    assert "show the version and exit" in build_parser().format_help()

    class Planted(VersionAction):
        def __init__(self, option_strings: list[str], version: str, help: str = "a different wording") -> None:
            super().__init__(option_strings, version, help=help)

    # Negative: a planted different default is caught by the same comparison.
    assert _default_help(Planted) != _cli_version_help()
