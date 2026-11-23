# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``install --venv`` and the feed rules: negative tests for refusals that had none (issue #11).

No pip runs and nothing reaches the network: the feeds answer in process and pip is either the
fake runner of ``test_install`` or the real pinned-pip runner with only ``subprocess.run``
replaced, as ``test_pip_arguments_are_wheels_only_and_hash_pinned`` does. Every refusal that
stands before a change to the venv also shows the venv's files are unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import pinned_pip, policy
from ssc_guardian.discovery import Environment
from ssc_guardian.feeds import osv, pypi
from ssc_guardian.feeds.kev import Kev
from ssc_guardian.findings import Rule
from ssc_guardian.net import Client, FeedError, Response
from ssc_guardian.plugin import PlannedFile
from tests.refusal_sites import refuses
from tests.unit.test_install import FILES, OLD, TODAY, FakePip, Feeds, handler, run, sha, tree, venv

pytestmark = pytest.mark.unit

GOOD = b"the pinned wheel"
Answer = Callable[[list[str]], "subprocess.CompletedProcess[bytes]"]


def _real_pip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: Answer
) -> tuple[int, dict[str, Any], str, Path, list[str], list[list[str]]]:
    """``install demo==1.1`` through the real pinned-pip runner; ``answer`` stands in for the
    process each pip step starts. The run's code, JSON and stderr, the venv, its files before
    the run, and every pip step's argument list."""
    monkeypatch.setattr(pinned_pip, "SHA256", hashlib.sha256(GOOD).hexdigest())  # the wheel the feed serves
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))  # the run's private folder, under tmp_path
    target = venv(tmp_path)
    before = tree(target)
    calls: list[list[str]] = []
    real = subprocess.run

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        if pinned_pip.BOOTSTRAP not in argv:  # not the pinned pip: run as it is
            return real(argv, **kwargs)
        calls.append(list(argv))
        return answer(list(argv))

    monkeypatch.setattr(pinned_pip.subprocess, "run", fake_run)
    code, result, err = run(handler(tmp_path, None, Feeds(wheel=GOOD)), target, "demo==1.1")
    return code, result, err, target, before, calls


def _report(argv: list[str]) -> None:
    """Write the check step's report, demo 1.1 alone, where pip was told to."""
    entry = {
        "metadata": {"name": "demo", "version": "1.1"},
        "download_info": {
            "url": f"{FILES}/packages/ab/demo-1.1-py3-none-any.whl",
            "archive_info": {"hashes": {"sha256": sha("demo", "1.1")}},
        },
        "is_direct": False,
        "requested": True,
    }
    Path(argv[argv.index("--report") + 1]).write_text(json.dumps({"version": "1", "install": [entry]}))


# --- the two pip steps (commands/install.py PinnedPip, pinned_pip.run) ----------------------


def test_check_step_that_stops_is_reported_with_pips_last_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    said = b"Collecting demo==1.1\n\nERROR: No matching distribution found for demo==1.1\n"

    def answer(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, b"", said)

    with refuses("install.step-stopped-exit"):
        code, result, err, target, before, calls = _real_pip(tmp_path, monkeypatch, answer)
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    message = (
        "pip's check step stopped (exit 1): Collecting demo==1.1; ERROR: No matching distribution found for demo==1.1"
    )
    assert f"ssc-guardian: {message}; nothing installed." in err
    assert len(calls) == 1 and "--dry-run" in calls[0]  # the install step never ran
    assert tree(target) == before


def test_install_step_that_stops_is_reported_with_what_it_left(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        if "--report" in argv:
            _report(argv)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return subprocess.CompletedProcess(argv, 1, b"", b"ERROR: THESE PACKAGES DO NOT MATCH THE HASHES\n")

    code, result, err, target, before, calls = _real_pip(tmp_path, monkeypatch, answer)
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    message = "pip's install step stopped (exit 1): ERROR: THESE PACKAGES DO NOT MATCH THE HASHES"
    assert f"ssc-guardian: {target}: {message}; written: nothing; removed: nothing." in err
    assert len(calls) == 2
    assert tree(target) == before


@pytest.mark.parametrize(
    ("write", "error"),
    [
        (None, "FileNotFoundError"),  # pip exits 0 and writes no report
        (b"{not json", "JSONDecodeError"),
        (b'{"version": "1", "install": ["\xff"]}', "UnicodeDecodeError"),
    ],
    ids=["missing", "not-json", "not-utf-8"],
)
def test_check_step_report_that_cannot_be_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, write: bytes | None, error: str
) -> None:
    def answer(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        if write is not None:
            Path(argv[argv.index("--report") + 1]).write_bytes(write)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    with refuses("install.pips-report-could-not-read"):
        code, result, err, target, before, calls = _real_pip(tmp_path, monkeypatch, answer)
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert f"ssc-guardian: pip's report could not be read ({error}); nothing installed." in err
    assert len(calls) == 1  # the install step never ran
    assert tree(target) == before


@pytest.mark.parametrize(
    ("failure", "name"),
    [
        (FileNotFoundError(2, "No such file or directory"), "FileNotFoundError"),
        (subprocess.TimeoutExpired(["python"], 1.0), "TimeoutExpired"),
    ],
    ids=["oserror", "timeout"],
)
def test_venv_python_that_cannot_be_started_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException, name: str
) -> None:
    def answer(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        raise failure

    with refuses("pinned_pip.venvs-python-could-not-run"):
        code, result, err, target, before, calls = _real_pip(tmp_path, monkeypatch, answer)
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert f"ssc-guardian: the venv's Python could not run Guardian's pip ({name}); nothing installed." in err
    assert len(calls) == 1  # the check step was tried; nothing else
    assert tree(target) == before


@dataclass
class SilentPip(FakePip):
    """An install step that reports success and writes nothing."""

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        self.installs.append(tuple(files))


def test_install_that_leaves_no_record_is_reported(tmp_path: Path) -> None:
    target = venv(tmp_path)
    (site,) = target.glob("lib/python3.*/site-packages")
    before = tree(target)
    runner = SilentPip()
    with refuses("install.pip-finished-but-not-installed"):
        code, result, err = run(handler(tmp_path, runner), target, "demo==1.1")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    message = f"pip finished, but demo 1.1 is not in {os.path.realpath(site)}"
    assert f"ssc-guardian: {target}: {message}; written: nothing; removed: nothing." in err
    assert "Installed into" not in err
    assert len(runner.installs) == 1
    assert tree(target) == before


# --- the target (commands/install.py target) ------------------------------------------------


def test_folder_with_pyvenv_cfg_but_no_lib_folder_is_refused(tmp_path: Path) -> None:
    prefix = tmp_path / "half" / ".venv"
    prefix.mkdir(parents=True)
    (prefix / "pyvenv.cfg").write_text("home = /usr/bin\ninclude-system-site-packages = false\n")
    before = tree(prefix)
    runner = FakePip()
    with refuses("install.cannot-read-venv"):
        code, result, err = run(handler(tmp_path, runner), prefix, "demo==1.1")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    message = (
        f"{prefix} cannot be read as a venv (venv with no single lib/pythonX.Y folder); create a venv and install there"
    )
    assert f"ssc-guardian: {message}; nothing installed." in err
    assert runner.checks == [] and runner.installs == []
    assert tree(prefix) == before


# --- the request's versions (commands/install.py Install._version) ---------------------------


@dataclass
class Pages(Feeds):
    """Feeds with more PyPI pages and OSV records than ``Feeds`` knows."""

    pages: dict[str, dict[str, Any]] = field(default_factory=dict)
    records: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        for name, page in self.pages.items():
            if url == f"{pypi.SIMPLE_URL}{name}/":
                self.sent.append(url)
                return Response(200, {}, json.dumps(page).encode(), url)
        for vid, record in self.records.items():
            if url == f"{osv.VULN_URL}{vid}":
                self.sent.append(url)
                return Response(200, {}, json.dumps(record).encode(), url)
        return super().__call__(request, timeout, limit)


def _file(filename: str, **extra: object) -> dict[str, Any]:
    url = f"{FILES}/packages/ab/{filename}"
    return {"filename": filename, "url": url, "hashes": {"sha256": hashlib.sha256(filename.encode()).hexdigest()}} | {
        "upload-time": OLD,
        **extra,
    }


def _project_page(name: str, files: list[dict[str, Any]], versions: list[str]) -> dict[str, Any]:
    return {"meta": {"api-version": "1.4"}, "name": name, "files": files, "versions": versions}


def _refused(tmp_path: Path, feeds: Feeds, request: str) -> str:
    """``install request``: exit 2, a check error, nothing resolved or installed, the venv as it
    was. Its stderr."""
    target = venv(tmp_path)
    before = tree(target)
    runner = FakePip()
    code, result, err = run(handler(tmp_path, runner, feeds), target, request)
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert runner.checks == [] and runner.installs == []
    assert tree(target) == before
    return err


def test_request_for_a_project_pypi_does_not_have_is_refused(tmp_path: Path) -> None:
    feeds = Feeds()
    with refuses("install.pypi-no-project-named"):
        err = _refused(tmp_path, feeds, "Ghost")
    assert "ssc-guardian: PyPI has no project named Ghost; nothing installed." in err
    assert f"{pypi.SIMPLE_URL}ghost/" in feeds.sent  # PyPI was asked and answered 404


@pytest.mark.parametrize(
    "files",
    [
        [_file("srconly-1.0.tar.gz")],
        [_file("srconly-1.0-py3-none-any.whl", yanked="broken upload"), _file("srconly-1.0.tar.gz")],
        [_file("srconly-1.0rc1-py3-none-any.whl")],
    ],
    ids=["sdist-only", "wheel-yanked", "pre-release-wheel-only"],
)
def test_loose_request_for_a_project_with_no_released_wheel_is_refused(
    tmp_path: Path, files: list[dict[str, Any]]
) -> None:
    versions = sorted({f["filename"].split("-")[1].removesuffix(".tar.gz") for f in files})
    feeds = Pages(pages={"srconly": _project_page("srconly", files, versions)})
    with refuses("install.guardian-installs-wheels-only"):
        err = _refused(tmp_path, feeds, "srconly")
    assert (
        "ssc-guardian: PyPI has no released wheel of srconly; Guardian installs wheels only; nothing installed." in err
    )


def test_loose_request_whose_only_release_has_an_unversioned_malware_record_is_refused(tmp_path: Path) -> None:
    # A MAL- record that names solo but no version is a weak compromise: below the default
    # block_on (strong) it is no violation, yet no replacement is ever offered past any
    # malware record. solo 1.0 then passes every rule, but nothing can be named to install.
    record = {"id": "MAL-2026-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "solo"}}]}
    page = _project_page("solo", [_file("solo-1.0-py3-none-any.whl")], ["1.0"])
    feeds = Pages(vulnerable={"solo": ["MAL-2026-1"]}, pages={"solo": page}, records={"MAL-2026-1": record})
    with refuses("install.passes-every-rule-can-installed"):
        err = _refused(tmp_path, feeds, "solo")
    assert "ssc-guardian: no version of solo passes every rule and can be installed now; nothing installed." in err


# --- the feed rules (policy.evaluate_packages) ----------------------------------------------


def test_a_package_whose_feeds_were_not_read_leaves_the_check_unfinished() -> None:
    # Facts gathered for demo alone; Helper was never looked up. demo's finding is kept, and
    # the unfinished check is raised after it.
    client = Client(transport=Feeds(), sleep=lambda _: None)
    facts = policy.gather_pypi(client, ["demo"])
    findings: list[Any] = []
    rules = policy.Rules(cooldown_days=21, today=TODAY)
    with refuses("policy.feeds-not-read"), pytest.raises(FeedError, match="^the feeds were not read for helper$"):
        policy.evaluate_packages(
            facts,
            Kev(client),
            [("demo", "1.0"), ("Helper", "2.0")],
            place="/Users/dev/app/.venv",
            venv="/Users/dev/app/.venv",
            rules=rules,
            into=findings,
        )
    assert [(f.rule, f.item) for f in findings] == [(Rule.KNOWN_VULNERABILITY, "demo")]


# --- the binding and the handler's second gate (#228) ---------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        f"{FILES}/packages/a b/demo-1.1-py3-none-any.whl",  # a space
        f"{FILES}/packages/ab/demo-1.1-py3-none-any.whl\t",  # a tab
        f"{FILES}/packages/ab\x07/demo-1.1-py3-none-any.whl",  # a control character
    ],
    ids=["space", "tab", "control"],
)
def test_file_url_with_whitespace_is_a_binding_refusal(tmp_path: Path, url: str) -> None:
    # The audit's RR5: PyPI's URL for the file pip chose cannot be a planned file's. It is a
    # binding refusal of its own (exit 2, nothing installed), not "check failed (ValueError)".
    wheel = {"filename": "demo-1.1-py3-none-any.whl", "url": url, "hashes": {"sha256": sha("demo", "1.1")}}
    page = _project_page("demo", [wheel | {"upload-time": OLD}], ["1.1"])
    target = venv(tmp_path)
    before = tree(target)
    runner = FakePip()
    with refuses("binding.pypi-file-url-not-plain"):
        code, result, err = run(handler(tmp_path, runner, Pages(pages={"demo": page})), target, "demo==1.1")
    assert code == 2, err
    assert result["findings"] == []
    assert result["skipped"][0]["reason"] == "check-error"
    said = "demo 1.1: PyPI's URL for demo-1.1-py3-none-any.whl is not an HTTPS URL without spaces or controls"
    assert f"ssc-guardian: {said}; nothing installed." in err
    assert "ValueError" not in err
    assert runner.checks == [("demo==1.1",)] and runner.installs == []
    assert tree(target) == before


@pytest.mark.parametrize("requirement", ["demo.zip", "demo.whl", "demo.tar.gz"])
def test_second_gate_has_its_own_site(tmp_path: Path, requirement: str) -> None:
    # The audit's RR6: a valid PyPI name that reads as an archive passes the command line's gate
    # and is refused by the handler's second gate, under its own site (exit 1, nothing resolved).
    target = venv(tmp_path)
    before = tree(target)
    runner = FakePip()
    with refuses("install.second-gate-malformed"):
        code, result, err = run(handler(tmp_path, runner), target, requirement)
    assert code == 1, err
    assert [(f["rule"], f["malformed_field"]) for f in result["findings"]] == [("malformed-name", "item")]
    assert f"{requirement}: a local path is refused: install a released version from PyPI by name." in err
    assert runner.checks == [] and runner.installs == []
    assert tree(target) == before


def test_pip_lines_are_stripped_in_the_check_step_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # #228 (L4-18): pip's colours, a bell or a right-to-left override never reach stderr. pip's
    # text is split into lines before each is stripped, and every line Guardian writes is
    # stripped again (cli._say), so this pins the outcome rather than either strip alone.
    said = "\x1b[31mERROR\x1b[0m: no\x07 match\u202e for demo==1.1\n".encode()

    def answer(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, b"", said)

    with refuses("install.step-stopped-exit"):
        code, _, err, target, before, _ = _real_pip(tmp_path, monkeypatch, answer)
    assert code == 2, err
    assert not {"\x1b", "\x07", "\u202e"} & set(err)
    message = "pip's check step stopped (exit 1): [31mERROR[0m: no match for demo==1.1"
    assert f"ssc-guardian: {message}; nothing installed." in err.splitlines()
    assert tree(target) == before
