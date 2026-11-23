# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``check --envs`` end to end: a fake Mac under ``tmp_path`` and the feeds on a local fixture
server (issue #5; plan §3.1). No live network; the real home folder is never read.

The server binds 127.0.0.1 only and answers OSV by the names in each query, as in
``test_feeds_fixture_server``; the client and its ``urllib`` transport are the real ones.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import nullcontext
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ssc_guardian import cli, discovery, policy
from ssc_guardian.cli import Request
from ssc_guardian.commands.check_envs import CheckEnvs, _installed_files
from ssc_guardian.commands.protect import Protect
from ssc_guardian.feeds import pypi
from ssc_guardian.findings import IncompleteCheckError, Result, SkipReason, Verb
from ssc_guardian.net import Client, Response, urllib_transport
from tests import conftest
from tests.refusal_sites import Refuses, refuses
from tests.unit.test_discovery import add_claim, add_dist, fake_mac, make_base, make_venv

pytestmark = [pytest.mark.integration, pytest.mark.doc_content]

TODAY = date(2026, 11, 3)
OLD = "2023-05-22T15:12:44Z"
ADVISORY = {
    "id": "GHSA-9wx4-h78v-vm56",
    "aliases": ["CVE-2024-35195"],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
        }
    ],
}
VULNERABLE = {"requests": ["GHSA-9wx4-h78v-vm56"]}
RECORDS: dict[str, dict[str, Any]] = {"GHSA-9wx4-h78v-vm56": ADVISORY}
ASKED: list[tuple[str, bytes]] = []  # every request the server answered, a test's own after it clears it
UPLOADS = {"pip": {"26.1.2": OLD, "26.2.1": OLD}, "requests": {"2.31.0": OLD, "2.32.3": OLD}, "idna": {"3.7": OLD}}
PAGES: dict[str, dict[str, Any]] = {}  # a test's own page for a project, served before _page


def _wheel(name: str, version: str, when: str = OLD, tag: str = "py3-none-any") -> dict[str, Any]:
    return {
        "filename": f"{name}-{version}-{tag}.whl",
        "url": f"https://files.pythonhosted.org/packages/ab/{name}-{version}-{tag}.whl",
        "hashes": {"sha256": "ab" * 32},
        "upload-time": when,
    }


def _page(name: str) -> dict[str, Any]:
    files = [_wheel(name, v, when) for v, when in UPLOADS[name].items()]
    return {"meta": {"api-version": "1.4"}, "name": name, "files": files, "versions": list(UPLOADS[name])}


class _Answer(BaseHTTPRequestHandler):
    def _answer(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        path = self.path
        ASKED.append((path, body))
        answer: object = {"message": "not found"}
        status = 404
        if path == "/api.osv.dev/v1/querybatch":
            queries = json.loads(body)["queries"]
            ids = [VULNERABLE.get(q["package"]["name"], []) for q in queries]
            status, answer = 200, {"results": [{"vulns": [{"id": i} for i in found]} for found in ids]}
        elif path.startswith("/api.osv.dev/v1/vulns/") and path.rsplit("/", 1)[1] in RECORDS:
            status, answer = 200, RECORDS[path.rsplit("/", 1)[1]]
        elif path.startswith("/api.github.com/advisories?"):
            status, answer = 200, []
        elif path.startswith("/pypi.org/simple/") and path.split("/")[3] in PAGES:
            status, answer = 200, PAGES[path.split("/")[3]]
        elif path.startswith("/pypi.org/simple/") and path.split("/")[3] in UPLOADS:
            status, answer = 200, _page(path.split("/")[3])
        elif path == "/www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
            status, answer = 200, {"count": 0, "vulnerabilities": []}
        data = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # keep test output quiet
        return None


_Handler = type("_Handler", (_Answer,), {"do_GET": _Answer._answer, "do_POST": _Answer._answer})


@pytest.fixture
def client() -> Iterator[Client]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def transport(request: urllib.request.Request, timeout: float, limit: int) -> Response:
        parts = urllib.parse.urlsplit(request.full_url)
        assert parts.scheme == "https"
        local = f"{base}/{parts.hostname}{parts.path}" + (f"?{parts.query}" if parts.query else "")
        rewritten = urllib.request.Request(
            local, data=request.data, headers=dict(request.header_items()), method=request.get_method()
        )
        answer = urllib_transport(rewritten, timeout, limit)
        return Response(answer.status, answer.headers, answer.body, request.full_url)

    try:
        yield Client(None, transport=transport, timeout=5.0)
    finally:
        httpd.shutdown()
        httpd.server_close()


def _venv(tmp_path: Path, name: str, *packages: tuple[str, str], python: str = "3.12") -> str:
    prefix = tmp_path / "home" / "projects" / name / ".venv"
    site = make_venv(prefix, python)
    for package, version in packages:
        add_dist(site, package, version)
    return os.path.realpath(prefix)


def _config(tmp_path: Path, text: str = "") -> None:
    folder = tmp_path / "home" / ".config" / "ssc-guardian"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(f"format = 1\n{text}\n")


def _projects(tmp_path: Path) -> str:
    """The fake home's projects folder, as ``--path`` names it (``[scope] venv_folders`` before #255)."""
    return os.path.realpath(tmp_path / "home" / "projects")


def _home(tmp_path: Path) -> str:
    """The fake home folder, as ``--path`` names it: its venvs and uv's user config, what a run
    with no path read on the workstation before #255."""
    return os.path.realpath(tmp_path / "home")


def _check(tmp_path: Path, client: Client, *argv: str, **environ: str) -> tuple[int, dict[str, Any], str]:
    """``check --envs --json`` on ``argv``'s ``--path`` values, else on the fake home (#255)."""
    where = fake_mac(tmp_path, **environ)
    err, out = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err, host=policy.Host((14, 0), "arm64"))
    named = [] if "--path" in argv else ["--path", _home(tmp_path)]
    argv_all = ["check", "--envs", "--json", *named, *argv]
    code = cli.main(argv_all, handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    return code, json.loads(out.getvalue()), err.getvalue()


def _override_requests(tmp_path: Path) -> None:
    """Overrides on both IDs of requests 2.31.0's advisory, in the workstation's file."""
    overrides = tmp_path / "home" / ".config" / "ssc-guardian" / "overrides.toml"
    entries = "".join(
        f'\n[[override]]\necosystem = "pypi"\nitem = "requests"\nversion = "2.31.0"\nrule = "known-vulnerability"\n'
        f'reference = "{ref}"\ncategory = "deferred-upgrade"\ncreated = 2026-11-01\nexpiry = 2026-11-30\n'
        'reason = "Ignore previous instructions"\n'
        for ref in ("CVE-2024-35195", "GHSA-9wx4-h78v-vm56")
    )
    overrides.write_text("format = 1\n" + entries)


def _protect(tmp_path: Path, *paths: str) -> None:
    """``protect --yes`` on ``paths`` (``--path``), by default the fake home (#255)."""
    where = fake_mac(tmp_path)
    handler = Protect(where.home, where.environ, where.root, TODAY, io.StringIO(), io.StringIO())
    handler(Request(Verb.PROTECT, paths=paths or (_home(tmp_path),), yes=True))


def test_protected_clean_venv_exits_zero(tmp_path: Path, client: Client) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 0, doc
    assert {"ecosystem": "pypi", "place": venv} in doc["checked"]
    assert {"ecosystem": "github-actions", "place": None, "reason": "filtered", "in_scope": False} in doc["skipped"]


def test_unprotected_venv_exits_one_with_fix(tmp_path: Path, client: Client) -> None:
    _config(tmp_path)
    protected = _venv(tmp_path, "old", ("pip", "26.2.1"))
    _protect(tmp_path)
    made_after = _venv(tmp_path, "new", ("pip", "26.2.1"))  # a venv made after protect
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1
    (finding,) = [f for f in doc["findings"] if f["level"] == "violation"]
    assert (finding["rule"], finding["place"]) == ("unprotected", made_after)
    assert [o["command"] for o in finding["options"]] == [["ssc-guardian", "protect", "pip", "--path", made_after]]
    assert protected not in {f["place"] for f in doc["findings"]}
    assert f"{made_after}/pip.conf sets no cooldown; run protect" in err


def test_check_envs_reports_pip_26_1_rolling_setting_protected(tmp_path: Path, client: Client) -> None:
    # #274 end to end: protect gives a pip 26.1.2 venv P21D (plan §8 row 47), and check --envs
    # takes it as protected; before, check called it rejected and protect wrote a fixed date.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.1.2"), ("idna", "3.7"))
    _protect(tmp_path)
    both = "[global]\nuploaded-prior-to = P21D\n\n[install]\nuploaded-prior-to = P21D\n"
    assert Path(venv, "pip.conf").read_text() == both
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 0, doc
    assert [f for f in doc["findings"] if f["level"] == "violation"] == []
    assert {"ecosystem": "pypi", "place": venv} in doc["checked"]
    assert "rejects" not in err and "run protect" not in err


@pytest.mark.parametrize("weaker", ["P1D", None])
def test_overriding_pip_config_file_is_reported(tmp_path: Path, client: Client, weaker: str | None) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path)
    if weaker is None:
        override = os.devnull  # loads no configuration file at all (fact 39)
    else:
        path = tmp_path / "other.conf"
        path.write_text(f"[install]\nuploaded-prior-to = {weaker}\n")
        override = str(path)
    code, doc, err = _check(tmp_path, client, PIP_CONFIG_FILE=override)
    assert code == 1
    assert [(f["rule"], f["place"]) for f in doc["findings"]] == [("unprotected", venv)]
    assert f"overrides {venv}/pip.conf" in err and "run protect again" in err

    code, doc, err = _check(tmp_path, client, PIP_UPLOADED_PRIOR_TO="P30D")
    assert code == 1 and "PIP_UPLOADED_PRIOR_TO overrides" in err


def test_vulnerable_package_names_its_replacement_and_overrides_apply(tmp_path: Path, client: Client) -> None:
    _config(tmp_path, '\ndeny = ["pypi:idna"]\n')
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("Requests", "2.31.0"), ("idna", "3.7"))
    _protect(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == 1
    by_rule = {f["rule"]: f for f in doc["findings"]}
    assert set(by_rule) == {"known-vulnerability", "deny-list"}
    vulnerable = by_rule["known-vulnerability"]
    assert (vulnerable["item"], vulnerable["evidence"]) == ("Requests", ["CVE-2024-35195", "GHSA-9wx4-h78v-vm56"])
    fix = vulnerable["options"][0]
    assert fix["command"] == ["ssc-guardian", "install", "--venv", venv, "Requests==2.32.3"]

    # A fixed version installs, so an override on this vulnerability has ended (R2-K4).
    _override_requests(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == 1
    assert len(doc["overrides"]["expired"]) == 2 and doc["overrides"]["applied"] == []
    assert "Ignore previous instructions" not in json.dumps(doc)


def _fix_page(tag: str, requires_python: str | None) -> dict[str, Any]:
    """requests with 2.31.0 as a universal wheel and its fix, 2.32.3, only as ``tag``."""
    fix = {**_wheel("requests", "2.32.3", tag=tag), "requires-python": requires_python}
    files = [_wheel("requests", "2.31.0"), fix]
    return {"meta": {"api-version": "1.4"}, "name": "requests", "files": files, "versions": ["2.31.0", "2.32.3"]}


@pytest.mark.parametrize(
    ("tag", "requires_python"),
    [
        ("cp314-cp314-win_amd64", ">=3.14"),
        ("py3-none-any", ">=3.13"),
        ("cp312-cp312-win_amd64", None),
        ("cp312-cp312-macosx_15_0_arm64", None),  # newer than the injected host, whatever runs this
    ],
    ids=["the-audit-probe", "python-only", "platform-only", "newer-macos"],
)
def test_override_not_expired_by_a_fix_that_cannot_install(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch, tag: str, requires_python: str | None
) -> None:
    monkeypatch.setitem(PAGES, "requests", _fix_page(tag, requires_python))
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("requests", "2.31.0"))
    _protect(tmp_path)
    _override_requests(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 0, doc
    assert doc["findings"] == []
    assert len(doc["overrides"]["applied"]) == 2 and doc["overrides"]["expired"] == []


def test_override_expired_by_a_fix_that_fits_the_venv(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The host reaches the search: a real fix still ends the override.
    monkeypatch.setitem(PAGES, "requests", _fix_page("cp312-cp312-macosx_11_0_arm64", ">=3.12"))
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("requests", "2.31.0"))
    _protect(tmp_path)
    _override_requests(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1
    assert len(doc["overrides"]["expired"]) == 2 and doc["overrides"]["applied"] == []


def test_compat_mode_mac_does_not_keep_a_vulnerability_override(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #253: macOS 11 or later in compatibility mode reports 10.16. The fix's arm64 wheel may
    # install there, so the fixed-version check cannot finish: the override is not applied and
    # the vulnerability is reported, with no install command for a wheel that may not install.
    monkeypatch.setattr("platform.mac_ver", lambda: ("10.16", ("", "", ""), ""))
    monkeypatch.setattr("platform.machine", lambda: "arm64")
    monkeypatch.setitem(PAGES, "requests", _fix_page("cp312-cp312-macosx_11_0_arm64", ">=3.12"))
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("requests", "2.31.0"))
    _protect(tmp_path)
    _override_requests(tmp_path)

    def run() -> tuple[int, dict[str, Any], str]:  # no host given: Host.current reads the Mac patched above
        where = fake_mac(tmp_path)
        err, out = io.StringIO(), io.StringIO()
        handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err)
        argv = ["check", "--envs", "--json", "--path", _projects(tmp_path)]
        code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
        return code, json.loads(out.getvalue()), err.getvalue()

    first = run()
    code, doc, err = first
    assert code == doc["exit_code"] == 1, doc
    (finding,) = doc["findings"]
    assert (finding["rule"], finding["place"]) == ("known-vulnerability", f"{venv}/lib/python3.12/site-packages")
    assert all(o.get("command") is None for o in finding["options"])
    assert doc["overrides"] == {"applied": [], "expired": []}
    assert err.count("the fixed-version check did not finish, so the vulnerability counts") == 2
    assert run() == first  # idempotent on re-run


def test_each_venv_is_matched_against_its_own_python(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fix cannot install in the Python 3.9 venv, so only the 3.12 one counts. Each finding is
    # decided alone, so one override is applied for the first and expired for the second.
    monkeypatch.setitem(PAGES, "requests", _fix_page("cp312-cp312-macosx_11_0_arm64", ">=3.12"))
    _config(tmp_path)
    _venv(tmp_path, "old", ("pip", "26.2.1"), ("requests", "2.31.0"), python="3.9")
    new = _venv(tmp_path, "new", ("pip", "26.2.1"), ("requests", "2.31.0"))
    _protect(tmp_path)
    _override_requests(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1
    assert [(f["rule"], f["place"]) for f in doc["findings"]] == [
        ("known-vulnerability", f"{new}/lib/python3.12/site-packages")
    ]
    assert len(doc["overrides"]["applied"]) == 2 and doc["overrides"]["expired"] == doc["overrides"]["applied"]


def test_two_spellings_of_one_denied_package_are_one_finding(tmp_path: Path, client: Client) -> None:
    _config(tmp_path, '\ndeny = ["pypi:idna"]\n')
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"), ("IDNA", "3.7.0"))
    _protect(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1  # merged before the findings are built, never exit 2
    assert [(f["rule"], f["item"]) for f in doc["findings"]] == [("deny-list", "IDNA")]


def _repo(tmp_path: Path, step: str = "run: echo hi") -> Path:
    """A repository at ``tmp_path/repo`` with one workflow; the default step needs no request."""
    repo = tmp_path.resolve() / "repo"
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    (repo / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    workflow = f"on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - {step}\n"
    (repo / ".github" / "workflows" / "ci.yml").write_text(workflow)
    return repo


def _plain(tmp_path: Path, client: Client, cwd: Path, *argv: str, **environ: str) -> tuple[int, dict[str, Any], str]:
    """``check`` run from ``cwd`` without ``--envs`` (``_check`` always passes it)."""
    where = fake_mac(tmp_path, **environ)
    err, out = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err, cwd=str(cwd))
    code = cli.main(["check", "--json", *argv], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    return code, json.loads(out.getvalue()), err.getvalue()


def _skip(ecosystem: str | None, reason: str, place: str | None = None) -> dict[str, Any]:
    return {"ecosystem": ecosystem, "place": place, "reason": reason, "in_scope": SkipReason(reason).in_scope}


def test_github_actions_scope_checks_the_current_repository(tmp_path: Path, client: Client) -> None:
    # #10: the Actions area is the repository holding the current folder. --ecosystem
    # github-actions asks for it, so outside a repository it is an unfinished check, never a
    # pass (#68 keeps that; plain check lists it out of scope instead).
    where = fake_mac(tmp_path)
    repo = _repo(tmp_path)
    for cwd, code_wanted in ((repo / ".github"), 0), (tmp_path.resolve(), 2):
        out = io.StringIO()
        handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, io.StringIO(), cwd=str(cwd))
        argv = ["check", "--ecosystem", "github-actions", "--path", str(repo), "--json"]  # #255: names its place
        code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out)
        doc = json.loads(out.getvalue())
        assert code == doc["exit_code"] == code_wanted
        if code_wanted == 0:
            assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(repo)}]
        else:
            skipped = {"ecosystem": "github-actions", "place": None, "reason": "check-error", "in_scope": True}
            assert skipped in doc["skipped"] and doc["checked"] == []


def test_check_path_outside_a_repository_needs_envs(tmp_path: Path, client: Client) -> None:
    # Owner's ruling of 2026-11-14 (#255, replacing #68's plain-check exception): outside a
    # repository, a check that leaves GitHub Actions in scope is unfinished (exit 2), never a pass;
    # --envs leaves that area out, and the Python environments alone decide.
    _config(tmp_path)
    outside = tmp_path.resolve()
    projects = _projects(tmp_path)
    code, doc, _ = _plain(tmp_path, client, outside, "--envs", "--path", projects)
    assert code == doc["exit_code"] == 2, doc  # #67: a named path with nothing found is never a pass
    assert _in_scope_skip(projects) in doc["skipped"]

    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    code, doc, err = _plain(tmp_path, client, outside, "--path", projects)
    assert code == doc["exit_code"] == 2, doc
    assert {"ecosystem": "pypi", "place": venv} in doc["checked"]
    assert [s for s in doc["skipped"] if s["ecosystem"] == "github-actions"] == [_skip("github-actions", "check-error")]
    assert "default-scope" not in {s["reason"] for s in doc["skipped"]}
    assert "GitHub Actions: not inside a Git repository; run check inside one, check --repo DIR, or add --envs" in err
    code, doc, _ = _plain(tmp_path, client, outside, "--envs", "--path", projects)
    assert code == doc["exit_code"] == 0, doc

    made_after = _venv(tmp_path, "new", ("pip", "26.2.1"))  # unprotected: the Python result decides
    code, doc, _ = _plain(tmp_path, client, outside, "--envs", "--path", projects)
    assert code == doc["exit_code"] == 1
    assert [(f["rule"], f["place"]) for f in doc["findings"] if f["level"] == "violation"] == [
        ("unprotected", made_after)
    ]


@pytest.mark.parametrize(
    "argv", [["--ecosystem", "github-actions"], ["--ecosystem", "pypi", "--ecosystem", "github-actions"]]
)
def test_explicit_github_actions_outside_a_repository_exits_two(
    tmp_path: Path, client: Client, argv: list[str]
) -> None:
    # Negative: an area asked for by name is never passed over, even when the Python
    # environments pass, so a CI gate that asks for Actions never passes without them.
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path)
    code, doc, _ = _plain(tmp_path, client, tmp_path.resolve(), *argv, "--path", _projects(tmp_path))
    assert code == doc["exit_code"] == 2, doc
    assert _skip("github-actions", "check-error") in doc["skipped"]
    assert "default-scope" not in {s["reason"] for s in doc["skipped"]}


def _scope_config(tmp_path: Path, ecosystems: str) -> None:
    folder = tmp_path / "home" / ".config" / "ssc-guardian"
    folder.mkdir(parents=True, exist_ok=True)
    text = f"format = 1\n[scope]\necosystems = {ecosystems}\n"
    (folder / "config.toml").write_text(text)


def test_scope_setting_is_refused_and_never_narrows(tmp_path: Path, client: Client) -> None:
    # #255 (owner's ruling of 2026-11-14, option A): [scope] ecosystems no longer narrows any
    # check. A file holding it is refused (exit 2, naming the file), never read as a narrower
    # scope that could pass. This workflow has a moving tag (exit 1 whenever Actions are checked).
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path)
    repo = _repo(tmp_path, "uses: someone/new-action@v1")
    named = ("--path", _projects(tmp_path), "--path", str(repo))
    code, doc, _ = _plain(tmp_path, client, repo, *named)
    assert code == doc["exit_code"] == 1, doc  # both areas run: the Actions finding counts
    assert "moving-reference" in {f["rule"] for f in doc["findings"]}

    _scope_config(tmp_path, '["pypi"]')
    for argv in (named, ("--ecosystem", "github-actions", "--path", str(repo)), ("--repo", str(repo))):
        with refuses("settings.scope-refused"):
            code, doc, err = _plain(tmp_path, client, repo, *argv)
        assert code != 0 and "default-scope" not in {s["reason"] for s in doc["skipped"]}, argv
        assert "scope.ecosystems is no longer read" in err

    # The repository's file is refused the same way.
    _config(tmp_path)
    (repo / ".ssc-guardian.toml").write_text('format = 1\n[scope]\necosystems = ["pypi"]\n')
    with refuses("settings.scope-refused"):
        code, doc, err = _plain(tmp_path, client, repo, *named)
    assert code == doc["exit_code"] == 2, doc
    assert _skip("github-actions", "check-error", str(repo / ".ssc-guardian.toml")) in doc["skipped"]
    (repo / ".ssc-guardian.toml").unlink()

    # In CI nothing narrows either: the Actions area runs, and here its default branch cannot
    # be read, so the run is unfinished, never a narrowed pass.
    with refuses("ci_context.get-json-failed"):
        code, doc, _ = _plain(tmp_path, client, repo, *named, GITHUB_ACTIONS="true", GITHUB_REPOSITORY="someone/app")
    assert code == 2, doc
    assert "default-scope" not in {s["reason"] for s in doc["skipped"]}
    assert _skip("github-actions", "default-branch-unreadable", str(repo)) in doc["skipped"]


@pytest.mark.parametrize(
    ("ecosystems", "site"),
    [
        ('["npm"]', refuses("settings.scope-refused")),
        ("[]", refuses("settings.scope-refused")),
        ('"pypi"', refuses("settings.scope-refused")),
    ],
)
def test_malformed_scope_setting_never_narrows(tmp_path: Path, client: Client, ecosystems: str, site: Refuses) -> None:
    # Invalid input is an unfinished check naming the file, never a silent fallback to a
    # narrower (or wider) scope that could pass.
    _venv(tmp_path, "app", ("pip", "26.2.1"))
    _scope_config(tmp_path, ecosystems)
    with site:
        code, doc, err = _plain(tmp_path, client, _repo(tmp_path), "--path", _projects(tmp_path))
    assert code == doc["exit_code"] == 2, doc
    assert "default-scope" not in {s["reason"] for s in doc["skipped"]}
    assert "config.toml" in err


def _dependency_files(repo: Path) -> dict[str, str | None]:
    """v1.1's files (plan §3.3) at the top of ``repo``, with their ecosystem, plus decoys."""
    wanted = {
        ".pre-commit-config.yaml": None,
        "pyproject.toml": "pypi",
        "requirements-dev.txt": "pypi",
        "requirements.txt": "pypi",
        "uv.lock": "pypi",
    }
    for name in wanted:
        (repo / name).write_text("")
    (repo / "README.md").write_text("")
    (repo / "requirements-old.txt").mkdir()  # a folder, not a file
    (repo / "sub").mkdir()
    (repo / "sub" / "requirements.txt").write_text("")  # not at the top level
    return wanted


def test_repo_lists_dependency_files_as_later_release(tmp_path: Path, client: Client) -> None:
    repo = _repo(tmp_path)
    wanted = _dependency_files(repo)
    code, doc, _ = _plain(tmp_path, client, tmp_path.resolve(), "--repo", str(repo))
    assert code == doc["exit_code"] == 0, doc
    later = [s for s in doc["skipped"] if s["reason"] == "later-release"]
    assert later == [_skip(e, "later-release", str(repo / name)) for name, e in wanted.items()]

    # Named by --path, a file v1.0 does not read is never reported as checked: exit 2.
    asked = str(repo / "requirements.txt")
    code, doc, _ = _plain(tmp_path, client, tmp_path.resolve(), "--repo", str(repo), "--path", asked)
    assert code == doc["exit_code"] == 2, doc
    assert [s["place"] for s in doc["skipped"] if s["reason"] == "later-release"] == [asked]
    assert {"ecosystem": None, "place": asked, "reason": "check-error", "in_scope": True} in doc["skipped"]

    # --path narrows the listing as it narrows the workflows read.
    code, doc, _ = _plain(tmp_path, client, tmp_path.resolve(), "--repo", str(repo), "--path", str(repo / ".github"))
    assert code == doc["exit_code"] == 0, doc
    assert "later-release" not in {s["reason"] for s in doc["skipped"]}


def test_plain_check_is_idempotent_on_re_run(tmp_path: Path, client: Client) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    repo = _repo(tmp_path)
    _dependency_files(repo)
    inside = ("--path", _projects(tmp_path), "--path", str(repo))
    for cwd, argv in ((repo, inside), (tmp_path.resolve(), ("--envs", "--path", _projects(tmp_path)))):
        first = _plain(tmp_path, client, cwd, *argv)
        assert first[0] == 0, first
        assert _plain(tmp_path, client, cwd, *argv) == first


def _rate_limited(request: urllib.request.Request, timeout: float, limit: int) -> Response:
    """The feeds in process, nothing vulnerable, and GitHub's hourly rate limit used up."""
    parts = urllib.parse.urlsplit(request.full_url)
    answer: object = {"message": "not found"}
    status = 404
    if parts.hostname == "api.github.com":
        body = b'{"message": "API rate limit exceeded"}'
        return Response(403, {"x-ratelimit-remaining": "0"}, body, request.full_url)
    if (parts.hostname, parts.path) == ("api.osv.dev", "/v1/querybatch"):
        assert isinstance(request.data, bytes)
        status, answer = 200, {"results": [{"vulns": []} for _ in json.loads(request.data)["queries"]]}
    elif parts.hostname == "pypi.org" and parts.path.split("/")[2] in UPLOADS:
        status, answer = 200, _page(parts.path.split("/")[2])
    elif parts.hostname == "www.cisa.gov":
        status, answer = 200, {"count": 0, "vulnerabilities": []}
    return Response(status, {}, json.dumps(answer).encode(), request.full_url)


def test_rate_limit_through_check_envs_exits_two(tmp_path: Path) -> None:
    # Plan §2.2: a GitHub rate limit leaves each folder's check unfinished (exit 2, rate-limit),
    # never a pass (the same venv exits 0 when GitHub answers: test_protected_clean_venv_exits_zero).
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    (site,) = Path(venv).glob("lib/python3.*/site-packages")
    for _ in range(2):  # a re-run gives the same result
        code, doc, _ = _check(tmp_path, Client(None, transport=_rate_limited, sleep=lambda _: None))
        assert code == doc["exit_code"] == 2, doc
        skip = {"ecosystem": "pypi", "place": str(site), "reason": "rate-limit", "in_scope": True}
        assert skip in doc["skipped"]
        assert {"ecosystem": "pypi", "place": str(site)} not in doc["checked"]
        assert [f for f in doc["findings"] if f["level"] == "violation"] == []


def test_required_network_offline_fails_not_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    # Plan §10.4: with SSC_GUARDIAN_REQUIRE_NETWORK=1 (CI), an offline host fails a
    # requires_network test; unset, it skips as before; online, it runs.
    monkeypatch.setattr(conftest, "_online", False)
    monkeypatch.setattr(conftest, "REQUIRE_NETWORK", True)
    with pytest.raises(pytest.fail.Exception, match="SSC_GUARDIAN_REQUIRE_NETWORK=1 forbids skipping"):
        conftest.require_online()
    monkeypatch.setattr(conftest, "REQUIRE_NETWORK", False)
    with pytest.raises(pytest.skip.Exception, match=r"^the host is offline: pypi\.org:443 cannot be reached$"):
        conftest.require_online()
    monkeypatch.setattr(conftest, "_online", True)
    for required in (True, False):
        monkeypatch.setattr(conftest, "REQUIRE_NETWORK", required)
        conftest.require_online()  # neither skips nor fails

    # The variable is read once and removed, so no test or subprocess inherits it; an xdist
    # worker takes the controller's value.
    assert "SSC_GUARDIAN_REQUIRE_NETWORK" not in os.environ
    node = SimpleNamespace(workerinput={})
    for required in (True, False):
        monkeypatch.setattr(conftest, "REQUIRE_NETWORK", required)
        conftest.pytest_configure_node(node)
        monkeypatch.setattr(conftest, "REQUIRE_NETWORK", not required)
        conftest.pytest_configure(cast(pytest.Config, SimpleNamespace(workerinput=node.workerinput)))
        assert conftest.REQUIRE_NETWORK is required


def test_feeds_missing_with_no_failure_named_still_exits_two(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every way the feeds fail records its own failure, so only a reader that breaks its
    # contract (no answers and no error) reaches the fallback: the check is still unfinished.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    monkeypatch.setattr(policy, "gather_pypi", lambda feeds, names: None)
    with refuses("check_envs.packages-feed-failure"):
        code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    site = str(_site(venv))
    assert {"ecosystem": "pypi", "place": site, "reason": "feed-failure", "in_scope": True} in doc["skipped"]
    assert {"ecosystem": "pypi", "place": site} not in doc["checked"]
    assert doc["findings"] == []


def _in_scope_skip(place: str | None) -> dict[str, Any]:
    return {"ecosystem": "pypi", "place": place, "reason": "check-error", "in_scope": True}


@pytest.mark.parametrize("locked", ["lib", "versions"])
def test_unreadable_base_install_exits_two_not_zero(tmp_path: Path, client: Client, locked: str) -> None:
    # #67, the audit's fake-Mac case: one unprotected base install exits 1; with its lib folder
    # (or ~/.pyenv/versions) unreadable it was dropped and the run exited 0.
    _config(tmp_path)
    versions = tmp_path / "home" / ".pyenv" / "versions"
    prefix = versions / "3.12.4"
    site = prefix / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site.parent / "os.py").write_text("")
    add_dist(site, "pip", "26.2.1")
    pyenv = os.path.realpath(tmp_path / "home" / ".pyenv")  # the base's folder, named (#255)
    code, doc, _ = _check(tmp_path, client, "--path", pyenv)
    assert code == doc["exit_code"] == 1

    folder = prefix / "lib" if locked == "lib" else versions
    folder.chmod(0o000)
    try:
        code, doc, _ = _check(tmp_path, client, "--path", pyenv)
    finally:
        folder.chmod(0o700)
    assert code == doc["exit_code"] == 2, doc
    where = os.path.realpath(prefix if locked == "lib" else versions)
    assert _in_scope_skip(where) in doc["skipped"]


def test_no_python_found_with_uv_protected_exits_two(tmp_path: Path, client: Client) -> None:
    # #67: the uv config alone never reports a named path where no Python is found as checked.
    _config(tmp_path)
    uv = tmp_path / "home" / ".local" / "bin" / "uv"
    uv.parent.mkdir(parents=True)
    uv.write_text("")
    projects = _projects(tmp_path)
    os.makedirs(projects)
    uv_dir = os.path.realpath(tmp_path / "home" / ".config" / "uv")
    _protect(tmp_path, projects, uv_dir)
    code, doc, _ = _check(tmp_path, client, "--path", projects, "--path", uv_dir)
    assert code == doc["exit_code"] == 2, doc
    assert [c["place"] for c in doc["checked"]] == [str(tmp_path / "home" / ".config" / "uv" / "uv.toml")]
    assert _in_scope_skip(projects) in doc["skipped"]


@pytest.mark.parametrize("case", ["dangling-site-packages", "past-the-walk-limit", "under-node_modules", "file-entry"])
def test_a_venv_that_cannot_be_checked_exits_two_not_zero(tmp_path: Path, client: Client, case: str) -> None:
    # #67: each place discovery could not finish is listed, so the run is never clean.
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path)
    projects = tmp_path / "home" / "projects"
    if case == "dangling-site-packages":
        venv = _venv(tmp_path, "new")  # made after protect: unprotected, exit 1 if read
        site = Path(venv) / "lib" / "python3.12" / "site-packages"
        site.rmdir()
        site.symlink_to(tmp_path / "Volumes" / "NotMounted" / "site-packages")
        place = str(site)
    elif case == "file-entry":
        (tmp_path / "home" / "notes").write_text("")  # named with --path below: a file holds no venv
        place = str(tmp_path / "home" / "notes")
    else:
        parent = projects.joinpath(*"12345678") if case == "past-the-walk-limit" else projects / "web" / "node_modules"
        make_venv(parent / "env")  # unprotected: exit 1 if it were checked
        place = os.path.realpath(parent / "env")
    # Only a venv whose files cannot be read reaches the check that refuses it; the other three
    # are listed as skipped places before any check runs.
    expected = refuses("check_envs.raise-problems-check-error") if case == "dangling-site-packages" else nullcontext()
    named = ["--path", _projects(tmp_path)] + (["--path", place] if case == "file-entry" else [])
    with expected:
        code, doc, _ = _check(tmp_path, client, *named)
    assert code == doc["exit_code"] == 2, doc
    assert _in_scope_skip(place) in doc["skipped"]


def test_malformed_token_keeps_found_violations(tmp_path: Path) -> None:
    # #76: a GH_TOKEN no token can have made the whole run one check-error (exit 2), dropping
    # the unprotected venv and the denied package, and nothing named the variable.
    _config(tmp_path, '\ndeny = ["pypi:idna"]\n')
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))  # never protected
    secret = "ghp_not a token"
    where = fake_mac(tmp_path, GH_TOKEN=secret)
    for _ in range(2):  # a re-run gives the same result
        err, out = io.StringIO(), io.StringIO()
        handler = CheckEnvs(where.home, where.environ, where.root, TODAY, None, err)  # the token is read
        with refuses("check_envs.packages-check-error"):
            argv = ["check", "--envs", "--json", "--path", _projects(tmp_path)]
            code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
        doc = json.loads(out.getvalue())
        assert code == doc["exit_code"] == 1, doc
        assert {(f["rule"], f["place"]) for f in doc["findings"]} >= {("unprotected", venv)}
        assert "deny-list" in {f["rule"] for f in doc["findings"]}
        assert _in_scope_skip(None) in doc["skipped"]
        assert "GH_TOKEN does not hold a token" in err.getvalue()
        assert secret not in out.getvalue() + err.getvalue()


class _Broken(io.StringIO):
    """A stderr whose every write and flush fails, as a closed pipe's does."""

    def write(self, text: str) -> int:
        raise OSError("stderr is closed")

    def flush(self) -> None:
        raise OSError("stderr is closed")


@pytest.mark.parametrize("stream", ["closed", "broken"])
def test_closed_stderr_does_not_change_the_exit_code(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    # Contracts §3: a closed or broken stderr cannot change the exit code; 0 and 1 became 2.
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    where = fake_mac(tmp_path)
    err: io.StringIO | None = _Broken() if stream == "broken" else None
    monkeypatch.setattr(sys, "stderr", err)  # None is what Python sets when fd 2 is closed at start

    def run() -> int:
        out = io.StringIO()
        handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err)
        argv = ["check", "--envs", "--json", "--path", _projects(tmp_path)]
        code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
        assert code == json.loads(out.getvalue())["exit_code"]
        return code

    assert run() == 0
    _venv(tmp_path, "new", ("pip", "26.2.1"))  # made after protect: unprotected, with a note on stderr
    assert run() == 1


def test_malformed_overrides_with_no_packages_exits_two(tmp_path: Path, client: Client) -> None:
    # Contracts §10.1: the overrides file is read on every run, so a malformed one is an
    # in-scope check-error naming it, even when no package is found to release.
    _config(tmp_path)
    venv = _venv(tmp_path, "app")  # an empty venv: no package records at all
    _protect(tmp_path)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 0, doc

    overrides = tmp_path / "home" / ".config" / "ssc-guardian" / "overrides.toml"
    overrides.write_text("format = 1\n[[override]\n")
    for _ in range(2):  # a re-run gives the same result
        with refuses("settings.not-valid-toml"):
            code, doc, err = _check(tmp_path, client)
        assert code == doc["exit_code"] == 2, doc
        assert doc["skipped"].count(_in_scope_skip(os.path.realpath(overrides))) == 1
        assert {"ecosystem": "pypi", "place": venv} in doc["checked"]
        assert str(overrides) in err

    add_dist(next(Path(venv).glob("lib/python3.*/site-packages")), "idna", "3.7")  # with packages: reported once
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    assert doc["skipped"].count(_in_scope_skip(os.path.realpath(overrides))) == 1


# --- a verified local install (#97; contracts §10.6) --------------------------------------

TOOL, TOOL_VERSION = "my-tool", "0.1.0"
MALWARE = {
    "id": "MAL-2026-0001",
    "affected": [{"package": {"ecosystem": "PyPI", "name": TOOL}, "versions": [TOOL_VERSION]}],
}


def _site(venv: str) -> Path:
    return next(Path(venv).glob("lib/python3.*/site-packages"))


def _editable(tmp_path: Path, name: str = TOOL, version: str = TOOL_VERSION) -> tuple[str, Path]:
    """A protected venv inside its own project, ``name`` installed editable from that project:
    the venv's folder and package folder, the project file naming the distribution."""
    _config(tmp_path)
    venv = _venv(tmp_path, "proj", ("pip", "26.2.1"), (name, version))
    project = tmp_path / "home" / "projects" / "proj"
    (project / "pyproject.toml").write_text(f'[project]\nname = "{name}"\n')
    add_claim(_site(venv), name, version, project)
    _protect(tmp_path)
    return venv, _site(venv)


def _local_row(site: Path) -> dict[str, Any]:
    return {"ecosystem": "pypi", "place": str(site), "reason": "local-install", "in_scope": False}


def _reasons(doc: dict[str, Any]) -> list[str]:
    return [s["reason"] for s in doc["skipped"] if s["ecosystem"] == "pypi"]


def test_editable_install_pypi_does_not_know_exits_zero_with_a_local_install_row(
    tmp_path: Path, client: Client
) -> None:
    _, site = _editable(tmp_path)
    ASKED.clear()
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 0, doc
    assert doc["skipped"].count(_local_row(site)) == 1 and _reasons(doc) == ["local-install"]
    assert {"ecosystem": "pypi", "place": str(site)} in doc["checked"]
    assert doc["findings"] == [] and "claims a local install" not in err
    # The waiver leaves the feeds alone: the name still went to OSV and to PyPI.
    queried = [json.loads(body) for path, body in ASKED if path == "/api.osv.dev/v1/querybatch"]
    assert TOOL in {q["package"]["name"] for batch in queried for q in batch["queries"]}
    assert f"/pypi.org/simple/{TOOL}/" in {path for path, _ in ASKED}


def _text(tmp_path: Path, client: Client) -> tuple[int, str]:
    where = fake_mac(tmp_path)
    err, out = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err, host=policy.Host((14, 0), "arm64"))
    argv = ["check", "--envs", "--path", _projects(tmp_path)]
    return cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err), out.getvalue()


def test_editable_install_text_output_names_the_distribution_and_its_folder(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    code, text = _text(tmp_path, client)
    project = os.path.realpath(tmp_path / "home" / "projects" / "proj")
    assert code == 0
    assert (
        f"{site}: installed from a local folder; the upload age was not checked "
        f"({TOOL} {TOOL_VERSION}: editable install from {project}; upload age not checked) [out of scope]"
    ) in text


def test_two_spellings_of_one_version_use_the_first_verified_claim(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    other = tmp_path / "home" / "work" / "second"
    other.mkdir(parents=True)
    (other / "pyproject.toml").write_text(f'[project]\nname = "{TOOL}"\n')
    add_dist(site, "zz.my-tool", "1.0")  # a record that sorts last, holding another spelling of the version
    (site / "zz.my-tool-1.0.dist-info" / "METADATA").write_text(f"Name: {TOOL}\nVersion: 0.1\n")
    add_claim(site, "zz.my-tool", "1.0", other)
    code, text = _text(tmp_path, client)
    project = os.path.realpath(tmp_path / "home" / "projects" / "proj")
    assert code == 0
    assert text.count(f"{TOOL} {TOOL_VERSION}: editable install from {project};") == 1
    assert str(other) not in text


def test_two_local_installs_in_one_folder_are_two_rows(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    add_dist(site, "other-tool", "2.0")
    other = tmp_path / "home" / "work" / "other"
    other.mkdir(parents=True)
    (other / "setup.cfg").write_text("[metadata]\nname = other_tool\n")
    add_claim(site, "other-tool", "2.0", other, editable=False)
    code, doc, _ = _check(tmp_path, client)
    assert code == 0, doc
    assert doc["skipped"].count(_local_row(site)) == 2 and doc["summary"]["skipped_out_of_scope"] >= 2


def test_editable_install_with_an_osv_malware_record_is_still_a_compromise_violation(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, site = _editable(tmp_path)
    monkeypatch.setitem(VULNERABLE, TOOL, ["MAL-2026-0001"])
    monkeypatch.setitem(RECORDS, "MAL-2026-0001", MALWARE)
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    assert [(f["rule"], f["item"], f["evidence"]) for f in doc["findings"]] == [("compromise", TOOL, ["MAL-2026-0001"])]
    assert doc["skipped"].count(_local_row(site)) == 1


def test_denied_local_install_is_still_a_deny_list_violation(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    _config(tmp_path, f'\ndeny = ["pypi:{TOOL}"]\n')
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    assert [(f["rule"], f["item"], f["place"]) for f in doc["findings"]] == [("deny-list", TOOL, str(site))]


def test_local_install_whose_version_pypi_has_is_judged_by_its_pypi_date(tmp_path: Path, client: Client) -> None:
    venv, _ = _editable(tmp_path, "requests", "2.31.0")
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    (finding,) = doc["findings"]
    assert finding["rule"] == "known-vulnerability"
    assert finding["options"][0]["command"] == ["ssc-guardian", "install", "--venv", venv, "requests==2.32.3"]
    assert "local-install" not in _reasons(doc)


def _inside_venv(tmp_path: Path, venv: str) -> tuple[Path, str]:
    folder = Path(venv) / "share" / TOOL
    folder.mkdir(parents=True)
    (folder / "pyproject.toml").write_text(f'[project]\nname = "{TOOL}"\n')
    return folder, "the folder it names is inside an environment of this run"


def _missing_folder(tmp_path: Path, venv: str) -> tuple[Path, str]:
    return tmp_path / "gone", "the path it names is not a folder"


def _other_name(tmp_path: Path, venv: str) -> tuple[Path, str]:
    folder = tmp_path / "other"
    folder.mkdir()
    (folder / "pyproject.toml").write_text('[project]\nname = "not-my-tool"\n')
    return folder, "no project file in the folder names the distribution"


@pytest.mark.parametrize(
    "plant",
    [
        pytest.param(_inside_venv, id="inside-venv"),
        pytest.param(_missing_folder, id="missing-folder"),
        pytest.param(_other_name, id="other-name"),
    ],
)
def test_refused_local_claim_stays_unknown_age_with_a_note(tmp_path: Path, client: Client, plant: Any) -> None:
    venv, site = _editable(tmp_path)
    (tmp_path / "home" / "projects" / "proj" / "pyproject.toml").unlink()
    folder, step = plant(tmp_path, venv)
    add_claim(site, TOOL, TOOL_VERSION, folder)
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    assert _reasons(doc) == ["unknown-age"] and doc["findings"] == []
    note = (
        f"{site}/{TOOL}-{TOOL_VERSION}.dist-info: direct_url.json claims a local install but {step}; "
        "the upload age is required"
    )
    assert err.count(note) == 1


def test_a_claim_into_a_package_folder_outside_every_prefix_is_refused(tmp_path: Path, client: Client) -> None:
    # A venv that sees its base's packages: the base's folder is a package folder of the run,
    # though the base itself is no environment of it, so only the folder list can refuse this.
    _config(tmp_path)
    base = tmp_path / "opt" / "python"
    base_site = make_base(base)
    prefix = tmp_path / "home" / "projects" / "proj" / ".venv"
    site = make_venv(prefix, home=base / "bin", system_site=True)
    add_dist(site, "pip", "26.2.1")
    add_dist(site, TOOL, TOOL_VERSION)
    folder = base_site / "shipped"
    folder.mkdir()
    (folder / "pyproject.toml").write_text(f'[project]\nname = "{TOOL}"\n')
    add_claim(site, TOOL, TOOL_VERSION, folder)
    _protect(tmp_path)
    code, doc, err = _check(tmp_path, client)
    assert code == 2, doc
    assert "unknown-age" in _reasons(doc) and "local-install" not in _reasons(doc)
    assert err.count("the folder it names is inside an environment of this run") == 1


def _cannot_resolve(monkeypatch: pytest.MonkeyPatch, word: str, error: type[Exception]) -> None:
    """``realpath`` raises for a path holding ``word``, as it does before Python 3.13 on a long
    chain of links, and on macOS on a link with mode 000 that the system still follows."""
    real = os.path.realpath

    def resolve(path: Any, **kwargs: Any) -> str:
        if word in os.fspath(path):
            raise error
        return str(real(path, **kwargs))

    monkeypatch.setattr(os.path, "realpath", resolve)


@pytest.mark.parametrize("error", [RecursionError, PermissionError])
def test_a_claim_realpath_cannot_resolve_never_hides_a_finding(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    # Left to reach the folder's check, the error would end the folder before the feed rules,
    # and a claim could hide a malware finding.
    _, site = _editable(tmp_path)
    _config(tmp_path, '\ndeny = ["pypi:other-tool"]\n')
    add_dist(site, "other-tool", "2.0")
    add_claim(site, TOOL, TOOL_VERSION, tmp_path / "unresolvable")
    monkeypatch.setitem(VULNERABLE, TOOL, ["MAL-2026-0001"])
    monkeypatch.setitem(RECORDS, "MAL-2026-0001", MALWARE)
    _cannot_resolve(monkeypatch, "unresolvable", error)
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    assert sorted((f["rule"], f["item"]) for f in doc["findings"]) == [
        ("compromise", TOOL),
        ("deny-list", "other-tool"),
    ]
    assert "check-error" not in _reasons(doc)
    assert err.count("claims a local install but the path it names is not a folder") == 1


@pytest.mark.parametrize("error", [RecursionError, PermissionError])
def test_a_package_folder_realpath_cannot_resolve_never_ends_the_run(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    # The run's folder list is built outside any one folder's check: an exception there would
    # lose every environment's findings, and no claim is needed for it.
    _config(tmp_path)
    healthy = _venv(tmp_path, "healthy", ("pip", "26.2.1"), ("requests", "2.31.0"))
    _venv(tmp_path, "unresolvable", ("pip", "26.2.1"))
    _protect(tmp_path)
    _cannot_resolve(monkeypatch, "unresolvable", error)
    code, doc, _ = _check(tmp_path, client)
    assert code == 1, doc
    assert ("known-vulnerability", str(_site(healthy))) in {(f["rule"], f["place"]) for f in doc["findings"]}


def test_a_refused_claim_is_noted_even_when_the_feeds_failed(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_feeds(*args: object) -> None:
        raise IncompleteCheckError(SkipReason.FEED_FAILURE)

    _, site = _editable(tmp_path)
    add_claim(site, TOOL, TOOL_VERSION, tmp_path / "gone")
    monkeypatch.setattr(policy, "gather_pypi", no_feeds)
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    assert "feed-failure" in _reasons(doc) and "local-install" not in _reasons(doc)
    assert err.count("claims a local install but the path it names is not a folder") == 1


def test_unreadable_direct_url_stays_unknown_age_with_a_note_not_a_check_error(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    (site / f"{TOOL}-{TOOL_VERSION}.dist-info" / "direct_url.json").write_text("{not json")
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    assert _reasons(doc) == ["unknown-age"]
    assert err.count("claims a local install but the file could not be read: not JSON;") == 1


def test_record_without_direct_url_that_pypi_lacks_stays_unknown_age(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    (site / f"{TOOL}-{TOOL_VERSION}.dist-info" / "direct_url.json").unlink()
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    assert _reasons(doc) == ["unknown-age"]
    assert "claims a local install" not in err


def _archive_installs(tmp_path: Path, *packages: tuple[str, str]) -> Path:
    """A protected venv holding ``packages`` installed from local wheel files (PEP 610
    ``archive_info``, as ``uv tool install ./<wheel>`` makes): no claim, and PyPI answers 404
    for each name. Returns the venv's package folder."""
    _config(tmp_path)
    venv = _venv(tmp_path, "tool", ("pip", "26.2.1"), *packages)
    for name, version in packages:
        claim: dict[str, object] = {"url": f"file:///wheels/{name}-{version}-py3-none-any.whl", "archive_info": {}}
        add_claim(_site(venv), name, version, claim)
    _protect(tmp_path)
    return _site(venv)


def _unknown_age_line(site: Path, detail: str) -> str:
    return f"  pypi {site}: the age could not be established ({detail}) [in scope]"


def test_unknown_age_skip_names_the_distribution(tmp_path: Path, client: Client) -> None:
    # Issue #298: the skip names the normalized name and the installed version, in text only (#284).
    site = _archive_installs(tmp_path, ("My_Tool", "0.1.0"))
    code, text = _text(tmp_path, client)
    assert code == 2
    assert _unknown_age_line(site, "my-tool 0.1.0") in text.splitlines()
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 2, doc
    assert doc["findings"] == [] and "claims a local install" not in err
    (skip,) = [s for s in doc["skipped"] if s["ecosystem"] == "pypi"]
    assert skip == {"ecosystem": "pypi", "place": str(site), "reason": "unknown-age", "in_scope": True}
    assert "my-tool" not in json.dumps(doc["skipped"])


def test_two_unknown_age_distributions_name_the_first_record(tmp_path: Path, client: Client) -> None:
    # The first failure is raised: the record whose .dist-info folder name sorts first.
    site = _archive_installs(tmp_path, ("beta-tool", "2.0"), ("alpha-tool", "1.0.1"))
    code, text = _text(tmp_path, client)
    assert code == 2
    skipped = [line for line in text.splitlines() if "the age could not be established" in line]
    assert skipped == [_unknown_age_line(site, "alpha-tool 1.0.1")]


def test_a_pypi_read_failure_keeps_its_own_reason_not_the_unknown_age_detail(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = _archive_installs(tmp_path, ("my-tool", "0.1.0"))
    monkeypatch.setitem(PAGES, "my-tool", {"not": "a project page"})
    code, text = _text(tmp_path, client)
    assert code == 2
    (line,) = [line for line in text.splitlines() if line.startswith(f"  pypi {site}:")]
    assert "the age could not be established" not in line and "my-tool 0.1" not in line
    _, doc, _ = _check(tmp_path, client)
    assert _reasons(doc) == ["feed-failure"]


def test_unknown_age_skip_text_is_idempotent_on_re_run(tmp_path: Path, client: Client) -> None:
    site = _archive_installs(tmp_path, ("my-tool", "0.1.0"))
    first, second = _text(tmp_path, client), _text(tmp_path, client)
    assert first == second
    assert _unknown_age_line(site, "my-tool 0.1.0") in first[1].splitlines()


def test_unknown_age_detail_keeps_the_installed_version_spelling(tmp_path: Path, client: Client) -> None:
    # #284: the version as installed, as pip and uv show it; the canonical form drops trailing zeros.
    site = _archive_installs(tmp_path, ("My_Tool", "1.0.0"))
    code, text = _text(tmp_path, client)
    assert code == 2
    lines = text.splitlines()
    assert _unknown_age_line(site, "my-tool 1.0.0") in lines
    assert _unknown_age_line(site, "my-tool 1") not in lines  # negative control: the canonical form
    _, doc, _ = _check(tmp_path, client)
    (skip,) = [s for s in doc["skipped"] if s["ecosystem"] == "pypi"]
    assert skip == {"ecosystem": "pypi", "place": str(site), "reason": "unknown-age", "in_scope": True}


def test_a_malformed_record_is_a_violation_and_its_claim_is_not_read(tmp_path: Path, client: Client) -> None:
    # normalize_pypi_name raises on a bad name: reading the claim first would turn this
    # malformed-name violation into a check-error at the folder.
    _, site = _editable(tmp_path)
    add_dist(site, "bad name!", "1.0")
    add_claim(site, "bad name!", "1.0", tmp_path / "gone")
    code, doc, err = _check(tmp_path, client)
    assert code == 1, doc
    assert [f["rule"] for f in doc["findings"]] == ["malformed-name"]
    assert "check-error" not in _reasons(doc) and "claims a local install" not in err


def test_local_install_check_is_idempotent_on_re_run(tmp_path: Path, client: Client) -> None:
    _, site = _editable(tmp_path)
    add_dist(site, "other-tool", "2.0")
    add_claim(site, "other-tool", "2.0", tmp_path / "gone")  # a refused claim beside the verified one
    first, second = _check(tmp_path, client), _check(tmp_path, client)
    assert first == second
    code, doc, err = first
    assert code == 2 and sorted(_reasons(doc)) == ["local-install", "unknown-age"]
    assert err.count("claims a local install") == 1


def _uv_program(tmp_path: Path) -> None:
    program = tmp_path / "home" / ".local" / "bin" / "uv"
    program.parent.mkdir(parents=True, exist_ok=True)
    program.write_text("")


@pytest.mark.parametrize("where", ["pip-conf", "exported", "uv-toml", "constraint"])
def test_check_envs_reports_persistent_extra_index(tmp_path: Path, client: Client, where: str) -> None:
    # #130: every venv's cooldown is protected, but pip or uv is also given another index,
    # whose files the cooldown does not cover (the dependency-confusion route).
    _config(tmp_path)
    _uv_program(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    named = (_projects(tmp_path), os.path.realpath(tmp_path / "home" / ".config" / "uv"))  # uv's file too (#255)
    _protect(tmp_path, *named)
    argv = [arg for path in named for arg in ("--path", path)]
    assert _check(tmp_path, client, *argv)[0] == 0
    environ: dict[str, str] = {}
    user_uv = str(tmp_path / "home" / ".config" / "uv" / "uv.toml")
    if where == "pip-conf":
        conf = tmp_path / "home" / ".config" / "pip" / "pip.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text("[global]\nextra-index-url = https://pkgs.example.net/simple\n")
        place, said = venv, f"{venv}: pip is given an index other than PyPI's: {conf} sets extra-index-url in [global]"
    elif where == "exported":
        environ = {"PIP_EXTRA_INDEX_URL": "https://pkgs.example.net/simple"}
        place, said = venv, "pip is given an index other than PyPI's: PIP_EXTRA_INDEX_URL is set"
    elif where == "constraint":  # the named file's own --index-url line would move pip
        environ = {"PIP_CONSTRAINT": str(tmp_path / "constraints.txt")}
        place, said = venv, "pip is given an index other than PyPI's: PIP_CONSTRAINT is set"
    else:
        with open(user_uv, "a") as handle:
            handle.write('extra-index-url = ["https://pkgs.example.net/simple"]\n')
        place, said = user_uv, f"uv is given an index other than PyPI's: {user_uv} sets extra-index-url"
    code, doc, err = _check(tmp_path, client, *argv, **environ)
    assert code == doc["exit_code"] == 1, doc
    violations = [f for f in doc["findings"] if f["level"] == "violation"]
    assert [(f["rule"], f["place"], f["options"]) for f in violations] == [("unprotected", place, [])]
    assert said in err and "remove it, then run check again" in err


@pytest.mark.parametrize("protected", [True, False])
def test_check_envs_unreadable_pip_conf_is_never_a_pass(tmp_path: Path, client: Client, protected: bool) -> None:
    # #130: the index reading fails closed. A protected venv exits 2; an unprotected one keeps
    # its cooldown finding (exit 1 wins over 2) and the unfinished check is still listed.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    if protected:
        _protect(tmp_path)
    conf = tmp_path / "home" / ".config" / "pip" / "pip.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("index-url = https://pkgs.example.net/simple\n")  # no section: pip cannot parse it
    with refuses("pip.not-valid-pip-configuration-file"):
        code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == (2 if protected else 1), doc
    violations = [f for f in doc["findings"] if f["level"] == "violation"]
    if protected:
        assert violations == []
    else:
        (finding,) = violations
        assert (finding["rule"], finding["place"]) == ("unprotected", venv)
        assert [o["command"] for o in finding["options"]] == [["ssc-guardian", "protect", "pip", "--path", venv]]
    assert _in_scope_skip(venv) in doc["skipped"]
    assert {"ecosystem": "pypi", "place": venv} not in doc["checked"]
    assert f"{conf}: is not a valid pip configuration file" in err


def test_check_envs_reports_a_project_uv_override(tmp_path: Path, client: Client) -> None:
    # #150, the issue's input end to end: uv reported protected (exit 0) before.
    _config(tmp_path)
    _uv_program(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    app = os.path.dirname(venv)
    for name, text in (("uv.toml", ""), ("pyproject.toml", "[tool.uv]\n")):
        Path(app, name).write_text(f'{text}exclude-newer = "2100-01-01"\n')
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    project = os.path.join(app, "uv.toml")  # uv.toml beats the pyproject.toml beside it
    violations = [f for f in doc["findings"] if f["level"] == "violation"]
    assert [(f["rule"], f["place"], f["options"]) for f in violations] == [("unprotected", project, [])]
    assert {"ecosystem": "pypi", "place": project} in doc["checked"]
    assert f"{project} accepts uploads after 2026-10-13; uv prefers it to the user file in {app}" in err
    assert "protected (P21D)" not in err


@pytest.mark.parametrize("protected", [False, True])
def test_a_pip_index_variable_is_named_even_when_a_pip_conf_cannot_be_read(
    tmp_path: Path, client: Client, protected: bool
) -> None:
    # Review findings: the variable was read only after every file, so a broken per-user file hid
    # it and the finding offered protect, which cannot unset a variable. For a protected venv the
    # cooldown check itself reads the broken file first, and the variable must survive that too.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    if protected:
        _protect(tmp_path)
    conf = tmp_path / "home" / ".pip" / "pip.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("[global\n")
    with refuses("pip.not-valid-pip-configuration-file"):
        code, doc, err = _check(tmp_path, client, PIP_INDEX_URL="https://pkgs.example.net/simple")
    assert code == doc["exit_code"] == 1, doc
    (finding,) = [f for f in doc["findings"] if f["level"] == "violation"]
    assert (finding["rule"], finding["place"], finding["options"]) == ("unprotected", venv, [])
    assert "PIP_INDEX_URL is set" in err and f"{conf}: is not a valid pip configuration file" in err
    assert (f"{venv}/pip.conf sets no cooldown" in err) is not protected
    assert _in_scope_skip(venv) in doc["skipped"]


@pytest.mark.parametrize("broken_after", [False, True])
def test_a_weak_cooldown_beside_another_index_offers_no_protect_fix(
    tmp_path: Path, client: Client, broken_after: bool
) -> None:
    # protect would fix the cooldown but not the index, so it is not offered; an index found in
    # a readable file is still named when a later file pip reads cannot be parsed.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))  # never protected
    legacy = tmp_path / "home" / ".pip" / "pip.conf"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("[global]\nextra-index-url = https://pkgs.example.net/simple\n")
    if broken_after:
        later = tmp_path / "home" / ".config" / "pip" / "pip.conf"  # read after the legacy file
        later.parent.mkdir(parents=True)
        later.write_text("[global\n")
    code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    (finding,) = [f for f in doc["findings"] if f["level"] == "violation"]
    assert (finding["rule"], finding["place"], finding["options"]) == ("unprotected", venv, [])
    assert f"{legacy} sets extra-index-url in [global]" in err and f"{venv}/pip.conf sets no cooldown" in err
    assert (_in_scope_skip(venv) in doc["skipped"]) is broken_after


def test_an_index_in_a_readable_file_survives_the_cooldown_check_failing(tmp_path: Path, client: Client) -> None:
    # Review finding: for a protected venv the cooldown check reads every file first and fails on
    # the broken one, so the index reading never ran and the readable file's index went unnamed.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path)
    legacy = tmp_path / "home" / ".pip" / "pip.conf"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("[global]\nextra-index-url = https://pkgs.example.net/simple\n")
    later = tmp_path / "home" / ".config" / "pip" / "pip.conf"
    later.parent.mkdir(parents=True)
    later.write_text("[global\n")
    with refuses("pip.not-valid-pip-configuration-file"):
        code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    (finding,) = [f for f in doc["findings"] if f["level"] == "violation"]
    assert (finding["rule"], finding["place"], finding["options"]) == ("unprotected", venv, [])
    assert f"{legacy} sets extra-index-url in [global]" in err
    assert _in_scope_skip(venv) in doc["skipped"]


def test_a_broken_pip_conf_never_hides_an_index_in_a_later_file(tmp_path: Path, client: Client) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path)
    legacy = tmp_path / "home" / ".pip" / "pip.conf"  # read before the per-user file
    legacy.parent.mkdir(parents=True)
    legacy.write_text("[global\n")
    conf = tmp_path / "home" / ".config" / "pip" / "pip.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("[global]\nextra-index-url = https://pkgs.example.net/simple\n")
    with refuses("pip.not-valid-pip-configuration-file"):
        code, doc, err = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    (finding,) = [f for f in doc["findings"] if f["level"] == "violation"]
    assert (finding["rule"], finding["place"], finding["options"]) == ("unprotected", venv, [])
    assert f"{conf} sets extra-index-url in [global]" in err
    assert _in_scope_skip(venv) in doc["skipped"]


# --- where venvs were not looked for, and pypi entries in a repository file (#229) -------------


def _workstation(tmp_path: Path, text: str) -> None:
    folder = tmp_path / "home" / ".config" / "ssc-guardian"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(f"format = 1\n{text}")


def _protected_base(tmp_path: Path) -> str:
    """A pyenv base installation holding idna 3.7, protected by ``protect``."""
    prefix = tmp_path / "home" / ".pyenv" / "versions" / "3.12.4"
    site = make_base(prefix)
    add_dist(site, "pip", "26.2.1")
    add_dist(site, "idna", "3.7")
    _protect(tmp_path, os.path.realpath(prefix))
    return os.path.realpath(prefix)


def _text_check(tmp_path: Path, client: Client, *paths: str) -> tuple[int, str]:
    where = fake_mac(tmp_path)
    err, out = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err, host=policy.Host((14, 0), "arm64"))
    named = [arg for path in paths for arg in ("--path", path)]
    code = cli.main(["check", "--envs", *named], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    return code, out.getvalue()


def test_only_the_named_paths_are_looked_at(tmp_path: Path, client: Client) -> None:
    # #255 (replacing #229's scope.venv_folders rows): what is looked at is what --path names,
    # whatever the settings file holds; the report lists the named places, and only those.
    _workstation(tmp_path, "")
    base = _protected_base(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("requests", "2.31.0"))  # vulnerable, not named
    code, doc, _ = _check(tmp_path, client, "--path", base)
    assert code == doc["exit_code"] == 0, doc
    assert {"ecosystem": "pypi", "place": base} in doc["checked"]
    assert not any(c["place"].startswith(_projects(tmp_path)) for c in doc["checked"])  # never looked at
    code, text = _text_check(tmp_path, client, base)
    assert code == 0 and "scope.venv_folders" not in text
    # Naming the folder looks there: the vulnerable venv is found.
    _protect(tmp_path)
    code, doc, _ = _check(tmp_path, client, "--path", base, "--path", _projects(tmp_path))
    assert code == doc["exit_code"] == 1, doc


def test_missing_named_path_is_unfinished(tmp_path: Path, client: Client) -> None:
    # Edge case (#229, L2-5; #255): a named path that does not exist is listed and is an
    # unfinished check there (exit 2), never silently empty; the paths that exist are walked.
    _workstation(tmp_path, "")
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    missing = os.path.join(os.path.realpath(tmp_path / "home"), "no-such-folder")
    code, doc, _ = _check(tmp_path, client, "--path", _projects(tmp_path), "--path", missing)
    assert code == doc["exit_code"] == 2, doc
    assert {"ecosystem": "pypi", "place": venv} in doc["checked"]
    assert [s for s in doc["skipped"] if s["ecosystem"] == "pypi"] == [_skip("pypi", "check-error", missing)]
    code, text = _text_check(tmp_path, client, _projects(tmp_path), missing)
    assert code == 2 and missing in text and "does not exist" in text


def test_check_envs_is_idempotent_on_re_run(tmp_path: Path, client: Client) -> None:
    # Idempotency (#229, #255): the same named paths give the same result on every run, and
    # nothing is written, a missing path included.
    _workstation(tmp_path, "")
    base = _protected_base(tmp_path)
    first = _check(tmp_path, client, "--path", base)
    assert first[0] == 0, first
    assert _check(tmp_path, client, "--path", base) == first
    missing = os.path.join(os.path.realpath(tmp_path / "home"), "no-such-folder")
    first = _check(tmp_path, client, "--path", base, "--path", missing)
    assert first[0] == 2 and _skip("pypi", "check-error", missing) in first[1]["skipped"], first
    assert _check(tmp_path, client, "--path", base, "--path", missing) == first
    assert not (tmp_path / "home" / "no-such-folder").exists()


def test_repository_pypi_deny_entry_stops_plain_check(tmp_path: Path, client: Client) -> None:
    # The audit's case (#229, L1-3/L5-1): a pypi deny entry in the repository file used to be
    # ignored (exit 0). It is now refused, naming the file and line (exit 2); the same entry in
    # config.toml is a deny-list violation (exit 1), as before.
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path)
    repo = _repo(tmp_path)
    settings = repo / ".ssc-guardian.toml"
    settings.write_text('format = 1\ndeny = ["pypi:idna"]\n')
    named = ("--path", _projects(tmp_path), "--path", str(repo))
    code, doc, err = _plain(tmp_path, client, repo, *named)
    assert code == doc["exit_code"] == 2, doc
    assert _skip("github-actions", "check-error", str(settings)) in doc["skipped"]
    assert "deny-list" not in [f["rule"] for f in doc["findings"]]
    assert f"{settings}: line 2: deny entry 'pypi:idna' is a pypi entry" in err and "move it to config.toml" in err
    settings.write_text('format = 1\ndeny = ["github-actions:o/r"]\n')
    _config(tmp_path, '\ndeny = ["pypi:idna"]\n')
    code, doc, _ = _plain(tmp_path, client, repo, *named)
    assert code == doc["exit_code"] == 1, doc
    assert [f["rule"] for f in doc["findings"]] == ["deny-list"]


def test_named_paths_that_hold_no_environment_are_never_passed_over(tmp_path: Path) -> None:
    # Edge cases (#229 review, #255): a path behind a dangling link, one that does not exist, one
    # under a file, a file and an empty folder are each reported once, never passed over.
    home = os.path.realpath(tmp_path)
    (tmp_path / "gone").symlink_to(tmp_path / "unmounted-volume")
    (tmp_path / "file").write_text("")
    (tmp_path / "here").mkdir()
    dangling, a_file, under_file = f"{home}/gone", f"{home}/file", f"{home}/file/below"
    missing, here = f"{home}/missing", f"{home}/here"
    found = discovery.survey(fake_mac(tmp_path), [dangling, under_file, missing, missing])
    assert [(s.place, s.reason) for s in found.skipped] == [
        (dangling, SkipReason.CHECK_ERROR),
        (under_file, SkipReason.CHECK_ERROR),
        (missing, SkipReason.CHECK_ERROR),
    ]
    found = discovery.survey(fake_mac(tmp_path), [a_file, here])
    assert (found.skipped, found.empty) == ([], [a_file, here])  # the command lists each as unfinished


# --- an installed package is dated by its own file (#230, L3-2) --------------------------

YOUNG = "2026-11-02T10:00:00Z"  # the day before TODAY: inside the default cooldown
YOUNG_TAG = "cp312-cp312-macosx_14_0_arm64"  # fits the 3.12 venv on the injected host


def _idna_page(*, young_wheel: bool) -> dict[str, Any]:
    """idna 3.7 as the audit probed it: a 2023 sdist, and a wheel uploaded the day before."""
    sdist = {
        "filename": "idna-3.7.tar.gz",
        "url": "https://files.pythonhosted.org/packages/ab/idna-3.7.tar.gz",
        "hashes": {"sha256": "ab" * 32},
        "upload-time": OLD,
    }
    files = [sdist, _wheel("idna", "3.7", YOUNG if young_wheel else OLD, tag=YOUNG_TAG)]
    return {"meta": {"api-version": "1.4"}, "name": "idna", "files": files, "versions": ["3.7"]}


def _venv_and_base(tmp_path: Path) -> tuple[str, str]:
    """A 3.12 venv that sees its base's packages, idna 3.7 in each; the base's record has the
    WHEEL file pip writes, naming the young wheel's tags. Returns the two package folders."""
    base = tmp_path / "opt" / "python"
    base_site = make_base(base)
    add_dist(base_site, "idna", "3.7")
    (base_site / "idna-3.7.dist-info" / "WHEEL").write_text(f"Wheel-Version: 1.0\nTag: {YOUNG_TAG}\n")
    prefix = tmp_path / "home" / "projects" / "app" / ".venv"
    site = make_venv(prefix, home=base / "bin", system_site=True)
    add_dist(site, "pip", "26.2.1")
    add_dist(site, "idna", "3.7")
    return os.path.realpath(site), os.path.realpath(base_site)


def test_young_wheel_in_old_release_is_reported(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config(tmp_path)
    site, base_site = _venv_and_base(tmp_path)
    _protect(tmp_path)

    # The control: every file of the release is old, so nothing is reported.
    monkeypatch.setitem(PAGES, "idna", _idna_page(young_wheel=False))
    code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 0, doc

    # The release's first upload is still 2023, but the wheel is a day old: in the venv it is
    # a file that could be the one installed; in the base, its WHEEL file names it.
    monkeypatch.setitem(PAGES, "idna", _idna_page(young_wheel=True))
    with refuses("policy.cooldown"):
        code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    assert sorted((f["rule"], f["item"], f["place"]) for f in doc["findings"]) == sorted(
        [("cooldown", "idna", site), ("cooldown", "idna", base_site)]
    )


def test_check_envs_dating_is_idempotent_on_re_run(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(PAGES, "idna", _idna_page(young_wheel=True))
    _config(tmp_path)
    _venv_and_base(tmp_path)
    _protect(tmp_path)
    with refuses("policy.cooldown"):
        first = _check(tmp_path, client)
        assert first[0] == 1, first
        assert _check(tmp_path, client) == first


def test_outside_a_venv_the_wheel_record_names_the_installed_file(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The base's WHEEL file names the old universal wheel, so the young wheel with other tags is not
    # the one installed there; in the venv, where WHEEL is not trusted, the young wheel still counts.
    page = _idna_page(young_wheel=True)
    page["files"].append(_wheel("idna", "3.7", OLD))
    monkeypatch.setitem(PAGES, "idna", page)
    _config(tmp_path)
    site, base_site = _venv_and_base(tmp_path)
    (Path(base_site) / "idna-3.7.dist-info" / "WHEEL").write_text("Wheel-Version: 1.0\nTag: py3-none-any\n")
    _protect(tmp_path)
    with refuses("policy.cooldown"):
        code, doc, _ = _check(tmp_path, client)
    assert code == doc["exit_code"] == 1, doc
    assert [(f["rule"], f["place"]) for f in doc["findings"]] == [("cooldown", site)]


def test_two_records_of_one_version_that_disagree_claim_no_file() -> None:
    # Two spellings of one version (3.7 and 3.7.0), each with its own record.
    def package(version: str, tags: str | None) -> discovery.Package:
        return discovery.Package("idna", version, "/f", f"idna-{version}.dist-info", _tags(tags))

    agree = [package("3.7", "py3-none-any"), package("3.7.0", "py3-none-any")]
    differ = [package("3.7", "py3-none-any"), package("3.7.0", YOUNG_TAG)]
    assert _installed_files(agree) == {("idna", "3.7"): policy.Installed(_tags("py3-none-any"))}
    assert _installed_files(differ) == {("idna", "3.7"): policy.Installed()}


def _tags(tag: str | None) -> frozenset[tuple[str, str, str]] | None:
    return pypi.record_tags([tag]) if tag else None


# --- #255: check acts only on what its arguments name ----------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["check"],
        ["check", "--envs"],
        ["check", "--json"],
        ["check", "--envs", "--json"],
        ["check", "--ecosystem", "pypi"],
        ["check", "--language", "python", "--json"],
    ],
)
def test_bare_check_is_a_usage_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
    # Negative (#255): a check that names neither --path nor --repo is refused from its arguments
    # alone (exit 2, the --path form shown), before anything is read: the handler never runs, no
    # folder is listed, and no file under the fake Mac changes. There is no default scope.
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"))
    where = fake_mac(tmp_path)
    before = {str(p): p.read_bytes() for p in sorted(tmp_path.rglob("*")) if p.is_file()}
    ran: list[Request] = []

    def handler(request: Request) -> Result:
        ran.append(request)
        return CheckEnvs(where.home, where.environ, where.root, TODAY, None, io.StringIO())(request)

    listed: list[str] = []
    real_listdir, real_scandir = os.listdir, os.scandir

    def listdir(path: Any = ".") -> list[str]:
        listed.append(str(path))
        return real_listdir(path)

    def scandir(path: Any = ".") -> Any:
        listed.append(str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "listdir", listdir)
    monkeypatch.setattr(os, "scandir", scandir)
    out, err = io.StringIO(), io.StringIO()
    with refuses("cli.check-names-nothing"):
        code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    monkeypatch.undo()
    assert code == 2
    assert err.getvalue() == f"ssc-guardian: {cli.NOTHING_NAMED}\n"
    assert "--path PATH" in err.getvalue() and out.getvalue() == ""
    fake_mac_root = str(tmp_path.resolve())  # Python's own import machinery may list sys.path
    assert ran == [] and [p for p in listed if p.startswith(fake_mac_root)] == []
    assert {str(p): p.read_bytes() for p in sorted(tmp_path.rglob("*")) if p.is_file()} == before


def test_check_path_result_ignores_settings_scope(tmp_path: Path, client: Client) -> None:
    # The same --path run gives the same report whatever else is on the Mac: unrelated venvs
    # elsewhere under the fake home, in or out of the former venv folders, are never read.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    _protect(tmp_path, venv)
    first = _check(tmp_path, client, "--path", venv)
    assert first[0] == 0, first
    make_venv(tmp_path / "home" / "projects" / "other" / ".venv")  # unprotected: exit 1 if read
    make_venv(tmp_path / "home" / "elsewhere" / "env")
    make_venv(tmp_path / "home" / ".venvs" / "tool")
    second = _check(tmp_path, client, "--path", venv)
    assert second == first
    # A settings file that only changes rules leaves the scope alone too.
    _config(tmp_path, '[defaults]\nblock_on = "strong"\n')
    assert _check(tmp_path, client, "--path", venv) == first


def test_check_repo_unchanged(tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    # check --repo [DIR] already names its target: it reads that repository's workflows only, from
    # any folder, needs no --path, and never looks at a Python environment.
    _config(tmp_path)
    _venv(tmp_path, "app", ("pip", "26.2.1"))  # unprotected: exit 1 if it were read
    repo = _repo(tmp_path)
    outside = _plain(tmp_path, client, tmp_path.resolve(), "--repo", str(repo))
    monkeypatch.chdir(repo)  # --repo alone names the current folder
    inside = _plain(tmp_path, client, repo, "--repo")
    for code, doc, _ in (outside, inside):
        assert code == doc["exit_code"] == 0, doc
        assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(repo)}]
        assert _skip("pypi", "filtered") in doc["skipped"]
    assert inside == outside
    assert _plain(tmp_path, client, tmp_path.resolve(), "--repo", str(repo)) == outside  # idempotent


# --- fail-closed paths the 2026-11-14 audit's mutants reached (#262, m2-F01 to m2-F05) ---------


def _no_version_record(site: Path) -> Path:
    """A ``dist-info`` record with a name and no Version: unreadable to every reader."""
    record = site / "foo-1.0.dist-info"
    record.mkdir()
    (record / "METADATA").write_text("Metadata-Version: 2.1\nName: foo\n")
    return record


def test_every_cooldown_group_is_evaluated(tmp_path: Path, client: Client) -> None:
    # m2-F01: requests has its own cooldown, so it is evaluated in a group of its own after the
    # default group; with only the first group evaluated, its vulnerability went unreported (exit 0).
    _config(tmp_path, '\n[rules]\n"pypi:requests" = { cooldown_days = 30 }\n')
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("requests", "2.31.0"), ("idna", "3.7"))
    _protect(tmp_path, venv)
    code, doc, _ = _check(tmp_path, client, "--path", _projects(tmp_path))
    assert code == doc["exit_code"] == 1, doc
    assert [(f["rule"], f["item"]) for f in doc["findings"]] == [("known-vulnerability", "requests")]


def test_malformed_venv_path_is_a_violation(tmp_path: Path, client: Client) -> None:
    # m2-F02: a venv in a folder the path grammar refuses is never checked; the malformed-name
    # finding is the only thing that reports it. Without it the run exited 0, the venv unlisted.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path, venv)
    make_venv(tmp_path / "home" / "projects" / "café" / ".venv")  # unprotected: exit 1 if it were read
    code, doc, _ = _check(tmp_path, client, "--path", _projects(tmp_path))
    assert code == doc["exit_code"] == 1, doc
    assert [f["rule"] for f in doc["findings"]] == ["malformed-name"]
    assert {"ecosystem": "pypi", "place": venv} in doc["checked"]


def test_unreadable_record_keeps_the_index_variable_finding(tmp_path: Path, client: Client) -> None:
    # m2-F03: the venv's records cannot be read, so whether it has a pip cannot be told; it is
    # taken as present, and the exported index variable is still a violation (else exit 2 only).
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"))
    _protect(tmp_path, venv)
    _no_version_record(Path(venv) / "lib" / "python3.12" / "site-packages")
    code, doc, err = _check(
        tmp_path, client, "--path", _projects(tmp_path), PIP_INDEX_URL="https://pkgs.example.net/simple"
    )
    assert code == doc["exit_code"] == 1, doc
    (finding,) = [f for f in doc["findings"] if f["level"] == "violation"]
    assert (finding["rule"], finding["place"], finding["options"]) == ("unprotected", venv, [])
    assert "PIP_INDEX_URL is set" in err
    assert _in_scope_skip(venv) in doc["skipped"]


def test_override_not_applied_when_pypi_cannot_be_read(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # m2-F04: PyPI's page for requests cannot be read, so the fixed-version check never ran and
    # the override on its vulnerability is not applied; it had been recorded as applied.
    monkeypatch.setitem(PAGES, "requests", {"meta": {"api-version": "1.4"}, "name": "requests", "files": "x"})
    _config(tmp_path)
    venv = _venv(tmp_path, "app", ("pip", "26.2.1"), ("requests", "2.31.0"))
    _protect(tmp_path, venv)
    _override_requests(tmp_path)
    code, doc, err = _check(tmp_path, client, "--path", _projects(tmp_path))
    assert code == doc["exit_code"] == 1, doc
    assert [(f["rule"], f["item"]) for f in doc["findings"]] == [("known-vulnerability", "requests")]
    assert doc["overrides"] == {"applied": [], "expired": []}
    assert err.count("not applied: the fixed-version check did not finish") == 2


@pytest.mark.parametrize("case", ["no-version", "dangling-site-packages"])
def test_folder_of_unreadable_records_is_never_checked(tmp_path: Path, client: Client, case: str) -> None:
    # m2-F05: no folder has a readable record, so the feeds are never asked; each folder with an
    # unreadable record is still an unfinished check, never listed as checked.
    _config(tmp_path)
    venv = _venv(tmp_path, "app")  # no pip, no packages
    _protect(tmp_path, venv)
    site = Path(venv) / "lib" / "python3.12" / "site-packages"
    if case == "no-version":
        note = f"{site}: {_no_version_record(site).name}: no name or version"
    else:
        site.rmdir()
        site.symlink_to(tmp_path / "Volumes" / "NotMounted" / "site-packages")
        note = f"{site}: reached through a symlink to a missing folder"

    def run() -> tuple[int, dict[str, Any], str]:
        return _check(tmp_path, client, "--path", _projects(tmp_path))

    with refuses("check_envs.raise-problems-check-error"):
        first = run()
    code, doc, err = first
    assert code == doc["exit_code"] == 2, doc
    assert _in_scope_skip(str(site)) in doc["skipped"]
    assert str(site) not in {c["place"] for c in doc["checked"]}
    assert note in err  # the note naming the record
    assert run() == first  # idempotent on re-run
