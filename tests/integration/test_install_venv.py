# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``install --venv`` end to end in real venvs (issue #6; plan §3.1 steps 1-8, M1 test).

A local server on 127.0.0.1 is both pip's index (``/simple/``, wheels under ``/files/``, which
pip trusts on 127.0.0.0/8 without ``--trusted-host``) and, through a transport that rewrites
``https://<host>/<path>`` to it, the feeds Guardian reads (OSV, GitHub, PyPI's Simple API,
KEV). The PyPI pages Guardian reads name ``files.pythonhosted.org`` URLs and the same SHA-256
digests as the index, so binding is checked for real. Guardian's pinned pip is the real
wheel, downloaded from ``files.pythonhosted.org`` and verified into a cache under the test's
home: those tests are marked ``requires_network``. Every venv is built in ``tmp_path``; the
owner's Pythons are only used to create venvs, and the home folder is never read.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, net, pinned_pip
from ssc_guardian.binding import Endpoints
from ssc_guardian.cli import Request
from ssc_guardian.commands.install import Install
from ssc_guardian.discovery import Environment
from ssc_guardian.findings import Verb
from ssc_guardian.net import PYPI_FILES, Client, Response, find_token, urllib_transport
from ssc_guardian.plugin import PlannedFile
from tests.refusal_sites import refuses
from tests.unit.test_discovery import add_dist, make_venv
from tests.unit.test_install import link_interpreter
from tests.unit.test_net import trusted_chain

pytestmark = pytest.mark.integration

TODAY = date(2026, 11, 3)  # pip's cutoff is 2026-10-13 under the 21-day cooldown
OLD = "2025-01-01T00:00:00.000000Z"
YOUNG = "2026-10-30T00:00:00.000000Z"
# demo needs helper; helper 2.0 is younger than the cutoff, so pip must choose helper 1.0.
PACKAGES: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("demo", "1.0", OLD, ("helper",)),
    ("demo", "1.1", OLD, ("helper>=1.0",)),
    ("helper", "1.0", OLD, ()),
    ("helper", "2.0", YOUNG, ()),
    ("evil", "1.0", OLD, ()),
    ("foo", "2.0", "2026-10-04T00:00:00.000000Z", ()),  # 30 days before TODAY
]
# Source distributions, (name, version, upload time): foo 2.0's sdist is 100 days old (#129).
SDISTS: list[tuple[str, str, str]] = [("foo", "2.0", "2026-07-26T00:00:00.000000Z")]
# The audit's L3-1 package: its X.data/scripts/python replaces the venv's bin/python and, run,
# appends a line to ``evil-ran`` in the wheels folder.
EVIL_SCRIPTS = {"python": "#!/bin/sh\necho ran >> '{marker}'\n"}


def build_wheel(
    folder: Path, name: str, version: str, requires: Sequence[str], scripts: Mapping[str, str] | None = None
) -> Path:
    """A minimal pure-Python wheel: one module, its metadata and its RECORD, plus ``scripts``
    (name -> text) as executable ``X.data/scripts`` files, which pip installs into ``bin``."""
    path = folder / f"{name}-{version}-py3-none-any.whl"
    info = f"{name}-{version}.dist-info"
    requirements = "".join(f"Requires-Dist: {r}\n" for r in requires)
    files = {
        f"{name}.py": f"VERSION = {version!r}\n",
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n{requirements}\n",
        f"{info}/WHEEL": "Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        **{f"{name}-{version}.data/scripts/{script}": text for script, text in (scripts or {}).items()},
    }
    record = []
    with zipfile.ZipFile(path, "w") as archive:
        for name_in, text in files.items():
            data = text.encode()
            entry = zipfile.ZipInfo(name_in)
            entry.external_attr = (0o100755 if ".data/scripts/" in name_in else 0o100644) << 16
            archive.writestr(entry, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            record.append(f"{name_in},sha256={digest},{len(data)}")
        archive.writestr(f"{info}/RECORD", "\n".join([*record, f"{info}/RECORD,,"]) + "\n")
    return path


@dataclass
class Index:
    base: str
    folder: Path
    wheels: dict[str, list[tuple[str, str, str]]]  # name -> (filename, sha256, upload time)

    def digest(self, filename: str) -> str:
        return next(s for entries in self.wheels.values() for f, s, _ in entries if f == filename)

    def page(self, name: str, origin: str) -> dict[str, Any]:
        entries = self.wheels[name]
        files = [
            {"filename": f, "url": f"{origin}/{f}", "hashes": {"sha256": s}, "upload-time": t} for f, s, t in entries
        ]
        versions = sorted({f.split("-")[1].removesuffix(".tar.gz") for f, _, _ in entries})
        return {"meta": {"api-version": "1.1"}, "name": name, "files": files, "versions": versions}


@pytest.fixture(scope="module")
def index(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Index]:
    folder = tmp_path_factory.mktemp("wheels")
    wheels: dict[str, list[tuple[str, str, str]]] = {}
    for name, version, uploaded, requires in PACKAGES:
        scripts = {s: t.format(marker=folder / "evil-ran") for s, t in EVIL_SCRIPTS.items()} if name == "evil" else None
        path = build_wheel(folder, name, version, requires, scripts)
        wheels.setdefault(name, []).append((path.name, hashlib.sha256(path.read_bytes()).hexdigest(), uploaded))
    for name, version, uploaded in SDISTS:
        path = folder / f"{name}-{version}.tar.gz"
        path.write_bytes(f"{name} {version} source\n".encode())
        wheels[name].append((path.name, hashlib.sha256(path.read_bytes()).hexdigest(), uploaded))
    served: dict[str, Index] = {}

    class Answer(BaseHTTPRequestHandler):
        def _send(self, status: int, data: bytes, kind: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _answer(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            parts = self.path.split("?")[0].split("/")
            index = served["index"]
            if parts[1] == "simple" and parts[2] in wheels:  # pip's index
                page = index.page(parts[2], f"{index.base}/files")
                return self._send(200, json.dumps(page).encode(), "application/vnd.pypi.simple.v1+json")
            if parts[1] == "files" and (folder / parts[2]).is_file():
                return self._send(200, (folder / parts[2]).read_bytes(), "application/octet-stream")
            if parts[1:3] == ["pypi.org", "simple"] and parts[3] in wheels:  # Guardian's PyPI feed
                page = index.page(parts[3], f"https://{PYPI_FILES}/packages/ab")
                return self._send(200, json.dumps(page).encode())
            if self.path == "/api.osv.dev/v1/querybatch":
                results: list[object] = [{"vulns": []} for _ in json.loads(body)["queries"]]  # nothing is vulnerable
                return self._send(200, json.dumps({"results": results}).encode())
            if parts[1] == "api.github.com":
                return self._send(200, b"[]")
            if parts[1] == "www.cisa.gov":
                return self._send(200, json.dumps({"vulnerabilities": []}).encode())
            return self._send(404, b'{"message": "not found"}')

        def log_message(self, format: str, *args: object) -> None:  # keep test output quiet
            return None

    handler = type("Handler", (Answer,), {"do_GET": Answer._answer, "do_POST": Answer._answer})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    served["index"] = Index(f"http://127.0.0.1:{httpd.server_address[1]}", folder, wheels)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield served["index"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _transport(base: str) -> Any:
    """Feeds go to the local server; files.pythonhosted.org (the pinned pip) goes out for real."""

    def transport(request: urllib.request.Request, timeout: float, limit: int) -> Response:
        parts = urllib.parse.urlsplit(request.full_url)
        assert parts.scheme == "https"
        if parts.hostname == PYPI_FILES:
            return urllib_transport(request, timeout, limit)
        local = f"{base}/{parts.hostname}{parts.path}" + (f"?{parts.query}" if parts.query else "")
        rewritten = urllib.request.Request(
            local, data=request.data, headers=dict(request.header_items()), method=request.get_method()
        )
        answer = urllib_transport(rewritten, timeout, limit)
        return Response(answer.status, answer.headers, answer.body, request.full_url)

    return transport


@pytest.fixture(scope="module")
def home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The tests' home folder: the pinned pip is downloaded and verified into its cache once."""
    return tmp_path_factory.mktemp("home")


def installer(index: Index, home: Path, *, stdin: io.StringIO | None = None, runner: Any = None) -> Install:
    return Install(
        home=str(home),
        environ={"PATH": ""},
        today=TODAY,
        client=Client(transport=_transport(index.base), timeout=60.0),
        stdin=stdin or io.StringIO(),
        endpoints=Endpoints(index_url=f"{index.base}/simple", files_origin=index.base),
        runner=runner,
    )


def run(install: Install, target: Path, *packages: str, yes: bool = True) -> tuple[int, dict[str, Any], str]:
    out, err = io.StringIO(), io.StringIO()
    install = Install(**{**install.__dict__, "stderr": err})
    argv = ["install", "--venv", str(target), "--json", *(["--yes"] if yes else []), *packages]
    code = cli.main(argv, handlers={Verb.INSTALL: install}, stdout=out, stderr=err)
    return code, json.loads(out.getvalue() or "{}"), err.getvalue()


def new_venv(base: str, prefix: Path) -> Path:
    """A venv made by ``base`` (test setup: Guardian itself never runs a found program)."""
    subprocess.run([base, "-m", "venv", "--without-pip", str(prefix)], check=True, capture_output=True)
    (site,) = prefix.glob("lib/python3.*/site-packages")
    return site


def tree(folder: Path) -> list[str]:
    return sorted(str(p.relative_to(folder)) for p in folder.rglob("*") if "__pycache__" not in p.parts)


def recorded_pip(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Every command line the pinned pip runs with, recorded as it runs for real."""
    calls: list[list[str]] = []
    real = subprocess.run

    def record(argv: list[str], **kwargs: Any) -> Any:
        if pinned_pip.BOOTSTRAP in argv:
            calls.append(list(argv))
        return real(argv, **kwargs)

    monkeypatch.setattr(pinned_pip.subprocess, "run", record)
    return calls


def _pythons() -> list[str]:
    """Apple's 3.9 and Homebrew's 3.11, 3.13 and 3.14 where they exist, and always the Python
    running the suite (3.11 or later), each interpreter once. Nothing is run to find them."""
    candidates = [
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3.11",
        "/opt/homebrew/bin/python3.13",
        "/opt/homebrew/bin/python3.14",
        sys.executable,
    ]
    found: dict[str, str] = {}
    for candidate in candidates:
        if os.path.isfile(candidate):
            found.setdefault(os.path.realpath(candidate), candidate)
    return sorted(found.values())


# --- the check step runs no installed code --------------------------------------------


# Installed code that could run during the check step: startup files, and packages whose names
# pip's own code imports when it can (rich imports attr, urllib3 imports backports, packaging
# imports _manylinux, pip imports keyring for a login).
TRAPS = {
    "trap.pth": "import pathlib; pathlib.Path({marker!r}).open('a').write('pth\\n')\n",
    "sitecustomize.py": "import pathlib; pathlib.Path({marker!r}).open('a').write('sitecustomize\\n')\n",
    "usercustomize.py": "import pathlib; pathlib.Path({marker!r}).open('a').write('usercustomize\\n')\n",
    "attr/__init__.py": "import pathlib; pathlib.Path({marker!r}).open('a').write('attr\\n')\n",
    "backports/__init__.py": "import pathlib; pathlib.Path({marker!r}).open('a').write('backports\\n')\n",
    "_manylinux.py": "import pathlib; pathlib.Path({marker!r}).open('a').write('_manylinux\\n')\n",
    "keyring/__init__.py": "import pathlib; pathlib.Path({marker!r}).open('a').write('keyring\\n')\n",
}


@pytest.mark.requires_network
def test_pth_file_never_runs_during_check_step(tmp_path: Path, index: Index, home: Path) -> None:
    prefix = tmp_path / "app" / ".venv"
    site = new_venv(sys.executable, prefix)
    marker = tmp_path / "trap-fired.txt"
    for name, trap in TRAPS.items():
        (site / name).parent.mkdir(exist_ok=True)
        (site / name).write_text(trap.format(marker=str(marker)))
    before = sorted(str(p.relative_to(prefix)) for p in prefix.rglob("*"))  # __pycache__ included

    # No terminal and no --yes: the check step and the binding run, then nothing is installed.
    code, result, err = run(installer(index, home), prefix, "demo==1.1", yes=False)
    assert code == 2, err
    assert "not confirmed; nothing installed" in err  # reached only after the check step and binding passed
    assert result["findings"] == []
    assert not marker.exists(), marker.read_text()  # no installed code ran during the check step
    assert sorted(str(p.relative_to(prefix)) for p in prefix.rglob("*")) == before  # nothing written

    # The traps are live: the venv's Python started normally runs them.
    subprocess.run([str(prefix / "bin" / "python"), "-c", "import attr, backports, keyring"], check=True)
    assert {"pth", "attr", "backports", "keyring"} <= set(marker.read_text().split())


# --- the venv's interpreter and gh are checked before they run (issue #71) --------------


@pytest.mark.requires_network
def test_installed_wheel_replacing_python_cannot_run_in_check(tmp_path: Path, index: Index, home: Path) -> None:
    # The audit's L3-1, end to end with the pinned pip: a package already installed has
    # replaced bin/python with its X.data/scripts/python.
    prefix = tmp_path / "app" / ".venv"
    new_venv(sys.executable, prefix)
    marker = index.folder / "evil-ran"
    install = installer(index, home)
    code, _, err = run(install, prefix, "evil==1.0")
    assert code == 0, err
    python = prefix / "bin" / "python"
    assert python.is_file() and not python.is_symlink()  # the wheel's script is now bin/python

    # The next checked install refuses the venv before anything runs.
    before = tree(prefix)
    with refuses("install.target-unchecked"):
        code, result, err = run(install, prefix, "demo==1.1")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert f"{prefix} has a file, not a link, at bin/python" in err
    assert not marker.exists()  # the replaced interpreter never ran
    assert tree(prefix) == before

    # The trap is live: run, the replaced bin/python writes the marker.
    subprocess.run(["/bin/sh", str(python)], check=True)
    assert marker.read_text() == "ran\n"


def test_real_venvs_pass_the_interpreter_check_and_copies_venvs_are_refused(
    tmp_path: Path, index: Index, home: Path
) -> None:
    # A venv as the Python running the suite makes it (Homebrew's on the build Mac,
    # setup-python's under /opt/hostedtoolcache on GitHub's runner) is accepted.
    prefix = tmp_path / "app" / ".venv"
    new_venv(sys.executable, prefix)
    runner = RecordingPip(index)
    code, _, err = run(installer(index, home, runner=runner), prefix, "demo")
    assert code == 0, err
    assert len(runner.installs) == 1

    # The same real venv with a python._pth in bin, which Python 3.11 and later read whatever
    # -I -S say, is refused before anything runs.
    (prefix / "bin" / "python._pth").write_text(f"{prefix}/lib\n")
    runner = RecordingPip(index)
    code, _, err = run(installer(index, home, runner=runner), prefix, "demo")
    assert code == 2, err
    assert f"{prefix} has a ._pth file in bin" in err
    assert runner.installs == []

    # The same Python's --copies venv is refused, with a message saying so.
    copies = tmp_path / "copies" / ".venv"
    command = [sys.executable, "-m", "venv", "--copies", "--without-pip", str(copies)]
    subprocess.run(command, check=True, capture_output=True)
    runner = RecordingPip(index)
    code, _, err = run(installer(index, home, runner=runner), copies, "demo")
    assert code == 2, err
    assert f"{copies} has a file, not a link, at bin/python: a venv made with --copies" in err
    assert runner.installs == []


def test_gh_is_run_from_root_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The audit's L3-3 probe: a gh that links to /usr/bin/env passes the file check, and env
    # runs "auth" from PATH. Run from /, a planted auth in the current folder never runs.
    here = tmp_path / "here"
    here.mkdir()
    marker = tmp_path / "auth-ran"
    auth = here / "auth"
    auth.write_text(f"#!/bin/sh\necho ran >> '{marker}'\necho gho_Planted0123456789abcdef\n")
    auth.chmod(0o755)
    links = tmp_path / "bin"
    links.mkdir()
    (links / "gh").symlink_to("/usr/bin/env")
    monkeypatch.chdir(here)
    monkeypatch.setenv("PATH", ".")
    ran: list[str] = []

    def run_gh(path: str) -> bytes | None:
        ran.append(path)
        return net._run_gh(path)

    found = find_token({}, gh_paths=(str(links / "gh"),), lstat_path=trusted_chain(tmp_path), run_gh=run_gh)
    assert ran == [os.path.realpath("/usr/bin/env")]  # the checked link was run...
    assert found is None and not marker.exists()  # ...from /, so the planted auth never ran

    # The trap is live: env run in the current folder runs it.
    subprocess.run(["/usr/bin/env", "auth"], check=True, capture_output=True)
    assert marker.read_text() == "ran\n"


# --- M1 -------------------------------------------------------------------------------


@pytest.mark.requires_network
@pytest.mark.parametrize("base", _pythons())
def test_install_into_python_3_9_and_newer_venvs(
    tmp_path: Path, index: Index, home: Path, base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Owner decision 2026-11-03 (plan §3.1 step 7, §10.4): Python 3.9 and the newer Pythons
    # on the build Mac, installing no interpreter; CI runs it on the Python it has.
    prefix = tmp_path / "app" / ".venv"
    site = new_venv(base, prefix)
    install = installer(index, home)
    calls = recorded_pip(monkeypatch)

    code, _, err = run(install, prefix, "demo==1.0")
    assert code == 0, err
    assert {"demo-1.0.dist-info", "helper-1.0.dist-info"} <= {p.name for p in site.iterdir()}

    # Real pip took exactly these arguments, literal values (plan §3.1 steps 4 and 7): the
    # check step locked down and wheels only, the install step hash-pinned with no dependencies.
    check, pinned = calls
    common = [
        "install",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "--no-cache-dir",
        "--index-url",
        f"{index.base}/simple",
        "--only-binary",
        ":all:",
        "--quiet",
    ]
    assert check[1:5] == ["-I", "-S", "-B", "-c"] and pinned[1:3] == ["-I", "-c"]
    assert os.path.basename(check[-2]) == "report.json"
    assert check[8 + int(check[7]) :] == [
        *common,
        "--upgrade",
        "--uploaded-prior-to",
        "2026-10-13T00:00:00+00:00",
        "--dry-run",
        "--report",
        check[-2],
        "demo==1.0",
    ]
    assert pinned[5] == "0" and os.path.basename(pinned[-1]) == "pinned-requirements.txt"
    assert pinned[6:] == [*common, "--no-deps", "--require-hashes", "-r", pinned[-1]]

    # A loose request takes the newest version that passes every rule and replaces 1.0. pip's
    # cutoff hides helper 2.0, which is younger than the cooldown.
    code, result, err = run(install, prefix, "demo")
    assert code == 0, err
    assert result["checked"] == [{"ecosystem": "pypi", "place": str(prefix.resolve())}]
    names = {p.name for p in site.iterdir()}
    assert "demo-1.1.dist-info" in names and "demo-1.0.dist-info" not in names
    assert "helper-1.0.dist-info" in names and "helper-2.0.dist-info" not in names
    assert (site / "demo.py").read_text() == "VERSION = '1.1'\n"

    # With real pip, a re-run reports nothing to install.
    before = tree(prefix)
    code, _, err = run(install, prefix, "demo")
    assert code == 0, err
    assert "Nothing to install" in err
    assert tree(prefix) == before


# --- idempotency and the empty request ------------------------------------------------


@dataclass
class RecordingPip:
    """The two pip steps without pip: the report leaves out what is already installed, as
    pip's does, and the install step writes each package's record."""

    index: Index
    installs: list[tuple[PlannedFile, ...]] = field(default_factory=list)

    def check(self, env: Environment, pins: Sequence[str], cutoff: str) -> object:
        installed = {p.name for p in Path(env.main_site).glob("*.dist-info")}
        entries = []
        for pin in [*pins, "helper==1.0"]:
            name, version = re.split("==|<=", pin)
            if f"{name}-{version}.dist-info" in installed:
                continue
            filename = f"{name}-{version}-py3-none-any.whl"
            url, digest = f"{self.index.base}/files/{filename}", self.index.digest(filename)
            entries.append(
                {
                    "metadata": {"name": name, "version": version},
                    "download_info": {"url": url, "archive_info": {"hashes": {"sha256": digest}}},
                    "is_direct": False,
                    "requested": name in {re.split("==|<=", p)[0] for p in pins},
                }
            )
        return {"version": "1", "install": entries}

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        self.installs.append(tuple(files))
        for planned in files:
            add_dist(Path(env.main_site), planned.item.name, planned.item.version)


def test_re_run_after_install_is_idempotent(tmp_path: Path, index: Index, home: Path) -> None:
    prefix = tmp_path / ".venv"
    site = make_venv(prefix, "3.12", home=tmp_path / "base" / "bin")
    link_interpreter(prefix, "3.12", tmp_path / "base" / "bin")  # never run: the recording runner stands in for pip
    runner = RecordingPip(index)
    install = installer(index, home, runner=runner)

    code, _, err = run(install, prefix, "demo")
    assert code == 0, err
    assert [[(f.item.name, f.item.version) for f in files] for files in runner.installs] == [
        [("demo", "1.1"), ("helper", "1.0")]
    ]
    before = tree(prefix)
    code, result, err = run(install, prefix, "demo")
    assert code == 0, err
    assert len(runner.installs) == 1  # nothing installed twice
    assert "Nothing to install" in err
    assert result["checked"] == [{"ecosystem": "pypi", "place": str(prefix)}]
    assert tree(prefix) == before
    assert sorted(p.name for p in site.iterdir()) == ["demo-1.1.dist-info", "helper-1.0.dist-info"]


@dataclass
class KeepingPip(RecordingPip):
    """pip when the installed version already meets the request and nothing better installs: an
    empty report, as the pinned pip's resolver gives for an installed candidate it keeps."""

    def check(self, env: Environment, pins: Sequence[str], cutoff: str) -> object:
        return {"version": "1", "install": []}


ADVISORY = {
    "id": "GHSA-9wx4-h78v-vm56",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
        }
    ],
}


def _demo_1_0_vulnerable(base: str) -> Any:
    """The local feeds, with OSV naming one advisory for demo 1.0 (fixed in 1.1)."""
    local = _transport(base)

    def transport(request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        if url == net.OSV_QUERYBATCH_URL:
            assert isinstance(request.data, bytes)
            names = [q["package"]["name"] for q in json.loads(request.data)["queries"]]
            results = [{"vulns": [{"id": ADVISORY["id"]}] if n == "demo" else []} for n in names]
            return Response(200, {}, json.dumps({"results": results}).encode(), url)
        if url == f"https://api.osv.dev/v1/vulns/{ADVISORY['id']}":
            return Response(200, {}, json.dumps(ADVISORY).encode(), url)
        answer: Response = local(request, timeout, limit)
        return answer

    return transport


def test_loose_request_kept_by_pip_is_checked(tmp_path: Path, index: Index, home: Path) -> None:
    # #228 (RR2), data integrity: a venv holds demo 1.0, which has a known vulnerability, and pip
    # keeps it for `demo<=1.1`. The request ends with demo 1.0, so 1.0 is what is checked: exit 1,
    # the venv's files untouched. A re-run is the same refusal.
    prefix = tmp_path / ".venv"
    site = make_venv(prefix, "3.12", home=tmp_path / "base" / "bin")
    link_interpreter(prefix, "3.12", tmp_path / "base" / "bin")  # never run: the keeping runner stands in for pip
    add_dist(site, "demo", "1.0")
    before = tree(prefix)
    runner = KeepingPip(index)
    install = Install(
        **{
            **installer(index, home, runner=runner).__dict__,
            "client": Client(transport=_demo_1_0_vulnerable(index.base), timeout=60.0),
        }
    )
    outcomes = [run(install, prefix, "demo") for _ in range(2)]
    assert outcomes[0] == outcomes[1]
    code, result, err = outcomes[0]
    assert code == 1, err
    assert [(f["rule"], f["item"], f["version"]) for f in result["findings"]] == [
        ("known-vulnerability", "demo", "1.0")
    ]
    assert "demo 1.0 fails known-vulnerability (installed; pip keeps it for this request" in err
    assert "Nothing to install" not in err
    assert runner.installs == []
    assert tree(prefix) == before
    assert sorted(p.name for p in site.iterdir()) == ["demo-1.0.dist-info"]


def test_empty_request_is_an_error(tmp_path: Path, index: Index, home: Path) -> None:
    prefix = tmp_path / ".venv"
    make_venv(prefix, "3.12", home=tmp_path / "base" / "bin")
    link_interpreter(prefix, "3.12", tmp_path / "base" / "bin")
    before = tree(prefix)
    runner = RecordingPip(index)

    # On the command line, a usage error (exit 2).
    assert cli.main(["install", "--venv", str(prefix)], stdout=io.StringIO(), stderr=io.StringIO()) == 2

    # At the handler, refused with the form to use (exit 2), nothing resolved or installed.
    err = io.StringIO()
    install = Install(**{**installer(index, home, runner=runner).__dict__, "stderr": err})
    with refuses("install.name-least-one-package-ssc"):
        result = install(Request(Verb.INSTALL, venv=str(prefix), requirements=(), yes=True))
    assert int(result.exit_code) == 2
    usage = f"name at least one package: ssc-guardian install --venv {prefix} NAME[==VERSION]"
    assert f"ssc-guardian: {usage}; nothing installed." in err.getvalue()
    assert runner.installs == []
    assert tree(prefix) == before


# --- the file pip chose is held to its package's own cooldown (#129) --------------------


def test_install_refuses_young_wheel_under_old_sdist(tmp_path: Path, index: Index) -> None:
    # foo 2.0 on the local index: its sdist is 100 days old, its wheel 30. The workstation's
    # rule gives foo 60 days; pip's cutoff is the default's 21, so the wheel is the file it takes.
    home = tmp_path / "home"
    config = home / ".config" / "ssc-guardian" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('format = 1\n[rules]\n"pypi:foo" = { cooldown_days = 60 }\n')
    prefix = tmp_path / ".venv"
    site = make_venv(prefix, "3.12", home=tmp_path / "base" / "bin")
    link_interpreter(prefix, "3.12", tmp_path / "base" / "bin")  # never run: the recording runner stands in for pip
    before = tree(prefix)

    outcomes = []
    for _ in range(2):  # a re-run is the same refusal, and installs nothing
        runner = RecordingPip(index)
        outcome = run(installer(index, home, runner=runner), prefix, "foo==2.0")
        code, result, err = outcome
        assert code == 1, err
        assert [(f["rule"], f["item"], f["version"]) for f in result["findings"]] == [("cooldown", "foo", "2.0")]
        assert "foo-2.0-py3-none-any.whl, the file pip chose, was uploaded on 2026-10-04" in err
        assert "inside its 60-day cooldown, eligible on 2026-12-03" in err
        assert "refused; nothing installed" in err
        assert runner.installs == []
        assert tree(prefix) == before  # the venv is unchanged
        outcomes.append(outcome)
    assert outcomes[0] == outcomes[1]
    assert list(site.iterdir()) == []


def test_install_file_without_upload_time_names_the_package(
    tmp_path: Path, index: Index, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #284: foo 2.0's release is dated by its old sdist, but PyPI gives the wheel pip chose no
    # upload time: the unknown-age skip names the package and version, as check's does.
    wheel, sdist = sorted(index.wheels["foo"], key=lambda entry: entry[0].endswith(".tar.gz"))
    monkeypatch.setitem(index.wheels, "foo", [(wheel[0], wheel[1], None), sdist])
    prefix = tmp_path / ".venv"
    make_venv(prefix, "3.12", home=tmp_path / "base" / "bin")
    link_interpreter(prefix, "3.12", tmp_path / "base" / "bin")  # never run: the recording runner stands in for pip
    before = tree(prefix)
    runner = RecordingPip(index)
    install = installer(index, tmp_path / "home", runner=runner)
    with refuses("install.bound-file-unknown-age"):
        code, result, err = run(install, prefix, "foo==2.0")
    assert code == 2, err
    assert result["skipped"] == [{"ecosystem": "pypi", "place": str(prefix), "reason": "unknown-age", "in_scope": True}]
    out = io.StringIO()
    text = Install(**{**install.__dict__, "stderr": io.StringIO()})
    argv = ["install", "--venv", str(prefix), "--yes", "foo==2.0"]
    assert cli.main(argv, handlers={Verb.INSTALL: text}, stdout=out, stderr=io.StringIO()) == 2
    assert f"  pypi {prefix}: the age could not be established (foo 2.0) [in scope]" in out.getvalue().splitlines()
    assert runner.installs == []
    assert tree(prefix) == before
