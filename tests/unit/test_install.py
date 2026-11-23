# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``install --venv``: target checks, request refusals, pinned pip, binding and the rules (issue #6).

No pip runs and nothing reaches the network: the feeds answer from an in-process transport
and a fake runner stands in for the pinned pip's two steps, recording every call, so a test
can show that a refused request never reached the install step. To pin pip's arguments, one
test runs the real pinned-pip runner with only ``subprocess.run`` replaced.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, pinned_pip, policy
from ssc_guardian.binding import BindingError, Reported, bind, read_report
from ssc_guardian.commands import install as install_module
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.install import Install, RefusedError, refusal
from ssc_guardian.discovery import Environment, Roots
from ssc_guardian.feeds import github_advisories, pypi
from ssc_guardian.feeds.kev import CATALOG_URL
from ssc_guardian.findings import Ecosystem, Verb
from ssc_guardian.grammars import MalformedValueError
from ssc_guardian.net import OSV_QUERYBATCH_URL, Client, Response
from ssc_guardian.plugin import PlannedFile, Requirement
from ssc_guardian.plugins.pip import PipPlugin
from tests.refusal_sites import refuses
from tests.unit.test_discovery import add_dist, fake_mac, make_base, make_venv

pytestmark = pytest.mark.unit

TODAY = date(2026, 11, 3)
OLD = "2025-01-01T00:00:00Z"
YOUNG = "2026-11-01T00:00:00Z"
FILES = "https://files.pythonhosted.org"
ADVISORY: dict[str, Any] = {
    "id": "GHSA-9wx4-h78v-vm56",
    "aliases": ["CVE-2026-1111"],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
        }
    ],
}
# demo 1.0 is vulnerable, 1.1 passes, 2.0 is in its cooldown; helper 3.0 is in its cooldown.
UPLOADS = {
    "demo": {"1.0": OLD, "1.1": OLD, "2.0": YOUNG},
    "helper": {"2.0": OLD, "3.0": YOUNG},
}


def sha(name: str, version: str) -> str:
    return hashlib.sha256(f"{name}-{version}".encode()).hexdigest()


def sdist_sha(name: str, version: str) -> str:
    return hashlib.sha256(f"{name}-{version}.tar.gz".encode()).hexdigest()


def wheel_url(name: str, version: str, origin: str = FILES) -> str:
    return f"{origin}/packages/ab/{name}-{version}-py3-none-any.whl"


def sdist_url(name: str, version: str) -> str:
    return f"{FILES}/packages/ab/{name}-{version}.tar.gz"


def _page(name: str, *, sdists: bool = False) -> dict[str, Any]:
    files = [
        {"filename": f"{name}-{v}-py3-none-any.whl", "url": wheel_url(name, v), "hashes": {"sha256": sha(name, v)}}
        | {"upload-time": when}
        for v, when in UPLOADS[name].items()
    ]
    if sdists:  # PyPI publishes each sdist and its digest too: only binding's wheel check refuses it
        files += [
            {"filename": f"{name}-{v}.tar.gz", "url": sdist_url(name, v), "hashes": {"sha256": sdist_sha(name, v)}}
            | {"upload-time": when}
            for v, when in UPLOADS[name].items()
        ]
    return {"meta": {"api-version": "1.4"}, "name": name, "files": files, "versions": list(UPLOADS[name])}


@dataclass
class Feeds:
    """OSV, GitHub, PyPI, KEV and files.pythonhosted.org, answered in process."""

    vulnerable: dict[str, list[str]] = field(default_factory=lambda: {"demo": ["GHSA-9wx4-h78v-vm56"]})
    advisory: dict[str, Any] = field(default_factory=lambda: ADVISORY)
    wheel: bytes = b""
    osv_status: int = 200
    kev_status: int = 200
    rate_limited: frozenset[str] = frozenset()  # GitHub's hourly limit is used up for these names
    sdists: bool = False
    sent: list[str] = field(default_factory=list)

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        self.sent.append(url)
        status, body = 404, b'{"message": "not found"}'
        if url.startswith(github_advisories.ADVISORIES_URL) and self.rate_limited:
            affects = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("affects", [""])[0].split(",")
            if self.rate_limited & set(affects):
                return Response(403, {"x-ratelimit-remaining": "0"}, b'{"message": "API rate limit exceeded"}', url)
        if url == OSV_QUERYBATCH_URL:
            assert isinstance(request.data, bytes)
            names = [q["package"]["name"] for q in json.loads(request.data)["queries"]]
            results = [{"vulns": [{"id": i} for i in self.vulnerable.get(n, [])]} for n in names]
            status, body = self.osv_status, json.dumps({"results": results}).encode()
        elif url == "https://api.osv.dev/v1/vulns/GHSA-9wx4-h78v-vm56":
            status, body = 200, json.dumps(self.advisory).encode()
        elif url.startswith(github_advisories.ADVISORIES_URL):
            status, body = 200, b"[]"
        elif url.startswith(pypi.SIMPLE_URL) and url.split("/")[4] in UPLOADS:
            status, body = 200, json.dumps(_page(url.split("/")[4], sdists=self.sdists)).encode()
        elif url == CATALOG_URL:
            catalog = {"count": 1, "vulnerabilities": [{"cveID": "CVE-2020-0001", "dateAdded": "2021-11-03"}]}
            status, body = self.kev_status, json.dumps(catalog).encode()
        elif url == pinned_pip.URL:
            status, body = 200, self.wheel
        return Response(status, {}, body, url)


@dataclass
class FakePip:
    """The two pip steps. ``extra`` adds dependencies to the report; ``urls`` and ``digests``
    rewrite an entry's file; ``report``, when given, is the whole report."""

    extra: Sequence[tuple[str, str]] = ()
    origin: str = FILES
    digests: dict[str, str] = field(default_factory=dict)
    urls: dict[str, str] = field(default_factory=dict)
    report: object = None
    checks: list[tuple[str, ...]] = field(default_factory=list)
    installs: list[tuple[PlannedFile, ...]] = field(default_factory=list)

    def check(self, env: Environment, pins: Sequence[str], cutoff: str) -> object:
        self.checks.append(tuple(pins))
        if self.report is not None:
            return self.report
        wanted = [tuple(re.split("==|<=", pin)) for pin in pins] + list(self.extra)
        installed = {p.name for p in Path(env.main_site).glob("*.dist-info")}
        entries = [
            {
                "metadata": {"name": name, "version": version},
                "download_info": {
                    "url": self.urls.get(name, wheel_url(name, version, self.origin)),
                    "archive_info": {"hashes": {"sha256": self.digests.get(name, sha(name, version))}},
                },
                "is_direct": False,
                "requested": name in {re.split("==|<=", pin)[0] for pin in pins},
            }
            for name, version in wanted
            if f"{name}-{version}.dist-info" not in installed
        ]
        return {"version": "1", "install": entries}

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        self.installs.append(tuple(files))
        for planned in files:
            add_dist(Path(env.main_site), planned.item.name, planned.item.version)


def link_interpreter(prefix: Path, python: str, home: Path) -> None:
    """``prefix/bin/python`` as ``venv`` makes it: a link to ``python<X.Y>`` in ``home`` (the
    venv's ``home``), itself a link to the real interpreter. Never run."""
    home.mkdir(parents=True, exist_ok=True)
    named = home / f"python{python}"
    if not named.is_symlink():
        named.symlink_to(os.path.realpath(sys.executable))
    (prefix / "bin").mkdir()
    (prefix / "bin" / "python").symlink_to(named)


def venv(tmp_path: Path, python: str = "3.12") -> Path:
    prefix = tmp_path / "projects" / "app" / ".venv"
    home = tmp_path / "base" / "bin"
    make_venv(prefix, python, home=home)
    link_interpreter(prefix, python, home)  # never run: the fake runner stands in for pip
    return prefix


def handler(
    tmp_path: Path,
    runner: FakePip | None,
    feeds: Feeds | None = None,
    *,
    stdin: str = "",
    host: policy.Host | None = None,
) -> Install:
    (tmp_path / "home").mkdir(exist_ok=True)
    client = Client(transport=feeds or Feeds(), sleep=lambda _: None)
    return Install(
        home=str(tmp_path / "home"),
        environ={"PATH": ""},
        today=TODAY,
        client=client,
        stdin=io.StringIO(stdin),
        runner=runner,
        host=host,
    )


def run(install: Install, target: Path | str, *packages: str, yes: bool = True) -> tuple[int, dict[str, Any], str]:
    out, err = io.StringIO(), io.StringIO()
    install = Install(**{**install.__dict__, "stderr": err})
    argv = ["install", "--venv", str(target), "--json", *(["--yes"] if yes else []), *packages]
    code = cli.main(argv, handlers={Verb.INSTALL: install}, stdout=out, stderr=err)
    text = out.getvalue()
    return code, json.loads(text) if text else {}, err.getvalue()


def tree(folder: Path) -> list[str]:
    return sorted(str(p.relative_to(folder)) for p in folder.rglob("*"))


# --- target -----------------------------------------------------------------------------


def test_refuses_non_venv_and_base_python(tmp_path: Path) -> None:
    runner = FakePip()
    plain = tmp_path / "plain"
    plain.mkdir()
    base = tmp_path / "Library" / "Frameworks" / "Python.framework" / "Versions" / "3.12"
    make_base(base)
    (base / "lib" / "python3.12" / "EXTERNALLY-MANAGED").write_text("[externally-managed]\n")
    for place, said in ((plain, "is not a venv"), (base, "is a base Python installation, not a venv")):
        code, result, err = run(handler(tmp_path, runner), place, "demo")
        assert code == 2
        assert result["skipped"][0]["reason"] == "check-error"
        assert said in err
        assert "create a venv and install there" in err
    assert runner.checks == [] and runner.installs == []


def test_refuses_python_older_than_3_9(tmp_path: Path) -> None:
    old = venv(tmp_path / "old", "3.8")
    runner = FakePip()
    with refuses("install.guardian-installs-into-python-3"):
        code, _, err = run(handler(tmp_path, runner), old, "demo==1.1")
    assert code == 2
    assert "runs Python 3.8; Guardian installs into Python 3.9 or later" in err
    assert runner.checks == []

    # 3.9 is the oldest target, and it is accepted.
    oldest = venv(tmp_path / "oldest", "3.9")
    code, _, _ = run(handler(tmp_path, runner), oldest, "demo==1.1")
    assert code == 0
    assert runner.checks == [("demo==1.1",)]


# --- the venv's interpreter (issue #71) -----------------------------------------------


NO_SYSTEM_SITE = "include-system-site-packages = false\n"


def refused(tmp_path: Path, prefix: Path) -> str:
    """``install demo==1.1`` into ``prefix``: refused before anything resolves (exit 2); stderr."""
    runner = FakePip()
    code, result, err = run(handler(tmp_path, runner), prefix, "demo==1.1")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert runner.checks == [] and runner.installs == []
    return err


def test_replaced_venv_python_is_refused(tmp_path: Path) -> None:
    prefix = venv(tmp_path)
    python = prefix / "bin" / "python"
    # An installed wheel's X.data/scripts/python lands as a file in place of the link.
    python.unlink()
    python.write_text("#!/bin/sh\n")
    python.chmod(0o755)
    assert f"{prefix} has a file, not a link, at bin/python" in refused(tmp_path, prefix)

    # A link to a program inside the venv, named as the base's interpreter is.
    inside = prefix / "lib" / "python3.12"
    (inside / "python3.12").write_text("#!/bin/sh\n")
    python.unlink()
    python.symlink_to(inside / "python3.12")
    assert f"{prefix} has a bin/python that resolves inside the venv" in refused(tmp_path, prefix)

    # A link that leads nowhere.
    python.unlink()
    python.symlink_to(tmp_path / "missing" / "python3.12")
    assert f"{prefix} has a bin/python or a pyvenv.cfg home that does not lead to an interpreter" in refused(
        tmp_path, prefix
    )

    # The positive control: the link to the base's interpreter is accepted.
    python.unlink()
    python.symlink_to(tmp_path / "base" / "bin" / "python3.12")
    if os.geteuid() != 0:  # root lists any folder
        (prefix / "bin").chmod(0o300)  # bin cannot be listed, so no ._pth file can be ruled out
        try:
            assert f"{prefix} has a bin folder that cannot be listed" in refused(tmp_path, prefix)
        finally:
            (prefix / "bin").chmod(0o755)
    runner = FakePip()
    code, _, err = run(handler(tmp_path, runner), prefix, "demo==1.1")
    assert code == 0, err
    assert runner.checks == [("demo==1.1",)]


def test_pyvenv_home_inside_the_venv_is_refused(tmp_path: Path) -> None:
    prefix = venv(tmp_path)
    config = prefix / "pyvenv.cfg"
    # An installed wheel's X.data/data/pyvenv.cfg names a home inside the venv; bin/python
    # still resolves outside, to the very interpreter that home names.
    inside = prefix / "base"
    inside.mkdir()
    (inside / "python3.12").symlink_to(os.path.realpath(sys.executable))
    config.write_text(f"home = {inside}\n{NO_SYSTEM_SITE}")
    assert f"{prefix} has a pyvenv.cfg home inside the venv" in refused(tmp_path, prefix)

    # A home that resolves outside but is written through the venv: Python walks up from it as
    # written, so a .. part, or a link inside the venv, would let it find a planted library.
    (prefix / "x").mkdir()
    for home in (f"{prefix}/x/../../../../base/bin", f"{prefix}/x/./../../../../base/bin"):
        config.write_text(f"home = {home}\n{NO_SYSTEM_SITE}")
        assert f"{prefix} has no plain absolute home in pyvenv.cfg" in refused(tmp_path, prefix), home
    (prefix / "link").symlink_to(tmp_path / "base")
    config.write_text(f"home = {prefix / 'link' / 'bin'}\n{NO_SYSTEM_SITE}")
    assert f"{prefix} has a pyvenv.cfg home inside the venv" in refused(tmp_path, prefix)

    # The venv spelled in another case: on a case-insensitive disk (APFS) it is the same folder,
    # so it is compared by device and inode, never by spelling. On a case-sensitive disk the
    # other spelling does not exist and leads to no interpreter.
    (prefix / "bin" / "python3.12").symlink_to(os.path.realpath(sys.executable))
    other_case = os.path.exists(str(prefix).swapcase())
    said = (
        "has a pyvenv.cfg home inside the venv"
        if other_case
        else "has a bin/python or a pyvenv.cfg home that does not lead to an interpreter"
    )
    config.write_text(f"home = {str(prefix / 'bin').swapcase()}\n{NO_SYSTEM_SITE}")
    assert f"{prefix} {said}" in refused(tmp_path, prefix)
    (prefix / "bin" / "python3.12").unlink()
    config.write_text(f"home = {inside}\n{NO_SYSTEM_SITE}")  # the venv named in another case
    if other_case:
        assert f"{str(prefix).swapcase()} has a pyvenv.cfg home inside the venv" in refused(
            tmp_path, Path(str(prefix).swapcase())
        )

    # A home outside the venv that names another program.
    other = tmp_path / "other" / "bin"
    other.mkdir(parents=True)
    (other / "python3.12").symlink_to("/bin/sh")
    config.write_text(f"home = {other}\n{NO_SYSTEM_SITE}")
    assert f"{prefix} has a bin/python that is not the interpreter pyvenv.cfg's home names" in refused(tmp_path, prefix)

    # No home, an empty one, or a relative one: the interpreter cannot be checked.
    for text in ("", "home =\n", "home = base/bin\n"):
        config.write_text(text + NO_SYSTEM_SITE)
        assert f"{prefix} has no plain absolute home in pyvenv.cfg" in refused(tmp_path, prefix), text

    # The interpreter takes the first home and site.venv the last, and they split lines
    # differently: a file the two could read apart is refused, whichever home is outside.
    outside = tmp_path / "base" / "bin"
    for text in (
        f"home = {inside}\nHOME = {outside}\n",  # two homes, the first inside
        f"home = {outside}\nhome = {inside}\n",
        f"junk\vhome = {outside}\nhome = {inside}\n",  # \v is a line end to splitlines() only
        f"junk\x85home = {outside}\n",
        f"junk\rhome = {outside}\nhome = {inside}\n",  # a lone CR is a line end to site.venv only
        f"home = {outside}\n# {'x' * 2000}\n",  # a line that ends Python 3.9's and 3.10's reading
        f"home = {outside}\n" + "#\n" * 40000,  # longer than the limit
    ):
        config.write_text(text + NO_SYSTEM_SITE)
        err = refused(tmp_path, prefix)
        assert f"{prefix} has a pyvenv.cfg that is not plain text with at most one home line" in err, text[:40]
    config.write_bytes(f"home = {outside}\n\xff\n{NO_SYSTEM_SITE}".encode("latin-1"))  # not UTF-8
    assert "not plain text with at most one home line" in refused(tmp_path, prefix)

    # A wheel's X.data/scripts/pyvenv.cfg lands in bin, where Python looks first.
    config.write_text(f"home = {outside}\n{NO_SYSTEM_SITE}")
    (prefix / "bin" / "pyvenv.cfg").write_text(f"home = {prefix / 'bin'}\n")
    assert f"{prefix} has a pyvenv.cfg in bin, which Python may read instead" in refused(tmp_path, prefix)
    (prefix / "bin" / "pyvenv.cfg").unlink()

    # From 3.11 Python reads bin/python._pth, whatever -I -S say: any ._pth in bin is refused.
    for name in ("python._pth", "python3.12._pth", ".hidden._pth", "python._PTH"):  # APFS ignores case
        (prefix / "bin" / name).write_text("../lib/python3.12/site-packages/evil\n")
        assert f"{prefix} has a ._pth file in bin" in refused(tmp_path, prefix), name
        (prefix / "bin" / name).unlink()

    # Keys are lowered and CRLF lines read as LF lines: one home outside is accepted.
    config.write_text(f"HOME = {outside}\r\n{NO_SYSTEM_SITE}")
    runner = FakePip()
    code, _, err = run(handler(tmp_path, runner), prefix, "demo==1.1")
    assert code == 0, err


def test_copies_venv_is_refused_with_a_message(tmp_path: Path) -> None:
    prefix = venv(tmp_path)
    python = prefix / "bin" / "python"
    python.unlink()
    shutil.copy2(os.path.realpath(sys.executable), python)  # what venv --copies writes
    err = refused(tmp_path, prefix)
    assert f"{prefix} has a file, not a link, at bin/python: a venv made with --copies" in err
    assert "Guardian runs only an interpreter outside the venv; create a venv without --copies and install there" in err


def test_interpreter_check_is_idempotent_on_re_run(tmp_path: Path) -> None:
    accepted, replaced = venv(tmp_path / "accepted"), venv(tmp_path / "replaced")
    python = replaced / "bin" / "python"
    python.unlink()
    python.write_text("#!/bin/sh\n")
    # No --yes and no terminal: the accepted venv goes as far as the confirmation.
    for prefix, said in ((accepted, "not confirmed; nothing installed"), (replaced, "a file, not a link")):
        before = tree(prefix)
        outcomes = []
        for _ in range(2):
            runner = FakePip()
            outcomes.append(run(handler(tmp_path, runner), prefix, "demo==1.1", yes=False))
            assert runner.installs == []
        assert outcomes[0] == outcomes[1]  # the same exit code, JSON and messages
        assert outcomes[0][0] == 2 and said in outcomes[0][2]
        assert tree(prefix) == before


def _fails_in_the_check(monkeypatch: pytest.MonkeyPatch, name: str, path: Path) -> None:
    """``os.<name>(path)`` raises PermissionError when the interpreter check calls it, and only
    there: the steps before it read the same venv."""
    real = getattr(os, name)

    def call(target: Any, *args: Any, **kwargs: Any) -> Any:
        if str(target) == str(path) and sys._getframe(1).f_code.co_name == "check_interpreter":
            raise PermissionError(13, "Permission denied")
        return real(target, *args, **kwargs)

    monkeypatch.setattr(os, name, call)


def _replace_python(prefix: Path, link: Path | None) -> None:
    python = prefix / "bin" / "python"
    python.unlink()
    if link is None:
        python.write_text("#!/bin/sh\n")
    else:
        python.symlink_to(link)


def _home(prefix: Path, home: str) -> None:
    (prefix / "pyvenv.cfg").write_text(f"home = {home}\n{NO_SYSTEM_SITE}")


def _inside_home(prefix: Path) -> None:
    inside = prefix / "base"
    inside.mkdir()
    (inside / "python3.12").symlink_to(os.path.realpath(sys.executable))
    _home(prefix, str(inside))


def _other_program(prefix: Path) -> None:
    other = prefix.parent / "other" / "bin"
    other.mkdir(parents=True)
    (other / "python3.12").symlink_to("/bin/sh")
    _home(prefix, str(other))


def _inside_program(prefix: Path) -> None:
    inside = prefix / "lib" / "python3.12" / "python3.12"
    inside.write_text("#!/bin/sh\n")
    _replace_python(prefix, inside)


# Each reason check_interpreter gives, with its own site (#148): how the venv is planted, the
# site, and the start of the message after the venv's path.
INTERPRETER_REASONS: list[tuple[str, Callable[[Path, pytest.MonkeyPatch], object], Any, str]] = [
    (
        "venv-cannot-be-looked-at",
        lambda p, m: _fails_in_the_check(m, "stat", p),
        refuses("install.venv-cannot-be-looked-at"),
        "cannot be looked at, so its interpreter cannot be checked",
    ),
    (
        "no-bin-python",
        lambda p, m: (p / "bin" / "python").unlink(),
        refuses("install.no-bin-python"),
        "has no bin/python",
    ),
    (
        "bin-python-is-a-file",
        lambda p, m: _replace_python(p, None),
        refuses("install.bin-python-is-a-file"),
        "has a file, not a link, at bin/python",
    ),
    (
        "bin-folder-cannot-be-listed",
        lambda p, m: _fails_in_the_check(m, "listdir", p / "bin"),
        refuses("install.bin-folder-cannot-be-listed"),
        "has a bin folder that cannot be listed",
    ),
    (
        "pyvenv-cfg-in-bin",
        lambda p, m: (p / "bin" / "pyvenv.cfg").write_text(f"home = {p / 'bin'}\n"),
        refuses("install.pyvenv-cfg-in-bin"),
        "has a pyvenv.cfg in bin, which Python may read instead",
    ),
    (
        "pth-file-in-bin",
        lambda p, m: (p / "bin" / "python._pth").write_text("../lib/python3.12/site-packages/evil\n"),
        refuses("install.pth-file-in-bin"),
        "has a ._pth file in bin",
    ),
    (
        "pyvenv-cfg-not-plain-text",
        lambda p, m: _home(p, f"{p.parent / 'a'}\nhome = {p.parent / 'b'}"),
        refuses("install.pyvenv-cfg-not-plain-text"),
        "has a pyvenv.cfg that is not plain text with at most one home line",
    ),
    (
        "home-not-plain-absolute",
        lambda p, m: _home(p, "base/bin"),
        refuses("install.home-not-plain-absolute"),
        "has no plain absolute home in pyvenv.cfg",
    ),
    (
        "interpreter-not-reached",
        lambda p, m: _replace_python(p, p.parent / "missing" / "python3.12"),
        refuses("install.interpreter-not-reached"),
        "has a bin/python or a pyvenv.cfg home that does not lead to an interpreter",
    ),
    (
        "python-resolves-inside-venv",
        lambda p, m: _inside_program(p),
        refuses("install.python-resolves-inside-venv"),
        "has a bin/python that resolves inside the venv",
    ),
    (
        "home-inside-venv",
        lambda p, m: _inside_home(p),
        refuses("install.home-inside-venv"),
        "has a pyvenv.cfg home inside the venv",
    ),
    (
        "python-not-home-interpreter",
        lambda p, m: _other_program(p),
        refuses("install.python-not-home-interpreter"),
        "has a bin/python that is not the interpreter pyvenv.cfg's home names",
    ),
]


@pytest.mark.parametrize(
    ("plant", "case", "said"), [r[1:] for r in INTERPRETER_REASONS], ids=[r[0] for r in INTERPRETER_REASONS]
)
def test_each_interpreter_refusal_has_its_own_site(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    plant: Callable[[Path, pytest.MonkeyPatch], object],
    case: Any,
    said: str,
) -> None:
    # Offline, through the handler: each reason fires its own site inside the one target-unchecked
    # refusal, exits 2 with its message, and nothing is installed or changed in the venv.
    prefix = venv(tmp_path)
    plant(prefix, monkeypatch)
    before = tree(prefix)
    runner = FakePip()
    with refuses("install.target-unchecked"), case:
        code, result, err = run(handler(tmp_path, runner), prefix, "demo==1.1")
    assert code == result["exit_code"] == 2
    assert result["skipped"][0]["reason"] == "check-error"
    assert f"{prefix} {said}" in err
    assert runner.checks == [] and runner.installs == []
    assert tree(prefix) == before


def test_the_twelve_interpreter_reasons_are_all_tested() -> None:
    # The table above holds every site check_interpreter has, each once.
    source = Path(install_module.__file__).read_text()
    body = source[source.index("def check_interpreter(") : source.index("def target(")]
    sites = re.findall(r'site="(install\.[a-z0-9-]+)"', body)
    assert len(sites) == 12
    assert sorted(sites) == sorted(f"install.{r[0]}" for r in INTERPRETER_REASONS)


def test_fifo_in_the_wheel_cache_is_refused_not_hung(tmp_path: Path) -> None:
    home = str(tmp_path / "home")
    cached = Path(pinned_pip.cache_dir(home)) / f"{pinned_pip.SHA256}.whl"
    cached.parent.mkdir(parents=True)
    os.mkfifo(cached)
    client = Client(transport=Feeds(wheel=b"not the pinned wheel"), sleep=lambda _: None)

    def wheel() -> BaseException | bytes:
        try:
            return pinned_pip.wheel_bytes(client, home)
        except pinned_pip.PinnedPipError as exc:
            return exc

    # No writer: a blocking open would wait for one forever.
    outcome = finishes(wheel, cached)
    assert "does not match the SHA-256" in str(outcome)  # a miss: the download was tried

    # A writer holding planted bytes: the FIFO is never read, so they are still there.
    writer = os.open(cached, os.O_RDWR | os.O_NONBLOCK)
    try:
        os.write(writer, b"planted")
        outcome = finishes(wheel, cached, writer)
        assert "does not match the SHA-256" in str(outcome)
        assert os.read(writer, 64) == b"planted"
    finally:
        with contextlib.suppress(OSError):  # finishes() closed it if the read hung
            os.close(writer)


def finishes(call: Callable[[], object], fifo: Path, writer: int | None = None) -> object:
    """``call()``'s answer; fails, never hangs, when ``call`` blocks on ``fifo``."""
    answer: list[object] = []
    thread = threading.Thread(target=lambda: answer.append(call()), daemon=True)
    thread.start()
    thread.join(10)
    if thread.is_alive():  # unblock the reader, then fail
        if writer is None:
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        else:
            os.close(writer)
        thread.join(10)
        pytest.fail(f"blocked on the FIFO at {fifo}")
    return answer[0]


# --- requests ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("requirement", "said"),
    [
        ("https://example.com/demo-1.0-py3-none-any.whl", "direct URL"),
        ("demo @ https://example.com/demo.tar.gz", "direct URL"),
        ("git+https://github.com/owner/demo", "VCS requirement"),
        ("hg+https://example.com/demo", "VCS requirement"),
        ("./demo", "local path"),
        ("/Users/dev/src/demo", "local path"),
        ("demo-1.0-py3-none-any.whl", "local path"),
        ("-e .", "editable requirement"),
        ("--editable=./demo", "editable requirement"),
    ],
)
def test_refuses_direct_url_vcs_local_and_editable(tmp_path: Path, requirement: str, said: str) -> None:
    why = refusal(requirement)
    assert why is not None and said in why
    assert "install a released version from PyPI by name" in why or "released wheels from PyPI" in why
    # The command line never lets one through: a malformed name (exit 1), nothing resolved.
    runner = FakePip()
    code, result, _ = run(handler(tmp_path, runner), venv(tmp_path), "--", requirement)
    assert code == 1
    assert result["findings"][0]["rule"] == "malformed-name"
    assert runner.checks == [] and runner.installs == []


@pytest.mark.parametrize(
    "line",
    [
        "--no-binary=:all:",
        "--no-binary :all:",
        "--find-links=/Users/dev/wheels",
        "-f https://example.com/wheels",
        "--index-url=https://example.com/simple",
        "-i https://example.com/simple",
        "--extra-index-url https://example.com/simple",
        "-r requirements.txt",
        "-c constraints.txt",
    ],
)
def test_refuses_requirement_file_option_lines(tmp_path: Path, line: str) -> None:
    why = refusal(line)
    assert why is not None and "option lines" in why
    assert refusal("demo") is None and refusal("demo==1.1") is None
    runner = FakePip()
    code, _, _ = run(handler(tmp_path, runner), venv(tmp_path), "--", line)
    assert code == 1
    assert runner.checks == [] and runner.installs == []


# --- pinned pip -------------------------------------------------------------------------


def test_pinned_pip_hash_mismatch_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = str(tmp_path / "home")
    cached = Path(pinned_pip.cache_dir(home)) / f"{pinned_pip.SHA256}.whl"

    # A corrupt download is refused and never cached.
    feeds = Feeds(wheel=b"not the pinned wheel")
    with (
        refuses("pinned_pip.does-not-match-sha-256"),
        pytest.raises(pinned_pip.PinnedPipError, match="does not match the SHA-256"),
    ):
        pinned_pip.wheel_bytes(Client(transport=feeds, sleep=lambda _: None), home)
    assert not cached.exists()

    # Through the command: exit 2, and no program is ever started.
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("no program runs with an unverified pip")

    monkeypatch.setattr(subprocess, "run", refuse)
    code, _, err = run(handler(tmp_path, None, feeds), venv(tmp_path), "demo==1.1")
    assert code == 2
    assert "does not match the SHA-256 Guardian pins" in err

    # A corrupt cached copy is replaced by a download that matches the pin.
    good = b"the pinned wheel"
    monkeypatch.setattr(pinned_pip, "SHA256", hashlib.sha256(good).hexdigest())
    cached = Path(pinned_pip.cache_dir(home)) / f"{pinned_pip.SHA256}.whl"
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(b"tampered")
    assert pinned_pip.wheel_bytes(Client(transport=Feeds(wheel=good), sleep=lambda _: None), home) == good
    assert cached.read_bytes() == good


def test_locked_down_bootstrap_loads_no_installed_module(tmp_path: Path) -> None:
    # The check step's safety, offline: under -I -S -B and the bootstrap's finder, modules that
    # pip's own code imports when it can (attr, backports, _manylinux, keyring) are never loaded
    # from the venv's package folders, while their metadata stays readable.
    marker, results = tmp_path / "trap-fired.txt", tmp_path / "results.json"
    folder = tmp_path / "site-packages"
    for name in ("attr/__init__.py", "backports/__init__.py", "_manylinux.py", "keyring/__init__.py"):
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(f"import pathlib; pathlib.Path({str(marker)!r}).open('a').write({name!r})\n")
    add_dist(folder, "attrs", "25.1.0")
    probe = (
        "import importlib, importlib.metadata, json, sys\n"
        "loaded = {}\n"
        "for name in ('attr', 'backports', '_manylinux', 'keyring', 'json'):\n"
        "    try:\n"
        "        importlib.import_module(name)\n"
        "        loaded[name] = True\n"
        "    except ImportError:\n"
        "        loaded[name] = False\n"
        "seen = sorted(d.metadata['Name'] for d in importlib.metadata.distributions())\n"
        "open(sys.argv[1], 'w').write(json.dumps({'loaded': loaded, 'seen': seen}))\n"
    )
    wheel = tmp_path / "pip.whl"
    with zipfile.ZipFile(wheel, "w") as archive:  # a stand-in for the pinned pip's wheel
        archive.writestr("pip/__init__.py", "")
        archive.writestr("pip/__main__.py", probe)
    work = tmp_path / "work"
    work.mkdir()
    done = pinned_pip.run(
        sys.executable,
        ("-I", "-S", "-B"),  # the literal flags, never LOCKED_DOWN itself: run() accepts only its two modes
        str(wheel),
        [str(folder)],
        [str(results)],
        env=pinned_pip.clean_environment(str(work)),
        cwd=str(work),
    )
    assert done.returncode == 0, done.stderr
    answer = json.loads(results.read_text())
    assert answer["loaded"] == {"attr": False, "backports": False, "_manylinux": False, "keyring": False, "json": True}
    assert "attrs" in answer["seen"]  # installed packages are still seen
    assert not marker.exists()
    assert not list(folder.rglob("__pycache__"))  # -B: nothing written


def test_locked_down_flags_are_isolated_and_no_site(tmp_path: Path) -> None:
    # Plan §3.1 steps 4 and 7, by literal value: the check step's Python runs isolated (-I),
    # with no site processing (-S) and writing no bytecode (-B); the install step's only -I.
    assert pinned_pip.LOCKED_DOWN == ("-I", "-S", "-B")
    assert pinned_pip.NORMAL == ("-I",)
    results = tmp_path / "flags.json"
    probe = (
        "import json, sys\n"
        "f = sys.flags\n"
        "seen = [f.isolated, f.no_site, f.dont_write_bytecode, 'site' in sys.modules]\n"
        "open(sys.argv[1], 'w').write(json.dumps(seen))\n"
    )
    wheel = tmp_path / "pip.whl"
    with zipfile.ZipFile(wheel, "w") as archive:  # a stand-in for the pinned pip's wheel
        archive.writestr("pip/__init__.py", "")
        archive.writestr("pip/__main__.py", probe)
    work = tmp_path / "work"
    work.mkdir()
    seen: dict[str, object] = {}
    for name, mode in (("check", pinned_pip.LOCKED_DOWN), ("install", pinned_pip.NORMAL)):
        environment = pinned_pip.clean_environment(str(work))
        done = pinned_pip.run(sys.executable, mode, str(wheel), [], [str(results)], env=environment, cwd=str(work))
        assert done.returncode == 0, done.stderr
        seen[name] = json.loads(results.read_text())
    assert seen == {"check": [1, 1, 1, False], "install": [1, 0, 0, True]}


def _report_entry(name: str, version: str) -> dict[str, Any]:
    return {
        "metadata": {"name": name, "version": version},
        "download_info": {
            "url": wheel_url(name, version),
            "archive_info": {"hashes": {"sha256": sha(name, version)}},
        },
        "is_direct": False,
        "requested": name == "demo",
    }


def test_pip_arguments_are_wheels_only_and_hash_pinned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real PinnedPip, with only subprocess.run replaced: each step's whole argument list
    # and environment, as literal values (plan §3.1 steps 4 and 7; never-cut wheels-only).
    good = b"the pinned wheel"
    monkeypatch.setattr(pinned_pip, "SHA256", hashlib.sha256(good).hexdigest())
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))  # the run's private folder, under tmp_path
    target = venv(tmp_path)
    (site,) = target.glob("lib/python3.*/site-packages")
    calls: list[tuple[list[str], dict[str, str], str]] = []
    pinned: list[str] = []
    real = subprocess.run

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        if pinned_pip.BOOTSTRAP not in argv:  # not the pinned pip: run as it is
            return real(argv, **kwargs)
        env, cwd = kwargs["env"], kwargs["cwd"]
        calls.append((list(argv), dict(env), cwd))
        if "--report" in argv:
            entries = [_report_entry("demo", "1.1"), _report_entry("helper", "2.0")]
            Path(argv[argv.index("--report") + 1]).write_text(json.dumps({"version": "1", "install": entries}))
        else:
            pinned.append(Path(argv[argv.index("-r") + 1]).read_text())
            for line in pinned[-1].splitlines():
                add_dist(site, *line.split(" ")[0].split("=="))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(pinned_pip.subprocess, "run", fake_run)
    code, _, err = run(handler(tmp_path, None, Feeds(wheel=good)), target, "demo==1.1")
    assert code == 0, err
    ((check, check_env, folder), (install, install_env, same)) = calls
    python, wheel = str(target / "bin" / "python"), os.path.join(folder, "pip-26.0.1-py3-none-any.whl")
    common = [
        "install",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "--no-cache-dir",
        "--index-url",
        "https://pypi.org/simple",
        "--only-binary",
        ":all:",
        "--quiet",
    ]
    assert check == [
        python,
        "-I",
        "-S",
        "-B",
        "-c",
        pinned_pip.BOOTSTRAP,
        wheel,
        "1",
        str(site),
        *common,
        "--upgrade",
        "--uploaded-prior-to",
        "2026-10-13T00:00:00+00:00",  # TODAY less the 21-day default cooldown
        "--dry-run",
        "--report",
        os.path.join(folder, "report.json"),
        "demo==1.1",
    ]
    requirements = os.path.join(folder, "pinned-requirements.txt")
    assert install == [
        python,
        "-I",
        "-c",
        pinned_pip.BOOTSTRAP,
        wheel,
        "0",
        *common,
        "--no-deps",
        "--require-hashes",
        "-r",
        requirements,
    ]
    assert pinned == [
        f"demo==1.1 --hash=sha256:{sha('demo', '1.1')}\nhelper==2.0 --hash=sha256:{sha('helper', '2.0')}\n"
    ]
    clean = {"PATH": "/usr/bin:/bin", "HOME": folder, "TMPDIR": folder, "PIP_CONFIG_FILE": os.devnull}
    assert check_env == install_env == clean and same == folder
    assert os.path.dirname(folder) == str(tmp_path)


# --- binding ----------------------------------------------------------------------------


def _projects(*names: str) -> dict[str, pypi.Project]:
    return {name: pypi.parse_project(_page(name), name) for name in names}


def test_file_not_from_pythonhosted_is_refused(tmp_path: Path) -> None:
    for url in (
        "https://evil.example/packages/ab/demo-1.1-py3-none-any.whl",
        "http://files.pythonhosted.org/packages/ab/demo-1.1-py3-none-any.whl",
        "https://files.pythonhosted.org.evil.example/packages/ab/demo-1.1-py3-none-any.whl",
    ):
        entry = Reported("demo", "1.1", url, sha("demo", "1.1"), is_direct=False, requested=True)
        with (
            refuses("binding.not-from-pypi-files-host"),
            pytest.raises(BindingError, match="not files.pythonhosted.org"),
        ):
            bind((entry,), _projects("demo"), target="/Users/dev/app/.venv")
    direct = Reported("demo", "1.1", wheel_url("demo", "1.1"), sha("demo", "1.1"), is_direct=True, requested=True)
    with (
        refuses("binding.direct-reference-not-file-pypi"),
        pytest.raises(
            BindingError, match="^" + re.escape("demo 1.1 is a direct reference, not a file from PyPI") + "$"
        ),
    ):
        bind((direct,), _projects("demo"), target="/Users/dev/app/.venv")
    nowhere = Reported(  # a URL with no host
        "demo",
        "1.1",
        "file:///packages/ab/demo-1.1-py3-none-any.whl",
        sha("demo", "1.1"),
        is_direct=False,
        requested=True,
    )
    said = "^" + re.escape("demo 1.1 would come from an unknown place, not files.pythonhosted.org") + "$"
    with refuses("binding.not-from-pypi-files-host"), pytest.raises(BindingError, match=said):
        bind((nowhere,), _projects("demo"), target="/Users/dev/app/.venv")
    unreadable = Reported(
        "demo",
        "1.1",
        "https://[files.pythonhosted.org/demo-1.1-py3-none-any.whl",
        sha("demo", "1.1"),
        is_direct=False,
        requested=True,
    )
    with (
        refuses("binding.pips-url-cannot-read"),
        pytest.raises(BindingError, match="^demo 1.1: pip's URL for it cannot be read$"),
    ):
        bind((unreadable,), _projects("demo"), target="/Users/dev/app/.venv")

    runner = FakePip(origin="https://evil.example")
    code, _, err = run(handler(tmp_path, runner), venv(tmp_path), "demo==1.1")
    assert code == 2
    assert "not files.pythonhosted.org" in err
    assert runner.installs == []


def test_digest_mismatch_is_refused(tmp_path: Path) -> None:
    entry = Reported("demo", "1.1", wheel_url("demo", "1.1"), "0" * 64, is_direct=False, requested=True)
    with (
        refuses("binding.does-not-match-sha-256"),
        pytest.raises(BindingError, match="does not match the SHA-256 PyPI publishes"),
    ):
        bind((entry,), _projects("demo"), target="/Users/dev/app/.venv")
    good = Reported("demo", "1.1", wheel_url("demo", "1.1"), sha("demo", "1.1"), is_direct=False, requested=True)
    (planned,) = bind((good,), _projects("demo"), target="/Users/dev/app/.venv")
    assert (planned.item.name, planned.item.version, planned.digest) == ("demo", "1.1", sha("demo", "1.1"))

    runner = FakePip(extra=[("helper", "2.0")], digests={"helper": "f" * 64})
    code, _, err = run(handler(tmp_path, runner), venv(tmp_path), "demo==1.1")
    assert code == 2
    assert "helper 2.0: helper-2.0-py3-none-any.whl does not match the SHA-256 PyPI publishes" in err
    assert runner.installs == []


TARGET = "/Users/dev/app/.venv"


def _refused_through_install(tmp_path: Path, runner: FakePip, feeds: Feeds, said: str) -> None:
    """``install demo==1.1`` with ``runner``'s report: exit 2, ``said`` on stderr, nothing installed."""
    target = venv(tmp_path)
    before = tree(target)
    code, result, err = run(handler(tmp_path, runner, feeds), target, "demo==1.1")
    assert code == 2, err
    assert result["skipped"] == [{"ecosystem": "pypi", "place": str(target), "reason": "check-error", "in_scope": True}]
    assert said in err and "nothing installed" in err
    assert runner.installs == []
    assert tree(target) == before


def test_sdist_is_refused_by_binding(tmp_path: Path) -> None:
    # PyPI publishes the sdist and its digest, so only the wheel check stands in its way.
    projects = {"demo": pypi.parse_project(_page("demo", sdists=True), "demo")}
    sdist = Reported("demo", "1.1", sdist_url("demo", "1.1"), sdist_sha("demo", "1.1"), is_direct=False, requested=True)
    with (
        refuses("binding.not-wheel"),
        pytest.raises(BindingError, match=r"^demo 1\.1: demo-1\.1\.tar\.gz is not a wheel$"),
    ):
        bind((sdist,), projects, target=TARGET)

    runner = FakePip(urls={"demo": sdist_url("demo", "1.1")}, digests={"demo": sdist_sha("demo", "1.1")})
    _refused_through_install(tmp_path, runner, Feeds(sdists=True), "demo-1.1.tar.gz is not a wheel")


def test_binding_refuses_a_file_for_another_version(tmp_path: Path) -> None:
    projects = _projects("demo", "helper")
    for url, digest, version in (
        (wheel_url("demo", "1.0"), sha("demo", "1.0"), "1.1"),  # 1.0's file, published by PyPI, reported as 1.1
        (wheel_url("helper", "2.0"), sha("helper", "2.0"), "1.1"),  # another project's file
        (wheel_url("demo", "1.1"), sha("demo", "1.1"), "one"),  # a version that is no version
    ):
        entry = Reported("demo", version, url, digest, is_direct=False, requested=True)
        with (
            refuses("binding.does-not-hold-name-version"),
            pytest.raises(BindingError, match="does not hold that name and version"),
        ):
            bind((entry,), projects, target=TARGET)

    runner = FakePip(urls={"demo": wheel_url("demo", "1.0")}, digests={"demo": sha("demo", "1.0")})
    said = "demo 1.1: the file demo-1.0-py3-none-any.whl does not hold that name and version"
    _refused_through_install(tmp_path, runner, Feeds(), said)


def test_binding_refuses_missing_or_unread_digests(tmp_path: Path) -> None:
    url, good = wheel_url("demo", "1.1"), sha("demo", "1.1")

    # pip's report gives no SHA-256, or one that is not 64 lowercase hex digits.
    for digest in (None, "", good.upper(), good[:63], f"sha256:{good}"):
        entry = Reported("demo", "1.1", url, digest, is_direct=False, requested=True)
        said = "^" + re.escape("demo 1.1: pip's report gives no SHA-256 for demo-1.1-py3-none-any.whl") + "$"
        with refuses("binding.pips-report-gives-no-sha"), pytest.raises(BindingError, match=said):
            bind((entry,), _projects("demo"), target=TARGET)

    # PyPI's digests were not read: no project (a failed read) or none by that name (404).
    entry = Reported("demo", "1.1", url, good, is_direct=False, requested=True)
    for projects in ({}, {"demo": pypi.Project("demo", False)}):
        with (
            refuses("binding.pypis-digests-could-not-read"),
            pytest.raises(BindingError, match="demo 1.1: PyPI's digests for it could not be read"),
        ):
            bind((entry,), projects, target=TARGET)

    # PyPI lists no such file, or the file without a SHA-256.
    page = _page("demo")
    without = {**page, "files": [f for f in page["files"] if f["filename"] != "demo-1.1-py3-none-any.whl"]}
    unhashed = {**page, "files": [{**f, "hashes": {}} for f in page["files"]]}
    for listed in (without, unhashed):
        said = "^" + re.escape("demo 1.1: PyPI publishes no SHA-256 for demo-1.1-py3-none-any.whl") + "$"
        with refuses("binding.pypi-publishes-no-sha-256"), pytest.raises(BindingError, match=said):
            bind((entry,), {"demo": pypi.parse_project(listed, "demo")}, target=TARGET)

    # Through the command: a dependency PyPI does not know (404).
    runner = FakePip(extra=[("ghost", "1.0")])
    _refused_through_install(tmp_path, runner, Feeds(), "ghost 1.0: PyPI's digests for it could not be read")


def test_binding_refuses_a_package_named_twice(tmp_path: Path) -> None:
    first = Reported("demo", "1.1", wheel_url("demo", "1.1"), sha("demo", "1.1"), is_direct=False, requested=True)
    for second in (
        Reported("Demo", "1.1", wheel_url("Demo", "1.1"), sha("demo", "1.1"), is_direct=False, requested=False),
        Reported("demo", "1.0", wheel_url("demo", "1.0"), sha("demo", "1.0"), is_direct=False, requested=False),
    ):
        with (
            refuses("binding.report-names-twice"),
            pytest.raises(BindingError, match=f"pip's report names {second.name} twice"),
        ):
            bind((first, second), _projects("demo"), target=TARGET)

    _refused_through_install(tmp_path, FakePip(extra=[("Demo", "1.1")]), Feeds(), "pip's report names Demo twice")


def test_binding_refuses_a_report_it_does_not_read(tmp_path: Path) -> None:
    good = _report_entry("demo", "1.1")
    for report in (None, [good], {"version": "2", "install": [good]}, {"version": 1}, {"version": "1", "install": {}}):
        with (
            refuses("binding.pips-report-not-installation-report"),
            pytest.raises(BindingError, match="pip's report is not an installation report Guardian reads"),
        ):
            read_report(report)
    for entry in ("demo", {"metadata": good["metadata"]}, {"download_info": good["download_info"]}):
        with (
            refuses("binding.pips-report-entry-without-metadata"),
            pytest.raises(BindingError, match="^pip's report has an entry without metadata or download information$"),
        ):
            read_report({"version": "1", "install": [entry]})
    for metadata, info in (
        ({"version": "1.1"}, good["download_info"]),
        ({"name": "demo", "version": 1.1}, good["download_info"]),
        (good["metadata"], {"archive_info": good["download_info"]["archive_info"]}),
    ):
        with (
            refuses("binding.pips-report-entry-without-name"),
            pytest.raises(BindingError, match="^pip's report has an entry without a name, version or URL$"),
        ):
            read_report({"version": "1", "install": [{**good, "metadata": metadata, "download_info": info}]})
    assert [e.name for e in read_report({"version": "1", "install": [good]})] == ["demo"]

    runner = FakePip(report={"version": "2", "install": [good]})
    _refused_through_install(tmp_path, runner, Feeds(), "pip's report is not an installation report Guardian reads")


# --- the rules --------------------------------------------------------------------------


def test_exact_request_failing_rule_names_newest_passing_version(tmp_path: Path) -> None:
    runner = FakePip()
    target = venv(tmp_path)
    code, result, err = run(handler(tmp_path, runner), target, "demo==1.0")
    assert code == 1
    (finding,) = [f for f in result["findings"] if f["rule"] == "known-vulnerability"]
    assert (finding["item"], finding["version"]) == ("demo", "1.0")
    replace = [o for o in finding["options"] if o["kind"] == "replace"]
    assert replace[0]["command"] == ["ssc-guardian", "install", "--venv", str(target), "demo==1.1"]
    assert (replace[1]["version"], replace[1]["eligible_on"]) == ("2.0", "2026-11-22")
    assert "demo==1.0 fails a rule" in err
    assert runner.checks == [] and runner.installs == []


def test_loose_request_installs_newest_passing_version(tmp_path: Path) -> None:
    runner = FakePip(extra=[("helper", "2.0")])
    target = venv(tmp_path)
    code, result, err = run(handler(tmp_path, runner), target, "demo")
    assert code == 0, err
    assert result["checked"] == [{"ecosystem": "pypi", "place": str(target)}]
    assert runner.checks == [("demo<=1.1",)]  # 1.0 is vulnerable and 2.0 is in its cooldown
    ((demo, helper),) = runner.installs
    assert (demo.item.name, demo.item.version, demo.digest) == ("demo", "1.1", sha("demo", "1.1"))
    assert (helper.item.name, helper.item.version) == ("helper", "2.0")
    assert "Confirmed in advance (--yes)." in err  # --yes still prints the change (D15)
    assert f"sha256:{sha('demo', '1.1')}" in err


@pytest.mark.parametrize("stream", ["closed", "broken"])
def test_closed_stderr_after_install_keeps_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    # Contracts §3 (#76): "Installed into ..." after a completed install turned exit 0 into 2.
    class Broken(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError("stderr is closed")

        def flush(self) -> None:
            raise OSError("stderr is closed")

    err: io.StringIO | None = Broken() if stream == "broken" else None
    monkeypatch.setattr(sys, "stderr", err)  # None is what Python sets when fd 2 is closed at start
    target = venv(tmp_path)
    for request, expected, installs in (("demo==1.1", 0, 1), ("demo==1.0", 1, 0)):  # 1.0 is vulnerable
        runner = FakePip()
        install = Install(**{**handler(tmp_path, runner).__dict__, "stderr": err})
        argv = ["install", "--venv", str(target), "--json", "--yes", request]
        assert cli.main(argv, handlers={Verb.INSTALL: install}, stdout=io.StringIO(), stderr=err) == expected
        assert len(runner.installs) == installs


def test_failing_dependency_refuses_whole_request(tmp_path: Path) -> None:
    runner = FakePip(extra=[("helper", "3.0")])
    target = venv(tmp_path)
    with refuses("policy.cooldown"):
        code, result, err = run(handler(tmp_path, runner), target, "demo==1.1")
    assert code == 1
    (finding,) = result["findings"]
    assert (finding["rule"], finding["item"], finding["version"]) == ("cooldown", "helper", "3.0")
    commands = [o["command"] for o in finding["options"] if o["command"]]
    assert commands == [["ssc-guardian", "install", "--venv", str(target), "helper==2.0"]]
    assert "helper 3.0 fails cooldown (a dependency pip chose for this request" in err
    assert runner.checks == [("demo==1.1",)]  # one resolve: no re-resolve loop
    assert runner.installs == []


def _deny(tmp_path: Path, name: str) -> None:
    """The workstation settings deny ``name`` on PyPI."""
    config = tmp_path / "home" / ".config" / "ssc-guardian"
    config.mkdir(parents=True, exist_ok=True)
    (config / "config.toml").write_text(f'format = 1\ndeny = ["pypi:{name}"]\n')


def test_a_denied_request_is_refused_before_pip_resolves(tmp_path: Path) -> None:
    # The package asked for is on the deny list: refused at the request, and pip never runs.
    runner, target = FakePip(), venv(tmp_path)
    install = handler(tmp_path, runner)
    _deny(tmp_path, "demo")
    with refuses("install.denied-requested"):
        code, result, err = run(install, target, "demo==1.1")
    assert code == 1
    assert [(f["rule"], f["item"], f["version"]) for f in result["findings"]] == [("deny-list", "demo", "1.1")]
    assert "demo is on the deny list; it is never installed." in err
    assert runner.checks == [] and runner.installs == []


def test_a_denied_dependency_pip_chose_is_refused(tmp_path: Path) -> None:
    # A dependency pip chose for the request is on the deny list: the whole request is refused.
    runner, target = FakePip(extra=[("helper", "2.0")]), venv(tmp_path)
    install = handler(tmp_path, runner)
    _deny(tmp_path, "helper")
    with refuses("install.denied-resolved"):
        code, result, _ = run(install, target, "demo==1.1")
    assert code == 1
    assert [(f["rule"], f["item"], f["version"]) for f in result["findings"]] == [("deny-list", "helper", "2.0")]
    assert runner.checks == [("demo==1.1",)] and runner.installs == []


def test_rate_limit_on_a_dependency_stops_the_install(tmp_path: Path) -> None:
    # Plan §2.2: a check that did not finish never gives 0. GitHub answers for demo; its hourly
    # limit is used up when Guardian reads helper, the dependency pip chose.
    runner = FakePip(extra=[("helper", "2.0")])
    feeds = Feeds(rate_limited=frozenset({"helper"}))
    target = venv(tmp_path)
    before = tree(target)
    code, result, err = run(handler(tmp_path, runner, feeds), target, "demo==1.1")
    assert code == 2, err
    assert result["skipped"] == [{"ecosystem": "pypi", "place": str(target), "reason": "rate-limit", "in_scope": True}]
    assert result["checked"] == [] and result["findings"] == []
    assert "GitHub's hourly rate limit is used up" in err and "nothing installed" in err
    assert any("affects=helper" in url for url in feeds.sent)  # reached only after pip resolved helper
    assert runner.checks == [("demo==1.1",)] and runner.installs == []
    assert tree(target) == before


@pytest.mark.parametrize(
    ("pip", "feeds", "expected"),
    [
        pytest.param({"extra": [("helper", "2.0")]}, {"rate_limited": frozenset({"helper"})}, 2, id="rate-limit"),
        pytest.param(
            {"urls": {"demo": sdist_url("demo", "1.1")}, "digests": {"demo": sdist_sha("demo", "1.1")}},
            {"sdists": True},
            2,
            id="sdist",
        ),
        pytest.param({"extra": [("helper", "3.0")]}, {}, 1, id="failing-dependency"),
    ],
)
def test_install_refusal_is_idempotent_on_re_run(
    tmp_path: Path, pip: dict[str, Any], feeds: dict[str, Any], expected: int
) -> None:
    # Each run is a fresh process: its own client, so GitHub's limit is not remembered between them.
    target = venv(tmp_path)
    before = tree(target)
    outcomes = []
    for _ in range(2):
        runner = FakePip(**pip)
        outcomes.append(run(handler(tmp_path, runner, Feeds(**feeds)), target, "demo==1.1"))
        assert runner.installs == []
    assert outcomes[0] == outcomes[1]  # the same exit code, JSON and messages
    assert outcomes[0][0] == expected
    assert tree(target) == before


@pytest.mark.parametrize(
    ("packages", "yes", "feeds", "expected"),
    [
        (["demo==1.0"], True, Feeds(), 1),  # a rule fails
        (["demo==1.1"], False, Feeds(), 2),  # no terminal: no confirmation
        (["demo==1.1"], True, Feeds(osv_status=500), 2),  # a feed fails
        (["demo==9.9"], True, Feeds(), 2),  # PyPI has no such release
    ],
)
def test_nothing_installed_on_exit_one_or_two(
    tmp_path: Path, packages: list[str], yes: bool, feeds: Feeds, expected: int
) -> None:
    runner = FakePip()
    target = venv(tmp_path)
    before = tree(target)
    code, _, err = run(handler(tmp_path, runner, feeds), target, *packages, yes=yes)
    assert code == expected
    assert "nothing installed" in err
    assert runner.installs == []
    assert tree(target) == before


def test_declined_confirmation_installs_nothing(tmp_path: Path) -> None:
    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    runner = FakePip()
    install = Install(**{**handler(tmp_path, runner).__dict__, "stdin": Terminal("n\n")})
    code, _, err = run(install, venv(tmp_path), "demo==1.1", yes=False)
    assert code == 2
    assert "Proceed? [y/N]" in err and "Add --yes to confirm in advance" in err
    assert runner.checks == [("demo==1.1",)] and runner.installs == []


def test_an_override_that_applies_releases_an_exact_request(tmp_path: Path) -> None:
    # Plan §3.1 step 6: overrides are part of the rules. With no fixed version, a workstation
    # override for each listed advisory releases demo 1.1 (contracts §10.4).
    unfixed = {
        **ADVISORY,
        "affected": [{**ADVISORY["affected"][0], "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
    }
    entries = "".join(
        f"""
[[override]]
ecosystem = "pypi"
item = "demo"
version = "1.1"
rule = "known-vulnerability"
reference = "{reference}"
category = "no-fix-available"
created = 2026-11-01
expiry = 2026-11-20
reason = "tests: reviewed, not reachable"
"""
        for reference in ("CVE-2026-1111", "GHSA-9wx4-h78v-vm56")
    )
    runner = FakePip()
    install = handler(tmp_path, runner, Feeds(advisory=unfixed))
    overrides = tmp_path / "home" / ".config" / "ssc-guardian" / "overrides.toml"

    code, result, _ = run(install, venv(tmp_path), "demo==1.1")
    assert code == 1  # no override yet: the vulnerability blocks, and nothing resolves
    assert runner.checks == []

    overrides.parent.mkdir(parents=True)
    overrides.write_text("format = 1\n" + entries)
    code, result, err = run(install, venv(tmp_path / "second"), "demo==1.1")
    assert code == 0, err
    assert {o["reference"] for o in result["overrides"]["applied"]} == {"CVE-2026-1111", "GHSA-9wx4-h78v-vm56"}
    assert runner.checks == [("demo==1.1",)] and len(runner.installs) == 1


ONE_OVERRIDE = """format = 1
[[override]]
ecosystem = "pypi"
item = "demo"
version = "1.0"
rule = "known-vulnerability"
reference = "CVE-2026-1111"
category = "no-fix-available"
created = 2026-11-01
expiry = 2026-11-20
reason = "tests: reviewed, not reachable"
"""
MALFORMED_OVERRIDES = "format = 1\n[[override]]\nitem = 1\n"


@pytest.mark.parametrize(
    ("text", "note", "skipped"),
    [(ONE_OVERRIDE, "not applied", 0), (MALFORMED_OVERRIDES, "has no ecosystem", 1)],
    ids=["not-applied", "malformed-file"],
)
def test_install_prints_each_override_note_once(tmp_path: Path, text: str, note: str, skipped: int) -> None:
    # Contracts §10.4 (#89): every failing request re-applies the overrides to all the findings so
    # far. The overridden package comes first, so without `said` the second request repeats its note.
    overrides = tmp_path / "home" / ".config" / "ssc-guardian" / "overrides.toml"
    overrides.parent.mkdir(parents=True)
    overrides.write_text(text)
    target = venv(tmp_path)
    before = tree(target)
    runner = FakePip()
    code, result, err = run(handler(tmp_path, runner, Feeds(kev_status=503)), target, "demo==1.0", "helper==3.0")
    lines = err.splitlines()
    assert sum(note in line for line in lines) == 1
    assert sum("demo==1.0 fails a rule" in line for line in lines) == 1
    assert sum("helper==3.0 fails a rule" in line for line in lines) == 1
    assert len(result["skipped"]) == skipped
    assert code == 1
    assert runner.checks == [] and runner.installs == []
    assert tree(target) == before


BOTH_OVERRIDES = ONE_OVERRIDE + ONE_OVERRIDE.removeprefix("format = 1\n").replace(
    "CVE-2026-1111", "GHSA-9wx4-h78v-vm56"
)
BOTH_IDS = {"CVE-2026-1111", "GHSA-9wx4-h78v-vm56"}
MAC = policy.Host((14, 0), "arm64")
WINDOWS_ONLY = "cp314-cp314-win_amd64"


@dataclass
class FitFeeds(Feeds):
    """demo 1.0 as a universal wheel; its fixes, 1.1 and 2.0, only as ``tag`` under ``requires``.
    All three are past the cooldown."""

    tag: str = "py3-none-any"
    requires: str | None = None

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        if not url.startswith(pypi.SIMPLE_URL) or url.split("/")[4] != "demo":
            return super().__call__(request, timeout, limit)
        names = {"1.0": "demo-1.0-py3-none-any.whl"} | {v: f"demo-{v}-{self.tag}.whl" for v in ("1.1", "2.0")}
        files: list[dict[str, Any]] = [
            {
                "filename": name,
                "url": f"{FILES}/packages/ab/{name}",
                "hashes": {"sha256": sha("demo", version)},
                "upload-time": OLD,
            }
            for version, name in names.items()
        ]
        for file in files[1:]:
            file["requires-python"] = self.requires
        page = {"meta": {"api-version": "1.4"}, "name": "demo", "files": files, "versions": list(names)}
        return Response(200, {}, json.dumps(page).encode(), url)


def overridden(tmp_path: Path) -> None:
    overrides = tmp_path / "home" / ".config" / "ssc-guardian" / "overrides.toml"
    overrides.parent.mkdir(parents=True, exist_ok=True)
    overrides.write_text(BOTH_OVERRIDES)


def references(entries: list[dict[str, Any]]) -> set[str]:
    return {entry["reference"] for entry in entries}


@pytest.mark.parametrize(
    ("tag", "requires"),
    [
        (WINDOWS_ONLY, ">=3.14"),
        ("py3-none-any", ">=3.13"),
        ("cp312-cp312-win_amd64", None),
        ("cp312-cp312-macosx_15_0_arm64", None),  # newer than the injected host, whatever runs this
    ],
    ids=["the-issue", "python-only", "platform-only", "newer-macos"],
)
def test_override_survives_a_fix_that_cannot_install_in_the_venv(
    tmp_path: Path, tag: str, requires: str | None
) -> None:
    # Contracts §10.4 item 3 (#92): a fix pip refuses in this venv ends no override.
    overridden(tmp_path)
    runner = FakePip()
    install = handler(tmp_path, runner, FitFeeds(tag=tag, requires=requires), host=MAC)
    code, result, err = run(install, venv(tmp_path), "demo==1.0")
    assert code == 0, err
    assert references(result["overrides"]["applied"]) == BOTH_IDS
    assert result["overrides"]["expired"] == []
    assert runner.checks == [("demo==1.0",)] and len(runner.installs) == 1


def test_override_survives_for_a_dependency_pip_chose(tmp_path: Path) -> None:
    # The resolved set takes its own path to the overrides: demo was never requested.
    overridden(tmp_path)
    runner = FakePip(extra=[("demo", "1.0")])
    install = handler(tmp_path, runner, FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14"), host=MAC)
    code, result, err = run(install, venv(tmp_path), "helper==2.0")
    assert code == 0, err
    assert references(result["overrides"]["applied"]) == BOTH_IDS
    assert result["overrides"]["expired"] == []
    assert len(runner.installs) == 1


@pytest.mark.parametrize(
    ("tag", "host"),
    [("py3-none-any", None), ("cp312-cp312-macosx_11_0_arm64", MAC)],
    ids=["universal-wheel", "wheel-for-the-injected-host"],
)
def test_override_ends_on_a_fix_that_fits_the_venv(tmp_path: Path, tag: str, host: policy.Host | None) -> None:
    overridden(tmp_path)
    runner = FakePip()
    code, result, _ = run(handler(tmp_path, runner, FitFeeds(tag=tag), host=host), venv(tmp_path), "demo==1.0")
    assert code == 1
    assert references(result["overrides"]["expired"]) == BOTH_IDS
    assert result["overrides"]["applied"] == []
    assert runner.checks == [] and runner.installs == []


@pytest.mark.parametrize(
    ("tag", "requires"),
    [("unreadable", None), ("py3-none-any", "not a specifier")],
    ids=["wheel-name", "requires-python"],
)
def test_unreadable_wheel_name_is_no_fix_on_install(tmp_path: Path, tag: str, requires: str | None) -> None:
    # #72's rule: that file never fits, and that is no error. The name still gives its version,
    # so the file reaches the release and only the fit check can turn it down.
    assert pypi.wheel_tags("demo-1.1-unreadable.whl") is None
    assert pypi.file_version("demo", "demo-1.1-unreadable.whl") is not None
    overridden(tmp_path)
    runner = FakePip()
    install = handler(tmp_path, runner, FitFeeds(tag=tag, requires=requires), host=MAC)
    code, result, err = run(install, venv(tmp_path), "demo==1.0")
    assert code == 0, err
    assert references(result["overrides"]["applied"]) == BOTH_IDS
    assert result["overrides"]["expired"] == []
    assert runner.checks == [("demo==1.0",)] and len(runner.installs) == 1


@pytest.mark.parametrize(
    ("tag", "requires", "applied", "expired"),
    [(WINDOWS_ONLY, ">=3.14", BOTH_IDS, set()), ("py3-none-any", None, set(), BOTH_IDS)],
    ids=["fix-cannot-install", "fix-fits"],
)
def test_install_and_check_agree_on_an_override(
    tmp_path: Path, tag: str, requires: str | None, applied: set[str], expired: set[str]
) -> None:
    # One venv, one set of feeds, one overrides file, both commands (plan §2.4).
    overridden(tmp_path)
    config = tmp_path / "home" / ".config" / "ssc-guardian" / "config.toml"
    config.write_text("format = 1\n")
    prefix = tmp_path / "home" / "projects" / "app" / ".venv"
    site = make_venv(prefix, "3.12", home=tmp_path / "base" / "bin")
    link_interpreter(prefix, "3.12", tmp_path / "base" / "bin")
    add_dist(site, "demo", "1.0")
    feeds = FitFeeds(tag=tag, requires=requires)
    where = fake_mac(tmp_path)

    out, err = io.StringIO(), io.StringIO()
    client = Client(transport=feeds, sleep=lambda _: None)
    check = CheckEnvs(where.home, where.environ, where.root, TODAY, client, err, host=MAC)
    cli.main(
        ["check", "--envs", "--path", str(tmp_path / "home" / "projects"), "--json"],
        handlers={Verb.CHECK: check},
        stdout=out,
        stderr=err,
    )
    checked = json.loads(out.getvalue())["overrides"]

    install = Install(**{**handler(tmp_path, FakePip(), feeds, host=MAC).__dict__, "root": where.root})
    _, result, _ = run(install, prefix, "demo==1.0")
    installed = result["overrides"]

    assert references(checked["applied"]) == references(installed["applied"]) == applied
    assert references(checked["expired"]) == references(installed["expired"]) == expired


def test_install_override_result_is_idempotent_on_re_run(tmp_path: Path) -> None:
    # A second venv starts as the first did; a re-run on it finds its package already in place.
    overridden(tmp_path)
    runner = FakePip()
    install = handler(tmp_path, runner, FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14"), host=MAC)
    first, second = venv(tmp_path / "first"), venv(tmp_path / "second")
    outcomes = []
    for target in (first, second, second):
        code, result, _ = run(install, target, "demo==1.0")
        outcomes.append((code, result["findings"], result["overrides"]))
    assert outcomes[0][0] == 0
    assert outcomes[0] == outcomes[1] == outcomes[2]
    assert len(runner.installs) == 2


def test_loose_request_is_bounded_by_the_newest_version_that_fits(tmp_path: Path) -> None:
    # A bound of 2.0 would name a version with no wheel for this venv (#92).
    runner = FakePip()
    feeds = FitFeeds(vulnerable={}, tag=WINDOWS_ONLY, requires=">=3.14")
    code, _, err = run(handler(tmp_path, runner, feeds, host=MAC), venv(tmp_path), "demo")
    assert code == 0, err
    assert runner.checks == [("demo<=1.0",)] and len(runner.installs) == 1


def took_demo_1_0() -> dict[str, Any]:
    """Pip's report when no wheel above demo 1.0 installs, whatever the bound."""
    entry = {
        "metadata": {"name": "demo", "version": "1.0"},
        "download_info": {
            "url": wheel_url("demo", "1.0"),
            "archive_info": {"hashes": {"sha256": sha("demo", "1.0")}},
        },
        "is_direct": False,
        "requested": True,
    }
    return {"version": "1", "install": [entry]}


def test_loose_request_names_no_fix_that_cannot_install(tmp_path: Path) -> None:
    # No passing version fits, so pip decides: it takes 1.0, and that fails with no fix to name.
    runner = FakePip(report=took_demo_1_0())
    feeds = FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    code, result, err = run(handler(tmp_path, runner, feeds, host=MAC), venv(tmp_path), "demo")
    assert code == 1
    assert runner.checks == [("demo<=2.0",)] and runner.installs == []
    (finding,) = result["findings"]
    assert (finding["rule"], finding["version"]) == ("known-vulnerability", "1.0")
    assert not [o for o in finding["options"] if o["kind"] == "replace"]
    assert "demo 1.0 fails known-vulnerability" in err


def test_loose_request_keeps_an_override_when_the_fix_cannot_install(tmp_path: Path) -> None:
    # The same outcome as `demo==1.0`: the version pip takes reaches the overrides.
    overridden(tmp_path)
    runner = FakePip(report=took_demo_1_0())
    feeds = FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    code, result, err = run(handler(tmp_path, runner, feeds, host=MAC), venv(tmp_path), "demo")
    assert code == 0, err
    assert references(result["overrides"]["applied"]) == BOTH_IDS
    assert result["overrides"]["expired"] == []
    assert len(runner.installs) == 1


def test_loose_request_lets_pip_take_a_fix_that_reads_as_no_fit(tmp_path: Path) -> None:
    # A 3.12.4 venv reads as 3.12.0, so `>=3.12.1` says no fit though pip installs the fix.
    runner = FakePip()
    feeds = FitFeeds(requires=">=3.12.1")
    code, _, err = run(handler(tmp_path, runner, feeds, host=MAC), venv(tmp_path), "demo")
    assert code == 0, err
    assert runner.checks == [("demo<=2.0",)]
    assert [f.item.version for f in runner.installs[0]] == ["2.0"]


# --- a requested package pip leaves in place (#228) ---------------------------------------

EMPTY_REPORT: dict[str, Any] = {"version": "1", "install": []}


def site_of(target: Path) -> Path:
    return target / "lib" / "python3.12" / "site-packages"


def test_loose_request_checks_installed_version_when_pip_keeps_it(tmp_path: Path) -> None:
    # The audit's RR2: demo 1.0 (vulnerable) is installed and its fixes ship only wheels for
    # another platform, so pip keeps 1.0 for `demo<=2.0` and its report is empty. The version
    # the request ends with is 1.0, and it fails a rule: exit 1, nothing installed.
    target = venv(tmp_path)
    add_dist(site_of(target), "demo", "1.0")
    before = tree(target)
    runner = FakePip(report=EMPTY_REPORT)
    feeds = FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    code, result, err = run(handler(tmp_path, runner, feeds, host=MAC), target, "demo")
    assert code == 1, err
    assert runner.checks == [("demo<=2.0",)] and runner.installs == []
    assert [(f["rule"], f["item"], f["version"]) for f in result["findings"]] == [
        ("known-vulnerability", "demo", "1.0")
    ]
    assert "demo 1.0 fails known-vulnerability (installed; pip keeps it for this request" in err
    assert "Nothing to install" not in err and "refused; nothing installed." in err
    assert tree(target) == before


def test_loose_request_installed_version_passing_exits_zero(tmp_path: Path) -> None:
    # Edge case: demo 1.1 is installed and passes; pip keeps it, so there is nothing to install.
    target = venv(tmp_path)
    add_dist(site_of(target), "demo", "1.1")
    before = tree(target)
    runner = FakePip()
    code, result, err = run(handler(tmp_path, runner), target, "demo")
    assert code == 0, err
    assert runner.checks == [("demo<=1.1",)] and runner.installs == []
    assert result["findings"] == [] and result["skipped"] == []
    assert "Nothing to install: every requested package is already in place." in err
    assert tree(target) == before


def _two_records(site: Path) -> None:
    add_dist(site, "demo", "1.0")
    add_dist(site, "demo", "1.1")


def _unreadable_record(site: Path) -> None:
    (site / "demo-1.1.dist-info").mkdir(parents=True)  # no METADATA


@pytest.mark.parametrize(
    ("make", "case", "said"),
    [
        (lambda site: None, refuses("install.kept-not-installed"), "has no record of it"),
        (_two_records, refuses("install.kept-recorded-twice"), "demo is recorded 2 times where"),
        (
            _unreadable_record,
            refuses("install.kept-record-unreadable"),
            "demo-1.1.dist-info: FileNotFoundError), so the installed version of demo cannot be told",
        ),
    ],
    ids=["not-installed", "recorded-twice", "unreadable"],
)
def test_kept_version_that_cannot_be_read_leaves_the_check_unfinished(
    tmp_path: Path, make: Callable[[Path], None], case: Any, said: str
) -> None:
    # Fail-closed: pip's report is empty, but the installed version cannot be told, so the run
    # cannot finish (exit 2, nothing installed), never "Nothing to install" with exit 0.
    target = venv(tmp_path)
    make(site_of(target))
    before = tree(target)
    runner = FakePip(report=EMPTY_REPORT)
    with case:
        code, result, err = run(handler(tmp_path, runner), target, "demo")
    assert code == 2, err
    assert result["findings"] == []
    assert result["skipped"][0]["reason"] == "check-error"
    assert said in err and "; nothing installed." in err
    assert "Nothing to install" not in err
    assert runner.installs == []
    assert tree(target) == before


def test_kept_version_failing_a_rule_wins_over_one_that_cannot_be_read(tmp_path: Path) -> None:
    # 1 wins over 2 (contracts §3): demo 1.0 is kept and fails; helper is kept but not installed.
    target = venv(tmp_path)
    add_dist(site_of(target), "demo", "1.0")
    runner = FakePip(report=EMPTY_REPORT)
    feeds = FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    with refuses("install.kept-not-installed"):
        code, result, err = run(handler(tmp_path, runner, feeds, host=MAC), target, "demo", "helper")
    assert code == 1, err
    assert [(f["rule"], f["version"]) for f in result["findings"]] == [("known-vulnerability", "1.0")]
    assert result["skipped"][0]["reason"] == "check-error"
    assert "pip installs nothing for helper" in err
    assert runner.installs == []


def test_kept_version_reads_the_per_user_folder(tmp_path: Path) -> None:
    # pip's check step (-I) does not see the per-user folder, but the venv's Python reads it
    # before its base's: a copy there could be the one imported, so it counts as a second
    # record (exit 2). Without one, the base's copy is the version kept.
    main, user, base = (tmp_path / name for name in ("main", "user", "base"))
    for folder in (main, user, base):
        folder.mkdir()
    env = Environment(install_module.discovery.Source.VENV, str(tmp_path), (3, 12), str(main), str(user), str(base))
    wanted = (Requirement(Ecosystem.PYPI, "demo"),)
    add_dist(base, "demo", "1.1")
    assert install_module._kept(env, wanted, ()) == ([("demo", "1.1")], [], None)
    add_dist(user, "demo", "1.0")
    kept, problems, failure = install_module._kept(env, wanted, ())
    assert (kept, problems) == ([], [])
    assert isinstance(failure, RefusedError)
    assert f"demo is recorded 2 times where {tmp_path}'s Python reads packages" in str(failure)
    assert f"1.0 in {user}" in str(failure) and f"1.1 in {base}" in str(failure)


def test_kept_version_that_is_malformed_is_named_without_none(tmp_path: Path) -> None:
    # A kept record whose version is malformed is a malformed-name violation (exit 1); the
    # message names the package, never "None" for the value the finding leaves out.
    target = venv(tmp_path)
    add_dist(site_of(target), "demo", "not-a-version")
    runner = FakePip(report=EMPTY_REPORT)
    code, result, err = run(handler(tmp_path, runner), target, "demo")
    assert code == 1, err
    assert [(f["rule"], f["malformed_field"]) for f in result["findings"]] == [("malformed-name", "version")]
    assert "demo fails malformed-name (installed; pip keeps it for this request" in err
    assert "None" not in err
    assert runner.installs == []


def test_install_is_idempotent_on_re_run(tmp_path: Path) -> None:
    # The first run installs demo 1.1; each later run finds it in place, checks it, writes nothing.
    target = venv(tmp_path)
    runner = FakePip()
    install = handler(tmp_path, runner)
    code, _, err = run(install, target, "demo")
    assert code == 0, err
    assert len(runner.installs) == 1
    before = tree(target)
    outcomes = [run(install, target, "demo") for _ in range(2)]
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == 0 and "Nothing to install" in outcomes[0][2]
    assert len(runner.installs) == 1
    assert tree(target) == before


@dataclass
class QuarantinedFeeds(Feeds):
    """demo as PyPI shows a quarantined project: ``versions`` listed, ``files`` its files."""

    versions: Sequence[str] = ()
    files: Sequence[dict[str, Any]] = ()

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        if url != f"{pypi.SIMPLE_URL}demo/":
            return super().__call__(request, timeout, limit)
        page = {
            "meta": {"api-version": "1.4"},
            "name": "demo",
            "files": list(self.files),
            "versions": list(self.versions),
            "project-status": {"status": "quarantined"},
        }
        return Response(200, {}, json.dumps(page).encode(), url)


SDIST_ONLY = [
    {"filename": "demo-1.0.tar.gz", "url": sdist_url("demo", "1.0"), "hashes": {"sha256": sdist_sha("demo", "1.0")}}
]


@pytest.mark.parametrize(
    ("request_text", "versions", "files", "version"),
    [
        ("demo", (), (), None),  # PyPI lists nothing for a quarantined project
        ("demo", ("1.0",), (), None),  # a release with no files
        ("demo", ("1.0",), SDIST_ONLY, None),  # no released wheel
        ("demo==9.9", ("1.0",), (), "9.9"),  # an exact version PyPI does not list
    ],
    ids=["nothing-listed", "no-files", "sdist-only", "exact-not-listed"],
)
def test_quarantined_project_loose_request_is_a_compromise(
    tmp_path: Path, request_text: str, versions: tuple[str, ...], files: Any, version: str | None
) -> None:
    # The audit's RR3: a quarantined project is a compromise (exit 1) however it is requested,
    # found before any "no released wheel" or "no release" refusal (exit 2).
    target = venv(tmp_path)
    before = tree(target)
    runner = FakePip()
    feeds = QuarantinedFeeds(versions=versions, files=files)
    with refuses("policy.quarantined-project"):
        code, result, err = run(handler(tmp_path, runner, feeds), target, request_text)
    assert code == 1, err
    (finding,) = result["findings"]
    assert (finding["rule"], finding["item"], finding["version"]) == ("compromise", "demo", version)
    assert finding["labels"] == ["registry-quarantined"]
    assert not [o for o in finding["options"] if o["kind"] == "replace"]
    assert result["skipped"] == []
    assert "PyPI has quarantined demo; Guardian installs no version of it." in err
    assert "no released wheel" not in err and "no release" not in err
    assert runner.checks == [] and runner.installs == []
    assert tree(target) == before


def test_quarantined_project_exact_request_keeps_its_evaluation(tmp_path: Path) -> None:
    # An exact version PyPI lists is evaluated as before: the compromise, then its unknown age.
    runner = FakePip()
    feeds = QuarantinedFeeds(versions=("1.0",))
    with refuses("policy.compromise"):
        code, result, err = run(handler(tmp_path, runner, feeds), venv(tmp_path), "demo==1.0")
    assert code == 1, err
    assert [(f["rule"], f["labels"]) for f in result["findings"]] == [
        ("compromise", ["registry-quarantined"]),
        ("known-vulnerability", []),
    ]
    assert runner.checks == [] and runner.installs == []


def test_one_package_at_two_versions_is_malformed(tmp_path: Path) -> None:
    runner = FakePip()
    with refuses("install.requested-twice"):
        code, result, err = run(handler(tmp_path, runner), venv(tmp_path), "demo==1.1", "Demo==1.0")
    assert code == 1
    assert [(f["rule"], f["malformed_field"]) for f in result["findings"]] == [("malformed-name", "version")]
    assert "requested twice" in err
    assert runner.checks == [] and runner.installs == []


def test_pip_plugin_plan_install_refuses_a_non_venv(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    plugin = PipPlugin(Roots(str(tmp_path / "home"), {"PATH": ""}))
    with (
        refuses("install.guardian-installs-into-venvs-only"),
        pytest.raises(RefusedError, match="create a venv and install there"),
    ):
        plugin.plan_install(str(tmp_path), ())
    assert os.listdir(tmp_path / "home") == []


def test_pip_plugin_plan_install_refuses_a_local_path(tmp_path: Path) -> None:
    # The CLI refuses this request first, so only the plugin API reaches this check.
    (tmp_path / "home").mkdir()
    plugin = PipPlugin(Roots(str(tmp_path / "home"), {"PATH": ""}))
    with refuses("install.malformed-requirement-name"), pytest.raises(MalformedValueError, match="malformed pypi-name"):
        plugin.plan_install(str(venv(tmp_path)), (Requirement(Ecosystem.PYPI, "demo.zip"),))


def test_pip_plugin_plan_install_refuses_one_package_at_two_versions(tmp_path: Path) -> None:
    # The second spelling at another version is the malformed one; nothing is asked of pip.
    (tmp_path / "home").mkdir()
    plugin = PipPlugin(Roots(str(tmp_path / "home"), {"PATH": ""}))
    asked = (Requirement(Ecosystem.PYPI, "demo", "1.0"), Requirement(Ecosystem.PYPI, "Demo", "2.0"))
    with (
        refuses("install.malformed-requirement-version"),
        pytest.raises(MalformedValueError, match="malformed pep440-version") as raised,
    ):
        plugin.plan_install(str(venv(tmp_path)), asked)
    assert raised.value.value == "Demo==2.0"


def test_apple_python_is_refused_as_a_base_installation(tmp_path: Path) -> None:
    prefix = tmp_path / "Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9"
    make_venv(prefix, "3.9", home=tmp_path / "base" / "bin")
    with refuses("install.base-python-installation-not-venv"):
        assert "is a base Python installation, not a venv; create a venv" in refused(tmp_path, prefix)


class PyPIDown(Feeds):
    """Every feed answers but PyPI's page for demo."""

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        if url.startswith(f"{pypi.SIMPLE_URL}demo/"):
            return Response(500, {}, b"{}", url)
        return super().__call__(request, timeout, limit)


def test_pypi_that_cannot_be_read_is_a_feed_failure(tmp_path: Path) -> None:
    runner = FakePip()
    with refuses("install.pypi-not-read"):
        code, result, err = run(handler(tmp_path, runner, PyPIDown()), venv(tmp_path), "demo")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "feed-failure"
    assert "pypi.org answered HTTP 500 after 2 retries" in err
    assert runner.installs == []


def test_exact_version_pypi_does_not_have_is_refused(tmp_path: Path) -> None:
    runner = FakePip()
    with refuses("install.pypi-no-release"):
        code, result, err = run(handler(tmp_path, runner), venv(tmp_path), "demo==9.9")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert "PyPI has no release 9.9 of demo" in err
    assert runner.installs == []


# --- refusal text (#102) ------------------------------------------------------------------

NAMED_BELOW = "demo==1.0 fails a rule; the version that passes is named below."
SEE_BELOW = "No version of demo passes every rule today; see below for when one will."
NOTHING_INSTALLS = "No version of demo that passes every rule installs in this venv today."
NO_FIX = copy.deepcopy(ADVISORY)
NO_FIX["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]


@dataclass
class YoungFitFeeds(FitFeeds):
    """FitFeeds with 1.1 and 2.0 still in their cooldown."""

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        answer = super().__call__(request, timeout, limit)
        if not request.full_url.startswith(f"{pypi.SIMPLE_URL}demo/"):
            return answer
        page = json.loads(answer.body)
        for file in page["files"]:
            if not file["filename"].startswith("demo-1.0-"):
                file["upload-time"] = YOUNG
        return Response(answer.status, answer.headers, json.dumps(page).encode(), answer.url)


@dataclass
class NoShowableId(Feeds):
    """demo's advisory has no ID Guardian may show, so its only violation is ``malformed-name``."""

    vulnerable: dict[str, list[str]] = field(default_factory=lambda: {"demo": ["OSV-2026-1"]})

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        if url == "https://api.osv.dev/v1/vulns/OSV-2026-1":
            return Response(200, {}, json.dumps(ADVISORY | {"id": "OSV-2026-1", "aliases": []}).encode(), url)
        return super().__call__(request, timeout, limit)


def named(finding: dict[str, Any]) -> list[str]:
    return [o["version"] for o in finding["options"] if o["kind"] == "replace"]


def test_exact_refusal_with_a_fix_says_it_is_named_below(tmp_path: Path) -> None:
    with refuses("policy.known-vulnerability"):
        code, result, err = run(handler(tmp_path, FakePip()), venv(tmp_path), "demo==1.0")
    assert code == 1
    (finding,) = result["findings"]
    assert named(finding) == ["1.1", "2.0"]
    assert NAMED_BELOW in err
    assert NOTHING_INSTALLS not in err


def test_exact_refusal_with_a_fix_in_its_cooldown_says_it_is_named_below(tmp_path: Path) -> None:
    # A date names the version as surely as a command does.
    code, result, err = run(handler(tmp_path, FakePip(), YoungFitFeeds()), venv(tmp_path), "demo==1.0")
    assert code == 1
    (finding,) = result["findings"]
    assert named(finding) == ["2.0"]
    assert NAMED_BELOW in err
    assert NOTHING_INSTALLS not in err


@pytest.mark.parametrize(
    ("feeds", "host"),
    [(FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14"), MAC), (Feeds(advisory=NO_FIX), None)],
    ids=["fix-cannot-install", "no-fix"],
)
def test_exact_refusal_with_no_installable_fix_names_nothing(
    tmp_path: Path, feeds: Feeds, host: policy.Host | None
) -> None:
    code, result, err = run(handler(tmp_path, FakePip(), feeds, host=host), venv(tmp_path), "demo==1.0")
    assert code == 1
    (finding,) = result["findings"]
    assert named(finding) == []
    assert NOTHING_INSTALLS in err
    assert "named below" not in err


def test_loose_refusal_with_a_fix_in_its_cooldown_says_when(tmp_path: Path) -> None:
    code, result, err = run(handler(tmp_path, FakePip(), YoungFitFeeds()), venv(tmp_path), "demo")
    assert code == 1
    (finding,) = result["findings"]
    assert (finding["rule"], finding["version"]) == ("cooldown", "2.0")
    assert named(finding) == ["1.1"]
    assert SEE_BELOW in err
    assert NOTHING_INSTALLS not in err


def test_loose_refusal_with_no_installable_fix_promises_no_date(tmp_path: Path) -> None:
    runner = FakePip()
    feeds = YoungFitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    code, result, err = run(handler(tmp_path, runner, feeds, host=MAC), venv(tmp_path), "demo")
    assert code == 1
    assert runner.checks == []
    assert [(f["rule"], f["version"]) for f in result["findings"]] == [("cooldown", "2.0")]
    assert named(result["findings"][0]) == []
    assert NOTHING_INSTALLS in err
    assert "see below" not in err


def test_dependency_refusal_with_a_fix_points_below(tmp_path: Path) -> None:
    code, result, err = run(handler(tmp_path, FakePip(extra=[("helper", "3.0")])), venv(tmp_path), "demo==1.1")
    assert code == 1
    (finding,) = result["findings"]
    assert named(finding) == ["2.0"]
    who = "a dependency pip chose for this request; install a version named below, then run again"
    assert f"helper 3.0 fails cooldown ({who})." in err


def test_dependency_refusal_without_a_fix_does_not_point_below(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(UPLOADS, "helper", {"3.0": YOUNG})
    runner = FakePip(extra=[("helper", "3.0")])
    code, result, err = run(handler(tmp_path, runner), venv(tmp_path), "demo==1.1")
    assert code == 1
    assert runner.installs == []
    (finding,) = result["findings"]
    assert (finding["item"], finding["version"]) == ("helper", "3.0")
    assert named(finding) == []
    assert "helper 3.0 fails cooldown (a dependency pip chose for this request)." in err
    assert "named below" not in err


def test_refusal_text_changes_no_exit_code_or_json(tmp_path: Path) -> None:
    feeds = FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    code, result, _ = run(handler(tmp_path, FakePip(), feeds, host=MAC), venv(tmp_path), "demo==1.0")
    assert code == result["exit_code"] == 1
    assert result["format_version"] == "1.0"
    (finding,) = result["findings"]
    assert (finding["rule"], finding["item"], finding["version"]) == ("known-vulnerability", "demo", "1.0")
    assert [o["kind"] for o in finding["options"]] == ["remove", "exception"]


def test_refusal_text_is_idempotent_on_re_run(tmp_path: Path) -> None:
    target = venv(tmp_path)
    feeds = FitFeeds(tag=WINDOWS_ONLY, requires=">=3.14")
    first = run(handler(tmp_path, FakePip(), feeds, host=MAC), target, "demo==1.0")
    second = run(handler(tmp_path, FakePip(), feeds, host=MAC), target, "demo==1.0")
    assert first == second
    assert first[2].count(NOTHING_INSTALLS) == 1


@pytest.mark.parametrize(
    ("tag", "requires"),
    [("unreadable", None), ("py3-none-any", "not a specifier")],
    ids=["wheel-name", "requires-python"],
)
def test_unreadable_wheel_refusal_says_nothing_installs(tmp_path: Path, tag: str, requires: str | None) -> None:
    feeds = FitFeeds(tag=tag, requires=requires)
    code, result, err = run(handler(tmp_path, FakePip(), feeds, host=MAC), venv(tmp_path), "demo==1.0")
    assert code == 1
    (finding,) = result["findings"]
    assert named(finding) == []
    assert NOTHING_INSTALLS in err
    assert "named below" not in err


@pytest.mark.parametrize("request_text", ["demo", "demo==1.0"], ids=["loose", "exact"])
def test_refusal_of_a_release_in_its_cooldown_says_today(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request_text: str
) -> None:
    # The only release fits and passes in days: the venv is not what stands in the way.
    monkeypatch.setitem(UPLOADS, "demo", {"1.0": YOUNG})
    code, result, err = run(handler(tmp_path, FakePip(), Feeds(vulnerable={})), venv(tmp_path), request_text)
    assert code == 1
    (finding,) = result["findings"]
    assert (finding["rule"], named(finding)) == ("cooldown", [])
    assert NOTHING_INSTALLS in err


def test_malformed_refusal_claims_nothing_about_other_versions(tmp_path: Path) -> None:
    target = venv(tmp_path)
    code, result, err = run(handler(tmp_path, FakePip(), NoShowableId()), target, "demo==1.0")
    assert code == 1
    (finding,) = result["findings"]
    assert (finding["rule"], finding["options"]) == ("malformed-name", [])
    assert "demo==1.0 fails a rule." in err
    assert NOTHING_INSTALLS not in err
    assert "named below" not in err
    # The claim it does not make would be false: the next version installs on the same feeds.
    code, _, err = run(handler(tmp_path, FakePip(), NoShowableId()), target, "demo==1.1")
    assert code == 0, err


def test_each_request_is_told_about_its_own_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # demo's named fix says nothing for helper, which has none.
    monkeypatch.setitem(UPLOADS, "helper", {"3.0": YOUNG})
    code, _, err = run(handler(tmp_path, FakePip()), venv(tmp_path), "demo==1.0", "helper==3.0")
    assert code == 1
    assert NAMED_BELOW in err
    assert "No version of helper that passes every rule installs in this venv today." in err


def test_each_dependency_is_told_about_its_own_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # helper's named fix says nothing for other, which has none.
    monkeypatch.setitem(UPLOADS, "other", {"1.0": YOUNG})
    runner = FakePip(extra=[("helper", "3.0"), ("other", "1.0")])
    code, _, err = run(handler(tmp_path, runner), venv(tmp_path), "demo==1.1")
    assert code == 1
    who = "a dependency pip chose for this request; install a version named below, then run again"
    assert f"helper 3.0 fails cooldown ({who})." in err
    assert "other 1.0 fails cooldown (a dependency pip chose for this request)." in err


# --- each value is stripped as it goes into a message (#161) ------------------------------

FORGED = "%0Aforged.whl"  # decodes to a line break, then a name of its own


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@dataclass
class Renamed(Feeds):
    """PyPI's page names demo 1.1's wheel ``demo-1.1-py3-none-any.whl`` and then ``tail``,
    decoded, at a URL ending in ``tail`` as given; ``uploaded`` is that wheel's upload time
    (None: PyPI gives none). The sdists keep the release's own date."""

    tail: str = FORGED
    uploaded: str | None = OLD
    sdists: bool = True

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        answer = super().__call__(request, timeout, limit)
        if not request.full_url.startswith(f"{pypi.SIMPLE_URL}demo/"):
            return answer
        page = json.loads(answer.body)
        for entry in page["files"]:
            if entry["filename"] == "demo-1.1-py3-none-any.whl":
                entry["filename"] += urllib.parse.unquote(self.tail)
                entry["url"] += self.tail
                entry.pop("upload-time")
                if self.uploaded is not None:
                    entry["upload-time"] = self.uploaded
        return Response(answer.status, answer.headers, json.dumps(page).encode(), answer.url)


def renamed(tmp_path: Path, tail: str = FORGED, uploaded: str | None = OLD) -> tuple[Install, FakePip]:
    """The handler and runner for demo==1.1, pip's report naming the renamed wheel's URL."""
    runner = FakePip(urls={"demo": wheel_url("demo", "1.1") + tail})
    install = handler(tmp_path, runner, Renamed(tail=tail, uploaded=uploaded))
    return Install(**{**install.__dict__, "stdin": _Terminal("n\n")}), runner


def change_lines(err: str, target: Path) -> list[str]:
    """The header of the change shown for confirmation, and the line after it."""
    lines = err.splitlines()
    start = lines.index(f"Guardian will install into {target} exactly these files, each bound to PyPI's SHA-256:")
    return lines[start : start + 2]


@pytest.mark.parametrize("yes", [False, True], ids=["prompt", "yes-record"])
def test_file_name_with_an_encoded_line_break_is_one_line(tmp_path: Path, yes: bool) -> None:
    install, runner = renamed(tmp_path)
    target = venv(tmp_path)
    code, result, err = run(install, target, "demo==1.1", yes=yes)
    # The file name is one value on the file's own line; the line Guardian writes before it stays.
    file_line = f"  demo 1.1  demo-1.1-py3-none-any.whlforged.whl  sha256:{sha('demo', '1.1')}"
    assert change_lines(err, target)[1] == file_line
    assert not any(line.startswith("forged.whl") for line in err.splitlines())
    # Nothing else changes: the exit code, the JSON and what is installed are as before.
    assert code == (0 if yes else 2) and result["findings"] == []
    assert [[f.url for f in files] for files in runner.installs] == (
        [[wheel_url("demo", "1.1") + FORGED]] if yes else []
    )


def test_file_name_with_an_encoded_line_separator_is_one_line(tmp_path: Path) -> None:
    tail = "%E2%80%A8forged.whl"  # U+2028, which str.splitlines() also ends a line on
    install, runner = renamed(tmp_path, tail)
    target = venv(tmp_path)
    code, _, err = run(install, target, "demo==1.1", yes=False)
    assert code == 2 and runner.installs == []
    file_line = f"  demo 1.1  demo-1.1-py3-none-any.whlforged.whl  sha256:{sha('demo', '1.1')}"
    assert change_lines(err, target)[1] == file_line
    assert "\u2028" not in err and not any(line.startswith("forged.whl") for line in err.splitlines())


@pytest.mark.parametrize("uploaded", [None, YOUNG], ids=["unknown-age", "cooldown"])
def test_cooldown_message_strips_the_file_name(tmp_path: Path, uploaded: str | None) -> None:
    install, runner = renamed(tmp_path, uploaded=uploaded)
    target = venv(tmp_path)
    if uploaded is None:
        with refuses("install.bound-file-unknown-age"):
            code, result, err = run(install, target, "demo==1.1")
        said = "demo 1.1: PyPI gives no upload time for demo-1.1-py3-none-any.whlforged.whl, so its age is unknown."
        assert (code, result["skipped"][0]["reason"]) == (2, "unknown-age")
    else:
        code, result, err = run(install, target, "demo==1.1")
        said = (
            "demo 1.1: demo-1.1-py3-none-any.whlforged.whl, the file pip chose, was uploaded on 2026-11-01: "
            "inside its 21-day cooldown, eligible on "
        )
        assert (code, [f["rule"] for f in result["findings"]]) == (1, ["cooldown"])
    lines = err.splitlines()
    assert any(line.startswith(said) for line in lines), err
    assert not any(line.startswith("forged.whl") for line in lines)
    assert runner.installs == []


# --- a control character in a stripped value never reaches output (#228, L4-18) ------------

CONTROLS = "\x1b\x07\u202e\u2028"  # an escape, a bell, a right-to-left override, a line separator


@dataclass
class BrokenPip(FakePip):
    """The install step stops with a message that holds control characters."""

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        self.installs.append(tuple(files))
        raise OSError("disk\x1b[2J full\x07\u202e\u2028written: everything")


def test_install_step_message_is_stripped(tmp_path: Path) -> None:
    # The exception's text is stripped as it goes into the message (#228, L4-18): its line
    # separator cannot add a line that reads as Guardian's own ("written: everything"), and no
    # control reaches stderr. Without that strip, the message splits into two lines.
    runner = BrokenPip()
    target = venv(tmp_path)
    with refuses("install.not-installed"):
        code, result, err = run(handler(tmp_path, runner), target, "demo==1.1")
    assert code == 2, err
    assert result["skipped"][0]["reason"] == "check-error"
    assert not set(CONTROLS) & set(err)
    said = f"ssc-guardian: {target}: disk[2J fullwritten: everything; written: nothing; removed: nothing."
    assert said in err.splitlines()


def test_venv_path_with_a_control_character_never_reaches_output(tmp_path: Path) -> None:
    # The venv's path is stripped where the change, an install failure and the installed line
    # name it; before any of them, the path grammar refuses it (Collector.check, as the command
    # line's own gate does), so the handler, called directly, prints none of its controls.
    target = venv(tmp_path / "app\x1b[2J\u202e")
    runner = FakePip()
    err = io.StringIO()
    install = Install(**{**handler(tmp_path, runner).__dict__, "stderr": err})
    request = cli.Request(
        Verb.INSTALL, venv=str(target), requirements=(Requirement(Ecosystem.PYPI, "demo", "1.1"),), yes=True
    )
    with refuses("findings.malformed-place"):
        result = install(request)
    assert int(result.exit_code) == 1
    assert [(f.rule.value, f.malformed_field) for f in result.findings] == [("malformed-name", "place")]
    assert not set(CONTROLS) & set(err.getvalue())
    assert runner.checks == [] and runner.installs == []
