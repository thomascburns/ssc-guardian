# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``install`` and ``check --envs`` on one venv: an override ends only on a fix that installs in
that venv (issue #92; plan §2.4, contracts §10.4 item 3).

The feeds answer from ``test_check_envs``'s local fixture server through the real client; a
fake runner stands in for pip. requests 2.31.0 is already in the venv, so pip's report is empty
and nothing is bound: what differs is only the override decision.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, policy
from ssc_guardian.commands.install import Install
from ssc_guardian.findings import Verb
from ssc_guardian.net import Client
from tests.integration import test_check_envs as server
from tests.integration.test_check_envs import (
    PAGES,
    TODAY,
    _check,
    _config,
    _fix_page,
    _override_requests,
    _protect,
    _wheel,
)
from tests.unit.test_discovery import add_dist, make_venv
from tests.unit.test_install import FakePip, link_interpreter

pytestmark = pytest.mark.integration

client = server.client


def _venv(tmp_path: Path) -> Path:
    """One venv both handlers accept: under ``~/projects`` for discovery, with the interpreter
    link ``install`` asks for."""
    prefix = tmp_path / "home" / "projects" / "app" / ".venv"
    home = tmp_path / "base" / "bin"
    site = make_venv(prefix, "3.12", home=home)
    link_interpreter(prefix, "3.12", home)
    add_dist(site, "pip", "26.2.1")
    add_dist(site, "requests", "2.31.0")
    return prefix


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _install(
    tmp_path: Path,
    client: Client,
    prefix: Path,
    runner: FakePip,
    *,
    package: str = "requests==2.31.0",
    answer: str = "",
) -> tuple[int, dict[str, Any], str]:
    """``install --yes PACKAGE``, or, given an ``answer``, without ``--yes`` at a terminal that gives it."""
    out, err = io.StringIO(), io.StringIO()
    handler = Install(
        home=str(tmp_path / "home"),
        environ={"PATH": ""},
        root=str(tmp_path / "root"),
        today=TODAY,
        client=client,
        stdin=_Terminal(answer) if answer else io.StringIO(),
        stderr=err,
        runner=runner,
        host=policy.Host((14, 0), "arm64"),
    )
    argv = ["install", "--venv", str(prefix), "--json", *([] if answer else ["--yes"]), package]
    code = cli.main(argv, handlers={Verb.INSTALL: handler}, stdout=out, stderr=err)
    return code, json.loads(out.getvalue()), err.getvalue()


def _scene(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tag: str, requires_python: str | None) -> Path:
    monkeypatch.setitem(PAGES, "requests", _fix_page(tag, requires_python))
    _config(tmp_path)
    prefix = _venv(tmp_path)
    _protect(tmp_path)
    _override_requests(tmp_path)
    return prefix


def test_install_keeps_an_override_when_the_fix_cannot_install(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = _scene(tmp_path, monkeypatch, "cp314-cp314-win_amd64", ">=3.14")
    code, doc, _ = _check(tmp_path, client)
    assert {"ecosystem": "pypi", "place": str(prefix.resolve())} in doc["checked"]  # discovery surveyed it
    assert code == 0, doc
    assert len(doc["overrides"]["applied"]) == 2 and doc["overrides"]["expired"] == []

    runner = FakePip()
    code, result, err = _install(tmp_path, client, prefix, runner)
    assert code == 0, err
    assert "Nothing to install" in err
    assert result["findings"] == []
    assert len(result["overrides"]["applied"]) == 2 and result["overrides"]["expired"] == []
    assert runner.checks == [("requests==2.31.0",)] and runner.installs == []


def test_install_ends_an_override_on_a_fix_that_fits(
    tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The host and the venv's Python reach the search: a real fix ends it for both commands.
    prefix = _scene(tmp_path, monkeypatch, "cp312-cp312-macosx_11_0_arm64", ">=3.12")
    code, doc, _ = _check(tmp_path, client)
    assert code == 1
    assert len(doc["overrides"]["expired"]) == 2 and doc["overrides"]["applied"] == []

    runner = FakePip()
    code, result, _ = _install(tmp_path, client, prefix, runner)
    assert code == 1
    assert len(result["overrides"]["expired"]) == 2 and result["overrides"]["applied"] == []
    assert runner.checks == [] and runner.installs == []


def test_install_prompt_strips_pypi_file_name(tmp_path: Path, client: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    # PyPI's page, from the local server, names idna 3.7's wheel with an encoded line break in
    # its URL; pip's report names the same URL. The prompt shows the name on the file's own line
    # (#161); nothing is installed on a "no", and nothing reaches the network.
    tail = "%0Aforged.whl"
    url = f"https://files.pythonhosted.org/packages/ab/idna-3.7-py3-none-any.whl{tail}"
    wheel = {**_wheel("idna", "3.7"), "filename": "idna-3.7-py3-none-any.whl\nforged.whl", "url": url}
    monkeypatch.setitem(PAGES, "idna", {"meta": {"api-version": "1.4"}, "name": "idna", "files": [wheel]})
    prefix = _venv(tmp_path)
    runner = FakePip(urls={"idna": url}, digests={"idna": "ab" * 32})

    code, result, err = _install(tmp_path, client, prefix, runner, package="idna==3.7", answer="n\n")
    assert code == 2, err
    assert result["findings"] == [] and runner.installs == []
    lines = err.splitlines()
    head = lines.index(f"Guardian will install into {prefix} exactly these files, each bound to PyPI's SHA-256:")
    assert lines[head + 1] == f"  idna 3.7  idna-3.7-py3-none-any.whlforged.whl  sha256:{'ab' * 32}"
    assert lines[head + 2].startswith("Proceed? [y/N] ")
    assert not any(line.startswith("forged.whl") for line in lines)
