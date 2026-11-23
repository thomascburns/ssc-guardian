# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Shadow mode's command, the half of it this repository owns (issue #7, part 2b; plan §5).

``docs/shadow-mode.md`` fixes the command a calling repository runs beside today's gate. These
tests run that command on the real CLI: the exit set, the JSON, no stdin, the time bound and
the one-venv scoping. They do not cover the wrapper and its wiring, which belong to the
calling repository, or the install.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, net, policy
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.discovery import Roots
from ssc_guardian.feeds import github_advisories, kev, osv, pypi
from ssc_guardian.findings import Verb
from ssc_guardian.net import Client
from tests.unit.test_discovery import add_dist, fake_mac, make_venv
from tests.unit.test_net import Recorder, reply

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
BOUND = 60  # seconds; a subprocess held up by the closed proxy port ends in about 5
TODAY = date(2026, 11, 5)
OLD = "2023-05-22T15:12:44Z"  # past any cooldown
SENTINEL = b"SENTINEL"
RESULT_KEYS = {
    "format_version",
    "tool",
    "command",
    "exit_code",
    "summary",
    "findings",
    "checked",
    "skipped",
    "overrides",
}
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
UPLOADS = {"idna": ["3.7"], "requests": ["2.31.0", "2.32.3"], "onlyinb": ["1.0"]}


def _argv(venv: str) -> list[str]:
    """The command of ``docs/shadow-mode.md``, without the program's name."""
    return ["check", "--envs", "--ecosystem", "pypi", "--path", venv, "--json"]


def _venv(home: Path, name: str, *packages: tuple[str, str]) -> str:
    prefix = home / "projects" / name / ".venv"
    site = make_venv(prefix)
    for package, version in packages:
        add_dist(site, package, version)
    return os.path.realpath(prefix)


def _config(home: Path, text: str = "") -> None:
    folder = home / ".config" / "ssc-guardian"
    folder.mkdir(parents=True)
    (folder / "config.toml").write_text(f"format = 1\n{text}\n")


# --- the real program, as a subprocess ----------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """One way a shadow run ends without a feed answering (net.py allows five hosts, so a
    subprocess cannot reach a fixture server)."""

    config: str | None  # the text of config.toml, None for no file
    packages: tuple[tuple[str, str], ...]
    code: int
    rules: frozenset[str] = frozenset()
    skips: frozenset[str] = frozenset()
    checked: bool = True


OUTCOMES = {
    # #255: --path reaches the venv with no config.toml at all (no venv_folders needed).
    "no-config": Outcome(None, (("idna", "3.7"),), 2, skips=frozenset({"feed-failure"})),
    "feeds-unreachable": Outcome("", (("idna", "3.7"),), 2, skips=frozenset({"feed-failure"})),
    "violation": Outcome(
        'deny = ["pypi:idna"]',
        (("idna", "3.7"),),
        1,
        rules=frozenset({"deny-list"}),
        skips=frozenset({"feed-failure"}),
    ),
    "empty-venv": Outcome("", (), 0),
}


def _run_shadow(home: Path, venv: str) -> tuple[subprocess.CompletedProcess[str], float, bytes]:
    """The exact command, with the time it took and what it left unread on its stdin. The
    write end stays open, so a program that waits for the end of stdin runs into the bound."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    env.update({"PYTHONPATH": str(REPO / "src"), "HOME": str(home), "PATH": "/usr/bin:/bin"})
    argv = [sys.executable, "-m", "ssc_guardian", *_argv(venv)]
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, SENTINEL)
        started = time.monotonic()
        proc = subprocess.run(argv, stdin=read_end, capture_output=True, text=True, env=env, timeout=BOUND, check=False)
        elapsed = time.monotonic() - started
        os.set_blocking(read_end, False)
        return proc, elapsed, os.read(read_end, len(SENTINEL))
    finally:
        os.close(read_end)
        os.close(write_end)


@pytest.mark.parametrize("outcome", OUTCOMES.values(), ids=OUTCOMES.keys())
def test_shadow_mode_never_blocks_a_commit(tmp_path: Path, outcome: Outcome) -> None:
    """Every outcome reachable without a feed: one of the three exit codes, JSON 1.0 on stdout,
    within a bound and without reading stdin, so a caller that discards the status can be
    neither blocked nor hung. A vulnerable venv (exit 1 by advisory) and a clean venv with
    packages (exit 0) need feeds that answer: they run in-process in
    ``test_shadow_mode_checks_only_the_repository_venv``."""
    home = tmp_path.resolve() / "home"
    home.mkdir()
    venv = _venv(home, "example-repo", *outcome.packages)
    if outcome.config is not None:
        _config(home, outcome.config)

    proc, elapsed, unread = _run_shadow(home, venv)

    assert proc.returncode == outcome.code
    assert proc.returncode in {0, 1, 2}
    assert elapsed < BOUND
    assert unread == SENTINEL
    doc = json.loads(proc.stdout)
    assert set(doc) == RESULT_KEYS
    assert doc["format_version"] == "1.0"
    assert doc["exit_code"] == proc.returncode
    assert {f["rule"] for f in doc["findings"]} == outcome.rules
    assert {s["reason"] for s in doc["skipped"] if s["in_scope"]} == outcome.skips
    assert ({"ecosystem": "pypi", "place": venv} in doc["checked"]) is outcome.checked


def test_shadow_mode_without_config_still_checks_the_named_venv(tmp_path: Path) -> None:
    # #255: before, a venv named by --path outside every [scope] venv_folders entry (here: no
    # config.toml at all) was never walked, so the gate missed it (listed, exit 2). The named
    # path is now the walk itself: the venv is checked, and only the unreachable feeds keep the
    # run unfinished.
    home = tmp_path.resolve() / "home"
    home.mkdir()
    venv = _venv(home, "example-repo", ("idna", "3.7"))

    proc, _, _ = _run_shadow(home, venv)

    doc = json.loads(proc.stdout)
    skipped = {(s["ecosystem"], s["place"], s["reason"]) for s in doc["skipped"]}
    assert (None, venv, "check-error") not in skipped  # never missed
    assert {"ecosystem": "pypi", "place": venv} in doc["checked"]
    assert proc.returncode == doc["exit_code"] == 2 and {s[2] for s in skipped} >= {"feed-failure"}


# --- the real CLI in process, with feeds that answer --------------------------------


def _page(name: str) -> dict[str, Any]:
    files = [
        {
            "filename": f"{name}-{version}-py3-none-any.whl",
            "url": f"https://files.pythonhosted.org/packages/ab/{name}-{version}-py3-none-any.whl",
            "hashes": {"sha256": "ab" * 32},
            "upload-time": OLD,
        }
        for version in UPLOADS[name]
    ]
    return {"meta": {"api-version": "1.4"}, "name": name, "files": files, "versions": UPLOADS[name]}


def _feeds(*names: str) -> Recorder:
    """The feeds, routed for ``names`` alone. A page or advisory request for any other package
    is recorded, then raises; the OSV batch is one URL, so its body is what shows a name."""
    ordered = sorted(names)
    vulns = [[{"id": ADVISORY["id"]}] if name == "requests" else [] for name in ordered]
    recorder = Recorder()
    recorder.route(net.OSV_QUERYBATCH_URL, reply(body={"results": [{"vulns": found} for found in vulns]}))
    recorder.route(f"{osv.VULN_URL}{ADVISORY['id']}", reply(body=ADVISORY))
    recorder.route(github_advisories._url(ordered), reply(body=[]))
    recorder.route(kev.CATALOG_URL, reply(body={"count": 0, "vulnerabilities": []}))
    for name in ordered:
        recorder.route(f"{pypi.SIMPLE_URL}{name}/", reply(body=_page(name)))
    return recorder


class _NoStdin:
    """Stands for ``sys.stdin``: the check must never look at it."""

    def _refuse(self, *args: object) -> str:
        raise AssertionError("shadow mode must never read stdin")

    read = readline = isatty = _refuse


def _check(where: Roots, argv: list[str], recorder: Recorder) -> tuple[int, dict[str, Any]]:
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(
        where.home,
        where.environ,
        where.root,
        TODAY,
        Client(None, transport=recorder),
        err,
        host=policy.Host((14, 0), "arm64"),
    )
    code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err, environ=where.environ)
    return code, json.loads(out.getvalue())


def _named_in_a_request(recorder: Recorder, name: str) -> bool:
    return any(name in sent.url or name.encode() in (sent.body or b"") for sent in recorder.sent)


@pytest.mark.parametrize(
    ("packages", "code"),
    [
        pytest.param((("idna", "3.7"),), 0, id="clean"),
        pytest.param((("idna", "3.7"), ("requests", "2.31.0")), 1, id="vulnerable"),
    ],
)
def test_shadow_mode_checks_only_the_repository_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packages: tuple[tuple[str, str], ...], code: int
) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    _config(home)
    venv_a = _venv(home, "example-repo", *packages)
    venv_b = _venv(home, "other", ("onlyinb", "1.0"))
    names = [name for name, _ in packages]
    recorder = _feeds(*names)
    monkeypatch.setattr(sys, "stdin", _NoStdin())

    exit_code, doc = _check(where, _argv(venv_a), recorder)

    assert exit_code == doc["exit_code"] == code
    assert set(doc) == RESULT_KEYS
    assert doc["format_version"] == "1.0"
    places = [c["place"] for c in doc["checked"]] + [f["place"] for f in doc["findings"]]
    assert doc["checked"] != []
    assert all(place == venv_a or place.startswith(venv_a + "/") for place in places)
    assert not any(venv_b in json.dumps(entry) for entry in (doc["checked"], doc["findings"], doc["skipped"]))
    sent = {s.url for s in recorder.sent if s.url.startswith(pypi.SIMPLE_URL)}
    assert sent == {f"{pypi.SIMPLE_URL}{name}/" for name in names}
    assert not _named_in_a_request(recorder, "onlyinb")
    if code == 1:
        (finding,) = doc["findings"]
        assert (finding["rule"], finding["item"]) == ("known-vulnerability", "requests")
        (option,) = [o for o in finding["options"] if o["command"] is not None]
        assert option["command"] == ["ssc-guardian", "install", "--venv", venv_a, "requests==2.32.3"]


def test_naming_the_parent_folder_the_other_venv_reaches_the_feeds(tmp_path: Path) -> None:
    # The control: the same Mac and the same config. Naming only venv A with `--path` is what
    # keeps venv B's package out of the requests above, not a fake Mac on which it was never found:
    # named by its parent folder (the former venv folder, #255), venv B is read.
    where = fake_mac(tmp_path)
    home = Path(where.home)
    _config(home)
    _venv(home, "example-repo", ("idna", "3.7"))
    _venv(home, "other", ("onlyinb", "1.0"))
    recorder = _feeds("idna", "onlyinb")

    _check(where, ["check", "--envs", "--ecosystem", "pypi", "--path", str(home / "projects"), "--json"], recorder)

    assert _named_in_a_request(recorder, "onlyinb")
