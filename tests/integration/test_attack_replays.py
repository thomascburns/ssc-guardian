# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The 2026 supply-chain attacks, replayed against v1.0's controls (issue #196).

Four attacks, from public write-ups (owner session of 2026-11-11):

- **LiteLLM** 1.82.7 and 1.82.8, uploaded to PyPI with stolen credentials on 2026-03-24 from
  10:39 UTC; 1.82.8 added ``litellm_init.pth``, which runs at every interpreter start;
  PYSEC-2026-2. 1.82.6 is the last clean release. Stopped by the 21-day cooldown on the day, and
  by OSV's ``MAL-`` record after it.
- **Telnyx** 4.87.1 and 4.87.2, 2026-03-27, an import-time payload; PyPI quarantined the project
  (PEP 792). Stopped by the quarantine, past the cooldown too, with no replacement offered.
- **lightning** 2.6.2 and 2.6.3, 2026-04-30 (Mini Shai-Hulud, PyPI side), reached as a
  dependency of ``pyannote-audio``; 2.6.1 is the last clean release. Hidden from pip by the
  cooldown cutoff on the day; after it, the ``MAL-`` record refuses the whole request.
- **Trivy Action**, 2026-03-19: 76 of 77 ``aquasecurity/trivy-action`` tags force-pushed to
  commits that stole runner secrets; GHSA-69fq-xp46-6x23. A use by tag is a moving reference
  (T1); a commit pin is unaffected; ``pin`` of the moved tag waits out T2, then T6 refuses it.
  From the attack day, ``check --repo`` and ``pin`` both warn that the tag the lock file
  recorded now names another commit (``moved-release-tag``, #201). The workflow is
  ``tests/fixtures/actions/trivy-tag-hijack-2026.yml``, whose header says what is faithful and
  what is modelled.

**Clocks.** Every test fixes Guardian's clock (``today``) at the attack day or a stated number of
days after it, and every upload is dated on the attack's own day, so no outcome depends on the
wall-clock date.

**Modelled.** The time of day of each attack upload (LiteLLM 1.82.7 and 1.82.8 both at 10:39 UTC,
the write-ups' "from 10:39"; Telnyx and lightning at midnight UTC), the day GHSA-69fq-xp46-6x23
appears (the day after the Trivy attack), the clean releases' upload dates (only "older than the
cooldown" matters), the
projects' version lists, ``pyannote-audio``'s version, the payloads (``litellm_init.pth``
writes a marker file; the others carry none), and the OSV ``MAL-`` IDs, stand-ins numbered after
this issue. A quarantined project's page keeps its files, as the existing feed tests model it.

**Fakes.** Nothing reaches the network. The wheels are real (``build_wheel``), served through
``Index`` pages; the feeds answer in process, from this replay's own packages, since the existing
fakes serve fixed package sets. pip's two steps are ``ReplayPip``: its check step resolves as pip
does under ``--uploaded-prior-to``, and its install step unpacks each wheel into the venv,
``.pth`` files included, so an install the rules let through would plant the payload. Each
``install`` venv is a real one made by the Python running the suite, and is started after a
refusal to show the payload never ran; ``check --envs`` reads a venv's files only, so its venv is
made of files. GitHub is the in-process fixture of the Actions tests.
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
import tempfile
import urllib.request
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, policy
from ssc_guardian.cli import Request
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.install import Install
from ssc_guardian.commands.protect import Protect
from ssc_guardian.discovery import Environment
from ssc_guardian.feeds import github_advisories, osv, pypi
from ssc_guardian.feeds.kev import CATALOG_URL
from ssc_guardian.findings import ExitCode, Level, Result, Rule, Verb
from ssc_guardian.grammars import normalize_pypi_name
from ssc_guardian.lockfile import LOCK_FILE, LockEntry, load_lock
from ssc_guardian.net import OSV_QUERYBATCH_URL, PYPI_FILES, Client, Response
from ssc_guardian.pep440 import parse, parse_specifiers, satisfies_all
from ssc_guardian.plugin import AgeSource, PlannedFile
from tests.integration.test_install_venv import Index, build_wheel, new_venv, run
from tests.refusal_sites import Refuses, refuses
from tests.unit.test_discovery import add_dist, fake_mac, make_venv
from tests.unit.test_feeds import record
from tests.unit.test_nested_and_advisories import NODE_ACTION, Advisory, GitHub, listed, make_repo
from tests.unit.test_nested_and_advisories import check as check_repo
from tests.unit.test_pinning import ADVISORIES, github_routes, push, run_pin

pytestmark = pytest.mark.integration

COOLDOWN_DAYS = 21  # Guardian's default (settings.py Key.COOLDOWN_DAYS), written to the config
PAST_COOLDOWN = 31  # days after an attack: every attack file is past the cooldown by then
HOST = policy.Host((14, 0), "arm64")
FILES = f"https://{PYPI_FILES}/packages/ab"  # where PyPI's pages say each wheel is


def _after(day: date, days: int) -> date:
    return date.fromordinal(day.toordinal() + days)


# --- the attacks' packages --------------------------------------------------------------

LITELLM_DAY = date(2026, 3, 24)
LITELLM_UPLOAD = "2026-03-24T10:39:00Z"
TELNYX_DAY = date(2026, 3, 27)
TELNYX_UPLOAD = "2026-03-27T00:00:00Z"
LIGHTNING_DAY = date(2026, 4, 30)
LIGHTNING_UPLOAD = "2026-04-30T00:00:00Z"
OLD = "2025-06-01T00:00:00Z"

# (PyPI name, version, upload time, dependencies)
PACKAGES: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("litellm", "1.82.6", "2026-02-24T00:00:00Z", ()),
    ("litellm", "1.82.7", LITELLM_UPLOAD, ()),
    ("litellm", "1.82.8", LITELLM_UPLOAD, ()),
    ("telnyx", "4.87.0", "2026-03-01T00:00:00Z", ()),
    ("telnyx", "4.87.1", TELNYX_UPLOAD, ()),
    ("telnyx", "4.87.2", TELNYX_UPLOAD, ()),
    ("lightning", "2.6.1", "2026-04-01T00:00:00Z", ()),
    ("lightning", "2.6.2", LIGHTNING_UPLOAD, ()),
    ("lightning", "2.6.3", LIGHTNING_UPLOAD, ()),
    ("pyannote-audio", "3.3.2", OLD, ("lightning",)),
]
PTH = "litellm_init.pth"  # in litellm 1.82.8 only
LITELLM_MAL = record("MAL-2026-19601", aliases=("PYSEC-2026-2",), name="litellm", versions=["1.82.7", "1.82.8"])
LIGHTNING_MAL = record("MAL-2026-19602", name="lightning", versions=["2.6.2", "2.6.3"])


def _wheel_name(name: str, version: str) -> str:
    return f"{name.replace('-', '_')}-{version}-py3-none-any.whl"


def _add_file(wheel: Path, name: str, text: str) -> None:
    """Rewrite ``wheel`` with one more file at its root, and its RECORD made again to list it."""
    with zipfile.ZipFile(wheel) as archive:
        members = {i.filename: archive.read(i) for i in archive.infolist() if not i.filename.endswith("/RECORD")}
        (record_name,) = [n for n in archive.namelist() if n.endswith(".dist-info/RECORD")]
    members[name] = text.encode()
    lines = []
    with zipfile.ZipFile(wheel, "w") as archive:
        for member, data in members.items():
            archive.writestr(member, data)
            digest = hashlib.sha256(data).digest()
            lines.append(f"{member},sha256={_b64(digest)},{len(data)}")
        archive.writestr(record_name, "\n".join([*lines, f"{record_name},,"]) + "\n")


def _b64(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# --- the fakes ---------------------------------------------------------------------------


@dataclass
class Feeds:
    """OSV, GitHub's malware advisories, PyPI's Simple API and KEV, answered in process from the
    replay's index. ``records`` are the OSV records by PyPI name; ``quarantined`` the projects
    PyPI reports under PEP 792 quarantine."""

    index: Index
    records: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    quarantined: frozenset[str] = frozenset()

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        status = 404
        body: Any = {"message": "not found"}
        if url == OSV_QUERYBATCH_URL:
            assert isinstance(request.data, bytes)
            names = [q["package"]["name"] for q in json.loads(request.data)["queries"]]
            results = [{"vulns": [{"id": r["id"]} for r in self.records.get(n, [])]} for n in names]
            status, body = 200, {"results": results}
        elif url.startswith(osv.VULN_URL):
            found = [r for listed in self.records.values() for r in listed if osv.VULN_URL + r["id"] == url]
            if found:
                status, body = 200, found[0]
        elif url.startswith(github_advisories.ADVISORIES_URL):
            status, body = 200, []
        elif url.startswith(pypi.SIMPLE_URL) and url[len(pypi.SIMPLE_URL) :].rstrip("/") in self.index.wheels:
            name = url[len(pypi.SIMPLE_URL) :].rstrip("/")
            body = self.index.page(name, self.index.base)
            if name in self.quarantined:
                body["project-status"] = {"status": "quarantined"}
            status = 200
        elif url == CATALOG_URL:
            status, body = 200, {"count": 0, "vulnerabilities": []}
        return Response(status, {}, json.dumps(body).encode(), url)

    def client(self) -> Client:
        return Client(transport=self, timeout=5.0)


def _cutoff(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _uploaded(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@dataclass
class ReplayPip:
    """pip's two steps without pip, over the replay's packages.

    The check step resolves as pip does with ``--uploaded-prior-to``: each requirement, then each
    dependency, takes the newest version its specifiers allow among those uploaded before the
    cutoff; a package already in the venv at that version is left out of the report. The install
    step refuses a file whose SHA-256 is not the bound one (``--require-hashes``) and unpacks every
    member of each wheel into the venv's site-packages, ``.pth`` files included, as pip installs a
    purelib wheel."""

    index: Index
    checks: list[tuple[tuple[str, ...], str]] = field(default_factory=list)
    installs: list[tuple[tuple[str, str], ...]] = field(default_factory=list)

    def _choose(self, requirement: str, cutoff: datetime) -> tuple[str, str, tuple[str, ...]]:
        found = re.fullmatch(r"([A-Za-z0-9._-]+)(.*)", requirement)
        assert found is not None, requirement
        name, spec = normalize_pypi_name(found[1]), found[2].strip()
        specifiers = parse_specifiers(spec) if spec else ()
        allowed = [
            (parse(v), v, requires)
            for n, v, when, requires in PACKAGES
            if n == name and _uploaded(when) < cutoff and satisfies_all(parse(v), specifiers)
        ]
        assert allowed, f"pip finds no version of {requirement} uploaded before {cutoff}"
        _, version, requires = max(allowed)
        return name, version, requires

    def check(self, env: Environment, pins: Sequence[str], cutoff: str) -> object:
        self.checks.append((tuple(pins), cutoff))
        site = Path(env.main_site)
        chosen: dict[str, tuple[str, bool]] = {}
        pending = [(pin, True) for pin in pins]
        while pending:
            requirement, requested = pending.pop(0)
            name, version, requires = self._choose(requirement, _cutoff(cutoff))
            if name not in chosen:
                chosen[name] = (version, requested)
                pending += [(r, False) for r in requires]
        entries = []
        for name, (version, requested) in chosen.items():
            if (site / f"{name.replace('-', '_')}-{version}.dist-info").is_dir():
                continue
            filename = _wheel_name(name, version)
            entries.append(
                {
                    "metadata": {"name": name, "version": version},
                    "download_info": {
                        "url": f"{FILES}/{filename}",
                        "archive_info": {"hashes": {"sha256": self.index.digest(filename)}},
                    },
                    "is_direct": False,
                    "requested": requested,
                }
            )
        return {"version": "1", "install": entries}

    def install(self, env: Environment, files: Sequence[PlannedFile]) -> None:
        self.installs.append(tuple((f.item.name, f.item.version) for f in files))
        for planned in files:
            wheel = self.index.folder / planned.url.rsplit("/", 1)[1]
            assert hashlib.sha256(wheel.read_bytes()).hexdigest() == planned.digest  # --require-hashes
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(env.main_site)


@dataclass
class Replay:
    """One test's world: the wheels, the marker the LiteLLM payload writes, and the home folder."""

    index: Index
    marker: Path
    home: Path
    pip: ReplayPip = field(init=False)  # the runner the last install() made

    def install(self, today: date, records: dict[str, list[dict[str, Any]]] | None = None, **feeds: Any) -> Install:
        """``install`` with its clock at ``today``, the feeds holding ``records``, and a new
        ``ReplayPip`` (``self.pip``) standing in for the pinned pip."""
        self.pip = ReplayPip(self.index)
        return Install(
            home=str(self.home),
            environ={"PATH": ""},
            today=today,
            client=Feeds(self.index, records or {}, **feeds).client(),
            stdin=io.StringIO(),
            runner=self.pip,
            host=HOST,
        )

    def venv(self, name: str) -> Path:
        """A real venv made by the Python running the suite."""
        prefix = self.home / "projects" / name / ".venv"
        new_venv(sys.executable, prefix)
        return prefix

    def start(self, prefix: Path) -> None:
        """Start the venv's Python as any later use of it would: its .pth files run. ``-I`` keeps
        the developer's environment out and still runs the venv's site-packages .pth files."""
        subprocess.run([str(prefix / "bin" / "python"), "-I", "-c", "pass"], check=True, capture_output=True)


@pytest.fixture
def replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Replay:
    """The attacks' wheels in a folder of this test's own; litellm 1.82.8 carries
    ``litellm_init.pth``, which appends a line to the marker each time Python starts. Guardian's
    own temporary folders go under ``tmp_path`` too, so the test writes nothing outside it."""
    (tmp_path / "tmp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    folder = tmp_path / "wheels"
    folder.mkdir()
    marker = tmp_path / "litellm_init-ran"
    wheels: dict[str, list[tuple[str, str, str]]] = {}
    for name, version, uploaded, requires in PACKAGES:
        path = build_wheel(folder, name.replace("-", "_"), version, requires)
        if (name, version) == ("litellm", "1.82.8"):
            _add_file(path, PTH, f"import pathlib; pathlib.Path({str(marker)!r}).open('a').write('litellm_init\\n')\n")
        wheels.setdefault(name, []).append((path.name, hashlib.sha256(path.read_bytes()).hexdigest(), uploaded))
    home = tmp_path / "home"
    config = home / ".config" / "ssc-guardian" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(f"format = 1\n[defaults]\ncooldown_days = {COOLDOWN_DAYS}\n")
    return Replay(Index(FILES, folder, wheels), marker, home)


def snapshot(folder: Path) -> dict[str, str]:
    """Every path under ``folder`` and its SHA-256 (a link: its target; a folder: "dir")."""
    found: dict[str, str] = {}
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            found[str(path.relative_to(folder))] = "link:" + os.readlink(path)
        elif path.is_file():
            found[str(path.relative_to(folder))] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            found[str(path.relative_to(folder))] = "dir"
    return found


def site_of(prefix: Path) -> Path:
    (site,) = prefix.glob("lib/python3.*/site-packages")
    return site


def violations(result: dict[str, Any]) -> list[tuple[str, str, str | None]]:
    return [(f["rule"], f["item"], f["version"]) for f in result["findings"] if f["level"] == "violation"]


def replacements(finding: dict[str, Any]) -> list[tuple[str, list[str] | None]]:
    return [(o["version"], o["command"]) for o in finding["options"] if o["kind"] == "replace"]


# --- LiteLLM: the cooldown on the day, the MAL- record after it ---------------------------

# (clock, OSV records, the refusal that must fire, the rule); each case's refuses block is used once
LITELLM_CASES = [
    pytest.param(LITELLM_DAY, {}, refuses("policy.cooldown"), "cooldown", id="attack-day"),
    pytest.param(
        _after(LITELLM_DAY, PAST_COOLDOWN),
        {"litellm": [LITELLM_MAL]},
        refuses("policy.compromise"),
        "compromise",
        id="mal-record",
    ),
]


@pytest.mark.parametrize(("today", "records", "case", "rule"), LITELLM_CASES)
def test_litellm_exact_request_refused_and_pth_never_runs(
    replay: Replay, today: date, records: dict[str, list[dict[str, Any]]], case: Refuses, rule: str
) -> None:
    # Clock: the attack day (2026-03-24, 1.82.8 inside its cooldown, no MAL- record yet), or 31
    # days after it (past the cooldown, OSV's MAL- record names 1.82.7 and 1.82.8).
    prefix = replay.venv("app")
    before = snapshot(prefix)
    install = replay.install(today, records)
    with case:
        code, result, err = run(install, prefix, "litellm==1.82.8")
    assert code == result["exit_code"] == 1, err
    assert violations(result) == [(rule, "litellm", "1.82.8")]
    (finding,) = result["findings"]
    ready = ["ssc-guardian", "install", "--venv", str(prefix), "litellm==1.82.6"]
    assert replacements(finding)[0] == ("1.82.6", ready)  # the last clean release, with its command
    assert "litellm==1.82.8 fails a rule; the version that passes is named below." in err
    assert "ssc-guardian: refused; nothing installed." in err
    assert replay.pip.checks == [] and replay.pip.installs == []  # pip never ran

    # Data integrity: every path and digest in the venv as before, and the payload never ran.
    assert snapshot(prefix) == before
    assert not (site_of(prefix) / PTH).exists()
    replay.start(prefix)
    assert not replay.marker.exists()

    # The trap is live: the same wheel unpacked into another venv runs at interpreter start.
    control = replay.venv("control")
    with zipfile.ZipFile(replay.index.folder / _wheel_name("litellm", "1.82.8")) as archive:
        archive.extractall(site_of(control))
    replay.start(control)
    assert set(replay.marker.read_text().split()) == {"litellm_init"}


@pytest.mark.parametrize(
    ("today", "records"),
    [
        pytest.param(LITELLM_DAY, {}, id="attack-day"),
        pytest.param(_after(LITELLM_DAY, PAST_COOLDOWN), {"litellm": [LITELLM_MAL]}, id="mal-record"),
    ],
)
def test_litellm_loose_request_installs_last_clean_version(
    replay: Replay, today: date, records: dict[str, list[dict[str, Any]]]
) -> None:
    # Clock: as above. A request by name alone is handed to pip as litellm<=1.82.6, the newest
    # version that passes every rule, and installs it.
    prefix = replay.venv("app")
    code, result, err = run(replay.install(today, records), prefix, "litellm")
    assert code == result["exit_code"] == 0, err
    assert violations(result) == []
    assert [pins for pins, _ in replay.pip.checks] == [("litellm<=1.82.6",)]
    assert replay.pip.installs == [(("litellm", "1.82.6"),)]
    site_packages = site_of(prefix)
    assert (site_packages / "litellm.py").read_text() == "VERSION = '1.82.6'\n"
    assert not (site_packages / PTH).exists()
    replay.start(prefix)
    assert not replay.marker.exists()


# --- lightning, a dependency of pyannote-audio ---------------------------------------------


def test_lightning_young_release_is_hidden_from_pip(replay: Replay) -> None:
    # Clock: the attack day, 2026-04-30. pip's cutoff is 21 days earlier, so 2.6.2 and 2.6.3,
    # uploaded that day, are invisible to it: pyannote-audio installs with lightning 2.6.1.
    prefix = replay.venv("app")
    code, result, err = run(replay.install(LIGHTNING_DAY), prefix, "pyannote-audio")
    assert code == result["exit_code"] == 0, err
    assert replay.pip.checks == [(("pyannote-audio<=3.3.2",), "2026-04-09T00:00:00+00:00")]
    assert replay.pip.installs == [(("pyannote-audio", "3.3.2"), ("lightning", "2.6.1"))]
    assert (site_of(prefix) / "lightning.py").read_text() == "VERSION = '2.6.1'\n"


def test_lightning_transitive_dependency_refuses_whole_request(replay: Replay) -> None:
    # Clock: 31 days after the attack (2026-05-31). Past the cooldown, pip's cutoff no longer
    # hides 2.6.3, so pip chooses it for pyannote-audio; OSV's MAL- record names it, and the
    # whole request is refused, naming the dependency, the version, the rule and 2.6.1.
    prefix = replay.venv("app")
    before = snapshot(prefix)
    install = replay.install(_after(LIGHTNING_DAY, PAST_COOLDOWN), {"lightning": [LIGHTNING_MAL]})
    with refuses("policy.compromise"):
        code, result, err = run(install, prefix, "pyannote-audio")
    assert code == result["exit_code"] == 1, err
    assert [pins for pins, _ in replay.pip.checks] == [("pyannote-audio<=3.3.2",)]
    assert violations(result) == [("compromise", "lightning", "2.6.3")]
    (finding,) = result["findings"]
    assert finding["evidence"] == ["MAL-2026-19602"]
    assert replacements(finding) == [("2.6.1", ["ssc-guardian", "install", "--venv", str(prefix), "lightning==2.6.1"])]
    assert (
        "lightning 2.6.3 fails compromise (a dependency pip chose for this request; "
        "install a version named below, then run again)." in err
    )
    assert "A package that fails a rule refuses the whole request; there is no second resolve." in err
    assert replay.pip.installs == []  # neither pyannote-audio nor lightning
    assert snapshot(prefix) == before


# --- Telnyx: PyPI's quarantine ------------------------------------------------------------

TELNYX_CLOCK = _after(TELNYX_DAY, PAST_COOLDOWN)  # 2026-04-27: past the cooldown, so only the quarantine refuses


@pytest.mark.parametrize("request_text", ["telnyx==4.87.2", "telnyx"], ids=["exact", "loose"])
def test_telnyx_quarantine_refuses_install(replay: Replay, request_text: str) -> None:
    # Clock: 2026-04-27, 31 days after the attack. The project is quarantined: the finding is a
    # compromise with no replacement, by exact version or by name alone.
    prefix = replay.venv("app")
    before = snapshot(prefix)
    install = replay.install(TELNYX_CLOCK, quarantined=frozenset({"telnyx"}))
    with refuses("policy.compromise"):
        code, result, err = run(install, prefix, request_text)
    assert code == result["exit_code"] == 1, err
    assert violations(result) == [("compromise", "telnyx", "4.87.2")]
    (finding,) = result["findings"]
    assert finding["labels"] == ["registry-quarantined"]
    assert [o["kind"] for o in finding["options"]] == ["remove", "exception"]  # no replacement
    assert "No version of telnyx that passes every rule installs in this venv today." in err
    assert replay.pip.checks == [] and replay.pip.installs == []
    assert snapshot(prefix) == before


def test_telnyx_quarantine_in_check_envs(replay: Replay, tmp_path: Path) -> None:
    # Clock: 2026-04-27. fake_mac's home is tmp_path/home, the replay fixture's, so its config.toml
    # applies, and --path names ~/projects (#255). A venv that already holds telnyx 4.87.2, protected:
    # check --envs reports the compromise with no replacement, and nothing else.
    where = fake_mac(tmp_path)
    site = make_venv(Path(where.home) / "projects" / "app" / ".venv")
    add_dist(site, "telnyx", "4.87.2")
    projects = os.path.realpath(Path(where.home) / "projects")
    Protect(where.home, where.environ, where.root, TELNYX_CLOCK, io.StringIO(), io.StringIO())(
        Request(Verb.PROTECT, paths=(projects,), yes=True)
    )
    feeds = Feeds(replay.index, quarantined=frozenset({"telnyx"}))
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TELNYX_CLOCK, feeds.client(), err, host=HOST)
    with refuses("policy.compromise"):
        argv = ["check", "--envs", "--json", "--path", projects]
        code = cli.main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    result = json.loads(out.getvalue())
    assert code == result["exit_code"] == 1, err.getvalue()
    assert violations(result) == [("compromise", "telnyx", "4.87.2")]
    (finding,) = [f for f in result["findings"] if f["level"] == "violation"]
    assert finding["labels"] == ["registry-quarantined"]
    assert [o["kind"] for o in finding["options"]] == ["remove", "exception"]


# --- Trivy Action: the moved tags ----------------------------------------------------------

TRIVY = "aquasecurity/trivy-action"
TAG = "0.28.0"  # modelled: stands for any of the 76 moved tags
GOOD = "28" * 20  # the commit the tag named before the attack (modelled)
MOVED = "66" * 20  # the commit the attackers moved it to (modelled)
GHSA = "GHSA-69fq-xp46-6x23"
TRIVY_DAY = date(2026, 3, 19)
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "actions" / "trivy-tag-hijack-2026.yml"
BY_TAG = f"{TRIVY}@{TAG}"


def _trivy_github() -> GitHub:
    """GitHub on the attack day: the tag names the moved commit; both commits hold an Action."""
    github = GitHub()
    files = {(GOOD, "action.yml"): NODE_ACTION, (MOVED, "action.yml"): NODE_ACTION}
    github.publisher(TRIVY, 7701, tags={TAG: MOVED}, files=files)
    return github


def _trivy_repo(tmp_path: Path, uses: str, lock: Sequence[LockEntry] = ()) -> Path:
    """A repository whose workflow is the fixture, with ``uses`` in place of the tag."""
    root = make_repo(tmp_path, lock=lock)
    text = FIXTURE.read_text()
    assert f"uses: {BY_TAG}\n" in text
    (root / ".github" / "workflows" / "ci.yml").write_text(text.replace(BY_TAG, uses))
    return root


def _violations_of(result: Result) -> list[tuple[Rule, str | None]]:
    return [(f.rule, f.item) for f in result.findings if f.level is Level.VIOLATION]


def test_trivy_moving_tag_is_exit_1(tmp_path: Path) -> None:
    # Clock: the attack day, 2026-03-19. The workflow uses the Action by tag: T1.
    root = _trivy_repo(tmp_path, BY_TAG)
    with refuses("resolver.reference-not-pinned"):
        result, _ = check_repo(root, _trivy_github(), today=TRIVY_DAY)
    assert result.exit_code is ExitCode.VIOLATION
    assert _violations_of(result) == [(Rule.MOVING_REFERENCE, TRIVY)]


def test_trivy_moved_tag_leaves_old_pin_passing(tmp_path: Path) -> None:
    # Clock: the attack day. Pinned to the commit the tag named before, which the lock file lists,
    # the workflow passes though the tag has moved; pinned to the moved commit, it is unverified.
    pinned = _trivy_repo(tmp_path / "pinned", f"{TRIVY}@{GOOD} # {TAG}", [listed(TRIVY, GOOD, TAG)])
    result, err = check_repo(pinned, _trivy_github(), today=TRIVY_DAY)
    assert result.exit_code is ExitCode.RULES_MET, err
    assert _violations_of(result) == []
    # #201: on the attack day the move itself is named, a warning that leaves the exit code at 0.
    assert [(f.rule, f.level, f.item, f.version) for f in result.findings] == [
        (Rule.MOVED_RELEASE_TAG, Level.WARNING, TRIVY, GOOD)
    ]
    assert f"release tag {TAG} names {MOVED} today, not {GOOD}" in err

    moved = _trivy_repo(tmp_path / "moved", f"{TRIVY}@{MOVED}", [listed(TRIVY, GOOD, TAG)])
    with refuses("resolver.reference-not-pinned"):
        result, _ = check_repo(moved, _trivy_github(), today=TRIVY_DAY)
    assert _violations_of(result) == [(Rule.UNVERIFIED_PIN, TRIVY)]


def _files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_trivy_pin_of_moved_tag_waits_then_refuses_on_advisory(tmp_path: Path) -> None:
    # Clocks: the attack day (2026-03-19); the day after, when GHSA-69fq-xp46-6x23 lists the
    # version (modelled); and 2026-04-09, the day the moved commit's 21-day wait ends. Plan §3.2 T2: a commit
    # inside its cooldown is a wait, not a failure; when the wait ends, pin checks T6 first.
    genuine = LockEntry(TRIVY, GOOD, TAG, date(2025, 10, 1), date(2025, 10, 1), AgeSource.ACTIVITY_LOG)
    root = _trivy_repo(tmp_path, f"{TRIVY}@{GOOD} # {TAG}", [genuine])
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text()
    routes = github_routes(
        TRIVY,
        tags={TAG: MOVED},
        activity=[push(GOOD, "2025-10-01T00:00:00Z")],
        history={GOOD: "behind", MOVED: "diverged"},
    )
    home = tmp_path / "home"

    # The attack day: the moved commit was never on a branch and is new, so it waits out T2's
    # cooldown; the workflow keeps the genuine commit.
    result, err = run_pin(root, BY_TAG, routes, home=home, today=TRIVY_DAY)
    assert result.exit_code is ExitCode.RULES_MET, err
    assert [(f.rule, f.level, f.version) for f in result.findings] == [
        (Rule.UNPUSHED_COMMIT, Level.WARNING, MOVED),
        (Rule.MOVED_RELEASE_TAG, Level.WARNING, GOOD),  # #201: the tag recorded for GOOD names MOVED now
        (Rule.COOLDOWN_WAIT, Level.NOTICE, MOVED),
    ]
    assert "eligible on 2026-04-09" in err
    assert err.index(f"release tag {TAG} names {MOVED} today, not {GOOD}") < err.index("eligible on 2026-04-09")
    assert (root / ".github" / "workflows" / "ci.yml").read_text() == workflow
    assert {e.sha: e.trusted for e in load_lock(str(root / LOCK_FILE))} == {GOOD: date(2025, 10, 1), MOVED: TRIVY_DAY}

    # The day after (modelled), the advisory lists the version: check --repo, the CI check, fails at once.
    # Plan §3.2 T6's known limit: the genuine commit, recorded under the same tag, is marked too,
    # and the finding names the fixed version.
    advisory = Advisory(GHSA, TRIVY, "<= 0.34.2", "0.35.0")
    github = _trivy_github()
    github.advisories.append(advisory)
    with refuses("advisories.advisory-hit"):
        checked, err = check_repo(root, github, today=_after(TRIVY_DAY, 1))
    assert checked.exit_code is ExitCode.VIOLATION, err
    assert [(f.rule, f.version, f.evidence) for f in checked.findings if f.level is Level.VIOLATION] == [
        (Rule.KNOWN_VULNERABILITY, GOOD, (GHSA,))
    ]
    assert f"{GHSA}; fixed in 0.35.0" in err

    # The wait ends: pin checks the advisories before writing, refuses the moved commit and
    # writes nothing; the workflow still holds the genuine commit.
    before = _files(root)
    with refuses("advisories.advisory-hit"):
        result, err = run_pin(
            root, BY_TAG, {**routes, ADVISORIES: (200, [advisory.body()])}, home=home, today=date(2026, 4, 9)
        )
    assert result.exit_code is ExitCode.VIOLATION, err
    assert [(f.rule, f.item, f.version, f.evidence) for f in result.findings if f.level is Level.VIOLATION] == [
        (Rule.KNOWN_VULNERABILITY, TRIVY, MOVED, (GHSA,))
    ]
    assert "breaks a rule check --repo applies; nothing written." in err
    assert _files(root) == before
    assert (root / ".github" / "workflows" / "ci.yml").read_text() == workflow


# --- idempotency ------------------------------------------------------------------------------


def test_attack_replays_are_idempotent_on_re_run(replay: Replay, tmp_path: Path) -> None:
    # Clocks: as in each test above. A second run gives the same result and writes nothing new.
    prefix = replay.venv("app")
    trivy_root = _trivy_repo(tmp_path / "trivy", BY_TAG)
    github = _trivy_github()
    installs: list[list[tuple[int, dict[str, Any], str]]] = []
    checks: list[Result] = []
    states: list[dict[str, str]] = []
    for _ in range(2):
        outcomes: list[tuple[int, dict[str, Any], str]] = []
        for today, records, quarantined, text, case in [
            (LITELLM_DAY, {}, frozenset(), "litellm==1.82.8", refuses("policy.cooldown")),
            (
                _after(LITELLM_DAY, PAST_COOLDOWN),
                {"litellm": [LITELLM_MAL]},
                frozenset(),
                "litellm==1.82.8",
                refuses("policy.compromise"),
            ),
            (
                _after(LIGHTNING_DAY, PAST_COOLDOWN),
                {"lightning": [LIGHTNING_MAL]},
                frozenset(),
                "pyannote-audio",
                refuses("policy.compromise"),
            ),
            (TELNYX_CLOCK, {}, frozenset({"telnyx"}), "telnyx==4.87.2", refuses("policy.compromise")),
        ]:
            with case:
                outcome = run(replay.install(today, records, quarantined=quarantined), prefix, text)
            outcomes.append(outcome)
            assert replay.pip.installs == []
        installs.append(outcomes)
        with refuses("resolver.reference-not-pinned"):
            checked, _ = check_repo(trivy_root, github, today=TRIVY_DAY)
        checks.append(checked)
        states.append(snapshot(tmp_path))
    assert [code for code, _, _ in installs[0]] == [1, 1, 1, 1]
    assert installs[0] == installs[1]
    assert checks[0] == checks[1] and checks[0].exit_code is ExitCode.VIOLATION
    assert states[0] == states[1]
    assert not replay.marker.exists()
