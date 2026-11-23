# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``ssc-guardian pin`` end to end: the CLI, a local fixture server for GitHub, the lock file
and the workflows (issue #9). No live network.

The server binds 127.0.0.1 only. The client is the real one with the real ``urllib``
transport; the test transport only rewrites ``https://api.github.com/<path>`` to
``http://127.0.0.1:<port>/<path>``, as ``test_feeds_fixture_server`` does.
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
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.cli import Request, main
from ssc_guardian.commands import pin
from ssc_guardian.commands.acknowledge import Acknowledge
from ssc_guardian.findings import Verb, pin_command
from ssc_guardian.lockfile import LOCK_FILE, LockEntry, dump_lock, load_lock
from ssc_guardian.net import Client, Response, urllib_transport
from ssc_guardian.plugin import AgeSource
from ssc_guardian.plugins.actions import advisories, resolver
from ssc_guardian.plugins.actions.models import UsesReference, load_workflow
from tests.refusal_sites import refuses
from tests.unit.test_nested_and_advisories import Advisory
from tests.unit.test_pinning import ADVISORIES, CHANGED_FILES, CI, GHSA, NEW, OLD, V45, V46, github_routes, push
from tests.unit.test_publisher import Tty

pytestmark = pytest.mark.integration

TODAY = date(2026, 11, 3)


class _Answer(BaseHTTPRequestHandler):
    routes: dict[str, tuple[Any, ...]] = {}
    seen: list[tuple[str, str]] = []

    def _answer(self) -> None:
        self.seen.append((self.command, self.path))
        # GitHub matches owner and repository names in any letter case; every advisories query
        # gets the ``/advisories`` route's answer (T6, #126).
        route = self.routes.get(self.path) or self.routes.get(self.path.lower())
        if route is None and urllib.parse.urlsplit(self.path).path == ADVISORIES:
            route = self.routes.get(ADVISORIES)
        status, body, *headers = route or (404, {"message": "Not Found"})
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers[0] if headers else {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # keep test output quiet
        return None


# http.server calls do_GET by name; the class is built by name so its own methods keep the
# naming rules.
_Handler = type("_Handler", (_Answer,), {"do_GET": _Answer._answer})


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A Git repository with one workflow, its symlinks resolved (``/private/var`` on macOS)."""
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(CI)
    return root


@pytest.fixture
def server() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    _Answer.seen = []
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(base: str) -> Client:
    def transport(request: urllib.request.Request, timeout: float, limit: int) -> Response:
        parts = urllib.parse.urlsplit(request.full_url)
        assert (parts.scheme, parts.hostname) == ("https", "api.github.com")
        local = f"{base}{parts.path}" + (f"?{parts.query}" if parts.query else "")
        rewritten = urllib.request.Request(local, headers=dict(request.header_items()), method=request.get_method())
        answer = urllib_transport(rewritten, timeout, limit)
        return Response(answer.status, answer.headers, answer.body, request.full_url)

    return Client(transport=transport, timeout=5.0)


def _pin(root: Path, base: str, spec: str, *, today: date = TODAY, yes: bool = True) -> tuple[int, dict[str, Any], str]:
    err = io.StringIO()
    handler = pin.Pin(
        stdin=io.StringIO(), stderr=err, cwd=str(root), home=str(root / "home"), today=today, client=_client(base)
    )
    out = io.StringIO()
    argv = ["pin", spec, "--json", *(["--yes"] if yes else [])]
    code = main(argv, handlers={Verb.PIN: handler}, stdout=out, stderr=io.StringIO(), environ={})
    return code, json.loads(out.getvalue()), err.getvalue()


def _workflow(root: Path) -> Path:
    return root / ".github" / "workflows" / "ci.yml"


def test_pin_writes_lock_entry_then_workflow(repo: Path, server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _Answer.routes = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    order: list[str] = []
    real_write = pin.atomic_write

    def recording(path: str, text: str) -> None:
        order.append(path)
        real_write(path, text)

    monkeypatch.setattr(pin, "atomic_write", recording)
    code, doc, err = _pin(repo, server, "actions/checkout@v4.2.2")
    assert (code, doc["exit_code"], doc["command"]) == (0, 0, "pin")
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(repo)}]
    lock, workflow = str(repo / LOCK_FILE), str(_workflow(repo))
    assert order == [lock, workflow]  # the lock file first, then the pin
    assert load_lock(lock) == (
        LockEntry("actions/checkout", NEW, "v4.2.2", TODAY, date(2024, 10, 23), AgeSource.ACTIVITY_LOG),
    )
    pinned = [r.raw for r in load_workflow(workflow).references]
    assert pinned == [f"actions/checkout@{NEW}", "actions/setup-python@v5", f"Actions/Checkout@{NEW}"]
    assert f"uses: actions/checkout@{NEW} # v4.2.2\n" in _workflow(repo).read_text()
    # --yes still prints the change, to stderr (D15); no temporary file is left behind.
    assert "Confirmed in advance (--yes)." in err and f"{lock}: add actions/checkout@{NEW}" in err
    assert sorted(p.name for p in repo.iterdir()) == [".git", ".github", LOCK_FILE]
    assert os.listdir(_workflow(repo).parent) == ["ci.yml"]
    # Every request was a GET; the checked workflow now passes T1 and T4.
    assert {method for method, _ in _Answer.seen} == {"GET"}
    findings = resolver.reference_findings(load_workflow(workflow).references, load_lock(lock))
    assert [(f.rule.value, f.item) for f in findings] == [("moving-reference", "actions/setup-python")]


def test_pin_is_idempotent_with_no_duplicate_entry(repo: Path, server: str) -> None:
    _Answer.routes = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    assert _pin(repo, server, "actions/checkout@v4.2.2")[0] == 0
    lock_bytes, workflow_text = (repo / LOCK_FILE).read_bytes(), _workflow(repo).read_text()

    # The same pin again, a day later and by another tag and by bare SHA: nothing to write.
    for spec in ("actions/checkout@v4.2.2", "actions/checkout@v4", f"Actions/Checkout@{NEW}"):
        code, doc, err = _pin(repo, server, spec, today=date(2026, 11, 4))
        assert (code, doc["findings"]) == (0, [])
        assert "Nothing to write" in err
    assert (repo / LOCK_FILE).read_bytes() == lock_bytes  # first_seen never moves
    assert _workflow(repo).read_text() == workflow_text
    assert len(load_lock(str(repo / LOCK_FILE))) == 1


def test_repin_drops_unused_entries_but_keeps_one_rollback(repo: Path, server: str) -> None:
    older = "a" * 40
    entries = [
        LockEntry("actions/checkout", older, "v4.1.0", date(2026, 1, 1), date(2025, 12, 1), AgeSource.ACTIVITY_LOG),
        LockEntry("actions/checkout", OLD, "v4.1.1", date(2026, 3, 1), date(2026, 2, 1), AgeSource.ACTIVITY_LOG),
    ]
    (repo / LOCK_FILE).write_text(dump_lock(entries))
    _workflow(repo).write_text(CI.replace("actions/checkout@v4", f"actions/checkout@{OLD} # v4.1.1"))
    _Answer.routes = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    code, _, err = _pin(repo, server, "actions/checkout@v4.2.2")
    assert code == 0
    assert f"remove actions/checkout@{older} (tag v4.1.0): no workflow uses it" in err
    kept = {(e.sha, e.tag) for e in load_lock(str(repo / LOCK_FILE))}
    assert kept == {(NEW, "v4.2.2"), (OLD, "v4.1.1")}  # the previous commit stays as a rollback target


# --- the 2025 reference case ------------------------------------------------------------

# reviewdog/action-setup during its compromise (GHSA-qmg3-hpqr-gqvc, CVE-2025-30154): on
# 2025-03-11 between 18:42 and 20:31 UTC the v1 tag pointed at the malicious commit f0d342d,
# which no branch of the repository held; before and after, v1 named 3f401fe (v1.3.0, merged
# to master on 2024-03-12). Reconstructed from the advisory and the repository's public tag,
# commit and repository data (read 2026-11-03); recorded here, never fetched by the test.
REVIEWDOG = "reviewdog/action-setup"
GENUINE = "3f401fe1d58fe77e10d665ab713057375e39b887"
MALICIOUS = "f0d342d24037bb11d26b9bd8496e0808ba32e9ec"
DURING_THE_ATTACK = date(2025, 3, 11)
REVIEWDOG_ROUTES = github_routes(
    REVIEWDOG,
    default="master",
    tags={"v1": MALICIOUS, "v1.3": GENUINE, "v1.3.0": GENUINE},
    activity=[push(GENUINE, "2024-03-12T15:16:47Z", ref="refs/heads/master", kind="pr_merge")],
    history={GENUINE: "behind", MALICIOUS: "diverged"},
)
LINT = f"""\
name: lint
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: {REVIEWDOG}@{GENUINE} # v1
"""


def test_reference_case_2025_tag_move_is_caught(repo: Path, server: str) -> None:
    genuine = LockEntry(REVIEWDOG, GENUINE, "v1", date(2025, 1, 15), date(2024, 3, 12), AgeSource.ACTIVITY_LOG)
    lock = repo / LOCK_FILE
    lock.write_text(dump_lock([genuine]))
    lint = repo / ".github" / "workflows" / "lint.yml"
    lint.write_text(LINT)

    # A workflow pinned to the commit the tag now names is not in the lock file: unverified.
    moved = UsesReference.read(f"{REVIEWDOG}@{MALICIOUS}", file=str(lint), line=7, job="lint", step=0)
    (finding,) = resolver.reference_findings([moved], load_lock(str(lock)))
    assert finding.rule.value == "unverified-pin"

    # pin v1 during the attack: the tag vouches for the commit (T4), but the commit was never on
    # a branch and is new, so it waits out the cooldown; the workflow keeps the genuine commit.
    _Answer.routes = REVIEWDOG_ROUTES
    code, doc, err = _pin(repo, server, f"{REVIEWDOG}@v1", today=DURING_THE_ATTACK)
    assert code == doc["exit_code"] == 0
    assert [(f["rule"], f["level"], f["version"]) for f in doc["findings"]] == [
        ("unpushed-commit", "warning", MALICIOUS),
        ("cooldown-wait", "notice", MALICIOUS),
    ]
    assert doc["findings"][1]["options"][0]["eligible_on"] == "2025-04-01"
    assert doc["findings"][1]["options"][0]["command"] is None
    assert lint.read_text() == LINT
    assert "eligible on 2025-04-01" in err
    recorded = {e.sha: e for e in load_lock(str(lock))}
    assert recorded[GENUINE] == genuine
    assert (recorded[MALICIOUS].trusted, recorded[MALICIOUS].trusted_source) == (
        DURING_THE_ATTACK,
        AgeSource.LOCK_FIRST_SEEN,
    )
    # The genuine pin still passes T1 and T4.
    assert resolver.reference_findings(load_workflow(str(lint)).references, load_lock(str(lock))) == ()


# --- T3, T6 and the deny list before anything is written (#126) ---------------------------

CHANGES = f"""\
name: changes
on: [pull_request]
jobs:
  changes:
    runs-on: ubuntu-latest
    steps:
      - uses: {CHANGED_FILES}@v45
"""
# tj-actions/changed-files with v45.0.7 and its fix v46.0.1, both pushed long ago; no
# advisory unless a test sets one.
CHANGED_FILES_ROUTES = github_routes(
    CHANGED_FILES,
    tags={"v45.0.7": V45, "v46.0.1": V46},
    activity=[push(V45, "2025-03-01T00:00:00Z"), push(V46, "2025-03-20T00:00:00Z")],
)
DENIED = f'format = 1\ndeny = ["github-actions:{CHANGED_FILES}"]\n'


def _files(root: Path) -> dict[str, bytes]:
    """Every file under ``root``, byte for byte: what a refused run must leave as it was."""
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _with_changes(root: Path) -> Path:
    """The repository with a second workflow using tj-actions/changed-files and a lock file
    holding one earlier pin."""
    (root / ".github" / "workflows" / "changes.yml").write_text(CHANGES)
    earlier = LockEntry("actions/checkout", OLD, "v4.1.1", date(2026, 3, 1), date(2026, 2, 1), AgeSource.ACTIVITY_LOG)
    (root / LOCK_FILE).write_text(dump_lock([earlier]))
    return root


def _violations(doc: dict[str, Any]) -> list[tuple[str, str, str | None, list[str]]]:
    return [(f["rule"], f["item"], f["version"], f["evidence"]) for f in doc["findings"] if f["level"] == "violation"]


def test_pin_refuses_a_denied_action_and_writes_nothing(repo: Path, server: str) -> None:
    _with_changes(repo)
    (repo / ".ssc-guardian.toml").write_text(DENIED)
    _Answer.routes = CHANGED_FILES_ROUTES
    before = _files(repo)
    code, doc, err = _pin(repo, server, f"{CHANGED_FILES}@v45.0.7")
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [("deny-list", CHANGED_FILES, V45, [])]
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(repo)}]  # refused, not unfinished
    assert f"ssc-guardian: {CHANGED_FILES}@{V45} breaks a rule check --repo applies; nothing written." in err
    assert "Guardian will pin" not in err and "Written:" not in err  # never shown, never written
    assert _files(repo) == before


def test_pin_refuses_a_version_with_an_advisory(repo: Path, server: str) -> None:
    _with_changes(repo)
    advisory = Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", "46.0.1")
    _Answer.routes = {**CHANGED_FILES_ROUTES, ADVISORIES: (200, [advisory.body()])}
    before = _files(repo)
    code, doc, err = _pin(repo, server, f"{CHANGED_FILES}@v45.0.7")
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [("known-vulnerability", CHANGED_FILES, V45, [GHSA])]
    # The message names the fixed version, and the finding gives its pin command.
    assert f"{GHSA}; fixed in 46.0.1" in err
    (finding,) = [f for f in doc["findings"] if f["rule"] == "known-vulnerability"]
    assert [o["command"] for o in finding["options"] if o["kind"] == "replace"] == [
        list(pin_command(CHANGED_FILES, "v46.0.1"))
    ]
    assert _files(repo) == before


def test_pin_by_major_tag_refuses_a_vulnerable_release(repo: Path, server: str) -> None:
    # #142: v4 names the commit that is release v4.1.3, inside the advisory's range. GitHub
    # answers the advisory only when asked about v4.1.3; asked about v4 alone it answers nothing.
    action, commit = "someone/major", "47" * 20
    routes = github_routes(
        action, tags={"v4": commit, "v4.1.3": commit}, activity=[push(commit, "2026-01-05T00:00:00Z")]
    )
    advisory = Advisory(GHSA, action, ">= 4.1.0, < 4.1.5", "4.1.5")
    asked = urllib.parse.urlsplit(advisories.url([f"{action}@v4.1.3"]))
    routes[f"{asked.path}?{asked.query}"] = (200, [advisory.body()])
    _Answer.routes = routes
    _workflow(repo).write_text(CI + f"      - uses: {action}@v4\n")
    before = _files(repo)
    code, doc, err = _pin(repo, server, f"{action}@v4")
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [("known-vulnerability", action, commit, [GHSA])]
    assert f"{action}@{commit} (v4.1.3): {GHSA}; fixed in 4.1.5" in err
    assert "Guardian will pin" not in err and "Written:" not in err
    assert _files(repo) == before  # nothing written: no lock entry, no workflow edit
    # The tags list T4 read is the one T6 used: asked once.
    assert sum(1 for _, path in _Answer.seen if path == f"/repos/{action}/tags?per_page=100") == 1


def test_pin_refuses_a_young_repository_until_acknowledged(repo: Path, server: str) -> None:
    young, commit = "someone/new-action", "61" * 20
    routes = github_routes(young, tags={"v1.0.0": commit}, activity=[push(commit, "2026-10-01T00:00:00Z")])
    meta = dict(routes[f"/repos/{young}"][1], created_at="2026-09-20T12:00:00Z", stargazers_count=10)
    routes[f"/repos/{young}"] = (200, meta)
    _Answer.routes = routes
    _workflow(repo).write_text(CI + f"      - uses: {young}@v1\n")
    before = _files(repo)
    code, doc, err = _pin(repo, server, f"{young}@v1.0.0")
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [("young-repository", young, None, [])]
    assert f"ssc-guardian acknowledge {young}" in err
    assert _files(repo) == before

    # A person acknowledges it (its numeric ID is recorded): the same pin is written.
    acknowledged = Acknowledge(
        stdin=Tty("y\n"),
        stderr=io.StringIO(),
        cwd=str(repo),
        home=str(repo / "home"),
        today=TODAY,
        client=_client(server),
    )(Request(Verb.ACKNOWLEDGE, repository=young))
    assert acknowledged.exit_code == 0
    code, doc, err = _pin(repo, server, f"{young}@v1.0.0")
    assert code == doc["exit_code"] == 0
    assert [f["rule"] for f in doc["findings"]] == ["first-use-publisher"]  # T3's notice, not a block
    assert [(e.action, e.sha, e.tag) for e in load_lock(str(repo / LOCK_FILE))] == [(young, commit, "v1.0.0")]
    assert f"uses: {young}@{commit} # v1.0.0\n" in _workflow(repo).read_text()


def test_pin_advisory_api_error_exits_two_and_writes_nothing(repo: Path, server: str) -> None:
    _with_changes(repo)
    _Answer.routes = {**CHANGED_FILES_ROUTES, ADVISORIES: (403, {"message": "Forbidden"})}
    before = _files(repo)
    with refuses("net.feed-answered-http-error"):
        code, doc, err = _pin(repo, server, f"{CHANGED_FILES}@v45.0.7")
    assert code == doc["exit_code"] == 2  # never a pass
    # What was found before the failure is still reported: here only T3's first-use notice.
    assert [f["rule"] for f in doc["findings"]] == ["first-use-publisher"] and doc["checked"] == []
    assert [(s["place"], s["reason"]) for s in doc["skipped"]] == [(str(repo), "feed-failure")]
    assert "answered HTTP 403; nothing written." in err
    assert _files(repo) == before


CHECKOUT_ROUTES = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])


def test_read_back_refusal_says_nothing_written_once(repo: Path, server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # #151: a reader that loses the pinned reference, so the rewrite does not read back. The
    # refusal's own message no longer ends in "nothing written"; the handler adds it once.
    real = pin._references

    def misread(reader: Any, source: str, path: str) -> Any:
        found = real(reader, source, path)
        return found[:-1] if NEW in source else found

    monkeypatch.setattr(pin, "_references", misread)
    _Answer.routes = CHECKOUT_ROUTES
    before = _files(repo)
    with refuses("pin.did-not-read-back-pin"):
        code, doc, err = _pin(repo, server, "actions/checkout@v4.2.2")
    assert code == doc["exit_code"] == 2
    assert [(s["place"], s["reason"]) for s in doc["skipped"]] == [(str(repo), "check-error")]
    assert f"ssc-guardian: {_workflow(repo)} did not read back as pin rewrote it; nothing written.\n" in err
    assert err.count("nothing written") == 1
    assert "Guardian will pin" not in err and "Written:" not in err
    assert _files(repo) == before


def test_d16_guard_refuses_a_write_outside_the_plan(repo: Path, server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # #151: reading refuses a workflow outside the repository (pin.symlink-lies-outside-repository-pin).
    # With that check switched off, here by reading another repository's workflows, the D16 guard
    # behind it refuses before the first write: exit 2, and neither repository changes.
    other = repo.parent / "other"
    (other / ".git").mkdir(parents=True)
    (other / ".github" / "workflows").mkdir(parents=True)
    (other / ".github" / "workflows" / "ci.yml").write_text(CI)
    real = pin.read_sources
    monkeypatch.setattr(pin, "read_sources", lambda root: real(str(other)))
    _Answer.routes = CHECKOUT_ROUTES
    before, elsewhere = _files(repo), _files(other)
    with refuses("pin.write-outside-plan"):
        code, doc, err = _pin(repo, server, "actions/checkout@v4.2.2")
    assert code == doc["exit_code"] == 2
    assert [(s["place"], s["reason"]) for s in doc["skipped"]] == [(str(repo), "check-error")]
    shown = other / ".github" / "workflows" / "ci.yml"
    assert err.endswith(f"ssc-guardian: {shown} is not part of the pin's plan; nothing written.\n")
    assert "Written:" not in err
    assert _files(repo) == before and not (repo / LOCK_FILE).exists()  # the lock file is not written either
    assert _files(other) == elsewhere


def test_bare_pin_without_ref_is_exit_two(repo: Path, server: str) -> None:
    # Contracts §2 (#151): the ref is required. A bare OWNER/REPO asks GitHub nothing and
    # writes nothing.
    _Answer.routes = CHECKOUT_ROUTES
    before = _files(repo)
    with refuses("pin.no-repository-or-version"):
        code, doc, err = _pin(repo, server, "actions/checkout")
    assert code == doc["exit_code"] == 2
    assert [s["reason"] for s in doc["skipped"]] == ["check-error"]
    assert err == (
        "ssc-guardian: name the version to pin: OWNER/REPO[/PATH]@TAG or OWNER/REPO[/PATH]@SHA; nothing written.\n"
    )
    assert _Answer.seen == []
    assert _files(repo) == before


def test_pin_rerun_after_a_refusal_is_idempotent(repo: Path, server: str) -> None:
    _with_changes(repo)
    (repo / ".ssc-guardian.toml").write_text(DENIED)
    _Answer.routes = CHANGED_FILES_ROUTES
    before = _files(repo)
    for _ in range(2):  # refused twice: no partial entry, no workflow edit, the same answer
        code, doc, _ = _pin(repo, server, f"{CHANGED_FILES}@v45.0.7")
        assert (code, _violations(doc)) == (1, [("deny-list", CHANGED_FILES, V45, [])])
        assert _files(repo) == before

    # With the deny entry gone the pin is written once, and a re-run writes nothing.
    (repo / ".ssc-guardian.toml").write_text("format = 1\n")
    assert _pin(repo, server, f"{CHANGED_FILES}@v45.0.7")[0] == 0
    written = _files(repo)
    code, _, err = _pin(repo, server, f"{CHANGED_FILES}@v45.0.7")
    assert code == 0 and "Nothing to write" in err
    assert _files(repo) == written
    assert [e.sha for e in load_lock(str(repo / LOCK_FILE)) if e.action == CHANGED_FILES] == [V45]


# --- a value never adds a line (#147) ------------------------------------------------------

# A committed workflow whose name holds a newline, U+2028 and U+0085, each followed by text
# shaped like one of pin's change lines: printed raw, each would be a line of its own.
FORGED = "  F.yml:1: evil@v1 -> evil@v6"
HOSTILE_NAME = f"x.yml: 1: harmless\n{FORGED}\u2028{FORGED}\x85{FORGED}.yml"
SHOWN_NAME = f"x.yml: 1: harmless{FORGED}{FORGED}{FORGED}.yml"  # the same, its line breaks stripped


def _hostile(repo: Path) -> Path:
    """``repo``'s one workflow, renamed to :data:`HOSTILE_NAME` on disk."""
    path = _workflow(repo).with_name(HOSTILE_NAME)
    _workflow(repo).rename(path)
    assert os.listdir(path.parent) == [HOSTILE_NAME]  # the name is stored as written
    return path


def _confirming(root: Path, base: str, spec: str, answer: str) -> tuple[int, str]:
    """``pin SPEC`` at a terminal (no ``--yes``), a person answering ``answer`` to the prompt."""
    err = io.StringIO()
    handler = pin.Pin(
        stdin=Tty(answer), stderr=err, cwd=str(root), home=str(root / "home"), today=TODAY, client=_client(base)
    )
    code = main(["pin", spec, "--json"], handlers={Verb.PIN: handler}, stdout=io.StringIO(), stderr=io.StringIO())
    return code, err.getvalue()


def _prompt(repo: Path) -> str:
    """What ``pin actions/checkout@v4.2.2`` prints up to the answer in the hostile workflow:
    T3's note, the change, and the question, which ends the line the answer is typed on."""
    shown = f"{_workflow(repo).parent}/{SHOWN_NAME}"
    lines = [
        "first use of actions/checkout in this repository: created 2019-07-23 (2660 days ago), 7000 stars, 2000 forks",
        f"Guardian will pin actions/checkout to {NEW} (v4.2.2):",
        f"  {repo / LOCK_FILE}: add actions/checkout@{NEW} (tag v4.2.2; cooldown starts 2024-10-23, activity-log)",
        f"  {shown}:7: actions/checkout@v4 -> actions/checkout@{NEW} # v4.2.2",
        f"  {shown}:12: Actions/Checkout@v3 -> Actions/Checkout@{NEW} # v4.2.2",
    ]
    return "\n".join(lines) + "\nProceed? [y/N] "


NOT_CONFIRMED = "ssc-guardian: not confirmed; nothing written. Add --yes to confirm in advance.\n"


def test_file_name_with_newline_adds_no_line_to_the_prompt(repo: Path, server: str) -> None:
    # Contracts §5: each value is stripped of line breaks before it goes into a message, so the
    # file name stays on its own line and the forged change lines never appear as lines.
    _Answer.routes = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    workflow = _hostile(repo)
    code, err = _confirming(repo, server, "actions/checkout@v4.2.2", "n\n")
    assert code == 2  # declined: nothing written
    assert err == _prompt(repo) + NOT_CONFIRMED
    assert len(err.splitlines()) == 6  # five lines and the question; no character in a value splits one
    assert not any(line.startswith(FORGED) for line in err.splitlines())
    assert workflow.read_text() == CI and not (repo / LOCK_FILE).exists()


def test_pin_without_terminal_or_yes_prints_the_plan_and_exits_2(repo: Path, server: str) -> None:
    # #284: a stdin that is not a terminal never confirms, but the plan is still shown, each
    # value stripped as at a terminal, and no question is asked.
    _Answer.routes = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    workflow = _hostile(repo)
    before = _files(repo)
    with refuses("pin.not-confirmed"):
        code, doc, err = _pin(repo, server, "actions/checkout@v4.2.2", yes=False)
    assert code == doc["exit_code"] == 2
    assert err == _prompt(repo).removesuffix("Proceed? [y/N] ") + NOT_CONFIRMED
    assert not any(line.startswith(FORGED) for line in err.splitlines())
    assert _files(repo) == before and workflow.read_text() == CI and not (repo / LOCK_FILE).exists()


def test_output_is_idempotent_on_re_run(repo: Path, server: str) -> None:
    # Two runs show the same change; what is shown is what is written; a third writes nothing.
    _Answer.routes = github_routes(tags={"v4.2.2": NEW, "v4": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])
    workflow = _hostile(repo)
    prompt = _prompt(repo)
    assert _confirming(repo, server, "actions/checkout@v4.2.2", "n\n") == (2, prompt + NOT_CONFIRMED)
    code, err = _confirming(repo, server, "actions/checkout@v4.2.2", "y\n")
    assert code == 0
    assert err == prompt + f"Written: {repo / LOCK_FILE}\nWritten: {workflow.parent}/{SHOWN_NAME}\n"
    written = workflow.read_text().splitlines()
    for line in prompt.splitlines()[3:5]:  # each change line's new value is on that line of the file
        head, _, value = line.rpartition(" -> ")  # the name holds " -> " too
        number = int(head.rsplit(": ", 1)[0].rsplit(":", 1)[1])
        assert written[number - 1].endswith(f"uses: {value}")
    assert [(e.action, e.sha, e.tag) for e in load_lock(str(repo / LOCK_FILE))] == [("actions/checkout", NEW, "v4.2.2")]
    before = _files(repo)
    code, err = _confirming(repo, server, "actions/checkout@v4.2.2", "y\n")
    assert code == 0
    recorded = f"actions/checkout@{NEW} is recorded in {repo / LOCK_FILE}"
    assert err == f"Nothing to write: {recorded} and every workflow pin is current.\n"
    assert _files(repo) == before


# --- output cannot change the exit code; a failed write step names what it wrote (#227) -----


class _BrokenOnWritten(io.StringIO):
    """A stderr whose reader went away once the change was shown: the "Written:" line meets a
    closed pipe."""

    def write(self, text: str) -> int:
        if text.startswith("Written:"):
            raise BrokenPipeError("closed")
        return super().write(text)


@pytest.mark.parametrize("stream", ["broken", "closed"])
def test_pin_broken_stderr_after_write_keeps_exit_code(
    repo: Path, server: str, monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    # Contracts §3: a closed or broken stream cannot change the exit code, even after a write.
    _Answer.routes = CHECKOUT_ROUTES
    err: io.StringIO | None = _BrokenOnWritten() if stream == "broken" else None
    monkeypatch.setattr(sys, "stderr", err)  # None is what Python sets when fd 2 is closed at start
    handler = pin.Pin(
        stdin=io.StringIO(), stderr=err, cwd=str(repo), home=str(repo / "home"), today=TODAY, client=_client(server)
    )
    out = io.StringIO()
    code = main(
        ["pin", "actions/checkout@v4.2.2", "--json", "--yes"], handlers={Verb.PIN: handler}, stdout=out, stderr=err
    )
    assert code == json.loads(out.getvalue())["exit_code"] == 0
    assert [(e.action, e.sha) for e in load_lock(str(repo / LOCK_FILE))] == [("actions/checkout", NEW)]
    assert f"uses: actions/checkout@{NEW} # v4.2.2\n" in _workflow(repo).read_text()
    if isinstance(err, _BrokenOnWritten):
        assert "Confirmed in advance (--yes)." in err.getvalue() and "Written:" not in err.getvalue()


def test_acknowledge_broken_stderr_keeps_exit_code(repo: Path, server: str) -> None:
    young = "someone/new-action"
    routes = github_routes(young, tags={"v1.0.0": "61" * 20})
    routes[f"/repos/{young}"] = (200, dict(routes[f"/repos/{young}"][1], created_at="2026-09-20T12:00:00Z"))
    _Answer.routes = routes
    err = _BrokenOnWritten()
    handler = Acknowledge(
        stdin=Tty("y\n"), stderr=err, cwd=str(repo), home=str(repo / "home"), today=TODAY, client=_client(server)
    )
    code = main(["acknowledge", young], handlers={Verb.ACKNOWLEDGE: handler}, stdout=io.StringIO(), stderr=err)
    assert code == 0
    assert f'repository = "{young}"' in (repo / ".ssc-guardian.toml").read_text()
    assert "Proceed? [y/N] " in err.getvalue() and "Written:" not in err.getvalue()


def test_pin_failed_workflow_write_reports_what_it_wrote(
    repo: Path, server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The write step writes the lock file, then each workflow, each atomically; a failure part
    # way is exit 2 and names what was written. Each file written had passed every check, and a
    # re-run finishes the change.
    real = pin.atomic_write

    def failing(path: str, text: str) -> None:
        if path.endswith("ci.yml"):
            raise OSError("disk full")
        real(path, text)

    monkeypatch.setattr(pin, "atomic_write", failing)
    _Answer.routes = CHECKOUT_ROUTES
    with refuses("pin.not-written"):
        code, doc, err = _pin(repo, server, "actions/checkout@v4.2.2")
    assert code == doc["exit_code"] == 2
    assert [(s["place"], s["reason"]) for s in doc["skipped"]] == [(str(repo), "check-error")]
    assert f"ssc-guardian: {_workflow(repo)}: disk full; written so far: {repo / LOCK_FILE}.\n" in err
    assert "Written:" not in err
    assert [(e.action, e.sha) for e in load_lock(str(repo / LOCK_FILE))] == [("actions/checkout", NEW)]
    assert _workflow(repo).read_text() == CI  # the workflow is whole, as it was
    assert os.listdir(_workflow(repo).parent) == ["ci.yml"]  # no temporary file left behind

    monkeypatch.setattr(pin, "atomic_write", real)
    code, doc, err = _pin(repo, server, "actions/checkout@v4.2.2")
    assert code == doc["exit_code"] == 0
    assert f"uses: actions/checkout@{NEW} # v4.2.2\n" in _workflow(repo).read_text()
    assert err.endswith(f"Written: {_workflow(repo)}\n")  # the lock file already held the entry
