# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The command-line frame against the frozen contract (issue #2)."""

from __future__ import annotations

import argparse
import ast
import asyncio
import dataclasses
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

import pytest

import ssc_guardian
from ssc_guardian.cli import DEFAULT_HANDLERS, KevCatalogLookup, Request, build_parser, confirm, main
from ssc_guardian.commands import acknowledge, check_envs, protect
from ssc_guardian.commands.override_add import OverrideAdd
from ssc_guardian.feeds import osv
from ssc_guardian.feeds.kev import CATALOG_URL
from ssc_guardian.findings import (
    Checked,
    Ecosystem,
    Option,
    OptionKind,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    install_command,
    make_finding,
)
from ssc_guardian.net import Client
from ssc_guardian.plugin import Item
from ssc_guardian.render import CONTRACT, FORMAT_VERSION
from tests.refusal_sites import refuses
from tests.samples import REPO as SAMPLE_REPO
from tests.samples import full_result
from tests.unit.test_nested_and_advisories import NODE_ACTION, TODAY, GitHub, listed, make_repo, sha
from tests.unit.test_net import Recorder, client, reply

pytestmark = pytest.mark.integration

# #255: check names what it checks. The sample result's places are all under SAMPLE_REPO.
NAMED = ("--path", SAMPLE_REPO)

REPO = Path(__file__).resolve().parents[2]


def _run(argv: list[str], **kwargs: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err, environ={}, **kwargs)
    return code, out.getvalue(), err.getvalue()


# The JSON format 1.0 key sets, written out here rather than read from render.CONTRACT,
# so a key added to both the renderer and its constant still fails this test.
EXPECTED_KEYS = {
    "result": {
        "format_version", "tool", "command", "exit_code", "summary", "findings", "checked", "skipped", "overrides",
    },
    "tool": {"name", "version", "commit"},
    "summary": {"violations", "warnings", "notices", "checked", "skipped_in_scope", "skipped_out_of_scope"},
    "finding": {
        "id", "rule", "level", "ecosystem", "place", "item", "version", "evidence", "labels", "options",
        "malformed_field", "via",
    },
    "option": {"kind", "item", "version", "command", "eligible_on", "requires_user_approval", "requires_person"},
    "checked": {"ecosystem", "place"},
    "skipped": {"ecosystem", "place", "reason", "in_scope"},
    "overrides": {"applied", "expired"},
    "override": {"id", "ecosystem", "item", "version", "rule", "reference", "category", "expiry"},
}  # fmt: skip


def test_renderer_constant_matches_the_written_contract() -> None:
    assert {k: set(v) for k, v in CONTRACT.items()} == EXPECTED_KEYS


def _assert_contract(doc: dict[str, Any]) -> None:
    assert set(doc) == EXPECTED_KEYS["result"]
    assert doc["format_version"] == "1.0" == FORMAT_VERSION
    assert set(doc["tool"]) == EXPECTED_KEYS["tool"]
    assert set(doc["summary"]) == EXPECTED_KEYS["summary"]
    assert set(doc["overrides"]) == EXPECTED_KEYS["overrides"]
    for finding in doc["findings"]:
        assert set(finding) == EXPECTED_KEYS["finding"]
        for option in finding["options"]:
            assert set(option) == EXPECTED_KEYS["option"]
    for entry in doc["checked"]:
        assert set(entry) == EXPECTED_KEYS["checked"]
    for entry in doc["skipped"]:
        assert set(entry) == EXPECTED_KEYS["skipped"]
    for record in doc["overrides"]["applied"] + doc["overrides"]["expired"]:
        assert set(record) == EXPECTED_KEYS["override"]


@pytest.mark.parametrize(
    "argv",
    [
        ["acknowledge", "someone/new-action", "--yes"],
        ["override", "add", "--yes"],
        ["acknowledge", "someone/new-action", "--json"],
        ["override", "add", "--json"],
    ],
)
def test_acknowledge_and_override_add_refuse_yes(argv: list[str]) -> None:
    called: list[Request] = []

    def handler(request: Request) -> Result:
        called.append(request)
        return Result(request.verb)

    handlers = {verb: handler for verb in Verb}
    code, out, err = _run(argv, handlers=handlers)
    assert code == 2
    assert called == []  # refused before anything runs
    assert out == ""
    assert "refuses --" in err


def test_exception_commands_never_confirm_in_advance() -> None:
    class NoTty(io.StringIO):
        def isatty(self) -> bool:
            return False

    for verb in (Verb.ACKNOWLEDGE, Verb.OVERRIDE_ADD):
        assert confirm("write it", verb=verb, yes=True, stdin=NoTty("y\n"), stdout=io.StringIO()) is False
    assert confirm("write it", verb=Verb.PIN, yes=True, stdin=NoTty(), stdout=io.StringIO()) is True
    assert confirm("write it", verb=Verb.PIN, yes=False, stdin=NoTty("y\n"), stdout=io.StringIO()) is False


def test_json_output_matches_contract_version() -> None:
    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: lambda request: full_result()})
    doc = json.loads(out)
    _assert_contract(doc)
    assert code == doc["exit_code"] == 1
    # Every optional part of the contract is present at least once in the sample.
    findings = doc["findings"]
    assert any(f["evidence"] and f["labels"] and f["options"] for f in findings)
    assert any(f["malformed_field"] for f in findings)
    assert any(o["eligible_on"] for f in findings for o in f["options"])
    assert doc["overrides"]["applied"] and doc["overrides"]["expired"]


def test_json_key_sets_unchanged_by_text_only_fields() -> None:
    # #38: a finding's detail is text only. Through the real frame, the JSON keeps the frozen key
    # sets and the ID formula (rule, place, ecosystem, item, version, malformed field and value,
    # outer Actions), and carries none of the detail.
    place = "/repo/.ssc-guardian.toml"
    notice = make_finding(
        Rule.WEAKENED_SETTING, Ecosystem.PYPI, place=place, item="requests", detail="cooldown_days 2, applied 21"
    )
    sample = full_result()
    result = replace(sample, findings=(*sample.findings, notice))
    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: lambda request: result})
    doc = json.loads(out)
    _assert_contract(doc)
    assert code == doc["exit_code"] == 1  # the sample's violations; the notice changes nothing
    payload = json.dumps(["weakened-setting", place, "pypi", "requests", None, None, None, []], separators=(",", ":"))
    expected_id = hashlib.sha256(payload.encode("ascii")).hexdigest()[:32]
    assert notice.id == expected_id == replace(notice, detail=None).id
    assert [f for f in doc["findings"] if f["id"] == expected_id] != []
    assert "applied 21" not in out
    assert "detail" not in out
    _, text, _ = _run(["check", *NAMED], handlers={Verb.CHECK: lambda request: result})
    assert "  detail: cooldown_days 2, applied 21\n" in text


def test_real_cli_json_matches_contract(tmp_path: Path) -> None:
    # Only the GitHub Actions area, on a temporary repository with no workflows (#10), so nothing
    # reaches the network: the Python environments (#5) would read this machine's real Pythons
    # and the live feeds, which no test may do. HOME is a temporary folder and CI's variables
    # are cleared, so neither the real config nor the default branch is read.
    folder = tmp_path.resolve() / "no-workflows"
    (folder / ".git").mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_") and k != "GH_TOKEN"}
    env.update({"PYTHONPATH": str(REPO / "src"), "HOME": str(tmp_path.resolve())})
    argv = [sys.executable, "-m", "ssc_guardian", "check", "--repo", str(folder), "--json"]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    doc = json.loads(proc.stdout)
    _assert_contract(doc)
    assert proc.returncode == doc["exit_code"] == 0
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(folder)}]
    assert {(s["ecosystem"], s["reason"]) for s in doc["skipped"]} == {("pypi", "filtered")}


def test_check_and_protect_are_wired() -> None:
    # Issue #5: their tests drive the handlers against a fake Mac (test_check_envs, test_protect).
    assert DEFAULT_HANDLERS[Verb.CHECK] is check_envs.handle
    assert DEFAULT_HANDLERS[Verb.PROTECT] is protect.handle


@pytest.mark.parametrize(("verb", "wanted"), [("check", 1), ("acknowledge", 2)])
def test_unbuilt_verbs_never_exit_zero(verb: str, wanted: int, tmp_path: Path) -> None:
    # #10 built the last two verbs. Neither exits 0 when it cannot pass: a moving tag is a
    # violation even with GitHub unreachable, and acknowledge with no terminal writes nothing.
    # No request leaves the process.
    repo = tmp_path.resolve() / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    workflow = (
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: someone/new-action@v1\n"
    )
    (repo / ".github" / "workflows" / "ci.yml").write_text(workflow)

    def offline(request: object, timeout: float, limit: int) -> NoReturn:
        raise OSError("no network in tests")

    client = Client(transport=offline)
    handlers = {
        Verb.CHECK: check_envs.CheckEnvs(home=str(tmp_path), environ={}, client=client, stderr=io.StringIO()),
        Verb.ACKNOWLEDGE: acknowledge.Acknowledge(stdin=io.StringIO("y\n"), stderr=io.StringIO(), cwd=str(repo)),
    }
    argv = ["check", "--repo", str(repo)] if verb == "check" else ["acknowledge", "someone/new-action"]
    code, out, _ = _run(argv, handlers=handlers)
    assert code == wanted
    assert ("moving-reference" in out) if verb == "check" else ("(no terminal)" in out)
    assert not (repo / ".ssc-guardian.toml").exists()


def test_override_add_is_wired_and_needs_a_terminal(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Issue #3: the default handler asks a person at a terminal; with no terminal on stdin,
    # nothing is written and the command exits 2 (D15).
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    code, out, _ = _run(["override", "add"])
    assert code == 2
    assert "(no terminal)" in out
    assert "needs a person at a terminal; nothing written" in capsys.readouterr().err


def test_handler_error_exits_two_not_one() -> None:
    def broken(request: Request) -> Result:
        raise RuntimeError("boom")

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: broken})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert {"ecosystem": None, "place": None, "reason": "check-error", "in_scope": True} in doc["skipped"]


@pytest.mark.parametrize(
    ("argv", "field"),
    [
        (["install", "--venv", "/tmp/v", "requests>=2"], "item"),
        (["install", "--venv", "/tmp/v", "requests==latest"], "version"),
        (["install", "--venv", "/tmp/v;rm", "requests"], "place"),
        (["pin", "actions/checkout@v4;x"], "version"),
        (["pin", "not-an-action"], "item"),
        (["acknowledge", "someone/new-action/sub"], "item"),
        (["check", "--path", "/tmp/a\x1bb"], "place"),
        (["check", "--repo", "/tmp/$(id)"], "place"),
    ],
)
def test_malformed_argument_is_a_violation(argv: list[str], field: str) -> None:
    called: list[Request] = []

    def handler(request: Request) -> Result:
        called.append(request)
        return Result(request.verb)

    json_flag = [] if argv[0] == "acknowledge" else ["--json"]  # acknowledge output is text only
    code, out, _ = _run([*argv, *json_flag], handlers={verb: handler for verb in Verb})
    assert code == 1
    assert called == []  # never a guess: the command does not run
    if argv[0] != "acknowledge":
        (finding,) = json.loads(out)["findings"]
        assert (finding["rule"], finding["malformed_field"]) == ("malformed-name", field)
    else:
        assert f"malformed {field}" in out


@pytest.mark.parametrize(
    ("argv", "in_scope", "filtered"),
    [
        (["check", *NAMED], {"pypi", "github-actions"}, set()),
        (["check", "--envs", *NAMED], {"pypi"}, {"github-actions"}),
        (["check", "--repo", "."], {"github-actions"}, {"pypi"}),
        (["check", "--language", "python", *NAMED], {"pypi"}, {"github-actions"}),
        (["check", "--ecosystem", "github-actions", *NAMED], {"github-actions"}, {"pypi"}),
    ],
)
def test_filters_narrow_scope_and_list_what_they_leave_out(
    argv: list[str], in_scope: set[str], filtered: set[str]
) -> None:
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        assert request.scope is not None
        places = request.scope.paths or (None,)  # each named place is reported (§3)
        return Result(
            Verb.CHECK, checked=tuple(Checked(e, p) for e in sorted(request.scope.ecosystems) for p in places)
        )

    code, out, _ = _run([*argv, "--json"], handlers={Verb.CHECK: handler})
    assert seen[0].scope is not None
    assert {e.value for e in seen[0].scope.ecosystems} == in_scope
    doc = json.loads(out)
    assert {s["ecosystem"] for s in doc["skipped"] if s["reason"] == SkipReason.FILTERED} == filtered
    assert all(not s["in_scope"] for s in doc["skipped"])
    assert code == 0


def test_path_and_repo_filters_are_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        return Result(Verb.CHECK)

    _run(["check", "--repo", "--path", "sub"], handlers={Verb.CHECK: handler})
    scope = seen[0].scope
    assert scope is not None
    assert scope.repo == str(tmp_path)
    assert scope.paths == (str(tmp_path / "sub"),)
    assert scope.ecosystems == frozenset({Ecosystem.GITHUB_ACTIONS})


def test_path_arguments_resolve_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # D18: a place reached through a symlink is the same place, so it gets one spelling and one ID.
    real = tmp_path.resolve() / "real"
    (real / "venv").mkdir(parents=True)
    (tmp_path / "link").symlink_to(real)
    monkeypatch.chdir(tmp_path)
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        return Result(request.verb, checked=(Checked(Ecosystem.PYPI),))

    handlers = {Verb.CHECK: handler, Verb.INSTALL: handler}
    _run(["check", "--path", "link/venv", "--path", str(real / "venv")], handlers=handlers)
    _run(["install", "--venv", "link/venv", "requests"], handlers=handlers)
    check_scope, install = seen[0].scope, seen[1]
    assert check_scope is not None
    assert check_scope.paths == (str(real / "venv"), str(real / "venv"))
    assert install.venv == str(real / "venv")


def test_each_place_argument_is_resolved_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A second read of the file system could disagree with the first and drop a place from scope.
    import ssc_guardian.cli as cli

    calls: list[str] = []
    real_place = cli._place

    def counting(raw: str) -> tuple[str | None, str]:
        calls.append(raw)
        return real_place(raw)

    monkeypatch.setattr(cli, "_place", counting)
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        return Result(Verb.CHECK, checked=(Checked(Ecosystem.GITHUB_ACTIONS),))

    _run(["check", "--path", str(tmp_path / "a"), "--repo", str(tmp_path)], handlers={Verb.CHECK: handler})
    assert sorted(calls) == sorted([str(tmp_path / "a"), str(tmp_path)])
    scope = seen[0].scope
    assert scope is not None
    assert (scope.paths, scope.repo) == ((os.path.realpath(tmp_path / "a"),), os.path.realpath(tmp_path))


@pytest.mark.parametrize("verb", [["check", "--path"], ["install", "--venv"]])
def test_malformed_place_shows_the_resolved_path(
    verb: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A valid name that resolves to a malformed one: the finding names the cause, for every verb.
    (tmp_path / "odd#dir").mkdir()
    (tmp_path / "ok").symlink_to(tmp_path / "odd#dir")
    monkeypatch.chdir(tmp_path)
    called: list[Request] = []

    def handler(request: Request) -> Result:
        called.append(request)
        return Result(request.verb)

    argv = [*verb, "ok", *(["requests"] if verb[0] == "install" else [])]
    code, out, _ = _run(argv, handlers={Verb.CHECK: handler, Verb.INSTALL: handler})
    assert code == 1
    assert called == []
    assert "odd#dir" in out


@pytest.mark.parametrize("verb", [["check", "--path"], ["install", "--venv"]])
def test_malformed_typed_path_is_refused_even_if_it_resolves_to_a_valid_one(
    verb: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The typed name is checked too: a refused character never runs through a symlink.
    (tmp_path / "good").mkdir()
    (tmp_path / "bad#link").symlink_to(tmp_path / "good")
    monkeypatch.chdir(tmp_path)
    called: list[Request] = []

    def handler(request: Request) -> Result:
        called.append(request)
        return Result(request.verb, checked=(Checked(Ecosystem.PYPI),))

    argv = [*verb, "bad#link", *(["requests"] if verb[0] == "install" else [])]
    code, out, _ = _run(argv, handlers={Verb.CHECK: handler, Verb.INSTALL: handler})
    assert code == 1
    assert called == []
    assert "bad#link" in out


@pytest.mark.parametrize(
    ("links", "typed"),
    [
        ({"dang": "missing/../real"}, "dang"),  # dangling: the system cannot open it
        ({"loop": "loop", "loopdd": "loop/../real"}, "loopdd"),  # a loop: the system cannot open it
        ({"dang": "missing/../real"}, "dang/venv"),  # a part under a dangling link
        ({"ln": "afile/../real"}, "ln"),  # a file used as a folder: strict realpath still collapses ".."
        ({"ln": "afile/../real"}, "ln/new"),
        # A chain longer than the kernel follows (32 links on macOS, 40 on Linux).
        ({**{f"c{i}": f"c{i + 1}" for i in range(45)}, "c45": "real"}, "c0"),
        # A chain long enough that realpath itself hits the recursion limit.
        ({**{f"c{i}": f"c{i + 1}" for i in range(1100)}, "c1100": "real"}, "c0"),
    ],
)
def test_a_symlink_the_system_cannot_follow_is_not_guessed(
    links: dict[str, str], typed: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Non-strict realpath would collapse "missing/.." as text and check "real", a place never named.
    base = tmp_path.resolve()
    (base / "real").mkdir()
    (base / "afile").write_text("")
    for name, target in links.items():
        (base / name).symlink_to(target)
    monkeypatch.chdir(base)
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        return Result(request.verb, checked=(Checked(Ecosystem.PYPI),))

    _run(["check", "--path", typed], handlers={Verb.CHECK: handler})
    _run(["install", "--venv", typed, "requests"], handlers={Verb.INSTALL: handler})
    scope = seen[0].scope
    assert scope is not None
    assert scope.paths == (str(base / typed),)
    assert seen[1].venv == str(base / typed)


def test_a_new_venv_under_a_symlink_gets_its_resolved_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path.resolve()
    (base / "real").mkdir()
    (base / "link").symlink_to(base / "real")
    monkeypatch.chdir(base)
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        return Result(request.verb, checked=(Checked(Ecosystem.PYPI),))

    _run(["install", "--venv", "link/new/.venv", "requests"], handlers={Verb.INSTALL: handler})
    assert seen[0].venv == str(base / "real" / "new" / ".venv")


@pytest.mark.parametrize(
    "argv",
    [["check", "--yes"], ["check", "--envs", "--repo"], ["check", "--language", "rust"], ["install", "requests"], []],
)
def test_usage_errors_exit_two(argv: list[str]) -> None:
    assert _run(argv)[0] == 2


def test_install_and_pin_requests_are_parsed() -> None:
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        ecosystem = Ecosystem.PYPI if request.verb is Verb.INSTALL else Ecosystem.GITHUB_ACTIONS
        return Result(request.verb, checked=(Checked(ecosystem),))

    handlers = {Verb.INSTALL: handler, Verb.PIN: handler}
    assert _run(["install", "--venv", "/tmp/v", "requests", "urllib3==2.2.3", "--yes"], handlers=handlers)[0] == 0
    assert _run(["pin", "github/codeql-action/init@v3"], handlers=handlers)[0] == 0
    install, pin = seen
    assert install.venv == os.path.realpath("/tmp/v")  # /private/tmp/v on macOS
    assert install.yes is True
    assert [(r.name, r.version) for r in install.requirements] == [("requests", None), ("urllib3", "2.2.3")]
    assert (pin.action, pin.ref, pin.yes) == ("github/codeql-action/init", "v3", False)


def test_version_flag() -> None:
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "ssc_guardian", "--version"], capture_output=True, text=True, env=env, check=False
    )
    assert proc.returncode == 0
    assert proc.stdout.startswith("ssc-guardian ")


@pytest.mark.parametrize(
    "argv",
    [
        ["check", "--envs", "--ecosystem", "github-actions"],
        ["check", "--repo", ".", "--ecosystem", "pypi"],
        ["check", "--repo", ".", "--language", "python"],
    ],
)
def test_empty_scope_is_a_usage_error(argv: list[str]) -> None:
    with refuses("cli.scope-filters-leave-nothing-check"):
        code, out, err = _run(argv)
    assert code == 2
    assert out == ""
    assert err == "ssc-guardian: the scope and filters leave nothing to check\n"


def test_ecosystem_the_handler_did_not_report_is_unfinished() -> None:
    def partial(request: Request) -> Result:
        return Result(Verb.CHECK, checked=(Checked(Ecosystem.PYPI),))

    for handler in (partial, lambda request: Result(Verb.CHECK)):
        code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
        doc = json.loads(out)
        assert code == doc["exit_code"] == 2
        assert {"ecosystem": "github-actions", "place": None, "reason": "check-error", "in_scope": True} in doc[
            "skipped"
        ]


@pytest.mark.parametrize(
    "returned",
    [None, "ok", Result(Verb.ACKNOWLEDGE), Result(Verb.INSTALL)],
)
def test_handler_returning_the_wrong_thing_exits_two(returned: object) -> None:
    def handler(request: Request) -> Any:
        return returned

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
    assert code == json.loads(out)["exit_code"] == 2


def test_malformed_value_inside_a_handler_is_a_violation() -> None:
    def handler(request: Request) -> Result:
        Item(Ecosystem.PYPI, "bad name", "1.0", "/Users/dev/.venv")
        return Result(Verb.INSTALL)

    code, out, _ = _run(["install", "--venv", "/tmp/v", "requests", "--json"], handlers={Verb.INSTALL: handler})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 1
    assert [(f["rule"], f["malformed_field"]) for f in doc["findings"]] == [("malformed-name", "item")]
    assert "bad name" not in out


def test_render_failure_exits_two_with_a_fixed_message() -> None:
    class Closed(io.StringIO):
        def write(self, text: str) -> int:
            raise BrokenPipeError

    err = io.StringIO()
    # A stub handler: since #10, the real check --repo would read this repository and ask GitHub.
    handlers = {Verb.CHECK: lambda request: Result(Verb.CHECK, checked=(Checked(Ecosystem.GITHUB_ACTIONS),))}
    assert main(["check", "--repo"], handlers=handlers, stdout=Closed(), stderr=err, environ={}) == 2
    assert "could not write output (BrokenPipeError)" in err.getvalue()


def test_unencodable_output_is_escaped_not_a_crash() -> None:
    record = replace(full_result().overrides_applied[0], reason="accepted by the caf\u00e9 team")

    def handler(request: Request) -> Result:
        return Result(
            Verb.CHECK, checked=tuple(Checked(e, SAMPLE_REPO) for e in Ecosystem), overrides_applied=(record,)
        )

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii")
    code = main(["check", *NAMED], handlers={Verb.CHECK: handler}, stdout=stream, stderr=io.StringIO(), environ={})
    assert code == 0
    assert b"reason: accepted by the caf\\xe9 team" in raw.getvalue()


def test_usage_error_strips_control_characters() -> None:
    code, _, err = _run(["check", "\x1b]0;pwned\x07"])
    assert code == 2
    assert "unrecognized arguments" in err
    assert "\x1b" not in err
    assert "\x07" not in err


def test_handler_calling_sys_exit_zero_exits_two() -> None:
    def handler(request: Request) -> Result:
        sys.exit(0)

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert all(s["reason"] in {"check-error"} for s in doc["skipped"])


def test_handler_cannot_mark_an_in_scope_ecosystem_out_of_scope() -> None:
    def handler(request: Request) -> Result:
        return Result(Verb.CHECK, skipped=tuple(Skip(e, None, SkipReason.FILTERED) for e in Ecosystem))

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert doc["summary"]["skipped_in_scope"] == 3  # both ecosystems and the named path


@pytest.mark.parametrize(
    ("argv", "ecosystems"),
    [
        (["check", "--path", "/tmp"], {"pypi", "github-actions"}),
        (["check", "--envs", "--path", "/tmp"], {"pypi"}),
        (["check", "--repo", "/tmp"], {"github-actions"}),
        (["check", "--language", "python", "--path", "/tmp"], {"pypi"}),
        (
            ["check", "--ecosystem", "pypi", "--ecosystem", "github-actions", "--path", "/tmp"],
            {"pypi", "github-actions"},
        ),
    ],
)
def test_no_check_request_carries_a_default_scope(argv: list[str], ecosystems: set[str]) -> None:
    # #255 (replacing #68's default scope): only the arguments choose what is checked; a request
    # has no default-scope flag for a setting to narrow (contracts §2, §10.2).
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        assert request.scope is not None
        places = request.scope.paths or (None,)
        return Result(Verb.CHECK, checked=tuple(Checked(e, p) for e in request.scope.ecosystems for p in places))

    code, _, _ = _run([*argv, "--json"], handlers={Verb.CHECK: handler})
    assert code == 0
    assert "default_scope" not in {f.name for f in dataclasses.fields(Request)}
    assert seen[0].scope is not None and {e.value for e in seen[0].scope.ecosystems} == ecosystems


_OUT_OF_SCOPE_REASONS = [r for r in SkipReason if not r.in_scope]


@pytest.mark.parametrize("reason", _OUT_OF_SCOPE_REASONS)
@pytest.mark.parametrize(
    "argv",
    [
        ["check", *NAMED],
        ["check", "--ecosystem", "github-actions", *NAMED],
        ["check", "--ecosystem", "pypi", "--ecosystem", "github-actions", *NAMED],
        ["check", "--repo", "/tmp"],
    ],
)
def test_out_of_scope_skip_never_reports_an_area(argv: list[str], reason: SkipReason) -> None:
    # Negative: a handler's out-of-scope skip never reports the area, so an area that is not
    # checked never passes. #282 removed `default-scope` (no run applies a default scope since
    # #255); every reason left out of scope is held to the same rule.
    def handler(request: Request) -> Result:
        return Result(
            Verb.CHECK,
            checked=(Checked(Ecosystem.PYPI, SAMPLE_REPO),),
            skipped=(Skip(Ecosystem.GITHUB_ACTIONS, None, reason),),
        )

    code, out, _ = _run([*argv, "--json"], handlers={Verb.CHECK: handler})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    unreported = {"ecosystem": "github-actions", "place": None, "reason": "check-error", "in_scope": True}
    assert unreported in doc["skipped"]


@pytest.mark.parametrize("reason", _OUT_OF_SCOPE_REASONS)
def test_out_of_scope_skip_never_reports_a_path(reason: SkipReason) -> None:
    # A --path value must still be reported by an in-scope check (§3), never by an out-of-scope skip.
    def handler(request: Request) -> Result:
        assert request.scope is not None
        (path,) = request.scope.paths
        return Result(
            Verb.CHECK,
            checked=(Checked(Ecosystem.PYPI),),
            skipped=(Skip(Ecosystem.GITHUB_ACTIONS, path, reason),),
        )

    code, out, _ = _run(["check", "--path", "/tmp", "--json"], handlers={Verb.CHECK: handler})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert any(s["reason"] == "check-error" and s["ecosystem"] is None for s in doc["skipped"])


def test_parser_failure_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreadable() -> str:
        raise PermissionError

    monkeypatch.setattr("ssc_guardian.cli.tool_version", unreadable)
    code, out, err = _run(["check"])
    assert (code, out) == (2, "")
    assert "internal error (PermissionError)" in err


@pytest.mark.parametrize(
    "argv",
    [
        ["install", "--venv", "", "requests"],
        ["check", "--repo", ""],
        ["check", "--path", ""],
        ["check", "--path", "/tmp/a/../etc"],
        ["install", "--venv", "../other/.venv", "requests"],
    ],
)
def test_empty_or_dot_dot_path_is_refused_not_guessed(argv: list[str]) -> None:
    called: list[Request] = []

    def handler(request: Request) -> Result:
        called.append(request)
        return Result(request.verb)

    code, out, _ = _run([*argv, "--json"], handlers={verb: handler for verb in Verb})
    assert code == 1
    assert called == []
    (finding,) = json.loads(out)["findings"]
    assert (finding["rule"], finding["malformed_field"]) == ("malformed-name", "place")


@pytest.mark.parametrize(
    "argv", [["install", "--venv", "/tmp/v", "foo"], ["pin", "a/b@v1"], ["protect", "--path", "/tmp/v"]]
)
def test_every_verb_must_report_its_area(argv: list[str]) -> None:
    def silent(request: Request) -> Result:
        return Result(request.verb)

    def out_of_scope(request: Request) -> Result:
        return Result(request.verb, skipped=tuple(Skip(e, None, SkipReason.FILTERED) for e in Ecosystem))

    for handler in (silent, out_of_scope):
        code, out, _ = _run([*argv, "--json"], handlers={verb: handler for verb in Verb})
        doc = json.loads(out)
        assert code == doc["exit_code"] == 2
        assert any(s["reason"] == "check-error" and s["in_scope"] for s in doc["skipped"])


@pytest.mark.parametrize("error", [asyncio.CancelledError(), GeneratorExit(), SystemExit(1)])
def test_base_exceptions_from_a_handler_exit_two(error: BaseException) -> None:
    def handler(request: Request) -> Result:
        raise error

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
    assert code == json.loads(out)["exit_code"] == 2


def test_keyboard_interrupt_is_left_to_python() -> None:
    def handler(request: Request) -> Result:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):  # Python's own interrupt: no Guardian message
        _run(["check", *NAMED], handlers={Verb.CHECK: handler})


@pytest.mark.parametrize("argv", [["check", "--h"], ["check", "--env"], ["install", "--ven", "/tmp/v", "x"]])
def test_abbreviated_options_are_usage_errors(argv: list[str]) -> None:
    assert _run(argv)[0] == 2


def test_malformed_value_text_is_escaped_not_hidden() -> None:
    code, out, _ = _run(["acknowledge", "evil/x\u202e"])
    assert code == 1
    assert "malformed item: evil/x\\u202e" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["check", "--envs", "--ecosystem", "github-actions"],
        ["acknowledge", "a/b", "--yes"],
        ["check", "--bogus"],
    ],
)
def test_closed_stderr_keeps_exit_two(
    argv: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stderr", None)  # what Python sets when fd 2 is closed at start
    out = io.StringIO()
    assert main(argv, stdout=out, environ={}) == 2
    assert out.getvalue() == ""
    assert capsys.readouterr().out == ""  # argparse must not fall back to stdout


def test_closed_stderr_in_a_real_process() -> None:
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "ssc_guardian", "check", "--envs", "--ecosystem", "github-actions"],
        capture_output=False,
        stdout=subprocess.DEVNULL,
        env=env,
        check=False,
        preexec_fn=lambda: os.close(2),
    )
    assert proc.returncode == 2


def test_one_shot_findings_iterator_still_exits_one() -> None:
    finding = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place="/v/.venv", item="requests", version="2.32.4")

    def handler(request: Request) -> Result:
        one_shot: Any = (f for f in [finding])  # what an untyped handler could pass
        return Result(Verb.CHECK, findings=one_shot, checked=tuple(Checked(e) for e in Ecosystem))

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 1
    assert doc["summary"]["violations"] == len(doc["findings"]) == 1


def test_wrong_element_type_in_a_result_exits_two() -> None:
    def handler(request: Request) -> Result:
        not_findings: Any = ("a violation, honestly",)
        return Result(Verb.CHECK, findings=not_findings)

    code, out, _ = _run(["check", *NAMED, "--json"], handlers={Verb.CHECK: handler})
    assert code == json.loads(out)["exit_code"] == 2


@pytest.mark.parametrize(("raw", "expected"), [("//tmp/v", "/tmp/v"), ("///tmp/v/", "/tmp/v"), ("/tmp//v", "/tmp/v")])
def test_doubled_slashes_name_one_place(raw: str, expected: str) -> None:
    seen: list[Request] = []

    def handler(request: Request) -> Result:
        seen.append(request)
        return Result(Verb.INSTALL, checked=(Checked(Ecosystem.PYPI),))

    code, _, _ = _run(["install", "--venv", raw, "requests"], handlers={Verb.INSTALL: handler})
    assert code == 0
    assert seen[0].venv == os.path.realpath(expected)  # /private/tmp/v on macOS


@pytest.mark.parametrize(
    ("stream", "argv"),
    [
        ("stdout", ["check", "--repo", "--json"]),
        ("stdout", ["check", "--repo"]),
        ("stderr", ["check", "--repo", ".", "--ecosystem", "pypi"]),
        ("stderr", ["check", "--bogus"]),
        ("stderr", ["override", "add", "--yes"]),
    ],
)
def test_broken_pipe_keeps_exit_two(stream: str, argv: list[str]) -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)  # every write to write_end now fails with EPIPE
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    pipes = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, stream: write_end}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ssc_guardian", *argv],
            stdout=pipes["stdout"],
            stderr=pipes["stderr"],
            env=env,
            check=False,
        )
    finally:
        os.close(write_end)
    assert proc.returncode == 2


@pytest.mark.parametrize("language", ["rust", "javascript", "Python"])
def test_unsupported_language_is_refused_with_the_supported_ones_named(language: str) -> None:
    # D11: refused (exit 2), never skipped, and the message says what is supported.
    code, out, err = _run(["check", "--language", language])
    assert (code, out) == (2, "")
    assert "this version checks python" in err
    assert "--repo" in err


def test_handler_result_with_duplicate_ids_is_an_unfinished_run() -> None:
    # D14: two findings with one ID are never merged silently.
    def handler(request: Request) -> Result:
        twin = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place="/tmp/v", item="requests", version="1.0")
        other = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place="/tmp/v", item="REQUESTS", version="1.0")
        return Result(Verb.CHECK, findings=(twin, other), checked=(Checked(Ecosystem.PYPI),))

    code, out, _ = _run(["check", "--envs", "--json"], handlers={Verb.CHECK: handler})
    assert code == 2


def test_install_is_wired_and_refuses_a_path_that_is_not_a_venv(tmp_path: Path) -> None:
    # Issue #6: the default handler is the checked install; its tests drive it in real venvs
    # (test_install_venv). A path that is not a venv is refused with the fix (exit 2).
    from ssc_guardian.commands import install

    assert DEFAULT_HANDLERS[Verb.INSTALL] is install.handle
    err = io.StringIO()
    (tmp_path / "home").mkdir()
    handler = install.Install(home=str(tmp_path / "home"), environ={"PATH": ""}, stderr=err)
    code, out, _ = _run(["install", "--venv", str(tmp_path), "requests", "--json"], handlers={Verb.INSTALL: handler})
    assert code == json.loads(out)["exit_code"] == 2
    assert "is not a venv: Guardian installs into venvs only; create a venv and install there" in err.getvalue()


def test_pin_is_wired_and_writes_nothing_outside_a_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Issue #9: the default handler is pin's; outside a Git repository it asks GitHub nothing,
    # writes nothing and exits 2 (its tests drive it with a fixture client, test_pin_command).
    from ssc_guardian.commands import pin

    assert DEFAULT_HANDLERS[Verb.PIN] is pin.handle
    monkeypatch.chdir(tmp_path)
    code, out, _ = _run(["pin", "actions/checkout@v4", "--yes", "--json"])
    assert code == json.loads(out)["exit_code"] == 2
    assert [s["reason"] for s in json.loads(out)["skipped"]] == ["check-error"]
    assert "pin works inside a Git repository" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_acknowledge_is_wired_and_no_verb_is_left_unbuilt() -> None:
    # Issue #10: acknowledge was the last verb on the not-available handler.
    from ssc_guardian.cli import not_available

    assert DEFAULT_HANDLERS[Verb.ACKNOWLEDGE] is acknowledge.handle
    assert [verb for verb, handler in DEFAULT_HANDLERS.items() if handler is not_available] == []


# --- override add's KEV lookup (#42) ----------------------------------------------

KEV_ANSWERS = ["pypi", "pkg", "1.0", "known-vulnerability", "CVE-2026-1111", "accepted-risk"]


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _override_add(tmp_path: Path, transport: Recorder, answers: list[str]) -> tuple[int, str]:
    """The real CLI's override add, its KEV lookup over a fake CISA feed."""
    default = DEFAULT_HANDLERS[Verb.OVERRIDE_ADD]
    assert isinstance(default, OverrideAdd) and default.kev_lookup == KevCatalogLookup()
    err = io.StringIO()
    handler = replace(
        default,
        stdin=_Terminal("".join(a + "\n" for a in answers)),
        stderr=err,
        home=str(tmp_path),
        today=date(2026, 11, 3),
        kev_lookup=KevCatalogLookup(client(transport)),
    )
    code, _, _ = _run(["override", "add"], handlers={Verb.OVERRIDE_ADD: handler})
    return code, err.getvalue()


def _catalog(*cves: str) -> Any:
    records = [{"cveID": c, "dateAdded": "2026-10-01"} for c in cves]
    return reply(200, {"count": len(records), "vulnerabilities": records})


def test_override_add_kev_warning_fires_with_a_listed_advisory(tmp_path: Path) -> None:
    # §10.4 step 3: a KEV-listed advisory gets the 7-day limit and the typed confirmation.
    listed = Recorder().route(CATALOG_URL, _catalog("CVE-2026-1111"))
    code, err = _override_add(tmp_path, listed, [*KEV_ANSWERS, "2026-11-11", "2026-11-10", "r", "y", "CVE-2026-1111"])
    assert code == 0, err
    assert "Expiry (YYYY-MM-DD, at most 7 days from today)" in err and "not accepted: at most 7 days" in err
    assert "WARNING: CVE-2026-1111 is in CISA's Known Exploited Vulnerabilities" in err
    assert [s.url for s in listed.sent] == [CATALOG_URL]
    # Control: not listed, so 90 days and no second warning.
    other = Recorder().route(CATALOG_URL, _catalog("CVE-2026-2222"))
    code, err = _override_add(tmp_path / "other", other, [*KEV_ANSWERS, "2026-12-01", "r", "y"])
    assert code == 0, err
    assert "Expiry (YYYY-MM-DD, at most 90 days from today)" in err
    assert "WARNING" not in err and "unknown" not in err


@pytest.mark.parametrize(
    ("answers", "said"),
    [
        (["bad", *KEV_ANSWERS, "2026-12-01", "r", "y"], "not accepted: answer one of: pypi, github-actions"),
        ([*KEV_ANSWERS, "2026-11-02", "2026-12-01", "r", "y"], "not accepted: the date is in the past"),
    ],
)
def test_override_add_asks_again_after_an_answer_it_refuses(tmp_path: Path, answers: list[str], said: str) -> None:
    transport = Recorder().route(CATALOG_URL, _catalog("CVE-2026-2222"))
    code, err = _override_add(tmp_path, transport, answers)
    assert code == 0, err
    assert said in err


@pytest.mark.parametrize(
    "failure", [TimeoutError("timed out"), reply(500), reply(200, {"count": 2, "vulnerabilities": []})]
)
def test_override_add_kev_feed_error_is_unknown(tmp_path: Path, failure: Any) -> None:
    # A KEV feed error is unknown, never "not listed": the person is told the override ends
    # 7 days after it was written if the advisory is KEV-listed.
    code, err = _override_add(tmp_path, Recorder().route(CATALOG_URL, failure), [*KEV_ANSWERS, "2026-12-01", "r", "y"])
    assert code == 0, err
    assert "KEV status of CVE-2026-1111 is unknown: if it is KEV-listed, this override ends 7 days after" in err
    assert KevCatalogLookup(client(Recorder().route(CATALOG_URL, failure)))("CVE-2026-1111") is None


GHSA = "GHSA-2222-3333-4444"
GHSA_ANSWERS = [*KEV_ANSWERS[:4], GHSA, "accepted-risk"]


def _osv(vid: str, *aliases: str) -> Any:
    return reply(200, {"id": vid, "aliases": list(aliases), "affected": []})


def test_override_add_warns_for_a_ghsa_of_a_kev_cve(tmp_path: Path) -> None:
    # #70: KEV lists CVEs, so a GHSA or PYSEC reference is looked up in OSV and checked over
    # its advisory's aliases: a GHSA of a KEV-listed CVE gets the 7-day limit and the warning.
    listed = (
        Recorder().route(CATALOG_URL, _catalog("CVE-2026-1111")).route(osv.VULN_URL + GHSA, _osv(GHSA, "CVE-2026-1111"))
    )
    code, err = _override_add(tmp_path, listed, [*GHSA_ANSWERS, "2026-11-11", "2026-11-10", "r", "y", GHSA])
    assert code == 0, err
    assert "Expiry (YYYY-MM-DD, at most 7 days from today)" in err and "not accepted: at most 7 days" in err
    assert f"WARNING: {GHSA} is in CISA's Known Exploited Vulnerabilities" in err
    assert [s.url for s in listed.sent] == [osv.VULN_URL + GHSA, CATALOG_URL]
    # A PYSEC record's aliases count the same way.
    pysec = "PYSEC-2026-7"
    both = Recorder().route(CATALOG_URL, _catalog("CVE-2026-2222"))
    both.route(osv.VULN_URL + pysec, _osv(pysec, "CVE-2026-1111", "CVE-2026-2222"))
    assert KevCatalogLookup(client(both))(pysec) is True
    # Control: an alias that is not KEV-listed gives 90 days and no second warning.
    other = (
        Recorder().route(CATALOG_URL, _catalog("CVE-2026-2222")).route(osv.VULN_URL + GHSA, _osv(GHSA, "CVE-2026-1111"))
    )
    code, err = _override_add(tmp_path / "other", other, [*GHSA_ANSWERS, "2026-12-01", "r", "y"])
    assert code == 0, err
    assert "Expiry (YYYY-MM-DD, at most 90 days from today)" in err
    assert "WARNING" not in err and "unknown" not in err


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("timed out"),
        reply(500),
        reply(429),
        reply(200, {"id": "GHSA-5555-6666-7777", "aliases": []}),  # not the record asked for
        reply(200, {"id": GHSA, "withdrawn": "2026-10-01T00:00:00Z", "affected": []}),
    ],
)
def test_override_add_kev_lookup_error_is_unknown(tmp_path: Path, failure: Any) -> None:
    # #70: when the reference's aliases cannot be read, its KEV status is unknown, never
    # "not listed", even though the catalog itself is readable.
    transport = Recorder().route(CATALOG_URL, _catalog("CVE-2026-1111")).route(osv.VULN_URL + GHSA, failure)
    code, err = _override_add(tmp_path, transport, [*GHSA_ANSWERS, "2026-12-01", "r", "y"])
    assert code == 0, err
    assert f"KEV status of {GHSA} is unknown: if it is KEV-listed, this override ends 7 days after" in err
    assert "WARNING" not in err


# --- leftover contract findings (#26) --------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "wanted"),
    [
        (["--help"], 0),
        (["-h"], 0),
        (["--version"], 0),
        (["check", "--help"], 2),
        (["check", "-h"], 2),
        (["--version", "check"], 2),
        (["--help", "check"], 2),
        (["override", "add", "--help"], 2),
        (["check", "--json", "-h"], 2),
        (["install", "--version"], 2),
    ],
)
def test_help_after_verb_is_handled_as_decided(argv: list[str], wanted: int) -> None:
    # §2 (owner's ruling, 2026-11-03): help and version exit 0 only as the whole command line,
    # so "check --help" in a CI gate never passes with nothing checked.
    called: list[Request] = []

    def handler(request: Request) -> Result:
        called.append(request)
        return Result(request.verb, checked=tuple(Checked(e) for e in Ecosystem))

    code, out, err = _run(argv, handlers=dict.fromkeys(Verb, handler))
    assert (code, called) == (wanted, [])
    if wanted == 2 and "--version" not in argv:
        assert out.startswith("usage: ssc-guardian")  # the text still prints
        assert "exit 0 only on their own; nothing was checked" in err


def test_usage_text_goes_to_injected_streams(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(["--help"])
    assert (code, err) == (0, "") and out.startswith("usage: ssc-guardian [-h] [--version] command")
    code, out, err = _run(["install", "-h"])
    assert code == 2 and out.startswith("usage: ssc-guardian install")
    for argv in (["check", "--bogus"], ["install", "requests"], ["override"], []):
        code, out, err = _run(argv)
        assert (code, out) == (2, "")
        assert err.startswith("usage: ssc-guardian") and "error:" in err
    assert capsys.readouterr() == ("", "")  # nothing reached the process's own streams


# --- the help text follows contracts §2 (#177, #180) -------------------------------------

_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


def _section_2_rows(text: str) -> dict[str, dict[str, str]]:
    """The command table of contracts §2, read from ``text``: each row's command cell, without
    its backticks, mapped to that row's cells by column header.

    Raises LookupError when §2 or its table is missing, or a row is short or doubled, so a test
    built on it fails rather than passes on nothing.
    """
    section = re.search(r"^## 2\. Commands\b.*?(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    if section is None:
        raise LookupError("contracts §2 (## 2. Commands) not found")
    lines = [line.strip() for line in section.group().splitlines() if line.startswith("|")]
    table = [[cell.strip() for cell in _UNESCAPED_PIPE.split(line)[1:-1]] for line in lines]
    if len(table) < 3 or table[0][:1] != ["Command"] or not set("".join(table[1])) <= set("-: "):
        raise LookupError("contracts §2 has no command table")
    header, rows = table[0], {}
    for cells in table[2:]:
        command = cells[0].strip("`")
        if len(cells) != len(header) or command in rows:
            raise LookupError(f"contracts §2 row {command!r} is short or doubled")
        rows[command] = dict(zip(header, cells, strict=True))
    return rows


def _pin_form_in_contracts(text: str) -> str:
    """The argument form of the one ``pin`` row in contracts §2, read from ``text``.

    Raises LookupError when §2 or its ``pin`` row is missing or doubled, so a test built on it
    fails rather than passes on nothing.
    """
    forms = [command.removeprefix("pin ") for command in _section_2_rows(text) if command.startswith("pin ")]
    if len(forms) != 1:
        raise LookupError(f"contracts §2 has {len(forms)} pin rows, not one")
    return forms[0]


def _pin_help_form(out: str) -> str:
    """The argument form ``pin --help`` prints for ``action``; LookupError when it is absent."""
    lines: list[str] = re.findall(r"^ +action +(\S+) *$", out, re.MULTILINE)
    if len(lines) != 1:
        raise LookupError(f"pin --help shows {len(lines)} action lines, not one")
    return lines[0]


def test_pin_help_shows_the_ref_as_required() -> None:
    code, out, err = _run(["pin", "--help"])
    assert code == 2  # §2: help after a verb still exits 2
    assert out.startswith("usage: ssc-guardian pin")
    assert "exit 0 only on their own; nothing was checked" in err
    assert _pin_help_form(out) == "OWNER/REPO[/PATH]@REF"
    assert "[@REF]" not in out


@pytest.mark.doc_content
def test_pin_help_matches_contracts_section_2() -> None:
    contracts = (REPO / "docs" / "contracts.md").read_text(encoding="utf-8")
    _, out, _ = _run(["pin", "--help"])
    assert _pin_help_form(out) == _pin_form_in_contracts(contracts)
    # Error path: §2 without its pin row is a failure, never a pass by default.
    without_row = re.sub(r"^\| `pin [^\n]*\n", "", contracts, flags=re.MULTILINE)
    assert without_row != contracts
    with pytest.raises(LookupError, match="0 pin rows"):
        _pin_form_in_contracts(without_row)
    with pytest.raises(LookupError, match="not found"):
        _pin_form_in_contracts(contracts.replace("## 2. Commands", "## 2. Verbs"))


def test_pin_help_is_idempotent_on_re_run() -> None:
    first, second = _run(["pin", "--help"]), _run(["pin", "--help"])
    assert first == second
    assert first[0] == 2


_HELP_FLAGS = ("--yes", "--json")


def _help_flags_in_contracts(text: str) -> dict[Verb, dict[str, bool]]:
    """For each command, whether contracts §2 lets its help list ``--yes`` and ``--json``: a
    ``yes`` cell lists the flag; a refusal or a ``not accepted`` cell hides it.

    Raises LookupError when a command has no row or two, a row names no command, or a cell
    says anything else, so a change on either side fails rather than passes by default.
    """
    expected: dict[Verb, dict[str, bool]] = {}
    for command, cells in _section_2_rows(text).items():
        words = re.match(r"[a-z]+(?: [a-z]+)*", command)
        try:
            verb = Verb(words.group() if words else command)
        except ValueError:
            raise LookupError(f"contracts §2 row {command!r} names no command") from None
        if verb in expected:
            raise LookupError(f"contracts §2 has two rows for {verb.value}")
        expected[verb] = {}
        for flag in _HELP_FLAGS:
            cell = cells.get(f"`{flag}`")
            if cell == "yes":
                expected[verb][flag] = True
            elif cell is not None and cell.startswith(("**refused**", "not accepted")):
                expected[verb][flag] = False
            else:
                raise LookupError(f"contracts §2 {verb.value} {flag} cell is {cell!r}")
    missing = sorted(verb.value for verb in Verb if verb not in expected)
    if missing:
        raise LookupError(f"contracts §2 has no row for {missing}")
    return expected


def _help_flags(verb: Verb) -> dict[str, bool]:
    """Whether ``<verb> --help`` lists ``--yes`` and ``--json``, anywhere in its text."""
    code, out, _ = _run([*verb.value.split(), "--help"])
    assert code == 2  # §2: help after a verb still exits 2
    assert out.startswith(f"usage: ssc-guardian {verb.value}")
    return {flag: re.search(rf"(?<![\w-]){flag}(?![\w-])", out) is not None for flag in _HELP_FLAGS}


def test_exception_command_help_hides_refused_flags() -> None:
    # #180: the help never offers a flag the command refuses (contracts §2, D2).
    for verb in (Verb.ACKNOWLEDGE, Verb.OVERRIDE_ADD):
        assert _help_flags(verb) == {"--yes": False, "--json": False}
        out = _run([*verb.value.split(), "--help"])[1]
        assert "confirm the shown change in advance" not in out
        assert "JSON output" not in out
    # The check sees a listed flag: a writing command's help lists both.
    assert _help_flags(Verb.PIN) == {"--yes": True, "--json": True}


@pytest.mark.parametrize("flag", _HELP_FLAGS)
@pytest.mark.parametrize("verb", [Verb.ACKNOWLEDGE, Verb.OVERRIDE_ADD])
def test_refused_flags_still_refuse_by_name(verb: Verb, flag: str, tmp_path: Path) -> None:
    # #180: hidden from the help, still parsed and refused by name, before any handler runs.
    # The real handlers sit behind a recorder, kept to the temporary home and repository with
    # a terminal that answers and no network; none is called and nothing appears there.
    repo = tmp_path.resolve() / "repo"
    (repo / ".git").mkdir(parents=True)

    def offline(request: object, timeout: float, limit: int) -> NoReturn:
        raise OSError("no network in tests")

    offline_client = Client(transport=offline)
    default = DEFAULT_HANDLERS[Verb.OVERRIDE_ADD]
    assert isinstance(default, OverrideAdd)
    handlers: dict[Verb, Any] = {
        Verb.ACKNOWLEDGE: acknowledge.Acknowledge(
            stdin=_Terminal("y\n"), stderr=io.StringIO(), cwd=str(repo), home=str(tmp_path), client=offline_client
        ),
        Verb.OVERRIDE_ADD: replace(
            default,
            stdin=_Terminal("".join(a + "\n" for a in KEV_ANSWERS)),
            stderr=io.StringIO(),
            cwd=str(repo),
            home=str(tmp_path),
            kev_lookup=KevCatalogLookup(offline_client),
        ),
    }
    called: list[Verb] = []

    def recording(handler: Any) -> Any:
        def run(request: Request) -> Result:
            called.append(request.verb)
            result: Result = handler(request)
            return result

        return run

    argv = ["acknowledge", "someone/new-action"] if verb is Verb.ACKNOWLEDGE else ["override", "add"]
    before = sorted(tmp_path.rglob("*"))
    code, out, err = _run([*argv, flag], handlers={v: recording(h) for v, h in handlers.items()})
    assert called == []  # refused before any handler runs
    assert (code, out) == (2, "")
    assert err == (
        f"ssc-guardian: {verb.value} refuses {flag}: a person confirms it at a terminal, and its output is text only.\n"
    )
    assert sorted(tmp_path.rglob("*")) == before  # nothing written


@pytest.mark.doc_content
def test_help_flags_match_contracts_section_2() -> None:
    # #180: every command's help lists --yes and --json exactly where §2 allows them.
    contracts = (REPO / "docs" / "contracts.md").read_text(encoding="utf-8")
    assert {verb: _help_flags(verb) for verb in Verb} == _help_flags_in_contracts(contracts)
    # Error path: a missing table, row or cell is a failure, never a pass by default.
    without_row = re.sub(r"^\| `acknowledge [^\n]*\n", "", contracts, flags=re.MULTILINE)
    assert without_row != contracts
    with pytest.raises(LookupError, match=r"no row for \['acknowledge'\]"):
        _help_flags_in_contracts(without_row)
    without_header = re.sub(r"^\| Command \|[^\n]*\n", "", contracts, flags=re.MULTILINE)
    assert without_header != contracts
    with pytest.raises(LookupError, match="no command table"):
        _help_flags_in_contracts(without_header)
    with pytest.raises(LookupError, match="not found"):
        _help_flags_in_contracts(contracts.replace("## 2. Commands", "## 2. Verbs"))
    unknown_cell = contracts.replace("| **refused** (exit 2) |", "| maybe |", 1)
    assert unknown_cell != contracts
    with pytest.raises(LookupError, match="cell is 'maybe'"):
        _help_flags_in_contracts(unknown_cell)
    pin_row = re.search(r"^\| `pin [^\n]*\n", contracts, re.MULTILINE)
    assert pin_row is not None
    for row, said in (
        ("| `check` | | yes | yes |", "'check' is short or doubled"),
        ("| `frobnicate` |", "'frobnicate' is short or doubled"),
        ("| `frobnicate` | | yes | yes |", "'frobnicate' names no command"),
        ("| `pin OWNER/REPO` | | yes | yes |", "two rows for pin"),
    ):
        extra = contracts[: pin_row.end()] + row + "\n" + contracts[pin_row.end() :]
        with pytest.raises(LookupError, match=said):
            _help_flags_in_contracts(extra)


def test_help_is_idempotent_on_re_run() -> None:
    for verb in Verb:
        argv = [*verb.value.split(), "--help"]
        first, second = _run(argv), _run(argv)
        assert first == second
        assert first[0] == 2


def test_fix_command_venv_with_space_is_handled_as_decided(tmp_path: Path) -> None:
    # §6 (owner's ruling, 2026-11-03): a space is allowed in a venv path, and a fix command is an
    # argument list, so the path stays one element; joined, it would split into venv and package.
    venv = str(tmp_path.resolve() / "a b" / ".venv")

    def handler(request: Request) -> Result:
        assert request.venv is not None
        fix = Option(
            OptionKind.REPLACE, "requests", "2.32.4", command=install_command(request.venv, "requests", "2.32.4")
        )
        finding = make_finding(
            Rule.KNOWN_VULNERABILITY, Ecosystem.PYPI, place=request.venv, item="requests", version="2.32.3",
            evidence=("CVE-2024-35195",), options=(fix,),
        )  # fmt: skip
        return Result(Verb.INSTALL, findings=(finding,), checked=(Checked(Ecosystem.PYPI, request.venv),))

    handlers = {Verb.INSTALL: handler}
    code, out, _ = _run(["install", "--venv", venv, "requests==2.32.3", "--json"], handlers=handlers)
    assert code == 1
    (command,) = [o["command"] for f in json.loads(out)["findings"] for o in f["options"]]
    assert command == ["ssc-guardian", "install", "--venv", venv, "requests==2.32.4"]
    assert shlex.split(" ".join(command)) != command  # the planted hazard: joining splits the path
    code, out, _ = _run(["install", "--venv", venv, "requests==2.32.3"], handlers=handlers)
    assert code == 1
    assert shlex.join(command) in out  # text output quotes it, so a copy runs as one argument


def test_unreported_path_is_unfinished(tmp_path: Path) -> None:
    # §3 (owner's ruling, 2026-11-03): each --path value must be reported by an in-scope ecosystem.
    a, b = str(tmp_path.resolve() / "a"), str(tmp_path.resolve() / "b")
    pypi, gha = Ecosystem.PYPI, Ecosystem.GITHUB_ACTIONS
    filtered = Skip(gha, b, SkipReason.FILTERED)  # an out-of-scope skip does not report b
    cases: list[tuple[list[str], tuple[Checked | Skip, ...], set[str]]] = [
        ([], (Checked(pypi), Checked(gha)), {a, b}),  # a handler that ignored every path
        ([], (Checked(pypi, a + "/venv"), Checked(gha)), {b}),  # one that ignored the second
        ([], (Checked(pypi, a + "b"), Checked(gha, b + "x")), {a, b}),  # a prefix is not inside
        (["--envs"], (Checked(pypi, a), Checked(gha, b)), {b}),  # GitHub Actions is out of scope
        (["--envs"], (Checked(pypi, a), filtered), {b}),
        ([], (Checked(pypi, a), Skip(gha, b + "/w.yml", SkipReason.CHECK_ERROR)), set()),
        ([], (Checked(pypi, a + "/venv"), Checked(gha, b)), set()),
    ]
    for scope, entries, unreported in cases:

        def handler(request: Request, entries: tuple[Checked | Skip, ...] = entries) -> Result:
            checked = tuple(e for e in entries if isinstance(e, Checked))
            return Result(Verb.CHECK, checked=checked, skipped=tuple(e for e in entries if isinstance(e, Skip)))

        code, out, _ = _run(["check", *scope, "--path", a, "--path", b, "--json"], handlers={Verb.CHECK: handler})
        doc = json.loads(out)
        missing = [s for s in doc["skipped"] if s["ecosystem"] is None]
        assert missing == [
            {"ecosystem": None, "place": p, "reason": "check-error", "in_scope": True} for p in sorted(unreported)
        ], entries
        if unreported:
            assert code == doc["exit_code"] == 2
        elif not any(isinstance(e, Skip) and e.in_scope for e in entries):
            assert code == 0


def test_unreported_path_is_unfinished_through_the_actions_handler(tmp_path: Path) -> None:
    # The real check --repo: a --path that matched a workflow is reported; a typo is not (exit 2).
    github = GitHub()
    github.publisher("t1/clean", 101, files={(sha(10), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"t1/clean@{sha(10)}", lock=[listed("t1/clean", sha(10), "v1")])
    workflows, typo = str(root / ".github" / "workflows"), str(root / ".github" / "workflow")

    def run(*paths: str) -> tuple[int, dict[str, Any]]:
        handler = check_envs.CheckEnvs(
            home=str(tmp_path / "home"), environ={}, today=TODAY, client=github.client(), stderr=io.StringIO()
        )
        argv = ["check", "--repo", str(root), *(x for p in paths for x in ("--path", p)), "--json"]
        code, out, _ = _run(argv, handlers={Verb.CHECK: handler})
        return code, json.loads(out)

    code, doc = run(workflows)
    assert code == 0
    assert doc["checked"] == [
        {"ecosystem": "github-actions", "place": workflows},
        {"ecosystem": "github-actions", "place": str(root)},
    ]
    code, doc = run(workflows, typo)
    assert code == doc["exit_code"] == 2
    assert [s for s in doc["skipped"] if s["in_scope"]] == [
        {"ecosystem": None, "place": typo, "reason": "check-error", "in_scope": True}
    ]
    code, doc = run(str(root))  # the repository itself: reported once, by its own checked entry
    assert code == 0 and doc["checked"] == [{"ecosystem": "github-actions", "place": str(root)}]


def test_say_strips_exception_type_name(monkeypatch: pytest.MonkeyPatch) -> None:
    hostile = type("Bad\x1b]0;pwned\x07‮Error", (Exception,), {})

    def unreadable() -> str:
        raise hostile

    monkeypatch.setattr("ssc_guardian.cli.tool_version", unreadable)
    code, out, err = _run(["check"])
    assert (code, out) == (2, "")
    assert "internal error (Bad]0;pwnedError)" in err
    assert not {"\x1b", "\x07", "‮"} & set(err)


@pytest.mark.parametrize("verb", [Verb.INSTALL, Verb.PIN, Verb.ACKNOWLEDGE])
def test_confirm_with_closed_stdin_is_not_confirmed(verb: Verb) -> None:
    # sys.stdin is None when fd 0 was closed: no terminal, so no confirmation, and no question;
    # the change is still shown, so the refusal says what --yes would do (#284).
    shown = io.StringIO()
    assert confirm("write x", verb=verb, yes=False, stdin=None, stdout=shown) is False
    if verb.person_only:  # --yes never confirms an exception command in advance
        assert confirm("write x", verb=verb, yes=True, stdin=None, stdout=shown) is False
    assert shown.getvalue() == "write x\n" * (2 if verb.person_only else 1)
    assert "Proceed?" not in shown.getvalue()


def test_rerun_gives_same_result(tmp_path: Path) -> None:
    # The same inputs give the same output, IDs and exit code, including the coverage skips.
    place = str(tmp_path.resolve() / "a")

    def handler(request: Request) -> Result:
        finding = make_finding(Rule.DENY_LIST, Ecosystem.PYPI, place=place, item="requests", version="1.0")
        return Result(Verb.CHECK, findings=(finding,), checked=(Checked(Ecosystem.PYPI),))

    for argv, wanted in ((["check", "--path", place, "--path", place + "x", "--json"], 1), (["check", "--help"], 2)):
        first, second = _run(argv, handlers={Verb.CHECK: handler}), _run(argv, handlers={Verb.CHECK: handler})
        assert first == second
        assert first[0] == wanted


# --- #284: every option has help, and no message carries an internal code ------------------


def _options_without_help(parser: argparse.ArgumentParser) -> list[str]:
    """Every option of ``parser`` and its commands with no help text; a ``SUPPRESS`` help hides
    a refused flag on purpose and counts as one."""
    parsers, missing = [parser], []
    while parsers:
        current = parsers.pop()
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                parsers += list(action.choices.values())
            elif action.option_strings and not action.help:
                missing.append(f"{current.prog} {'/'.join(action.option_strings)}")
    return missing


def test_install_help_describes_every_option() -> None:
    code, out, _ = _run(["install", "--help"])
    assert code == 2  # --help exits 0 only on its own (contracts §2); the help is still printed
    assert "--venv PATH" in out and "the virtual environment to install into" in " ".join(out.split())
    parser = build_parser()
    assert _options_without_help(parser) == []
    assert parser._option_string_actions["--version"].help == "show the version and exit"
    commands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    (installer,) = [a for a in commands.choices["protect"]._actions if a.dest == "installer"]
    assert installer.help and "pip" in installer.help and "uv" in installer.help
    # Negative check: an option added without a help is caught.
    planted = build_parser()
    commands = next(a for a in planted._actions if isinstance(a, argparse._SubParsersAction))
    commands.choices["install"].add_argument("--planted")
    assert _options_without_help(planted) == ["ssc-guardian install --planted"]


_CODE = re.compile(r"\([A-Z]{1,2}\d+(?:\.\d+)*\)")  # an internal decision code, such as (D16) or (N6)


def _internal_codes(source: str) -> list[str]:
    """Every string literal in ``source`` that carries an internal code, docstrings left out
    (comments are not in the syntax tree)."""
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
        and _CODE.search(node.value)
    ]


def test_no_stderr_string_carries_an_internal_code() -> None:
    planted = (
        'def f(err):\n    """Doc (D15)."""\n'
        "    # a comment (D14)\n"
        '    err.write(f"{x} is not part (D16); nothing written.")\n'
    )
    assert _internal_codes(planted) == [" is not part (D16); nothing written."]  # the planted one fails
    src = Path(ssc_guardian.__file__).parent
    found = {str(p.relative_to(src)): _internal_codes(p.read_text()) for p in sorted(src.rglob("*.py"))}
    assert {name: codes for name, codes in found.items() if codes} == {}
