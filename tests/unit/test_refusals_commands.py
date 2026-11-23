# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Negative tests for the refusals of acknowledge, pin, protect and the overrides model (issue #11), and
for the refusals the commands, the CLI and the collector build by hand (issue #131).

GitHub is the in-process fixture of ``test_nested_and_advisories`` or ``test_pinning``; no test
reaches the network.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import cli, lockfile
from ssc_guardian.cli import Handler, Request, main, not_available
from ssc_guardian.commands import pin
from ssc_guardian.commands.acknowledge import Acknowledge
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.override_add import OverrideAdd
from ssc_guardian.commands.pin import Pin
from ssc_guardian.findings import (
    Checked,
    Collector,
    Ecosystem,
    ExitCode,
    IncompleteCheckError,
    Installer,
    OverrideCategory,
    Result,
    Rule,
    SkipReason,
    Verb,
)
from ssc_guardian.grammars import Field, check
from ssc_guardian.lockfile import LOCK_FILE
from ssc_guardian.overrides import Override, parse_overrides
from ssc_guardian.plugins import pip, uv
from ssc_guardian.settings import ConfigFileError, FileKind, MalformedEntryError
from tests.refusal_sites import refuses
from tests.unit import test_install as installs
from tests.unit.test_discovery import fake_mac
from tests.unit.test_nested_and_advisories import NODE_ACTION, TODAY, GitHub, make_repo, sha
from tests.unit.test_pinning import NEW, FakeGitHub, _Person, github_routes, push, run_pin
from tests.unit.test_protect import _config, _protect, _uv_dir, _venv

pytestmark = pytest.mark.unit

ACTION = "someone/new-action"
ACTION_ID = 61
ROUTES = github_routes(tags={"v4.2.2": NEW}, activity=[push(NEW, "2024-10-23T14:46:00Z")])


# --- acknowledge ------------------------------------------------------------------------


class _Tty(io.StringIO):
    """A person at a terminal, answering from the text given."""

    def isatty(self) -> bool:
        return True


def _acknowledge(root: Path, github: GitHub) -> tuple[Result, str]:
    err = io.StringIO()
    handler = Acknowledge(
        stdin=_Tty("y\n"),
        stderr=err,
        cwd=str(root),
        home=str(root.parent / "home"),
        today=TODAY,
        client=github.client(),
    )
    return handler(Request(Verb.ACKNOWLEDGE, repository=ACTION)), err.getvalue()


def test_acknowledge_never_writes_through_a_symlinked_settings_file(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(ACTION, ACTION_ID, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{ACTION}@{sha(1)}")
    target = tmp_path.resolve() / "elsewhere.toml"
    before = b"# someone else's file\nformat = 1\n"
    target.write_bytes(before)
    link = root / ".ssc-guardian.toml"
    link.symlink_to(target)
    with refuses("acknowledge.symlink-acknowledge-writes-only-repositorys"):
        outcome, said = _acknowledge(root, github)
    assert outcome.exit_code is ExitCode.INCOMPLETE
    message = f"{link} is a symlink; acknowledge writes only the repository's own settings file"
    assert f"ssc-guardian: {message}; nothing written.\n" in said
    assert link.is_symlink() and link.readlink() == target
    assert target.read_bytes() == before
    assert github.seen == []  # stopped before GitHub was asked


def test_acknowledge_stops_when_the_name_now_answers_with_another_id(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(ACTION, ACTION_ID + 1, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{ACTION}@{sha(1)}")
    settings_file = root / ".ssc-guardian.toml"
    text = (
        f'format = 1\n\n[[acknowledgment]]\nrepository = "{ACTION}"\nrepository_id = {ACTION_ID}\ndate = 2026-10-01\n'
    )
    settings_file.write_text(text)
    outcome, said = _acknowledge(root, github)
    assert outcome.exit_code is ExitCode.INCOMPLETE
    message = (
        f"{settings_file} acknowledges {ACTION} with ID {ACTION_ID}, but GitHub now gives {ACTION} ID "
        f"{ACTION_ID + 1}: the name may now belong to another repository. Review it, and change the entry by "
        "hand if you accept the new one"
    )
    assert f"ssc-guardian: {message}; nothing written.\n" in said
    assert settings_file.read_text() == text


# --- pin --------------------------------------------------------------------------------


def _pin_repo(tmp_path: Path, workflow: str) -> tuple[Path, Path]:
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    ci = root / ".github" / "workflows" / "ci.yml"
    ci.write_text(workflow)
    return root, ci


STEPS = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"


def test_pin_refuses_a_local_action_that_lies_outside_the_repository(tmp_path: Path) -> None:
    root, ci = _pin_repo(tmp_path, STEPS + "      - uses: actions/checkout@v4\n      - uses: ./.github/actions/ext\n")
    outside = tmp_path.resolve() / "outside-action"
    outside.mkdir()
    action_text = "name: ext\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
    (outside / "action.yml").write_text(action_text)
    (root / ".github" / "actions").mkdir()
    (root / ".github" / "actions" / "ext").symlink_to(outside)  # the folder, not the file, is the link
    result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES)
    assert result.exit_code is ExitCode.INCOMPLETE
    path = root / ".github" / "actions" / "ext" / "action.yml"
    message = f"{path} is a symlink or lies outside the repository; pin writes only the repository's files"
    assert f"ssc-guardian: {message}; nothing written.\n" in err
    assert (outside / "action.yml").read_text() == action_text
    assert not (root / LOCK_FILE).exists()
    assert "actions/checkout@v4\n" in ci.read_text()


def test_pin_stops_when_a_workflow_disappears_while_it_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, ci = _pin_repo(tmp_path, STEPS + "      - uses: actions/checkout@v4\n")
    gone = root / ".github" / "workflows" / "gone.yml"
    gone.write_text(STEPS + "      - uses: actions/cache@v4\n")
    real = pin.read_text

    def vanishing(path: str) -> str | None:
        # Another program deletes the file after pin listed the folder and before it read it.
        if path == str(gone) and gone.exists():
            gone.unlink()
        return real(path)

    monkeypatch.setattr(pin, "read_text", vanishing)
    with refuses("pin.disappeared-while-read"):
        result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES)
    assert result.exit_code is ExitCode.INCOMPLETE
    message = f"{gone} disappeared while it was read"
    assert f"ssc-guardian: {message}; nothing written.\n" in err
    assert not (root / LOCK_FILE).exists()
    assert ci.read_text() == STEPS + "      - uses: actions/checkout@v4\n"


def test_pin_rewrites_only_a_plain_uses_line(tmp_path: Path) -> None:
    # A quoted key is the same 'uses' to YAML, but not a line pin can rewrite in place.
    text = STEPS + '      - "uses": actions/checkout@v4\n'
    root, ci = _pin_repo(tmp_path, text)
    with refuses("pin.pin-rewrites-only-plain-uses"):
        result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES)
    assert result.exit_code is ExitCode.INCOMPLETE
    message = f"{ci}:6: pin rewrites only a plain 'uses: VALUE' line"
    assert f"ssc-guardian: {message}; nothing written.\n" in err
    assert ci.read_text() == text
    assert not (root / LOCK_FILE).exists()


def test_pin_writes_nothing_when_a_rewrite_does_not_read_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A reader that loses the pinned reference: the rewritten text is read back before any write.
    text = STEPS + "      - uses: actions/checkout@v4\n"
    root, ci = _pin_repo(tmp_path, text)
    real = pin._references

    def misread(reader: Any, source: str, path: str) -> Any:
        found = real(reader, source, path)
        return found[:-1] if NEW in source else found

    monkeypatch.setattr(pin, "_references", misread)
    with refuses("pin.did-not-read-back-pin"):
        result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES)
    assert result.exit_code is ExitCode.INCOMPLETE
    message = f"{ci} did not read back as pin rewrote it"
    assert f"ssc-guardian: {message}; nothing written.\n" in err and err.count("nothing written") == 1
    assert "Written:" not in err
    assert ci.read_text() == text
    assert not (root / LOCK_FILE).exists()


def test_pin_writes_nothing_when_the_lock_file_does_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A lock parser that reads back what was not written: the lock text is read back before
    # anything is written. The command ends unfinished with a check-error skip; the refusal's
    # own message is checked on dump_lock itself.
    text = STEPS + "      - uses: actions/checkout@v4\n"
    root, ci = _pin_repo(tmp_path, text)
    monkeypatch.setattr(lockfile, "_parse_lock", lambda lock_text: ("an entry never written",))
    with refuses("lockfile.lock-entries-did-not-read"):
        result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.reason, s.detail) for s in result.skipped] == [(SkipReason.CHECK_ERROR, "MalformedEntryError")]
    assert "Written:" not in err
    assert ci.read_text() == text
    assert not (root / LOCK_FILE).exists()
    with (
        refuses("lockfile.lock-entries-did-not-read"),
        pytest.raises(MalformedEntryError, match="^the lock entries did not read back as written$"),
    ):
        lockfile.dump_lock(())


# --- protect ----------------------------------------------------------------------------


def test_protect_names_a_setting_that_did_not_read_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _config(tmp_path)
    config = tmp_path / "home" / ".config" / "uv" / "uv.toml"
    config.parent.mkdir(parents=True)
    config.write_text('exclude-newer = "3 days"\n')
    other = 'exclude-newer = "1 day"\n'
    real = uv.atomic_write

    def raced(path: str, text: str) -> None:
        real(path, text)
        Path(path).write_text(other)  # another program writes the file just after Guardian

    monkeypatch.setattr(uv, "atomic_write", raced)
    with refuses("protect.did-not-read-back-written"):
        result, err = _protect(tmp_path, installer=Installer.UV, paths=(_uv_dir(tmp_path),))
    assert result.exit_code is ExitCode.INCOMPLETE
    place = str(config)
    assert f"ssc-guardian: {place}: {place}: did not read back as written; written so far: nothing.\n" in err
    assert "Written:" not in err
    assert config.read_text() == other


# --- the overrides model ----------------------------------------------------------------

DAY = date(2026, 11, 3)
BASE = Override(
    Ecosystem.PYPI,
    "Example_Package",
    "1.2.3",
    Rule.KNOWN_VULNERABILITY,
    "CVE-2026-12345",
    OverrideCategory.DEFERRED_UPGRADE,
    DAY - timedelta(days=10),
    DAY + timedelta(days=30),
    "upgrade blocked by the vendor",
)


def _override(**changes: Any) -> Override:
    return replace(BASE, **changes)


@pytest.mark.parametrize(("field", "value"), [("ecosystem", "pypi"), ("rule", "known-vulnerability")])
def test_override_refuses_an_unknown_ecosystem_or_rule(field: str, value: str) -> None:
    with (
        refuses("overrides.ecosystem-rule-not-one-known"),
        pytest.raises(MalformedEntryError, match="^ecosystem or rule is not one of the known values$"),
    ):
        _override(**{field: value})


def test_override_refuses_an_unknown_category() -> None:
    with (
        refuses("overrides.category-not-one-known-values"),
        pytest.raises(MalformedEntryError, match="^category is not one of the known values$"),
    ):
        _override(category="deferred-upgrade")


def test_override_refuses_an_item_outside_its_grammar() -> None:
    with (
        refuses("overrides.item-not-valid"),
        pytest.raises(MalformedEntryError, match="^item is not a valid pypi-name$"),
    ):
        _override(item="not a name")
    with refuses("overrides.item-not-valid"), pytest.raises(MalformedEntryError, match="^item is not a valid action$"):
        _override(
            ecosystem=Ecosystem.GITHUB_ACTIONS,
            item="outer",
            version="0123456789abcdef0123456789abcdef01234567",
            rule=Rule.NESTING_LIMIT,
            reference="nesting-depth",
        )


def test_override_refuses_an_expiry_before_created() -> None:
    with (
        refuses("overrides.expiry-before-created"),
        pytest.raises(MalformedEntryError, match="^expiry is before created$"),
    ):
        _override(created=DAY, expiry=DAY - timedelta(days=1))


def test_override_refuses_an_expiry_past_its_limit() -> None:
    with (
        refuses("overrides.expiry-more-than"),
        pytest.raises(MalformedEntryError, match="^expiry is more than 90 days after created$"),
    ):
        _override(created=DAY, expiry=DAY + timedelta(days=91))
    with (
        refuses("overrides.expiry-more-than"),
        pytest.raises(MalformedEntryError, match="^expiry is more than 7 days after created$"),
    ):
        _override(rule=Rule.COMPROMISE, reference="MAL-2026-1", created=DAY, expiry=DAY + timedelta(days=8))


ENTRY = """
[[override]]
ecosystem = "pypi"
item = "example-package"
version = "1.2.3"
rule = "known-vulnerability"
reference = "CVE-2026-12345"
category = "deferred-upgrade"
created = 2026-11-01
expiry = 2026-12-01
reason = "upgrade blocked by the vendor"
"""
PLACE = "/Users/me/overrides.toml"


def test_an_override_in_the_other_file_is_refused() -> None:
    message = f"{PLACE}: override 1 is a pypi override, which belongs in the other overrides file"
    with (
        refuses("overrides.malformed-entry"),
        refuses("overrides.override-which-belongs-other-overrides"),
        pytest.raises(ConfigFileError, match=re.escape(message)),
    ):
        parse_overrides("format = 1\n" + ENTRY, kind=FileKind.REPOSITORY, place=PLACE, today=DAY)
    actions = (
        ENTRY.replace('"pypi"', '"github-actions"')
        .replace("example-package", "outer/action")
        .replace('"1.2.3"', '"0123456789abcdef0123456789abcdef01234567"')
    )
    message = f"{PLACE}: override 1 is a github-actions override, which belongs in the other overrides file"
    with (
        refuses("overrides.malformed-entry"),
        refuses("overrides.override-which-belongs-other-overrides"),
        pytest.raises(ConfigFileError, match=re.escape(message)),
    ):
        parse_overrides("format = 1\n" + actions, kind=FileKind.WORKSTATION, place=PLACE, today=DAY)


def test_an_override_created_after_today_is_refused() -> None:
    text = "format = 1\n" + ENTRY.replace("created = 2026-11-01", "created = 2026-11-04")
    message = f"{PLACE}: override 1: created is after today"
    with (
        refuses("overrides.created-after-today"),
        refuses("overrides.malformed-entry"),
        pytest.raises(ConfigFileError, match=f"^{re.escape(message)}$"),
    ):
        parse_overrides(text, kind=FileKind.WORKSTATION, place=PLACE, today=DAY)


# --- refusals built by hand (issue #131) ------------------------------------------------
# An in-scope skip a command builds itself, and the exit 2 the CLI sets itself: each names its
# site. Each test asserts the outcome (exit 2, or 1 where a violation wins, and the message)
# besides the site firing.

PROCEED = "not confirmed; nothing written. Add --yes to confirm in advance."


def _cli(argv: list[str], **kwargs: Any) -> tuple[int, str, str]:
    """``cli.main`` on ``argv``: (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err, environ={}, **kwargs)
    return code, out.getvalue(), err.getvalue()


def _skip(ecosystem: str | None, place: str | None, reason: str = "check-error") -> dict[str, Any]:
    return {"ecosystem": ecosystem, "place": place, "reason": reason, "in_scope": True}


def _in_scope(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [skip for skip in doc["skipped"] if skip["in_scope"]]


def _checks(*checked: Checked) -> Handler:
    """A ``check`` handler that reports ``checked`` and nothing else."""
    return lambda request: Result(Verb.CHECK, checked=checked)


def test_person_only_command_refuses_yes_and_json(tmp_path: Path) -> None:
    # Plan §2.4: a person confirms acknowledge and override add at a terminal.
    for argv, verb in ((["acknowledge", ACTION], "acknowledge"), (["override", "add"], "override add")):
        for flag in ("--yes", "--json"):
            with refuses("cli.person-only-flag"):
                code, out, err = _cli([*argv, flag])
            assert (code, out) == (2, "")
            said = f"ssc-guardian: {verb} refuses {flag}: a person confirms it at a terminal, "
            assert err == said + "and its output is text only.\n"
    # No terminal: nothing is asked and nothing written.
    github = GitHub()
    root = make_repo(tmp_path, f"{ACTION}@{sha(1)}")
    home = str(tmp_path / "home")
    stderr = io.StringIO()
    acknowledge = Acknowledge(stdin=io.StringIO("y\n"), stderr=stderr, cwd=str(root), home=home, client=github.client())
    with refuses("acknowledge.no-terminal"):
        outcome = acknowledge(Request(Verb.ACKNOWLEDGE, repository=ACTION))
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert stderr.getvalue() == "ssc-guardian: acknowledge needs a person at a terminal; nothing written.\n"
    stderr = io.StringIO()
    override_add = OverrideAdd(stdin=io.StringIO("y\n"), stderr=stderr, cwd=str(root), home=home)
    with refuses("override_add.stopped"):
        outcome = override_add(Request(Verb.OVERRIDE_ADD))
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert stderr.getvalue() == "ssc-guardian: override add needs a person at a terminal; nothing written.\n"
    assert not (root / ".ssc-guardian.toml").exists() and github.seen == []


@pytest.mark.parametrize("argv", [["check", "--help"], ["--version", "check"], ["install", "-h"], ["-h", "--json"]])
def test_help_with_other_words_never_exits_zero(argv: list[str]) -> None:
    # #26: "check --help" in a CI gate checks nothing, so it is never a pass.
    with refuses("cli.help-not-alone"):
        code, out, err = _cli(argv)
    assert code == 2 and out
    assert err.endswith("ssc-guardian: --help, -h and --version exit 0 only on their own; nothing was checked.\n")


def test_unreported_path_is_incomplete(tmp_path: Path) -> None:
    # Contracts §2 and §3: a --path no handler reported, and an area no handler reported.
    missing, elsewhere = str(tmp_path.resolve() / "nothing-here"), str(tmp_path.resolve() / "elsewhere")
    handlers = {Verb.CHECK: _checks(Checked(Ecosystem.PYPI, elsewhere))}
    with refuses("cli.path-not-reported"):
        code, out, _ = _cli(["check", "--envs", "--path", missing, "--json"], handlers=handlers)
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _in_scope(doc) == [_skip(None, missing)]
    with refuses("cli.area-not-reported"):
        code, out, _ = _cli(["check", "--envs", "--path", elsewhere, "--json"], handlers={Verb.CHECK: _checks()})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _in_scope(doc) == [_skip("pypi", None), _skip(None, elsewhere)]  # the named path too (#255)
    with refuses("cli.area-not-reported"):
        code, out, _ = _cli(["check", "--envs", "--path", elsewhere], handlers={Verb.CHECK: _checks()})
    assert code == 2 and "not reported" in out


def _check_envs(tmp_path: Path, argv: list[str], *, cwd: Path | None = None, **environ: str) -> tuple[int, str, str]:
    """``check`` through ``cli.main``, with the workstation under ``tmp_path`` and no network."""
    where = fake_mac(tmp_path, **environ)
    err = io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, None, err, cwd=str(cwd or tmp_path.resolve()))
    code, out, said = _cli(argv, handlers={Verb.CHECK: handler})
    return code, out, said + err.getvalue()


def test_no_environment_and_no_repository_are_incomplete(tmp_path: Path) -> None:
    _config(tmp_path)
    projects = tmp_path.resolve() / "home" / "projects"
    projects.mkdir(parents=True)
    # #67, #255: a named path where no Python environment is checked is never a pass.
    with refuses("check_envs.empty-path"):
        code, out, _ = _check_envs(tmp_path, ["check", "--envs", "--path", str(projects), "--json"])
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _in_scope(doc) == [_skip("pypi", str(projects))]
    with refuses("check_envs.empty-path"):
        code, out, _ = _check_envs(tmp_path, ["check", "--envs", "--path", str(projects)])
    assert code == 2 and "no Python environment at or under the named path" in out
    # #68: an explicit --ecosystem github-actions outside a Git repository.
    with refuses("check_envs.no-repository"):
        argv = ["check", "--ecosystem", "github-actions", "--path", str(projects), "--json"]
        code, out, err = _check_envs(tmp_path, argv)
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _skip("github-actions", None) in doc["skipped"]
    assert "GitHub Actions: not inside a Git repository; run check inside one, check --repo DIR, or add --envs" in err


def _repo_and_empty(tmp_path: Path) -> tuple[Path, Path]:
    """A Git repository with no workflows as the working folder, and an empty folder outside it."""
    _config(tmp_path)
    empty = tmp_path.resolve() / "home" / "projects"
    empty.mkdir(parents=True)
    repo = tmp_path.resolve() / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo, empty


def test_both_ecosystems_name_no_python_environment_for_an_empty_path(tmp_path: Path) -> None:
    # #284: with GitHub Actions in scope too, the PyPI handler's own reason reaches the output,
    # never the safety net's generic "not reported".
    repo, empty = _repo_and_empty(tmp_path)
    with refuses("check_envs.empty-path"):
        code, out, _ = _check_envs(tmp_path, ["check", "--path", str(empty), "--json"], cwd=repo)
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _in_scope(doc) == [_skip("pypi", str(empty))]
    code, out, err = _check_envs(tmp_path, ["check", "--path", str(empty)], cwd=repo)
    assert code == 2
    assert f"pypi {empty}: the check failed (no Python environment at or under the named path)" in out
    assert "not reported" not in out + err


def test_a_path_the_actions_side_reported_gets_no_python_environment_skip(tmp_path: Path) -> None:
    # #284: a named folder that holds a checked workflow is reported by the Actions side.
    repo, _ = _repo_and_empty(tmp_path)
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(STEPS + "      - run: echo hi\n")
    code, out, _ = _check_envs(tmp_path, ["check", "--path", str(workflows), "--json"], cwd=repo)
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2  # PyPI reported nothing: still unfinished, as before
    assert {"ecosystem": "github-actions", "place": str(workflows)} in doc["checked"]
    assert all(skip["place"] != str(workflows) for skip in doc["skipped"])
    code, out, _ = _check_envs(tmp_path, ["check", "--path", str(workflows)], cwd=repo)
    assert "no Python environment" not in out


def test_empty_path_skip_is_idempotent_on_re_run(tmp_path: Path) -> None:
    repo, empty = _repo_and_empty(tmp_path)
    runs = [_check_envs(tmp_path, ["check", "--path", str(empty), "--json"], cwd=repo) for _ in range(2)]
    assert runs[0] == runs[1]
    assert _in_scope(json.loads(runs[0][1])) == [_skip("pypi", str(empty))]


def test_a_token_variable_that_holds_no_token_is_incomplete(tmp_path: Path) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    _protect(tmp_path)
    with refuses("check_envs.no-token"):
        argv = ["check", "--envs", "--path", str(tmp_path.resolve() / "home" / "projects"), "--json"]
        code, out, err = _check_envs(tmp_path, argv, GH_TOKEN="not a token")
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2, doc
    assert _skip("pypi", None) in doc["skipped"]
    assert "ssc-guardian: GH_TOKEN does not hold a token" in err and "not a token" not in err


def _files(folder: Path) -> dict[str, bytes]:
    """Every file under ``folder`` with its bytes, so a write anywhere shows."""
    return {str(path): path.read_bytes() for path in sorted(folder.rglob("*")) if path.is_file()}


def _declined_pin(tmp_path: Path) -> Callable[[], tuple[Result, str]]:
    root, _ = _pin_repo(tmp_path, STEPS + "      - uses: actions/checkout@v4\n")

    def run() -> tuple[Result, str]:
        result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES, yes=False)  # no terminal, no --yes
        return result, err

    return run


def _declined_protect(tmp_path: Path) -> Callable[[], tuple[Result, str]]:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")

    def run() -> tuple[Result, str]:
        result, err = _protect(tmp_path, yes=False, answer="n\n")  # a person at a terminal says no
        return result, err

    return run


def _declined_install(tmp_path: Path) -> Callable[[], tuple[ExitCode, str]]:
    target, runner = installs.venv(tmp_path), installs.FakePip()

    def run() -> tuple[ExitCode, str]:
        code, _, err = installs.run(installs.handler(tmp_path, runner), target, "demo==1.1", yes=False)
        assert runner.installs == []
        return ExitCode(code), err

    return run


@pytest.mark.parametrize(
    ("case", "declined", "said"),
    [
        (refuses("pin.not-confirmed"), _declined_pin, PROCEED),
        (refuses("protect.not-confirmed"), _declined_protect, PROCEED),
        (refuses("install.not-confirmed"), _declined_install, PROCEED.replace("written", "installed")),
    ],
    ids=["pin", "protect", "install"],
)
def test_declined_confirmation_writes_nothing(
    tmp_path: Path, case: Any, declined: Callable[[Path], Callable[[], tuple[Result | ExitCode, str]]], said: str
) -> None:
    # D15: a change is written only on a yes; a no, or no terminal without --yes, writes nothing.
    # The test holds the Result pin and protect return, so their refusal reaches it (issue #164).
    run = declined(tmp_path)
    before = _files(tmp_path)
    with case:
        outcome, err = run()
    code = outcome.exit_code if isinstance(outcome, Result) else outcome
    assert code is ExitCode.INCOMPLETE
    assert f"ssc-guardian: {said}\n" in err
    assert _files(tmp_path) == before


def test_file_changed_while_confirming_writes_nothing(tmp_path: Path) -> None:
    root, ci = _pin_repo(tmp_path, STEPS + "      - uses: actions/checkout@v4\n")
    other = root / ".github" / "workflows" / "other.yml"
    other.write_text(STEPS + "      - uses: actions/cache@v4\n")
    err = io.StringIO()
    handler = Pin(
        stdin=_Person(other),
        stderr=err,
        cwd=str(root),
        home=str(root / "home"),
        today=TODAY,
        client=FakeGitHub(ROUTES).client(),
    )
    before = ci.read_text()
    with refuses("pin.changed-while-confirming"):
        result = handler(Request(Verb.PIN, action="actions/checkout", ref="v4.2.2", yes=False))
    assert result.exit_code is ExitCode.INCOMPLETE
    assert "ssc-guardian: a file changed while you read the change; run pin again. Nothing written.\n" in err.getvalue()
    assert ci.read_text() == before and not (root / LOCK_FILE).exists()


def test_a_failed_write_is_incomplete_and_names_what_was_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full(path: str, text: str) -> None:
        raise OSError("disk full")

    # pin: the lock file is written first, so nothing is written when it fails.
    root, ci = _pin_repo(tmp_path / "pin", STEPS + "      - uses: actions/checkout@v4\n")
    monkeypatch.setattr(pin, "atomic_write", full)
    with refuses("pin.not-written"):
        result, err = run_pin(root, "actions/checkout@v4.2.2", ROUTES)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert f"ssc-guardian: {root / LOCK_FILE}: disk full; written so far: nothing.\n" in err
    assert not (root / LOCK_FILE).exists() and "actions/checkout@v4\n" in ci.read_text()
    # protect: each setting is its own check.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    monkeypatch.setattr(pip, "atomic_write", full)
    with refuses("protect.not-written"):
        outcome, err = _protect(tmp_path)
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert f"ssc-guardian: {venv / 'pip.conf'}: disk full; written so far: nothing.\n" in err
    assert not (venv / "pip.conf").exists()


class _FailingPip(installs.FakePip):
    """pip's install step fails after its check passed."""

    def install(self, env: Any, files: Any) -> None:
        raise OSError("pip exited 1")


def test_a_failed_install_is_incomplete_and_names_what_it_left(tmp_path: Path) -> None:
    target, runner = installs.venv(tmp_path), _FailingPip()
    before = _files(target)
    with refuses("install.not-installed"):
        code, doc, err = installs.run(installs.handler(tmp_path, runner), target, "demo==1.1")
    assert code == doc["exit_code"] == 2
    assert doc["skipped"] == [_skip("pypi", str(target))]
    assert f"ssc-guardian: {target}: pip exited 1; written: nothing; removed: nothing.\n" in err
    assert _files(target) == before


def test_outside_a_repository_or_without_a_name_writes_nothing(tmp_path: Path) -> None:
    outside = tmp_path.resolve() / "outside"
    outside.mkdir()
    github = GitHub()
    root = make_repo(tmp_path, f"{ACTION}@{sha(1)}")
    for cwd, repository, why in (
        (outside, ACTION, "acknowledge works inside a Git repository, and this is not one"),
        (root, None, "name OWNER/REPO"),
    ):
        err = io.StringIO()
        handler = Acknowledge(stdin=_Tty("y\n"), stderr=err, cwd=str(cwd), home=str(tmp_path / "home"), today=TODAY)
        with refuses("acknowledge.no-repository-or-name"):
            outcome = handler(Request(Verb.ACKNOWLEDGE, repository=repository))
        assert outcome.exit_code is ExitCode.INCOMPLETE
        assert err.getvalue() == f"ssc-guardian: {why}; nothing written.\n"
    for cwd, action, why in (
        (outside, "actions/checkout", "pin works inside a Git repository, and this is not one"),
        (root, None, "name the version to pin: OWNER/REPO[/PATH]@TAG or OWNER/REPO[/PATH]@SHA"),
    ):
        err = io.StringIO()
        pinner = Pin(stderr=err, cwd=str(cwd), home=str(tmp_path / "home"), today=TODAY, client=github.client())
        with refuses("pin.no-repository-or-version"):
            outcome = pinner(Request(Verb.PIN, action=action, ref="v4.2.2", yes=True))
        assert outcome.exit_code is ExitCode.INCOMPLETE
        assert err.getvalue() == f"ssc-guardian: {why}; nothing written.\n"
    assert github.seen == [] and not (root / ".ssc-guardian.toml").exists() and not (root / LOCK_FILE).exists()


class _ClosedPipe(io.StringIO):
    def write(self, text: str) -> int:
        raise BrokenPipeError("closed")


def test_cli_failures_exit_two_and_name_the_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    handlers = {Verb.CHECK: _checks(Checked(Ecosystem.PYPI))}
    # A usage error main reports itself.
    with refuses("cli.usage-error"):
        code, out, err = _cli(["check", "--envs", "--ecosystem", "github-actions"])
    assert (code, out, err) == (2, "", "ssc-guardian: the scope and filters leave nothing to check\n")
    # Output that cannot be written (a fake writer that fails).
    out_stream, err_stream = _ClosedPipe(), io.StringIO()
    with refuses("cli.output-not-written"):
        argv = ["check", "--envs", "--path", "/Users/me/app"]
        code = main(argv, handlers=handlers, stdout=out_stream, stderr=err_stream, environ={})
    assert code == 2
    assert err_stream.getvalue() == "ssc-guardian: could not write output (BrokenPipeError).\n"

    # A renderer that fails.
    def broken(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("renderer")

    monkeypatch.setattr(cli, "to_json", broken)
    with refuses("cli.internal-error"):
        code, out, err = _cli(["check", "--envs", "--path", "/Users/me/app", "--json"], handlers=handlers)
    assert (code, out) == (2, "")
    assert err == "ssc-guardian: internal error (RuntimeError); nothing was checked or written.\n"

    # A parser that fails before any verb runs (for example unreadable package metadata).
    class _Parser:
        def parse_args(self, arguments: list[str]) -> Any:
            raise PermissionError("metadata")

    monkeypatch.setattr(cli, "build_parser", lambda **streams: _Parser())
    with refuses("cli.parse-failed"):
        code, out, err = _cli(["check"])
    assert (code, out) == (2, "")
    assert err == "ssc-guardian: internal error (PermissionError); nothing was checked or written.\n"


def test_a_handler_that_fails_or_is_not_built_is_incomplete() -> None:
    def crash(request: Request) -> Result:
        raise RuntimeError("handler")

    def malformed_name(request: Request) -> Result:
        check(Field.PYPI_NAME, "not a name")
        raise AssertionError("not reached")

    named = ["--path", "/Users/me/app"]  # #255: check names what it checks
    with refuses("cli.handler-failed"):
        code, out, _ = _cli(["check", "--envs", *named, "--json"], handlers={Verb.CHECK: crash})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _skip(None, None) in doc["skipped"]
    with refuses("cli.handler-failed"):
        code, out, _ = _cli(["check", "--envs", *named], handlers={Verb.CHECK: crash})
    assert code == 2 and "RuntimeError" in out
    # A malformed value is a violation besides the unfinished check: 1 wins over 2.
    with refuses("cli.handler-malformed-value"):
        code, out, _ = _cli(["check", "--envs", *named, "--json"], handlers={Verb.CHECK: malformed_name})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 1
    assert _skip(None, None) in doc["skipped"]
    assert [f["rule"] for f in doc["findings"]] == ["malformed-name"]
    # A verb that is not built yet: its area is an in-scope skip.
    with refuses("cli.not-available"):
        code, out, _ = _cli(["check", "--envs", *named, "--json"], handlers={Verb.CHECK: not_available})
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _in_scope(doc) == [_skip("pypi", None, "not-available"), _skip(None, "/Users/me/app")]


def _incomplete() -> None:
    raise IncompleteCheckError(SkipReason.FEED_FAILURE)


def _reason_reassigned() -> None:
    error = IncompleteCheckError(SkipReason.CHECK_ERROR)
    error.reason = SkipReason.FILTERED  # bypasses the constructor's check
    raise error


def _malformed() -> None:
    check(Field.PYPI_NAME, "not a name")


def _crash() -> None:
    raise RuntimeError("check")


PLACE_OK = "/Users/me/app/.venv"


@pytest.mark.parametrize(
    ("case", "place", "body", "skip", "code"),
    [
        (refuses("findings.incomplete-check"), PLACE_OK, _incomplete, (PLACE_OK, "feed-failure", None), 2),
        (
            refuses("findings.reason-out-of-scope"),
            PLACE_OK,
            _reason_reassigned,
            (PLACE_OK, "check-error", "IncompleteCheckError"),
            2,
        ),
        (
            refuses("findings.malformed-value"),
            PLACE_OK,
            _malformed,
            (PLACE_OK, "check-error", "MalformedValueError"),
            1,
        ),
        (refuses("findings.check-raised"), PLACE_OK, _crash, (PLACE_OK, "check-error", "RuntimeError"), 2),
        (refuses("findings.malformed-place"), "not/absolute", _crash, (None, "check-error", "MalformedValueError"), 1),
    ],
    ids=["incomplete", "reason-out-of-scope", "malformed-value", "raised", "malformed-place"],
)
def test_collector_turns_a_failed_check_into_an_in_scope_skip(
    case: Any, place: str, body: Callable[[], None], skip: tuple[str | None, str, str | None], code: int
) -> None:
    collector = Collector(Verb.CHECK)
    with case, collector.check(Ecosystem.PYPI, place) as ok:
        if ok:
            body()
    result = collector.result()
    assert int(result.exit_code) == code
    assert [(s.place, s.reason.value, s.detail) for s in result.skipped] == [skip]
    assert all(s.in_scope for s in result.skipped) and not result.checked


def test_an_unusable_file_names_itself_in_its_skip(tmp_path: Path) -> None:
    # A settings file that cannot be used: nothing in it applies, and the run is unfinished.
    folder = tmp_path / "home" / ".config" / "ssc-guardian"
    folder.mkdir(parents=True)
    (folder / "config.toml").write_text("format = [\n")
    with refuses("settings.file-unusable"):
        code, out, err = _check_envs(tmp_path, ["check", "--envs", "--path", str(tmp_path.resolve()), "--json"])
    doc = json.loads(out)
    assert code == doc["exit_code"] == 2
    assert _skip("pypi", str(folder / "config.toml")) in doc["skipped"]
    assert f"ssc-guardian: {folder / 'config.toml'}: " in err


# --- the command line -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["check", "--no-such-flag"], "unrecognized arguments: --no-such-flag"),
        (["no-such-command"], "invalid choice: 'no-such-command'"),
        (["check", "--envs", "--language", "cobol"], "unsupported language 'cobol'"),
    ],
    ids=["unknown-flag", "unknown-command", "bad-value"],
)
def test_an_argparse_usage_error_fires_its_site(argv: list[str], said: str) -> None:
    # argparse's own usage error is a refusal through incomplete_exit (#148): exit 2, its
    # message on stderr, nothing on stdout, and no site in either.
    out, err = io.StringIO(), io.StringIO()
    with refuses("cli.argparse-usage-error"):
        code = main(argv, stdout=out, stderr=err, environ={})
    assert code == 2
    assert out.getvalue() == ""
    assert said in err.getvalue() and "usage:" in err.getvalue()
    assert "argparse-usage-error" not in err.getvalue()
