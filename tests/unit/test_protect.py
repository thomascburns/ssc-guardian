# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``protect`` and the pip and uv cooldown forms (issue #5; plan §3.1; D15, D16).

Each test builds a fake Mac under ``tmp_path`` (see ``test_discovery``); ``protect`` never
touches the real home folder, pip.conf or uv config.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest

from ssc_guardian import cli, discovery
from ssc_guardian.cli import Request
from ssc_guardian.commands.check_envs import cooldown_of, unprotected
from ssc_guardian.commands.protect import Protect, _nothing_to_write
from ssc_guardian.findings import (
    Collector,
    Ecosystem,
    FindingField,
    Installer,
    Result,
    Rule,
    SkipReason,
    Verb,
    malformed,
)
from ssc_guardian.plugin import CooldownSetting
from ssc_guardian.plugins import pip, uv
from ssc_guardian.settings import ConfigFileError, workstation_settings
from tests.refusal_sites import Refuses, refuses
from tests.unit.test_discovery import add_dist, fake_mac, make_base, make_venv

TODAY = date(2026, 11, 3)  # 21 days earlier: 2026-10-13


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _venv(tmp_path: Path, name: str, pip_version: str | None, python: str = "3.12") -> Path:
    prefix = tmp_path / "home" / "projects" / name
    site = make_venv(prefix, python)
    if pip_version is not None:
        add_dist(site, "pip", pip_version)
    return Path(os.path.realpath(prefix))


def _config(tmp_path: Path, text: str = "") -> None:
    folder = tmp_path / "home" / ".config" / "ssc-guardian"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(f"format = 1\n{text}")


def _uv_dir(tmp_path: Path) -> str:
    """The folder holding the fake home's uv user config, as ``--path`` names it (#255)."""
    return os.path.realpath(tmp_path / "home" / ".config" / "uv")


def _protect(
    tmp_path: Path,
    *,
    yes: bool = True,
    answer: str | None = None,
    installer: Installer | None = None,
    access: Callable[[str], pip.Access] = pip.access,
    env: dict[str, str] | None = None,
    paths: tuple[str, ...] | None = None,
    **environ: str,
) -> tuple[Result, str]:
    """``protect`` on ``paths`` (``--path``, as the CLI resolves them): by default the fake home's
    projects folder, which ``[scope] venv_folders`` named before #255."""
    where = fake_mac(tmp_path, **(env or {}), **environ)
    err = io.StringIO()
    stdin = _Terminal(answer) if answer is not None else io.StringIO()
    handler = Protect(where.home, where.environ, where.root, TODAY, stdin, err, access)
    named = paths if paths is not None else (os.path.realpath(tmp_path / "home" / "projects"),)
    return handler(Request(Verb.PROTECT, paths=named, installer=installer, yes=yes)), err.getvalue()


def test_old_pip_fails_with_upgrade_message(tmp_path: Path) -> None:
    _config(tmp_path)
    old = _venv(tmp_path, "old", "25.3")
    result, err = _protect(tmp_path)
    (finding,) = result.findings
    assert (finding.rule, finding.place, finding.options) == (Rule.UNPROTECTED, str(old), ())
    assert result.exit_code == 1
    said = "pip 25.3 ignores the cooldown setting: upgrade pip or leave this installation out of the paths you name"
    assert said in err
    assert not (old / "pip.conf").exists()  # pip 25.3 would silently ignore anything written


# #302: the clean-Mac VM run's venv, made with Apple's Python 3.9.6, carries pip 21.2.4.
APPLE_VENV_PIP = "21.2.4"
_ALL_PROTECTED = "Nothing to write: every installation Guardian found and can write is protected."
_ONE_CANNOT = "Nothing to write: 1 installation cannot be protected as it stands; see the report."


def test_protect_old_pip_does_not_claim_everything_is_protected(tmp_path: Path) -> None:
    _config(tmp_path)
    old = _venv(tmp_path, "app", APPLE_VENV_PIP, python="3.9")
    result, err = _protect(tmp_path)
    (finding,) = result.findings
    assert (finding.rule, finding.place, finding.options) == (Rule.UNPROTECTED, str(old), ())
    assert result.exit_code == 1 and not result.skipped
    assert "every installation" not in err
    assert err.endswith(f"{_ONE_CANNOT}\n")
    assert "recreate this venv with Python 3.10 or later, or leave this installation out of the paths you name" in err
    assert not (old / "pip.conf").exists()


def test_protect_all_protected_keeps_the_every_installation_line(tmp_path: Path) -> None:
    # Negative control: with every venv protected, the existing sentence still prints.
    _config(tmp_path)
    venv = _venv(tmp_path, "done", "26.2.1")
    both = "[global]\nuploaded-prior-to = P21D\n\n[install]\nuploaded-prior-to = P21D\n"
    (venv / "pip.conf").write_text(both)
    result, err = _protect(tmp_path)
    assert result.exit_code == 0 and not result.findings and not result.skipped
    assert err == f"{_ALL_PROTECTED}\n"
    assert (venv / "pip.conf").read_text() == both


def test_protect_old_pip_with_unfinished_check_says_nothing_to_write(tmp_path: Path) -> None:
    # Edge case: an old pip plus an in-scope skip (a named path with no Python) keeps the short
    # line. The violation still sets the exit code: 1 wins over 2 (contracts §3), as before #302.
    _config(tmp_path)
    old = _venv(tmp_path, "app", APPLE_VENV_PIP, python="3.9")
    empty = tmp_path / "home" / "empty"
    empty.mkdir()
    named = (os.path.realpath(tmp_path / "home" / "projects"), os.path.realpath(empty))
    with refuses("protect.empty-path"):
        result, err = _protect(tmp_path, paths=named)
    assert [(f.rule, f.place) for f in result.findings] == [(Rule.UNPROTECTED, str(old))]
    assert [s.place for s in result.skipped if s.in_scope] == [os.path.realpath(empty)]
    assert result.exit_code == 1
    assert err.endswith("Nothing to write.\n")
    assert "every installation" not in err and "cannot be protected as it stands" not in err


def test_protect_two_old_pips_are_counted(tmp_path: Path) -> None:
    _config(tmp_path)
    _venv(tmp_path, "one", APPLE_VENV_PIP, python="3.9")
    _venv(tmp_path, "two", "25.3")
    result, err = _protect(tmp_path)
    assert result.exit_code == 1 and len(result.findings) == 2
    assert err.endswith("Nothing to write: 2 installations cannot be protected as they stand; see the report.\n")


def test_nothing_to_write_with_only_another_violation_never_claims_protection() -> None:
    # A violation that is not "unprotected" (a malformed place) gives no count and no claim.
    collector = Collector(Verb.PROTECT)
    collector.findings.append(malformed(FindingField.PLACE, "bad\x1bname", ecosystem=Ecosystem.PYPI))
    assert _nothing_to_write(collector) == "Nothing to write; see the report."
    assert _nothing_to_write(Collector(Verb.PROTECT)) == _ALL_PROTECTED


def test_protect_old_pip_message_is_idempotent_on_re_run(tmp_path: Path) -> None:
    _config(tmp_path)
    old = _venv(tmp_path, "app", APPLE_VENV_PIP, python="3.9")
    first, err = _protect(tmp_path)
    second, again = _protect(tmp_path)
    assert again == err and _ONE_CANNOT in err
    assert first.exit_code == second.exit_code == 1
    assert not (old / "pip.conf").exists()


def test_never_writes_a_form_the_pip_rejects(tmp_path: Path) -> None:
    _config(tmp_path)
    fixed = _venv(tmp_path, "fixed", "26.0.1")
    (fixed / "pip.conf").write_text("[global]\nuploaded-prior-to = P21D\n")  # pip 26.0 stops on this
    rolling = _venv(tmp_path, "rolling", "26.2.1")
    beta = _venv(tmp_path, "beta", "26.2b1")  # sorts above 26.1 (#274): the rolling form
    result, _ = _protect(tmp_path)
    assert result.exit_code == 0, result
    both = "[global]\nuploaded-prior-to = {0}\n\n[install]\nuploaded-prior-to = {0}\n"
    assert (fixed / "pip.conf").read_text() == both.format("2026-10-13T00:00:00+00:00")
    assert (beta / "pip.conf").read_text() == both.format("P21D")
    assert (rolling / "pip.conf").read_text() == both.format("P21D")
    assert pip.form_for(pip.parse("25.3")) is None


BOTH = "[global]\nuploaded-prior-to = {0}\n\n[install]\nuploaded-prior-to = {0}\n"
FIXED_TEXT = "2026-10-13T00:00:00+00:00"  # TODAY minus the 21-day cooldown


def _assess(tmp_path: Path, folder: Path, **environ: str) -> pip.Assessment:
    """``assess`` on the one environment at ``folder``, under the fake Mac."""
    where = fake_mac(tmp_path, **environ)
    (env,) = discovery.survey(where, [str(folder)]).environments
    return pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=pip.Sources.of(where))


def _base_behind_user_pip(tmp_path: Path, base_pip: str, user_pip: str) -> Path:
    """A pyenv base holding ``base_pip``, with ``user_pip`` in the per-user folder ahead of it:
    the per-user pip loads, and the base pip runs whenever the per-user folder is off."""
    where = fake_mac(tmp_path)
    prefix = Path(where.home) / ".pyenv" / "versions" / "3.12.4"
    add_dist(make_base(prefix), "pip", base_pip)
    add_dist(Path(where.home) / ".local" / "lib" / "python3.12" / "site-packages", "pip", user_pip)
    return Path(os.path.realpath(prefix))


def test_pip_26_1_gets_the_rolling_form(tmp_path: Path) -> None:
    # #274: pip 26.1 takes P<n>D (plan §8 row 47), so it gets the rolling form, not a fixed date.
    _config(tmp_path)
    patched, first = _venv(tmp_path, "patched", "26.1.2"), _venv(tmp_path, "first", "26.1")
    result, _ = _protect(tmp_path)
    assert result.exit_code == 0, result
    assert (patched / "pip.conf").read_text() == BOTH.format("P21D")
    assert (first / "pip.conf").read_text() == BOTH.format("P21D")
    assert pip.form_for(pip.parse("26.1")) is pip.Form.ROLLING
    assert pip.form_for(pip.parse("26.1.2")) is pip.Form.ROLLING


def test_rolling_setting_on_pip_26_1_is_protected(tmp_path: Path) -> None:
    # #274: the old boundary called this REJECTED, and protect replaced it with a fixed date.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.1.2")
    (venv / "pip.conf").write_text(BOTH.format("P21D"))
    before = (venv / "pip.conf").read_bytes()
    mtime = (venv / "pip.conf").stat().st_mtime_ns
    state = _assess(tmp_path, venv)
    assert (state.verdict, state.why) == (pip.Verdict.PROTECTED, "protected (P21D)")
    result, err = _protect(tmp_path)
    assert result.exit_code == 0, result
    assert "Nothing to write" in err
    assert (venv / "pip.conf").read_bytes() == before  # byte for byte as it was
    assert (venv / "pip.conf").stat().st_mtime_ns == mtime  # never rewritten


def test_pip_26_0_keeps_the_fixed_form(tmp_path: Path) -> None:
    # Negative (#274): pip 26.0.x takes only a datetime (plan §8 row 2); nothing changes for it.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.0.1")
    (venv / "pip.conf").write_text(BOTH.format("P21D"))
    state = _assess(tmp_path, venv)
    assert state.verdict is pip.Verdict.REJECTED
    assert state.why == "pip 26.0.1 rejects P21D and stops; run protect again"
    result, _ = _protect(tmp_path)
    assert result.exit_code == 0, result
    assert (venv / "pip.conf").read_text() == BOTH.format(FIXED_TEXT)
    assert pip.form_for(pip.parse("26.0")) is pip.form_for(pip.parse("26.0.1")) is pip.Form.FIXED


def test_pip_26_1_pre_release_keeps_the_fixed_form(tmp_path: Path) -> None:
    # Edge case (#274): a pre-release of 26.1 sorts below 26.1 and is not shown to take P<n>D.
    _config(tmp_path)
    venv = _venv(tmp_path, "beta", "26.1b1")
    (venv / "pip.conf").write_text(BOTH.format("P21D"))
    assert _assess(tmp_path, venv).verdict is pip.Verdict.REJECTED
    result, _ = _protect(tmp_path)
    assert result.exit_code == 0, result
    assert (venv / "pip.conf").read_text() == BOTH.format(FIXED_TEXT)
    assert pip.form_for(pip.parse("26.1b1")) is pip.form_for(pip.parse("26.1.dev0")) is pip.Form.FIXED


def test_hidden_pip_26_0_keeps_the_fixed_form(tmp_path: Path) -> None:
    # Edge case (#274): the loaded pip is 26.1.2, but the base's 26.0.1 behind it still runs
    # whenever the per-user folder is off, and it stops on P<n>D.
    _config(tmp_path)
    prefix = _base_behind_user_pip(tmp_path, "26.0.1", "26.1.2")
    state = _assess(tmp_path, prefix)
    assert state.pip is not None and state.pip.version == "26.1.2"
    assert [p.version for p in state.hidden] == ["26.0.1"]
    result, _ = _protect(tmp_path, paths=(str(prefix),))
    assert result.exit_code == 0, result
    assert (prefix / "pip.conf").read_text() == BOTH.format(FIXED_TEXT)


def test_unreadable_hidden_pip_version_keeps_the_fixed_form(tmp_path: Path) -> None:
    # Error path (#274): a pip whose version cannot be read might reject P<n>D. Hidden behind a
    # 26.1.2 it forces the fixed date; loaded, it is an old pip and nothing is written.
    _config(tmp_path / "hidden")  # two fake Macs, one per case
    _config(tmp_path / "loaded")
    hidden = _base_behind_user_pip(tmp_path / "hidden", "not-a-version", "26.1.2")
    result, _ = _protect(tmp_path / "hidden", paths=(str(hidden),))
    assert [f.rule for f in result.findings] == [Rule.MALFORMED_NAME]  # the version itself is reported
    assert (hidden / "pip.conf").read_text() == BOTH.format(FIXED_TEXT)
    loaded = _base_behind_user_pip(tmp_path / "loaded", "26.1.2", "not-a-version")
    state = _assess(tmp_path / "loaded", loaded)
    assert (state.verdict, state.wanted) == (pip.Verdict.OLD_PIP, None)
    result, _ = _protect(tmp_path / "loaded", paths=(str(loaded),))
    assert result.exit_code == 1
    assert not (loaded / "pip.conf").exists()


def test_fixed_date_on_pip_26_1_becomes_rolling_and_re_run_is_idempotent(tmp_path: Path) -> None:
    # Idempotency (#274): a 26.1.2 venv the old boundary gave a fixed date keeps it while it is
    # fresh (a valid date is never weaker than the cooldown); once it goes stale, the "run
    # protect again" it reports writes P21D once, and a second run writes nothing.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.1.2")
    (venv / "pip.conf").write_text("# meant: the duration form\n" + BOTH.format(FIXED_TEXT))
    assert _assess(tmp_path, venv).verdict is pip.Verdict.PROTECTED
    (venv / "pip.conf").write_text("# meant: the duration form\n" + BOTH.format("2026-10-01T00:00:00+00:00"))
    assert _assess(tmp_path, venv).verdict is pip.Verdict.STALE  # 12 days past, over the 7-day tolerance
    first, _ = _protect(tmp_path, paths=(str(venv),))
    written = (venv / "pip.conf").read_text()
    mtime = (venv / "pip.conf").stat().st_mtime_ns
    second, err = _protect(tmp_path, paths=(str(venv),))
    assert first.exit_code == second.exit_code == 0
    assert written == "# meant: the duration form\n" + BOTH.format("P21D")  # no duplicate keys
    assert (venv / "pip.conf").read_text() == written
    assert (venv / "pip.conf").stat().st_mtime_ns == mtime  # no second write
    assert "Nothing to write" in err
    assert [c.place for c in first.checked] == [c.place for c in second.checked] == [str(venv)]


def test_root_owned_prefix_needs_administrator_never_sudo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "system", "26.2.1")

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("protect never runs a program, sudo least of all")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    for name in ("system", "execv", "execve", "execvp", "posix_spawn", "posix_spawnp"):
        monkeypatch.setattr(os, name, refuse)
    result, err = _protect(tmp_path, access=lambda path: pip.Access.ADMINISTRATOR)
    (finding,) = result.findings
    assert (finding.rule, finding.place) == (Rule.UNPROTECTED, str(venv))
    assert result.exit_code == 1
    assert "is owned by root or a signed Apple bundle: an administrator must set" in err
    assert "'uploaded-prior-to = P21D' in [global] and [install]" in err
    assert "Guardian never uses sudo" in err
    assert not (venv / "pip.conf").exists()


def test_access_names_a_root_owned_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Owner:
        st_uid = 0

    monkeypatch.setattr(pip.os, "access", lambda path, mode: False)
    monkeypatch.setattr(pip.os, "stat", lambda path: Owner())
    root_owned = pip.access(str(tmp_path / "pip.conf"))
    Owner.st_uid = 501
    someone_else = pip.access(str(tmp_path / "pip.conf"))
    monkeypatch.undo()
    assert (root_owned, someone_else) == (pip.Access.ADMINISTRATOR, pip.Access.NOT_WRITABLE)
    assert pip.access(str(tmp_path / "pip.conf")) is pip.Access.WRITABLE


@pytest.mark.parametrize(
    ("written", "verdict"),
    [
        ("2026-10-13T00:00:00+00:00", pip.Verdict.PROTECTED),  # today minus the cooldown
        ("2026-10-06", pip.Verdict.PROTECTED),  # exactly the tolerance (7 days) old
        ("2026-10-05T23:00:00Z", pip.Verdict.STALE),  # one day past it
        ("2026-10-14", pip.Verdict.WEAKER),  # later than today minus the cooldown
        ("P21D", pip.Verdict.REJECTED),  # pip 26.0 stops on a rolling form
        ("soon", pip.Verdict.UNREADABLE),
    ],
)
def test_stale_fixed_date_beyond_tolerance_fails(tmp_path: Path, written: str, verdict: pip.Verdict) -> None:
    venv = _venv(tmp_path, "fixed", "26.0.1")
    (venv / "pip.conf").write_text(f"[global]\nuploaded_prior_to = {written}\n")
    where = fake_mac(tmp_path)
    (env,) = discovery.survey(where, [str(tmp_path / "home" / "projects")]).environments
    state = pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=pip.Sources.of(where))
    assert state.verdict is verdict
    assert state.protected is (verdict is pip.Verdict.PROTECTED)
    if not state.protected:
        assert state.why.endswith("run protect again")


def test_tolerance_setting_cannot_raise_the_tolerance(tmp_path: Path) -> None:
    assert [pip.tolerance_days(days, None) for days in (0, 1, 3, 4, 21, 30)] == [1, 1, 1, 2, 7, 10]
    assert pip.tolerance_days(21, 30) == 7  # a larger setting cannot raise it
    assert pip.tolerance_days(21, 3) == 3  # a smaller one lowers it
    _config(tmp_path, "[defaults]\nfixed_date_tolerance_days = 30\n")
    assert cooldown_of(workstation_settings(str(tmp_path / "home"))) == (21, 7)


def test_protect_is_idempotent_on_re_run(tmp_path: Path) -> None:
    _config(tmp_path, "[defaults]\ncooldown_days = 30\n")
    venv = _venv(tmp_path, "app", "26.2.1")
    head = "# mine\n[global]\nindex-url = https://pypi.org/simple\n"
    tail = "[install]\n{}no-cache-dir = true\n"
    (venv / "pip.conf").write_text(f"{head}uploaded-prior-to = P3D\n  P4D\n{tail.format('')}")  # a continued value
    first, _ = _protect(tmp_path, paths=(str(venv),))  # the same --path each time (#255)
    written = (venv / "pip.conf").read_text()
    mtime = (venv / "pip.conf").stat().st_mtime_ns
    second, err = _protect(tmp_path, paths=(str(venv),))
    assert first.exit_code == second.exit_code == 0
    assert written == f"{head}uploaded-prior-to = P30D\n{tail.format('uploaded-prior-to = P30D' + chr(10))}"
    assert (venv / "pip.conf").read_text() == written  # no duplicate lines, nothing rewritten
    assert (venv / "pip.conf").stat().st_mtime_ns == mtime  # not even rewritten with the same bytes
    assert "Nothing to write" in err
    assert [c.place for c in second.checked] == [str(venv)]  # reported as checked and protected


def test_protect_with_no_python_found_exits_two(tmp_path: Path) -> None:
    # Error path (#229, L2-2): uv already protected and no Python under the named path is
    # unfinished (exit 2) there, as check --envs is (#67), never "every installation is protected".
    _config(tmp_path)
    projects = tmp_path / "home" / "projects"
    projects.mkdir(parents=True)
    program = tmp_path / "home" / ".local" / "bin" / "uv"
    program.parent.mkdir(parents=True)
    program.write_text("")
    config = tmp_path / "home" / ".config" / "uv" / "uv.toml"
    config.parent.mkdir(parents=True)
    config.write_text('exclude-newer = "P21D"\n\n[pip]\nexclude-newer = "P21D"\n')
    for _ in range(2):  # idempotent: the same answer on re-run, nothing written
        with refuses("protect.empty-path"):
            result, err = _protect(tmp_path)
        assert result.exit_code == 2
        assert [(s.reason, s.place, s.detail) for s in result.skipped] == [
            (SkipReason.CHECK_ERROR, os.path.realpath(projects), discovery.NO_ENVIRONMENT),
        ]
        assert not result.findings
        assert "no Python environment at or under it" in err and "Nothing to write." in err
        assert "every installation" not in err
        assert config.read_text() == 'exclude-newer = "P21D"\n\n[pip]\nexclude-newer = "P21D"\n'
    # protect uv asks only about uv: no Python is not its business, and uv is protected.
    only_uv, err = _protect(tmp_path, installer=Installer.UV, paths=(_uv_dir(tmp_path),))
    assert only_uv.exit_code == 0 and not only_uv.skipped and "every installation Guardian found" in err


def test_protect_reports_a_malformed_overrides_file(tmp_path: Path) -> None:
    # Contracts §10.1: protect reads overrides.toml too, so a malformed one is a check-error
    # naming it (exit 2); overrides never feed the write, which goes on.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    overrides = tmp_path / "home" / ".config" / "ssc-guardian" / "overrides.toml"
    overrides.write_text("format = 1\n[[override]\n")
    first, err = _protect(tmp_path)
    (skip,) = first.skipped
    assert (skip.place, skip.reason, skip.in_scope) == (os.path.realpath(overrides), SkipReason.CHECK_ERROR, True)
    assert first.exit_code == 2 and str(overrides) in err
    assert "uploaded-prior-to = P21D" in (venv / "pip.conf").read_text()
    second, err = _protect(tmp_path)  # a re-run reports it again, and writes nothing
    assert (second.exit_code, second.skipped) == (2, first.skipped)
    assert "Nothing to write" in err and str(overrides) in err


class _Broken(io.StringIO):
    """A stderr whose every write and flush fails, as a closed pipe's does."""

    def write(self, text: str) -> int:
        raise OSError("stderr is closed")

    def flush(self) -> None:
        raise OSError("stderr is closed")


@pytest.mark.parametrize("stream", ["closed", "broken"])
def test_protect_closed_stderr_after_write_keeps_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    # Contracts §3: "Written: ..." after a completed write turned exit 0 (and 1) into 2.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    where = fake_mac(tmp_path)
    err: io.StringIO | None = _Broken() if stream == "broken" else None
    monkeypatch.setattr(sys, "stderr", err)  # None is what Python sets when fd 2 is closed at start
    handler = Protect(where.home, where.environ, where.root, TODAY, io.StringIO(), err)

    def run() -> int:
        argv = ["protect", "--yes", "--path", str(tmp_path / "home" / "projects")]
        return cli.main(argv, handlers={Verb.PROTECT: handler}, stdout=io.StringIO(), stderr=err)

    assert run() == 0
    assert "uploaded-prior-to = P21D" in (venv / "pip.conf").read_text()
    _venv(tmp_path, "old", "25.3")  # ignores the setting: unprotected, with its reason on stderr
    assert run() == 1


def test_no_per_user_pip_file_is_written(tmp_path: Path) -> None:
    _config(tmp_path)
    where = fake_mac(tmp_path)
    make_base(Path(where.root) / "Library/Frameworks/Python.framework/Versions/3.12")
    user = Path(where.home) / "Library" / "Python" / "3.12" / "lib" / "python" / "site-packages"
    add_dist(user, "pip", "26.2.1")
    venv = _venv(tmp_path, "app", "26.2.1")
    framework = Path(os.path.realpath(Path(where.root) / "Library/Frameworks/Python.framework/Versions/3.12"))
    before = sorted(p for p in tmp_path.rglob("*"))
    result, _ = _protect(tmp_path, paths=(str(venv.parent), str(framework)))
    after = sorted(p for p in tmp_path.rglob("*"))
    assert result.exit_code == 0
    assert set(after) - set(before) == {Path(str(framework / "pip.conf")), Path(str(venv / "pip.conf"))}
    for user_file in (".pip/pip.conf", ".config/pip/pip.conf", "Library/Application Support/pip/pip.conf"):
        assert not (Path(where.home) / user_file).exists()


def test_declined_or_no_terminal_writes_nothing_and_exits_two(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    declined, err = _protect(tmp_path, yes=False, answer="n\n")
    assert declined.exit_code == 2 and not (venv / "pip.conf").exists()
    assert "Proceed? [y/N]" in err and "Add --yes to confirm in advance" in err
    no_terminal, _ = _protect(tmp_path, yes=False)
    assert no_terminal.exit_code == 2 and not (venv / "pip.conf").exists()
    confirmed, err = _protect(tmp_path, yes=False, answer="y\n")
    assert confirmed.exit_code == 0 and (venv / "pip.conf").exists()


def test_yes_still_prints_the_change_to_stderr(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    _, err = _protect(tmp_path, yes=True)
    assert f"{venv}/pip.conf: (no setting) -> P21D" in err
    assert "Confirmed in advance (--yes)." in err


def test_uv_window_written_kept_and_verified(tmp_path: Path) -> None:
    _config(tmp_path)
    config = tmp_path / "home" / ".config" / "uv" / "uv.toml"
    config.parent.mkdir(parents=True)
    config.write_text('# keep me\nnative-tls = true\nexclude-newer = "3 days"\n\n[pip]\nexclude-newer = "P1D"\n')
    named = (_uv_dir(tmp_path),)
    result, err = _protect(tmp_path, installer=Installer.UV, paths=named)
    assert result.exit_code == 0
    assert config.read_text() == (
        '# keep me\nnative-tls = true\nexclude-newer = "P21D"\n\n[pip]\nexclude-newer = "P21D"\n'
    )
    assert 'exclude-newer = "P21D"' in err and "[tool.uv]" in err  # the project line is shown
    assert uv.UvPlugin().installer_cooldown(str(config)) == CooldownSetting(str(config), rolling_days=21)
    again, err = _protect(tmp_path, installer=Installer.UV, paths=named)
    assert again.exit_code == 0 and "Nothing to write" in err

    overridden, err = _protect(tmp_path, installer=Installer.UV, paths=named, UV_EXCLUDE_NEWER="1 day")
    assert overridden.exit_code == 1 and "UV_EXCLUDE_NEWER overrides" in err


def test_write_cooldown_refuses_a_setting_with_no_value(tmp_path: Path) -> None:
    place = str(tmp_path / "pip.conf")
    with pytest.raises(ValueError, match="removing the cooldown"):
        pip.PipPlugin(fake_mac(tmp_path)).write_cooldown(CooldownSetting(place))
    with pytest.raises(ValueError, match="a setting with no value would remove the cooldown"):
        uv.UvPlugin().write_cooldown(CooldownSetting(place))
    assert not Path(place).exists()


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("PIP_UPLOADED_PRIOR_TO", "P0D"),
        ("PIP_Uploaded_Prior_To", "P0D"),
        ("PIP_CONFIG_FILE", ""),  # the null device
        ("PIP_CONFIG_FILE", "[global]\nuploaded-prior-to =\n[install]\nuploaded-prior-to =\n"),
        ("PIP_CONFIG_FILE", "[DEFAULT]\nuploaded-prior-to =\n[global]\n[install]\n"),
    ],
)
def test_an_outside_override_is_never_written_over(tmp_path: Path, variable: str, value: str) -> None:
    # Review finding: with no pip.conf yet, protect wrote one and exited 0 although the variable
    # still overruled it. The override is now judged first; nothing is written, exit 1.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    if variable == "PIP_CONFIG_FILE":  # an empty value in a later file erases the site file's
        other = tmp_path / "other.conf"
        other.write_text(value)
        value = str(other) if value else os.devnull
    result, err = _protect(tmp_path, env={variable: value})
    assert result.exit_code == 1 and [f.rule for f in result.findings] == [Rule.UNPROTECTED]
    assert f"overrides {venv}/pip.conf; remove it, then run protect again" in err
    assert not (venv / "pip.conf").exists()


def test_an_empty_variable_is_not_an_override(tmp_path: Path) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    result, _ = _protect(tmp_path, PIP_UPLOADED_PRIOR_TO="")  # pip drops an empty value
    assert result.exit_code == 0


def test_a_per_user_install_value_is_beaten_by_writing_both_sections(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    (venv / "pip.conf").write_text("[global]\nuploaded-prior-to = P21D\n")
    user = tmp_path / "home" / ".config" / "pip" / "pip.conf"
    user.parent.mkdir(parents=True)
    user.write_text("[install]\nuploaded-prior-to = P1D\n")  # beats a site [global] value
    where = fake_mac(tmp_path)
    (env,) = discovery.survey(where, [str(tmp_path / "home" / "projects")]).environments
    sources = pip.Sources.of(where)
    assert pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=sources).verdict is pip.Verdict.SHADOWED
    result, _ = _protect(tmp_path)
    assert result.exit_code == 0
    assert pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=sources).protected
    assert user.read_text() == "[install]\nuploaded-prior-to = P1D\n"  # the per-user file is never written


def test_a_hidden_pip_26_0_gets_the_fixed_form(tmp_path: Path) -> None:
    _config(tmp_path)
    where = fake_mac(tmp_path)
    prefix = Path(where.home) / ".pyenv" / "versions" / "3.12.4"
    add_dist(make_base(prefix), "pip", "26.0.1")  # runs whenever the per-user folder is off
    add_dist(Path(where.home) / ".local" / "lib" / "python3.12" / "site-packages", "pip", "26.2.1")
    result, _ = _protect(tmp_path, paths=(os.path.realpath(prefix),))
    assert result.exit_code == 0
    assert "P21D" not in (prefix / "pip.conf").read_text()
    assert "uploaded-prior-to = 2026-10-13T00:00:00+00:00" in (prefix / "pip.conf").read_text()


def test_other_sections_keep_their_own_value(tmp_path: Path) -> None:
    text = "[DEFAULT]\nuploaded-prior-to = P90D\n[download]\nuploaded-prior-to = P90D\n"
    assert pip.with_value(text, "P21D") == (
        text + "\n[global]\nuploaded-prior-to = P21D\n\n[install]\nuploaded-prior-to = P21D\n"
    )


@pytest.mark.parametrize("text", ["2026-10-13 junk", "2026-10-13T00:00:00.5+00:00", "13/10/2026"])
def test_dates_outside_the_portable_forms_are_unreadable(text: str) -> None:
    assert pip.parse_value(text, "/p/pip.conf") is None
    assert uv.parse_value(text, "/p/uv.toml") is None


@pytest.mark.parametrize("override", ["UV_EXCLUDE_NEWER", "file-package"])
def test_uv_overrides_are_judged_before_writing(tmp_path: Path, override: str) -> None:
    _config(tmp_path)
    config = tmp_path / "home" / ".config" / "uv" / "uv.toml"
    environ: dict[str, str] = {}
    if override == "file-package":
        config.parent.mkdir(parents=True)
        config.write_text('[exclude-newer-package]\nrequests = "2026-11-02"\n')
    else:
        environ[override] = "1 day"
    before = config.read_text() if config.exists() else None
    result, err = _protect(tmp_path, installer=Installer.UV, env=environ, paths=(_uv_dir(tmp_path),))
    assert result.exit_code == 1 and "run protect uv" in err
    assert (config.read_text() if config.exists() else None) == before  # nothing written


def test_a_lower_case_variable_is_not_read_by_pip(tmp_path: Path) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    result, _ = _protect(tmp_path, env={"pip_uploaded_prior_to": "P0D"})  # pip reads PIP_ only
    assert result.exit_code == 0


def test_an_override_offers_no_protect_fix(tmp_path: Path) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    result, _ = _protect(tmp_path, env={"PIP_UPLOADED_PRIOR_TO": "P0D"})
    (finding,) = result.findings
    assert finding.options == ()  # running protect again would not fix it


def test_apple_python_is_left_to_an_administrator(tmp_path: Path) -> None:
    _config(tmp_path)
    where = fake_mac(tmp_path)
    prefix = (
        Path(where.root) / "Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9"
    )
    add_dist(make_base(prefix, "3.9"), "pip", "26.0.1")
    # The bundle is writable here, as an unpacked Xcode is.
    result, err = _protect(tmp_path, paths=(os.path.realpath(prefix),))
    (finding,) = result.findings
    assert (finding.rule, finding.options, result.exit_code) == (Rule.UNPROTECTED, (), 1)
    assert "signed Apple bundle" in err and not (prefix / "pip.conf").exists()


def test_a_symlinked_pip_conf_is_never_written_through(tmp_path: Path) -> None:
    # Review finding: a shared dotfile could get a form one of its pips rejects, and a link to
    # the per-user file would make protect write it. A person sets a linked file by hand.
    _config(tmp_path)
    old, new = _venv(tmp_path, "old", "26.0.1"), _venv(tmp_path, "new", "26.2.1")
    dotfile = tmp_path / "dotfiles" / "pip.conf"
    dotfile.parent.mkdir()
    dotfile.write_text("[global]\ntimeout = 30\n")
    (old / "pip.conf").symlink_to(dotfile)
    user = tmp_path / "home" / ".config" / "pip" / "pip.conf"
    user.parent.mkdir(parents=True)
    user.write_text("")
    (new / "pip.conf").symlink_to(user)
    result, err = _protect(tmp_path)
    assert result.exit_code == 1
    assert [(f.rule, f.options) for f in result.findings] == [(Rule.UNPROTECTED, ())] * 2
    assert dotfile.read_text() == "[global]\ntimeout = 30\n" and user.read_text() == ""
    assert f"is a symlink to {os.path.realpath(dotfile)}" in err
    with (
        refuses("pip.symlink-set-key-target-hand"),
        pytest.raises(ConfigFileError, match="is a symlink; set the key at its target by hand"),
    ):
        pip.PipPlugin(fake_mac(tmp_path)).write_cooldown(CooldownSetting(str(old / "pip.conf"), rolling_days=21))


def test_a_symlinked_uv_config_stays_a_link(tmp_path: Path) -> None:
    _config(tmp_path)
    uv_dotfile = tmp_path / "dotfiles" / "uv.toml"
    uv_dotfile.parent.mkdir()
    uv_dotfile.write_text("native-tls = true\n")
    uv_config = tmp_path / "home" / ".config" / "uv" / "uv.toml"
    uv_config.parent.mkdir(parents=True)
    uv_config.symlink_to(uv_dotfile)  # one per-user file: writing its target is writing uv's config
    # #255: the link leads out of ~/.config/uv, so naming only that folder writes nothing there.
    with refuses("protect.uv-config-outside"):
        outside, err = _protect(tmp_path, installer=Installer.UV, paths=(_uv_dir(tmp_path),))
    assert outside.exit_code == 2 and uv_dotfile.read_text() == "native-tls = true\n"
    assert "outside the named paths; name that file with --path" in err
    # Named as the file itself (the CLI resolves it to the dotfile), it is written through the link.
    result, _ = _protect(tmp_path, installer=Installer.UV, paths=(os.path.realpath(uv_config),))
    assert result.exit_code == 0 and uv_config.is_symlink()
    assert 'exclude-newer = "P21D"' in uv_dotfile.read_text()


def test_default_values_and_a_second_spelling_do_not_block_the_write(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    (venv / "pip.conf").write_text(
        "[DEFAULT]\ntimeout = 30\n[global]\nuploaded-prior-to = P3D\nuploaded_prior_to = P4D\n"
    )
    result, _ = _protect(tmp_path)
    assert result.exit_code == 0
    assert (venv / "pip.conf").read_text() == (
        "[DEFAULT]\ntimeout = 30\n[global]\nuploaded-prior-to = P21D\n\n[install]\nuploaded-prior-to = P21D\n"
    )


def test_pip_config_file_naming_a_global_or_the_site_file_is_not_an_override(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    global_file = tmp_path / "root" / "Library" / "Application Support" / "pip" / "pip.conf"
    global_file.parent.mkdir(parents=True)
    global_file.write_text("[install]\nuploaded-prior-to = P1D\n")
    for named in (global_file, venv / "pip.conf"):
        result, _ = _protect(tmp_path, env={"PIP_CONFIG_FILE": str(named)})
        assert result.exit_code == 0, named  # pip keeps a repeated file at its first place


def test_an_unreadable_pip_version_gets_the_fixed_form(tmp_path: Path) -> None:
    _config(tmp_path)
    where = fake_mac(tmp_path)
    prefix = Path(where.home) / ".pyenv" / "versions" / "3.12.4"
    add_dist(make_base(prefix), "pip", "not-a-version")
    add_dist(Path(where.home) / ".local" / "lib" / "python3.12" / "site-packages", "pip", "26.2.1")
    result, _ = _protect(tmp_path, paths=(os.path.realpath(prefix),))
    assert [f.rule for f in result.findings] == [Rule.MALFORMED_NAME]  # the version itself is reported
    assert "uploaded-prior-to = 2026-10-13T00:00:00+00:00" in (prefix / "pip.conf").read_text()


@pytest.mark.parametrize(
    ("relative", "xdg"),
    [("etc/xdg/uv/uv.toml", None), ("etc/uv/uv.toml", None), ("etc/uv/uv.toml", "nowhere"), ("cfg/uv/uv.toml", "cfg")],
)
def test_a_system_uv_exemption_is_an_override(tmp_path: Path, relative: str, xdg: str | None) -> None:
    _config(tmp_path)
    system = tmp_path / "root" / relative
    system.parent.mkdir(parents=True)
    system.write_text('[exclude-newer-package]\nrequests = "2026-11-02"\n')
    env = {"XDG_CONFIG_DIRS": str(tmp_path / "root" / xdg)} if xdg else {}
    named = (_uv_dir(tmp_path),)
    result, err = _protect(tmp_path, installer=Installer.UV, env=env, paths=named)
    assert result.exit_code == 1 and f"{system} sets exclude-newer-package" in err
    ignored, _ = _protect(tmp_path, installer=Installer.UV, env={**env, "UV_NO_SYSTEM_CONFIG": "1"}, paths=named)
    assert ignored.exit_code == 0


# --- index settings (#130): check --envs reads them; protect neither reads nor writes them ----


def _surveyed(tmp_path: Path, **environ: str) -> tuple[discovery.Environment, pip.Sources]:
    where = fake_mac(tmp_path, **environ)
    (env,) = discovery.survey(where, [str(tmp_path / "home" / "projects")]).environments
    return env, pip.Sources.of(where)


def _user_pip_conf(tmp_path: Path, text: str) -> Path:
    user = tmp_path / "home" / ".config" / "pip" / "pip.conf"
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(text)
    return user


@pytest.mark.parametrize("where", ["user", "global", "site", "pip-config-file"])
def test_extra_index_url_in_user_pip_conf_is_reported(tmp_path: Path, where: str) -> None:
    # The issue's input (a per-user file), and the other files pip reads for a venv.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    assert _protect(tmp_path)[0].exit_code == 0
    line = "extra-index-url = https://pkgs.example.net/simple\n"
    environ: dict[str, str] = {}
    if where == "user":
        place, section = _user_pip_conf(tmp_path, f"[global]\n{line}"), "global"
    elif where == "global":
        place, section = tmp_path / "root" / "Library" / "Application Support" / "pip" / "pip.conf", "global"
        place.parent.mkdir(parents=True)
        place.write_text(f"[global]\n{line}")
    elif where == "site":
        place, section = venv / "pip.conf", "install"
        place.write_text(place.read_text() + line)  # protect's file ends in its [install] section
    else:
        place, section = tmp_path / "other.conf", "install"
        place.write_text(f"[install]\n{line}")
        environ = {"PIP_CONFIG_FILE": str(place)}
    env, sources = _surveyed(tmp_path, **environ)
    assessment = pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=sources)
    assert assessment.verdict is pip.Verdict.PROTECTED  # all check saw before #130
    assert pip.other_indexes(env.pip_conf, sources) == [f"{place} sets extra-index-url in [{section}]"]
    finding = unprotected(env.prefix, pip.Verdict.OTHER_INDEX, Installer.PIP)
    assert (finding.rule, finding.options) == (Rule.UNPROTECTED, ())  # protect does not fix it
    again, _ = _protect(tmp_path, env=environ)  # protect's own verdict does not change
    assert again.exit_code == 0


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("PIP_EXTRA_INDEX_URL", "https://pkgs.example.net/simple"),
        ("PIP_INDEX_URL", "https://mirror.example.net/simple"),
        ("PIP_FIND_LINKS", "/Users/me/wheels"),
        ("PIP_Extra_Index_Url", "https://pkgs.example.net/simple"),  # pip normalizes the name
        ("PIP_EXTRA_INDEX_URL", "https://pypi.org/simple https://pkgs.example.net/simple"),
    ],
)
def test_exported_pip_extra_index_url_is_reported(tmp_path: Path, variable: str, value: str) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    _protect(tmp_path)
    env, sources = _surveyed(tmp_path, **{variable: value})
    assert pip.other_indexes(env.pip_conf, sources) == [f"{variable} is set"]


@pytest.mark.parametrize(
    ("value", "reported"),
    [
        ("https://pypi.org/simple", False),
        ("https://pypi.org/simple/", False),
        ("https://pypi.org/simple https://pypi.org/simple/", False),
        ("http://pypi.org/simple", True),  # exactly PyPI's URL, nothing near it
        ("https://pypi.org/simple//", True),
        ("https://pypi.python.org/simple", True),
        ("https://PYPI.org/simple", True),
    ],
)
def test_pypi_index_url_is_not_reported(tmp_path: Path, value: str, reported: bool) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    user = _user_pip_conf(tmp_path, f"[global]\nindex-url = {value}\n[install]\nextra-index-url =\n")
    env, sources = _surveyed(tmp_path, PIP_INDEX_URL=value, PIP_FIND_LINKS="")  # empty: pip drops it
    found = pip.other_indexes(env.pip_conf, sources)
    assert found == ([f"{user} sets index-url in [global]", "PIP_INDEX_URL is set"] if reported else [])


@pytest.mark.parametrize(
    ("text", "site"),
    [
        ("extra-index-url = https://pkgs.example.net/simple\n", refuses("pip.not-valid-pip-configuration-file")),
        (None, refuses("settings.read-failed")),  # a folder in the file's place: reading it fails
    ],
)
def test_unreadable_pip_conf_stays_check_error(tmp_path: Path, text: str | None, site: Refuses) -> None:
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")  # no pip.conf yet: the cooldown check alone never reads the user file
    if text is None:
        (tmp_path / "home" / ".config" / "pip" / "pip.conf").mkdir(parents=True)
    else:
        _user_pip_conf(tmp_path, text)
    env, sources = _surveyed(tmp_path)
    assert pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=sources).verdict is pip.Verdict.MISSING
    with site, pytest.raises(ConfigFileError) as raised:
        pip.other_indexes(env.pip_conf, sources)
    assert raised.value.reason is SkipReason.CHECK_ERROR and raised.value.reason.in_scope
    # As check --envs runs it: an unfinished check (exit 2), never a pass, the venv not checked.
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, env.prefix):
        pip.other_indexes(env.pip_conf, sources)
    result = collector.result()
    assert result.exit_code == 2 and result.checked == () and result.findings == ()


def test_index_reading_is_idempotent_on_re_run(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    _protect(tmp_path)
    user = _user_pip_conf(
        tmp_path, "[global]\nindex-url = https://mirror.example.net/simple\n[install]\nfind-links = /wheels\n"
    )
    before = {p: p.read_bytes() for p in sorted(tmp_path.rglob("*")) if p.is_file()}
    # PIP_CONFIG_FILE naming the user file: pip reads it once, so it is named once.
    env, sources = _surveyed(tmp_path, PIP_CONFIG_FILE=str(user), PIP_FIND_LINKS="/more")
    first, second = pip.other_indexes(env.pip_conf, sources), pip.other_indexes(env.pip_conf, sources)
    named = [f"{user} sets index-url in [global]", f"{user} sets find-links in [install]", "PIP_FIND_LINKS is set"]
    assert first == second == named
    assert {p: p.read_bytes() for p in sorted(tmp_path.rglob("*")) if p.is_file()} == before
    assert (venv / "pip.conf").exists()


def test_pypi_url_is_the_index_url_by_another_name(tmp_path: Path) -> None:
    # Review finding: pip looks a key up as "--" + key, and --pypi-url is --index-url's other name.
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    user = _user_pip_conf(tmp_path, "[global]\npypi-url = https://pkgs.example.net/simple\n")
    env, sources = _surveyed(tmp_path, PIP_PYPI_URL="https://pkgs.example.net/simple")
    assert pip.other_indexes(env.pip_conf, sources) == [f"{user} sets pypi-url in [global]", "PIP_PYPI_URL is set"]


def test_a_broken_file_never_hides_the_files_after_it(tmp_path: Path) -> None:
    # Review finding: the reading stopped at the first file that failed.
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    legacy = tmp_path / "home" / ".pip" / "pip.conf"  # read first
    legacy.parent.mkdir(parents=True)
    legacy.write_text("[global\n")
    user = _user_pip_conf(tmp_path, "[global]\nextra-index-url = https://pkgs.example.net/simple\n")
    env, sources = _surveyed(tmp_path)
    read: list[str] = []
    with refuses("pip.not-valid-pip-configuration-file"), pytest.raises(ConfigFileError, match=str(legacy)):
        pip.other_indexes(env.pip_conf, sources, read)
    assert read == [f"{user} sets extra-index-url in [global]"]


@pytest.mark.parametrize("key", ["constraint", "requirement"])
def test_a_constraint_or_requirement_file_is_reported_unread(tmp_path: Path, key: str) -> None:
    # Owner ruling of 2026-11-10: such a file's own --index-url line moves pip to another index,
    # so the setting is reported whatever its value, and the file it names is never opened.
    _config(tmp_path)
    _venv(tmp_path, "app", "26.2.1")
    named = tmp_path / "never-read.txt"  # does not exist: Guardian must not need it
    user = _user_pip_conf(tmp_path, f"[install]\n{key} = {named}\n")
    variable = f"PIP_{key.upper()}"
    env, sources = _surveyed(tmp_path, **{variable: "https://pypi.org/simple"})  # even a PyPI-looking value
    assert pip.other_indexes(env.pip_conf, sources) == [f"{user} sets {key} in [install]", f"{variable} is set"]
    assert not named.exists()


# --- a value read from a file is one value on its change line (#161) ----------------------

FORGED = "Guardian will write nothing else"  # a continuation line that reads like Guardian's own


def _continued(tmp_path: Path) -> Path:
    """A venv whose pip.conf continues its cooldown value onto a second line (configparser keeps
    the break in the value)."""
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    (venv / "pip.conf").write_text(f"[global]\nuploaded-prior-to = P7D\n  {FORGED}\n")
    return venv


@pytest.mark.parametrize("yes", [False, True], ids=["prompt", "yes-record"])
def test_multi_line_pip_conf_value_is_one_change_line(tmp_path: Path, yes: bool) -> None:
    venv = _continued(tmp_path)
    result, err = _protect(tmp_path, yes=yes, answer=None if yes else "n\n")
    lines = err.splitlines()
    head = lines.index("Guardian will write its cooldown setting (and nothing else):")
    assert lines[head + 1] == f"  {venv}/pip.conf: P7D{FORGED} -> P21D"
    assert not any(line.startswith(FORGED) for line in lines)
    # What protect writes is its own value, and the exit code is as before.
    both = "[global]\nuploaded-prior-to = P21D\n\n[install]\nuploaded-prior-to = P21D\n"
    assert result.exit_code == (0 if yes else 2)
    assert (venv / "pip.conf").read_text() == (both if yes else f"[global]\nuploaded-prior-to = P7D\n  {FORGED}\n")


def test_protect_prompt_is_idempotent_on_re_run(tmp_path: Path) -> None:
    venv = _continued(tmp_path)
    before = (venv / "pip.conf").read_text()
    first, said = _protect(tmp_path, yes=False, answer="n\n")
    second, again = _protect(tmp_path, yes=False, answer="n\n")
    assert first.exit_code == second.exit_code == 2
    assert said == again  # the same files give the same change text
    assert f"  {venv}/pip.conf: P7D{FORGED} -> P21D" in said.splitlines()
    assert (venv / "pip.conf").read_text() == before  # declined: nothing written


# --- #255: protect writes only under the paths its --path arguments name ------------------------


def _tree(tmp_path: Path) -> dict[str, tuple[bytes, int]]:
    """Every file under the fake Mac, with its bytes and mtime: a run that changes any shows."""
    return {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in sorted(tmp_path.rglob("*")) if p.is_file()}


def test_protect_writes_only_under_the_named_path(tmp_path: Path) -> None:
    _config(tmp_path)
    named = _venv(tmp_path, "named", "26.2.1")
    other = _venv(tmp_path, "other", "26.2.1")
    (other / "pip.conf").write_text("[global]\nuploaded-prior-to = P1D\n")  # weak: protect would fix it
    before = (other / "pip.conf").read_bytes(), (other / "pip.conf").stat().st_mtime_ns

    result, err = _protect(tmp_path, paths=(str(named),))

    assert result.exit_code == 0, result
    assert "uploaded-prior-to = P21D" in (named / "pip.conf").read_text()
    assert ((other / "pip.conf").read_bytes(), (other / "pip.conf").stat().st_mtime_ns) == before
    assert str(other) not in err  # never shown as a change either
    assert [c.place for c in result.checked] == [str(named)]


def test_protect_without_path_is_a_usage_error_and_writes_nothing(tmp_path: Path) -> None:
    # Negative (#255): a bare protect is refused from its arguments alone, before anything is
    # read, so nothing under the fake Mac changes; the message shows the --path form.
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    (venv / "pip.conf").write_text("[global]\nuploaded-prior-to = P1D\n")
    where = fake_mac(tmp_path)
    before = _tree(tmp_path)
    for argv in (["protect", "--yes"], ["protect", "pip", "--yes"], ["protect", "uv", "--yes"]):
        out, err = io.StringIO(), io.StringIO()
        handler = Protect(where.home, where.environ, where.root, TODAY, io.StringIO(), err)
        with refuses("cli.argparse-usage-error"):
            code = cli.main(argv, handlers={Verb.PROTECT: handler}, stdout=out, stderr=err)
        assert code == 2, argv
        assert "the following arguments are required: --path" in err.getvalue(), argv
        assert "--path PATH" in err.getvalue()  # the usage line shows the form to use
        assert out.getvalue() == ""
    assert _tree(tmp_path) == before


def test_protect_uv_needs_the_uv_config_named(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    config = tmp_path / "home" / ".config" / "uv" / "uv.toml"
    with refuses("protect.uv-config-not-named"):
        missed, err = _protect(tmp_path, installer=Installer.UV, paths=(str(venv),))
    assert missed.exit_code == 2
    assert [(s.place, s.reason) for s in missed.skipped] == [(str(venv), SkipReason.CHECK_ERROR)]
    assert "name it, or its folder, with --path" in err
    assert not config.exists() and not (venv / "pip.conf").exists()  # protect uv never writes pip

    named, _ = _protect(tmp_path, installer=Installer.UV, paths=(_uv_dir(tmp_path),))
    assert named.exit_code == 0
    assert 'exclude-newer = "P21D"' in config.read_text()


def test_unprotected_finding_suggests_protect_with_its_place(tmp_path: Path) -> None:
    _config(tmp_path)
    venv = _venv(tmp_path, "app", "26.2.1")
    finding = unprotected(str(venv), pip.Verdict.MISSING, Installer.PIP)
    (option,) = finding.options
    assert option.command == ("ssc-guardian", "protect", "pip", "--path", str(venv))
    config = os.path.join(_uv_dir(tmp_path), "uv.toml")
    (uv_option,) = unprotected(config, pip.Verdict.WEAKER, Installer.UV).options
    assert uv_option.command == ("ssc-guardian", "protect", "uv", "--path", config)
    # The fix acts on exactly what was reported: another place, or the bare form, is refused.
    from ssc_guardian.findings import Option, OptionKind, make_finding, protect_command

    elsewhere = Option(OptionKind.PROTECT, command=protect_command(str(tmp_path), Installer.PIP))
    with pytest.raises(ValueError, match="--path is its finding's place"):
        make_finding(Rule.UNPROTECTED, Ecosystem.PYPI, place=str(venv), options=(elsewhere,))
    with pytest.raises(ValueError, match="must be built by"):
        Option(OptionKind.PROTECT, command=("ssc-guardian", "protect", "pip"))
