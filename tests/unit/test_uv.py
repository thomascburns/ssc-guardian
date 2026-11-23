# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``check --envs`` and what beats uv's per-user window (issues #150 and #130; plan §10.4).

uv lets a project's ``uv.toml`` or ``pyproject.toml`` ``[tool.uv]`` replace the per-user
``exclude-newer`` window, and an index setting or ``UV_`` index variable add a source the
cooldown does not cover. Each test builds a fake Mac under ``tmp_path`` (``test_discovery``):
uv is "installed" as an empty file, the user window is protected, and the venvs hold no
packages, so the run reads no feed and reaches no network.
"""

from __future__ import annotations

import io
import os
from datetime import date
from pathlib import Path

import pytest

from ssc_guardian.cli import Request
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.protect import Protect
from ssc_guardian.findings import Ecosystem, Result, Rule, Scope, SkipReason, Verb
from ssc_guardian.plugins import pip, uv
from tests.refusal_sites import Refuses, refuses
from tests.unit.test_discovery import fake_mac, make_venv

TODAY = date(2026, 11, 3)  # 21 days earlier: 2026-10-13


def _home(tmp_path: Path, window: str = "P21D") -> Path:
    """The workstation: settings, a uv program, and the per-user window ``protect`` writes."""
    home = tmp_path / "home"
    settings = home / ".config" / "ssc-guardian"
    settings.mkdir(parents=True)
    (settings / "config.toml").write_text("format = 1\n")
    program = home / ".local" / "bin" / "uv"
    program.parent.mkdir(parents=True)
    program.write_text("")
    user = home / ".config" / "uv" / "uv.toml"
    user.parent.mkdir(parents=True)
    user.write_text(f'exclude-newer = "{window}"\n')
    return home


def _project(tmp_path: Path, name: str = "app") -> Path:
    """A project folder under ``~/projects`` holding an empty venv, resolved."""
    folder = tmp_path / "home" / "projects" / name
    make_venv(folder / ".venv")
    return Path(os.path.realpath(folder))


def _named(tmp_path: Path) -> tuple[str, ...]:
    """What these runs name with --path (#255): the projects folder and uv's user config folder."""
    return tuple(os.path.realpath(tmp_path / "home" / p) for p in ("projects", ".config/uv"))


def _check(tmp_path: Path, **environ: str) -> tuple[Result, str]:
    where = fake_mac(tmp_path, **environ)
    err = io.StringIO()
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, None, err)
    scope = Scope(frozenset({Ecosystem.PYPI}), _named(tmp_path))
    return handler(Request(Verb.CHECK, scope=scope)), err.getvalue()


def _violations(result: Result) -> list[tuple[Rule, str | None, tuple[object, ...]]]:
    return [(f.rule, f.place, f.options) for f in result.findings]


def _tree(folder: Path) -> dict[str, bytes]:
    return {str(p): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}


def test_project_uv_toml_weaker_window_is_unprotected(tmp_path: Path) -> None:
    # The issue's input: the user window protected, and a project file beside the venv lifting it.
    home = _home(tmp_path)
    app = _project(tmp_path)
    (app / "uv.toml").write_text('exclude-newer = "2100-01-01"\n')
    (app / "pyproject.toml").write_text('[tool.uv]\nexclude-newer = "2100-01-01"\n')
    where = fake_mac(tmp_path)
    user = uv.assess(where, cooldown_days=21, tolerance=7, today=TODAY)
    assert user.verdict is pip.Verdict.PROTECTED  # what check reported alone before #150
    result, err = _check(tmp_path)
    assert result.exit_code == 1
    # uv.toml wins over the pyproject.toml beside it, as uv reads them; protect is not its fix.
    assert _violations(result) == [(Rule.UNPROTECTED, str(app / "uv.toml"), ())]
    assert f"{app}/uv.toml accepts uploads after 2026-10-13; uv prefers it to the user file in {app}" in err
    assert (home / ".config" / "uv" / "uv.toml").read_text() == 'exclude-newer = "P21D"\n'


@pytest.mark.parametrize(
    ("table", "said"),
    [
        ('exclude-newer = "P3D"', "holds 3 days, under the 21-day cooldown"),
        ('exclude-newer = "1 day"', "holds 1 days, under the 21-day cooldown"),
        ('exclude-newer = "2026-11-01"', "accepts uploads after 2026-10-13"),
        ('exclude-newer = ""', "sets an exclude-newer Guardian cannot read"),  # a removed window
        ("exclude-newer = 5", "sets an exclude-newer Guardian cannot read"),
        ('[tool.uv.pip]\nexclude-newer = "P1D"', "holds 1 days"),  # the copy `uv pip` prefers
        ('exclude-newer-package = { requests = "2100-01-01" }', "sets exclude-newer-package"),
        ('[tool.uv.pip]\nexclude-newer-package = { requests = "2100-01-01" }', "sets exclude-newer-package"),
    ],
)
def test_project_pyproject_tool_uv_weaker_window_is_unprotected(tmp_path: Path, table: str, said: str) -> None:
    _home(tmp_path)
    app = _project(tmp_path)
    pyproject = app / "pyproject.toml"
    header = "" if table.startswith("[tool.uv.") else "[tool.uv]\n"
    pyproject.write_text(f'[project]\nname = "app"\n\n{header}{table}\n')
    result, err = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(pyproject), ())]
    assert f"{pyproject} {said}" in err


@pytest.mark.parametrize(
    ("name", "text", "site"),
    [
        ("uv.toml", "exclude-newer = \n", refuses("uv.not-valid-toml")),
        ("pyproject.toml", "[tool.uv\n", refuses("uv.not-valid-toml")),  # uv only warns and moves on
        ("pyproject.toml", "tool = 1\n", refuses("uv.project-tool-uv-not-table")),
        ("pyproject.toml", "[tool]\nuv = 2\n", refuses("uv.project-tool-uv-not-table")),
        ("uv.toml", b"exclude-newer = '\xff'\n", refuses("settings.not-utf8")),
    ],
)
def test_unreadable_project_uv_file_is_check_error(tmp_path: Path, name: str, text: str | bytes, site: Refuses) -> None:
    _home(tmp_path)
    app = _project(tmp_path)
    place = app / name
    place.write_bytes(text if isinstance(text, bytes) else text.encode())
    with site:
        result, err = _check(tmp_path)
    assert result.exit_code == 2  # never a pass: the file might lift the window
    assert result.findings == ()
    (skip,) = [s for s in result.skipped if s.reason is SkipReason.CHECK_ERROR]
    assert (skip.ecosystem, skip.place, skip.reason.in_scope) == (Ecosystem.PYPI, str(place), True)
    assert str(place) in err


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("uv.toml", 'exclude-newer = "P21D"\n'),  # equal
        ("uv.toml", 'exclude-newer = "P30D"\n'),
        ("uv.toml", 'exclude-newer = "3 weeks"\n'),
        ("uv.toml", 'exclude-newer = "2026-01-01"\n'),  # an older date is stricter, and never stale here
        ("uv.toml", 'index-url = "https://pypi.org/simple/"\n[pip]\nexclude-newer = "P21D"\n'),
        ("pyproject.toml", '[tool.uv]\nexclude-newer = "P28D"\n'),
        ("pyproject.toml", "[tool.uv]\ndev-dependencies = []\n"),  # no window: the user's applies
        ("pyproject.toml", '[project]\nname = "app"\n'),  # no [tool.uv]: passed over, nothing found
    ],
)
def test_project_window_equal_or_stricter_passes(tmp_path: Path, name: str, text: str) -> None:
    _home(tmp_path)
    app = _project(tmp_path)
    (app / name).write_text(text)
    result, err = _check(tmp_path)
    assert result.exit_code == 0, err
    assert result.findings == ()
    found = name == "uv.toml" or "[tool.uv]" in text
    assert ((Ecosystem.PYPI, str(app / name)) in [(c.ecosystem, c.place) for c in result.checked]) is found


def test_project_scan_is_idempotent_on_re_run(tmp_path: Path) -> None:
    # One file above two venvs is judged once; a second run gives the same result and writes nothing.
    _home(tmp_path)
    first, second = _project(tmp_path, "a"), _project(tmp_path, "b")
    shared = first.parent / "uv.toml"
    shared.write_text('exclude-newer = "P2D"\n')
    before = _tree(tmp_path)
    one, two = _check(tmp_path), _check(tmp_path)
    assert one == two
    result, err = one
    assert _violations(result) == [(Rule.UNPROTECTED, str(shared), ())]
    assert [c.place for c in result.checked].count(str(shared)) == 1
    assert err.count(f"{shared} holds 2 days") == 1
    assert {str(first / ".venv"), str(second / ".venv")} <= {c.place for c in result.checked}
    assert _tree(tmp_path) == before


def test_a_pyproject_without_tool_uv_is_passed_over(tmp_path: Path) -> None:
    # uv goes on searching past a pyproject.toml with no [tool.uv] table, so Guardian does too.
    _home(tmp_path)
    app = _project(tmp_path)
    (app / "pyproject.toml").write_text('[project]\nname = "app"\n')
    above = app.parent / "uv.toml"
    above.write_text('exclude-newer = "P1D"\n')
    result, _ = _check(tmp_path)
    assert _violations(result) == [(Rule.UNPROTECTED, str(above), ())]


def test_the_search_reads_the_home_folder_and_stops_there(tmp_path: Path) -> None:
    home = _home(tmp_path)
    _project(tmp_path)
    (tmp_path / "uv.toml").write_text('exclude-newer = "P1D"\n')  # above the home folder: not read
    result, err = _check(tmp_path)
    assert result.exit_code == 0, err
    in_home = Path(os.path.realpath(home)) / "uv.toml"
    in_home.write_text('exclude-newer = "P1D"\n')
    result, _ = _check(tmp_path)
    assert _violations(result) == [(Rule.UNPROTECTED, str(in_home), ())]


@pytest.mark.parametrize(
    ("name", "text", "key"),
    [
        ("uv.toml", 'index-url = "https://pkgs.example.net/simple"\n', "index-url"),
        ("uv.toml", 'extra-index-url = ["https://pypi.org/simple", "https://pkgs.example.net/simple"]\n', "extra"),
        ("uv.toml", 'find-links = ["/Users/me/wheels"]\n', "find-links"),
        ("uv.toml", '[[index]]\nname = "corp"\nurl = "https://pkgs.example.net/simple"\n', "index"),
        ("uv.toml", '[[index]]\nname = "corp"\n', "index"),  # no url: never taken as PyPI
        ("uv.toml", '[pip]\nextra-index-url = ["https://pkgs.example.net/simple"]\n', "[pip] extra-index-url"),
        ("pyproject.toml", '[[tool.uv.index]]\nurl = "https://pypi.org/simple//"\n', "index"),
    ],
)
def test_a_project_index_setting_is_unprotected(tmp_path: Path, name: str, text: str, key: str) -> None:
    _home(tmp_path)
    app = _project(tmp_path)
    (app / name).write_text(text)
    result, err = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(app / name), ())]
    assert f"{app / name} sets {key}" in err and "an index other than PyPI's" in err


@pytest.mark.parametrize(
    ("environ", "user", "said"),
    [
        ({}, 'extra-index-url = ["https://pkgs.example.net/simple"]\n', "uv.toml sets extra-index-url"),
        ({}, '[pip]\nindex-url = "http://pypi.org/simple"\n', "uv.toml sets [pip] index-url"),
        ({"UV_INDEX": "corp=https://pkgs.example.net/simple"}, "", "UV_INDEX is set"),
        ({"UV_INDEX": "https://pypi.org/simple https://pkgs.example.net/simple"}, "", "UV_INDEX is set"),
        ({"UV_DEFAULT_INDEX": "https://mirror.example.net/simple"}, "", "UV_DEFAULT_INDEX is set"),
        ({"UV_INDEX_URL": "https://pkgs.example.net/simple"}, "", "UV_INDEX_URL is set"),
        ({"UV_EXTRA_INDEX_URL": "https://pkgs.example.net/simple"}, "", "UV_EXTRA_INDEX_URL is set"),
        ({"UV_FIND_LINKS": "https://pypi.org/simple,/Users/me/wheels"}, "", "UV_FIND_LINKS is set"),
    ],
)
def test_uv_index_settings_are_reported(tmp_path: Path, environ: dict[str, str], user: str, said: str) -> None:
    # #130 for uv: the user file and the exported variables. Option A's stand-in for the option-B
    # test the issue names (test_plan_states_the_index_limit), which pins a §7 sentence instead.
    home = _home(tmp_path)
    config = home / ".config" / "uv" / "uv.toml"
    config.write_text(f'exclude-newer = "P21D"\n{user}')
    _project(tmp_path)
    result, err = _check(tmp_path, **environ)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(config), ())]  # protect would not fix it
    assert f"uv is given an index other than PyPI's: {str(config) + ' ' if user else ''}" in err
    assert said in err


def test_a_system_uv_index_setting_is_reported(tmp_path: Path) -> None:
    home = _home(tmp_path)
    _project(tmp_path)
    system = tmp_path / "root" / "etc" / "uv" / "uv.toml"
    system.parent.mkdir(parents=True)
    system.write_text('find-links = ["https://pkgs.example.net/wheels/"]\n')
    result, err = _check(tmp_path)
    assert _violations(result) == [(Rule.UNPROTECTED, str(home / ".config" / "uv" / "uv.toml"), ())]
    assert f"{system} sets find-links" in err


@pytest.mark.parametrize(
    "environ",
    [
        {"UV_INDEX": "https://pypi.org/simple"},
        {"UV_DEFAULT_INDEX": "https://pypi.org/simple/", "UV_FIND_LINKS": ""},
        {"UV_INDEX": "pypi=https://pypi.org/simple/"},
    ],
)
def test_pypi_in_a_uv_index_variable_is_not_reported(tmp_path: Path, environ: dict[str, str]) -> None:
    _home(tmp_path)
    _project(tmp_path)
    result, err = _check(tmp_path, **environ)
    assert result.exit_code == 0, err


def test_protect_still_writes_only_the_user_file(tmp_path: Path) -> None:
    # protect's behaviour does not change: it neither reads nor rewrites a project file.
    home = _home(tmp_path, window="P1D")
    app = _project(tmp_path)
    (app / "uv.toml").write_text('exclude-newer = "P1D"\nindex-url = "https://pkgs.example.net/simple"\n')
    where = fake_mac(tmp_path)
    err = io.StringIO()
    result = Protect(where.home, where.environ, where.root, TODAY, io.StringIO(), err)(
        Request(Verb.PROTECT, paths=_named(tmp_path), installer=None, yes=True)
    )
    assert result.exit_code == 0, err.getvalue()
    assert (home / ".config" / "uv" / "uv.toml").read_text() == 'exclude-newer = "P21D"\n'
    assert (app / "uv.toml").read_text() == 'exclude-newer = "P1D"\nindex-url = "https://pkgs.example.net/simple"\n'


def test_a_failing_project_search_never_ends_the_run(tmp_path: Path) -> None:
    # Review finding: tomllib recurses on a deeply nested array, and the RecursionError escaped
    # check, losing every other finding. It is now an unfinished check naming the folder.
    _home(tmp_path)
    deep = _project(tmp_path, "deep")
    (deep / "uv.toml").write_text("a = " + "[" * 5000 + "]" * 5000 + "\n")  # a uv.toml stops the search
    weak = _project(tmp_path, "weak")
    (weak / "uv.toml").write_text('exclude-newer = "P1D"\n')
    with refuses("check_envs.project-search-failed"):
        result, err = _check(tmp_path)
    assert _violations(result) == [(Rule.UNPROTECTED, str(weak / "uv.toml"), ())]  # the run went on
    (skip,) = [s for s in result.skipped if s.reason is SkipReason.CHECK_ERROR]
    assert (skip.place, skip.reason.in_scope) == (str(deep), True)
    assert f"{deep}: the search for uv's project file failed (RecursionError)" in err


def test_the_uv_cooldown_finding_survives_an_unreadable_system_file(tmp_path: Path) -> None:
    # Review finding: assess stops at UV_EXCLUDE_NEWER before it reads the system file, and the
    # index reading then failed on it, losing the cooldown finding. It is kept, as for pip.
    home = _home(tmp_path)
    _project(tmp_path)
    system = tmp_path / "root" / "etc" / "uv" / "uv.toml"
    system.parent.mkdir(parents=True)
    system.write_text("index-url = \n")
    with refuses("uv.not-valid-toml"):
        result, err = _check(tmp_path, UV_EXCLUDE_NEWER="P1D")
    user = str(home / ".config" / "uv" / "uv.toml")
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, user, ())]  # an override: protect is not its fix
    (skip,) = [s for s in result.skipped if s.reason is SkipReason.CHECK_ERROR]
    assert (skip.ecosystem, skip.place) == (Ecosystem.PYPI, user)
    assert "UV_EXCLUDE_NEWER overrides" in err and f"{system}: is not valid TOML" in err


def test_a_uv_index_variable_is_named_even_when_the_user_file_cannot_be_read(tmp_path: Path) -> None:
    # Review finding: the variables were read only after every file, so a broken file hid them.
    home = _home(tmp_path)
    _project(tmp_path)
    config = home / ".config" / "uv" / "uv.toml"
    config.write_text("exclude-newer = \n")
    with refuses("uv.not-valid-toml"):
        result, err = _check(tmp_path, UV_INDEX_URL="https://pkgs.example.net/simple")
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(config), ())]
    assert "UV_INDEX_URL is set" in err and f"{config}: is not valid TOML" in err
    assert [s.place for s in result.skipped if s.reason is SkipReason.CHECK_ERROR] == [str(config)]


def test_a_weak_window_beside_another_index_offers_no_protect_fix(tmp_path: Path) -> None:
    # protect would fix the window but not the index, so it is not offered.
    home = _home(tmp_path, window="P1D")
    config = home / ".config" / "uv" / "uv.toml"
    config.write_text('exclude-newer = "P1D"\nindex-url = "https://pkgs.example.net/simple"\n')
    _project(tmp_path)
    result, err = _check(tmp_path)
    assert _violations(result) == [(Rule.UNPROTECTED, str(config), ())]
    assert "holds 1 days" in err and f"{config} sets index-url" in err


def test_an_index_found_before_a_file_fails_is_still_named(tmp_path: Path) -> None:
    # Review finding: the index reading's partial result was dropped when a later file failed.
    home = _home(tmp_path)
    config = home / ".config" / "uv" / "uv.toml"
    config.write_text('exclude-newer = "P21D"\nindex-url = "https://pkgs.example.net/simple"\n')
    system = tmp_path / "root" / "etc" / "uv" / "uv.toml"
    system.parent.mkdir(parents=True)
    system.write_text("index-url = \n")
    _project(tmp_path)
    with refuses("uv.not-valid-toml"):  # assess stops at the variable; the index reading reaches the file
        result, err = _check(tmp_path, UV_EXCLUDE_NEWER="P30D")
    assert _violations(result) == [(Rule.UNPROTECTED, str(config), ())]
    assert f"uv is given an index other than PyPI's: {config} sets index-url" in err
    assert [s.place for s in result.skipped if s.reason is SkipReason.CHECK_ERROR] == [str(config)]


def test_a_broken_user_file_never_hides_a_system_index(tmp_path: Path) -> None:
    # Review finding: the reading stopped at the first file that failed.
    home = _home(tmp_path)
    config = home / ".config" / "uv" / "uv.toml"
    config.write_text("exclude-newer = \n")
    system = tmp_path / "root" / "etc" / "uv" / "uv.toml"
    system.parent.mkdir(parents=True)
    system.write_text('index-url = "https://pkgs.example.net/simple"\n')
    _project(tmp_path)
    with refuses("uv.not-valid-toml"):
        result, err = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(config), ())]
    assert f"{system} sets index-url" in err and f"{config}: is not valid TOML" in err


def test_a_broken_pyproject_never_hides_a_project_file_further_up(tmp_path: Path) -> None:
    # Review finding: uv warns about a pyproject.toml it cannot parse and searches on, so the
    # file further up is in use; Guardian reports both, the broken one as unfinished.
    _home(tmp_path)
    app = _project(tmp_path)
    (app / "pyproject.toml").write_text("[tool.uv\n")
    above = app.parent / "uv.toml"
    above.write_text('index-url = "https://pkgs.example.net/simple"\n')
    with refuses("uv.not-valid-toml"):
        result, err = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(above), ())]
    assert [s.place for s in result.skipped if s.reason is SkipReason.CHECK_ERROR] == [str(app / "pyproject.toml")]
    assert f"{above} sets index-url" in err


def test_a_broken_uv_toml_stops_the_search_as_it_stops_uv(tmp_path: Path) -> None:
    _home(tmp_path)
    app = _project(tmp_path)
    (app / "uv.toml").write_text("exclude-newer = \n")
    (app.parent / "uv.toml").write_text('exclude-newer = "P1D"\n')  # never reached: uv stops below
    with refuses("uv.not-valid-toml"):
        result, _ = _check(tmp_path)
    assert result.exit_code == 2 and result.findings == ()


@pytest.mark.parametrize("name", ["UV_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_FIND_LINKS"])
def test_only_named_index_variables_take_the_name_form(tmp_path: Path, name: str) -> None:
    # Review nit: "x=https://pypi.org/simple" is a NAME=URL index only in UV_INDEX and
    # UV_DEFAULT_INDEX; elsewhere it is not PyPI's URL.
    _home(tmp_path)
    _project(tmp_path)
    result, err = _check(tmp_path, **{name: "x=https://pypi.org/simple"})
    assert result.exit_code == 1 and f"{name} is set" in err


def test_a_project_file_above_a_tool_uv_table_is_judged_too(tmp_path: Path) -> None:
    # Review finding (checked with uv 0.11 by the reviewer): uv passes over a [tool.uv] its own
    # rules reject, here an unknown key, and uses the file further up. Guardian cannot tell, so
    # it judges every candidate up to the first uv.toml.
    _home(tmp_path)
    app = _project(tmp_path)
    pyproject = app / "pyproject.toml"
    pyproject.write_text('[tool.uv]\nexclude-newer = "P30D"\nbogus-key = 1\n')
    above = app.parent / "uv.toml"
    above.write_text('exclude-newer = "2100-01-01"\nindex-url = "https://pkgs.example.net/simple"\n')
    (tmp_path / "home" / "uv.toml").write_text('exclude-newer = "P1D"\n')  # beyond the first uv.toml: not read
    result, err = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(above), ())]
    assert (Ecosystem.PYPI, str(pyproject)) in [(c.ecosystem, c.place) for c in result.checked]
    assert f"{above} accepts uploads after 2026-10-13" in err and f"{above} sets index-url" in err


DEEP = "a = " + "[" * 5000 + "]" * 5000 + "\n"  # tomllib recurses past Python's limit


def test_a_too_deeply_nested_pyproject_is_passed_over_like_a_broken_one(tmp_path: Path) -> None:
    _home(tmp_path)
    app = _project(tmp_path)
    (app / "pyproject.toml").write_text(DEEP)
    above = app.parent / "uv.toml"
    above.write_text('exclude-newer = "P1D"\n')
    with refuses("uv.project-nested-too-deeply"):
        result, err = _check(tmp_path)
    assert _violations(result) == [(Rule.UNPROTECTED, str(above), ())]
    assert [s.place for s in result.skipped if s.reason is SkipReason.CHECK_ERROR] == [str(app / "pyproject.toml")]
    assert f"{app / 'pyproject.toml'}: is nested too deeply to read" in err


@pytest.mark.parametrize(
    ("text", "site"),
    [("exclude-newer = \n", refuses("uv.not-valid-toml")), (DEEP, refuses("check_envs.project-search-failed"))],
)
def test_a_project_found_before_the_search_fails_is_still_judged(tmp_path: Path, text: str, site: Refuses) -> None:
    # Review finding: a broken or too deeply nested uv.toml further up threw away the weak
    # pyproject.toml already found, which uv itself uses without ever reaching the broken file.
    _home(tmp_path)
    app = _project(tmp_path)
    pyproject = app / "pyproject.toml"
    pyproject.write_text('[tool.uv]\nexclude-newer = "P1D"\n')
    (app.parent / "uv.toml").write_text(text)
    with site:
        result, _ = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(pyproject), ())]
    assert [s.reason for s in result.skipped] == [SkipReason.CHECK_ERROR]


def test_a_too_deeply_nested_user_file_never_hides_a_system_index(tmp_path: Path) -> None:
    # Review finding: RecursionError on the user file stopped the index reading before the
    # system file was read.
    home = _home(tmp_path)
    (home / ".config" / "uv" / "uv.toml").write_text(DEEP)
    system = tmp_path / "root" / "etc" / "uv" / "uv.toml"
    system.parent.mkdir(parents=True)
    system.write_text('index-url = "https://pkgs.example.net/simple"\n')
    _project(tmp_path)
    result, err = _check(tmp_path)
    assert result.exit_code == 1
    assert _violations(result) == [(Rule.UNPROTECTED, str(home / ".config" / "uv" / "uv.toml"), ())]
    assert f"{system} sets index-url" in err
    assert [s.reason for s in result.skipped] == [SkipReason.CHECK_ERROR]


def test_a_uv_config_that_leads_outside_the_named_paths_is_never_read(tmp_path: Path) -> None:
    # #255 review: a dotfiles link in ~/.config/uv leads out of the named folder, so check never
    # reads it there (unfinished at its place); named as the file itself, it is read.
    home = _home(tmp_path, window="P1D")  # weaker than the cooldown: unprotected if read
    _project(tmp_path)
    user = home / ".config" / "uv" / "uv.toml"
    dotfile = tmp_path / "dotfiles" / "uv.toml"
    dotfile.parent.mkdir()
    user.rename(dotfile)
    user.symlink_to(dotfile)
    with refuses("check_envs.uv-config-outside"):
        result, err = _check(tmp_path)
    assert result.exit_code == 2 and not result.findings
    assert [(s.place, s.reason) for s in result.skipped] == [(str(user), SkipReason.CHECK_ERROR)]
    assert "outside the named paths" in err
    where = fake_mac(tmp_path)
    handler = CheckEnvs(where.home, where.environ, where.root, TODAY, None, io.StringIO())
    named = Scope(frozenset({Ecosystem.PYPI}), (*_named(tmp_path)[:1], os.path.realpath(user)))
    read = handler(Request(Verb.CHECK, scope=named))
    assert [f.rule for f in read.findings] == [Rule.UNPROTECTED]  # the dotfile's weak window, at last
