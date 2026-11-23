# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Discovery and the effective pip (issue #5; plan §1, §3.1, §2.3).

Every test builds a fake Mac under ``tmp_path``: ``root`` stands for ``/`` and ``home`` for
the home folder, so nothing here reads the real home folder or the system's Pythons.
"""

from __future__ import annotations

import gc
import json
import os
import re
import subprocess
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import direct_url, discovery
from ssc_guardian.direct_url import LocalInstall
from ssc_guardian.discovery import LocalInstallRefusedError, Roots, Source
from ssc_guardian.findings import (
    Ecosystem,
    ExitCode,
    IncompleteCheckError,
    Scope,
    SkipReason,
    aggregate_exit_code,
)
from ssc_guardian.plugins import pip
from tests.refusal_sites import refuses

TODAY = date(2026, 11, 3)


def make_base(prefix: Path, python: str = "3.12") -> Path:
    """A base installation: ``lib/pythonX.Y/os.py`` and an empty ``site-packages``."""
    lib = prefix / "lib" / f"python{python}"
    (lib / "site-packages").mkdir(parents=True)
    (lib / "os.py").write_text("")
    (prefix / "bin").mkdir(exist_ok=True)
    return lib / "site-packages"


def make_venv(prefix: Path, python: str = "3.12", *, home: Path | None = None, system_site: bool = False) -> Path:
    site = prefix / "lib" / f"python{python}" / "site-packages"
    site.mkdir(parents=True)
    lines = [f"home = {home or '/nowhere/bin'}", f"include-system-site-packages = {str(system_site).lower()}"]
    (prefix / "pyvenv.cfg").write_text("\n".join(lines) + "\n")
    return site


def add_dist(folder: Path, name: str, version: str) -> None:
    record = folder / f"{name}-{version}.dist-info"
    record.mkdir(parents=True)
    (record / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nName: decoy\n")


def add_claim(
    site: Path, name: str, version: str, claim: str | Path | dict[str, object], *, editable: bool = True
) -> None:
    """``direct_url.json`` in a record ``add_dist`` made: a folder or URL as ``dir_info``, or
    the file's whole data as a dict."""
    url = claim if isinstance(claim, str) else f"file://{claim}"
    data = claim if isinstance(claim, dict) else {"url": url, "dir_info": {"editable": editable}}
    (site / f"{name}-{version}.dist-info" / "direct_url.json").write_text(json.dumps(data))


def fake_mac(tmp_path: Path, **environ: str) -> Roots:
    (tmp_path / "home").mkdir(exist_ok=True)
    (tmp_path / "root").mkdir(exist_ok=True)
    return Roots(str(tmp_path / "home"), {"PATH": "", **environ}, str(tmp_path / "root"))


def _assess(env: discovery.Environment, where: Roots) -> pip.Assessment:
    return pip.assess(env, cooldown_days=21, tolerance=7, today=TODAY, sources=pip.Sources.of(where))


def _forbid_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("discovery must never run a program")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    for name in ("system", "popen", "execv", "execve", "execvp", "spawnv", "posix_spawn", "posix_spawnp", "fork"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse)


def test_discovery_never_executes_found_programs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "ran"
    trap = f"#!/bin/sh\ntouch {marker}\n"
    home = tmp_path / "home"
    prefix = home / ".pyenv" / "versions" / "3.12.4"
    site = make_base(prefix)
    add_dist(site, "pip", "26.2.1")
    add_dist(site, "requests", "2.32.3")
    venv = home / "projects" / "app" / ".venv"
    add_dist(make_venv(venv), "pip", "26.2.1")
    (venv / "bin").mkdir()
    for program in (prefix / "bin" / "python3", prefix / "bin" / "pip", venv / "bin" / "python"):
        program.write_text(trap)  # a booby-trapped interpreter: running it leaves the marker
        program.chmod(0o755)
    where = fake_mac(tmp_path, PATH=str(prefix / "bin"))
    _forbid_programs(monkeypatch)

    found = discovery.survey(where, [str(home)])
    items = pip.PipPlugin(where).discover(Scope(frozenset({Ecosystem.PYPI}), (str(home),))).items
    states = [_assess(env, where) for env in found.environments]

    assert not marker.exists()  # read, never run
    assert {(e.source, e.prefix) for e in found.environments} == {
        (Source.PYENV, os.path.realpath(prefix)),
        (Source.VENV, os.path.realpath(venv)),
    }
    assert {(i.name, i.version) for i in items} == {("pip", "26.2.1"), ("requests", "2.32.3")}
    assert all(s.pip == pip.Pip("26.2.1", s.env.main_site) for s in states)


def test_effective_pip_prefers_per_user_folder(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    main = make_base(Path(where.root) / "Library/Frameworks/Python.framework/Versions/3.12")
    user = Path(where.home) / "Library" / "Python" / "3.12" / "lib" / "python" / "site-packages"
    add_dist(main, "pip", "24.0")
    add_dist(user, "pip", "26.2.1")

    (env,) = discovery.survey(where, [where.home, where.root]).environments
    assert env.source is Source.PYTHON_ORG
    assert env.search_order == (os.path.realpath(user), os.path.realpath(main))  # per-user first
    state = _assess(env, where)
    assert state.pip == pip.Pip("26.2.1", os.path.realpath(user))
    assert state.hidden == (pip.Pip("24.0", os.path.realpath(main)),)  # reported, never loaded


def test_an_older_per_user_pip_is_the_one_judged(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    main = make_base(Path(where.home) / ".local" / "share" / "uv" / "python" / "cpython-3.12.4-macos-aarch64-none")
    user = Path(where.home) / ".local" / "lib" / "python3.12" / "site-packages"  # not a framework build
    add_dist(main, "pip", "26.2.1")
    add_dist(user, "pip", "25.3")

    (env,) = discovery.survey(where, [where.home, where.root]).environments
    state = _assess(env, where)
    assert (env.source, state.pip, state.hidden) == (Source.UV, pip.Pip("25.3", os.path.realpath(user)), ())
    assert state.verdict is pip.Verdict.OLD_PIP
    assert "upgrade pip or leave this installation out of the paths you name" in state.why


# #302: pip 26.0.x is the newest pip for Python 3.9, so "upgrade pip" leads nowhere there.
_BELOW_310 = "ignores the cooldown setting, and Python {} cannot run a pip that both honours it and is current: "
_LEAVE_OUT = "leave this installation out of the paths you name"  # #284: Guardian has no exclude setting
_RECREATE = "recreate this venv with Python 3.10 or later, or " + _LEAVE_OUT


def _venv_with_pip(where: Roots, name: str, python: str, pip_version: str) -> discovery.Environment:
    prefix = Path(where.home) / "projects" / name
    add_dist(make_venv(prefix, python), "pip", pip_version)
    (env,) = discovery.survey(where, [str(prefix)]).environments
    return env


def test_old_pip_on_python_39_advises_recreating_the_venv(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    env = _venv_with_pip(where, "app", "3.9", "21.2.4")
    assert (env.is_venv, env.python) == (True, (3, 9))
    state = _assess(env, where)
    assert state.verdict is pip.Verdict.OLD_PIP and state.wanted is None
    assert state.why == "pip 21.2.4 " + _BELOW_310.format("3.9") + _RECREATE
    # The version comes from the environment: an older Python reads right.
    older = _assess(_venv_with_pip(where, "older", "3.8", "21.2.4"), where)
    assert older.why == "pip 21.2.4 " + _BELOW_310.format("3.8") + _RECREATE
    # A pip whose version cannot be read on such a Python gets the same text.
    unread = _assess(_venv_with_pip(where, "unread", "3.9", "not-a-version"), where)
    assert unread.verdict is pip.Verdict.OLD_PIP
    assert unread.why == "pip not-a-version " + _BELOW_310.format("3.9") + _RECREATE


def test_old_pip_on_apple_python_39_base_advises_a_newer_python(tmp_path: Path) -> None:
    root = tmp_path / "root"
    framework = (
        root / "Applications/Xcode-16.4.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9"
    )
    add_dist(make_base(framework, "3.9"), "pip", "21.2.4")
    (framework / "bin" / "python3").write_text("")
    bin_dir = root / "Applications/Xcode-16.4.app/Contents/Developer/usr/bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python3").symlink_to(framework / "bin" / "python3")
    where = fake_mac(tmp_path, PATH=str(bin_dir))

    (env,) = discovery.survey(where, [where.home, where.root]).environments
    assert (env.source, env.is_venv, env.python) == (Source.APPLE, False, (3, 9))
    state = _assess(env, where)
    assert state.verdict is pip.Verdict.OLD_PIP
    remedy = "use a Python 3.10 or later for this work, or " + _LEAVE_OUT
    assert state.why == "pip 21.2.4 " + _BELOW_310.format("3.9") + remedy
    assert "recreate this venv" not in state.why and "upgrade pip" not in state.why


def test_old_pip_on_python_311_keeps_upgrade_pip_advice(tmp_path: Path) -> None:
    # Negative control: a Python that runs a current pip keeps "upgrade pip".
    where = fake_mac(tmp_path)
    state = _assess(_venv_with_pip(where, "app", "3.11", "21.2.4"), where)
    assert state.verdict is pip.Verdict.OLD_PIP
    assert state.why == "pip 21.2.4 ignores the cooldown setting: upgrade pip or " + _LEAVE_OUT


def test_unreadable_pip_version_keeps_existing_reason(tmp_path: Path) -> None:
    # Error path: on Python 3.10 or later a pip whose version cannot be read keeps today's handling.
    where = fake_mac(tmp_path)
    state = _assess(_venv_with_pip(where, "app", "3.10", "not-a-version"), where)
    assert (state.verdict, state.wanted) == (pip.Verdict.OLD_PIP, None)
    assert state.why == "pip not-a-version ignores the cooldown setting: upgrade pip or " + _LEAVE_OUT


def test_old_pip_reason_says_leave_out_of_the_paths(tmp_path: Path) -> None:
    # #284: scope comes only from --path, so the remedy names the paths, never an exclude setting.
    where = fake_mac(tmp_path)
    state = _assess(_venv_with_pip(where, "app", "3.11", "25.3"), where)
    assert state.verdict is pip.Verdict.OLD_PIP  # the verdict does not change
    said = "pip 25.3 ignores the cooldown setting: upgrade pip or leave this installation out of the paths you name"
    assert state.why == said
    assert "exclude" not in state.why


def test_handles_empty_and_missing_package_folders(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    make_base(Path(where.root) / "opt/homebrew/opt/python@3.13/Frameworks/Python.framework/Versions/3.13", "3.13")
    projects = Path(where.home) / "projects"
    venv = projects / "empty"
    make_venv(venv)
    (projects / "not-a-venv" / "lib").mkdir(parents=True)  # a folder with no pyvenv.cfg is ignored

    found = discovery.survey(where, [str(projects), str(Path(where.root) / "opt/homebrew")])
    assert found.skipped == [] and found.malformed == []
    assert sorted(e.source for e in found.environments) == [Source.HOMEBREW, Source.VENV]
    for env in found.environments:
        for folder in env.search_order:  # the per-user folder does not exist; the main one is empty
            assert discovery.packages(folder) == ([], [])
        assert _assess(env, where).verdict is pip.Verdict.NO_PIP  # nothing reads the setting

    # A record that names no version is an unfinished check, never dropped silently.
    bad = Path(found.environments[1].main_site) / "broken-1.0.dist-info"
    bad.mkdir()
    (bad / "METADATA").write_text("Name: broken\n")
    records, problems = discovery.packages(str(bad.parent))
    assert records == [] and [p.reason.value for p in problems] == ["check-error"]


def test_venv_search_order_follows_site_py(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    base = Path(where.home) / ".pyenv" / "versions" / "3.11.9"
    base_site = make_base(base, "3.11")
    projects = Path(where.home) / "code"
    isolated = make_venv(projects / "a" / ".venv", "3.11", home=base / "bin")
    shared = make_venv(projects / "b" / ".venv", "3.11", home=base / "bin", system_site=True)

    envs = {e.prefix: e for e in discovery.survey(where, [str(projects)]).environments}
    user = os.path.realpath(Path(where.home) / ".local" / "lib" / "python3.11" / "site-packages")
    assert envs[os.path.realpath(isolated.parents[2])].search_order == (os.path.realpath(isolated),)
    # A venv that sees system packages: its own folder, then the per-user one, then its base's.
    assert envs[os.path.realpath(shared.parents[2])].search_order == (
        os.path.realpath(shared),
        user,
        os.path.realpath(base_site),
    )


def test_an_interpreter_on_path_is_named_by_its_installation(tmp_path: Path) -> None:
    root = tmp_path / "root"
    cellar = root / "opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13"
    make_base(cellar, "3.13")
    (cellar / "bin" / "python3.13").write_text("")
    (root / "opt/homebrew/opt/python@3.13").mkdir(parents=True)
    (root / "opt/homebrew/opt/python@3.13/Frameworks").symlink_to(cellar.parents[2])
    (root / "opt/homebrew/bin").mkdir(parents=True)
    (root / "opt/homebrew/bin/python3").symlink_to(cellar / "bin" / "python3.13")
    where = fake_mac(tmp_path, PATH=str(root / "opt/homebrew/bin"))

    (env,) = discovery.survey(where, [where.home, where.root]).environments
    assert (env.source, env.prefix) == (Source.HOMEBREW, os.path.realpath(cellar))


def test_path_filter_and_malformed_places(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    make_venv(projects / "keep" / ".venv")
    make_venv(projects / "other" / ".venv")
    make_venv(projects / "café" / ".venv")  # D3: a refused character makes the place malformed

    assert any("café" in raw for raw in discovery.survey(where, [str(projects)]).malformed)
    found = discovery.survey(where, [os.path.realpath(projects / "keep")])
    assert [e.prefix for e in found.environments] == [os.path.realpath(projects / "keep" / ".venv")]
    assert found.malformed == []  # --path bounds malformed places too


def test_a_symlinked_venv_and_xdg_data_home_are_found(tmp_path: Path) -> None:
    data = tmp_path / "data"
    where = fake_mac(tmp_path, XDG_DATA_HOME=str(data))
    make_base(data / "uv" / "python" / "cpython-3.12.4-macos-aarch64-none")
    real = tmp_path / "elsewhere" / "venv"
    make_venv(real)
    app = Path(where.home) / "projects" / "app"
    app.mkdir(parents=True)
    (app / ".venv").symlink_to(real)

    # The link resolves outside home/projects, so its target is named too (#255).
    named = [str(Path(where.home) / "projects"), str(tmp_path / "elsewhere"), str(data)]
    found = discovery.survey(where, named)
    assert sorted((e.source, e.prefix) for e in found.environments) == [
        (Source.UV, os.path.realpath(data / "uv" / "python" / "cpython-3.12.4-macos-aarch64-none")),
        (Source.VENV, os.path.realpath(real)),
    ]


def test_two_pip_records_in_one_folder_cannot_be_judged(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    site = make_venv(Path(where.home) / "projects" / "app")
    add_dist(site, "pip", "26.2.1")
    add_dist(site, "pip", "9.0.1")  # a leftover: which code is on disk cannot be told
    (env,) = discovery.survey(where, [str(Path(where.home) / "projects")]).environments
    with refuses("pip.all-pips-check-error"), pytest.raises(IncompleteCheckError, match="check-error"):
        _assess(env, where)


def test_a_homebrew_venv_finds_its_base_through_the_interpreter(tmp_path: Path) -> None:
    # Review finding: home = .../opt/python@3.11/bin, whose parent holds no standard library;
    # the base is where the interpreter there resolves to (read, never run).
    root = tmp_path / "root"
    framework = root / "opt/homebrew/Cellar/python@3.11/3.11.15/Frameworks/Python.framework/Versions/3.11"
    base_site = make_base(framework, "3.11")
    add_dist(base_site, "pip", "26.0.1")
    (framework / "bin" / "python3.11").write_text("")
    opt_bin = root / "opt/homebrew/opt/python@3.11/bin"
    opt_bin.mkdir(parents=True)
    (opt_bin / "python3.11").symlink_to(framework / "bin" / "python3.11")
    venv = tmp_path / "home" / "projects" / "app"
    make_venv(venv, "3.11", home=opt_bin, system_site=True)
    where = fake_mac(tmp_path)

    found = discovery.survey(where, [str(tmp_path / "home" / "projects")])
    (env,) = [e for e in found.environments if e.is_venv]
    assert env.base_site == os.path.realpath(base_site)
    state = _assess(env, where)
    assert state.pip == pip.Pip("26.0.1", os.path.realpath(base_site))  # the base's pip runs here
    assert state.verdict is pip.Verdict.MISSING and state.wanted is not None
    assert state.wanted.fixed_date is not None  # pip 26.0 gets the fixed form


@pytest.mark.parametrize(
    ("layout", "found"),
    [
        ("two-libs-settled", True),  # two lib folders; pyvenv.cfg's version picks one
        ("two-libs", False),
        ("no-lib", False),
        ("no-base", False),  # sees its base's packages, but the base cannot be found
        ("not-utf8", True),
        ("fifo", False),
    ],
)
def test_a_venv_that_cannot_be_read_exactly_is_never_dropped(tmp_path: Path, layout: str, found: bool) -> None:
    where = fake_mac(tmp_path)
    venv = Path(where.home) / "projects" / "odd"
    make_venv(venv)
    config = venv / "pyvenv.cfg"
    if layout.startswith("two-libs"):
        (venv / "lib" / "python3.11" / "site-packages").mkdir(parents=True)
        if layout == "two-libs-settled":
            config.write_text(config.read_text() + "version_info = 3.12.4.final.0\n")
    elif layout == "no-lib":
        (venv / "lib" / "python3.12" / "site-packages").rmdir()
        (venv / "lib" / "python3.12").rmdir()
    elif layout == "no-base":
        config.write_text("home = /nowhere/bin\ninclude-system-site-packages = true\n")
    elif layout == "not-utf8":
        config.write_bytes(b"home = /nowhere/bin\ninclude-system-site-packages = false\nprompt = \xff\n")
    elif layout == "fifo":
        config.unlink()
        os.mkfifo(config)  # must not hang the run

    survey = discovery.survey(where, [str(Path(where.home) / "projects")])
    assert bool(survey.environments) is found
    if not found:
        assert [(s.place, s.reason.value) for s in survey.skipped] == [(os.path.realpath(venv), "check-error")]


def test_a_pyenv_virtualenv_is_a_venv(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    base = Path(where.home) / ".pyenv" / "versions" / "3.12.4"
    make_base(base)
    make_venv(Path(where.home) / ".pyenv" / "versions" / "tools", home=base / "bin")
    sources = sorted(e.source for e in discovery.survey(where, [where.home, where.root]).environments)
    assert sources == [Source.PYENV, Source.VENV]


def test_an_unreachable_venv_folder_is_unknown_not_empty(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    folder = Path(where.home) / "projects"
    folder.symlink_to(tmp_path / "Volumes" / "NotMounted" / "projects")  # a volume not mounted
    found = discovery.survey(where, [str(folder)])
    assert [(s.place, s.reason.value) for s in found.skipped] == [(str(folder), "check-error")]
    # A named path that does not exist is unfinished there too, never "holds none" (#255).
    missing = str(Path(where.home) / "missing")
    assert _detailed(discovery.survey(where, [missing])) == [(missing, "check-error", discovery.NO_SUCH_PATH)]


def test_a_venv_inside_a_symlinked_project_is_found_once(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    work = tmp_path / "work" / "app"
    make_venv(work / ".venv")
    projects = Path(where.home) / "projects"
    projects.mkdir()
    (projects / "app").symlink_to(work)
    (projects / "loop").symlink_to(projects)  # a link loop ends
    found = discovery.survey(where, [str(projects), str(tmp_path / "work")])  # the link's target is named
    assert [e.prefix for e in found.environments] == [os.path.realpath(work / ".venv")]


def test_apple_python_is_named_apple_and_sees_library_python(tmp_path: Path) -> None:
    root = tmp_path / "root"
    framework = (
        root / "Applications/Xcode-16.4.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9"
    )
    make_base(framework, "3.9")
    (framework / "bin" / "python3").write_text("")
    bin_dir = root / "Applications/Xcode-16.4.app/Contents/Developer/usr/bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python3").symlink_to(framework / "bin" / "python3")
    system = root / "Library" / "Python" / "3.9" / "site-packages"
    add_dist(system, "requests", "2.31.0")  # where `sudo pip3 install` puts packages
    where = fake_mac(tmp_path, PATH=str(bin_dir))

    (env,) = discovery.survey(where, [where.home, where.root]).environments
    assert env.source is Source.APPLE
    assert env.search_order[-1] == os.path.realpath(system)


@pytest.mark.parametrize("case", ["locked", "under-a-dangling-link"])
def test_a_named_folder_that_cannot_be_looked_at_is_unknown(tmp_path: Path, case: str) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    if case == "locked":
        (home / "locked" / "projects").mkdir(parents=True)
        (home / "locked").chmod(0o600)
        folder = home / "locked" / "projects"
    else:
        (home / "vol").symlink_to(tmp_path / "Volumes" / "NotMounted")
        folder = home / "vol" / "projects"
    try:
        found = discovery.survey(where, [str(folder)])
    finally:
        (home / "locked").chmod(0o700) if case == "locked" else None
    assert [(s.place, s.reason.value) for s in found.skipped] == [(str(folder), "check-error")]


def test_a_linked_venv_outside_the_path_filter_is_listed_where_it_was_found(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    real = Path(where.home) / "venvs" / "app"
    make_venv(real)
    app = Path(where.home) / "projects" / "app"
    app.mkdir(parents=True)
    (app / ".venv").symlink_to(real)
    found = discovery.survey(where, [os.path.realpath(app)])
    assert found.environments == []
    ((place, reason),) = [(s.place, s.reason.value) for s in found.skipped]
    assert (place, reason) == (str(app / ".venv"), "check-error")


def test_one_unreadable_folder_reached_twice_is_one_skip(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    projects = Path(where.home) / "projects"
    projects.mkdir()
    (projects / "l1").symlink_to(other)
    (projects / "l2").symlink_to(other)
    other.chmod(0o000)
    try:
        found = discovery.survey(where, [str(projects), str(other)])  # the links' target is named
    finally:
        other.chmod(0o700)
    assert len(found.skipped) == 1


def _skips(found: discovery.Survey) -> list[tuple[str | None, str]]:
    return [(s.place, s.reason.value) for s in found.skipped]


def test_path_reports_a_venv_linked_from_two_projects(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    make_venv(home / "venvs" / "x")
    for project in ("a", "b"):
        (home / "projects" / project).mkdir(parents=True)
        (home / "projects" / project / ".venv").symlink_to(home / "venvs" / "x")
    b = os.path.realpath(home / "projects" / "b")
    found = discovery.survey(where, [b])
    assert found.environments == [] and _skips(found) == [(f"{b}/.venv", "check-error")]


def test_path_through_a_symlinked_subfolder_is_judged_resolved(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    make_venv(home / "venvs" / "y")
    (tmp_path / "work" / "app").mkdir(parents=True)
    (tmp_path / "work" / "app" / ".venv").symlink_to(home / "venvs" / "y")
    (home / "projects").mkdir()
    (home / "projects" / "link").symlink_to(tmp_path / "work")
    app = os.path.realpath(home / "projects" / "link" / "app")  # as the CLI resolves --path
    found = discovery.survey(where, [app])
    assert _skips(found) == [(f"{app}/.venv", "check-error")]


@pytest.mark.parametrize("case", ["broken-venv", "unreadable-folder"])
def test_path_reports_a_linked_place_that_cannot_be_read(tmp_path: Path, case: str) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    app = home / "projects" / "app"
    app.mkdir(parents=True)
    target = tmp_path / "elsewhere" / "envs"
    target.mkdir(parents=True)
    if case == "broken-venv":
        (target / "pyvenv.cfg").write_text("home = /nowhere/bin\n")  # no lib/pythonX.Y
        (app / ".venv").symlink_to(target)
        name = ".venv"
    else:
        (app / "envs").symlink_to(target)
        target.chmod(0o000)
        name = "envs"
    try:
        found = discovery.survey(where, [os.path.realpath(app)])
    finally:
        target.chmod(0o700)
    assert (f"{os.path.realpath(app)}/{name}", "check-error") in _skips(found)


def test_tox_and_nox_envs_are_venvs(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    app = Path(where.home) / "projects" / "app"
    make_venv(app / ".tox" / "py312")
    make_venv(app / ".nox" / "tests")
    assert len(discovery.survey(where, [str(Path(where.home) / "projects")]).environments) == 2


def test_path_reports_a_venv_inside_a_linked_folder(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    make_venv(tmp_path / "elsewhere" / "envs" / "v")
    b = home / "projects" / "b"
    b.mkdir(parents=True)
    (b / "envs").symlink_to(tmp_path / "elsewhere" / "envs")
    make_venv(b / "tools")
    found = discovery.survey(where, [os.path.realpath(b)])
    assert [e.prefix for e in found.environments] == [os.path.realpath(b / "tools")]
    assert _skips(found) == [(f"{os.path.realpath(b)}/envs/v", "check-error")]


def test_path_reports_an_unreadable_folder_inside_a_linked_folder(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    locked = tmp_path / "elsewhere" / "locked"
    locked.mkdir(parents=True)
    b = home / "projects" / "b"
    b.mkdir(parents=True)
    (b / "work").symlink_to(tmp_path / "elsewhere")
    locked.chmod(0o000)
    try:
        found = discovery.survey(where, [os.path.realpath(b)])
    finally:
        locked.chmod(0o700)
    assert (f"{os.path.realpath(b)}/work/locked", "check-error") in _skips(found)


def test_path_on_the_second_link_to_one_folder_still_sees_inside(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    make_venv(tmp_path / "elsewhere" / "envs" / "v")
    for project in ("a", "b"):
        (home / "projects" / project).mkdir(parents=True)
        (home / "projects" / project / "envs").symlink_to(tmp_path / "elsewhere" / "envs")
    b = os.path.realpath(home / "projects" / "b")
    found = discovery.survey(where, [b])
    assert _skips(found) == [(f"{b}/envs/v", "check-error")]
    # With the links' target named too, the one venv is found once and nothing is skipped.
    plain = discovery.survey(where, [str(home / "projects"), str(tmp_path / "elsewhere")])
    assert len(plain.environments) == 1 and plain.skipped == []


def test_a_folder_cut_off_by_depth_is_still_walked_by_a_shorter_route(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    deep = projects / "a" / "1" / "2" / "3" / "4" / "5" / "6"
    deep.mkdir(parents=True)
    shared = tmp_path / "shared"
    make_venv(shared / "v")
    (deep / "lnk").symlink_to(shared)  # reached first, at the depth limit
    (projects / "b").symlink_to(shared)  # the same folder, one level down
    found = discovery.survey(where, [str(projects), str(shared)])  # projects is walked first
    assert [e.prefix for e in found.environments] == [os.path.realpath(shared / "v")]
    assert found.skipped == []  # checked by the shorter route, so not listed past the limit (#67)


def test_a_link_loop_through_an_outside_folder_ends_with_a_path_filter(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    b = projects / "b"
    make_venv(b / "tools")
    outside = tmp_path / "outside"
    outside.mkdir()
    (b / "out").symlink_to(outside)
    (outside / "back").symlink_to(projects)  # leads back in: the walk must still end
    found = discovery.survey(where, [os.path.realpath(b)])
    assert [e.prefix for e in found.environments] == [os.path.realpath(b / "tools")]


def test_a_longer_first_route_inside_the_limit_hides_nothing(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    (projects / "a" / "1").mkdir(parents=True)
    shared = tmp_path / "shared"
    deep = shared / "x" / "y" / "z" / "w" / "u" / "v"
    make_venv(deep)  # within the limit through b, past it through a/1/lnk
    (projects / "a" / "1" / "lnk").symlink_to(shared)  # sorts first, reached first
    (projects / "b").symlink_to(shared)
    found = discovery.survey(where, [str(projects), str(shared)])  # projects is walked first
    assert [e.prefix for e in found.environments] == [os.path.realpath(deep)]


def test_a_malformed_place_reached_twice_is_one_finding(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    (projects / "a" / "1" / "2").mkdir(parents=True)
    shared = tmp_path / "shared"
    bad = shared / "bad#x"  # '#' is refused by the path grammar
    bad.mkdir(parents=True)
    (projects / "a" / "1" / "2" / "lnk").symlink_to(shared)  # the deep route, reached first
    (projects / "b").symlink_to(shared)
    bad.chmod(0o000)
    try:
        found = discovery.survey(where, [str(projects), str(shared)])  # projects is walked first
    finally:
        bad.chmod(0o700)
    assert found.malformed == [os.path.realpath(bad)]


# --- #67: every failed read is an unfinished place, never "nothing here" (plan §2.1) --------


def _detailed(found: discovery.Survey) -> list[tuple[str | None, str, str | None]]:
    return [(s.place, s.reason.value, s.detail) for s in found.skipped]


@pytest.mark.parametrize("case", ["lib", "lib/python3.12", "dangling-lib"])
def test_unreadable_base_lib_is_not_checked(tmp_path: Path, case: str) -> None:
    where = fake_mac(tmp_path)
    prefix = Path(where.home) / ".pyenv" / "versions" / "3.12.4"
    add_dist(make_base(prefix), "pip", "26.2.1")
    if case == "dangling-lib":
        (prefix / "lib").rename(tmp_path / "moved")
        (prefix / "lib").symlink_to(tmp_path / "Volumes" / "NotMounted" / "lib")
        locked, error = None, "FileNotFoundError"
    else:
        locked, error = prefix / case, "PermissionError"
        locked.chmod(0o000)
    try:
        found = discovery.survey(where, [str(prefix)])  # the base named: its own tree is not walked
    finally:
        if locked is not None:
            locked.chmod(0o700)
    assert found.environments == []  # never dropped: an unprotected base would read as clean
    assert _detailed(found) == [(os.path.realpath(prefix), "check-error", f"unreadable ({error})")]


@pytest.mark.parametrize(
    "case", ["prefix", "versions", "dangling-version", "dangling-pyenv", "path-folder", "system-folder"]
)
def test_unreadable_prefix_and_pyenv_versions_are_not_checked(tmp_path: Path, case: str) -> None:
    where = fake_mac(tmp_path)
    versions = Path(where.home) / ".pyenv" / "versions"
    make_base(versions / "3.12.4")
    locked: Path | None = versions
    mode, place = 0o000, os.path.realpath(versions)
    if case == "prefix":  # the folder lists, but its entries cannot be looked at
        mode, place = 0o444, os.path.join(place, "3.12.4")
    elif case == "dangling-version":
        (versions / "3.12.4").rename(tmp_path / "moved")
        (versions / "3.12.4").symlink_to(tmp_path / "Volumes" / "NotMounted" / "3.12.4")
        locked, place = None, os.path.join(place, "3.12.4")
    elif case == "dangling-pyenv":  # a folder on the way, behind a volume that is not mounted
        (Path(where.home) / ".pyenv").rename(tmp_path / "moved")
        (Path(where.home) / ".pyenv").symlink_to(tmp_path / "Volumes" / "NotMounted" / ".pyenv")
        locked, place = None, str(versions)
    elif case == "path-folder":
        locked = tmp_path / "bin"
        locked.mkdir()
        where = fake_mac(tmp_path, PATH=str(locked))
        place = os.path.realpath(locked)
    elif case == "system-folder":  # a folder on the way to a wildcard
        locked = Path(where.root) / "opt" / "homebrew" / "opt"
        locked.mkdir(parents=True)
        place = os.path.realpath(locked)
    if locked is not None:
        locked.chmod(mode)
    named = [where.home, where.root] + ([str(tmp_path / "bin")] if case == "path-folder" else [])
    try:
        found = discovery.survey(where, named)
    finally:
        if locked is not None:
            locked.chmod(0o700)
    assert (place, "check-error") in _skips(found)
    if case not in ("path-folder", "system-folder"):
        assert found.environments == [] and len(found.skipped) == 1
    else:
        assert [e.source for e in found.environments] == [Source.PYENV]  # the rest is still checked


def test_dangling_site_packages_is_not_checked(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    site = make_venv(projects / "app")
    site.rmdir()
    site.symlink_to(tmp_path / "Volumes" / "NotMounted" / "site-packages")
    (env,) = discovery.survey(where, [str(projects)]).environments
    records, problems = discovery.packages(env.main_site)
    assert records == []
    assert [(p.place, p.reason.value) for p in problems] == [(env.main_site, "check-error")]
    with (
        refuses("pip.all-pips-check-error"),
        pytest.raises(IncompleteCheckError, match="check-error"),
    ):  # never NO_PIP, which counts as protected
        _assess(env, where)
    site.unlink()  # a folder that is plainly missing still holds none
    assert discovery.packages(env.main_site) == ([], [])


def _plant_record(site: Path, planted: str) -> None:
    """A record in ``site`` that cannot be read, or that names no version."""
    record = site / "evil-1.0.dist-info"
    record.mkdir(parents=True)
    if planted == "metadata-folder":
        (record / "METADATA").mkdir()
    elif planted == "metadata-fifo":
        os.mkfifo(record / "METADATA")  # a hung read would hang the run
    else:
        (record / "METADATA").write_text("Metadata-Version: 2.1\nName: evil\n")


@pytest.mark.parametrize(
    ("planted", "case", "detail"),
    [
        ("metadata-folder", refuses("discovery.unreadable-record"), "evil-1.0.dist-info: IsADirectoryError"),
        ("metadata-fifo", refuses("discovery.unreadable-record"), "evil-1.0.dist-info: OSError"),
        ("no-version", refuses("discovery.record-no-name-or-version"), "evil-1.0.dist-info: no name or version"),
        ("dangling-folder", refuses("discovery.dangling-link"), "reached through a symlink to a missing folder"),
        ("file-as-folder", refuses("discovery.unreadable-folder"), "unreadable (NotADirectoryError)"),
    ],
    ids=["metadata-folder", "metadata-fifo", "no-version", "dangling-folder", "file-as-folder"],
)
def test_unreadable_package_record_is_incomplete(tmp_path: Path, planted: str, case: Any, detail: str) -> None:
    site = tmp_path / "site-packages"
    if planted == "dangling-folder":
        site.symlink_to(tmp_path / "Volumes" / "NotMounted" / "site-packages")
    elif planted == "file-as-folder":
        site.write_text("")
    else:
        add_dist(site, "requests", "2.32.3")  # a good record beside it is still read
        _plant_record(site, planted)
    with case:
        records, problems = discovery.packages(str(site))
    assert [(p.place, p.reason, p.in_scope, p.detail) for p in problems] == [
        (str(site), SkipReason.CHECK_ERROR, True, detail)
    ]
    assert aggregate_exit_code([], problems) is ExitCode.INCOMPLETE  # never a pass
    good = [("requests", "2.32.3")] if planted in ("metadata-folder", "metadata-fifo", "no-version") else []
    assert [(r.name, r.version) for r in records] == good


def test_a_venv_with_no_lib_folder_is_not_checked(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    prefix = Path(where.home) / "projects" / "app"
    prefix.mkdir(parents=True)
    (prefix / "pyvenv.cfg").write_text("home = /nowhere/bin\ninclude-system-site-packages = false\n")
    with refuses("discovery.not-checked"):
        found = discovery.survey(where, [str(prefix.parent)])
    assert found.environments == []
    assert [(s.place, s.reason, s.in_scope, s.detail) for s in found.skipped] == [
        (os.path.realpath(prefix), SkipReason.CHECK_ERROR, True, "venv with no single lib/pythonX.Y folder")
    ]
    assert aggregate_exit_code([], found.skipped) is ExitCode.INCOMPLETE


def _base_not_found(tmp_path: Path, home: Path) -> tuple[list[str], tuple[str, ...], str, str]:
    prefix = home / "projects" / "app"
    make_venv(prefix, system_site=True)  # sees its base's packages; home is /nowhere/bin
    return (
        [str(home / "projects")],
        (),
        os.path.realpath(prefix),
        "venv sees its base's packages, but its base was not found",
    )


def _dangling_version(tmp_path: Path, home: Path) -> tuple[list[str], tuple[str, ...], str, str]:
    versions = home / ".pyenv" / "versions"
    versions.mkdir(parents=True)
    (versions / "3.12.4").symlink_to(tmp_path / "Volumes" / "NotMounted" / "3.12.4")
    place = os.path.join(os.path.realpath(versions), "3.12.4")
    return [str(home)], (), place, "reached through a symlink to a missing folder"


def _outside_the_path(tmp_path: Path, home: Path) -> tuple[list[str], tuple[str, ...], str, str]:
    make_venv(home / "venvs" / "x")
    web = home / "projects" / "web"
    web.mkdir(parents=True)
    (web / ".venv").symlink_to(home / "venvs" / "x")
    shown = f"{os.path.realpath(web)}/.venv"
    return (
        [str(home / "projects")],
        (os.path.realpath(web),),
        shown,
        f"resolves outside the named paths, to {os.path.realpath(home / 'venvs' / 'x')}",
    )


def _folder_cannot_be_reached(tmp_path: Path, home: Path) -> tuple[list[str], tuple[str, ...], str, str]:
    (home / "projects").symlink_to(tmp_path / "Volumes" / "NotMounted" / "projects")
    return [str(home / "projects")], (), str(home / "projects"), "reached through a symlink to a missing folder"


@pytest.mark.parametrize(
    "plant",
    [_base_not_found, _dangling_version, _outside_the_path, _folder_cannot_be_reached],
    ids=lambda f: f.__name__,
)
def test_each_not_checked_cause_names_its_place_reason_and_detail(
    tmp_path: Path, plant: Callable[[Path, Path], tuple[list[str], tuple[str, ...], str, str]]
) -> None:
    # discovery.not-checked stands for several causes (#148): each of these four, asserted until
    # now by place and reason only, is asserted by its own detail too, and is never a pass.
    where = fake_mac(tmp_path)
    folders, wanted, place, detail = plant(tmp_path, Path(where.home))
    with refuses("discovery.not-checked"):
        found = discovery.survey(where, list(wanted) or folders)
    assert (place, "check-error", detail) in _detailed(found)
    assert all(s.in_scope for s in found.skipped)
    assert aggregate_exit_code([], found.skipped) is ExitCode.INCOMPLETE


def _beyond_the_walk(projects: Path) -> tuple[Path, dict[str, str]]:
    """Venvs at the walk's edges; returns the one at the limit and the listed ones -> why."""
    chain = projects.joinpath(*"1234567")  # depth 7
    make_venv(chain / "at-limit")  # depth 8: found
    make_venv(chain / "d8" / "past")  # depth 9: listed
    make_venv(chain / "d8" / "d9" / "unseen")  # depth 10: not seen
    make_venv(projects / "web" / "node_modules" / "env")  # directly inside a pruned name: listed
    make_venv(projects / "web" / "node_modules" / "pkg" / "deeper")  # not seen
    make_venv(projects / "repo" / ".git" / "v")
    listed = {
        os.path.realpath(chain / "d8" / "past"): "past the walk limit",
        os.path.realpath(projects / "web" / "node_modules" / "env"): "under a pruned folder name (node_modules)",
        os.path.realpath(projects / "repo" / ".git" / "v"): "under a pruned folder name (.git)",
    }
    return chain / "at-limit", listed


def test_venv_past_the_depth_limit_is_listed_not_checked(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    projects = Path(where.home) / "projects"
    at_limit, listed = _beyond_the_walk(projects)

    found = discovery.survey(where, [str(projects)])
    assert [e.prefix for e in found.environments] == [os.path.realpath(at_limit)]
    assert sorted(_detailed(found)) == sorted((p, "check-error", why) for p, why in listed.items())

    # Naming the folder with --path checks it: nothing is listed then.
    named = [str(projects), str(at_limit.parent / "d8")]
    named += [str(projects / "web" / "node_modules"), str(projects / "repo" / ".git")]
    found = discovery.survey(where, named)
    assert found.skipped == []
    assert set(listed) < {e.prefix for e in found.environments}

    # With --path, a listed venv is reported inside the path it was found under.
    web = os.path.realpath(projects / "web")
    found = discovery.survey(where, [web])
    assert _skips(found) == [(f"{web}/node_modules/env", "check-error")]


def test_a_named_file_holds_no_environment_and_is_never_a_pass(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    entry = Path(where.home) / "projects"
    entry.write_text("")  # a file: nothing is found there, and the command lists it (Survey.empty)
    found = discovery.survey(where, [str(entry)])
    assert (found.environments, found.skipped, found.empty) == ([], [], [str(entry)])
    missing = str(Path(where.home) / "missing")
    assert _detailed(discovery.survey(where, [missing])) == [(missing, "check-error", discovery.NO_SUCH_PATH)]


def test_discovery_is_idempotent_on_re_run(tmp_path: Path) -> None:
    where = fake_mac(tmp_path)
    home = Path(where.home)
    locked = home / ".pyenv" / "versions" / "3.12.4" / "lib"
    make_base(locked.parent)
    _beyond_the_walk(home / "projects")
    site = make_venv(home / "projects" / "app")
    site.rmdir()
    site.symlink_to(tmp_path / "Volumes" / "NotMounted" / "site-packages")
    (home / "file").write_text("")
    folders = [str(home / "projects"), str(home / "file"), str(locked.parent)]
    locked.chmod(0o000)
    try:
        runs = [discovery.survey(where, folders) for _ in range(2)]
        listed = [[discovery.packages(f) for e in run.environments for f in e.search_order] for run in runs]
    finally:
        locked.chmod(0o700)
    first, second = runs
    assert first.environments == second.environments and first.malformed == second.malformed
    assert first.skipped == second.skipped
    assert listed[0] == listed[1]
    assert first.empty == second.empty == [str(home / "file")]  # the file holds no environment
    assert len(first.skipped) == 4  # the base, three venvs past the walk


def test_an_unreadable_pruned_folder_is_not_checked(tmp_path: Path) -> None:
    # The one look inside a pruned folder is a read too: one that fails is listed, never empty.
    where = fake_mac(tmp_path)
    folder = Path(where.home) / "projects" / "web" / "node_modules"
    make_venv(folder / "env")
    folder.chmod(0o000)
    try:
        found = discovery.survey(where, [str(Path(where.home) / "projects")])
    finally:
        folder.chmod(0o700)
    assert _detailed(found) == [(os.path.realpath(folder), "check-error", "unreadable (PermissionError)")]


# --- #255: discovery reads only the named paths (owner's rulings of 2026-11-13) ----------------


def _spy_listings(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every folder listed while the spy runs: ``os.listdir``, ``os.scandir`` (which ``os.walk``
    lists with) and each ``os.walk`` top."""
    listed: list[str] = []
    real_listdir, real_scandir, real_walk = os.listdir, os.scandir, os.walk

    def listdir(path: Any = ".") -> list[str]:
        if not isinstance(path, int):  # a descriptor: pytest's own cleanup
            listed.append(os.fspath(path))
        return real_listdir(path)

    def scandir(path: Any = ".") -> Any:
        if not isinstance(path, int):  # a descriptor: pytest's own cleanup
            listed.append(os.fspath(path))
        return real_scandir(path)

    def walk(top: Any, *args: Any, **kwargs: Any) -> Any:
        listed.append(os.fspath(top))
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr(os, "listdir", listdir)
    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os, "walk", walk)
    return listed


def _at_or_under(place: str, top: str) -> bool:
    return place == top or place.startswith(top.rstrip("/") + "/")


def test_survey_walks_only_the_named_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Venvs in two sibling folders, bases in the usual places and a PATH folder elsewhere: with
    # --path naming one folder, nothing outside it is ever listed (#255).
    usr_bin = tmp_path / "root" / "usr" / "bin"
    where = fake_mac(tmp_path, PATH=str(usr_bin))
    usr_bin.mkdir(parents=True)
    projects = Path(where.home) / "projects"
    make_venv(projects / "named" / ".venv")
    make_venv(projects / "other" / ".venv")
    make_base(Path(where.home) / ".pyenv" / "versions" / "3.12.4")
    make_base(Path(where.root) / "Library/Frameworks/Python.framework/Versions/3.12")
    named = os.path.realpath(projects / "named")
    listed = _spy_listings(monkeypatch)

    found = discovery.survey(where, [named])

    assert [e.prefix for e in found.environments] == [os.path.realpath(projects / "named" / ".venv")]
    assert found.skipped == [] and found.empty == []
    assert listed, "the spy saw no listing at all"
    assert [p for p in listed if not _at_or_under(p, named)] == []  # never the sibling, a base or PATH


def test_named_venv_outside_any_folder_is_found(tmp_path: Path) -> None:
    # A venv no setting ever named, outside home and every former venv folder, is checked when
    # --path names it.
    where = fake_mac(tmp_path)
    venv = tmp_path / "scratch" / "deep" / "env"
    add_dist(make_venv(venv), "pip", "26.2.1")

    found = discovery.survey(where, [os.path.realpath(venv)])

    assert [(e.source, e.prefix) for e in found.environments] == [(Source.VENV, os.path.realpath(venv))]
    assert (found.skipped, found.empty) == ([], [])


def test_base_installation_found_only_under_a_named_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    homebrew = root / "opt/homebrew"
    framework = homebrew / "opt/python@3.13/Frameworks/Python.framework/Versions/3.13"
    make_base(framework, "3.13")
    (homebrew / "bin").mkdir(parents=True)
    (homebrew / "bin" / "python3").symlink_to(framework / "bin" / "python3.13")
    (framework / "bin" / "python3.13").write_text("")
    where = fake_mac(tmp_path, PATH=str(homebrew / "bin"))
    projects = Path(where.home) / "projects"
    make_venv(projects / "app")

    with_it = discovery.survey(where, [os.path.realpath(homebrew)])
    assert [(e.source, e.prefix) for e in with_it.environments] == [(Source.HOMEBREW, os.path.realpath(framework))]
    # Named directly (as the CLI resolves --path), the prefix is that installation.
    direct = discovery.survey(where, [os.path.realpath(framework)])
    assert [e.prefix for e in direct.environments] == [os.path.realpath(framework)]

    listed = _spy_listings(monkeypatch)
    without = discovery.survey(where, [os.path.realpath(projects)])
    assert [e.prefix for e in without.environments] == [os.path.realpath(projects / "app")]
    assert all(_at_or_under(p, os.path.realpath(projects)) for p in listed)  # the PATH folder is never listed
    assert str(homebrew / "bin") not in listed


def test_missing_or_empty_named_path_is_unfinished(tmp_path: Path) -> None:
    # A path that does not exist, a folder that cannot be read and a folder holding no
    # environment are each an unfinished check at that place (exit 2), never a pass.
    where = fake_mac(tmp_path)
    home = Path(where.home)
    missing = str(home / "missing")
    locked = home / "locked"
    locked.mkdir()
    empty = home / "empty"
    (empty / "src").mkdir(parents=True)
    named = [missing, str(locked), str(empty)]
    locked.chmod(0o000)
    try:
        with refuses("discovery.not-checked"):
            found = discovery.survey(where, named)
        with refuses("pip.empty-path"):
            discovered = pip.PipPlugin(where).discover(Scope(frozenset({Ecosystem.PYPI}), tuple(named)))
    finally:
        locked.chmod(0o700)
    assert found.environments == []
    assert _detailed(found) == [
        (missing, "check-error", discovery.NO_SUCH_PATH),
        (str(locked), "check-error", "unreadable (PermissionError)"),
    ]
    assert found.empty == [str(empty)]  # the command lists it as unfinished: below, the plug-in
    assert [(s.place, s.reason, s.detail) for s in discovered.skipped] == [
        (missing, SkipReason.CHECK_ERROR, discovery.NO_SUCH_PATH),
        (str(locked), SkipReason.CHECK_ERROR, "unreadable (PermissionError)"),
        (str(empty), SkipReason.CHECK_ERROR, discovery.NO_ENVIRONMENT),
    ]
    assert aggregate_exit_code([], list(discovered.skipped)) is ExitCode.INCOMPLETE  # never a pass
    with pytest.raises(ValueError, match="none was named"):  # no named path: refused, no default scope
        discovery.survey(where, [])


def test_walk_limits_still_apply_under_a_named_path(tmp_path: Path) -> None:
    # Depth 8, the pruned names and a symlink loop behave under a named path as they always did.
    where = fake_mac(tmp_path)
    named = Path(where.home) / "work"
    at_limit, listed = _beyond_the_walk(named)
    (named / "loop").symlink_to(named)  # a link loop under the named path ends

    found = discovery.survey(where, [str(named)])

    assert [e.prefix for e in found.environments] == [os.path.realpath(at_limit)]
    assert sorted(_detailed(found)) == sorted((p, "check-error", why) for p, why in listed.items())
    assert found.empty == []


def test_a_venv_whose_base_folder_is_malformed_is_never_dropped(tmp_path: Path) -> None:
    # #255 review, finding 1: venv b sees its base's packages, and the base's folder fails the
    # path grammar. b is reported as a malformed place wherever that folder is, never dropped
    # while venv a beside it makes the named path look checked.
    where = fake_mac(tmp_path)
    base = tmp_path / "odd#base"
    make_base(base)
    (base / "bin" / "python3.12").write_text("")
    named = Path(where.home) / "named"
    make_venv(named / "a")
    make_venv(named / "b", home=base / "bin", system_site=True)
    found = discovery.survey(where, [os.path.realpath(named)])
    assert [e.prefix for e in found.environments] == [os.path.realpath(named / "a")]
    assert found.malformed and all("odd#base" in m for m in found.malformed)  # malformed-name: exit 1


def test_a_venv_inside_a_named_base_is_found(tmp_path: Path) -> None:
    # #255 review, finding 2: a named base installation is that installation and is walked too,
    # so a pyenv-virtualenv in its envs folder, and a venv kept in a custom prefix, are found.
    where = fake_mac(tmp_path)
    for prefix, inner in (
        (Path(where.home) / ".pyenv" / "versions" / "3.12.0", "envs/myenv"),
        (tmp_path / "opt-py", "venvs/x"),
    ):
        make_base(prefix)
        make_venv(prefix / inner, home=prefix / "bin")
        found = discovery.survey(where, [os.path.realpath(prefix)])
        assert {e.prefix for e in found.environments} == {
            os.path.realpath(prefix),
            os.path.realpath(prefix / inner),
        }, prefix
        assert found.empty == [] and found.skipped == []


def test_a_base_installation_reached_by_the_walk_is_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # #255 review, finding 3: Homebrew's Python under a named Cellar folder sits beside the usual
    # place (opt/homebrew/opt), so the walk recognises it by its standard library; a keg and its
    # framework folder are one installation, named by the framework's resolved prefix.
    where = fake_mac(tmp_path)
    cellar = Path(where.root) / "opt/homebrew/Cellar"
    keg = cellar / "python@3.12" / "3.12.7"
    framework = keg / "Frameworks/Python.framework/Versions/3.12"
    make_base(framework)
    (keg / "lib").mkdir()
    (keg / "lib" / "python3.12").symlink_to(framework / "lib" / "python3.12")  # as Homebrew links it
    make_venv(cellar / "awscli" / "2.0" / "libexec")
    found = discovery.survey(where, [os.path.realpath(cellar)])
    assert sorted((e.source, e.prefix) for e in found.environments) == sorted(
        [(Source.HOMEBREW, os.path.realpath(framework)), (Source.VENV, os.path.realpath(cellar / "awscli/2.0/libexec"))]
    )
    assert found.skipped == [] and found.empty == []
    # A standard-library link realpath cannot follow is unknown, never "not a base" (#255 review).
    real = discovery.real_place

    def blind(path: str) -> str | None:
        return None if path.endswith("/lib/python3.12") else real(path)

    monkeypatch.setattr(discovery, "real_place", blind)
    unresolved = discovery.survey(where, [os.path.realpath(cellar)])
    monkeypatch.undo()
    assert (os.path.realpath(keg), "check-error") in _skips(unresolved)


# --- an activated venv: its own bin on PATH (issue #301) -----------------------------------


def _activated(tmp_path: Path, venv: Path, base: Path) -> Roots:
    """``venv`` made as ``python -m venv`` makes one: ``bin/python3`` and ``bin/python3.12``
    link to ``base``'s interpreter; its ``bin`` is first on ``PATH``, as activating it puts it."""
    make_base(base)
    (base / "bin" / "python3.12").write_text("")
    add_dist(make_venv(venv, home=base / "bin"), "pip", "26.2.1")
    (venv / "bin").mkdir()
    for name in ("python3", "python3.12"):
        (venv / "bin" / name).symlink_to(base / "bin" / "python3.12")
    return fake_mac(tmp_path, PATH=f"{os.path.realpath(venv / 'bin')}:/usr/bin")


def test_activated_venv_bin_on_path_is_not_a_base_installation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The scenario: the venv's interpreters lead to a base outside the named path. The venv is
    # checked, and nothing names bin/python3 as an unfinished check (it used to: exit 2).
    venv = tmp_path / "home" / "projects" / "app" / ".venv"
    where = _activated(tmp_path, venv, tmp_path / "Cellar" / "python@3.12")
    for named in (venv, venv.parent):  # --path .venv, and --path on its project
        found = discovery.survey(where, [os.path.realpath(named)])
        assert [(e.source, e.prefix) for e in found.environments] == [(Source.VENV, os.path.realpath(venv))]
        assert (found.skipped, found.empty) == ([], [])
        scope = Scope(frozenset({Ecosystem.PYPI}), (os.path.realpath(named),))
        discovered = pip.PipPlugin(where).discover(scope)
        assert aggregate_exit_code([], list(discovered.skipped)) is ExitCode.RULES_MET
    # Naming the bin folder alone names no environment: the venv above it is outside, so the
    # folder is handled as before, never a pass, and its pyvenv.cfg is never read (#255).
    bin_dir = os.path.realpath(venv / "bin")
    read: list[str] = []
    record = discovery._read_record

    def spy(path: str) -> str:
        read.append(path)
        return record(path)

    monkeypatch.setattr(discovery, "_read_record", spy)
    found = discovery.survey(where, [bin_dir])
    monkeypatch.undo()
    assert found.environments == []
    base = f"resolves outside the named paths, to {os.path.realpath(tmp_path / 'Cellar' / 'python@3.12')}"
    assert set(_detailed(found)) == {
        (os.path.join(bin_dir, name), "check-error", base) for name in ("python3", "python3.12")
    }
    assert read == []  # nothing outside the named path is read


def test_path_folder_under_p_that_is_not_a_venv_bin_still_reports_outside(tmp_path: Path) -> None:
    # Negative control: a plain bin folder (no pyvenv.cfg above it) whose python3 resolves
    # outside the named path is still an in-scope unfinished check.
    base = tmp_path / "Cellar" / "python@3.12"
    make_base(base)
    (base / "bin" / "python3.12").write_text("")
    tools = tmp_path / "home" / "tools" / "bin"
    tools.mkdir(parents=True)
    (tools / "python3").symlink_to(base / "bin" / "python3.12")
    where = fake_mac(tmp_path, PATH=os.path.realpath(tools))
    with refuses("discovery.not-checked"):
        found = discovery.survey(where, [os.path.realpath(tools.parent)])
    shown = os.path.join(os.path.realpath(tools), "python3")
    assert found.environments == []
    assert _detailed(found) == [
        (shown, "check-error", f"resolves outside the named paths, to {os.path.realpath(base)}")
    ]
    assert all(s.in_scope for s in found.skipped)
    assert aggregate_exit_code([], found.skipped) is ExitCode.INCOMPLETE


@pytest.mark.parametrize("case", ["other-installation", "not-bin", "unreadable-cfg", "nul-home"])
def test_only_the_venvs_own_base_is_dropped(tmp_path: Path, case: str) -> None:
    # #301 review: in a venv's bin, only the interpreter its pyvenv.cfg's home names is the
    # venv's base. Another installation's interpreter there, a folder in the venv not named bin,
    # and a bin whose pyvenv.cfg cannot be read are handled as before: in-scope unfinished checks.
    venv = tmp_path / "home" / "projects" / "app" / ".venv"
    base = tmp_path / "Cellar" / "python@3.12"
    where = _activated(tmp_path, venv, base)
    folder = os.path.realpath(venv / "bin")
    outside = f"resolves outside the named paths, to {os.path.realpath(base)}"
    if case == "other-installation":
        other = tmp_path / "opt" / "other"
        make_base(other, "3.11")
        (other / "bin" / "python3.11").write_text("")
        (venv / "bin" / "python3.11").symlink_to(other / "bin" / "python3.11")
        outside = f"resolves outside the named paths, to {os.path.realpath(other)}"
        expected = {(os.path.join(folder, "python3.11"), "check-error", outside)}
    elif case == "not-bin":
        (venv / "bin").rename(venv / "tools")
        folder = os.path.realpath(venv / "tools")
        where = fake_mac(tmp_path, PATH=folder)
        expected = {(os.path.join(folder, name), "check-error", outside) for name in ("python3", "python3.12")}
    elif case == "nul-home":  # realpath refuses a NUL byte with ValueError: never a crash
        (venv / "pyvenv.cfg").write_text("home = /x\x00y/bin\ninclude-system-site-packages = false\n")
        expected = {(os.path.join(folder, name), "check-error", outside) for name in ("python3", "python3.12")}
    else:
        expected = {(os.path.join(folder, name), "check-error", outside) for name in ("python3", "python3.12")}
        expected.add((os.path.realpath(venv), "check-error", "unreadable (PermissionError)"))
        (venv / "pyvenv.cfg").chmod(0o000)
    try:
        found = discovery.survey(where, [os.path.realpath(venv.parent)])
    finally:
        (venv / "pyvenv.cfg").chmod(0o600)
    assert set(_detailed(found)) == expected
    assert all(s.in_scope for s in found.skipped)
    venvs = [] if case == "unreadable-cfg" else [os.path.realpath(venv)]
    assert [e.prefix for e in found.environments] == venvs


def test_venv_bin_whose_pyvenv_cfg_links_outside_is_handled_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #301 review: a venv only PATH reaches (two levels into a pruned folder) whose pyvenv.cfg is
    # a link out of the named path. That file is never read, and the bin is handled as before:
    # in-scope unfinished checks, never a pass.
    work = tmp_path / "home" / "work"
    venv = work / "node_modules" / "tool" / ".venv"
    base = tmp_path / "Cellar" / "python@3.12"
    where = _activated(tmp_path, venv, base)
    elsewhere = tmp_path / "elsewhere.cfg"
    (venv / "pyvenv.cfg").rename(elsewhere)
    (venv / "pyvenv.cfg").symlink_to(elsewhere)
    read: list[str] = []
    record = discovery._read_record

    def spy(path: str) -> str:
        read.append(path)
        return record(path)

    monkeypatch.setattr(discovery, "_read_record", spy)
    found = discovery.survey(where, [os.path.realpath(work)])
    monkeypatch.undo()
    folder = os.path.realpath(venv / "bin")
    outside = f"resolves outside the named paths, to {os.path.realpath(base)}"
    assert found.environments == []
    assert set(_detailed(found)) == {
        (os.path.join(folder, name), "check-error", outside) for name in ("python3", "python3.12")
    }
    assert all(s.in_scope for s in found.skipped)
    assert read == []


def test_unreadable_pyvenv_parent_is_not_treated_as_venv_bin(tmp_path: Path) -> None:
    # Error path: the venv folder cannot be looked at, so its pyvenv.cfg cannot be seen. Its bin
    # on PATH is handled as any other folder there (unreadable: an unfinished check), never dropped.
    venv = tmp_path / "home" / "projects" / "app" / ".venv"
    where = _activated(tmp_path, venv, tmp_path / "Cellar" / "python@3.12")
    venv.chmod(0o000)
    try:
        found = discovery.survey(where, [os.path.realpath(venv.parent)])
    finally:
        venv.chmod(0o700)
    assert found.environments == []
    assert sorted(_detailed(found)) == [
        (os.path.realpath(venv), "check-error", "unreadable (PermissionError)"),  # the walk
        (os.path.join(os.path.realpath(venv), "bin"), "check-error", "unreadable (PermissionError)"),  # PATH
    ]


def test_venv_bin_on_path_with_python_inside_p_is_checked_once(tmp_path: Path) -> None:
    # Edge case: the venv's base is under the named path too. Each is checked once.
    work = tmp_path / "home" / "work"
    venv, base = work / "app" / ".venv", work / "python"
    where = _activated(tmp_path, venv, base)
    found = discovery.survey(where, [os.path.realpath(work)])
    assert sorted((e.source, e.prefix) for e in found.environments) == sorted(
        [(Source.PATH, os.path.realpath(base)), (Source.VENV, os.path.realpath(venv))]
    )
    assert (found.skipped, found.empty) == ([], [])


def test_venv_bin_on_path_the_walk_cannot_reach_is_still_checked(tmp_path: Path) -> None:
    # Integrity: a venv and its base that only PATH reaches (two levels into a pruned folder,
    # where the walk never looks) are both checked; nothing PATH checked before goes unchecked.
    hidden = tmp_path / "home" / "work" / "node_modules" / "tool"
    venv, base = hidden / ".venv", hidden / "python"
    where = _activated(tmp_path, venv, base)
    found = discovery.survey(where, [os.path.realpath(tmp_path / "home" / "work")])
    assert sorted(e.prefix for e in found.environments) == sorted([os.path.realpath(base), os.path.realpath(venv)])
    assert (found.skipped, found.empty) == ([], [])


def test_activated_venv_discovery_is_idempotent_on_re_run(tmp_path: Path) -> None:
    venv = tmp_path / "home" / "projects" / "app" / ".venv"
    where = _activated(tmp_path, venv, tmp_path / "Cellar" / "python@3.12")
    named = [os.path.realpath(venv.parent)]
    first, second = (discovery.survey(where, named) for _ in range(2))
    assert first == second
    assert [e.prefix for e in first.environments] == [os.path.realpath(venv)]


# --- local installs (issue #97; contracts §10.6) ------------------------------------------


def _claimed(
    tmp_path: Path, claim: str | Path | dict[str, object], *, editable: bool = True
) -> tuple[discovery.Package, set[str]]:
    """``my-tool 1.0`` in a venv inside ``tmp_path/proj``, claiming ``claim``, and the run's
    ``outside`` set."""
    prefix = tmp_path / "proj" / ".venv"
    site = make_venv(prefix)
    add_dist(site, "my-tool", "1.0")
    add_claim(site, "my-tool", "1.0", claim, editable=editable)
    (package,), _ = discovery.packages(str(site))
    return package, {os.path.realpath(prefix), os.path.realpath(site)}


def _project(folder: Path, text: str = '[project]\nname = "my-tool"\n', file: str = "pyproject.toml") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / file).write_text(text)
    return folder


@pytest.mark.parametrize(
    ("file", "text"),
    [
        ("pyproject.toml", '[project]\nname = "My_Tool"\n'),
        ("pyproject.toml", '[tool.poetry]\nname = "my.tool"\n'),
        ("setup.cfg", "[metadata]\nname = my-tool\n"),
    ],
)
def test_local_install_is_verified_by_a_real_folder_whose_project_names_the_distribution(
    tmp_path: Path, file: str, text: str
) -> None:
    project = _project(tmp_path / "proj", text, file)
    package, outside = _claimed(tmp_path, project)  # the venv is inside the project: it passes
    assert discovery.local_install(package, outside) == LocalInstall(os.path.realpath(project), True)


def test_a_plain_local_install_is_not_editable_and_a_link_is_resolved(tmp_path: Path) -> None:
    project = _project(tmp_path / "proj")
    (tmp_path / "link").symlink_to(project)
    package, outside = _claimed(tmp_path, tmp_path / "link", editable=False)
    assert discovery.local_install(package, outside) == LocalInstall(os.path.realpath(project), False)


def test_any_of_a_folders_project_files_may_name_the_distribution(tmp_path: Path) -> None:
    project = _project(tmp_path / "proj", "not toml [")
    (project / "setup.cfg").write_text("[metadata]\nname = my-tool\n")
    package, outside = _claimed(tmp_path, project)
    assert discovery.local_install(package, outside) == LocalInstall(os.path.realpath(project), True)


@pytest.mark.parametrize(
    "claim",
    [
        None,
        {"url": "https://example.test/r", "vcs_info": {"vcs": "git", "commit_id": "a" * 40}},
        {"url": "https://example.test/r", "vcs_info": {"vcs": "git", "commit_id": "short"}},
        {"url": "file:///wheels/my_tool-1.0-py3-none-any.whl", "archive_info": {}},
    ],
)
def test_record_without_direct_url_or_with_a_vcs_install_makes_no_claim(
    tmp_path: Path, claim: dict[str, object] | None
) -> None:
    site = make_venv(tmp_path / ".venv")
    add_dist(site, "my-tool", "1.0")
    if claim is not None:
        add_claim(site, "my-tool", "1.0", claim)
    (package,), _ = discovery.packages(str(site))
    assert discovery.local_install(package, {str(tmp_path / ".venv")}) is None


def test_a_single_file_egg_info_record_makes_no_claim(tmp_path: Path) -> None:
    site = make_venv(tmp_path / ".venv")
    (site / "my_tool-1.0.egg-info").write_text("Name: my-tool\nVersion: 1.0\n")
    (package,), _ = discovery.packages(str(site))
    assert discovery.local_install(package, set()) is None


@pytest.mark.parametrize("where", ["site-packages", "venv", "prefix", "package-folder", "through-a-link"])
def test_local_claim_inside_the_venv_or_a_package_folder_is_refused(tmp_path: Path, where: str) -> None:
    prefix = tmp_path / "proj" / ".venv"
    site = prefix / "lib" / "python3.12" / "site-packages"
    folder = {
        "site-packages": site / "my_tool",
        "venv": prefix / "share" / "my-tool",
        "prefix": prefix,
        "package-folder": site,
        "through-a-link": site / "my_tool",
    }[where]
    link = tmp_path / "innocent"
    package, outside = _claimed(tmp_path, link if where == "through-a-link" else folder)
    _project(folder)  # a matching project file: step 3 refuses the claim, not step 4
    link.symlink_to(folder)
    with (
        refuses("discovery.folder-names-inside-environment-run"),
        pytest.raises(LocalInstallRefusedError, match="^the folder it names is inside an environment of this run$"),
    ):
        discovery.local_install(package, outside)


def test_another_spelling_of_a_folder_of_the_run_is_still_inside_it(tmp_path: Path) -> None:
    # macOS has spellings realpath keeps (".VENV" for ".venv", /System/Volumes/Data/...). Linux
    # has neither, so a link in ``outside`` stands in: the names differ, the folder is the same.
    package, _ = _claimed(tmp_path, tmp_path / "proj" / ".venv" / "share" / "my-tool")
    _project(tmp_path / "proj" / ".venv" / "share" / "my-tool")
    (tmp_path / "other-spelling").symlink_to(tmp_path / "proj" / ".venv")
    with (
        refuses("discovery.folder-names-inside-environment-run"),
        pytest.raises(LocalInstallRefusedError, match="^the folder it names is inside an environment of this run$"),
    ):
        discovery.local_install(package, {str(tmp_path / "other-spelling"), str(tmp_path / "no-such-folder")})


def test_a_spelling_with_no_real_parents_is_followed_up_through_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # /.vol/<device>/<inode> names a folder inside a venv, and its parents as text are /.vol and
    # /. Only its real parents lead to the venv. A link realpath leaves alone stands in for it.
    alias = tmp_path / "alias"
    package, outside = _claimed(tmp_path, alias)
    alias.symlink_to(_project(Path(package.folder) / "shipped"))
    monkeypatch.setattr(discovery, "real_place", lambda path: path)
    with (
        refuses("discovery.folder-names-inside-environment-run"),
        pytest.raises(LocalInstallRefusedError, match="^the folder it names is inside an environment of this run$"),
    ):
        discovery.local_install(package, outside)


def test_a_parent_that_cannot_be_read_is_not_known_to_be_outside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path / "project")
    package, outside = _claimed(tmp_path, project)
    identity = discovery._identity
    monkeypatch.setattr(discovery, "_identity", lambda path: None if path.endswith("..") else identity(path))
    with (
        refuses("discovery.folder-names-inside-environment-run"),
        pytest.raises(LocalInstallRefusedError, match="^the folder it names is inside an environment of this run$"),
    ):
        discovery.local_install(package, outside)


def test_a_project_folder_that_holds_the_venv_is_not_inside_it_by_identity(tmp_path: Path) -> None:
    project = _project(tmp_path / "proj")
    package, _ = _claimed(tmp_path, project)
    (tmp_path / "other-spelling").symlink_to(project / ".venv")
    assert discovery.local_install(package, {str(tmp_path / "other-spelling")}) == LocalInstall(
        os.path.realpath(project), True
    )


def test_a_sibling_whose_name_starts_like_the_venv_is_not_inside_it(tmp_path: Path) -> None:
    project = _project(tmp_path / "proj" / ".venv-tools")
    package, outside = _claimed(tmp_path, project)
    assert discovery.local_install(package, outside) == LocalInstall(os.path.realpath(project), True)


@pytest.mark.parametrize(
    ("planted", "step"),
    [
        ("other-name", "no project file in the folder names the distribution"),
        ("setup-py-only", "no project file in the folder names the distribution"),
        ("root", "no project file in the folder names the distribution"),
        ("tmp", "no project file in the folder names the distribution"),
        ("dangling", "the path it names is not a folder"),
        ("missing", "the path it names is not a folder"),
        ("a-file", "the path it names is not a folder"),
    ],
)
def test_mismatched_name_setup_py_only_root_and_dangling_folder_are_refused(
    tmp_path: Path, planted: str, step: str
) -> None:
    folder = tmp_path / "project"
    if planted == "other-name":
        _project(folder, '[project]\nname = "my-tool2"\n')
    elif planted == "setup-py-only":
        _project(folder, "from setuptools import setup; setup(name='my-tool')\n", "setup.py")
    elif planted == "root":
        folder = Path("/")
    elif planted == "tmp":
        folder = tmp_path.parent
    elif planted == "dangling":
        folder.symlink_to(tmp_path / "gone")
    elif planted == "a-file":
        folder.write_text('[project]\nname = "my-tool"\n')
    package, outside = _claimed(tmp_path, folder)
    with pytest.raises(LocalInstallRefusedError, match=re.escape(step)) as raised:
        discovery.local_install(package, outside)
    assert str(raised.value) == step


@pytest.mark.parametrize(
    ("file", "text"),
    [
        ("pyproject.toml", "name = ["),
        ("pyproject.toml", "x = " + "[" * 1000),  # RecursionError, not TOMLDecodeError
        ("pyproject.toml", "x = {a = " * 5000),
        ("pyproject.toml", "x = " + "1" * 5000),  # a plain ValueError: too many digits for int()
        ("pyproject.toml", "project = 3\ntool = 4\n"),
        ("pyproject.toml", "[tool]\npoetry = 3\n"),
        ("pyproject.toml", "[project]\nname = 3\n"),
        ("pyproject.toml", '[project]\nname = ["my-tool"]\n'),
        ("pyproject.toml", '[project]\nname = "bad name!"\n'),  # normalizing this one would raise
        ("pyproject.toml", '[project]\nname = ""\n'),
        ("setup.cfg", "name = my-tool\n"),  # no section header
        ("setup.cfg", "[metadata]\n[metadata]\n"),
        ("setup.cfg", "[metadata]\nname = bad name!\n"),
        ("setup.cfg", "[metadata]\nname = my%tool\n"),  # the plain ConfigParser raises reading this one
        ("setup.cfg", "[other]\nname = my-tool\n"),
        ("setup.cfg", "[DEFAULT]\nname = my-tool\n[metadata]\n"),  # the name is [metadata]'s own, or none
    ],
)
def test_a_project_file_that_gives_no_valid_name_is_a_refusal_never_an_error(
    tmp_path: Path, file: str, text: str
) -> None:
    package, outside = _claimed(tmp_path, _project(tmp_path / "project", text, file))
    with (
        refuses("discovery.no-project-file-folder-names"),
        pytest.raises(LocalInstallRefusedError, match="^no project file in the folder names the distribution$"),
    ):
        discovery.local_install(package, outside)


_LINE, _FILE = discovery.MAX_PROJECT_LINE_CHARS, discovery.MAX_PROJECT_FILE_CHARS
_NAMED_TOML, _NAMED_CFG = '[project]\nname = "my-tool"\n', "[metadata]\nname = my-tool\n"


@pytest.mark.parametrize(
    ("file", "text"),
    [
        ("pyproject.toml", _NAMED_TOML + "a." * _LINE + "a = 1\n"),  # tomllib: square of a key's parts
        ("pyproject.toml", _NAMED_TOML + '"\u2028".' * _LINE + "a = 1\n"),  # splitlines would see short lines
        ("pyproject.toml", _NAMED_TOML + "# a comment\n" * (_FILE // 12)),
        ("setup.cfg", _NAMED_CFG + "a" + " " * _LINE + "b\n"),  # configparser: square of a run of spaces
        ("setup.cfg", _NAMED_CFG + "a\n" * (_FILE // 2)),  # and of the bad lines it reports
    ],
)
def test_a_project_file_large_enough_to_hang_a_parser_is_refused_unparsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, file: str, text: str
) -> None:
    # 1 MiB of these takes about an hour. Timing it here would be slow and flaky, so the test
    # holds both parsers to never seeing the file.
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("no parser may see this file")

    package, outside = _claimed(tmp_path, _project(tmp_path / "project", text, file))
    monkeypatch.setattr(discovery.tomllib, "loads", refuse)
    monkeypatch.setattr(discovery.configparser.RawConfigParser, "read_string", refuse)
    with (
        refuses("discovery.no-project-file-folder-names"),
        pytest.raises(LocalInstallRefusedError, match="^no project file in the folder names the distribution$"),
    ):
        discovery.local_install(package, outside)


@pytest.mark.parametrize(
    ("file", "named", "comment"), [("pyproject.toml", _NAMED_TOML, "#"), ("setup.cfg", _NAMED_CFG, "#")]
)
def test_a_project_file_exactly_at_the_limits_is_parsed(tmp_path: Path, file: str, named: str, comment: str) -> None:
    line = comment * _LINE + "\n"
    filler = line * ((_FILE - len(named)) // len(line))
    tail = comment * (_FILE - len(named) - len(filler))
    text = named + filler + tail
    assert len(text) == _FILE
    project = _project(tmp_path / "project", text, file)
    package, outside = _claimed(tmp_path, project)
    assert discovery.local_install(package, outside) == LocalInstall(os.path.realpath(project), True)


@pytest.mark.parametrize("error", [RecursionError, PermissionError])
def test_a_path_realpath_cannot_resolve_is_a_refusal_not_an_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    # A link chain, and on macOS a link with mode 000, which the system still follows. realpath
    # raises on both before Python 3.13 and on neither after it, so the raise is planted.
    def cannot(path: str) -> str:
        raise error

    project = _project(tmp_path / "project")
    package, outside = _claimed(tmp_path, project)
    monkeypatch.setattr(discovery.os.path, "realpath", cannot)
    with (
        refuses("discovery.path-names-not-folder"),
        pytest.raises(LocalInstallRefusedError, match="^the path it names is not a folder$"),
    ):
        discovery.local_install(package, outside)


def test_reading_a_folder_in_a_project_files_place_leaves_no_descriptor_open(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "pyproject.toml").mkdir(parents=True)
    package, outside = _claimed(tmp_path, project)
    gc.collect()  # a descriptor another test left to the collector must not close during the count
    before = len(os.listdir("/dev/fd"))
    for _ in range(5):
        with (
            refuses("discovery.no-project-file-folder-names"),
            pytest.raises(LocalInstallRefusedError, match="no project file in the folder names the distribution"),
        ):
            discovery.local_install(package, outside)
    assert len(os.listdir("/dev/fd")) <= before


@pytest.mark.parametrize("planted", ["fifo", "folder"])
def test_a_project_file_that_is_not_a_regular_file_is_a_refusal(tmp_path: Path, planted: str) -> None:
    project = tmp_path / "project"
    project.mkdir()
    if planted == "fifo":
        os.mkfifo(project / "pyproject.toml")  # a hung read would hang the run
    else:
        (project / "pyproject.toml").mkdir()
    package, outside = _claimed(tmp_path, project)
    with (
        refuses("discovery.no-project-file-folder-names"),
        pytest.raises(LocalInstallRefusedError, match="^no project file"),
    ):
        discovery.local_install(package, outside)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/tool",
        "file://host/x",
        "file:relative",
        "file:///a%00b",
        "file:///a\ud800b",
        "file://[bad/x",
    ],
)
def test_a_dir_info_url_that_names_no_local_folder_is_refused(tmp_path: Path, url: str) -> None:
    package, outside = _claimed(tmp_path, url)
    with (
        refuses("discovery.url-not-absolute-file-path"),
        pytest.raises(LocalInstallRefusedError, match="^its URL is not an absolute file:// path$"),
    ):
        discovery.local_install(package, outside)


@pytest.mark.parametrize(
    ("data", "text"), [(b"{not json", "not JSON"), (b" " * (direct_url.MAX_BYTES + 1), "larger than PEP 610 data")]
)
def test_unreadable_direct_url_is_a_refused_claim_not_a_check_error(tmp_path: Path, data: bytes, text: str) -> None:
    package, outside = _claimed(tmp_path, _project(tmp_path / "project"))
    (Path(package.folder) / package.record / "direct_url.json").write_bytes(data)
    with (
        refuses("discovery.file-could-not-read"),
        pytest.raises(LocalInstallRefusedError, match=re.escape(f"the file could not be read: {text}")) as raised,
    ):
        discovery.local_install(package, outside)
    assert str(raised.value) == f"the file could not be read: {text}"


def test_a_direct_url_that_cannot_be_opened_is_a_refused_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The open fails (no permission, a disk error): the claim is refused, never read as "no
    # claim". Planted, so the test runs as root too, where a mode-000 file still opens (#148).
    package, outside = _claimed(tmp_path, _project(tmp_path / "project"))
    file = str(Path(package.folder) / package.record / "direct_url.json")
    real = os.open

    def cannot(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
        if path == file:
            raise PermissionError(13, "Permission denied")
        return real(path, flags, *args, **kwargs)

    monkeypatch.setattr(direct_url.os, "open", cannot)
    with (
        refuses("direct_url.open-failed"),
        refuses("discovery.file-could-not-read"),
        pytest.raises(LocalInstallRefusedError, match="^the file could not be read: it cannot be opened$"),
    ):
        discovery.local_install(package, outside)
