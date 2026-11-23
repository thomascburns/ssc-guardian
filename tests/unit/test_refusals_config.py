# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Negative tests for the settings, pip, uv and pin file refusals the coverage baseline listed (issue #11)."""

from __future__ import annotations

import errno
import os
import re
from pathlib import Path
from types import TracebackType
from typing import IO

import pytest

from ssc_guardian import settings as settings_module
from ssc_guardian.commands.pin import read_sources
from ssc_guardian.findings import ExitCode, IncompleteCheckError
from ssc_guardian.lockfile import LOCK_FILE
from ssc_guardian.plugin import CooldownSetting
from ssc_guardian.plugins import pip, uv
from ssc_guardian.settings import ConfigFileError, FileKind, LayerSource, load_settings, parse_settings
from tests.refusal_sites import refuses
from tests.unit.test_discovery import fake_mac
from tests.unit.test_pinning import run_pin

pytestmark = pytest.mark.unit

REPOSITORY_FILE = "/repo/.ssc-guardian.toml"
WORKSTATION_FILE = "/Users/me/.config/ssc-guardian/config.toml"


def _parse(text: str, *, kind: FileKind = FileKind.REPOSITORY) -> None:
    source = LayerSource.REPOSITORY if kind is FileKind.REPOSITORY else LayerSource.WORKSTATION
    place = REPOSITORY_FILE if kind is FileKind.REPOSITORY else WORKSTATION_FILE
    parse_settings("format = 1\n" + text, kind=kind, source=source, place=place, home="/Users/me")


def _entries(folder: Path) -> dict[str, bytes | None]:
    """Every path under ``folder`` with its bytes (None for a folder), to show nothing changed."""
    found: dict[str, bytes | None] = {}
    for path in sorted(folder.rglob("*")):
        found[str(path.relative_to(folder))] = path.read_bytes() if path.is_file() else None
    return found


# --- settings: reading the file -------------------------------------------------------


def test_a_settings_path_through_a_regular_file_could_not_be_read(tmp_path: Path) -> None:
    # A file where a folder should be: the open fails with something other than "absent",
    # which is never read as "no settings".
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("format = 1\n")
    path = blocker / ".ssc-guardian.toml"
    with (
        refuses("settings.open-failed"),
        pytest.raises(ConfigFileError, match=re.escape(f"{path}: could not be read (NotADirectoryError)") + r"\Z"),
    ):
        load_settings(str(path), kind=FileKind.REPOSITORY)


class _FailingDisk:
    """The open file, whose read fails as a failing disk's does (EIO)."""

    def __init__(self, handle: IO[bytes]) -> None:
        self._handle = handle

    def __enter__(self) -> _FailingDisk:
        return self

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None, tb: TracebackType | None) -> None:
        self._handle.close()

    def fileno(self) -> int:
        return self._handle.fileno()

    def read(self, size: int = -1) -> bytes:
        raise OSError(errno.EIO, "Input/output error")


def test_a_settings_file_whose_read_fails_could_not_be_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The open succeeds and the file is regular; the read itself fails (an external fault).
    path = tmp_path / ".ssc-guardian.toml"
    path.write_text("format = 1\n")
    real_fdopen = os.fdopen

    def fdopen(fd: int, mode: str) -> _FailingDisk:
        assert mode == "rb"
        return _FailingDisk(real_fdopen(fd, mode))

    with monkeypatch.context() as patch:
        patch.setattr(settings_module.os, "fdopen", fdopen)
        with (
            refuses("settings.read-failed"),
            pytest.raises(ConfigFileError, match=re.escape(f"{path}: could not be read (OSError)") + r"\Z") as caught,
        ):
            load_settings(str(path), kind=FileKind.REPOSITORY)
    assert caught.value.place == str(path)
    assert isinstance(caught.value.__cause__, OSError) and caught.value.__cause__.errno == errno.EIO


# --- settings: entries ----------------------------------------------------------------


def test_a_note_longer_than_500_characters_is_malformed() -> None:
    entry = '[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\ndate = 2026-11-03\nnote = "{}"\n'
    _parse(entry.format("n" * 500))  # the limit itself is accepted
    said = f"{REPOSITORY_FILE}: acknowledgment 1 note is longer than 500 characters"
    with (
        refuses("settings.free-text-too-long"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"),
    ):
        _parse(entry.format("n" * 501))


def test_a_deny_entry_that_is_not_a_list_is_malformed() -> None:
    with (
        refuses("settings.deny-not-list"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(f"{REPOSITORY_FILE}: deny is not a list") + r"\Z"),
    ):
        _parse('deny = "pypi:requests"\n')


def test_venv_folders_that_is_not_a_list_is_malformed() -> None:
    # #255: [scope] venv_folders is refused whatever it holds, before its value is read.
    said = f"{WORKSTATION_FILE}: line 3: scope.venv_folders is no longer read"
    with (
        refuses("settings.malformed-entry"),
        refuses("settings.scope-refused"),
        pytest.raises(ConfigFileError, match=re.escape(said)),
    ):
        _parse('[scope]\nvenv_folders = "/Users/me/projects"\n', kind=FileKind.WORKSTATION)


# --- pin: the workflows folder --------------------------------------------------------


def test_pin_stops_when_the_workflows_folder_could_not_be_read(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".github").mkdir()
    (root / ".github" / "workflows").write_text("a file where the folder should be\n")
    folder = root / ".github" / "workflows"
    said = f"{folder} could not be read (NotADirectoryError)"
    with refuses("pin.could-not-read"), pytest.raises(IncompleteCheckError, match=re.escape(said) + r"\Z") as caught:
        read_sources(str(root))
    assert type(caught.value).__name__ == "_StopError"
    before = _entries(root)
    result, err = run_pin(root, "actions/checkout@v4.2.2", {})
    assert result.exit_code is ExitCode.INCOMPLETE
    assert f"ssc-guardian: {said}; nothing written.\n" in err
    assert _entries(root) == before
    assert not (root / LOCK_FILE).exists()


# --- uv -------------------------------------------------------------------------------


def _uv_config(tmp_path: Path, text: str) -> Path:
    config = tmp_path / "uv" / "uv.toml"
    config.parent.mkdir(parents=True)
    config.write_text(text)
    return config


def test_a_uv_config_that_is_not_valid_toml_is_refused(tmp_path: Path) -> None:
    config = _uv_config(tmp_path, "exclude-newer = \n")
    before = _entries(tmp_path)
    # The parser's own words vary by Python version; the frame around them does not.
    pattern = re.escape(f"{config}: is not valid TOML (") + r".+\)\Z"
    with refuses("uv.not-valid-toml"), pytest.raises(ConfigFileError, match=pattern):
        uv.UvPlugin().installer_cooldown(str(config))
    with refuses("uv.not-valid-toml"), pytest.raises(ConfigFileError, match=pattern):  # never rewritten either
        uv.UvPlugin().write_cooldown(CooldownSetting(str(config), rolling_days=21))
    assert _entries(tmp_path) == before


def test_a_uv_window_in_a_form_guardian_cannot_read_is_refused(tmp_path: Path) -> None:
    config = _uv_config(tmp_path, 'exclude-newer = "soon"\n')
    said = f"{config}: exclude-newer is in a form Guardian cannot read"
    with refuses("uv.form-guardian-cannot-read"), pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"):
        uv.UvPlugin().installer_cooldown(str(config))


def test_a_uv_rewrite_that_is_not_valid_toml_writes_nothing(tmp_path: Path) -> None:
    # A window spread over several lines: the line rewrite replaces only its first line, and
    # the rest no longer parses.
    config = _uv_config(tmp_path, 'exclude-newer = [\n  "P3D",\n]\n')
    before = _entries(tmp_path)
    with (
        refuses("uv.new-text-not-toml"),
        pytest.raises(ConfigFileError, match=re.escape(f"{config}: the new text did not read back") + r"\Z"),
    ):
        uv.UvPlugin().write_cooldown(CooldownSetting(str(config), rolling_days=21))
    assert _entries(tmp_path) == before


def test_a_uv_rewrite_that_changes_another_value_writes_nothing(tmp_path: Path) -> None:
    # A line inside a multi-line string looks like the key: rewriting it would change the string.
    config = _uv_config(tmp_path, 'note = """\nexclude-newer = 1\n"""\n')
    before = _entries(tmp_path)
    said = f"{config}: the new text did not read back as written; edit it by hand"
    with refuses("uv.new-text-did-not-read-back"), pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"):
        uv.UvPlugin().write_cooldown(CooldownSetting(str(config), rolling_days=21))
    assert _entries(tmp_path) == before


# --- pip ------------------------------------------------------------------------------


def _pip_conf(tmp_path: Path, text: str) -> Path:
    conf = tmp_path / "venv" / "pip.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text(text)
    return conf


def test_a_pip_conf_pip_cannot_parse_is_refused(tmp_path: Path) -> None:
    conf = _pip_conf(tmp_path, "uploaded-prior-to = P21D\n")  # no section header
    plugin = pip.PipPlugin(fake_mac(tmp_path))
    before = _entries(tmp_path / "venv")
    said = f"{conf}: is not a valid pip configuration file (MissingSectionHeaderError)"
    with refuses("pip.not-valid-pip-configuration-file"), pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"):
        plugin.installer_cooldown(str(conf))
    with (
        refuses("pip.not-valid-pip-configuration-file"),
        pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"),
    ):  # never rewritten either
        plugin.write_cooldown(CooldownSetting(str(conf), rolling_days=21))
    assert _entries(tmp_path / "venv") == before


def test_a_pip_value_in_a_form_guardian_cannot_read_is_refused(tmp_path: Path) -> None:
    conf = _pip_conf(tmp_path, "[global]\nuploaded-prior-to = soon\n")
    said = f"{conf}: uploaded-prior-to is in a form Guardian cannot read"
    with refuses("pip.form-guardian-cannot-read"), pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"):
        pip.PipPlugin(fake_mac(tmp_path)).installer_cooldown(str(conf))


def test_a_pip_rewrite_that_changes_another_value_writes_nothing(tmp_path: Path) -> None:
    # The key indented under another key is that key's continuation line to pip; rewriting it
    # as the key would change the other value.
    conf = _pip_conf(tmp_path, "[global]\nindex-url = https://example.invalid/simple\n  uploaded-prior-to = P3D\n")
    before = _entries(tmp_path / "venv")
    said = f"{conf}: the new text did not read back as written"
    with refuses("pip.new-text-did-not-read"), pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"):
        pip.PipPlugin(fake_mac(tmp_path)).write_cooldown(CooldownSetting(str(conf), rolling_days=21))
    assert _entries(tmp_path / "venv") == before
