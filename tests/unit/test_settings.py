# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Settings files, stricter wins, the deny list and atomic writes (issue #3, contracts §10.1-§10.3)."""

from __future__ import annotations

import os
import re
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from ssc_guardian import settings as settings_module
from ssc_guardian.findings import Ecosystem, Rule, SkipReason
from ssc_guardian.settings import (
    BUILT_IN,
    Acknowledgment,
    BlockOn,
    ConfigFileError,
    FileKind,
    Key,
    Layer,
    LayerSource,
    Settings,
    append_acknowledgment,
    find_repository_root,
    load_settings,
    parse_settings,
    workstation_dir,
    workstation_settings,
)
from tests.refusal_sites import Refuses, refuses

pytestmark = pytest.mark.unit


# #255: [scope] is refused, with the arguments that replace it.
ECOSYSTEMS_REFUSED = (
    "scope.ecosystems is no longer read: a command acts only on what its arguments name; remove [scope] and "
    "choose the ecosystems with --envs, --repo or --ecosystem, and the places with --path PATH"
)


def _layer(text: str, *, kind: FileKind = FileKind.REPOSITORY, place: str = "/repo/.ssc-guardian.toml") -> Layer:
    source = LayerSource.REPOSITORY if kind is FileKind.REPOSITORY else LayerSource.WORKSTATION
    return parse_settings("format = 1\n" + text, kind=kind, source=source, place=place, home="/Users/me")


def _workstation(text: str) -> Layer:
    return _layer(text, kind=FileKind.WORKSTATION, place="/Users/me/.config/ssc-guardian/config.toml")


@pytest.mark.parametrize(
    ("text", "said", "site"),
    [
        (
            '[rules]\n"requests" = { cooldown_days = 3 }\n',
            re.escape("rule 'requests' does not name its ecosystem (pypi: or github-actions:)"),
            refuses("settings.does-not-name-ecosystem-pypi"),
        ),
        (
            'deny = ["requests"]\n',
            re.escape("deny entry 'requests' does not name its ecosystem (pypi: or github-actions:)"),
            refuses("settings.does-not-name-ecosystem-pypi"),
        ),
        (
            '[rules]\n"npm:left-pad" = { cooldown_days = 3 }\n',
            "names an unknown ecosystem",
            refuses("settings.names-unknown-ecosystem"),
        ),
        ('deny = ["pip:requests"]\n', "names an unknown ecosystem", refuses("settings.names-unknown-ecosystem")),
        (
            'deny = ["github-actions:not an action"]\n',
            "is not a valid action",
            refuses("settings.parse-item-not-valid"),
        ),
    ],
)
def test_unprefixed_rule_is_refused(text: str, said: str, site: Refuses) -> None:
    # Never guessed: the whole file is malformed (exit 2) and nothing in it applies.
    with site, refuses("settings.malformed-entry"), pytest.raises(ConfigFileError, match=said) as caught:
        _layer(text)
    assert caught.value.place == "/repo/.ssc-guardian.toml"
    assert caught.value.reason.in_scope


_MOVE_IT = "is a pypi entry, which only ~/.config/ssc-guardian/config.toml applies; move it to config.toml"


def test_repository_file_refuses_pypi_deny_entry(tmp_path: Path) -> None:
    # Negative control (#229, L1-3/L5-1): the Python commands read only config.toml, so a pypi
    # deny entry in a repository file is refused (exit 2) naming the file and its line, never
    # ignored while its author believes it blocks.
    path = tmp_path / ".ssc-guardian.toml"
    path.write_text(
        'format = 1\n# "pypi:idna" in a comment is not the entry\n'
        'deny = [\n  "github-actions:o/r",\n  "pypi:idna",\n]\n'
    )
    said = f"{path}: line 5: deny entry 'pypi:idna' {_MOVE_IT}"
    with (
        refuses("settings.repository-pypi-deny-entry"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z") as caught,
    ):
        load_settings(str(path), kind=FileKind.REPOSITORY)
    assert caught.value.place == str(path)
    assert caught.value.reason is SkipReason.CHECK_ERROR and caught.value.reason.in_scope  # exit 2
    # The default branch's copy, read in CI, is refused the same way.
    with (
        refuses("settings.repository-pypi-deny-entry"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(f"default branch: line 1: deny entry 'pypi:x' {_MOVE_IT}")),
    ):
        parse_settings(
            'deny = ["pypi:x"]\nformat = 1\n', kind=FileKind.REPOSITORY, source=LayerSource.DEFAULT_BRANCH, place=None
        )
    # The same entry in config.toml still applies.
    assert Settings.of(_workstation('deny = ["pypi:idna"]\n')).denied(Ecosystem.PYPI, "idna")


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ('[rules]\n"pypi:requests" = { cooldown_days = 30 }\n', 3),
        ("[rules]\n'pypi:Requests' = { cooldown_days = 30 }\n", 3),
        ('[rules."pypi:requests"]\ncooldown_days = 30\n', 2),
        ('rules."pypi:requests".cooldown_days = 30\n', 2),
    ],
)
def test_repository_file_refuses_pypi_rule(text: str, line: int) -> None:
    # Negative (#229): a pypi rule in a repository file, however it is written, is refused.
    name = "pypi:Requests" if "Requests" in text else "pypi:requests"
    said = f"/repo/.ssc-guardian.toml: line {line}: rule {name!r} {_MOVE_IT}"
    with (
        refuses("settings.repository-pypi-rule"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z") as caught,
    ):
        _layer(text)
    assert caught.value.reason.in_scope
    # The same rule in config.toml still applies.
    assert Settings.of(_workstation(text)).cooldown_days(Ecosystem.PYPI, "requests") == 30


@pytest.mark.parametrize(
    ("text", "said", "site"),
    [
        # Other line-break characters in a comment are not TOML line ends: the count holds.
        (
            'format = 1\n# a b\u0085c\ndeny = ["pypi:idna"]\n',
            "line 3: deny entry 'pypi:idna'",
            refuses("settings.repository-pypi-deny-entry"),
        ),
        # A comment that quotes the entry on an earlier line is not the entry.
        (
            'format = 1\ndeny = ["github-actions:o/r"] # was "pypi:idna"\n'
            '[rules]\n"pypi:idna" = { cooldown_days = 3 }\n',
            "line 4: rule 'pypi:idna'",
            refuses("settings.repository-pypi-rule"),
        ),
        (
            'format = 1\n[rules]\n"pypi:idna" = { cooldown_days = 3 }  # "pypi:idna" once more\n',
            "line 3: rule 'pypi:idna'",
            refuses("settings.repository-pypi-rule"),
        ),
        # Written twice, as a deny entry and a rule: every line that holds it is named.
        (
            'format = 1\ndeny = ["pypi:idna"]\n[rules]\n"pypi:idna" = { cooldown_days = 3 }\n',
            "lines 2, 4: rule 'pypi:idna'",
            refuses("settings.repository-pypi-rule"),
        ),
    ],
)
def test_refusal_names_the_entrys_own_lines(text: str, said: str, site: Refuses) -> None:
    # Edge cases (#229 review): the line named is the entry's own, never a comment's.
    with site, refuses("settings.malformed-entry"), pytest.raises(ConfigFileError, match=re.escape(said)):
        parse_settings(text, kind=FileKind.REPOSITORY, source=LayerSource.REPOSITORY, place="/repo/.ssc-guardian.toml")


def test_refusal_reads_past_a_hash_inside_a_string() -> None:
    said = "line 2: deny entry 'pypi:idna'"
    with (
        refuses("settings.repository-pypi-deny-entry"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(said)),
    ):
        _layer('deny = ["github-actions:o/r", "pypi:idna"]  # "pypi:idna"\n')
    assert settings_module._code('deny = ["a#b", "c"] # "d"') == 'deny = ["a#b", "c"] '
    assert settings_module._code("x = 'a#b' # c") == "x = 'a#b' "
    assert settings_module._code('x = "a\\"#b" # c') == 'x = "a\\"#b" '


def test_repository_file_refuses_a_pypi_entry_it_cannot_place_on_a_line() -> None:
    # An entry spelled with an escape is still refused; the message then names no line.
    said = f"/repo/.ssc-guardian.toml: deny entry 'pypi:idna' {_MOVE_IT}"
    with (
        refuses("settings.repository-pypi-deny-entry"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"),
    ):
        _layer('deny = ["pypi:\\u0069dna"]\n')


def test_repository_file_keeps_github_actions_entries() -> None:
    # Edge case (#229): github-actions entries stay valid in both files, unchanged.
    text = (
        'deny = ["github-actions:bad-org/action"]\n[rules]\n"github-actions:actions/checkout" = { cooldown_days = 7 }\n'
    )
    for layer in (_layer(text), _workstation(text)):
        assert layer.deny == {(Ecosystem.GITHUB_ACTIONS, "bad-org/action")}
        assert layer.rules == {(Ecosystem.GITHUB_ACTIONS, "actions/checkout"): 7}
        settings = Settings.of(layer)
        assert settings.denied(Ecosystem.GITHUB_ACTIONS, "Bad-Org/Action")
        assert settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "actions/checkout") == 7
    assert _layer(text) == _layer(text)  # idempotent on re-read


def test_deny_entry_blocks_whatever_other_layers_say() -> None:
    workstation = _workstation('deny = ["pypi:Evil_Package", "github-actions:Bad-Org/Action"]\n')
    repository = _layer(
        '[defaults]\ncooldown_days = 0\n[rules]\n"github-actions:bad-org/action" = { cooldown_days = 0 }\n'
    )
    settings = Settings.of(workstation, repository)
    # Matched in the one spelling of each name (D18), whatever the other layer allows.
    assert settings.denied(Ecosystem.PYPI, "evil.package")
    assert settings.denied(Ecosystem.GITHUB_ACTIONS, "bad-org/action")
    assert not settings.denied(Ecosystem.PYPI, "requests")
    # A repository's entry denies every Action under a path in it (owner ruling N6).
    assert settings.denied(Ecosystem.GITHUB_ACTIONS, "Bad-Org/Action/sub")
    assert not settings.denied(Ecosystem.GITHUB_ACTIONS, "bad-org/action-two")


def test_a_deny_entry_with_a_path_denies_only_that_path() -> None:
    settings = Settings.of(_layer('deny = ["github-actions:org/repo/setup"]\n'))
    assert settings.denied(Ecosystem.GITHUB_ACTIONS, "Org/Repo/setup")
    assert not settings.denied(Ecosystem.GITHUB_ACTIONS, "org/repo")
    assert not settings.denied(Ecosystem.GITHUB_ACTIONS, "org/repo/other")


def test_command_line_cannot_weaken_a_rule() -> None:
    workstation = _workstation('[defaults]\ncooldown_days = 21\nblock_on = "any"\n')
    command_line = Layer(LayerSource.COMMAND_LINE, defaults={Key.COOLDOWN_DAYS: 3, Key.BLOCK_ON: BlockOn.NEVER})
    settings = Settings.of(workstation, command_line)
    assert settings.cooldown_days(Ecosystem.PYPI, "requests") == 21
    assert settings.block_on is BlockOn.ANY
    # The weakened values are reported, as notices with no place for the command line.
    weakened = {(w.key, w.source, w.value, w.applied) for w in settings.weakened}
    assert weakened == {
        (Key.COOLDOWN_DAYS, LayerSource.COMMAND_LINE, 3, 21),
        (Key.BLOCK_ON, LayerSource.COMMAND_LINE, BlockOn.NEVER, BlockOn.ANY),
    }
    # One notice for the command line, its detail naming both weakened keys (#38).
    notices = settings.notices()
    assert [(f.rule, f.place) for f in notices] == [(Rule.WEAKENED_SETTING, None)]
    assert notices[0].detail == "cooldown_days 3, applied 21; block_on never, applied any"


def test_command_line_can_tighten_a_rule() -> None:
    command_line = Layer(LayerSource.COMMAND_LINE, defaults={Key.COOLDOWN_DAYS: 30})
    settings = Settings.of(_workstation("[defaults]\ncooldown_days = 21\n"), command_line)
    assert settings.cooldown_days(Ecosystem.PYPI, "requests") == 30
    assert [w.source for w in settings.weakened] == [LayerSource.WORKSTATION]


@pytest.mark.parametrize(
    ("key", "workstation", "repository", "stricter"),
    [
        (Key.COOLDOWN_DAYS, 0, 1, 1),
        (Key.COOLDOWN_DAYS, 3650, 3649, 3650),
        (Key.BLOCK_ON, '"never"', '"strong"', BlockOn.STRONG),
        (Key.BLOCK_ON, '"any"', '"strong"', BlockOn.ANY),
        (Key.FIXED_DATE_TOLERANCE_DAYS, 1, 2, 1),
        (Key.YOUNG_REPOSITORY_DAYS, 90, 91, 91),
        (Key.MIN_STARS, 60, 50, 60),
        (Key.NESTING_DEPTH, 10, 1, 1),
        (Key.NESTED_REFERENCE_LIMIT, 500, 499, 499),
    ],
)
def test_stricter_wins_for_each_field(key: Key, workstation: object, repository: object, stricter: object) -> None:
    settings = Settings.of(
        _workstation(f"[defaults]\n{key.value} = {workstation}\n"),
        _layer(f"[defaults]\n{key.value} = {repository}\n"),
    )
    assert settings.value(key) == stricter
    # The other layer's value is reported as weakened, from its own file.
    assert len(settings.weakened) == 1
    assert settings.weakened[0].applied == stricter


@pytest.mark.parametrize(
    ("key", "low", "high"),
    [
        (Key.COOLDOWN_DAYS, -1, 3651),
        (Key.FIXED_DATE_TOLERANCE_DAYS, 0, 3651),
        (Key.NESTING_DEPTH, 0, 11),
        (Key.NESTED_REFERENCE_LIMIT, 0, 501),
        (Key.MIN_STARS, 49, 10_000_001),
        (Key.YOUNG_REPOSITORY_DAYS, 89, 36501),
    ],
)
def test_values_outside_their_range_are_malformed(key: Key, low: int, high: int) -> None:
    # T3 thresholds can only be raised and T5 limits only lowered from the built-in values (N-4).
    for value in (low, high, "true", '"7"'):
        with (
            refuses("settings.malformed-entry"),
            refuses("settings.not-whole-number"),
            pytest.raises(ConfigFileError, match=f"{key.value} is not a whole number"),
        ):
            _layer(f"[defaults]\n{key.value} = {value}\n")


def test_stricter_wins_for_start_dates_and_rules() -> None:
    sha = "a" * 40
    workstation = _workstation(
        f'[[start_date]]\naction = "Actions/Checkout"\nsha = "{sha}"\ndate = 2026-10-01\n'
        '[rules]\n"github-actions:actions/checkout" = { cooldown_days = 30 }\n'
    )
    repository = _layer(
        f'[[start_date]]\naction = "actions/checkout"\nsha = "{sha}"\ndate = 2026-10-05\n'
        '[rules]\n"github-actions:Actions/Checkout" = { cooldown_days = 40 }\n'
    )
    settings = Settings.of(workstation, repository)
    assert settings.start_date("actions/checkout", sha) == date(2026, 10, 5)  # the later date
    assert settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "actions/checkout") == 40
    assert [(w.place, w.item, w.value) for w in settings.weakened] == [
        ("/Users/me/.config/ssc-guardian/config.toml", "actions/checkout", 30)
    ]


def test_scope_ecosystems_is_refused_in_either_file() -> None:
    # #255 (owner's rulings of 2026-11-13, option A): no setting changes what a command checks, so
    # the default scope plain check read from [scope] ecosystems is gone, and a file still
    # holding it is malformed in either file, never "no narrowing" read in silence.
    for kind in FileKind:
        for value in ('["pypi"]', "[]"):
            with (
                refuses("settings.malformed-entry"),
                refuses("settings.scope-refused"),
                pytest.raises(
                    ConfigFileError, match=re.escape(f"/repo/.ssc-guardian.toml: line 3: {ECOSYSTEMS_REFUSED}") + r"\Z"
                ),
            ):
                _layer(f"[scope]\necosystems = {value}\n", kind=kind)


@pytest.mark.parametrize(
    ("value", "said", "site"),
    [
        ('["npm"]', "line 3: " + ECOSYSTEMS_REFUSED, refuses("settings.scope-refused")),
        ('["pypi", "PyPI"]', "line 3: " + ECOSYSTEMS_REFUSED, refuses("settings.scope-refused")),
        ('"pypi"', "line 3: " + ECOSYSTEMS_REFUSED, refuses("settings.scope-refused")),
        ("[1]", "line 3: " + ECOSYSTEMS_REFUSED, refuses("settings.scope-refused")),
    ],
)
def test_scope_setting_with_unknown_ecosystem_is_malformed(value: str, said: str, site: Refuses) -> None:
    # Whatever it holds, [scope] is refused before its value is read (#255).
    with (
        site,
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(f"/repo/.ssc-guardian.toml: {said}") + r"\Z"),
    ):
        _layer(f"[scope]\necosystems = {value}\n")


def test_a_rules_entry_may_shorten_within_its_own_file() -> None:
    # Q4: built-in defaults are only the fallback and take no part in stricter-wins.
    settings = Settings.of(
        _layer('[defaults]\ncooldown_days = 21\n[rules]\n"github-actions:actions/checkout" = { cooldown_days = 3 }\n')
    )
    assert settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "Actions/Checkout") == 3
    assert settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "actions/setup-python") == 21
    assert settings.weakened == ()
    # Another layer's default is stricter for that item, and the shortened rule is reported.
    stricter = Settings.of(_workstation("[defaults]\ncooldown_days = 14\n"), settings.layers[0])
    assert stricter.cooldown_days(Ecosystem.GITHUB_ACTIONS, "actions/checkout") == 14
    assert [(w.source, w.item, w.value) for w in stricter.weakened if w.item] == [
        (LayerSource.REPOSITORY, "actions/checkout", 3)
    ]


def test_missing_settings_files_use_defaults(tmp_path: Path) -> None:
    settings = workstation_settings(home=str(tmp_path))
    assert settings.layers == ()
    for key, value in BUILT_IN.items():
        assert settings.value(key) == value
    assert settings.value(Key.FIXED_DATE_TOLERANCE_DAYS) is None  # computed by #5
    assert settings.cooldown_days(Ecosystem.PYPI, "requests") == 21
    assert settings.block_on is BlockOn.STRONG
    assert settings.notices() == ()
    assert load_settings(str(tmp_path / "nope.toml"), kind=FileKind.REPOSITORY) is None


@pytest.mark.parametrize(
    ("text", "said", "site"),
    [
        ("", "must start with format = 1", refuses("settings.must-start-format")),  # no format line
        ("format = 2\n", "must start with format = 1", refuses("settings.must-start-format")),
        ("format = true\n", "must start with format = 1", refuses("settings.must-start-format")),
        # A mistyped key never leaves a weaker built-in value.
        ("format = 1\n[defaults]\ncooldown = 21\n", "unknown key 'cooldown'", refuses("settings.unknown-key")),
        ("format = 1\nextra = 1\n", "unknown key 'extra'", refuses("settings.unknown-key")),
        (
            'format = 1\n[defaults]\nblock_on = "some"\n',
            "block_on is not never, strong or any",
            refuses("settings.block-not-never-strong-any"),
        ),
        (
            "format = 1\n[scope]\necosystems = []\n",
            "line 3: scope.ecosystems is no longer read",
            refuses("settings.scope-refused"),
        ),
        (
            'format = 1\n[scope]\necosystems = ["npm"]\n',
            "line 3: scope.ecosystems is no longer read",
            refuses("settings.scope-refused"),
        ),
        # Refused in either file (#255).
        (
            'format = 1\n[scope]\nvenv_folders = ["/Users/me/projects"]\n',
            "line 3: scope.venv_folders is no longer read",
            refuses("settings.scope-refused"),
        ),
        (
            'format = 1\n[rules]\n"github-actions:o/a" = { cooldown_days = 1 }\n'
            '"github-actions:O/A" = { cooldown_days = 2 }\n',
            "names an item another rule names",
            refuses("settings.names-item-another-rule-names"),
        ),
        (
            'format = 1\n[rules]\n"github-actions:o/a" = { block_on = "any" }\n',
            "unknown key 'block_on'",
            refuses("settings.unknown-key"),
        ),
        (
            'format = 1\n[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\n',
            "has no date",
            refuses("settings.acknowledgment-missing-key"),
        ),
        (
            'format = 1\n[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\ndate = "2026-11-03"\n',
            re.escape("/r/.ssc-guardian.toml: acknowledgment 1 date is not a date (YYYY-MM-DD, unquoted)") + r"\Z",
            refuses("settings.not-date-yyyy-mm-dd"),
        ),
        (
            'format = 1\n[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\n'
            'date = 2026-11-03\nnote = "a\\nb"\n',
            re.escape("/r/.ssc-guardian.toml: acknowledgment 1 note holds a control, format or line-break character")
            + r"\Z",
            refuses("settings.holds-control-format-line-break"),
        ),
        (
            'format = 1\n[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\ndate = 2026-11-03T10:00:00\n',
            re.escape("/r/.ssc-guardian.toml: acknowledgment 1 date is not a date (YYYY-MM-DD, unquoted)") + r"\Z",
            refuses("settings.not-date-yyyy-mm-dd"),
        ),
        (
            'format = 1\n[[start_date]]\naction = "o/r"\nsha = "v4"\ndate = 2026-11-03\n',
            "sha is not a valid sha",
            refuses("settings.text-value-not-valid"),
        ),
        # The parser's own words vary by Python version; the frame around them does not.
        (
            "format = 1\nnot toml",
            re.escape("/r/.ssc-guardian.toml: is not valid TOML (") + r".+\)\Z",
            refuses("settings.not-valid-toml"),
        ),
    ],
)
def test_malformed_settings_file_is_refused_whole(text: str, said: str, site: Refuses) -> None:
    with site, refuses("settings.malformed-entry"), pytest.raises(ConfigFileError, match=said):
        parse_settings(text, kind=FileKind.REPOSITORY, source=LayerSource.REPOSITORY, place="/r/.ssc-guardian.toml")


def test_files_hold_only_their_own_entries(tmp_path: Path) -> None:
    with (
        refuses("settings.malformed-entry"),
        refuses("settings.unknown-key"),
        pytest.raises(ConfigFileError, match="unknown key 'acknowledgment'"),
    ):
        _workstation('[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\ndate = 2026-11-03\n')


def test_unreadable_large_or_non_utf8_file_is_refused(tmp_path: Path) -> None:
    big = tmp_path / "big.toml"
    big.write_bytes(b"format = 1\n" + b"#" * (1024 * 1024))
    bad = tmp_path / "bad.toml"
    bad.write_bytes(b"format = 1\n# \xff\n")
    for path, said, site in (
        (big, "is larger than", refuses("settings.larger-than-limit")),
        (bad, "is not UTF-8", refuses("settings.not-utf8")),
    ):
        with site, pytest.raises(ConfigFileError, match=said) as caught:
            load_settings(str(path), kind=FileKind.REPOSITORY)
        assert caught.value.place == str(path)


def test_acknowledgments_count_from_the_default_branch_only_in_ci() -> None:
    ack = '[[acknowledgment]]\nrepository = "o/{}"\nrepository_id = 7\ndate = 2026-11-03\n'
    change = _layer(ack.format("change"))
    default = parse_settings(
        "format = 1\n" + ack.format("main"), kind=FileKind.REPOSITORY, source=LayerSource.DEFAULT_BRANCH, place=None
    )
    assert [a.repository for a in Settings.of(change).acknowledgments] == ["o/change"]
    assert [a.repository for a in Settings.of(change, default, ci=True).acknowledgments] == ["o/main"]


def test_acknowledgment_append_is_atomic_idempotent_and_keeps_comments(tmp_path: Path) -> None:
    path = tmp_path / ".ssc-guardian.toml"
    path.write_text("# team settings\nformat = 1\n[defaults]\ncooldown_days = 30\n")
    path.chmod(0o640)
    ack = Acknowledgment("Some-Org/new-action", 123, date(2026, 11, 3), 'reviewed "by hand"')
    assert append_acknowledgment(str(path), ack) is True
    first = path.read_text()
    assert first.startswith("# team settings\n")
    assert append_acknowledgment(str(path), ack) is False  # no duplicate
    assert path.read_text() == first
    layer = load_settings(str(path), kind=FileKind.REPOSITORY)
    assert layer is not None and layer.acknowledgments == (ack,)
    assert layer.defaults == {Key.COOLDOWN_DAYS: 30}
    assert path.stat().st_mode & 0o777 == 0o640
    assert sorted(p.name for p in tmp_path.iterdir()) == [".ssc-guardian.toml"]  # no temporary left
    # A changed ID is a person's edit, never silent.
    with (
        refuses("settings.another-id-edit-hand"),
        pytest.raises(ConfigFileError, match="with another ID; edit it by hand"),
    ):
        append_acknowledgment(str(path), Acknowledgment("some-org/new-action", 999, date(2026, 11, 3)))


def test_acknowledgment_append_creates_the_file(tmp_path: Path) -> None:
    path = tmp_path / ".ssc-guardian.toml"
    assert append_acknowledgment(str(path), Acknowledgment("o/r", 1, date(2026, 11, 3)))
    assert path.read_text().startswith("format = 1\n")
    assert path.stat().st_mode & 0o777 == 0o644


def test_repository_root_and_workstation_folder(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "a" / "b").mkdir(parents=True)
    assert find_repository_root(str(tmp_path / "a" / "b")) == str(tmp_path)
    assert workstation_dir("/Users/me") == "/Users/me/.config/ssc-guardian"


def test_a_malformed_file_names_itself_in_its_skip() -> None:
    said = "deny entry 'requests' does not name its ecosystem (pypi: or github-actions:)"
    with (
        refuses("settings.does-not-name-ecosystem-pypi"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match=re.escape(f"/repo/.ssc-guardian.toml: {said}") + r"\Z") as caught,
    ):
        _layer('deny = ["requests"]\n')
    skip = caught.value.skip(Ecosystem.GITHUB_ACTIONS)
    assert (skip.place, skip.reason, skip.in_scope) == ("/repo/.ssc-guardian.toml", SkipReason.CHECK_ERROR, True)
    assert skip.detail is not None and "does not name its ecosystem" in skip.detail
    assert ConfigFileError("not a path", "x").skip(None).place is None


def test_a_fifo_or_device_in_place_of_a_settings_file_is_refused(tmp_path: Path) -> None:
    fifo = tmp_path / ".ssc-guardian.toml"
    os.mkfifo(fifo)
    for path in (str(fifo), "/dev/null"):
        with (
            refuses("settings.not-regular-file"),
            pytest.raises(ConfigFileError, match=re.escape(f"{path}: is not a regular file") + r"\Z"),
        ):
            load_settings(path, kind=FileKind.REPOSITORY)


def test_a_symlink_to_a_missing_file_is_refused_not_absent(tmp_path: Path) -> None:
    link = tmp_path / "config.toml"
    link.symlink_to(tmp_path / "unmounted" / "config.toml")
    said = "is reached through a symlink to a missing file or folder"
    with (
        refuses("settings.reached-through-symlink-missing-file"),
        pytest.raises(ConfigFileError, match=re.escape(f"{link}: {said}") + r"\Z"),
    ):
        load_settings(str(link), kind=FileKind.WORKSTATION)
    # So is a settings folder that is a symlink to a missing folder.
    home = tmp_path / "home"
    (home / ".config").mkdir(parents=True)
    (home / ".config" / "ssc-guardian").symlink_to(tmp_path / "unmounted-volume")
    config = home / ".config" / "ssc-guardian" / "config.toml"
    with (
        refuses("settings.reached-through-symlink-missing-file"),
        pytest.raises(ConfigFileError, match=re.escape(f"{config}: {said}") + r"\Z"),
    ):
        workstation_settings(home=str(home))
    assert workstation_settings(home=str(tmp_path / "no-such-home")).layers == ()  # truly absent


@pytest.mark.parametrize(
    ("text", "said", "site"),
    [
        ("rules = 5\n", r"\[rules\] is not a table", refuses("settings.not-table")),
        ("acknowledgment = 5\n", "acknowledgment is not a list of tables", refuses("settings.not-list-tables")),
        ("acknowledgment = [1]\n", "acknowledgment is not a list of tables", refuses("settings.not-list-tables")),
        ('[rules]\n"github-actions:actions/checkout" = {}\n', "sets nothing", refuses("settings.sets-nothing")),
    ],
)
def test_an_entry_of_the_wrong_shape_is_malformed(text: str, said: str, site: Refuses) -> None:
    with site, refuses("settings.malformed-entry"), pytest.raises(ConfigFileError, match=said):
        _layer(text)


def test_a_venv_folder_that_fails_the_path_grammar_is_malformed() -> None:
    # Refused before its value is read (#255): the value is never resolved or grammar-checked.
    with (
        refuses("settings.malformed-entry"),
        refuses("settings.scope-refused"),
        pytest.raises(ConfigFileError, match=re.escape("line 3: scope.venv_folders is no longer read")),
    ):
        _workstation('[scope]\nvenv_folders = ["/Users/me/odd#dir"]\n')


@pytest.mark.parametrize(
    ("text", "line"),
    [
        # The owner's file at #255: a comment, [scope] on line 3, venv_folders on line 4.
        ('format = 1\n# my settings\n[scope]\nvenv_folders = ["~/projects"]\n', 4),
        ('format = 1\nscope = { venv_folders = ["~/projects"] }\n[defaults]\ncooldown_days = 30\n', 2),
        ('format = 1\nscope.venv_folders = ["~/projects"]\n', 2),
        ("format = 1\n[scope]\n  venv_folders = []  # none\n", 3),
        ("format = 1\n[scope]\n", 2),  # an empty table names no key: its header line
    ],
)
def test_venv_folders_is_refused_with_a_path_hint(tmp_path: Path, text: str, line: int) -> None:
    # Error path (#255): a config.toml still holding [scope] venv_folders is malformed (exit 2),
    # never ignored: the message names its line and says to pass --path instead. Reading it
    # changes nothing on disk.
    folder = tmp_path / ".config" / "ssc-guardian"
    folder.mkdir(parents=True)
    config = folder / "config.toml"
    config.write_text(text)
    before = config.read_bytes(), config.stat().st_mtime_ns
    said = "[scope] is no longer read" if "venv_folders" not in text else "scope.venv_folders is no longer read"
    with (
        refuses("settings.malformed-entry"),
        refuses("settings.scope-refused"),
        pytest.raises(ConfigFileError) as raised,
    ):
        workstation_settings(home=str(tmp_path))
    message = str(raised.value)
    assert message.startswith(f"{config}: line {line}: {said}")
    assert "pass --path PATH (repeatable)" in message
    assert raised.value.skip(Ecosystem.PYPI).in_scope  # an unfinished check (exit 2), never a pass
    assert (config.read_bytes(), config.stat().st_mtime_ns) == before


def test_settings_duplicate_acknowledgment_is_malformed() -> None:
    # One repository in two spellings: a silent second entry could carry another ID.
    first = '[[acknowledgment]]\nrepository = "o/r"\nrepository_id = 1\ndate = 2026-11-03\n'
    second = '[[acknowledgment]]\nrepository = "O/R"\nrepository_id = 2\ndate = 2026-11-03\n'
    with (
        refuses("settings.acknowledgment-repeats-repository"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match="acknowledgment 2 repeats repository O/R"),
    ):
        _layer(first + second)


def test_settings_duplicate_start_date_is_malformed() -> None:
    sha = "a" * 40
    first = f'[[start_date]]\naction = "o/r"\nsha = "{sha}"\ndate = 2026-11-03\n'
    second = f'[[start_date]]\naction = "O/R"\nsha = "{sha}"\ndate = 2026-11-03\n'
    with (
        refuses("settings.malformed-entry"),
        refuses("settings.start-date-repeats"),
        pytest.raises(ConfigFileError, match="start_date 2 repeats O/R@"),
    ):
        _layer(first + second)


@pytest.mark.parametrize("missing", ["action", "sha", "date"])
def test_settings_start_date_missing_a_key_is_malformed(missing: str) -> None:
    keys = {"action": '"o/r"', "sha": f'"{"a" * 40}"', "date": "2026-11-03"}
    entry = "".join(f"{key} = {value}\n" for key, value in keys.items() if key != missing)
    with (
        refuses("settings.start-date-missing-key"),
        pytest.raises(ConfigFileError, match=f"start_date 1 has no {missing}" + r"\Z"),
    ):
        _layer("[[start_date]]\n" + entry)


def test_acknowledgment_that_does_not_read_back_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The appended block always parses, so only a stand-in reader reaches this self-check.
    real = settings_module.parse_settings
    monkeypatch.setattr(settings_module, "parse_settings", lambda *a, **k: replace(real(*a, **k), acknowledgments=()))
    path = tmp_path / ".ssc-guardian.toml"
    said = f"{path}: the appended acknowledgment did not read back"
    with (
        refuses("settings.appended-acknowledgment-did-not-read"),
        pytest.raises(ConfigFileError, match=re.escape(said) + r"\Z"),
    ):
        append_acknowledgment(str(path), Acknowledgment("o/r", 1, date(2026, 11, 3)))
    assert not path.exists()
