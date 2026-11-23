# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Result model and exit aggregator: 1 wins over 2, skipped is never clean, stable IDs (issue #2)."""

from __future__ import annotations

import asyncio
import io
import json
import re
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import date, datetime
from typing import Any, cast

import pytest

from ssc_guardian.cli import Request, main
from ssc_guardian.findings import (
    Checked,
    Collector,
    DuplicateFindingIdError,
    Ecosystem,
    ExitCode,
    Finding,
    FindingField,
    IncompleteCheckError,
    Level,
    LimitName,
    Option,
    OptionKind,
    OverrideCategory,
    OverrideRecord,
    Result,
    Rule,
    Scope,
    Skip,
    SkipReason,
    Verb,
    install_command,
    make_finding,
    malformed,
    malformed_from,
    pin_command,
    protect_command,
)
from ssc_guardian.grammars import Field, MalformedValueError, check
from ssc_guardian.plugin import Item
from ssc_guardian.yaml_subset import UnsupportedYamlError
from tests.refusal_sites import refuses
from tests.samples import VENV, full_result

pytestmark = pytest.mark.unit

GHA = Ecosystem.GITHUB_ACTIONS
# Plain strings where enum members belong: what a coding mistake, never outside data, produces.
_not_a_label: Any = [Verb.OVERRIDE_ADD]
_not_a_rule: Any = "cooldown"
_not_a_reason: Any = "filtered"
_not_an_ecosystem: Any = "pypi"
_not_a_kind: Any = "remove"
_not_a_verb: Any = "check"


def _violation() -> Finding:
    return make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4")


def test_exit_one_wins_over_two() -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        collector.findings.append(make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="a", version="1"))
    with collector.check(GHA, "/repo"):
        raise IncompleteCheckError(SkipReason.RATE_LIMIT)
    result = collector.result()
    assert result.exit_code is ExitCode.VIOLATION
    assert [f.rule for f in result.findings] == [Rule.COOLDOWN]
    assert [(s.ecosystem, s.reason) for s in result.skipped] == [(GHA, SkipReason.RATE_LIMIT)]
    assert result.summary.violations == 1
    assert result.summary.skipped_in_scope == 1


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyError("x"), OSError(13, "denied"), ValueError()])
def test_failed_check_never_exits_zero(error: Exception) -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        pass
    with collector.check(GHA, "/repo"):
        raise error
    result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert result.exit_code is not ExitCode.RULES_MET
    skip = result.skipped[0]
    assert (skip.reason, skip.in_scope, skip.detail) == (SkipReason.CHECK_ERROR, True, type(error).__name__)
    assert [c.ecosystem for c in result.checked] == [Ecosystem.PYPI]  # the failed check is not "checked"


def test_failed_check_keeps_findings_it_made() -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        collector.findings.append(make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="a", version="1"))
        raise RuntimeError
    assert collector.result().exit_code is ExitCode.VIOLATION


@pytest.mark.parametrize("reason", [r for r in SkipReason if r.in_scope])
def test_in_scope_skip_exits_two_and_is_never_clean(reason: SkipReason) -> None:
    result = Result(Verb.CHECK, skipped=(Skip(Ecosystem.PYPI, VENV, reason),))
    assert result.exit_code is ExitCode.INCOMPLETE
    # Warnings and notices alongside do not turn it into "all rules met".
    notices = (make_finding(Rule.DEGRADED_FEED, Ecosystem.PYPI), make_finding(Rule.HIDDEN_PIP, Ecosystem.PYPI))
    assert Result(Verb.CHECK, findings=notices, skipped=result.skipped).exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize("reason", [r for r in SkipReason if not r.in_scope])
def test_out_of_scope_skip_does_not_change_exit_code(reason: SkipReason) -> None:
    skip = Skip(GHA, None, reason)
    assert Result(Verb.CHECK, skipped=(skip,)).exit_code is ExitCode.RULES_MET
    assert Result(Verb.CHECK, findings=(_violation(),), skipped=(skip,)).exit_code is ExitCode.VIOLATION
    in_scope = Skip(Ecosystem.PYPI, VENV, SkipReason.FEED_FAILURE)
    assert Result(Verb.CHECK, skipped=(skip, in_scope)).exit_code is ExitCode.INCOMPLETE
    assert Result(Verb.CHECK, skipped=(skip,)).summary.skipped_out_of_scope == 1


def test_out_of_scope_reasons_are_exactly_the_four() -> None:
    # #282: the out-of-scope set is the contract table's right column (docs/contracts.md); every
    # other reason, including any added later, is in scope, so a place not checked is never clean.
    out_of_scope = {"filtered", "later-release", "deeper-than-one-level", "local-install"}
    assert {r.value for r in SkipReason if not r.in_scope} == out_of_scope
    assert all(r.in_scope for r in SkipReason if r.value not in out_of_scope)


def test_no_default_scope_reason() -> None:
    # #282: no command can emit `default-scope` since #255 removed the default scope.
    with pytest.raises(ValueError, match="default-scope"):
        SkipReason("default-scope")
    assert not hasattr(SkipReason, "DEFAULT_SCOPE")


@pytest.mark.parametrize("reason", [r for r in SkipReason if not r.in_scope])
def test_a_failure_cannot_be_reported_out_of_scope(reason: SkipReason) -> None:
    with pytest.raises(ValueError, match="out-of-scope"):
        IncompleteCheckError(reason)


@pytest.mark.parametrize("detail", [None, "my-tool 0.1"])
@pytest.mark.parametrize("reason", [r for r in SkipReason if not r.in_scope])
def test_a_failure_with_or_without_a_detail_cannot_be_reported_out_of_scope(
    reason: SkipReason, detail: str | None
) -> None:
    with pytest.raises(ValueError, match="out-of-scope"):
        IncompleteCheckError(reason, detail=detail)


def test_incomplete_check_error_keeps_its_detail() -> None:
    # Issue #298: the detail survives to the in-scope skip, text only; the message stays the reason.
    error = IncompleteCheckError(SkipReason.UNKNOWN_AGE, detail="my-tool 0.1")
    assert (str(error), error.skip_detail) == ("unknown-age", "my-tool 0.1")
    assert IncompleteCheckError(SkipReason.UNKNOWN_AGE).skip_detail is None
    for raised, expected in ((error, "my-tool 0.1"), (IncompleteCheckError(SkipReason.UNKNOWN_AGE), None)):
        collector = Collector(Verb.CHECK)
        with collector.check(Ecosystem.PYPI, VENV):
            raise raised
        (skip,) = collector.result().skipped
        assert (skip.reason, skip.place, skip.in_scope, skip.detail) == (SkipReason.UNKNOWN_AGE, VENV, True, expected)


def test_a_subclass_own_detail_never_reaches_the_skip() -> None:
    # UnsupportedYamlError keeps what it found in the file as ``detail``: file content, never a
    # skip's detail (#298's security AC).
    error = UnsupportedYamlError(".github/workflows/ci.yml", 4, "duplicate key", "\x1b[31mplanted")
    collector = Collector(Verb.CHECK)
    with collector.check(GHA, "/repo"):
        raise error
    assert [(s.reason, s.detail) for s in collector.result().skipped] == [(SkipReason.UNSUPPORTED_YAML, None)]


class _RaisingDetailError(IncompleteCheckError):
    @property
    def skip_detail(self) -> str:
        raise RuntimeError("detail unavailable")

    @skip_detail.setter
    def skip_detail(self, value: object) -> None:
        pass


def _detail_never_set() -> IncompleteCheckError:
    error = IncompleteCheckError(SkipReason.UNKNOWN_AGE)
    del error.skip_detail
    return error


def _detail_not_a_string() -> IncompleteCheckError:
    error = IncompleteCheckError(SkipReason.UNKNOWN_AGE)
    error.skip_detail = cast(Any, 42)
    return error


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_detail_never_set, id="never-set"),
        pytest.param(lambda: _RaisingDetailError(SkipReason.UNKNOWN_AGE), id="raises"),
        pytest.param(_detail_not_a_string, id="not-a-string"),
    ],
)
def test_an_unreadable_detail_leaves_the_skip_without_one(build: Callable[[], IncompleteCheckError]) -> None:
    # Read like the reason (_reason_of): a bad detail must not let the failure escape the collector.
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        raise build()
    assert [(s.reason, s.detail) for s in collector.result().skipped] == [(SkipReason.UNKNOWN_AGE, None)]


def test_warnings_and_notices_never_fail() -> None:
    quiet = [r for r in Rule if r.level is not Level.VIOLATION]
    assert quiet  # the rule set has warnings and notices
    findings = tuple(make_finding(r, Ecosystem.PYPI) for r in quiet)
    assert Result(Verb.CHECK, findings=findings).exit_code is ExitCode.RULES_MET


def test_finding_id_is_stable_on_re_run() -> None:
    first = [f.id for f in full_result().findings]
    second = [f.id for f in full_result().findings]
    assert first == second
    assert len(set(first)) == len(first)
    assert all(len(i) == 32 and set(i) <= set("0123456789abcdef") for i in first)
    # The ID is the rule + place + ecosystem + item + version, nothing else.
    a = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4")
    b = make_finding(
        Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4", evidence=["CVE-2024-35195"]
    )
    assert a.id == b.id
    for changed in (
        make_finding(Rule.COMPROMISE, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4"),
        make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place="/other", item="requests", version="2.32.4"),
        make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="urllib3", version="2.32.4"),
        make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.5"),
    ):
        assert changed.id != a.id


def test_finding_id_golden_value() -> None:
    # Pinned so a change to the frozen ID formula fails here, not only across two runs.
    finding = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4")
    assert finding.id == "189761a8f6a79ec3b0361a8c85edc50b"


@pytest.mark.parametrize(
    ("ecosystem", "spellings", "version"),
    [
        (Ecosystem.PYPI, ["requests", "Requests", "REQUESTS"], "2.32.4"),
        (Ecosystem.PYPI, ["zope.interface", "zope-interface", "Zope_Interface", "zope--interface"], "7.1"),
        (Ecosystem.GITHUB_ACTIONS, ["actions/checkout", "Actions/Checkout", "ACTIONS/CHECKOUT"], "v4.2.2"),
        (Ecosystem.GITHUB_ACTIONS, ["github/codeql-action/init", "GitHub/CodeQL-Action/init"], "v3"),
    ],
)
def test_equivalent_name_spellings_share_one_id(ecosystem: Ecosystem, spellings: list[str], version: str) -> None:
    # D18: one package or repository under two spellings is one finding, so one ID.
    ids = {make_finding(Rule.COOLDOWN, ecosystem, place=VENV, item=s, version=version).id for s in spellings}
    assert len(ids) == 1
    # The finding still shows the name as found.
    assert make_finding(Rule.COOLDOWN, ecosystem, place=VENV, item=spellings[1], version=version).item == spellings[1]


@pytest.mark.parametrize(
    "spellings",
    [
        ["1.0", "1.0.0", "v1.0", "1", "1.0.0.0"],
        ["2.0rc1", "2.0.0RC1", "2.0c1", "2.0-rc.1", "2.0pre1"],
        ["1.0.post1", "1.0-1", "1.0.0-post1", "1.0.r1"],
        ["1.0.dev0", "1.0dev", "1.0.0.dev0"],
        ["0!1.0", "1.0.0"],
        ["1.0+ubuntu.1", "1.0.0+UBUNTU-1", "1+ubuntu_01"],
    ],
)
def test_equivalent_version_spellings_share_one_id(spellings: list[str]) -> None:
    # D18: PEP 440 says these are one version, so they are one finding with one ID.
    ids = {make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version=v).id for v in spellings}
    assert len(ids) == 1
    # The finding still shows the version as found.
    shown = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version=spellings[1]).version
    assert shown == spellings[1]


@pytest.mark.parametrize(
    ("first", "second"),
    [("1.0", "1.0.1"), ("1.0", "1.0rc1"), ("1.0", "1.0.post1"), ("1.0", "1.0+local"), ("1.0", "1!1.0")],
)
def test_different_versions_keep_different_ids(first: str, second: str) -> None:
    def make(v: str) -> Finding:
        return make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version=v)

    assert make(first).id != make(second).id


def test_git_ref_is_hashed_as_given() -> None:
    # Only PyPI versions are normalized: "v1.0" and "1.0" are two different Git refs.
    a = make_finding(Rule.MOVING_REFERENCE, GHA, place=VENV, item="actions/checkout", version="v1.0")
    b = make_finding(Rule.MOVING_REFERENCE, GHA, place=VENV, item="actions/checkout", version="1.0")
    assert a.id != b.id


def test_one_version_two_spellings_is_one_finding_or_refused() -> None:
    # Two spellings of one version share an ID but are not equal findings, so a handler must
    # merge them; one that does not makes the result refused (exit 2), never two findings.
    a = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="1.0")
    b = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="1.0.0")
    with pytest.raises(ValueError, match="share one ID"):
        Result(Verb.CHECK, findings=(a, b))


@pytest.mark.parametrize(
    ("ecosystem", "first", "second"),
    [
        # A path inside a repository is case-sensitive: two different actions.
        (Ecosystem.GITHUB_ACTIONS, ("github/codeql-action/init", "v3"), ("github/codeql-action/Init", "v3")),
        # A Git ref is case-sensitive: two different references.
        (Ecosystem.GITHUB_ACTIONS, ("actions/checkout", "v4"), ("actions/checkout", "V4")),
        (Ecosystem.PYPI, ("requests", "2.32.4"), ("requests-oauthlib", "2.32.4")),
    ],
)
def test_different_names_keep_different_ids(
    ecosystem: Ecosystem, first: tuple[str, str], second: tuple[str, str]
) -> None:
    a = make_finding(Rule.COOLDOWN, ecosystem, place=VENV, item=first[0], version=first[1])
    b = make_finding(Rule.COOLDOWN, ecosystem, place=VENV, item=second[0], version=second[1])
    assert a.id != b.id


def test_sys_exit_inside_a_check_is_an_unfinished_check() -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        sys.exit(0)
    result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.reason, s.detail) for s in result.skipped] == [(SkipReason.CHECK_ERROR, "SystemExit")]


@pytest.mark.parametrize("error", [asyncio.CancelledError(), GeneratorExit()])
def test_base_exception_inside_a_check_is_an_unfinished_check(error: BaseException) -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        raise error
    assert collector.result().exit_code is ExitCode.INCOMPLETE


def test_malformed_non_finding_field_is_an_unfinished_check() -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        check(Field.DATE, "2026-13-01")
    result = collector.result()
    assert result.findings == ()
    assert result.exit_code is ExitCode.INCOMPLETE


def test_malformed_raw_value_is_stable_text() -> None:
    first = malformed(FindingField.ITEM, object(), ecosystem=Ecosystem.PYPI)
    second = malformed(FindingField.ITEM, object(), ecosystem=Ecosystem.PYPI)
    assert first.malformed_value == "<object>"
    assert first.id == second.id
    assert malformed(FindingField.ITEM, 7, ecosystem=Ecosystem.PYPI).malformed_value == "7"


def test_result_freezes_its_lists() -> None:
    finding = _violation()
    one_shot: Any = iter([finding])  # what an untyped caller could pass
    result = Result(Verb.CHECK, findings=one_shot)
    assert result.findings == (finding,)
    assert result.summary.violations == 1
    assert result.exit_code is ExitCode.VIOLATION


def test_datetime_is_not_a_date() -> None:
    with pytest.raises(TypeError, match=re.escape("a date field holds a datetime.date, not a datetime")):
        Option(OptionKind.REPLACE, item="requests", version="2.32.4", eligible_on=datetime(2026, 11, 20, 1, 2, 3))
    with pytest.raises(TypeError, match=re.escape("a required date field holds a datetime.date")):
        replace(BASE_OVERRIDE, expiry=datetime(2026, 12, 1, 0, 0))


def test_forged_enum_class_is_refused() -> None:
    # #26 item 8: each claims an enum through __class__, which isinstance trusts, and its fake
    # value would reach JSON.
    reason: Any = type("_ForgedReason", (), {"__class__": SkipReason, "value": "pass", "in_scope": False})()
    rule: Any = type("_ForgedRule", (), {"__class__": Rule, "value": "not-a-rule"})()
    assert isinstance(reason, SkipReason) and isinstance(rule, Rule)
    with pytest.raises(TypeError, match="expected a SkipReason, got _ForgedReason"):
        Skip(Ecosystem.PYPI, None, reason)
    with pytest.raises(TypeError, match="expected a Rule, got _ForgedRule"):
        Finding(rule, Ecosystem.PYPI)


def test_lists_given_to_options_and_findings_are_frozen() -> None:
    command: Any = list(install_command(VENV, "requests", "2.32.3"))
    option = Option(OptionKind.REPLACE, item="requests", version="2.32.3", command=command)
    command[4] = "evil==1.0"
    assert option.command == install_command(VENV, "requests", "2.32.3")
    evidence: Any = ["CVE-2024-35195"]
    finding = Finding(Rule.KNOWN_VULNERABILITY, Ecosystem.PYPI, evidence=evidence)
    evidence.append("not an advisory")
    assert finding.evidence == ("CVE-2024-35195",)


def test_check_for_a_malformed_place_is_recorded_before_it_runs() -> None:
    collector = Collector(Verb.CHECK)
    ran: list[bool] = []
    with collector.check(Ecosystem.PYPI, "relative/place"):
        ran.append(True)
        raise RuntimeError("anything the body raises is already accounted for")
    result = collector.result()
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.malformed_field, finding.place) == (FindingField.PLACE, None)
    assert [(s.place, s.reason) for s in result.skipped] == [(None, SkipReason.CHECK_ERROR)]
    assert result.checked == ()


@pytest.mark.parametrize("ignores_flag", [False, True])
def test_malformed_place_body_can_skip(ignores_flag: bool) -> None:
    # #26 item 1: the body is told the place is malformed; one that works anyway adds nothing.
    collector = Collector(Verb.CHECK)
    flags: list[bool] = []
    with collector.check(Ecosystem.PYPI, VENV) as ok:
        flags.append(ok)
    with collector.check(Ecosystem.PYPI, "relative/place") as ok:
        flags.append(ok)
        if ignores_flag:  # planted: findings, entries and a rewritten list for the bad place
            collector.findings.append(make_finding(Rule.DENY_LIST, Ecosystem.PYPI, place=VENV, item="x", version="1"))
            collector.checked.append(Checked(Ecosystem.PYPI, VENV))
            collector.skipped[:] = []
            collector.overrides_applied.append(BASE_OVERRIDE)
            collector.overrides_expired += [BASE_OVERRIDE]
    assert flags == [True, False]  # read outside the body, which swallows a failed assert
    result = collector.result()
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.malformed_field) == (Rule.MALFORMED_NAME, FindingField.PLACE)
    assert result.checked == (Checked(Ecosystem.PYPI, VENV),)
    assert [(s.place, s.reason, s.in_scope) for s in result.skipped] == [(None, SkipReason.CHECK_ERROR, True)]
    assert (result.overrides_applied, result.overrides_expired) == ((), ())


def test_check_guard_restores_a_reassigned_attribute() -> None:
    # #144 item 9: a body that ignores the flag and binds new lists to the collector's fields
    # (not a slice) must not drop the malformed-name violation and unfinished check recorded
    # for the bad place, nor leave what it planted.
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, "relative/place"):
        collector.findings = []
        collector.checked = [Checked(Ecosystem.PYPI, VENV)]
        collector.skipped = []
        collector.overrides_applied = [BASE_OVERRIDE]
        collector.overrides_expired = [BASE_OVERRIDE]
    result = collector.result()
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.malformed_field) == (Rule.MALFORMED_NAME, FindingField.PLACE)
    assert result.checked == ()
    assert [(s.place, s.reason, s.in_scope) for s in result.skipped] == [(None, SkipReason.CHECK_ERROR, True)]
    assert (result.overrides_applied, result.overrides_expired) == ((), ())


class _NoCheckError(IncompleteCheckError):
    def __init__(self) -> None:  # skips the base class's in-scope check on purpose
        Exception.__init__(self)
        self.reason = SkipReason.LATER_RELEASE


class _NoReasonError(IncompleteCheckError):
    def __init__(self) -> None:  # never sets a reason at all
        Exception.__init__(self)


class _RaisingReasonError(IncompleteCheckError):
    def __init__(self) -> None:
        Exception.__init__(self)

    def __getattribute__(self, name: str) -> Any:
        if name == "reason":
            raise RuntimeError("reason unavailable")
        return super().__getattribute__(name)


def test_out_of_scope_reason_smuggled_into_a_failure_is_in_scope() -> None:
    reassigned = IncompleteCheckError(SkipReason.FEED_FAILURE)
    reassigned.reason = SkipReason.LATER_RELEASE
    for error in (reassigned, _NoCheckError(), _NoReasonError(), _RaisingReasonError()):
        collector = Collector(Verb.CHECK)
        with collector.check(Ecosystem.PYPI, "/ok"):
            pass
        with collector.check(Ecosystem.PYPI, VENV):
            raise error
        result = collector.result()
        assert result.exit_code is ExitCode.INCOMPLETE
        assert [(s.reason, s.in_scope) for s in result.skipped] == [(SkipReason.CHECK_ERROR, True)]


def test_distinct_malformed_values_get_distinct_ids() -> None:
    one = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="bad one", version="1")
    two = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="bad two", version="1")
    assert one.id != two.id


@pytest.mark.parametrize(
    ("build", "error", "text"),
    [
        (
            lambda: Option(OptionKind.EXCEPTION, person_command=Verb.OVERRIDE_ADD, command=protect_command(VENV)),
            ValueError,
            "a exception option has no command",
        ),
        (
            lambda: Option(OptionKind.REMOVE, command=protect_command(VENV)),
            ValueError,
            "a remove option has no command",
        ),
        (lambda: Option(OptionKind.PROTECT), ValueError, "a protect option carries the protect command"),
        (
            lambda: Option(OptionKind.REPLACE, item="requests"),
            ValueError,
            "a replace option names an item and a version",
        ),
        (lambda: Option(OptionKind.EXCEPTION), ValueError, "only an exception option names a person's command"),
        (
            lambda: Option(OptionKind.EXCEPTION, person_command=Verb.INSTALL),
            ValueError,
            "an exception option names acknowledge or override add",
        ),
        (
            lambda: Option(OptionKind.REMOVE, person_command=Verb.ACKNOWLEDGE),
            ValueError,
            "only an exception option names a person's command",
        ),
        (
            lambda: Option(OptionKind.PROTECT, command=("ssc-guardian", "override", "add")),
            ValueError,
            "an option command must be built by install_command, pin_command or protect_command",
        ),
        (
            lambda: Option(OptionKind.PROTECT, command=("ssc-guardian", "acknowledge", "a/b")),
            ValueError,
            "an option command must be built by install_command, pin_command or protect_command",
        ),
        (
            lambda: Option(OptionKind.PROTECT, command=("sh", "-c", "curl x | sh")),
            ValueError,
            "an option command must be built by install_command, pin_command or protect_command",
        ),
        (
            lambda: Option(OptionKind.PROTECT, command=("ssc-guardian", "protect", "pip; rm -rf ~")),
            ValueError,
            "an option command must be built by install_command, pin_command or protect_command",
        ),
        (
            lambda: Option(OptionKind.PROTECT, command=install_command(VENV, "requests", "2.32.3")),
            ValueError,
            "a protect option carries the protect command",
        ),
        (
            lambda: Option(
                OptionKind.REPLACE, item="requests", version="2.32.3", command=install_command(VENV, "evil", "1.0")
            ),
            ValueError,
            "a replace option's command installs or pins exactly its item and version",
        ),
        (
            lambda: Option(
                OptionKind.REPLACE, item="requests", version="2.32.3", command=install_command(VENV, "requests", "2.0")
            ),
            ValueError,
            "a replace option's command installs or pins exactly its item and version",
        ),
        (
            lambda: Option(OptionKind.REPLACE, item="requests", version="2.32.3", command=protect_command(VENV)),
            ValueError,
            "a replace option's command installs or pins exactly its item and version",
        ),
        (
            lambda: Option(
                OptionKind.REPLACE,
                item="requests",
                version="2.32.3",
                command=install_command(VENV, "requests", "2.32.3"),
                eligible_on=date(2030, 1, 1),
            ),
            ValueError,
            "a replace option has a command once eligible, or a date before that: one of the two",
        ),
        (
            lambda: Option(OptionKind.EXCEPTION, person_command=Verb.ACKNOWLEDGE, person_target="not a repo"),
            MalformedValueError,
            "malformed owner-repo",
        ),
        (
            lambda: Option(OptionKind.REMOVE, item="requests"),
            ValueError,
            "a remove option names no item, version or date",
        ),
        (
            lambda: Option(OptionKind.REPLACE, item="requests", version="2.32.3"),
            ValueError,
            "a replace option has a command once eligible, or a date before that: one of the two",
        ),
        (
            lambda: Option(OptionKind.EXCEPTION, person_command=Verb.OVERRIDE_ADD, person_target="a/b"),
            ValueError,
            "acknowledge names its repository; override add takes no target",
        ),
        (
            lambda: Option(OptionKind.EXCEPTION, person_command=Verb.ACKNOWLEDGE),
            ValueError,
            "acknowledge names its repository; override add takes no target",
        ),
        (
            lambda: Option(OptionKind.PROTECT, command=protect_command(VENV), eligible_on=date(2030, 1, 1)),
            ValueError,
            "a protect option names no item, version or date",
        ),
    ],
)
def test_option_shapes_are_refused(build: Callable[[], object], error: type[Exception], text: str) -> None:
    with pytest.raises(error, match=re.escape(text)):
        build()


def test_replacement_command_matches_the_finding_ecosystem() -> None:
    pin = Option(
        OptionKind.REPLACE, item="actions/checkout", version="v4", command=pin_command("actions/checkout", "v4")
    )
    with pytest.raises(ValueError, match="pypi replacement uses install"):
        make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="1", options=[pin])
    ok = make_finding(Rule.MOVING_REFERENCE, GHA, item="actions/checkout", version="main", options=[pin])
    assert ok.options == (pin,)


def test_malformed_value_inside_a_check_is_a_violation() -> None:
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI, VENV):
        Item(Ecosystem.PYPI, "bad name", "1.0", VENV)
    result = collector.result()
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.malformed_field, finding.place) == (Rule.MALFORMED_NAME, FindingField.ITEM, VENV)
    assert finding.malformed_value == "bad name"
    assert [(s.reason, s.detail) for s in result.skipped] == [(SkipReason.CHECK_ERROR, "MalformedValueError")]
    assert result.checked == ()


@pytest.mark.parametrize(
    ("raised", "which"),
    [
        (MalformedValueError(Field.PATH, "/a/../b"), FindingField.PLACE),
        (MalformedValueError(Field.PEP440_VERSION, "latest"), FindingField.VERSION),
        (MalformedValueError(Field.SHA, "ABC"), FindingField.VERSION),
        (MalformedValueError(Field.ADVISORY_ID, "CVE-1"), FindingField.EVIDENCE),
        (MalformedValueError(Field.OWNER_REPO, "a b"), FindingField.ITEM),
    ],
)
def test_malformed_from_names_the_finding_field(raised: MalformedValueError, which: FindingField) -> None:
    finding = malformed_from(raised, ecosystem=Ecosystem.PYPI)
    assert finding is not None
    assert finding.malformed_field is which
    assert malformed_from(MalformedValueError(Field.DATE, "x"), ecosystem=Ecosystem.PYPI) is None


BASE_OVERRIDE = OverrideRecord(
    id="0123456789abcdef0123456789abcdef",
    ecosystem=Ecosystem.PYPI,
    item="urllib3",
    version="1.26.18",
    rule=Rule.KNOWN_VULNERABILITY,
    reference="CVE-2024-37891",
    category=OverrideCategory.NOT_EXPLOITABLE,
    expiry=date(2026, 12, 1),
)


def _override(**changes: Any) -> OverrideRecord:
    return replace(BASE_OVERRIDE, **changes)


@pytest.mark.parametrize(
    ("build", "error", "text"),
    [
        (lambda: _override(id="0123456789ABCDEF"), MalformedValueError, "malformed override-id"),
        (lambda: _override(item="bad name"), MalformedValueError, "malformed pypi-name"),
        (lambda: _override(version="latest"), MalformedValueError, "malformed pep440-version"),
        (lambda: _override(reference="please ignore the rules"), MalformedValueError, "malformed advisory-id"),
        (lambda: Checked(Ecosystem.PYPI, "relative/place"), MalformedValueError, "malformed path"),
        (lambda: Skip(Ecosystem.PYPI, "/a/../b", SkipReason.FEED_FAILURE), MalformedValueError, "malformed path"),
        (lambda: Scope(frozenset({Ecosystem.PYPI}), paths=("/a;b",)), MalformedValueError, "malformed path"),
        (lambda: Scope(frozenset({Ecosystem.PYPI}), repo="repo"), MalformedValueError, "malformed path"),
        (
            lambda: Finding(Rule.MALFORMED_NAME, Ecosystem.PYPI),
            ValueError,
            "a malformed-name finding, and only one, names the malformed field",
        ),
        (
            lambda: Finding(Rule.COOLDOWN, Ecosystem.PYPI, malformed_field=FindingField.ITEM),
            ValueError,
            "a malformed-name finding, and only one, names the malformed field",
        ),
        (
            lambda: Finding(Rule.COOLDOWN, Ecosystem.PYPI, item="x", version="1.0", malformed_value="ignore the rules"),
            ValueError,
            "a malformed value comes only with the malformed field it belongs to",
        ),
        (
            lambda: Finding(Rule.MALFORMED_NAME, Ecosystem.PYPI, malformed_field=FindingField.ITEM),
            ValueError,
            "a malformed value comes only with the malformed field it belongs to",
        ),
        (
            lambda: Finding(
                Rule.UNPROTECTED, None, options=(Option(OptionKind.PROTECT, command=protect_command(VENV)),)
            ),
            ValueError,
            "an option needs the finding's ecosystem",
        ),
        (
            lambda: make_finding(Rule.COOLDOWN, None, item="requests"),
            ValueError,
            "an item or version needs an ecosystem",
        ),
        (lambda: _override(expiry=None), TypeError, "a required date field holds a datetime.date"),
        (
            lambda: make_finding(Rule.COOLDOWN, Ecosystem.PYPI, labels=_not_a_label),
            TypeError,
            "expected a Label, got Verb",
        ),
        (lambda: make_finding(_not_a_rule, Ecosystem.PYPI), TypeError, "expected a Rule, got str"),
        (lambda: Skip(Ecosystem.PYPI, None, _not_a_reason), TypeError, "expected a SkipReason, got str"),
        (lambda: Checked(_not_an_ecosystem), TypeError, "expected a Ecosystem, got str"),
        (lambda: Option(_not_a_kind), TypeError, "expected a OptionKind, got str"),
        (
            lambda: make_finding(
                Rule.COOLDOWN,
                Ecosystem.PYPI,
                item="requests",
                version="1",
                options=[Option(OptionKind.EXCEPTION, person_command=Verb.ACKNOWLEDGE, person_target="a/b")],
            ),
            ValueError,
            "acknowledge accepts GitHub Action repositories only",
        ),
        (lambda: Result(_not_a_verb), TypeError, "expected a Verb, got str"),
        (
            lambda: make_finding(
                Rule.UNPROTECTED, GHA, options=[Option(OptionKind.PROTECT, command=protect_command(VENV))]
            ),
            ValueError,
            "protect fixes Python environments only",
        ),
    ],
)
def test_result_model_refuses_bad_values(build: Callable[[], object], error: type[Exception], text: str) -> None:
    with pytest.raises(error, match=re.escape(text)):
        build()


def test_limit_name_is_a_valid_override_reference() -> None:
    assert _override(reference=LimitName.NESTING_DEPTH.value).reference == "nesting-depth"


def test_fix_commands_are_built_from_checked_values() -> None:
    assert install_command(VENV, "requests", "2.32.3") == (
        "ssc-guardian",
        "install",
        "--venv",
        VENV,
        "requests==2.32.3",
    )
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed pypi-name"):
        install_command(VENV, "requests; rm -rf ~", "1.0")
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed path"):
        install_command("--index-url=https://evil.example", "requests", "1.0")


WORKFLOW = "/Users/dev/projects/app/.github/workflows/ci.yml"
OUTER_SHA = "0123456789abcdef0123456789abcdef01234567"


def _nested(*via: str) -> Finding:
    return make_finding(
        Rule.NESTED_MOVING_REFERENCE,
        Ecosystem.GITHUB_ACTIONS,
        place=WORKFLOW,
        item="someone/inner-action",
        version="v1",
        via=via,
    )


def test_one_inner_reference_through_two_outer_actions_gets_two_ids() -> None:
    # D14: two problems, two fixes, two overrides; one ID would let fixing one hide the other.
    first = _nested(f"someone/outer-a@{OUTER_SHA}")
    second = _nested(f"someone/outer-b@{OUTER_SHA}")
    assert first.id != second.id
    assert _nested().id not in {first.id, second.id}
    # The chain's Actions use the D18 spelling; their refs stay as written.
    assert _nested(f"Someone/Outer-A@{OUTER_SHA}").id == first.id
    assert _nested("someone/outer-a@v4").id != _nested("someone/outer-a@V4").id


@pytest.mark.parametrize("step", ["someone/outer", "someone/outer@", "@v1", "someone/outer@v1 --yes", "-x/y@v1"])
def test_malformed_via_step_is_a_malformed_name_violation(step: str) -> None:
    finding = _nested(step)
    assert finding.rule is Rule.MALFORMED_NAME
    assert finding.malformed_field is FindingField.VIA
    assert finding.via == ()


def test_via_is_only_for_github_actions() -> None:
    with pytest.raises(ValueError, match="outer Actions"):
        Finding(Rule.COOLDOWN, Ecosystem.PYPI, VENV, "requests", "2.32.4", via=(f"a/b@{OUTER_SHA}",))


def test_a_result_with_two_findings_sharing_an_id_is_refused() -> None:
    # D14: a duplicate ID is refused outright rather than merged silently.
    finding = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4")
    twin = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="Requests", version="2.32.4")
    with pytest.raises(ValueError, match="share one ID"):
        Result(Verb.CHECK, findings=(finding, twin))
    assert Result(Verb.CHECK, findings=(finding,)).findings == (finding,)


def test_a_handler_whose_result_shares_an_id_names_the_duplicate_and_exits_two() -> None:
    # RR4 (#234): the backstop is its own refusal, reached through a command's handler. It names
    # the shared ID, its type is what the unfinished check shows, and the run exits 2, not 0 or 1.
    finding = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="requests", version="2.32.4")
    twin = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=VENV, item="Requests", version="2.32.4")
    assert finding.id == twin.id and finding != twin

    def handler(request: Request) -> Result:
        return Result(Verb.CHECK, findings=(finding, twin))

    with pytest.raises(DuplicateFindingIdError) as raised:
        handler(Request(Verb.CHECK))
    assert str(raised.value) == f"two different findings share one ID: {finding.id}"
    assert isinstance(raised.value, ValueError) and raised.value.reason is SkipReason.CHECK_ERROR
    for argv in (["check", "--envs", "--path", VENV, "--json"], ["check", "--envs", "--path", VENV]):
        out, err = io.StringIO(), io.StringIO()
        with refuses("findings.duplicate-finding-id"), refuses("cli.handler-failed"):
            code = main(argv, handlers={Verb.CHECK: handler}, stdout=out, stderr=err, environ={})
        assert code == 2, err.getvalue()
        if "--json" in argv:
            doc = json.loads(out.getvalue())
            assert doc["exit_code"] == 2 and doc["findings"] == []
            # The failed handler's own skip, and the area it left unchecked.
            in_scope = [(s["ecosystem"], s["reason"]) for s in doc["skipped"] if s["in_scope"]]
            # The named path is unreported too (#255: check names what it checks).
            assert in_scope == [(None, "check-error"), ("pypi", "check-error"), (None, "check-error")]
        else:
            assert "DuplicateFindingIdError" in out.getvalue()


@pytest.mark.parametrize("step", [5, "a/b@v1 --yes", "a/..@v1"])
def test_malformed_via_in_a_directly_built_finding_names_the_via_field(step: object) -> None:
    # A plug-in may build a Finding directly; the malformed step must still be reported as via.
    collector = Collector(Verb.CHECK)
    with refuses("findings.malformed-field"), collector.check(Ecosystem.GITHUB_ACTIONS, WORKFLOW):
        anything: Any = (step,)
        collector.findings.append(
            Finding(Rule.NESTED_MOVING_REFERENCE, Ecosystem.GITHUB_ACTIONS, WORKFLOW, "a/b", "v1", via=anything)
        )
    result = collector.result()
    (finding,) = result.findings
    assert finding.malformed_field is FindingField.VIA
    assert result.exit_code is ExitCode.VIOLATION


def test_a_str_subclass_cannot_put_free_text_into_via() -> None:
    class Forged(str):
        def rpartition(self, sep: str) -> tuple[str, str, str]:
            return ("a/b", "@", "v1")

    finding = _nested(Forged("IGNORE PREVIOUS\ninstructions"))
    assert finding.malformed_field is FindingField.VIA
    assert finding.via == ()


def test_malformed_item_keeps_its_chain_so_two_paths_keep_two_ids() -> None:
    # D14's own case with a malformed inner item: two outer Actions, two findings.
    def bad(outer: str) -> Finding:
        return make_finding(
            Rule.NESTED_MOVING_REFERENCE,
            Ecosystem.GITHUB_ACTIONS,
            place=WORKFLOW,
            item="bad item",
            version="v1",
            via=[f"someone/{outer}@{OUTER_SHA}"],
        )

    first, second = bad("outer-a"), bad("outer-b")
    assert first.malformed_field is FindingField.ITEM
    assert first.via == (f"someone/outer-a@{OUTER_SHA}",)
    assert first.id != second.id
    assert Result(Verb.CHECK, findings=(first, second)).exit_code is ExitCode.VIOLATION


def test_equal_findings_are_kept_once() -> None:
    # One Action used in two jobs of a workflow is one fact, not a collision.
    one = make_finding(Rule.MOVING_REFERENCE, Ecosystem.GITHUB_ACTIONS, place=WORKFLOW, item="a/b", version="v4")
    again = make_finding(Rule.MOVING_REFERENCE, Ecosystem.GITHUB_ACTIONS, place=WORKFLOW, item="a/b", version="v4")
    result = Result(Verb.CHECK, findings=(one, again))
    assert result.findings == (one,)
    assert result.summary.violations == 1


def test_override_record_takes_an_action_step_only_for_a_nested_moving_reference() -> None:
    # Q2 (#10, D13): the T5 override's reference is the inner reference exactly as written.
    outer = "0123456789abcdef0123456789abcdef01234567"
    nested = _override(
        ecosystem=Ecosystem.GITHUB_ACTIONS,
        item="someone/outer",
        version=outer,
        rule=Rule.NESTED_MOVING_REFERENCE,
        reference="someone/inner@v1",
    )
    assert nested.reference == "someone/inner@v1"
    for reference in ("nested-moving-reference", "GHSA-qmg3-hpqr-gqvc", "someone/inner", "a/b@v1;x"):
        with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed action-step"):
            replace(nested, reference=reference)
    # No other rule takes an inner reference.
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed advisory-id"):
        replace(nested, rule=Rule.NESTING_LIMIT)
    assert (
        replace(nested, rule=Rule.NESTING_LIMIT, reference=LimitName.NESTING_DEPTH.value).reference == "nesting-depth"
    )
