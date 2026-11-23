# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The ``refuses`` helper and the site recorder behind it (issues #117, #148, #164)."""

from __future__ import annotations

import dataclasses
import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest

from ssc_guardian import findings
from ssc_guardian.cli import main
from ssc_guardian.commands import install
from ssc_guardian.feeds import kev
from ssc_guardian.findings import (
    Collector,
    Ecosystem,
    Finding,
    IncompleteCheckError,
    Result,
    Rule,
    Skip,
    SkipReason,
    Verb,
    make_finding,
)
from ssc_guardian.grammars import Field, MalformedValueError, check
from ssc_guardian.net import FeedError
from ssc_guardian.render import ToolInfo, to_json, to_text
from tests.refusal_sites import Refuses, refuses

EMPTY_SCOPE = ["check", "--envs", "--ecosystem", "github-actions"]


def _run(argv: list[str], **kwargs: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err, environ={}, **kwargs)
    return code, out.getvalue(), err.getvalue()


def test_refuses_passes_when_the_named_site_fires() -> None:
    with refuses("cli.scope-filters-leave-nothing-check") as block:
        code, out, err = _run(EMPTY_SCOPE)
    assert code == 2
    assert out == ""
    assert err == "ssc-guardian: the scope and filters leave nothing to check\n"
    assert block.fired == ("cli.scope-filters-leave-nothing-check", "cli.usage-error")


def test_refuses_fails_when_a_different_site_fires() -> None:
    with (
        pytest.raises(AssertionError, match=r"'inline\.not-this-one' did not fire; sites that fired: grammars\."),
        refuses("inline.not-this-one"),
        pytest.raises(MalformedValueError, match="malformed sha"),
    ):
        check(Field.SHA, "not a sha")


def test_refuses_fails_when_no_refusal_fires() -> None:
    with (
        pytest.raises(AssertionError, match=r"'inline\.never' did not fire; sites that fired: none"),
        refuses("inline.never"),
    ):
        assert check(Field.SHA, "a" * 40) == "a" * 40
    # A refusal the block raises, but that never named this site, fails as well: the
    # AssertionError replaces it, so the test's own pytest.raises does not see a pass.
    with pytest.raises(AssertionError, match="did not fire"), refuses("inline.never"):
        raise ValueError("not a refusal of Guardian's")


def test_recorder_is_inert_outside_refuses() -> None:
    assert findings._SITES.get() is None
    exc = IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.outside")
    assert findings._SITES.get() is None
    # The site changes nothing a person or a program can read.
    assert exc.args == ("check-error",) and str(exc) == "check-error"
    assert "inline.outside" not in repr(exc)
    value = MalformedValueError(Field.SHA, "x", site="inline.outside")
    assert value.args == ("malformed sha",) and value.value == "x"
    # The out-of-scope check still comes first, and records nothing.
    with refuses("inline.recorded") as block, pytest.raises(IncompleteCheckError):
        with pytest.raises(ValueError, match="out-of-scope reason"):
            IncompleteCheckError(SkipReason.FILTERED, site="inline.out-of-scope")
        raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.recorded")
    assert block.fired == ("inline.recorded",)
    assert findings._SITES.get() is None
    with block, pytest.raises(IncompleteCheckError):  # a block can run again, and starts empty
        raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.recorded")
    assert block.fired == ("inline.recorded",)
    # Blocks nest: the outer one sees what the inner one recorded.
    with refuses("inline.outer") as outer, pytest.raises(IncompleteCheckError):
        with refuses("inline.inner"), pytest.raises(IncompleteCheckError):
            raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.inner")
        raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.outer")
    assert outer.fired == ("inline.inner", "inline.outer")
    with pytest.raises(TypeError, match="one refusal site ID"):
        Refuses("")  # the class: a refuses("") literal would read as a site a test names


def test_refuses_sees_a_site_caught_inside_cli_main(tmp_path: Path) -> None:
    # The install handler's RefusedError is caught inside main and becomes an in-scope skip
    # and exit 2; the recorder still saw it built.
    err = io.StringIO()
    (tmp_path / "home").mkdir()
    handler = install.Install(home=str(tmp_path / "home"), environ={"PATH": ""}, stderr=err)
    with refuses("install.guardian-installs-into-venvs-only"):
        code, out, _ = _run(
            ["install", "--venv", str(tmp_path), "requests", "--json"], handlers={Verb.INSTALL: handler}
        )
    assert code == json.loads(out)["exit_code"] == 2
    assert "is not a venv: Guardian installs into venvs only" in err.getvalue()


# --- a refusal must reach the test, not only be built (issue #148) ----------------------


# Built with the class, not refuses(): an expected failure names no site for the coverage check,
# and is not a refuses block inside a catch-all.
KEV_SITE = "kev.kev-catalog-not-object"


class _NotAnObject:
    """A KEV catalog answer that is JSON but not an object."""

    def json(self) -> object:
        return ["not", "an", "object"]


class _KevClient:
    """Answers the KEV catalog request with :class:`_NotAnObject`; reaches no network."""

    def get(self, url: str, **_: object) -> _NotAnObject:
        assert url == kev.CATALOG_URL
        return _NotAnObject()


def _kev_swallows() -> kev.KevStatus:
    """The KEV reader on a catalog that is not an object: it builds the refusal
    ``kev.kev-catalog-not-object``, catches it and keeps only its text (``Kev.failure``)."""
    lookups = kev.Kev(cast(Any, _KevClient()))
    status = lookups.status({"CVE-2024-3094"})
    assert lookups.failure == "the KEV catalog is not an object"
    return status


def test_refuses_fails_when_the_refusal_was_swallowed() -> None:
    # The audit's synthetic case: the site is built inside the block, but Guardian's own code
    # caught the refusal, so it never reached the test or a result.
    with (
        pytest.raises(AssertionError, match=r"'kev\.kev-catalog-not-object' fired, but its refusal was swallowed"),
        Refuses(KEV_SITE) as block,
    ):
        assert _kev_swallows() is kev.KevStatus.UNAVAILABLE
    assert block.fired == ("kev.kev-catalog-not-object",)  # it fired: the old check passed here
    # The control: the same refusal raised to the test passes the block.
    with refuses("kev.kev-catalog-not-object"), pytest.raises(FeedError, match="not an object"):
        kev.parse_catalog(["not", "an", "object"])


def test_refuses_fails_when_another_refusal_ended_the_block() -> None:
    # The swallowed KEV refusal fired, and then a different refusal ended the block: the block
    # names the one that did, and fails.
    with (
        pytest.raises(AssertionError, match=r"swallowed: .* refusals that did: grammars\.malformed-value"),
        Refuses(KEV_SITE),
        pytest.raises(MalformedValueError, match="malformed sha"),
    ):
        _kev_swallows()
        check(Field.SHA, "not a sha")
    # The ending refusal's own block passes on the same run.
    with refuses("grammars.malformed-value") as ended, pytest.raises(MalformedValueError):
        _kev_swallows()
        check(Field.SHA, "not a sha")
    assert ended.fired == ("kev.kev-catalog-not-object", "grammars.malformed-value")


def test_a_refusal_turned_into_a_listed_skip_or_a_returned_one_reaches_the_test() -> None:
    # Collector.check lists the failed check: the refusal reached the result, even when the
    # Result is built after the block.
    collector = Collector(Verb.CHECK)
    with refuses("inline.listed"), collector.check(Ecosystem.PYPI):
        raise IncompleteCheckError(SkipReason.FEED_FAILURE, site="inline.listed")
    assert [s.reason for s in collector.result().skipped] == [SkipReason.FEED_FAILURE]
    # A skip a function returns to the test, which the test then holds, has reached it.
    with refuses("inline.returned"):
        problems = [Skip(None, None, SkipReason.CHECK_ERROR, site="inline.returned")]
    assert problems[0].in_scope
    # One built and dropped has not.
    with pytest.raises(AssertionError, match="swallowed"), refuses("inline.dropped"):
        Skip(None, None, SkipReason.CHECK_ERROR, site="inline.dropped")
    # An exit 2 set by hand is returned, so it reaches the result at once.
    with refuses("inline.exit"):
        code = findings.incomplete_exit(site="inline.exit")
    assert code == 2


def test_a_refusal_caught_and_passed_on_reaches_the_test_through_the_one_built_from_it() -> None:
    # A refusal built in the except clause of another stands for it.
    def pass_on() -> None:
        try:
            raise IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.first")
        except IncompleteCheckError:
            raise IncompleteCheckError(SkipReason.FEED_FAILURE, site="inline.second") from None

    with refuses("inline.first"), refuses("inline.second"), pytest.raises(IncompleteCheckError, match="feed"):
        pass_on()


def test_reach_tracking_is_idempotent_on_re_run() -> None:
    # The same run gives the same verdict every time, and leaves the recorder unset.
    outcomes = []
    for _ in range(2):
        try:
            with Refuses(KEV_SITE):
                _kev_swallows()
        except AssertionError as exc:
            outcomes.append(str(exc))
        assert findings._SITES.get() is None
    assert outcomes[0] == outcomes[1] and "swallowed" in outcomes[0]


# --- a violation finding names its site (issue #164) ------------------------------------

TOOL = ToolInfo("1.0.0")
PLACE = "/Users/dev/app/.venv"


def _cooldown(site: str) -> Finding:
    """A cooldown violation built at the planted ``site``."""
    return make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=PLACE, item="demo", version="2.0", site=site)


def test_refuses_names_a_finding_site_that_reached_the_result() -> None:
    # Rendered: the result the command returns lists the finding.
    with refuses("inline.rendered-finding") as block:
        text = to_json(Result(Verb.CHECK, findings=(_cooldown("inline.rendered-finding"),)), TOOL)
    assert json.loads(text)["exit_code"] == 1
    assert block.fired == ("inline.rendered-finding",)
    # Held: the test keeps the result a function returned.
    with refuses("inline.held-finding"):
        result = Result(Verb.CHECK, findings=(_cooldown("inline.held-finding"),))
    assert [f.rule for f in result.findings] == [Rule.COOLDOWN]


def test_refuses_fails_when_a_finding_was_built_and_dropped() -> None:
    with (
        pytest.raises(AssertionError, match=r"'inline\.dropped-finding' fired, but its refusal was swallowed"),
        refuses("inline.dropped-finding"),
    ):
        _cooldown("inline.dropped-finding")
    # A warning or notice names no site, and a violation built outside a block records nothing.
    assert findings._SITES.get() is None
    assert _cooldown("inline.outside").rule is Rule.COOLDOWN


def test_finding_site_never_reaches_output() -> None:
    # Data integrity: the site is no field, so it is in no text, no JSON, no ID and no comparison.
    built = _cooldown("inline.never-shown")
    plain = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=PLACE, item="demo", version="2.0")
    assert built == plain and built.id == plain.id and repr(built) == repr(plain)
    assert "site" not in {f.name for f in dataclasses.fields(Finding)}
    result = Result(Verb.CHECK, findings=(built,))
    shown = [to_json(result, TOOL), to_text(result, TOOL)]
    assert all("cooldown" in text for text in shown)
    assert [text for text in shown if "inline.never-shown" in text or "never-shown" in text] == []
    with refuses("findings.malformed-name"):  # the malformed-name finding's own site: shown nowhere either
        bad = to_json(Result(Verb.CHECK, findings=(make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place=""),)), TOOL)
    assert json.loads(bad)["findings"][0]["rule"] == "malformed-name" and "findings." not in bad


# --- the three weak spots of the owner's ruling, 2026-11-10 (issue #164) ------------------


def _discards() -> int:
    """Builds a result listing a refusal and a violation, and throws it away: only its exit code
    is kept, as a command that builds a second result would."""
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI):
        raise IncompleteCheckError(SkipReason.FEED_FAILURE, site="inline.discarded-skip")
    collector.findings.append(_cooldown("inline.discarded-finding"))
    return int(collector.result().exit_code)


def test_refusal_in_a_discarded_result_does_not_count() -> None:
    # Weak spot 1: a Result or a collector listing a refusal is not enough; the result the command
    # returns must, rendered or held by the test.
    for site in ("inline.discarded-skip", "inline.discarded-finding"):
        with pytest.raises(AssertionError, match="swallowed"), Refuses(site):
            assert _discards() == 1
    # The control: the same result rendered, or held, reaches the test.
    collector = Collector(Verb.CHECK)
    with refuses("inline.kept-result"), collector.check(Ecosystem.PYPI):
        raise IncompleteCheckError(SkipReason.FEED_FAILURE, site="inline.kept-result")
    assert collector.result().exit_code == 2
    with refuses("inline.rendered-result"):
        shown = _rendered_skip("inline.rendered-result")
    assert json.loads(shown)["exit_code"] == 2
    # A collector the test holds counts for the result it gives: of two equal findings, the result
    # keeps the first, so the second, still in the collector's list, never reached it.
    held = Collector(Verb.CHECK)
    with refuses("inline.first-copy"):
        held.findings += [_cooldown("inline.first-copy")]
    with pytest.raises(AssertionError, match="swallowed"), Refuses("inline.second-copy"):
        held.findings += [_cooldown("inline.second-copy")]
    assert len(held.findings) == 2 and len(held.result().findings) == 1


def _rendered_skip(site: str) -> str:
    """A collector's result with one listed refusal, rendered: the command's own result."""
    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.PYPI):
        raise IncompleteCheckError(SkipReason.FEED_FAILURE, site=site)
    return to_json(collector.result(), TOOL)


def _keeps_a_refusal() -> Skip:
    """Holds a refusal in a variable and drops it; the skip it returns is built from nothing."""
    kept = IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.kept-in-a-local")
    assert kept.reason is SkipReason.CHECK_ERROR
    return Skip(None, None, SkipReason.CHECK_ERROR, site="inline.unrelated-skip")


def _names_its_source() -> Skip:
    source = IncompleteCheckError(SkipReason.CHECK_ERROR, site="inline.named-source")
    return Skip(None, None, SkipReason.CHECK_ERROR, site="inline.built-from-it", made_from=source)


def test_refusal_kept_in_a_dropped_local_does_not_count() -> None:
    # Weak spot 2: a refusal the building code merely holds does not reach the result with the skip.
    with pytest.raises(AssertionError, match="swallowed"), Refuses("inline.kept-in-a-local"):
        skip = _keeps_a_refusal()
    with refuses("inline.unrelated-skip"):  # the skip itself, held by the test, did reach it
        skip = _keeps_a_refusal()
    assert skip.in_scope
    # The control: a skip that names its source with made_from carries it.
    with refuses("inline.named-source"), refuses("inline.built-from-it"):
        named = _names_its_source()
    assert named.in_scope


@contextmanager
def _expecting(site: str) -> Iterator[None]:
    """A test helper that runs the refuses block for the test (Refuses: refuses takes a literal)."""
    with Refuses(site):
        yield


def test_refuses_inside_a_helper_context_manager_finds_the_test() -> None:
    # Weak spot 3: the frame running the with statement is the helper's generator, not the test;
    # refuses reads the test's own variables, where the returned skip is held.
    with _expecting("inline.through-a-helper"):
        problems = [Skip(None, None, SkipReason.CHECK_ERROR, site="inline.through-a-helper")]
    assert problems[0].in_scope
    # The helper's own variables count for nothing: a skip only it holds, across its yield, never
    # reached the test (the frame the old check read was this helper's).
    with pytest.raises(AssertionError, match="swallowed"), _holding("inline.only-the-helper"):
        pass


@contextmanager
def _holding(site: str) -> Iterator[None]:
    """A helper that builds a skip in the block and keeps it in its own variable, not the test's."""
    with Refuses(site):
        kept = Skip(None, None, SkipReason.CHECK_ERROR, site=site)
        yield
        assert kept.in_scope
