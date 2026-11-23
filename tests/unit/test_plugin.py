# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The typed plug-in protocol: conformance is checked by mypy, data shapes refuse bad values (issue #2)."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date, datetime
from typing import Any

import pytest

from ssc_guardian.findings import Checked, Ecosystem, IncompleteCheckError, Scope, SkipReason
from ssc_guardian.grammars import MalformedValueError
from ssc_guardian.plugin import (
    AgeSource,
    CodeExecution,
    CooldownSetting,
    DigestAlgorithm,
    Discovery,
    EcosystemPlugin,
    InstallPlan,
    Item,
    PlannedFile,
    PluginName,
    Requirement,
    TrustedAge,
)

pytestmark = pytest.mark.unit

_not_items: Any = ("not an item",)
_made_up_source: Any = "made-up"
_no_date: Any = None

VENV = "/Users/dev/.venv"
WHEEL = "https://files.pythonhosted.org/packages/requests-2.32.3-py3-none-any.whl"


class FakePip:
    """A minimal plug-in. Assigning it to ``EcosystemPlugin`` below makes mypy check every signature."""

    @property
    def name(self) -> PluginName:
        return PluginName.PIP

    @property
    def ecosystem(self) -> Ecosystem:
        return Ecosystem.PYPI

    @property
    def code_execution(self) -> CodeExecution:
        return CodeExecution.NEVER

    def discover(self, scope: Scope) -> Discovery:
        return Discovery((Item(Ecosystem.PYPI, "requests", "2.32.3", VENV),), (Checked(Ecosystem.PYPI, VENV),), ())

    def trusted_age(self, item: Item) -> TrustedAge:
        if item.name != "requests":
            raise IncompleteCheckError(SkipReason.UNKNOWN_AGE)
        return TrustedAge(date(2024, 5, 29), AgeSource.REGISTRY_UPLOAD)

    def plan_install(self, target: str, requirements: tuple[Requirement, ...]) -> InstallPlan:
        item = Item(Ecosystem.PYPI, "requests", "2.32.3", target)
        return InstallPlan(target, (item,), (PlannedFile(item, WHEEL, DigestAlgorithm.SHA256, "a" * 64),))

    def apply(self, plan: InstallPlan) -> None:
        return None

    def installer_cooldown(self, place: str) -> CooldownSetting:
        return CooldownSetting(place, rolling_days=21)

    def write_cooldown(self, setting: CooldownSetting) -> None:
        return None


def test_fake_plugin_satisfies_the_protocol() -> None:
    plugin: EcosystemPlugin = FakePip()
    found = plugin.discover(Scope(frozenset({Ecosystem.PYPI})))
    assert [i.name for i in found.items] == ["requests"]
    plan = plugin.plan_install(VENV, (Requirement(Ecosystem.PYPI, "requests"),))
    assert plan.files[0].algorithm is DigestAlgorithm.SHA256
    with pytest.raises(IncompleteCheckError, match="unknown-age"):
        plugin.trusted_age(Item(Ecosystem.PYPI, "urllib3", "2.2.3", VENV))


def test_code_execution_has_exactly_three_values() -> None:
    assert [v.value for v in CodeExecution] == ["never", "can-be-turned-off", "always"]


@pytest.mark.parametrize(
    ("build", "error", "text"),
    [
        (lambda: Item(Ecosystem.PYPI, "bad name", "1.0", VENV), MalformedValueError, "malformed pypi-name"),
        (lambda: Item(Ecosystem.PYPI, "requests", "latest", VENV), MalformedValueError, "malformed pep440-version"),
        (lambda: Item(Ecosystem.PYPI, "requests", "1.0", "/a/../b"), MalformedValueError, "malformed path"),
        (lambda: Item(Ecosystem.GITHUB_ACTIONS, "requests", "v4", VENV), MalformedValueError, "malformed action"),
        (lambda: Requirement(Ecosystem.PYPI, "requests", ">=2"), MalformedValueError, "malformed pep440-version"),
        (
            lambda: PlannedFile(
                Item(Ecosystem.PYPI, "a", "1", VENV), "http://x/a.whl", DigestAlgorithm.SHA256, "a" * 64
            ),
            ValueError,
            "a planned file is fetched over HTTPS from a URL with no spaces or controls",
        ),
        (
            lambda: PlannedFile(Item(Ecosystem.PYPI, "a", "1", VENV), WHEEL, DigestAlgorithm.SHA256, "A" * 64),
            ValueError,
            "a planned file carries a lowercase hex sha256 digest",
        ),
        (
            lambda: PlannedFile(Item(Ecosystem.PYPI, "a", "1", VENV), WHEEL, DigestAlgorithm.SHA512, "a" * 64),
            ValueError,
            "a planned file carries a lowercase hex sha512 digest",
        ),
        (lambda: InstallPlan("/a;b", ()), MalformedValueError, "malformed path"),
        (
            lambda: CooldownSetting(VENV, rolling_days=21, fixed_date=date(2026, 10, 1)),
            ValueError,
            "a cooldown setting is rolling or a fixed date, not both",
        ),
        (lambda: CooldownSetting(VENV, rolling_days=-1), ValueError, "a rolling cooldown is not negative"),
        (lambda: CooldownSetting(VENV, rolling_days=True), TypeError, "a rolling cooldown is a whole number of days"),
        (
            lambda: CooldownSetting(VENV, fixed_date=datetime(2026, 10, 1, 12, 0)),
            TypeError,
            "a date field holds a datetime.date, not a datetime",
        ),
        (
            lambda: TrustedAge(datetime(2026, 10, 1, 12, 0), AgeSource.REGISTRY_UPLOAD),
            TypeError,
            "a trusted age starts on a datetime.date",
        ),
        (
            lambda: PlannedFile(Item(Ecosystem.PYPI, "a", "1", VENV), WHEEL + " x", DigestAlgorithm.SHA256, "a" * 64),
            ValueError,
            "a planned file is fetched over HTTPS from a URL with no spaces or controls",
        ),
        (
            lambda: PlannedFile(Item(Ecosystem.PYPI, "a", "1", VENV), WHEEL + "\n", DigestAlgorithm.SHA256, "a" * 64),
            ValueError,
            "a planned file is fetched over HTTPS from a URL with no spaces or controls",
        ),
        (lambda: InstallPlan(VENV, _not_items), TypeError, "InstallPlan.items holds only Item"),
        (lambda: Discovery(_not_items, (), ()), TypeError, "Discovery.items holds only Item"),
        (
            lambda: PlannedFile(_not_items, WHEEL, DigestAlgorithm.SHA256, "a" * 64),
            TypeError,
            "a planned file names an Item and a DigestAlgorithm",
        ),
        (lambda: TrustedAge(date(2026, 1, 1), _made_up_source), TypeError, "a trusted age names an AgeSource"),
        (lambda: TrustedAge(_no_date, AgeSource.REGISTRY_UPLOAD), TypeError, "a trusted age starts on a datetime.date"),
        (lambda: Item(_made_up_source, "a", "1", VENV), TypeError, "an Ecosystem names the item's ecosystem"),
        (lambda: Requirement(_made_up_source, "a"), TypeError, "an Ecosystem names the item's ecosystem"),
    ],
)
def test_plugin_data_refuses_bad_values(build: Callable[[], object], error: type[Exception], text: str) -> None:
    with pytest.raises(error, match=re.escape(text)):
        build()


def test_plugin_lists_are_frozen() -> None:
    item = Item(Ecosystem.PYPI, "a", "1", VENV)
    items: Any = [item]
    plan = InstallPlan(VENV, items)
    items.append("not an item")
    assert plan.items == (item,)


def test_sha512_digest_is_accepted() -> None:
    item = Item(Ecosystem.PYPI, "a", "1", VENV)
    assert PlannedFile(item, WHEEL, DigestAlgorithm.SHA512, "b" * 128).digest == "b" * 128


@pytest.mark.parametrize(
    ("also_writes", "error", "text"),
    [
        ((VENV,), ValueError, "also_writes names each other file once, and not the target"),  # the target itself
        (
            ("/Users/dev/projects/app/.ssc-guardian.lock",) * 2,
            ValueError,
            "also_writes names each other file once, and not the target",
        ),  # named twice
        (("relative/.ssc-guardian.lock",), MalformedValueError, "malformed path"),  # not a valid path
        (("/a;b",), MalformedValueError, "malformed path"),
    ],
)
def test_install_plan_also_writes_is_checked(also_writes: tuple[str, ...], error: type[Exception], text: str) -> None:
    # D16: every file outside the target is named once and grammar-checked, so the
    # confirmation can show it and apply writes nothing else.
    with pytest.raises(error, match=re.escape(text)):
        InstallPlan(VENV, (), also_writes=also_writes)


def test_install_plan_names_every_other_file_it_writes() -> None:
    lock = "/Users/dev/projects/app/.ssc-guardian.lock"
    plan = InstallPlan("/Users/dev/projects/app/.github/workflows/ci.yml", (), also_writes=(lock,))
    assert plan.also_writes == (lock,)


def test_protocol_has_a_function_that_writes_the_cooldown() -> None:
    # D16: protect writes through the protocol, after confirmation, never around it.
    assert callable(getattr(EcosystemPlugin, "write_cooldown", None))
    assert "confirmed" in (EcosystemPlugin.write_cooldown.__doc__ or "")
