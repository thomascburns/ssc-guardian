# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Negative tests for the plug-in steps that are not available (issue #11).

uv's plug-in sets up and reports its cooldown only (N18): discovery, trusted age, planning and
applying an install are pip's or the core's, so each of those steps refuses, as an in-scope
``not-available``, rather than answering with nothing. pip's plug-in leaves trusted age to the
core, which reads PyPI. Only the plug-in API reaches these steps; no command calls them, so each
test calls the step itself and checks that it refuses rather than returns.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ssc_guardian.discovery import Roots
from ssc_guardian.findings import Ecosystem, IncompleteCheckError, Scope, SkipReason
from ssc_guardian.plugin import InstallPlan, Item, Requirement
from ssc_guardian.plugins.pip import PipPlugin
from ssc_guardian.plugins.uv import UvPlugin
from tests.refusal_sites import Refuses, refuses

pytestmark = pytest.mark.unit

PLACE = "/Users/me/project/.venv"
ITEM = Item(Ecosystem.PYPI, "demo", "1.0", PLACE)


def _uv_discover(home: Path) -> object:
    return UvPlugin().discover(Scope(frozenset({Ecosystem.PYPI})))


def _uv_trusted_age(home: Path) -> object:
    return UvPlugin().trusted_age(ITEM)


def _uv_plan_install(home: Path) -> object:
    return UvPlugin().plan_install(PLACE, (Requirement(Ecosystem.PYPI, "demo", "1.0"),))


def _uv_apply(home: Path) -> object:
    UvPlugin().apply(InstallPlan(PLACE, (ITEM,)))
    return None


def _pip_trusted_age(home: Path) -> object:
    return PipPlugin(Roots(str(home), {"PATH": ""})).trusted_age(ITEM)


@pytest.mark.parametrize(
    ("step", "site"),
    [
        (_uv_discover, refuses("uv.discover-not-available")),
        (_uv_trusted_age, refuses("uv.trusted-age-not-available")),
        (_uv_plan_install, refuses("uv.plan-install-not-available")),
        (_uv_apply, refuses("uv.apply-not-available")),
        (_pip_trusted_age, refuses("pip.trusted-age-not-available")),
    ],
)
def test_a_step_the_plugin_does_not_provide_refuses(
    tmp_path: Path, step: Callable[[Path], object], site: Refuses
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    with site, pytest.raises(IncompleteCheckError, match="^not-available$") as raised:
        step(home)
    assert raised.value.reason is SkipReason.NOT_AVAILABLE
    assert raised.value.reason.in_scope
    assert list(home.iterdir()) == []
