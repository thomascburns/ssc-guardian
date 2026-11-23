# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``check --envs`` facts that keep a check fail-closed (issue #262, the 2026-11-14 audit's
m2-F03 and m2-F04): an override's fixed-version fact stays unknown when PyPI was not read, and
an environment whose records cannot be read is taken to have a pip. No network; files only
under ``tmp_path``."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssc_guardian import discovery, policy
from ssc_guardian.commands.check_envs import CheckEnvs, _has_pip
from ssc_guardian.feeds import pypi
from ssc_guardian.findings import Ecosystem, Finding, Option, OptionKind, Rule, make_finding
from tests.unit.test_discovery import add_dist, fake_mac, make_venv

pytestmark = pytest.mark.unit


def _vulnerable_requests() -> Finding:
    """A known-vulnerability finding with no replacement to install (no REPLACE option)."""
    return make_finding(
        Rule.KNOWN_VULNERABILITY,
        Ecosystem.PYPI,
        place="/Users/me/projects/app/.venv/lib/python3.12/site-packages",
        item="requests",
        version="2.31.0",
        evidence=("CVE-2024-35195", "GHSA-9wx4-h78v-vm56"),
        options=(Option(OptionKind.REMOVE),),
    )


def test_facts_unknown_when_project_was_not_read() -> None:
    # m2-F04: PyPI's page for requests failed, so the replacement search never ran: unknown,
    # never "no fix". Only a project that was read can say no fix installs now.
    finding = _vulnerable_requests()
    aliases = frozenset(finding.evidence)
    unread = policy.PypiFacts({}, {}, {}, {"requests": "PyPI answered something it could not use"})
    assert CheckEnvs._facts(finding, aliases, unread, None).fix_passes is None
    read = policy.PypiFacts({}, {}, {"requests": pypi.Project("requests", True)}, {})
    assert CheckEnvs._facts(finding, aliases, read, None).fix_passes is False


def test_has_pip_is_true_when_records_cannot_be_read(tmp_path: Path) -> None:
    # m2-F03: a record with no Version stops pip.all_pips, so whether a pip is there cannot be
    # told; it is taken as present, so its index settings are still read.
    where = fake_mac(tmp_path)
    site = make_venv(tmp_path / "home" / "projects" / "app" / ".venv")
    add_dist(site, "idna", "3.7")
    (env,) = discovery.survey(where, [str(tmp_path / "home" / "projects")]).environments
    assert _has_pip(env, None) is False  # every record read, and none is pip's
    record = site / "foo-1.0.dist-info"
    record.mkdir()
    (record / "METADATA").write_text("Metadata-Version: 2.1\nName: foo\n")
    assert _has_pip(env, None) is True
