# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``install --venv``: the file pip chose is held to its own package's cooldown (issue #129).

pip takes one cutoff, the shortest cooldown in the request, and the release-level check dates a
version by its earliest file (contracts §7, ``trusted_age``), so a wheel uploaded long after its
release's sdist passed both. These tests plant such wheels. Nothing reaches the network: the
feeds answer in process and a fake runner stands in for pip (``tests/unit/test_install.py``).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import policy
from ssc_guardian.discovery import Environment
from ssc_guardian.feeds import pypi
from ssc_guardian.net import Response
from tests.refusal_sites import refuses
from tests.unit.test_install import (
    TODAY,
    FakePip,
    Feeds,
    handler,
    run,
    sdist_sha,
    sdist_url,
    sha,
    tree,
    venv,
    wheel_url,
)

pytestmark = pytest.mark.unit


def days_ago(days: int, clock: str = "00:00:00") -> str:
    """An upload time ``days`` whole days before :data:`TODAY`, at ``clock`` UTC."""
    return f"{(TODAY - timedelta(days=days)).isoformat()}T{clock}Z"


def wheel(name: str, version: str, uploaded: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "filename": f"{name}-{version}-py3-none-any.whl",
        "url": wheel_url(name, version),
        "hashes": {"sha256": sha(name, version)},
    }
    return entry if uploaded is None else entry | {"upload-time": uploaded}


def sdist(name: str, version: str, uploaded: str) -> dict[str, Any]:
    return {
        "filename": f"{name}-{version}.tar.gz",
        "url": sdist_url(name, version),
        "hashes": {"sha256": sdist_sha(name, version)},
        "upload-time": uploaded,
    }


# The issue's input: foo 2.0's sdist is 100 days old and its wheel, the file pip takes, 30.
OLD_SDIST_YOUNG_WHEEL = [sdist("foo", "2.0", days_ago(100)), wheel("foo", "2.0", days_ago(30))]


@dataclass
class Pages(Feeds):
    """:class:`Feeds`, with PyPI's page for each project in ``files`` built from those files."""

    files: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        url = request.full_url
        if url.startswith(pypi.SIMPLE_URL) and url.split("/")[4] in self.files:
            self.sent.append(url)
            name = url.split("/")[4]
            versions = sorted({f["filename"].split("-")[1].removesuffix(".tar.gz") for f in self.files[name]})
            page = {"meta": {"api-version": "1.4"}, "name": name, "files": self.files[name], "versions": versions}
            return Response(200, {}, json.dumps(page).encode(), url)
        return super().__call__(request, timeout, limit)


@dataclass
class CutoffPip(FakePip):
    """:class:`FakePip`, keeping the cutoff each check step was given."""

    cutoffs: list[str] = field(default_factory=list)

    def check(self, env: Environment, pins: Any, cutoff: str) -> object:
        self.cutoffs.append(cutoff)
        return super().check(env, pins, cutoff)


def configure(tmp_path: Path, rules: str) -> None:
    """The workstation config: ``rules`` are the lines of its ``[rules]`` table."""
    config = tmp_path / "home" / ".config" / "ssc-guardian" / "config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(f"format = 1\n[rules]\n{rules}\n")


def cooldown_findings(result: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["item"], f["version"]) for f in result["findings"] if f["rule"] == "cooldown"]


def test_bound_wheel_younger_than_its_package_cooldown_is_refused(tmp_path: Path) -> None:
    configure(tmp_path, '"pypi:foo" = { cooldown_days = 60 }')
    runner = CutoffPip()
    target = venv(tmp_path)
    before = tree(target)

    with refuses("install.file-cooldown"):
        code, result, err = run(
            handler(tmp_path, runner, Pages(files={"foo": OLD_SDIST_YOUNG_WHEEL})), target, "foo==2.0"
        )
    assert code == 1, err
    assert cooldown_findings(result) == [("foo", "2.0")]
    # pip was given the default's 21-day cutoff, so it took the 30-day-old wheel; the release
    # (dated by its 100-day-old sdist) passed; the wheel itself is inside foo's 60 days.
    assert runner.cutoffs == ["2026-10-13T00:00:00+00:00"]
    eligible = (TODAY - timedelta(days=30) + timedelta(days=60)).isoformat()
    assert f"foo-2.0-py3-none-any.whl, the file pip chose, was uploaded on {days_ago(30)[:10]}" in err
    assert f"inside its 60-day cooldown, eligible on {eligible}" in err
    assert "foo 2.0 fails cooldown (requested)" in err and "refused; nothing installed" in err
    assert runner.installs == []
    assert tree(target) == before

    # The positive control: the same wheel once it is past foo's 60 days installs.
    files = [sdist("foo", "2.0", days_ago(100)), wheel("foo", "2.0", days_ago(60))]
    code, result, err = run(handler(tmp_path, runner, Pages(files={"foo": files})), target, "foo==2.0")
    assert code == 0, err
    assert [[(f.item.name, f.item.version) for f in planned] for planned in runner.installs] == [[("foo", "2.0")]]


def test_shortened_rule_does_not_lower_a_dependency_cooldown(tmp_path: Path) -> None:
    # A [rules] entry shortens foo's cooldown to 3 days, so pip's one cutoff is 3 days for
    # every package; lib, the dependency pip chose, keeps the default 21.
    configure(tmp_path, '"pypi:foo" = { cooldown_days = 3 }')
    files = {
        "foo": [sdist("foo", "2.0", days_ago(100)), wheel("foo", "2.0", days_ago(100))],
        "lib": [sdist("lib", "1.0", days_ago(100)), wheel("lib", "1.0", days_ago(10))],
    }
    runner = CutoffPip(extra=[("lib", "1.0")])
    target = venv(tmp_path)
    before = tree(target)

    code, result, err = run(handler(tmp_path, runner, Pages(files=files)), target, "foo==2.0")
    assert code == 1, err
    assert runner.cutoffs == [f"{(TODAY - timedelta(days=3)).isoformat()}T00:00:00+00:00"]
    assert cooldown_findings(result) == [("lib", "1.0")]
    assert "inside its 21-day cooldown" in err
    assert "lib 1.0 fails cooldown (a dependency pip chose for this request" in err
    assert runner.installs == []
    assert tree(target) == before


def test_bound_file_without_upload_time_is_unknown_age(tmp_path: Path) -> None:
    # The release has a date (its sdist's), the wheel pip chose has none: never a pass.
    files = {"foo": [sdist("foo", "2.0", days_ago(100)), wheel("foo", "2.0", None)]}
    runner = FakePip()
    target = venv(tmp_path)
    before = tree(target)

    with refuses("install.bound-file-unknown-age"):
        code, result, err = run(handler(tmp_path, runner, Pages(files=files)), target, "foo==2.0")
    assert code == 2, err
    assert result["skipped"] == [{"ecosystem": "pypi", "place": str(target), "reason": "unknown-age", "in_scope": True}]
    assert "PyPI gives no upload time for foo-2.0-py3-none-any.whl, so its age is unknown" in err
    assert "nothing installed" in err
    assert runner.installs == []
    assert tree(target) == before

    # A re-run is the same refusal, and still installs nothing.
    with refuses("install.bound-file-unknown-age"):
        again = run(handler(tmp_path, runner, Pages(files=files)), target, "foo==2.0")
    assert again == (code, result, err)
    assert runner.installs == []
    assert tree(target) == before


@pytest.mark.parametrize(
    ("uploaded", "met"),
    [
        pytest.param(days_ago(21), True, id="midnight-21-days-ago"),
        pytest.param(days_ago(21, "00:00:01"), False, id="a-second-after-midnight-21-days-ago"),
        pytest.param(days_ago(22, "23:59:59"), True, id="last-second-22-days-ago"),
        pytest.param(days_ago(20), False, id="midnight-20-days-ago"),
    ],
)
def test_file_exactly_at_cooldown_boundary(tmp_path: Path, uploaded: str, met: bool) -> None:
    # The per-file check counts whole days as cooldown_met does: from the first whole day
    # after the upload, under the default 21 days.
    started = policy.cooldown_start(datetime.fromisoformat(uploaded.replace("Z", "+00:00")))
    assert policy.cooldown_met(started, 21, TODAY) is met
    files = {"foo": [sdist("foo", "2.0", days_ago(100)), wheel("foo", "2.0", uploaded)]}
    runner = FakePip()

    code, result, err = run(handler(tmp_path, runner, Pages(files=files)), venv(tmp_path), "foo==2.0")
    assert code == (0 if met else 1), err
    assert cooldown_findings(result) == ([] if met else [("foo", "2.0")])
    assert len(runner.installs) == (1 if met else 0)


COOLDOWN_OVERRIDE = """format = 1
[[override]]
ecosystem = "pypi"
item = "foo"
version = "2.0"
rule = "cooldown"
reference = "cooldown"
category = "no-fix-available"
created = 2026-11-01
expiry = 2026-11-20
reason = "tests: a cooldown is not overridable"
"""


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        pytest.param(None, 1, id="none"),
        # The cooldown's exception is a [rules] entry (contracts §10.4, Q3): it releases both.
        pytest.param("rules", 0, id="rules-entry"),
        # An override cannot name the cooldown rule (Q3): the file is refused, releasing neither.
        pytest.param("override", 1, id="cooldown-override"),
    ],
)
def test_override_releases_a_per_file_cooldown_finding(tmp_path: Path, exception: str | None, expected: int) -> None:
    # The per-file finding is released exactly as the release-level one is: foo 2.0 once with
    # an old sdist and a 10-day-old wheel (per file), once with that wheel only (release level).
    # foo 1.0 passes, so each finding names it as the replacement, and the options are compared.
    older = wheel("foo", "1.0", days_ago(200))
    outcomes = []
    for case, files in (
        ("file", [older, sdist("foo", "2.0", days_ago(100)), wheel("foo", "2.0", days_ago(10))]),
        ("release", [older, wheel("foo", "2.0", days_ago(10))]),
    ):
        home = tmp_path / case
        (home / "home").mkdir(parents=True)
        if exception == "rules":
            configure(home, '"pypi:foo" = { cooldown_days = 7 }')
        elif exception == "override":
            overrides = home / "home" / ".config" / "ssc-guardian" / "overrides.toml"
            overrides.parent.mkdir(parents=True, exist_ok=True)
            overrides.write_text(COOLDOWN_OVERRIDE)
        runner = FakePip()
        code, result, err = run(handler(home, runner, Pages(files={"foo": files})), venv(home), "foo==2.0")
        assert code == expected, err
        assert len(runner.installs) == (1 if expected == 0 else 0)
        if exception == "override":
            assert "rule cooldown cannot be overridden for pypi" in err
        # The same findings, options included; the ID and place differ only by where the venv is.
        found = [{k: v for k, v in f.items() if k != "id"} for f in result["findings"]]
        outcomes.append((code, json.dumps(found).replace(str(home), "~"), result["overrides"]))
    assert outcomes[0] == outcomes[1]
    if expected == 1:
        (finding,) = json.loads(outcomes[0][1])
        assert (finding["rule"], finding["item"], finding["version"]) == ("cooldown", "foo", "2.0")
        commands = [o["command"] for o in finding["options"] if o["command"]]
        assert commands == [["ssc-guardian", "install", "--venv", "~/projects/app/.venv", "foo==1.0"]]
