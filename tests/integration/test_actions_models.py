# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Workflow, composite Action and reusable workflow models over the YAML reader (plan §3.2, T5; issue #8)."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from ssc_guardian import yaml_subset
from ssc_guardian.findings import Collector, Ecosystem, ExitCode, Rule, SkipReason, Verb
from ssc_guardian.grammars import Field, MalformedValueError
from ssc_guardian.plugins.actions.models import (
    UsesKind,
    UsesReference,
    load_action,
    load_workflow,
)
from tests.refusal_sites import Refuses, refuses

pytestmark = pytest.mark.integration


def _write(tmp_path: Path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body).lstrip("\n"))
    return str(path)


def test_reusable_and_composite_references_are_found(tmp_path: Path) -> None:
    wf = _write(
        tmp_path,
        "wf.yml",
        """
        on:
          workflow_call:
          push:
        jobs:
          call-remote:
            uses: octo-org/shared/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567
            with:
              uses: not/a-reference@main
          call-local:
            uses: ./.github/workflows/local.yml
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Script
                run: |
                  uses: evil/action@main
              - uses: actions/checkout@v4
                with:
                  uses: also/not-a-reference@main
              - uses: "./.github/actions/setup"
              - uses: docker://alpine:3.20
              - id: plain-run
                run: echo uses=evil/x@main
        """,
    )
    workflow = load_workflow(wf)
    assert workflow.triggers == ("workflow_call", "push")
    assert workflow.is_reusable
    assert [(j.id, len(j.steps)) for j in workflow.jobs] == [("call-remote", 0), ("call-local", 0), ("build", 5)]
    assert workflow.references == (
        UsesReference(
            "octo-org/shared/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567",
            UsesKind.REUSABLE_WORKFLOW,
            wf,
            6,
            "call-remote",
            None,
            "octo-org/shared/.github/workflows/build.yml",
            "0123456789abcdef0123456789abcdef01234567",
        ),
        UsesReference("./.github/workflows/local.yml", UsesKind.LOCAL, wf, 10, "call-local", None),
        UsesReference("actions/checkout@v4", UsesKind.ACTION, wf, 17, "build", 1, "actions/checkout", "v4"),
        UsesReference("./.github/actions/setup", UsesKind.LOCAL, wf, 20, "build", 2),
        UsesReference("docker://alpine:3.20", UsesKind.DOCKER, wf, 21, "build", 3),
    )

    action = _write(
        tmp_path,
        "action.yml",
        """
        name: Setup
        runs:
          using: composite
          steps:
            - run: 'echo "uses: evil/x@main"'
              shell: bash
            - uses: Actions/Setup-Python@v5   # spelling kept exactly as written
            - uses: ./inner
        """,
    )
    meta = load_action(action)
    assert meta.is_composite
    assert meta.references == (
        UsesReference("Actions/Setup-Python@v5", UsesKind.ACTION, action, 7, None, 1, "Actions/Setup-Python", "v5"),
        UsesReference("./inner", UsesKind.LOCAL, action, 8, None, 2),
    )
    # The runner's spelling of "composite" may differ in case; its steps are read either way,
    # and steps written under any other ``using`` are read too, so none is hidden.
    for using in ("Composite", "node24"):
        odd = _write(tmp_path, "odd.yml", f"runs:\n  using: {using}\n  steps:\n    - uses: evil/a@main\n")
        assert [r.raw for r in load_action(odd).references] == ["evil/a@main"]
    assert load_action(odd).is_composite is False
    assert load_action(_write(tmp_path, "c.yml", "runs:\n  using: COMPOSITE\n  steps: []\n")).is_composite
    node = _write(tmp_path, "node.yml", "runs:\n  using: node24\n  main: index.js\n")
    assert load_action(node).using == "node24"
    assert load_action(node).references == ()


@pytest.mark.parametrize(
    ("uses", "field"),
    [
        ("actions/checkout", Field.ACTION_STEP),
        ("actions/checkout@${{ matrix.ref }}", Field.GIT_REF),
        ("actions/checkout@-rf", Field.GIT_REF),
        ("-x/checkout@v4", Field.ACTION),
        ("actions/../checkout@v4", Field.ACTION),
        ("$/.github/actions/setup", Field.ACTION_STEP),
    ],
)
def test_malformed_reference_is_a_malformed_name(tmp_path: Path, uses: str, field: Field) -> None:
    wf = _write(tmp_path, "wf.yml", f"on: push\njobs:\n  b:\n    steps:\n      - uses: '{uses}'\n")
    with pytest.raises(MalformedValueError, match=f"^malformed {field.value}$") as info:
        load_workflow(wf)
    assert info.value.field is field

    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.GITHUB_ACTIONS, wf):
        load_workflow(wf)
    result = collector.result()
    assert result.exit_code is ExitCode.VIOLATION
    assert [f.rule for f in result.findings] == [Rule.MALFORMED_NAME]


def test_docker_reference_is_not_a_reusable_workflow(tmp_path: Path) -> None:
    wf = _write(tmp_path, "wf.yml", "on: push\njobs:\n  b:\n    uses: docker://alpine:3\n")
    with refuses("models.malformed-action-step"), pytest.raises(MalformedValueError, match="malformed action-step"):
        load_workflow(wf)


@pytest.mark.parametrize(
    ("body", "line", "detail", "site"),
    [
        ("", 1, "the file is empty", refuses("models.file-empty")),
        ("- a\n", 1, "the file is not a mapping", refuses("models.file-not-mapping")),
        ("on: push\n", 1, "a workflow has no 'jobs'", refuses("models.workflow-no-jobs")),
        ("on: push\njobs: [a]\n", 2, "'jobs' is not a mapping", refuses("models.value-not-mapping")),
        ("on: push\njobs:\n  b: x\n", 3, "job 'b' is not a mapping", refuses("models.value-not-mapping")),
        ("on: push\njobs:\n  b:\n    steps: x\n", 4, "'steps' is not a list", refuses("models.steps-not-list")),
        (
            "on: push\njobs:\n  b:\n    steps:\n      - x\n",
            5,
            "step 1 is not a mapping",
            refuses("models.value-not-mapping"),
        ),
        (
            "on: push\njobs:\n  b:\n    steps:\n      - uses:\n",
            5,
            "a step's 'uses' is not a single value",
            refuses("models.not-single-value"),
        ),
        (
            "on: push\njobs:\n  b:\n    steps:\n      - uses: [a/b@c]\n",
            5,
            "a step's 'uses' is not a single value",
            refuses("models.not-single-value"),
        ),
        (
            "on: push\njobs:\n  b:\n    uses:\n      x: y\n",
            5,
            "job 'b''s 'uses' is not a single value",
            refuses("models.not-single-value"),
        ),
    ],
)
def test_unexpected_structure_refuses_with_line(
    tmp_path: Path, body: str, line: int, detail: str, site: Refuses
) -> None:
    wf = str(tmp_path / "wf.yml")
    Path(wf).write_text(body)
    with site, pytest.raises(yaml_subset.UnsupportedYamlError, match=re.escape(detail)) as info:
        load_workflow(wf)
    assert (info.value.source, info.value.line, info.value.form, info.value.detail) == (
        wf,
        line,
        "unexpected structure",
        detail,
    )
    assert info.value.reason is SkipReason.UNSUPPORTED_YAML


def test_action_metadata_structure_refuses_with_line(tmp_path: Path) -> None:
    for body, detail, site in [
        ("name: x\n", "an Action's metadata has no 'runs'", refuses("models.actions-metadata-no-runs")),
        ("runs:\n  main: x\n", "'runs' has no 'using'", refuses("models.runs-no-using")),
        (
            "runs:\n  using: composite\n",
            "a composite Action has no 'steps'",
            refuses("models.composite-action-no-steps"),
        ),
        (
            "runs:\n  using: Composite\n",
            "a composite Action has no 'steps'",
            refuses("models.composite-action-no-steps"),
        ),
    ]:
        path = _write(tmp_path, "action.yml", body)
        with site, pytest.raises(yaml_subset.UnsupportedYamlError, match=re.escape(detail)) as info:
            load_action(path)
        assert (info.value.form, info.value.detail) == ("unexpected structure", detail)
