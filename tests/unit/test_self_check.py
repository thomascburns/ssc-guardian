# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""This repository is held to its own gate (#206).

Guardian tells adopters to pin every Action through ``ssc-guardian pin``, which records it in
``.ssc-guardian.lock``, and to run ``check --repo`` in CI as a gate. This module holds the
repository to both, offline:

- every remote ``uses:`` in ``.github/workflows`` has a lock entry for its exact commit, and that
  entry's tag is the version in the pin's comment. The workflows are read with Guardian's own
  reader (``commands.pin.read_sources``, the one ``pin`` and ``check --repo`` use), the lock file
  with ``lockfile.parse_lock``, and a commit is matched by ``resolver.commit_key``, as Guardian
  keys it. No lock file is a failure, never a pass;
- the lock file is in canonical form: ``dump_lock`` of its parsed entries is the file itself;
- ``tests.yml``'s ``tests-linux`` job runs ``check --repo .`` from the source tree with
  ``GITHUB_TOKEN`` after the tests, and the step cannot pass on failure: it has exactly the keys
  ``name``, ``env`` and ``run``, so no ``continue-on-error``, ``if`` or ``shell`` can be added, its
  ``run`` is the command alone (no ``|| true``), and the job has no ``continue-on-error`` either.
  ``tests.yml`` is read with Guardian's YAML reader (``yaml_subset``). It is the workflow both this
  repository and its published copy hold (#325).

Each guard is a function that returns the problems it finds, so the real files must give none and
a planted copy must give at least one. A planted copy is the real file with one exact
substitution, made only after the test has checked that the text it replaces is there exactly
once, so a negative case can never pass because the file moved on. No network; nothing is written
outside ``tmp_path``.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from ssc_guardian.commands.pin import read_sources
from ssc_guardian.lockfile import LOCK_FILE, dump_lock, lock_path, parse_lock
from ssc_guardian.plugins.actions.resolver import commit_key
from ssc_guardian.yaml_subset import parse, to_python

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
TESTS_WORKFLOW = WORKFLOWS / "tests.yml"
TESTS_JOB = "tests-linux"
LOCK = REPO / LOCK_FILE

STEP_NAME = "Check this repository with Guardian"
STEP_RUN = ".venv/bin/python -m ssc_guardian check --repo ."
STEP_ENV = {"GITHUB_TOKEN": "${{ github.token }}", "PYTHONPATH": "src"}
PIN_COMMENT = re.compile(r"#\s*(?P<tag>\S+)\s*$")


def unrecorded_pins(root: Path) -> list[str]:
    """Each remote ``uses:`` under ``root``'s workflows that the lock file does not record."""
    lock = Path(lock_path(str(root)))
    if not lock.is_file():
        return [f"{LOCK_FILE} is missing"]
    entries = {e.key: e for e in parse_lock(lock.read_text(encoding="utf-8"), place=str(lock))}
    sources = read_sources(str(root))
    if not sources:
        return ["no workflow was read"]
    problems: list[str] = []
    for source in sources:
        lines = source.text.splitlines()
        for ref in source.references:
            if ref.action is None or ref.ref is None:  # a local or Docker reference
                continue
            where = f"{Path(source.path).name}:{ref.line}: {ref.raw}"
            entry = entries.get(commit_key(ref.action, ref.ref))
            if entry is None:
                problems.append(f"{where}: no lock entry for this commit")
                continue
            comment = PIN_COMMENT.search(lines[ref.line - 1])
            if comment is None or comment.group("tag") != entry.tag:
                problems.append(f"{where}: the pin comment does not name the lock entry's tag {entry.tag}")
    return problems


def lock_problems(text: str) -> list[str]:
    """The lock file's text is not in canonical form."""
    return [] if dump_lock(parse_lock(text, place=LOCK_FILE)) == text else [f"{LOCK_FILE} is not canonical"]


def self_check_problems(text: str, job_name: str = TESTS_JOB, source: str = "tests.yml") -> list[str]:
    """The workflow *text*'s job *job_name* does not run Guardian on this repository, or could pass
    when Guardian fails."""
    doc = to_python(parse(text, source))
    assert isinstance(doc, dict)
    job = doc["jobs"][job_name]
    steps = job["steps"]
    named = [i for i, step in enumerate(steps) if step.get("name") == STEP_NAME]
    if len(named) != 1:
        return [f"the {job_name} job has {len(named)} steps named {STEP_NAME!r}, not 1"]
    index = named[0]
    step = steps[index]
    problems: list[str] = []
    if "continue-on-error" in job:
        problems.append(f"the {job_name} job sets continue-on-error")
    for scope, owner in (("the workflow", doc), (f"the {job_name} job", job)):
        if "defaults" in owner:
            problems.append(f"{scope} sets defaults, which can change the shell that runs the step")
    if set(step) != {"name", "env", "run"}:
        problems.append(f"the step's keys are {sorted(step)}, not env, name and run")
    if step.get("run") != STEP_RUN:
        problems.append(f"the step runs {step.get('run')!r}, not {STEP_RUN!r}")
    if step.get("env") != STEP_ENV:
        problems.append(f"the step's env is {step.get('env')!r}, not {STEP_ENV!r}")
    tests = [i for i, s in enumerate(steps) if s.get("name") == "Test"]
    if not tests or index < tests[0]:
        problems.append("the step does not run after the tests")
    return problems


def planted(text: str, old: str, new: str) -> str:
    """``text`` with its one ``old`` replaced by ``new``."""
    assert text.count(old) == 1, f"expected {old!r} exactly once"
    return text.replace(old, new)


def planted_repository(tmp_path: Path, *, lock: bool = True) -> Path:
    """A copy of this repository's workflows, and of its lock file when ``lock``."""
    root = tmp_path / "repo"
    shutil.copytree(WORKFLOWS, root / ".github" / "workflows")
    if lock:
        shutil.copyfile(LOCK, root / LOCK_FILE)
    return root


def snapshot() -> dict[Path, tuple[bytes, int]]:
    """Each file the guards read, with its bytes and modification time."""
    paths = [LOCK, *sorted(WORKFLOWS.iterdir())]
    return {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}


def test_every_workflow_pin_is_in_the_lock_file() -> None:
    assert unrecorded_pins(REPO) == []


def test_unrecorded_pin_is_caught(tmp_path: Path) -> None:
    root = planted_repository(tmp_path)
    workflow = root / ".github" / "workflows" / "tests.yml"
    sha = "1" * 40  # made up: the guard reads no network
    extra = f"      - uses: example/unrecorded@{sha} # v1.0.0\n"
    anchor = f"      - name: {STEP_NAME}\n"
    text = workflow.read_text(encoding="utf-8")
    line = text[: text.index(anchor)].count("\n") + 1  # where the extra pin goes
    workflow.write_text(planted(text, anchor, extra + anchor))
    assert unrecorded_pins(root) == [f"tests.yml:{line}: example/unrecorded@{sha}: no lock entry for this commit"]


def test_removed_lock_entry_is_caught(tmp_path: Path) -> None:
    root = planted_repository(tmp_path)
    lock = root / LOCK_FILE
    kept = [e for e in parse_lock(lock.read_text(encoding="utf-8"), place=None) if e.action != "actions/attest"]
    lock.write_text(dump_lock(kept), encoding="utf-8")
    problems = unrecorded_pins(root)
    assert len(problems) == 1
    assert problems[0].startswith("release.yml:") and "actions/attest@" in problems[0]


def test_pin_comment_must_name_the_recorded_tag(tmp_path: Path) -> None:
    root = planted_repository(tmp_path)
    release = root / ".github" / "workflows" / "release.yml"
    old = "1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"
    new = "1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.1"
    release.write_text(planted(release.read_text(encoding="utf-8"), old, new))
    problems = unrecorded_pins(root)
    assert len(problems) == 1 and "lock entry's tag v4.2.2" in problems[0]


def test_lock_file_is_canonical() -> None:
    text = LOCK.read_text(encoding="utf-8")
    assert lock_problems(text) == []
    assert len(parse_lock(text, place=str(LOCK))) == 5


def test_non_canonical_lock_file_is_caught() -> None:
    text = LOCK.read_text(encoding="utf-8")
    assert lock_problems(planted(text, "format = 1\n", "format = 1\n\n")) != []


def test_tests_workflow_runs_guardian_on_this_repository() -> None:
    assert self_check_problems(TESTS_WORKFLOW.read_text(encoding="utf-8")) == []
    doc = to_python(parse(TESTS_WORKFLOW.read_text(encoding="utf-8"), "tests.yml"))
    assert isinstance(doc, dict)
    step = next(s for s in doc["jobs"][TESTS_JOB]["steps"] if s.get("name") == STEP_NAME)
    assert step["run"].endswith("check --repo .")
    assert "GITHUB_TOKEN" in step["env"]
    assert "${{" not in step["run"]


# Each substitution that would let the self-check pass on failure; the development CI's copy of the
# step is held to the same list.
CANNOT_PASS = pytest.mark.parametrize(
    ("old", "new"),
    [
        (f"run: {STEP_RUN}\n", f"run: {STEP_RUN}\n        continue-on-error: true\n"),
        (f"run: {STEP_RUN}\n", f"run: {STEP_RUN} || true\n"),
        (f"run: {STEP_RUN}\n", f"run: {STEP_RUN}\n        if: false\n"),
        ("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    continue-on-error: true\n"),
        ("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    defaults:\n      run:\n        shell: sh {0}\n"),
        ("concurrency:\n", "defaults:\n  run:\n    shell: sh {0}\n\nconcurrency:\n"),
        (f"run: {STEP_RUN}\n", "run: .venv/bin/python -m ssc_guardian check --repo src\n"),
        ("PYTHONPATH: src\n", "PYTHONPATH: src\n          EXTRA: x\n"),
        (f"      - name: {STEP_NAME}\n", "      - name: Check this repository\n"),
    ],
    ids=[
        "continue-on-error",
        "or-true",
        "if-false",
        "job-continue-on-error",
        "job-defaults",
        "workflow-defaults",
        "other-command",
        "env",
        "renamed",
    ],
)


@CANNOT_PASS
def test_tests_workflow_self_check_cannot_pass_on_failure(tmp_path: Path, old: str, new: str) -> None:
    real = TESTS_WORKFLOW.read_text(encoding="utf-8")
    assert self_check_problems(real) == []  # the control: only the substitution makes it fail
    copy = tmp_path / "tests.yml"
    copy.write_text(planted(real, old, new), encoding="utf-8")
    assert self_check_problems(copy.read_text(encoding="utf-8")) != []


def test_self_check_guards_are_idempotent() -> None:
    before = snapshot()
    first = (unrecorded_pins(REPO), lock_problems(LOCK.read_text(encoding="utf-8")))
    second = (unrecorded_pins(REPO), lock_problems(LOCK.read_text(encoding="utf-8")))
    assert first == second == ([], [])
    assert snapshot() == before


def test_missing_lock_file_fails_the_guard(tmp_path: Path) -> None:
    root = planted_repository(tmp_path, lock=False)
    assert unrecorded_pins(root) == [f"{LOCK_FILE} is missing"]
