# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The release documents do what they say (issue #12, part 2; moved here by #325).

``docs/gate-snippet.md``'s commit gate checks the wheel's SHA-256 on every run, and a mismatch
stops it before anything runs. ``docs/claude-code-routing.md``'s deny rules each match the
installer command they name, and none of them blocks the commands the allow rules let through.
No allow rule lets a ``uvx`` call of Guardian through, and every one starts with the command
name: nothing comes before it, neither a wildcard nor a launcher (#198). The ``Edit`` rules for
Guardian's own files start ``//``, so they match wherever the session starts (#213). Parts 3, 4
and 6 say that a session started in a subfolder loads neither the rules nor the hook, and name
the same two settings files that cover it; ``docs/authority-patterns.md`` Pattern 1 names the
same Guardian file rules as the routing doc (#215).

The gate doc's CI example cannot be faked by the pull request it checks (#226): every Python call
passes ``-I`` and runs from the runner's temp folder, so a ``pip/``
or ``venv/`` package in the workspace cannot stand in for the real module; the documented
``sha256sum -c`` line checks the wheel before the install and nothing lets a failed check pass;
the one install line takes only the checked wheel, with ``--no-deps``; and the checks
``tests/unit/test_release_workflow.py`` runs on ``release.yml`` that fit a pull-request check
(pinned ``uses:``, no ``${{ }}`` inside ``run:``) hold, with read-only permissions and no
``pull_request_target``. Each check returns the problems it finds; the doc must give none, and a
planted copy (the doc with one exact substitution) must give one.

Every test reads the documents, so they carry ``doc_content``. None reaches the network: the
gate runs with stand-in ``gh`` and ``uvx`` programs that only record their calls.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.unit.test_release_workflow import (
    Workflow,
    expressions_in_run,
    pin_comment_problems,
    read_workflow,
    unpinned_uses,
)

pytestmark = [pytest.mark.integration, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
GATE_DOC = REPO / "docs" / "gate-snippet.md"
ROUTING_DOC = REPO / "docs" / "claude-code-routing.md"
AUTHORITY_DOC = REPO / "docs" / "authority-patterns.md"

# The two settings files Claude Code reads in a session started in a subfolder: the local file
# from the repository root, and the user's own (#213, #215, plan §8 fact 43).
SUBFOLDER_SETTINGS = (".claude/settings.local.json", "~/.claude/settings.json")

_SHA_LINE = re.compile(r"^GUARDIAN_SHA256=.*$", re.M)
_WHEEL = "ssc_guardian-1.0.1-py3-none-any.whl"

# The one deny set for Guardian's exception commands, in `*` syntax, that both Claude Code pages
# give (#232): each command started as the installed command, through `uvx --from`, through
# `uv tool run --from` (uvx's long form, #292), and as `python -m ssc_guardian`.
GUARDIAN_DENY = (
    "Bash(ssc-guardian override add)",
    "Bash(ssc-guardian override add *)",
    "Bash(ssc-guardian acknowledge *)",
    "Bash(uvx --from * ssc-guardian override add)",
    "Bash(uvx --from * ssc-guardian override add *)",
    "Bash(uvx --from * ssc-guardian acknowledge *)",
    "Bash(uv tool run --from * ssc-guardian override add)",
    "Bash(uv tool run --from * ssc-guardian override add *)",
    "Bash(uv tool run --from * ssc-guardian acknowledge *)",
    "Bash(* -m ssc_guardian override add)",
    "Bash(* -m ssc_guardian override add *)",
    "Bash(* -m ssc_guardian acknowledge *)",
)
# The deny rules plan §4 names (part 3 of the routing section).
REQUIRED_DENY = (
    "Bash(pip install *)",
    "Bash(pip3 install *)",
    "Bash(* -m pip install *)",
    "Bash(*/bin/pip* install *)",
    "Bash(uv pip install *)",
    "Bash(uv add *)",
    "Bash(uv tool install *)",
    "Bash(pipx install *)",
    "Bash(pipx run *)",
    *GUARDIAN_DENY,
    "Edit(//**/.ssc-guardian.toml)",
    "Edit(//**/.ssc-guardian-overrides.toml)",
    "Edit(//**/.ssc-guardian.lock)",
    "Edit(~/.config/ssc-guardian/**)",
)
# Guardian's own file names. Claude Code anchors a single leading `/` at the session's primary
# working directory, not the repository root, and a bare name only at or below it; only a `//`
# rule matches the file wherever the session starts (#213, plan §8 fact 43).
GUARDIAN_FILES = (".ssc-guardian.toml", ".ssc-guardian-overrides.toml", ".ssc-guardian.lock")
_EDIT_RULE = re.compile(r"Edit\([^)`]*\)")
# Only the installed Guardian is pre-approved: a `uvx --from *` allow rule would let an agent run
# code from any package name or Git URL without asking (#198, owner ruling of 2026-11-11).
REQUIRED_ALLOW = (
    "Bash(ssc-guardian install *)",
    "Bash(ssc-guardian check *)",
)
# Installer commands from part 1 of the routing section, in the forms an agent types them.
INSTALLERS = (
    "pip install requests",
    "pip3 install requests",
    "python -m pip install requests",
    "python3 -m pip install -U requests",
    ".venv/bin/pip install requests",
    "/usr/local/bin/pip3 install requests",
    "uv pip install requests",
    "uv add requests",
    "uv tool install ruff",
    "pipx install ruff",
    "pipx run ruff",
    "PIP_INDEX_URL=https://example.invalid/simple pip install requests",
    "cd app && pip install requests",
    "ssc-guardian override add",
    "ssc-guardian acknowledge example/action",
)
# The exception commands in each of the four spellings the deny rules cover (#232, #292).
EXCEPTION_CALLS = {
    "installed": ("ssc-guardian override add", "ssc-guardian override add --yes", "ssc-guardian acknowledge a/b"),
    "uvx --from": (
        f"uvx --from ./{_WHEEL} ssc-guardian override add",
        "uvx --from git+https://example.invalid/x ssc-guardian override add --yes",
        f"uvx --from ./{_WHEEL} ssc-guardian acknowledge a/b",
    ),
    "uv tool run --from": (
        f"uv tool run --from ./{_WHEEL} ssc-guardian override add",
        "uv tool run --from git+https://example.invalid/x ssc-guardian override add --yes",
        f"uv tool run --from ./{_WHEEL} ssc-guardian acknowledge a/b",
    ),
    "python -m": (
        "python -m ssc_guardian override add",
        "python3 -m ssc_guardian override add --yes",
        ".venv/bin/python3.11 -m ssc_guardian acknowledge a/b",
    ),
}
ALLOWED = (
    "ssc-guardian install --venv .venv requests",
    "ssc-guardian check --repo . --json",
)
# uvx calls of Guardian, which must ask each time: from the pinned wheel, from any source, and with
# an extra package pulled in beside it; also in uvx's long form, `uv tool run` (#292).
UVX_CALLS = (
    f"uvx --from ./{_WHEEL} ssc-guardian check --repo .",
    f"uvx --from ./{_WHEEL} ssc-guardian install --venv .venv requests",
    "uvx --from git+https://example.invalid/x ssc-guardian check .",
    f"uvx --from ./{_WHEEL} --with evil ssc-guardian check .",
    "uvx --from evil-package ssc-guardian install --venv .venv requests",
    "uvx ssc-guardian check .",
    f"uv tool run --from ./{_WHEEL} ssc-guardian check --repo .",
    "uv tool run --from git+https://example.invalid/x ssc-guardian install --venv .venv requests",
    "uv tool run ssc-guardian check .",
)

_FAKE_GH = """#!/bin/sh
echo "gh $*" >> "$GATE_LOG"
while [ $# -gt 0 ]; do
    if [ "$1" = "-p" ]; then cp "$GATE_SOURCE" "./$2"; fi
    shift
done
"""
_FAKE_UVX = """#!/bin/sh
echo "uvx $*" >> "$GATE_LOG"
"""


def _fenced(text: str, language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", text, re.S)


# --- the gate snippet -----------------------------------------------------------


def _gate_script(sha: str) -> str:
    """The doc's commit gate with *sha* as the pinned SHA-256."""
    blocks = [b for b in _fenced(GATE_DOC.read_text(encoding="utf-8"), "sh") if b.startswith("#!/bin/sh")]
    assert len(blocks) == 1, "docs/gate-snippet.md must hold exactly one gate script"
    script, count = _SHA_LINE.subn(f'GUARDIAN_SHA256="{sha}"', blocks[0])
    assert count == 1, "the gate script must set GUARDIAN_SHA256 on one line"
    return script


class _Gate:
    """A scratch home, repository and PATH in which the doc's gate runs without the network."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.home = root / "home"
        self.repo = root / "repo"
        self.log = root / "calls.log"
        self.source = root / _WHEEL
        for folder in (self.bin, self.home, self.repo):
            folder.mkdir()
        for name, body in (("gh", _FAKE_GH), ("uvx", _FAKE_UVX)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.source.write_bytes(b"a scratch file standing in for the wheel\n")
        self.log.write_text("")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)

    @property
    def cached(self) -> Path:
        return self.home / ".cache" / "ssc-guardian-gate" / "v1.0.1-reference" / _WHEEL

    def run(self, sha: str) -> subprocess.CompletedProcess[str]:
        script = self.root / "pre-commit"
        script.write_text(_gate_script(sha))
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.home),
            "GATE_LOG": str(self.log),
            "GATE_SOURCE": str(self.source),
        }
        return subprocess.run(
            ["/bin/sh", str(script)], cwd=self.repo, env=env, capture_output=True, text=True, check=False
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


def test_gate_snippet_stops_on_hash_mismatch(tmp_path: Path) -> None:
    """A wrong SHA-256 stops the gate before Guardian runs; the right one runs it (control)."""
    gate = _Gate(tmp_path)
    right = hashlib.sha256(gate.source.read_bytes()).hexdigest()
    wrong = hashlib.sha256(b"another file").hexdigest()

    # A pinned hash that does not match the downloaded file: nothing runs after the check.
    stopped = gate.run(wrong)
    assert stopped.returncode == 2, stopped.stderr
    assert "nothing was run" in stopped.stderr
    assert stopped.stdout == ""
    assert gate.calls() == [f"gh release download v1.0.1-reference -R thomascburns/ssc-guardian -p {_WHEEL}"]

    # Control: with the right hash the same gate runs Guardian, so the check above is what stopped it.
    passed = gate.run(right)
    assert passed.returncode == 0, passed.stderr
    assert gate.calls()[-1] == f"uvx --from {gate.cached} ssc-guardian check --repo ."
    assert sum(call.startswith("gh ") for call in gate.calls()) == 1, "the cached wheel is not downloaded again"

    # The hash is checked on every run: a cached file changed later stops the gate too.
    gate.cached.write_bytes(b"tampered after download\n")
    before = gate.calls()
    tampered = gate.run(right)
    assert tampered.returncode == 2
    assert "nothing was run" in tampered.stderr
    assert gate.calls() == before


# --- the CI example (#226) ----------------------------------------------------------

# Each run: step starts again in the workspace, the pull request's own checkout, and
# `python -m X` puts the current folder first on sys.path; `-I` drops it, and PYTHONPATH too
# (an earlier step can set PYTHONPATH through $GITHUB_ENV, so the temp folder alone is not enough).
OUTSIDE_WORKSPACE = "${{ runner.temp }}"
VENV_PYTHON = "$RUNNER_TEMP/ssc-guardian/bin/python"
CHECKED_WHEEL = "$RUNNER_TEMP/$GUARDIAN_WHEEL"
# The hash check, word for word: a commented-out, wrapped (`if …; then`) or `||` form is not it.
HASH_WORDS = ["echo", "$GUARDIAN_SHA256  $GUARDIAN_WHEEL", "|", "sha256sum", "-c", "-"]
# The install line's options, an allowlist: any other option (an index URL, a find-links folder)
# is a problem until a reviewer adds it here.
INSTALL_OPTIONS = frozenset({"--no-deps"})
# Triggers that run the workflow file of the commit being checked, with a read-only token.
CI_TRIGGERS = frozenset({"push", "pull_request", "merge_group", "workflow_dispatch"})
_PYTHON = re.compile(r"^python(?:3(?:\.\d+)?)?$")
# Interpreter options that take the next word as their value (`-W -I` sets no isolation).
_VALUE_OPTIONS = ("-W", "-X")
# Allowlists of keys. Anything else could let a failed check pass or skip the job, and a skipped
# job counts as a passing required check: shell, env, continue-on-error, if, defaults.
WORKFLOW_KEYS = frozenset({"name", "on", "permissions", "jobs"})
JOB_KEYS = frozenset({"runs-on", "env", "steps", "permissions", "timeout-minutes"})
JOB_ENV = frozenset({"GUARDIAN_TAG", "GUARDIAN_WHEEL", "GUARDIAN_SHA256"})
CHECK_STEP_KEYS = frozenset({"name", "run"})
INSTALL_STEP_KEYS = frozenset({"name", "working-directory", "run"})
# The step that runs Guardian (#258): its exit code is the build's verdict, so it runs in one
# fixed form. Any other key (continue-on-error, if, shell) or env name, a second command, `||`
# or `set +` could let the job pass without the check.
VENV_FOLDER = "$RUNNER_TEMP/ssc-guardian"
GUARDIAN_WORDS = [f"{VENV_FOLDER}/bin/ssc-guardian", "check", "--repo", "."]
GUARDIAN_STEP_KEYS = frozenset({"name", "env", "run"})
GUARDIAN_STEP_ENV = frozenset({"GITHUB_TOKEN"})

FIXED_INSTALL = (
    "      - name: Install ssc-guardian into its own venv\n"
    "        working-directory: ${{ runner.temp }}\n"
    "        run: |\n"
    '          python -I -m venv "$RUNNER_TEMP/ssc-guardian"\n'
    '          "$RUNNER_TEMP/ssc-guardian/bin/python" -I -m pip install --no-deps "$RUNNER_TEMP/$GUARDIAN_WHEEL"\n'
)
# The step as it stood before #226: it ran in the workspace with no `-I`.
UNFIXED_INSTALL = (
    "      - name: Install ssc-guardian into its own venv\n"
    "        run: |\n"
    '          python -m venv "$RUNNER_TEMP/ssc-guardian"\n'
    '          "$RUNNER_TEMP/ssc-guardian/bin/python" -m pip install --no-deps "$RUNNER_TEMP/$GUARDIAN_WHEEL"\n'
)
HASH_LINE = '          echo "$GUARDIAN_SHA256  $GUARDIAN_WHEEL" | sha256sum -c -\n'
INSTALL_LINE = (
    '          "$RUNNER_TEMP/ssc-guardian/bin/python" -I -m pip install --no-deps "$RUNNER_TEMP/$GUARDIAN_WHEEL"\n'
)
GUARDIAN_HEAD = "      - name: Check the repository\n"
GUARDIAN_TOKEN = "          GITHUB_TOKEN: ${{ github.token }}\n"
GUARDIAN_LINE = '          "$RUNNER_TEMP/ssc-guardian/bin/ssc-guardian" check --repo .\n'
GUARDIAN_STEP = f"{GUARDIAN_HEAD}        env:\n{GUARDIAN_TOKEN}        run: |\n{GUARDIAN_LINE}"


def _ci_example(text: str | None = None) -> Workflow:
    """The gate doc's CI example (or *text*'s), read with Guardian's own YAML reader."""
    doc = GATE_DOC.read_text(encoding="utf-8") if text is None else text
    blocks = _fenced(doc, "yaml")
    assert len(blocks) == 1, "docs/gate-snippet.md must hold exactly one CI example"
    return read_workflow(blocks[0], f"{GATE_DOC}: CI example")


def _planted_ci(*substitutions: tuple[str, str]) -> Workflow:
    """The CI example after exact substitutions, each made only where its text occurs once."""
    doc = GATE_DOC.read_text(encoding="utf-8")
    for old, new in substitutions:
        assert doc.count(old) == 1, f"the planted text must occur exactly once: {old!r}"
        doc = doc.replace(old, new)
    return _ci_example(doc)


def _ci_jobs(wf: Workflow) -> dict[str, dict[str, Any]]:
    jobs = wf.doc.get("jobs")
    assert isinstance(jobs, dict), "the CI example has no jobs mapping"
    return jobs


def _ci_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps") or []
    assert isinstance(steps, list)
    return steps


def _step_lines(step: dict[str, Any]) -> list[str]:
    """A step's run: script as logical lines (backslash continuations joined)."""
    run = step.get("run")
    if not isinstance(run, str):
        return []
    return [line.strip() for line in run.replace("\\\n", " ").splitlines() if line.strip()]


def _words(line: str) -> list[str] | None:
    """*line* split as the shell would, without its comment; None when it cannot be split. A ``#``
    inside a word starts a comment for shlex but not for bash (``-c -#|| true``), so it is None."""
    if re.search(r"\S#", line):
        return None
    try:
        return shlex.split(line, comments=True)
    except ValueError:
        return None


def _python_calls(line: str) -> list[list[str]] | None:
    """The interpreter options of each Python call on *line*: the words between the interpreter
    and ``-m``, ``-c`` or the script, a value-taking option keeping only its own name. None when
    the line cannot be split, or names Python more often than it holds calls this can read
    (``bash -c 'python …'``)."""
    words = _words(line)
    if words is None:
        return None
    calls = []
    for index, word in enumerate(words):
        if _PYTHON.match(word.rsplit("/", 1)[-1]):
            options: list[str] = []
            rest = iter(words[index + 1 :])
            for option in rest:
                if option in ("-m", "-c") or not option.startswith("-"):
                    break
                options.append(option)
                if option in _VALUE_OPTIONS:
                    next(rest, None)
            calls.append(options)
    if sum(word.count("python") for word in words) != len(calls):
        return None
    return calls


def _outside_workspace(step: dict[str, Any]) -> bool:
    folder = str(step.get("working-directory", ""))
    inside = folder == OUTSIDE_WORKSPACE or folder.startswith(f"{OUTSIDE_WORKSPACE}/")
    return inside and ".." not in folder


def workspace_python_problems(wf: Workflow) -> list[str]:
    """Every Python call passes ``-I`` and runs from the runner's temp folder, and its step never
    changes folder (a ``cd`` can lead back into the workspace). A line that
    names Python in a way this cannot read is a problem too (fail closed)."""
    problems: list[str] = []
    for name, job in _ci_jobs(wf).items():
        for number, step in enumerate(_ci_steps(job), 1):
            runs_python = False
            for line in _step_lines(step):
                calls = _python_calls(line)
                if calls is None:
                    runs_python = True
                    problems.append(f"{name}: step {number}: cannot read the Python call in: {line}")
                    continue
                runs_python = runs_python or bool(calls)
                problems += [f"{name}: step {number}: Python call without -I: {line}" for o in calls if "-I" not in o]
            if not runs_python:
                continue
            if not _outside_workspace(step):
                problems.append(f"{name}: step {number}: runs Python but not from {OUTSIDE_WORKSPACE}")
            moves = sorted({w for line in _step_lines(step) for w in _words(line) or [] if w in ("cd", "pushd")})
            if moves:
                problems.append(f"{name}: step {number}: {', '.join(moves)} can lead back into the workspace")
    return problems


def _ordered_lines(job: dict[str, Any]) -> list[tuple[int, dict[str, Any], str]]:
    return [(number, step, line) for number, step in enumerate(_ci_steps(job), 1) for line in _step_lines(step)]


def _is_install(words: list[str]) -> bool:
    """A line that names ``install`` or runs pip under any spelling counts as an install."""
    return "install" in words or any(word.rsplit("/", 1)[-1].startswith("pip") for word in words)


def wheel_hash_problems(wf: Workflow) -> list[str]:
    """The documented ``sha256sum -c`` line checks the wheel against GUARDIAN_SHA256 before the
    install, under the default shell (``bash -e``, which stops at a failed line), and nothing lets
    a failed check pass: any other line naming ``sha256sum`` (commented out, wrapped in ``if``, or
    with ``||``) is a problem, no ``set +`` comes before it, and, as for the macOS gitleaks step
    (#245), allowlists of workflow, job and step keys leave no room for a ``shell:``,
    ``continue-on-error``, a job ``if:``, ``defaults`` or an env such as ``BASH_ENV``."""
    problems: list[str] = []
    extra = sorted(set(wf.doc) - WORKFLOW_KEYS)
    if extra:
        problems.append(f"the workflow sets {', '.join(extra)}, which may let a failed check pass")
    for name, job in _ci_jobs(wf).items():
        extra = sorted(set(job) - JOB_KEYS)
        if extra:
            problems.append(f"{name}: job {', '.join(extra)} may let the job pass without the check")
        env = job.get("env") or {}
        names = sorted(env) if isinstance(env, dict) else [repr(env)]
        problems += [f"{name}: job env {key} is not a GUARDIAN_ setting" for key in names if key not in JOB_ENV]
        lines = _ordered_lines(job)
        words = [_words(line) for _, _, line in lines]
        checks = [index for index, split in enumerate(words) if split == HASH_WORDS]
        installs = [index for index, split in enumerate(words) if split is None or _is_install(split)]
        problems += [
            f"{name}: step {number}: not the documented check: {line}"
            for (number, _, line), split in zip(lines, words, strict=True)
            if "sha256sum" in line and split != HASH_WORDS
        ]
        if not installs:
            continue
        if not checks:
            problems.append(f"{name}: no sha256sum -c check of the wheel")
            continue
        if min(checks) > min(installs):
            problems.append(f"{name}: the wheel is installed before its sha256sum -c check")
        for index in checks:
            number, step, line = lines[index]
            if any(other.startswith("set +") for _, other_step, other in lines if other_step is step):
                problems.append(f"{name}: step {number}: set + turns off bash -e before the check")
        for index, allowed in [(i, CHECK_STEP_KEYS) for i in checks] + [(i, INSTALL_STEP_KEYS) for i in installs]:
            number, step, _ = lines[index]
            extra = sorted(set(step) - allowed)
            if extra:
                problems.append(f"{name}: step {number}: {', '.join(extra)} may let a failed check pass")
    return sorted(set(problems))


def install_line_problems(wf: Workflow) -> list[str]:
    """One install line, ``<venv python> -I -m pip install``, of the checked wheel only, with
    ``--no-deps`` and no option off the list. Any line that names ``install`` or runs pip under
    any spelling counts, and so does a line that cannot be split."""
    problems: list[str] = []
    installs: list[tuple[str, list[str]]] = []
    for job in _ci_jobs(wf).values():
        for _, _, line in _ordered_lines(job):
            words = _words(line)
            if words is None:
                problems.append(f"cannot read the line: {line}")
            elif _is_install(words):
                installs.append((line, words))
    if len(installs) != 1:
        problems.append(f"{len(installs)} install lines, not one")
    for line, words in installs:
        start = words.index("install") if "install" in words else len(words)
        if words[:start] != [VENV_PYTHON, "-I", "-m", "pip"]:
            problems.append(f"the install is not {VENV_PYTHON} -I -m pip install: {line}")
        after = words[start + 1 :]
        options = [word for word in after if word.startswith("-")]
        targets = [word for word in after if not word.startswith("-")]
        if "--no-deps" not in options:
            problems.append(f"pip install without --no-deps: {line}")
        problems += [
            f"pip install option {option} is not on the list" for option in options if option not in INSTALL_OPTIONS
        ]
        if targets != [CHECKED_WHEEL]:
            problems.append(f"pip install takes {targets}, not the checked wheel {CHECKED_WHEEL}")
    return problems


def ci_permission_problems(wf: Workflow) -> list[str]:
    """The top level reads only, and no job asks for more."""
    problems: list[str] = []
    if wf.doc.get("permissions") != {"contents": "read"}:
        problems.append(f"top-level permissions are {wf.doc.get('permissions')!r}, not contents: read")
    for name, job in _ci_jobs(wf).items():
        perms = job.get("permissions")
        if perms is None:
            continue
        if not isinstance(perms, dict):
            problems.append(f"{name}: permissions {perms!r} are not a per-scope mapping")
            continue
        problems += [f"{name}: {scope}: {level}" for scope, level in perms.items() if level not in ("read", "none")]
    return problems


def ci_trigger_problems(wf: Workflow) -> list[str]:
    """It runs on pull requests, and only on triggers that run the checked commit's own workflow
    with a read-only token: no ``pull_request_target`` or ``workflow_run``."""
    on = wf.doc.get("on")
    if not isinstance(on, dict):
        return [f"triggers {on!r} are not a mapping"]
    problems = [f"trigger {key} is not allowed" for key in on if key not in CI_TRIGGERS]
    if "pull_request" not in on:
        problems.append("no pull_request trigger, so it cannot be a required check on pull requests")
    return problems


def _runs_guardian(words: list[str]) -> bool:
    """A line that calls Guardian: its console script under any path or on PATH, or its module.
    The venv folder ``$RUNNER_TEMP/ssc-guardian`` is not a call."""
    return any(
        (word.rsplit("/", 1)[-1] == "ssc-guardian" and word.rstrip("/") != VENV_FOLDER)
        or word.split(".")[0] == "ssc_guardian"
        for word in words
    )


def guardian_step_problems(wf: Workflow) -> list[str]:
    """Exactly one step runs Guardian, after the install step, in one fixed form: its keys are
    within ``name``, ``env`` and ``run``, its env names only ``GITHUB_TOKEN``, and its ``run:`` is
    the one line ``$RUNNER_TEMP/ssc-guardian/bin/ssc-guardian check --repo .``, with no ``||``, no
    ``set +`` and no second command. Every line is split as the shell would; a line that cannot be
    split is a problem (fail closed), so a ``#`` inside a word cannot hide a ``|| true``."""
    problems: list[str] = []
    guardian_steps: list[tuple[str, int, dict[str, Any], list[int]]] = []
    for name, job in _ci_jobs(wf).items():
        installs: list[int] = []
        runs: list[tuple[int, dict[str, Any]]] = []
        for number, step in enumerate(_ci_steps(job), 1):
            runs_guardian = False
            for line in _step_lines(step):
                words = _words(line)
                if words is None:
                    problems.append(f"{name}: step {number}: cannot read the line: {line}")
                    continue
                if _is_install(words):
                    installs.append(number)
                runs_guardian = runs_guardian or _runs_guardian(words)
            if runs_guardian:
                runs.append((number, step))
        guardian_steps += [(name, number, step, installs) for number, step in runs]
    if len(guardian_steps) != 1:
        problems.append(f"{len(guardian_steps)} steps run Guardian, not one")
    call = " ".join(GUARDIAN_WORDS)
    for name, number, step, installs in guardian_steps:
        where = f"{name}: step {number}"
        if not installs or number <= max(installs):
            problems.append(f"{where}: runs Guardian but does not come after the install step")
        extra = sorted(set(step) - GUARDIAN_STEP_KEYS)
        if extra:
            problems.append(f"{where}: {', '.join(extra)} may let the job pass without the check")
        env = step.get("env") or {}
        names = sorted(env) if isinstance(env, dict) else [repr(env)]
        problems += [f"{where}: env {key} is not GITHUB_TOKEN" for key in names if key not in GUARDIAN_STEP_ENV]
        lines = _step_lines(step)
        if len(lines) != 1:
            problems.append(f"{where}: run: holds {len(lines)} lines, not one")
        problems += [
            f"{where}: not the fixed call {call}: {line}"
            for line in lines
            if _words(line) not in (None, GUARDIAN_WORDS)
        ]
    return problems


ALL_CI_CHECKS: tuple[Callable[[Workflow], list[str]], ...] = (
    workspace_python_problems,
    wheel_hash_problems,
    install_line_problems,
    unpinned_uses,
    pin_comment_problems,
    expressions_in_run,
    ci_permission_problems,
    ci_trigger_problems,
    guardian_step_problems,
)


def test_ci_example_runs_python_outside_the_workspace() -> None:
    """Negative: the unfixed step, which ran Python in the workspace without -I, fails the check."""
    wf = _ci_example()
    assert workspace_python_problems(wf) == []
    # The doc does both: the install step runs from the temp folder and each Python call has -I.
    install = next(s for s in _ci_steps(_ci_jobs(wf)["check"]) if "venv" in str(s.get("name")))
    assert install.get("working-directory") == OUTSIDE_WORKSPACE
    calls = [options for line in _step_lines(install) for options in _python_calls(line) or []]
    assert calls == [["-I"], ["-I"]]

    # The planted copy of the step as it stood before #226: both Python calls and the folder.
    venv_line, pip_line = (line.strip() for line in UNFIXED_INSTALL.splitlines()[2:])
    no_temp = "check: step 4: runs Python but not from ${{ runner.temp }}"
    assert workspace_python_problems(_planted_ci((FIXED_INSTALL, UNFIXED_INSTALL))) == [
        f"check: step 4: Python call without -I: {venv_line}",
        f"check: step 4: Python call without -I: {pip_line}",
        no_temp,
    ]
    # A working folder inside the workspace is no defence.
    in_workspace = FIXED_INSTALL.replace(OUTSIDE_WORKSPACE, "${{ github.workspace }}")
    assert workspace_python_problems(_planted_ci((FIXED_INSTALL, in_workspace))) == [no_temp]
    # Each defence is required: the temp folder alone leaves PYTHONPATH (settable through
    # $GITHUB_ENV), and -I alone leaves the step in the workspace.
    temp_only = FIXED_INSTALL.replace(" -I -m", " -m")
    assert len(workspace_python_problems(_planted_ci((FIXED_INSTALL, temp_only)))) == 2
    isolated_only = FIXED_INSTALL.replace("        working-directory: ${{ runner.temp }}\n", "")
    assert workspace_python_problems(_planted_ci((FIXED_INSTALL, isolated_only))) == [no_temp]
    # A cd back into the workspace after the step starts in the temp folder.
    back = FIXED_INSTALL.replace("run: |\n", 'run: |\n          cd "$GITHUB_WORKSPACE"\n')
    assert workspace_python_problems(_planted_ci((FIXED_INSTALL, back))) == [
        "check: step 4: cd can lead back into the workspace"
    ]
    # Edge cases of the reader: a versioned interpreter and a quoted path are calls; -W takes -I
    # as its value, so isolation is off; a Python call it cannot read fails closed.
    assert _python_calls("python3.11 -m venv x") == [[]]
    assert _python_calls('"$RUNNER_TEMP/v/bin/python" -I -m pip install y') == [["-I"]]
    assert _python_calls("python -W -I -m pip install y") == [["-W"]]
    assert _python_calls("ssc-guardian check --repo .") == []
    assert _python_calls('python -I -m pip install "unterminated') is None
    assert _python_calls("python -I -m venv x && bash -c 'python -m venv y'") is None
    wrapped = FIXED_INSTALL.replace('python -I -m venv "$RUNNER_TEMP/ssc-guardian"', "bash -c 'python -I -m venv x'")
    assert workspace_python_problems(_planted_ci((FIXED_INSTALL, wrapped))) == [
        "check: step 4: cannot read the Python call in: bash -c 'python -I -m venv x'"
    ]


def test_ci_example_checks_the_wheel_hash_before_install() -> None:
    """Error path: a copy without the sha256sum -c line, or one that lets it fail, fails the check."""
    assert wheel_hash_problems(_ci_example()) == []

    assert wheel_hash_problems(_planted_ci((HASH_LINE, ""))) == ["check: no sha256sum -c check of the wheel"]
    # Forms that keep the text but not the check: ||, commented out, wrapped in if.
    hash_text = HASH_LINE.strip()
    # The last one: bash reads `-#` as a word, so sha256sum fails and `|| true` swallows it.
    for weakened in (f"{hash_text} || true", f"# {hash_text}", f"if {hash_text}; then :; fi", f"{hash_text}#|| true"):
        assert wheel_hash_problems(_planted_ci((HASH_LINE, f"          {weakened}\n"))) == [
            "check: no sha256sum -c check of the wheel",
            f"check: step 3: not the documented check: {weakened}",
        ], weakened
    # The check moved after the install: the wheel would be installed unchecked.
    moved = wheel_hash_problems(_planted_ci((HASH_LINE, ""), (INSTALL_LINE, INSTALL_LINE + HASH_LINE)))
    assert "check: the wheel is installed before its sha256sum -c check" in moved
    unset = HASH_LINE.replace("          echo", "          set +e\n          echo")
    assert wheel_hash_problems(_planted_ci((HASH_LINE, unset))) == [
        "check: step 3: set + turns off bash -e before the check"
    ]
    # Step keys, defaults and env that could let a failed check through (#245's list).
    step = "      - name: Download and verify ssc-guardian\n"
    for key in ("continue-on-error: true", "shell: bash {0}", "env:\n          BASH_ENV: ./no-errexit.sh"):
        planted = wheel_hash_problems(_planted_ci((step, f"{step}        {key}\n")))
        assert planted == [f"check: step 3: {key.split(':')[0]} may let a failed check pass"], key
    install = "      - name: Install ssc-guardian into its own venv\n"
    assert wheel_hash_problems(_planted_ci((install, f"{install}        continue-on-error: true\n"))) == [
        "check: step 4: continue-on-error may let a failed check pass"
    ]
    job_env = "    env:\n      GUARDIAN_TAG: v1.0.1-reference\n"
    assert wheel_hash_problems(_planted_ci((job_env, job_env + "      BASH_ENV: ./no-errexit.sh\n"))) == [
        "check: job env BASH_ENV is not a GUARDIAN_ setting"
    ]
    # Job keys: defaults reach the shell; continue-on-error passes a failed job; an if: skips it,
    # and a skipped job counts as a passing required check.
    runs_on = "    runs-on: ubuntu-latest\n"
    for key in (
        "defaults:\n      run:\n        shell: bash {0}",
        "continue-on-error: true",
        "if: github.event_name != 'pull_request'",
    ):
        planted = wheel_hash_problems(_planted_ci((runs_on, f"{runs_on}    {key}\n")))
        assert planted == [f"check: job {key.split(':')[0]} may let the job pass without the check"], key
    top = "permissions:\n  contents: read\n"
    assert wheel_hash_problems(_planted_ci((top, top + "\nenv:\n  BASH_ENV: ./no-errexit.sh\n"))) == [
        "the workflow sets env, which may let a failed check pass"
    ]


def test_ci_example_installs_with_no_deps() -> None:
    """Edge case: dropping --no-deps, installing from an index or adding an index fails the check."""
    assert install_line_problems(_ci_example()) == []

    dropped = INSTALL_LINE.replace(" --no-deps", "")
    assert install_line_problems(_planted_ci((INSTALL_LINE, dropped))) == [
        f"pip install without --no-deps: {dropped.strip()}"
    ]
    by_name = INSTALL_LINE.replace(f'"{CHECKED_WHEEL}"', "ssc-guardian")
    assert install_line_problems(_planted_ci((INSTALL_LINE, by_name))) == [
        f"pip install takes ['ssc-guardian'], not the checked wheel {CHECKED_WHEEL}"
    ]
    extra = INSTALL_LINE.replace("--no-deps", "--no-deps --extra-index-url=https://example.invalid/simple")
    assert install_line_problems(_planted_ci((INSTALL_LINE, extra))) == [
        "pip install option --extra-index-url=https://example.invalid/simple is not on the list"
    ]
    # A second install beside the real one, under spellings a `pip install` search misses.
    for second in (f'"{VENV_PYTHON}" -I -m pip -q install evil-pkg', '"$RUNNER_TEMP/ssc-guardian/bin/pip3" install x'):
        problems = install_line_problems(_planted_ci((INSTALL_LINE, f"{INSTALL_LINE}          {second}\n")))
        assert problems[0] == "2 install lines, not one", second
        assert f"the install is not {VENV_PYTHON} -I -m pip install: {second}" in problems
    # A `#` inside a word is no comment to bash: the line cannot be read, so it fails closed.
    hidden = INSTALL_LINE.rstrip("\n") + "#|| pip install ssc-guardian\n"
    assert install_line_problems(_planted_ci((INSTALL_LINE, hidden))) == [
        f"cannot read the line: {hidden.strip()}",
        "0 install lines, not one",
    ]
    # The install without -I.
    plain = INSTALL_LINE.replace(" -I -m pip", " -m pip")
    assert install_line_problems(_planted_ci((INSTALL_LINE, plain))) == [
        f"the install is not {VENV_PYTHON} -I -m pip install: {plain.strip()}"
    ]


def test_ci_example_pins_actions_and_limits_permissions() -> None:
    """Negative: an unpinned uses:, write-all, a job write scope or pull_request_target fails."""
    wf = _ci_example()
    for check in (unpinned_uses, pin_comment_problems, expressions_in_run, ci_permission_problems, ci_trigger_problems):
        assert check(wf) == [], check.__name__

    checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
    assert unpinned_uses(_planted_ci((checkout, "actions/checkout@v7"))) == ["check: actions/checkout@v7"]
    # A full SHA that is not the reviewed pin, or a reviewed pin without its version comment.
    other_sha = checkout.replace("3d3c42e5", "0000000a")
    assert unpinned_uses(_planted_ci((checkout, other_sha))) == []
    assert len(pin_comment_problems(_planted_ci((checkout, other_sha)))) == 1
    assert len(pin_comment_problems(_planted_ci((checkout, checkout.removesuffix(" # v7.0.1"))))) == 1
    write_all = _planted_ci(("permissions:\n  contents: read\n", "permissions: write-all\n"))
    assert ci_permission_problems(write_all) == ["top-level permissions are 'write-all', not contents: read"]
    runs_on = "    runs-on: ubuntu-latest\n"
    job_write = _planted_ci((runs_on, runs_on + "    permissions:\n      contents: write\n"))
    assert ci_permission_problems(job_write) == ["check: contents: write"]
    target = ci_trigger_problems(_planted_ci(("  pull_request:\n", "  pull_request_target:\n")))
    assert target == [
        "trigger pull_request_target is not allowed",
        "no pull_request trigger, so it cannot be a required check on pull requests",
    ]
    check_line = 'bin/ssc-guardian" check --repo .\n'
    expression = _planted_ci((check_line, 'bin/ssc-guardian" check --repo ${{ github.workspace }}\n'))
    assert expressions_in_run(expression) == ["check: step 5: ${{ }} inside run"]


def _all_ci_problems(wf: Workflow) -> set[str]:
    return {problem for check in ALL_CI_CHECKS for problem in check(wf)}


def test_ci_example_runs_guardian_in_one_fixed_step() -> None:
    """Negative: a copy that lets the Guardian step pass without its verdict fails the check."""
    assert guardian_step_problems(_ci_example()) == []

    call = " ".join(GUARDIAN_WORDS)
    step = "check: step 5"
    planted: list[tuple[tuple[tuple[str, str], ...], list[str]]] = [
        # A second command on the call's line, or a call that is not the venv's console script.
        *(
            (((GUARDIAN_LINE, f"          {line}\n"),), [f"{step}: not the fixed call {call}: {line}"])
            for line in (
                f"{GUARDIAN_LINE.strip()} || true",
                f"{GUARDIAN_LINE.strip()}; exit 0",
                "ssc-guardian check --repo .",
            )
        ),
        # A second command after the call, or `set +e` before it.
        (
            ((GUARDIAN_LINE, f"{GUARDIAN_LINE}          exit 0\n"),),
            [f"{step}: run: holds 2 lines, not one", f"{step}: not the fixed call {call}: exit 0"],
        ),
        (
            ((GUARDIAN_LINE, f"          set +e\n{GUARDIAN_LINE}"),),
            [f"{step}: run: holds 2 lines, not one", f"{step}: not the fixed call {call}: set +e"],
        ),
        # Step keys that let the job pass without the verdict: a failed step passes, or it is skipped.
        (
            ((GUARDIAN_HEAD, f"{GUARDIAN_HEAD}        continue-on-error: true\n"),),
            [f"{step}: continue-on-error may let the job pass without the check"],
        ),
        (
            ((GUARDIAN_HEAD, f"{GUARDIAN_HEAD}        if: github.event_name == 'push'\n"),),
            [f"{step}: if may let the job pass without the check"],
        ),
        # An env name beyond the token: BASH_ENV runs a file before the call.
        (
            ((GUARDIAN_TOKEN, f"{GUARDIAN_TOKEN}          BASH_ENV: ./no-errexit.sh\n"),),
            [f"{step}: env BASH_ENV is not GITHUB_TOKEN"],
        ),
        # The step removed, run twice, or moved before the install.
        (((GUARDIAN_STEP, ""),), ["0 steps run Guardian, not one"]),
        (
            ((GUARDIAN_STEP, GUARDIAN_STEP + GUARDIAN_STEP.replace("Check the", "Check again the")),),
            ["2 steps run Guardian, not one"],
        ),
        (
            ((GUARDIAN_STEP, ""), (FIXED_INSTALL, GUARDIAN_STEP + FIXED_INSTALL)),
            ["check: step 4: runs Guardian but does not come after the install step"],
        ),
    ]
    for substitutions, expected in planted:
        wf = _planted_ci(*substitutions)
        assert guardian_step_problems(wf) == expected, substitutions
        # The check is one of the CI checks, so the full set reports these problems too.
        assert set(expected) <= _all_ci_problems(wf), substitutions


def test_ci_example_guardian_step_reader_fails_closed() -> None:
    """Error path: a Guardian line that cannot be split is reported, never read as clean."""
    # An unbalanced quote, and a `#` inside a word: shlex reads the second as the plain call with a
    # comment, but bash runs `.#` as the folder and `|| true` swallows the failure.
    for line in (
        '"$RUNNER_TEMP/ssc-guardian/bin/ssc-guardian check --repo .',
        f"{GUARDIAN_LINE.strip()}#|| true",
    ):
        assert _words(line) is None, line
        wf = _planted_ci((GUARDIAN_LINE, f"          {line}\n"))
        assert guardian_step_problems(wf) == [
            f"check: step 5: cannot read the line: {line}",
            "0 steps run Guardian, not one",
        ], line
    # The reader's edge cases: the venv folder is not a call; the module and a uvx call are.
    assert not _runs_guardian(["cd", VENV_FOLDER])
    assert not _runs_guardian(["python", "-I", "-m", "venv", f"{VENV_FOLDER}/"])
    assert _runs_guardian(["python", "-I", "-m", "ssc_guardian", "check"])
    assert _runs_guardian(["uvx", "--from", "x", "ssc-guardian", "check"])


def test_ci_example_check_is_idempotent_on_re_run() -> None:
    """Idempotency: two runs give equal results and leave the doc unchanged."""
    before = GATE_DOC.read_bytes()
    first = [check(_ci_example()) for check in ALL_CI_CHECKS]
    second = [check(_ci_example()) for check in ALL_CI_CHECKS]
    assert first == second == [[] for _ in ALL_CI_CHECKS]
    assert _ci_example() == _ci_example()
    assert GATE_DOC.read_bytes() == before


# --- the Claude Code routing rules ------------------------------------------------


def _permissions(text: str | None = None) -> dict[str, list[str]]:
    """The ``permissions`` object of the routing doc's settings example (or of *text*)."""
    doc = ROUTING_DOC.read_text(encoding="utf-8") if text is None else text
    found: list[dict[str, list[str]]] = [
        json.loads(block)["permissions"] for block in _fenced(doc, "json") if '"permissions"' in block
    ]
    assert len(found) == 1, "docs/claude-code-routing.md must hold exactly one permissions example"
    return found[0]


def _rule_table() -> dict[str, str]:
    """Each row of the doc's "What each deny rule stops" table: rule -> command."""
    rows = re.findall(r"^\| `(Bash\(.*?\))` \| `(.*?)` \|$", ROUTING_DOC.read_text(encoding="utf-8"), re.M)
    return dict(rows)


def _command_parts(command: str) -> list[str]:
    """A compound command split into its parts, each without leading variable assignments."""
    parts = re.split(r"\s*(?:&&|\|\||;|\|)\s*", command.strip())
    return [re.sub(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+", "", part) for part in parts if part]


def _matches(rule: str, command: str) -> bool:
    """True when a ``Bash(<pattern>)`` rule matches *command*; ``*`` is a wildcard.

    This is the test's own model of plan §8 fact 42, so the test proves the doc agrees with
    itself under that model, not how Claude Code matches.
    """
    pattern = rule.removeprefix("Bash(").removesuffix(")")
    regex = ".*".join(re.escape(piece) for piece in pattern.split("*"))
    return any(re.fullmatch(regex, part) for part in _command_parts(command))


def _session_anchored(deny: list[str]) -> list[str]:
    """The ``Edit`` rules for a Guardian file that do not start ``//``.

    A single ``/`` anchors at the session's primary working directory and a bare name matches
    only at or below it, so such a rule misses the file in a session started in a subfolder, in
    another worktree or after ``/cd`` (plan §8 fact 43).
    """
    found = []
    for rule in deny:
        path = rule.removeprefix("Edit(").removesuffix(")")
        if rule.startswith("Edit(") and path.endswith(GUARDIAN_FILES) and not path.startswith("//"):
            found.append(rule)
    return found


def _anything_before_command(rule: str) -> bool:
    """True unless a ``Bash(...)`` rule starts with the ``ssc-guardian`` command: anything before
    it, a wildcard or a launcher such as ``uvx``, or no Guardian command at all."""
    pattern = rule.removeprefix("Bash(").removesuffix(")")
    before, found, _ = pattern.partition("ssc-guardian ")
    return not found or before != ""


def test_no_allow_rule_lets_uvx_through() -> None:
    """Negative: no allow rule matches a uvx call of Guardian, from the wheel or any other source."""
    allow = _permissions()["allow"]
    for command in UVX_CALLS:
        allowing = [rule for rule in allow if _matches(rule, command)]
        assert allowing == [], f"{allowing} let {command!r} through without asking"


def test_no_allow_rule_has_a_wildcard_before_the_command() -> None:
    """Edge case: each Bash allow rule starts with the Guardian command, with nothing before it."""
    # The check itself: the rules #198 removed, a leading wildcard and a bare uvx launcher are
    # flagged; a kept rule is not.
    assert _anything_before_command("Bash(uvx --from * ssc-guardian check *)")
    assert _anything_before_command("Bash(uvx --from * ssc-guardian install *)")
    assert _anything_before_command("Bash(* ssc-guardian check *)")
    assert _anything_before_command("Bash(uvx *)")
    assert _anything_before_command("Bash(uvx ssc-guardian check *)")
    assert not _anything_before_command("Bash(ssc-guardian check *)")

    bash_allow = [rule for rule in _permissions()["allow"] if rule.startswith("Bash(")]
    assert bash_allow, "the routing doc's allow list has no Bash rule"
    assert [rule for rule in bash_allow if _anything_before_command(rule)] == []


# --- the subfolder limit (#215) ---------------------------------------------------


def _part(doc: str, number: int) -> str:
    """The text of the routing doc's part *number*, from its heading to the next one."""
    match = re.search(rf"^## {number}\. .*?(?=^## |\Z)", doc, re.M | re.S)
    assert match, f"docs/claude-code-routing.md has no part {number}"
    return match.group(0)


def _subfolder_files(text: str) -> list[str]:
    """The settings files *text* names for a subfolder session; empty unless it names the case."""
    if "subfolder" not in text:
        return []
    return [name for name in SUBFOLDER_SETTINGS if f"`{name}`" in text]


def test_hook_section_names_the_subfolder_limit() -> None:
    """Part 4 says a subfolder session does not run the hook and names the files that cover it."""
    doc = ROUTING_DOC.read_text(encoding="utf-8")
    hook = _part(doc, 4)
    assert "no parent-directory fallback" in " ".join(hook.split()), "part 4 must quote the permissions page"
    # Data integrity: parts 3, 4 and 6 name the same two settings files.
    for number in (3, 4, 6):
        assert _subfolder_files(_part(doc, number)) == list(SUBFOLDER_SETTINGS), f"part {number}"


def test_honest_limit_names_the_subfolder_case() -> None:
    """Part 6 names the subfolder case; a planted copy without that sentence fails the check."""
    doc = ROUTING_DOC.read_text(encoding="utf-8")
    honest = _part(doc, 6)
    assert _subfolder_files(honest) == list(SUBFOLDER_SETTINGS)

    # Error path: remove the sentence that names the case, and the check finds nothing.
    sentence = re.search(r"A session started in a subfolder.*?\.(?=\s|\Z)", honest, re.S)
    assert sentence, "part 6 has no sentence naming a session started in a subfolder"
    planted = doc.replace(sentence.group(0), "")
    assert planted != doc
    assert [name for name in SUBFOLDER_SETTINGS if name in _part(planted, 6)] == []
    assert _subfolder_files(_part(planted, 6)) == []


def _guardian_file_rules(text: str) -> list[str]:
    """The ``Edit`` deny rules for Guardian's own files in *text*'s permissions example."""
    found = [json.loads(block)["permissions"] for block in _fenced(text, "json") if '"permissions"' in block]
    assert len(found) == 1, "each doc must hold exactly one permissions example"
    deny = found[0]["deny"]
    return sorted(rule for rule in deny if rule.startswith("Edit(") and rule.removesuffix(")").endswith(GUARDIAN_FILES))


def test_authority_pattern_matches_routing_rules() -> None:
    """Pattern 1 and the routing doc name the same Guardian file rules and the same settings files."""
    routing = ROUTING_DOC.read_text(encoding="utf-8")
    authority = AUTHORITY_DOC.read_text(encoding="utf-8")
    rules = _guardian_file_rules(routing)
    assert len(rules) == len(GUARDIAN_FILES)
    assert _guardian_file_rules(authority) == rules
    assert _session_anchored(rules) == []
    pattern = authority[authority.index("## Pattern 1") : authority.index("## Pattern 2")]
    assert _subfolder_files(pattern) == list(SUBFOLDER_SETTINGS)
    assert "Branch protection (pattern 2)" in " ".join(pattern.split())

    # Error path: a planted copy with the old session-anchored lock rule no longer matches.
    planted = authority.replace('"Edit(//**/.ssc-guardian.lock)"', '"Edit(**/.ssc-guardian.lock)"')
    assert planted != authority
    assert _guardian_file_rules(planted) != rules
    assert _session_anchored(_guardian_file_rules(planted)) == ["Edit(**/.ssc-guardian.lock)"]


def test_subfolder_checks_are_idempotent() -> None:
    """Idempotency: a second run gives the same result and writes nothing."""
    docs = (ROUTING_DOC, AUTHORITY_DOC)
    before = {path: path.read_bytes() for path in docs}

    def run() -> tuple[list[list[str]], list[str]]:
        routing = ROUTING_DOC.read_text(encoding="utf-8")
        parts = [_subfolder_files(_part(routing, number)) for number in (3, 4, 6)]
        return parts, _guardian_file_rules(AUTHORITY_DOC.read_text(encoding="utf-8"))

    assert run() == run()
    assert {path: path.read_bytes() for path in docs} == before


# --- one deny set on both pages, the floor claim, config.toml readers (#232) -------

CONTRACTS_DOC = REPO / "docs" / "contracts.md"
README_DOC = REPO / "README.md"
COMMANDS_DIR = REPO / "src" / "ssc_guardian" / "commands"
# Each command module and the command it serves; a new module fails the readers test until named.
MODULE_COMMAND = {
    "check_envs": "check",
    "check_repo": "check",
    "protect": "protect",
    "install": "install",
    "pin": "pin",
    "acknowledge": "acknowledge",
    "override_add": "override add",
}
# What loads the workstation settings file, config.toml: directly, or through the repository context.
_LOADS_CONFIG = ("workstation_settings(", "kind=FileKind.WORKSTATION", "load_repository_context(")
_COMMAND_NAME = re.compile(r"`(check|protect|install|pin|acknowledge|override add)\b[^`]*`")


def _guardian_bash_rules(text: str) -> list[str]:
    """The Bash deny rules naming Guardian (``ssc-guardian`` or ``ssc_guardian``) in *text*'s one
    permissions example, sorted."""
    return sorted(_rules_in_page_order(text))


def _rules_in_page_order(text: str) -> list[str]:
    """The Bash deny rules naming Guardian in *text*'s one permissions example, in page order."""
    found = [json.loads(block)["permissions"] for block in _fenced(text, "json") if '"permissions"' in block]
    assert len(found) == 1, "each doc must hold exactly one permissions example"
    return [r for r in found[0]["deny"] if r.startswith("Bash(") and re.search(r"ssc[-_]guardian", r)]


def deny_set_problems(routing: str, authority: str) -> list[str]:
    """The two pages' Guardian Bash rules differ, are not the one set, or use the `:*` syntax."""
    problems: list[str] = []
    rules, pattern = _guardian_bash_rules(routing), _guardian_bash_rules(authority)
    problems += [f"only in docs/claude-code-routing.md: {r}" for r in rules if r not in pattern]
    problems += [f"only in docs/authority-patterns.md: {r}" for r in pattern if r not in rules]
    if rules != sorted(GUARDIAN_DENY):
        problems.append("docs/claude-code-routing.md does not give the one deny set")
    problems += [f"not `*` syntax: {r}" for r in [*rules, *pattern] if ":*" in r]
    return problems


def test_both_pages_name_the_same_bash_deny_rules() -> None:
    routing, authority = ROUTING_DOC.read_text(encoding="utf-8"), AUTHORITY_DOC.read_text(encoding="utf-8")
    assert deny_set_problems(routing, authority) == []
    assert len(GUARDIAN_DENY) == 12
    assert len(_guardian_bash_rules(routing)) == len(_guardian_bash_rules(authority)) == 12
    # Edge case: each page lists the rules in GUARDIAN_DENY's order, so the `uv tool run --from`
    # rules sit right after the `uvx --from` rules (#292); a page with them moved is caught.
    assert _rules_in_page_order(routing) == _rules_in_page_order(authority) == list(GUARDIAN_DENY)
    moved = authority.replace('      "Bash(uv tool run --from * ssc-guardian override add)",\n', "").replace(
        '      "Bash(* -m ssc_guardian acknowledge *)"',
        '      "Bash(* -m ssc_guardian acknowledge *)",\n      "Bash(uv tool run --from * ssc-guardian override add)"',
    )
    assert sorted(_rules_in_page_order(moved)) == sorted(GUARDIAN_DENY)
    assert _rules_in_page_order(moved) != list(GUARDIAN_DENY)
    # Negative control: a planted extra rule on one page is rejected (fail-closed either way).
    extra = '"Bash(* -m ssc_guardian acknowledge *)",\n      "Bash(ssc-guardian override *)"'
    planted = authority.replace('"Bash(* -m ssc_guardian acknowledge *)"', extra)
    assert planted != authority
    assert deny_set_problems(routing, planted) == ["only in docs/authority-patterns.md: Bash(ssc-guardian override *)"]
    # A rule dropped from one page, and the old `:*` syntax, are rejected too.
    dropped = authority.replace('      "Bash(uvx --from * ssc-guardian acknowledge *)",\n', "")
    assert dropped != authority
    assert deny_set_problems(routing, dropped) == [
        "only in docs/claude-code-routing.md: Bash(uvx --from * ssc-guardian acknowledge *)"
    ]
    # One of the `uv tool run --from` rules (#292) dropped from one page is reported too.
    dropped_long = authority.replace('      "Bash(uv tool run --from * ssc-guardian override add)",\n', "")
    assert dropped_long != authority
    assert deny_set_problems(routing, dropped_long) == [
        "only in docs/claude-code-routing.md: Bash(uv tool run --from * ssc-guardian override add)"
    ]
    colon = authority.replace('"Bash(ssc-guardian acknowledge *)"', '"Bash(ssc-guardian acknowledge:*)"')
    assert "not `*` syntax: Bash(ssc-guardian acknowledge:*)" in deny_set_problems(routing, colon)


def test_deny_rules_cover_uvx_and_python_m_forms() -> None:
    # Edge case: each way to start Guardian is matched on both pages, under the test's rule model.
    for doc in (ROUTING_DOC, AUTHORITY_DOC):
        rules = _guardian_bash_rules(doc.read_text(encoding="utf-8"))
        for form, commands in EXCEPTION_CALLS.items():
            for command in commands:
                assert any(_matches(rule, command) for rule in rules), f"{doc.name}: {form}: {command!r}"
        # The checks Guardian allows are never denied.
        for command in ALLOWED:
            assert not any(_matches(rule, command) for rule in rules), f"{doc.name} denies {command!r}"
    # Without the `python -m` rules, that form gets through.
    without = [r for r in GUARDIAN_DENY if "-m ssc_guardian" not in r]
    assert not any(_matches(r, "python3 -m ssc_guardian override add") for r in without)
    # Without the `uv tool run --from` rules (#292), that form gets through.
    without = [r for r in GUARDIAN_DENY if "uv tool run" not in r]
    assert not any(_matches(r, f"uv tool run --from ./{_WHEEL} ssc-guardian override add") for r in without)


# The four spellings the routing page's coverage sentence names (#292).
COVERED_SPELLINGS = ("the installed command", "`uvx --from`", "`uv tool run --from`", "`python -m ssc_guardian`")


# What part 3 must say about the spellings the rules do not match.
NOT_MATCHED = (
    "four spellings",
    "Options placed before `--from`",
    "a full path to the program",
    "other spellings are not matched",
)
# Claims part 3 must not make: every way to start Guardian, and a hook that catches the exception
# commands (part 4's hook matches only package installers).
OVERCLAIMS = ("three ways", "every way", "catches more of them")


def coverage_problems(routing: str) -> list[str]:
    """Part 3's coverage sentence for the exception commands overclaims or misses a spelling."""
    text = " ".join(_part(routing, 3).split())
    problems = [f"part 3 says {claim!r}" for claim in OVERCLAIMS if claim in text]
    problems += [f"part 3 does not name {spelling}" for spelling in COVERED_SPELLINGS if spelling not in text]
    problems += [f"part 3 does not say {phrase!r}" for phrase in NOT_MATCHED if phrase not in text]
    return problems


def test_coverage_sentence_names_four_spellings() -> None:
    routing = ROUTING_DOC.read_text(encoding="utf-8")
    assert coverage_problems(routing) == []
    new = re.search(r"Their rules cover four spellings:.*?are not matched\.", routing, re.S)
    assert new
    # Negative control: the #232 sentence, put back, is rejected.
    old = (
        "Their rules cover the three ways to start Guardian: the installed command, `uvx --from`, and "
        "`python -m ssc_guardian`."
    )
    planted = routing.replace(new.group(0), old)
    assert planted != routing
    assert coverage_problems(planted) == [
        "part 3 says 'three ways'",
        "part 3 does not name `uv tool run --from`",
        "part 3 does not say 'four spellings'",
        "part 3 does not say 'Options placed before `--from`'",
        "part 3 does not say 'a full path to the program'",
        "part 3 does not say 'other spellings are not matched'",
    ]
    # Error path: a claim that the part 4 hook catches the other spellings is rejected.
    hook = routing.replace(new.group(0), new.group(0)[:-1] + "; the hook in part 4 catches more of them.")
    assert hook != routing
    assert coverage_problems(hook) == ["part 3 says 'catches more of them'"]


def test_deny_set_check_is_idempotent_on_re_run() -> None:
    docs = (ROUTING_DOC, AUTHORITY_DOC)
    before = {path: path.read_bytes() for path in docs}

    def run() -> list[str]:
        return deny_set_problems(*(path.read_text(encoding="utf-8") for path in docs))

    assert run() == run() == []
    assert {path: path.read_bytes() for path in docs} == before


def floor_problems(doc: str) -> list[str]:
    """Parts 1 and 6 of the routing page: each claim that `protect`'s cooldown still holds names uv
    and never pipx, the run forms are named, and pipx is said to get nothing (#232)."""
    problems: list[str] = []
    for number in (1, 6):
        part = " ".join(_part(doc, number).split())
        claims = [c for c in re.split(r"(?<=[.;])\s+", part) if "floor" in c or "still applies" in c]
        if not claims:
            problems.append(f"part {number}: no claim of what still applies")
        for claim in claims:
            if "pipx" in claim:
                problems.append(f"part {number}: the claim names pipx: {claim}")
            if not re.search(r"\buv\b", claim):
                problems.append(f"part {number}: the claim is not limited to uv: {claim}")
        if "`pipx run`" not in part or "nothing applies" not in part:
            problems.append(f"part {number}: does not say `pipx install` and `pipx run` get no cooldown")
    if not all(f"`{form}`" in _part(doc, 1) for form in ("uvx", "uv tool run", "pipx run")):
        problems.append("part 1 does not name the run forms")
    return problems


def test_floor_claim_names_only_uv() -> None:
    doc = ROUTING_DOC.read_text(encoding="utf-8")
    assert floor_problems(doc) == []
    # Error path: a planted floor sentence that names pipx fails, and so does the old blanket claim.
    honest = _part(doc, 6)
    pipx = honest.replace("and uv (`uvx`", "pipx (`pipx run`) and uv (`uvx`")
    assert pipx != honest
    assert floor_problems(doc.replace(honest, pipx))[0].startswith("part 6: the claim names pipx")
    old = re.sub(
        r"Whatever gets past the rules,.*?places you name\.",
        "Whatever gets past the rules, the cooldown that `ssc-guardian protect` wrote remains the floor, "
        "and `ssc-guardian check` reports what arrived.",
        honest,
        flags=re.S,
    )
    assert old != honest
    assert any("not limited to uv" in p for p in floor_problems(doc.replace(honest, old)))


def _doc_readers(text: str) -> tuple[set[str], set[str]]:
    """The commands *text* names before and after its first "not" or "never"."""
    parts = re.split(r"\b(?:not|never)\b", text, maxsplit=1)
    reads, excluded = parts[0], parts[1] if len(parts) > 1 else ""
    return {m.group(1) for m in _COMMAND_NAME.finditer(reads)}, {m.group(1) for m in _COMMAND_NAME.finditer(excluded)}


def published_readers(readme: str, authority: str, contracts: str) -> dict[str, tuple[set[str], set[str]]]:
    """Which commands each published page says read config.toml, and which it says do not."""
    flat = {name: " ".join(text.split()) for name, text in (("readme", readme), ("authority", authority))}
    clauses: dict[str, str] = {}
    match = re.search(r"reads your `~/\.config/ssc-guardian/config\.toml` for (.*?)\. When it checks", flat["readme"])
    clauses["README.md"] = match.group(1) if match else ""
    match = re.search(r"`config\.toml` is read by (.*?);", flat["authority"])
    clauses["docs/authority-patterns.md"] = match.group(1) if match else ""
    row = re.search(r"^\| `config\.toml` \|.*\| ([^|]*) \|$", contracts, re.M)
    clauses["docs/contracts.md"] = row.group(1) if row else ""
    return {name: _doc_readers(clause) for name, clause in clauses.items()}


def config_loaders() -> set[str]:
    """The commands whose module loads config.toml."""
    modules = {p.stem for p in COMMANDS_DIR.glob("*.py") if p.stem != "__init__"}
    assert modules == set(MODULE_COMMAND), "name each command module in MODULE_COMMAND"
    return {
        MODULE_COMMAND[m]
        for m in modules
        if any(marker in (COMMANDS_DIR / f"{m}.py").read_text(encoding="utf-8") for marker in _LOADS_CONFIG)
    }


def test_config_toml_readers_match_the_commands_that_load_it() -> None:
    loaders = config_loaders()
    # Edge case: `override add` never reads config.toml.
    assert "override add" not in loaders
    assert loaders == {"check", "protect", "install", "pin", "acknowledge"}
    pages = published_readers(
        README_DOC.read_text(encoding="utf-8"),
        AUTHORITY_DOC.read_text(encoding="utf-8"),
        CONTRACTS_DOC.read_text(encoding="utf-8"),
    )
    for name, (reads, excluded) in pages.items():
        assert reads == loaders, name
        assert not excluded & loaders, f"{name} says a command that reads config.toml does not"
    # README and contracts also say `override add` does not read it.
    assert pages["README.md"][1] == pages["docs/contracts.md"][1] == {"override add"}
    # Data integrity, negative: the old "every command" wording names no command, so it fails. The
    # README is whitespace-normalized first, so a rewrapped paragraph does not break this control.
    readme = " ".join(README_DOC.read_text(encoding="utf-8").split())
    old = re.sub(
        r"config\.toml` for `check` \(.*?never for `override add`\.", "config.toml` for every command.", readme
    )
    assert old != readme
    assert published_readers(old, "", "")["README.md"][0] != loaders
