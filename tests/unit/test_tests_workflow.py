# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The Tests workflow and its requirements keep their safety properties (#325).

``.github/workflows/tests.yml`` runs the test suite and Guardian's check of this repository on
every push and pull request. It is read with Guardian's own YAML reader, through the helpers
``tests/unit/test_release_workflow.py`` uses for ``release.yml``. Each property is a function
that returns the problems it finds: the real file must give none, and a planted copy (the real
file with one exact substitution, made only after the text it replaces is checked to be there)
must give at least one.

The properties: every ``uses:`` is a reviewed pin at a 40-hex commit SHA with its version in a
comment; the workflow reads only, every checkout takes only ``persist-credentials: false``, and
no ``${{ }}`` expression sits inside a ``run:`` script; each job installs once, from
``requirements-test.txt`` with ``--require-hashes`` and ``--no-deps``, and nothing else installs;
``requirements-test.txt`` pins every package with ``==`` and SHA-256 hashes, pytest among them and
PyYAML not; the Guardian self-check step is there once and cannot pass on failure; the Linux job
always runs and the macOS job runs in the public repository or on a manual run; the Linux job runs
once on each Python version ``pyproject.toml``'s classifiers name, from the ``requires-python``
floor up, and one red version does not cancel the others; and CONTRIBUTING.md gives the commands
the workflow runs, its venv built with a Python at the ``requires-python`` floor or later, never a
bare ``python3`` (Apple's 3.9 on a new Mac, #354), and installing no pip that neither Python's own
bundle nor the hash-locked requirements cover (#368). No network; nothing is written outside
``tmp_path``.
"""

from __future__ import annotations

import itertools
import re
import shlex
import tomllib
from pathlib import Path

import pytest

from tests.unit.test_release_workflow import (
    HASH_OPTION,
    REQUIREMENT,
    Workflow,
    _jobs,
    _run_lines,
    _steps,
    _uses,
    expressions_in_run,
    pin_comment_problems,
    read_workflow,
    unpinned_uses,
)
from tests.unit.test_self_check import STEP_NAME, self_check_problems

# doc_content: one check reads CONTRIBUTING.md.
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
TESTS_WORKFLOW = REPO / ".github" / "workflows" / "tests.yml"
REQUIREMENTS = REPO / "requirements-test.txt"
CONTRIBUTING = REPO / "CONTRIBUTING.md"
PYPROJECT = REPO / "pyproject.toml"
PUBLIC_REPOSITORY = "thomascburns/ssc-guardian"

LINUX_JOB = "tests-linux"
MACOS_JOB = "tests-macos"
MACOS_CONDITION = f"github.repository == '{PUBLIC_REPOSITORY}' || github.event_name == 'workflow_dispatch'"
TRIGGERS = {"push", "pull_request", "workflow_dispatch"}
CHECKOUT_WITH = {"persist-credentials": "false"}
INSTALL = ".venv/bin/python -m pip install --require-hashes --no-deps -r requirements-test.txt"
INSTALLER = re.compile(r"\b(?:pip3?|uv|pipx|easy_install|conda)\b")
# What CONTRIBUTING.md tells a visitor to run; the workflow runs the same install and test with
# setup-python's `python` building the venv (#354: a visitor's bare `python3` may be Apple's 3.9).
VISITOR_VENV = "uv venv --python 3.11 .venv && .venv/bin/python -m ensurepip && "
VISITOR_COMMANDS = (
    f"{VISITOR_VENV}.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-test.txt",
    ".venv/bin/python -m pytest",
)
CONTRIBUTING_SECTION = "## Running the tests"
# A fenced block, backticks or tildes; a line's commands are split at &&, ||, ; and |.
FENCED_BLOCK = re.compile(r"^(```|~~~)[\w-]*\n(.*?)^\1", re.MULTILINE | re.DOTALL)
COMMAND_SEPARATOR = re.compile(r"&&|\|\||[;|]")
NAMED_PYTHON = re.compile(r"^(?:python|cpython-?)?(3\.\d+)(?:\.\d+)?$")
CHECKOUT_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
TEST_STEP = (
    "      - name: Test\n"
    "        env:\n"
    '          SSC_GUARDIAN_REQUIRE_NETWORK: "1"\n'
    "        run: .venv/bin/python -m pytest\n"
)
SELF_CHECK_RUN = ".venv/bin/python -m ssc_guardian check --repo ."
# The Linux job's matrix: one leg per `Programming Language :: Python :: 3.N` classifier.
PYTHON_CLASSIFIER = re.compile(r"^Programming Language :: Python :: (3\.\d+)$")
PYTHON_VERSION = re.compile(r"^3\.\d+$")
PYTHON_FLOOR = re.compile(r"^>=\s*(3\.\d+)$")
MATRIX_VERSION = "${{ matrix.python-version }}"
MATRIX_LINE = '        python-version: ["3.11", "3.12", "3.13"]\n'


def _read(text: str | None = None) -> Workflow:
    return read_workflow(TESTS_WORKFLOW.read_text(encoding="utf-8") if text is None else text, str(TESTS_WORKFLOW))


def _planted(old: str, new: str, *, count: int = 1) -> str:
    """The real workflow's text with its *count* occurrences of *old* replaced by *new*."""
    text = TESTS_WORKFLOW.read_text(encoding="utf-8")
    assert text.count(old) == count, f"expected {old!r} {count} times"
    return text.replace(old, new)


# --- the checks ----------------------------------------------------------------


def pin_problems(wf: Workflow) -> list[str]:
    """Each ``uses:`` is a reviewed pin at a full commit SHA with its version in a comment."""
    return unpinned_uses(wf) + pin_comment_problems(wf)


def privilege_problems(wf: Workflow) -> list[str]:
    """The workflow reads only, every checkout keeps no credentials, and no run script holds ``${{``."""
    problems: list[str] = []
    if wf.doc.get("permissions") != {"contents": "read"}:
        problems.append(f"top-level permissions are {wf.doc.get('permissions')!r}, not contents: read")
    for name, job in _jobs(wf).items():
        if "permissions" in job:
            problems.append(f"{name}: sets its own permissions {job['permissions']!r}")
        for index, step in enumerate(_steps(job), 1):
            if str(step.get("uses", "")).startswith("actions/checkout@") and step.get("with") != CHECKOUT_WITH:
                problems.append(f"{name}: step {index}: checkout takes {step.get('with')!r}, not {CHECKOUT_WITH!r}")
    return problems + expressions_in_run(wf)


def install_problems(wf: Workflow) -> list[str]:
    """Each job installs exactly once, from the hash-locked requirements-test.txt, and nothing else installs."""
    problems: list[str] = []
    for name, job in _jobs(wf).items():
        installs = [line for line in _run_lines(job) if INSTALLER.search(line)]
        if installs != [INSTALL]:
            problems.append(f"{name}: installs with {installs!r}, not once with {INSTALL!r}")
    return problems


def requirements_problems(text: str) -> list[str]:
    """Every requirement is pinned with ``==`` and carries SHA-256 hashes only; pytest is there and PyYAML
    is not, since no published test may import it (#335)."""
    problems: list[str] = []
    names: set[str] = set()
    for line in text.replace("\\\n", " ").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        spec, *options = stripped.split()
        if not REQUIREMENT.match(spec):
            problems.append(f"not pinned with ==: {spec}")
            continue
        names.add(spec.split("==", 1)[0].lower())
        hashes = [opt for opt in options if HASH_OPTION.match(opt)]
        if not hashes or len(hashes) != len(options):
            problems.append(f"{spec}: every option must be --hash=sha256:<64 hex>, and one at least")
    if "pytest" not in names:
        problems.append("pytest is not locked")
    if "pyyaml" in names:
        problems.append("pyyaml is locked, though no published test may import it")
    return problems


def self_check_step_problems(wf: Workflow) -> list[str]:
    """The Guardian self-check step is in the workflow exactly once, in the Linux job, and cannot pass on failure."""
    named = [name for name, job in _jobs(wf).items() for step in _steps(job) if step.get("name") == STEP_NAME]
    if named != [LINUX_JOB]:
        return [f"the self-check step is in {named!r}, not once in {LINUX_JOB}"]
    return self_check_problems(wf.text, LINUX_JOB)


def job_problems(wf: Workflow) -> list[str]:
    """The triggers and the jobs: Linux always; macOS in the public repository or on a manual run."""
    problems: list[str] = []
    triggers = wf.doc.get("on")
    if not isinstance(triggers, dict) or set(triggers) != TRIGGERS:
        problems.append(f"triggers are {triggers!r}, not {sorted(TRIGGERS)}")
    jobs = _jobs(wf)
    if set(jobs) != {LINUX_JOB, MACOS_JOB}:
        problems.append(f"jobs are {sorted(jobs)}, not {LINUX_JOB} and {MACOS_JOB}")
        return problems
    if "if" in jobs[LINUX_JOB]:
        problems.append(f"{LINUX_JOB} runs only when {jobs[LINUX_JOB]['if']!r}")
    if jobs[MACOS_JOB].get("if") != MACOS_CONDITION:
        problems.append(f"{MACOS_JOB} runs when {jobs[MACOS_JOB].get('if')!r}, not {MACOS_CONDITION!r}")
    for name, runner in ((LINUX_JOB, "ubuntu-latest"), (MACOS_JOB, "macos-latest")):
        if jobs[name].get("runs-on") != runner:
            problems.append(f"{name} runs on {jobs[name].get('runs-on')!r}, not {runner}")
        tests = [s for s in _steps(jobs[name]) if s.get("name") == "Test"]
        if [(s.get("run"), s.get("env")) for s in tests] != [
            (".venv/bin/python -m pytest", {"SSC_GUARDIAN_REQUIRE_NETWORK": "1"})
        ]:
            problems.append(f"{name}: the Test step is not the suite with SSC_GUARDIAN_REQUIRE_NETWORK=1")
    return problems


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def matrix_problems(wf: Workflow, pyproject: str | None = None) -> list[str]:
    """The Linux job runs once on each Python 3.N the ``pyproject.toml`` classifiers name and on no
    other, its lowest version is the ``requires-python`` floor, one red version does not cancel the
    others, and setup-python takes the matrix's version. *pyproject* is that file's text; the real
    file when None. A file that cannot be read, or holds no version, is a problem, never a pass."""
    text = PYPROJECT.read_text(encoding="utf-8") if pyproject is None else pyproject
    try:
        project = tomllib.loads(text).get("project")
    except tomllib.TOMLDecodeError as error:
        return [f"pyproject.toml cannot be read: {error}"]
    if not isinstance(project, dict):
        return ["pyproject.toml has no [project] table"]
    problems: list[str] = []
    classifiers = project.get("classifiers")
    if not isinstance(classifiers, list):
        return [f"pyproject.toml's classifiers are {classifiers!r}, not a list"]
    claimed = sorted(
        {match.group(1) for item in classifiers if isinstance(item, str) and (match := PYTHON_CLASSIFIER.match(item))},
        key=_version_key,
    )
    if not claimed:
        problems.append("pyproject.toml's classifiers name no Python 3.N version")
    floor = PYTHON_FLOOR.match(str(project.get("requires-python", "")))
    if floor is None:
        problems.append(f"requires-python is {project.get('requires-python')!r}, not >=3.N")
    job = _jobs(wf).get(LINUX_JOB) or {}
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(strategy, dict) or not isinstance(matrix, dict):
        return [*problems, f"{LINUX_JOB} has no strategy matrix"]
    if strategy.get("fail-fast") != "false":
        problems.append(f"{LINUX_JOB}: fail-fast is {strategy.get('fail-fast')!r}, not false")
    if set(matrix) != {"python-version"}:
        problems.append(f"{LINUX_JOB}: the matrix keys are {sorted(matrix)}, not python-version alone")
    versions = matrix.get("python-version")
    if not isinstance(versions, list) or not all(isinstance(v, str) and PYTHON_VERSION.match(v) for v in versions):
        return [*problems, f"{LINUX_JOB}: the matrix python-version is {versions!r}, not a list of 3.N"]
    if sorted(versions, key=_version_key) != claimed:
        problems.append(f"{LINUX_JOB}: the matrix runs {versions}, the classifiers name {claimed}")
    if floor is not None and (not versions or min(versions, key=_version_key) != floor.group(1)):
        problems.append(f"{LINUX_JOB}: the matrix's lowest version is not the requires-python floor {floor.group(1)}")
    setups = [step for step in _steps(job) if str(step.get("uses", "")).startswith("actions/setup-python@")]
    if [step.get("with") for step in setups] != [{"python-version": MATRIX_VERSION}]:
        problems.append(f"{LINUX_JOB}: setup-python does not take python-version {MATRIX_VERSION} once")
    return problems


def _venv_python(tokens: list[str]) -> tuple[str | None, str | None]:
    """The Python version a venv command names, or why it names none: ``(version, None)`` or
    ``(None, problem)``. ``uv venv`` names it with ``--python``/``-p``; ``<python> -m venv`` with
    its interpreter, where a bare ``python`` or ``python3`` names none."""
    if tokens[:2] == ["uv", "venv"]:
        named = None
        for index, token in enumerate(tokens):
            if token in ("--python", "-p") and index + 1 < len(tokens):
                named = tokens[index + 1]
            elif token.startswith("--python="):
                named = token.split("=", 1)[1]
        if named is None:
            return None, "uv venv names no Python version"
        match = NAMED_PYTHON.match(named)
        return (match.group(1), None) if match else (None, f"uv venv names Python {named!r}, not a 3.N version")
    interpreter = Path(tokens[0]).name
    if interpreter in ("python", "python3"):
        return None, f"builds with the bare {interpreter}, which may be Apple's Python 3.9"
    match = NAMED_PYTHON.match(interpreter)
    return (match.group(1), None) if match else (None, f"builds with {tokens[0]!r}, which names no 3.N version")


def _builds_venv(tokens: list[str]) -> bool:
    if tokens[:2] == ["uv", "venv"]:
        return True
    return "-m" in tokens[:-1] and tokens[tokens.index("-m") + 1] in ("venv", "virtualenv")


def _section_commands(text: str) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """The commands in the fenced blocks of CONTRIBUTING.md's "Running the tests", each as its
    text and its tokens, and a problem for each command that cannot be read. A missing section is
    a problem, never an empty pass."""
    if CONTRIBUTING_SECTION not in text:
        return [], [f"CONTRIBUTING.md has no {CONTRIBUTING_SECTION!r} section"]
    section = text.split(CONTRIBUTING_SECTION, 1)[1].split("\n## ", 1)[0]
    commands: list[tuple[str, list[str]]] = []
    problems: list[str] = []
    for _fence, block in FENCED_BLOCK.findall(section):
        for line in block.splitlines():
            for command in COMMAND_SEPARATOR.split(line):
                try:
                    tokens = shlex.split(command)
                except ValueError as error:
                    problems.append(f"cannot read the command {command.strip()!r}: {error}")
                    continue
                if tokens:
                    commands.append((command.strip(), tokens))
    return commands, problems


def venv_floor_problems(contributing: str | None = None, pyproject: str | None = None) -> list[str]:
    """CONTRIBUTING.md's "Running the tests" builds its venv with a named Python at the
    ``requires-python`` floor or later (#354). *contributing* and *pyproject* are those files' text;
    the real files when None. A missing section, a section with no venv command and an unreadable
    ``pyproject.toml`` are each a problem, never a pass."""
    text = CONTRIBUTING.read_text(encoding="utf-8") if contributing is None else contributing
    toml = PYPROJECT.read_text(encoding="utf-8") if pyproject is None else pyproject
    try:
        project = tomllib.loads(toml).get("project")
    except tomllib.TOMLDecodeError as error:
        return [f"pyproject.toml cannot be read: {error}"]
    requires = project.get("requires-python") if isinstance(project, dict) else None
    floor = PYTHON_FLOOR.match(str(requires))
    if floor is None:
        return [f"requires-python is {requires!r}, not >=3.N"]
    commands, problems = _section_commands(text)
    if CONTRIBUTING_SECTION not in text:
        return problems
    venvs = 0
    for command, tokens in commands:
        if not _builds_venv(tokens):
            continue
        venvs += 1
        version, problem = _venv_python(tokens)
        if problem is not None:
            problems.append(f"CONTRIBUTING.md's venv command {command!r} {problem}")
        elif version is not None and _version_key(version) < _version_key(floor.group(1)):
            problems.append(
                f"CONTRIBUTING.md's venv command builds with Python {version},"
                f" below the requires-python floor {floor.group(1)}"
            )
    if not venvs:
        problems.append(f"CONTRIBUTING.md's {CONTRIBUTING_SECTION!r} gives no venv command")
    return problems


# What makes a venv command fetch pip (or its seed packages) from the index, unpinned and unhashed
# (#368): uv venv's --seed (or UV_VENV_SEED), venv's --upgrade-deps, virtualenv's --download.
DOWNLOADING_SEED = ("--seed", "--upgrade-deps", "--download")


def pip_source_problems(contributing: str | None = None) -> list[str]:
    """CONTRIBUTING.md's "Running the tests" installs no pip that neither Python's own bundle nor
    the hash-locked requirements cover (#368): its venv command fetches no seed packages, and the
    only install is the hash-locked ``INSTALL`` line (``ensurepip`` installs the bundled pip and
    downloads nothing). *contributing* is that file's text; the real file when None. A missing
    section, or a section with no venv command, is a problem, never a pass."""
    text = CONTRIBUTING.read_text(encoding="utf-8") if contributing is None else contributing
    commands, problems = _section_commands(text)
    if CONTRIBUTING_SECTION not in text:
        return problems
    venvs = 0
    for command, tokens in commands:
        seeded = [
            token for token in tokens if token.split("=", 1)[0] in DOWNLOADING_SEED or token.startswith("UV_VENV_SEED=")
        ]
        # An environment assignment before the command (UV_VENV_SEED=1 uv venv ...) is skipped.
        builds = _builds_venv(list(itertools.dropwhile(lambda token: "=" in token, tokens)))
        if builds:
            venvs += 1
        if seeded:
            problems.append(f"CONTRIBUTING.md's command {command!r} downloads pip unchecked with {seeded[0]!r}")
        elif not builds and INSTALLER.search(command) and command != INSTALL:
            problems.append(f"CONTRIBUTING.md's command {command!r} installs other than with {INSTALL!r}")
    if not venvs:
        problems.append(f"CONTRIBUTING.md's {CONTRIBUTING_SECTION!r} gives no venv command")
    return problems


ALL_CHECKS = (
    pin_problems,
    privilege_problems,
    install_problems,
    self_check_step_problems,
    job_problems,
    matrix_problems,
)


# --- the real files ----------------------------------------------------------------


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_real_tests_workflow_passes(check: object) -> None:
    assert callable(check)
    assert check(_read()) == []


def test_tests_workflow_pins_every_action_to_a_sha() -> None:
    wf = _read()
    assert pin_problems(wf) == []
    assert len([ref for job in _jobs(wf).values() for ref in _uses(job)]) == 4
    # Negative control: a tag-pinned checkout fails, and so does a SHA without its version comment.
    tagged = _read(_planted(CHECKOUT_PIN, "actions/checkout@v4", count=2))
    assert unpinned_uses(tagged) == [f"{LINUX_JOB}: actions/checkout@v4", f"{MACOS_JOB}: actions/checkout@v4"]
    bare = _read(_planted(CHECKOUT_PIN, CHECKOUT_PIN.split(" #")[0], count=2))
    assert any("lacks the version comment" in p for p in pin_problems(bare))


def test_tests_workflow_least_privilege() -> None:
    assert privilege_problems(_read()) == []
    planted = {
        "write": ("permissions:\n  contents: read\n", "permissions:\n  contents: write\n", 1),
        "credentials": ("          persist-credentials: false\n", "          persist-credentials: true\n", 2),
        "expression": (
            "        run: .venv/bin/python -m pytest\n",
            "        run: .venv/bin/python -m pytest -k ${{ github.head_ref }}\n",
            2,
        ),
        "job-permissions": ("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    permissions: write-all\n", 1),
    }
    for label, (old, new, count) in planted.items():
        assert privilege_problems(_read(_planted(old, new, count=count))) != [], label


def test_tests_workflow_installs_with_require_hashes() -> None:
    assert install_problems(_read()) == []
    # Error path: an install without --require-hashes, an unlocked extra package, or a second
    # installer each fail.
    for old, new in (
        (" --require-hashes --no-deps -r requirements-test.txt", " --no-deps -r requirements-test.txt"),
        (" -r requirements-test.txt", " -r requirements-test.txt pytest-xdist"),
        (
            "          python -m venv .venv\n",
            "          python -m venv .venv\n          pip install uv\n",
        ),
    ):
        assert install_problems(_read(_planted(old, new, count=2))) != [], new


def test_requirements_test_pins_have_hashes() -> None:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert requirements_problems(text) == []
    assert re.search(r"^pytest==\S+ \\$", text, re.MULTILINE), "pytest is not locked"
    assert not re.search(r"^pyyaml\b", text, re.MULTILINE | re.IGNORECASE), "PyYAML is locked"
    # Edge cases: a range, a requirement without a hash, a dropped pytest and a PyYAML added back
    # (no published test may import it, #335) each fail.
    pin = re.search(r"^pytest==(\S+) \\\n((?:    --hash=\S+(?: \\)?\n)+)", text, re.MULTILINE)
    assert pin is not None
    assert requirements_problems(text.replace(f"pytest=={pin.group(1)}", "pytest>=9")) == [
        "not pinned with ==: pytest>=9",
        "pytest is not locked",
    ]
    unhashed = text.replace(pin.group(0), f"pytest=={pin.group(1)}\n")
    assert requirements_problems(unhashed) == [
        f"pytest=={pin.group(1)}: every option must be --hash=sha256:<64 hex>, and one at least"
    ]
    assert requirements_problems(text.replace(pin.group(0), "")) == ["pytest is not locked"]
    added = f"{text}PyYAML==6.0.3 \\\n    --hash=sha256:{'0' * 64}\n"
    assert requirements_problems(added) == ["pyyaml is locked, though no published test may import it"]


def test_tests_workflow_runs_the_self_check() -> None:
    wf = _read()
    assert self_check_step_problems(wf) == []
    step = f"      - name: {STEP_NAME}\n"
    run = "        run: .venv/bin/python -m ssc_guardian check --repo .\n"
    for old, new in (
        (run, run.replace(" .\n", " . || true\n")),
        (run, run + "        continue-on-error: true\n"),
        (step, step.replace(STEP_NAME, "Check the repository")),
    ):
        assert self_check_step_problems(_read(_planted(old, new))) != [], new
    # A second copy of the step, in the macOS job, fails too: the step is there once.
    second = _planted(TEST_STEP, TEST_STEP + f"      - name: {STEP_NAME}\n        run: {SELF_CHECK_RUN}\n", count=2)
    assert self_check_step_problems(_read(second)) == [
        f"the self-check step is in {[LINUX_JOB, LINUX_JOB, MACOS_JOB]!r}, not once in {LINUX_JOB}"
    ]


def test_tests_workflow_jobs_and_triggers() -> None:
    assert job_problems(_read()) == []
    for old, new, count in (
        (f"    if: {MACOS_CONDITION}\n", "", 1),
        (f"    if: {MACOS_CONDITION}\n", f"    if: {MACOS_CONDITION} || true\n", 1),
        ("    runs-on: ubuntu-latest\n", "    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n", 1),
        ("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n", 1),
        ("  tests-linux:\n", "  linux:\n", 1),
        ('          SSC_GUARDIAN_REQUIRE_NETWORK: "1"\n', '          SSC_GUARDIAN_REQUIRE_NETWORK: "0"\n', 2),
    ):
        assert job_problems(_read(_planted(old, new, count=count))) != [], new


def _planted_pyproject(old: str, new: str) -> str:
    """The real pyproject.toml's text with its one *old* replaced by *new*."""
    text = PYPROJECT.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"expected {old!r} once"
    return text.replace(old, new)


def test_linux_matrix_matches_the_classifiers() -> None:
    wf = _read()
    assert matrix_problems(wf) == []
    # Negative control: a matrix without 3.13 fails, and so does a 3.14 classifier with no leg.
    no_313 = _read(_planted(MATRIX_LINE, MATRIX_LINE.replace(', "3.13"', "")))
    assert matrix_problems(no_313) == [
        f"{LINUX_JOB}: the matrix runs ['3.11', '3.12'], the classifiers name ['3.11', '3.12', '3.13']"
    ]
    c313 = '    "Programming Language :: Python :: 3.13",\n'
    with_314 = _planted_pyproject(c313, c313 + c313.replace("3.13", "3.14"))
    assert matrix_problems(wf, with_314) == [
        f"{LINUX_JOB}: the matrix runs ['3.11', '3.12', '3.13'], the classifiers name ['3.11', '3.12', '3.13', '3.14']"
    ]
    # A matrix and classifiers that agree but start above the requires-python floor fail.
    c311 = '    "Programming Language :: Python :: 3.11",\n'
    above = _read(_planted(MATRIX_LINE, MATRIX_LINE.replace('"3.11", ', "")))
    assert matrix_problems(above, _planted_pyproject(c311, "")) == [
        f"{LINUX_JOB}: the matrix's lowest version is not the requires-python floor 3.11"
    ]
    # Edge case: fail-fast true would let one red version cancel the others.
    fast = _read(_planted("      fail-fast: false\n", "      fail-fast: true\n"))
    assert matrix_problems(fast) == [f"{LINUX_JOB}: fail-fast is 'true', not false"]
    # setup-python must take the matrix's version, or every leg runs the same interpreter.
    pinned = _read(_planted(f"          python-version: {MATRIX_VERSION}\n", '          python-version: "3.11"\n'))
    assert matrix_problems(pinned) == [f"{LINUX_JOB}: setup-python does not take python-version {MATRIX_VERSION} once"]
    # Error path: no classifiers, no matrix, or an unreadable pyproject.toml are problems, never a pass.
    text = PYPROJECT.read_text(encoding="utf-8")
    start = text.index("classifiers = [")
    unclassified = text[:start] + text[text.index("]\n", start) + 2 :]
    assert "classifiers" not in tomllib.loads(unclassified)["project"]
    assert matrix_problems(wf, unclassified) == ["pyproject.toml's classifiers are None, not a list"]
    no_python = (
        _planted_pyproject(c311, "").replace('    "Programming Language :: Python :: 3.12",\n', "").replace(c313, "")
    )
    assert "pyproject.toml's classifiers name no Python 3.N version" in matrix_problems(wf, no_python)
    no_matrix = _read(_planted("    strategy:\n      fail-fast: false\n      matrix:\n" + MATRIX_LINE, ""))
    assert matrix_problems(no_matrix) == [f"{LINUX_JOB} has no strategy matrix"]
    assert matrix_problems(wf, "[project\n")[0].startswith("pyproject.toml cannot be read: ")


def test_contributing_gives_the_workflow_commands() -> None:
    """CONTRIBUTING.md's "Running the tests" gives the two commands the workflow runs."""
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "## Running the tests" in text
    section = text.split("## Running the tests", 1)[1].split("\n## ", 1)[0]
    for command in VISITOR_COMMANDS:
        assert command in section, command
    workflow = TESTS_WORKFLOW.read_text(encoding="utf-8")
    install = VISITOR_COMMANDS[0].replace(VISITOR_VENV, "")
    assert workflow.count(f"          python -m venv .venv\n          {install}\n") == 2
    assert workflow.count(f"        run: {VISITOR_COMMANDS[1]}\n") == 2


def _planted_contributing(old: str, new: str) -> str:
    """The real CONTRIBUTING.md's text with its one *old* replaced by *new*."""
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"expected {old!r} once"
    return text.replace(old, new)


def test_contributing_venv_meets_the_python_floor() -> None:
    """The documented venv is built with a Python at the requires-python floor or later (#354)."""
    assert venv_floor_problems() == []
    # Negative control: Apple's `python3` (3.9 on a new Mac), or a bare `python`, fails by name.
    bare = venv_floor_problems(_planted_contributing(VISITOR_VENV, "python3 -m venv .venv && "))
    assert bare == [
        "CONTRIBUTING.md's venv command 'python3 -m venv .venv' builds with the bare python3,"
        " which may be Apple's Python 3.9"
    ]
    assert "the bare python," in venv_floor_problems(_planted_contributing(VISITOR_VENV, "python -m venv .venv && "))[0]
    assert venv_floor_problems(_planted_contributing(VISITOR_VENV, "python3.11 -m venv .venv && ")) == []
    # Edge cases: 3.10 is below the 3.11 floor; 3.12 is above it; a uv venv naming no version fails.
    assert venv_floor_problems(_planted_contributing("--python 3.11", "--python 3.10")) == [
        "CONTRIBUTING.md's venv command builds with Python 3.10, below the requires-python floor 3.11"
    ]
    assert venv_floor_problems(_planted_contributing("--python 3.11", "--python 3.12")) == []
    assert venv_floor_problems(_planted_contributing("--python 3.11 ", "")) == [
        "CONTRIBUTING.md's venv command 'uv venv .venv' uv venv names no Python version"
    ]
    # A bare python3 behind ||, ;, or in a tilde fence is read too, never skipped.
    fallback = _planted_contributing(" .venv && ", " .venv || python3 -m venv .venv && ")
    assert [p for p in venv_floor_problems(fallback) if "bare python3" in p] != []
    after_semicolon = _planted_contributing(VISITOR_VENV, "true; uv venv --seed .venv && ")
    assert "uv venv names no Python version" in venv_floor_problems(after_semicolon)[0]
    tilde = _planted_contributing("suite:\n\n```sh\n", "suite:\n\n~~~sh\npython3 -m venv .venv\n~~~\n\n```sh\n")
    assert [p for p in venv_floor_problems(tilde) if "bare python3" in p] != []
    # Error path: no section, no venv command, or an unreadable pyproject.toml is a problem, never a pass.
    assert venv_floor_problems(_planted_contributing(CONTRIBUTING_SECTION, "## Tests")) == [
        f"CONTRIBUTING.md has no {CONTRIBUTING_SECTION!r} section"
    ]
    assert venv_floor_problems(_planted_contributing(VISITOR_VENV, "")) == [
        f"CONTRIBUTING.md's {CONTRIBUTING_SECTION!r} gives no venv command"
    ]
    assert venv_floor_problems(pyproject="[project\n")[0].startswith("pyproject.toml cannot be read: ")
    assert venv_floor_problems(pyproject='[project]\nname = "x"\n') == ["requires-python is None, not >=3.N"]


def test_contributing_setup_downloads_no_unchecked_pip() -> None:
    """The documented setup installs only Python's bundled pip and the hash-locked requirements (#368)."""
    assert pip_source_problems() == []
    # Negative control: uv venv's --seed fetches the current pip from the index, unhashed.
    assert pip_source_problems(_planted_contributing(" 3.11 .venv && ", " 3.11 --seed .venv && ")) == [
        "CONTRIBUTING.md's command 'uv venv --python 3.11 --seed .venv' downloads pip unchecked with '--seed'"
    ]
    # Edge cases: venv's --upgrade-deps, an environment-set seed, and another install route each fail.
    upgrade = pip_source_problems(_planted_contributing(VISITOR_VENV, "python3.11 -m venv --upgrade-deps .venv && "))
    assert upgrade == [
        "CONTRIBUTING.md's command 'python3.11 -m venv --upgrade-deps .venv' downloads pip unchecked with"
        " '--upgrade-deps'"
    ]
    env_seed = pip_source_problems(_planted_contributing("uv venv --python", "UV_VENV_SEED=1 uv venv --python"))
    assert env_seed != [] and "'UV_VENV_SEED=1'" in env_seed[0]
    other = pip_source_problems(_planted_contributing("-m ensurepip &&", "-m pip install --upgrade pip &&"))
    assert other == [
        "CONTRIBUTING.md's command '.venv/bin/python -m pip install --upgrade pip' installs other than"
        f" with {INSTALL!r}"
    ]
    assert pip_source_problems(_planted_contributing("-m ensurepip &&", "get-pip.py &&")) != []
    # A venv that installs its bundled pip itself (python3.11 -m venv) passes.
    assert pip_source_problems(_planted_contributing(VISITOR_VENV, "python3.11 -m venv .venv && ")) == []
    # Error path: no section, or no venv command, is a problem, never a pass.
    assert pip_source_problems(_planted_contributing(CONTRIBUTING_SECTION, "## Tests")) == [
        f"CONTRIBUTING.md has no {CONTRIBUTING_SECTION!r} section"
    ]
    assert pip_source_problems(_planted_contributing(VISITOR_VENV, "")) == [
        f"CONTRIBUTING.md's {CONTRIBUTING_SECTION!r} gives no venv command"
    ]


def test_checks_are_idempotent() -> None:
    files = (TESTS_WORKFLOW, REQUIREMENTS, PYPROJECT, CONTRIBUTING)
    before = [path.read_bytes() for path in files]

    def run() -> tuple[object, ...]:
        return (
            [check(_read()) for check in ALL_CHECKS],
            requirements_problems(REQUIREMENTS.read_text(encoding="utf-8")),
            venv_floor_problems(),
            pip_source_problems(),
        )

    assert run() == run()
    assert [path.read_bytes() for path in files] == before
