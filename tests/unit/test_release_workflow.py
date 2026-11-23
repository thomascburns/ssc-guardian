# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The release workflow keeps its safety properties (plan §5 "Release workflow"; part 3 of #12).

``.github/workflows/release.yml`` is read with Guardian's own YAML reader
(``ssc_guardian.yaml_subset``), which keeps every value as text and ``on`` as the key ``on``; the
pin comments, which a reader drops, are read from the plain text. Each property is a function
that returns the problems it finds, so the real file must give none and a planted copy must give
at least one. A planted copy is the real file with one exact substitution, made only after the
test has checked that the text it replaces is there exactly once, so a negative case can never
pass because the file moved on.

The properties: every ``uses:`` is pinned to a full commit SHA with its version in a comment,
the pins are the reviewed ones and checkout and setup-python reuse tests.yml's; the build tool comes
only from ``requirements-release.txt``, from wheels, with ``--require-hashes`` and builds without
isolation; the top level reads only and each write scope sits only in the job that needs it; no
pull-request or branch-push trigger, only the one tag pattern ``v*-reference``, the public
repository runs only on a pushed tag and the development repository only on a manual run (job
conditions are compared whole, so a condition that ORs a safeguard away fails); no ``${{ }}``
expression inside a ``run:`` script; the attestation runs only in the public repository and the
public draft waits for it; the release is created as a draft with the wheel and its SHA-256
attached and is never changed afterwards, also not through GraphQL; the version step, run under
bash, refuses a release tag whose wheel version differs. The integrity steps (#231): every
checkout takes only ``persist-credentials: false`` (no ``ref``); the record step, run under
bash, hashes exactly one wheel; the attest and release jobs each run ``sha256sum -c`` on the
downloaded wheel before they use it; the attested subject is the wheel. A release tag has three
parts, ``v<major>.<minor>.<patch>-reference`` (#327): the tag step refuses a two-part tag such as
``v1.1-reference`` and the version step no longer pads one. The checked-in ``pyproject.toml``
version passes both steps under its own three-part tag (#294). The release
notes stay true once the release is published (#309): they name the commit, the wheel and its
SHA-256, point at SECURITY.md and end with a ``Known issues:`` line, with no draft-only wording
and no link to the development repository. No network;
nothing is written outside ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.yaml_subset import parse, to_python

# doc_content: the notes checks name SECURITY.md, so a docs-only commit reruns this module (#181).
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
RELEASE = REPO / ".github" / "workflows" / "release.yml"
TESTS_WORKFLOW = REPO / ".github" / "workflows" / "tests.yml"
REQUIREMENTS = REPO / "requirements-release.txt"
PYPROJECT = REPO / "pyproject.toml"
PUBLIC_REPOSITORY = "thomascburns/ssc-guardian"
# Another repository of the same owner, whose name starts with the public one's, stands in for any
# repository but the public one, so a prefix or glob comparison is still caught. This file holds no
# form of the development repository's name; the checks that need it run in that repository (#325).
OTHER_REPOSITORY = "thomascburns/ssc-guardian-fork"

SHA_REF = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
VERSION_COMMENT = re.compile(r"^\s+#\s+(?P<version>v\d+(?:\.\d+){0,2})\s*$")
REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!-]+$")
HASH_OPTION = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")

# The reviewed pins (commit SHA, release). A new pin is a release at least 21 days old, named
# with its date in the commit message that adds it; checkout and setup-python reuse tests.yml's.
EXPECTED_PINS: dict[str, tuple[str, str]] = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2"),
    "actions/download-artifact": ("9000827ccba6bdab643e8b6fd33ac0654aef8333", "v8.0.2"),
    "actions/attest": ("1e69f48acb82d1966a394da916b4c1698aa569d6", "v4.2.2"),
}
REUSED_FROM_CI = ("actions/checkout", "actions/setup-python")

# The job conditions, compared whole: a substring test would accept a condition that ORs the
# safeguard away. build: the public repository releases only from a pushed tag (so the wheel is
# built from the tagged commit) and the development repository only from a manual rehearsal.
# attest: the public repository only. release: the build succeeded and, in the public repository,
# so did the attestation.
BUILD_CONDITION = (
    f"(github.event_name == 'push' && github.repository == '{PUBLIC_REPOSITORY}')"
    f" || (github.event_name == 'workflow_dispatch' && github.repository != '{PUBLIC_REPOSITORY}')"
)
ATTEST_CONDITION = f"github.repository == '{PUBLIC_REPOSITORY}'"
RELEASE_CONDITION = (
    "!cancelled() && needs.build.result == 'success' && (needs.attest.result == 'success'"
    f" || (needs.attest.result == 'skipped' && github.repository != '{PUBLIC_REPOSITORY}'))"
)
VERSION_STEP = "Check the wheel version against the tag"
RECORD_STEP = "Record the wheel's SHA-256"
TAG_PATTERN = "v*-reference"
WHEEL_GLOB = "ssc_guardian-*-py3-none-any.whl"
HASH_CHECK = f"sha256sum -c {WHEEL_GLOB}.sha256"
CHECKOUT_WITH = {"persist-credentials": "false"}


@dataclass(frozen=True)
class Workflow:
    text: str
    doc: dict[str, Any]


def read_workflow(text: str, source: str) -> Workflow:
    doc = to_python(parse(text, source))
    assert isinstance(doc, dict), f"{source}: not a mapping"
    return Workflow(text, doc)


def _jobs(wf: Workflow) -> dict[str, dict[str, Any]]:
    jobs = wf.doc.get("jobs")
    assert isinstance(jobs, dict), "workflow has no jobs mapping"
    return jobs


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps") or []
    assert isinstance(steps, list)
    return steps


def _uses(job: dict[str, Any]) -> list[str]:
    refs = [job["uses"]] if "uses" in job else []
    return refs + [step["uses"] for step in _steps(job) if "uses" in step]


def _run_lines(job: dict[str, Any]) -> list[str]:
    """The job's ``run:`` scripts as logical lines (backslash continuations joined)."""
    lines: list[str] = []
    for step in _steps(job):
        run = step.get("run")
        if isinstance(run, str):
            lines += [line.strip() for line in run.replace("\\\n", " ").splitlines() if line.strip()]
    return lines


def _action(ref: str) -> str:
    return "/".join(ref.split("@", 1)[0].split("/")[:2])


def _condition(job: dict[str, Any]) -> str:
    raw = str(job.get("if", "")).strip()
    if raw.startswith("${{") and raw.endswith("}}"):
        raw = raw[3:-2].strip()
    return raw


def _attest_jobs(wf: Workflow) -> dict[str, dict[str, Any]]:
    return {n: j for n, j in _jobs(wf).items() if any(_action(r) == "actions/attest" for r in _uses(j))}


def _release_jobs(wf: Workflow) -> dict[str, dict[str, Any]]:
    return {n: j for n, j in _jobs(wf).items() if any("gh release create" in line for line in _run_lines(j))}


# --- the checks ----------------------------------------------------------------


def unpinned_uses(wf: Workflow) -> list[str]:
    """Every ``uses:`` that is not ``owner/repo@<40-hex commit SHA>``."""
    return [f"{name}: {ref}" for name, job in _jobs(wf).items() for ref in _uses(job) if not SHA_REF.match(ref)]


def pin_comment_problems(wf: Workflow) -> list[str]:
    """Each ``uses:`` line names a reviewed pin and ends with that pin's version as a comment."""
    problems: list[str] = []
    for number, line in enumerate(wf.text.splitlines(), 1):
        m = USES_LINE.match(line)
        if m is None:
            continue
        ref, rest = m.group("ref"), m.group("rest")
        expected = EXPECTED_PINS.get(_action(ref))
        if expected is None:
            problems.append(f"line {number}: {ref} is not a reviewed pin")
            continue
        sha, version = expected
        if ref.split("@", 1)[-1] != sha:
            problems.append(f"line {number}: {ref} is not the reviewed commit {sha}")
        comment = VERSION_COMMENT.match(rest)
        if comment is None or comment.group("version") != version:
            problems.append(f"line {number}: {ref} lacks the version comment '# {version}'")
    return problems


def pin_reuse_problems(wf: Workflow, source: Workflow, source_name: str = "tests.yml") -> list[str]:
    """checkout and setup-python use exactly the commits the workflow *source* uses."""
    source_refs = {ref for job in _jobs(source).values() for ref in _uses(job)}
    return [
        f"{name}: {ref} is not {source_name}'s pin"
        for name, job in _jobs(wf).items()
        for ref in _uses(job)
        if _action(ref) in REUSED_FROM_CI and ref not in source_refs
    ]


def build_tool_problems(wf: Workflow) -> list[str]:
    """The build tool is installed only from requirements-release.txt, from wheels, with
    --require-hashes, and the build runs without isolation (an isolated build, or pip building a
    source distribution, would fetch an unpinned backend). Nothing else builds or fetches packages."""
    problems: list[str] = []
    lines = [line for job in _jobs(wf).values() for line in _run_lines(job)]
    installs = [line for line in lines if re.search(r"\bpip\s+install\b", line)]
    builds = [line for line in lines if re.search(r"-m\s+build\b", line)]
    if not installs:
        problems.append("no pip install of the build tool")
    if not builds:
        problems.append("no build step")
    for line in installs:
        if "--require-hashes" not in line.split():
            problems.append(f"pip install without --require-hashes: {line}")
        if "-r requirements-release.txt" not in line:
            problems.append(f"pip install not from requirements-release.txt: {line}")
        if "--only-binary :all:" not in line:
            problems.append(f"pip install may build a source distribution (no --only-binary :all:): {line}")
    problems += [f"build with isolation: {line}" for line in builds if "--no-isolation" not in line.split()]
    for line in lines:
        if re.search(
            r"\b(?:uv\s+(?:pip\s+install|add|tool\s+install|build)|pipx\s+install|pip\s+(?:wheel|download))\b", line
        ):
            problems.append(f"installer outside the locked route: {line}")
    return problems


def requirement_problems(text: str) -> list[str]:
    """Every requirement is pinned with == and carries SHA-256 hashes; build and setuptools are there."""
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
    problems += [f"{name} is not locked" for name in ("build", "setuptools") if name not in names]
    return problems


WRITE_NEEDS: dict[str, tuple[str, Callable[[str, Workflow], bool]]] = {
    "contents": ("creates the release", lambda name, wf: name in _release_jobs(wf)),
    "id-token": ("attests", lambda name, wf: name in _attest_jobs(wf)),
    "attestations": ("attests", lambda name, wf: name in _attest_jobs(wf)),
}


def permission_problems(wf: Workflow) -> list[str]:
    """The top level reads only; every job declares its permissions; a write scope sits only in
    the job that needs it."""
    problems: list[str] = []
    if wf.doc.get("permissions") != {"contents": "read"}:
        problems.append(f"top-level permissions are {wf.doc.get('permissions')!r}, not contents: read")
    for name, job in _jobs(wf).items():
        perms = job.get("permissions")
        if not isinstance(perms, dict):
            problems.append(f"{name}: permissions {perms!r} are not an explicit per-scope mapping")
            continue
        for scope, level in perms.items():
            if level in ("read", "none"):
                continue
            need = WRITE_NEEDS.get(scope)
            if level != "write" or need is None:
                problems.append(f"{name}: {scope}: {level} is never needed")
            elif not need[1](name, wf):
                problems.append(f"{name}: {scope}: write in a job that never {need[0]}")
    return problems


def trigger_problems(wf: Workflow) -> list[str]:
    """Only a pushed tag and a manual run start it: no pull request of any kind, no branch push.
    The build job, which every other job needs, runs on a pushed tag only in the public repository
    and on a manual run only in the development repository."""
    on = wf.doc.get("on")
    if not isinstance(on, dict):
        return [f"triggers {on!r} are not a mapping of push and workflow_dispatch"]
    problems = [f"trigger {key} is not allowed" for key in on if key not in ("push", "workflow_dispatch")]
    push = on.get("push")
    if push is not None and (not isinstance(push, dict) or set(push) != {"tags"}):
        problems.append(f"push trigger {push!r} is not tags only")
    elif isinstance(push, dict) and push.get("tags") != [TAG_PATTERN]:
        problems.append(f"push tags {push.get('tags')!r} are not the one tag pattern {TAG_PATTERN!r}")
    build = _jobs(wf).get("build")
    if build is None or _condition(build) != BUILD_CONDITION:
        found = "no build job" if build is None else repr(_condition(build) or "always")
        problems.append(f"build: runs when {found}, not when {BUILD_CONDITION!r}")
    for name, job in _jobs(wf).items():
        needs = job.get("needs") or []
        if name != "build" and "build" not in ([needs] if isinstance(needs, str) else needs):
            problems.append(f"{name}: does not need build, so the build job's condition does not gate it")
    return problems


def expressions_in_run(wf: Workflow) -> list[str]:
    """No ``${{ }}`` expression inside a run: script; values reach the shell through env."""
    return [
        f"{name}: step {index}: ${{{{ }}}} inside run"
        for name, job in _jobs(wf).items()
        for index, step in enumerate(_steps(job), 1)
        if "${{" in str(step.get("run", ""))
    ]


def attestation_problems(wf: Workflow) -> list[str]:
    """The attestation job runs only in the public repository, and every draft-creating job waits
    for it there; only the development repository, where it is skipped, drafts without it."""
    attest = _attest_jobs(wf)
    if not attest:
        return ["no attestation step"]
    problems = [
        f"{name}: runs when {_condition(job) or 'always'!r}, not only when {ATTEST_CONDITION}"
        for name, job in attest.items()
        if _condition(job) != ATTEST_CONDITION
    ]
    for name, job in attest.items():
        problems += [f"{name}: step {i} has its own if" for i, step in enumerate(_steps(job), 1) if "if" in step]
    if set(attest) != {"attest"}:
        problems.append(f"the attestation must run in the one job named attest, not {sorted(attest)}")
    for name, job in _release_jobs(wf).items():
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        if "attest" not in needs:
            problems.append(f"{name}: does not wait for attest")
        if _condition(job) != RELEASE_CONDITION:
            problems.append(
                f"{name}: drafts when {_condition(job) or 'always'!r}, not only after a successful build"
                f" and, in the public repository, a successful attestation ({RELEASE_CONDITION!r})"
            )
    return problems


def draft_problems(wf: Workflow) -> list[str]:
    """The release is created as a draft with the wheel and its SHA-256 attached at creation
    (fact 16); the workflow never publishes, edits or adds files to a release."""
    problems: list[str] = []
    lines = [line for job in _jobs(wf).values() for line in _run_lines(job)]
    creates = [line for line in lines if "gh release create" in line]
    if not creates:
        problems.append("no gh release create")
    for line in creates:
        tokens = line.split()
        if "--draft" not in tokens or any(t.startswith("--draft=") for t in tokens):
            problems.append(f"release not created as a draft: {line}")
        # Positional arguments after `create`: the tag, then the files; a file and the same name
        # with .sha256 must both be there.
        after = tokens[tokens.index("create") + 1 :]
        positional = [
            t.strip("\"'") for t in after[: next((i for i, t in enumerate(after) if t.startswith("-")), None)]
        ]
        files = positional[1:]
        if not any(f"{name}.sha256" in files for name in files):
            problems.append(f"wheel and SHA-256 not attached at creation: {line}")
    problems += [
        f"changes a release after creation: {line}"
        for line in lines
        if re.search(r"gh release (?:edit|upload|delete)\b", line)
        or re.search(r"\bdraft=", line)
        or re.search(r"\bgh\s+api\b.*\breleases\b", line)
        # GitHub's GraphQL API changes a release through mutations such as updateRelease.
        or re.search(r"\bgh\s+api\b.*\bgraphql\b", line)
        or re.search(r"\b(?:create|update|delete)Release(?:Asset)?\b", line, re.IGNORECASE)
    ]
    return problems


# The release notes (#309). Publishing keeps them, so they must read true on the published release;
# a link to the development repository would be built on a rehearsal, where GH_REPO is that one.
NOTES_ARG = re.compile(r"--notes(?![\w-])(?:=|\s+)(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s\"']+)")
# Every way gh takes notes; gh keeps the last one given, so the notes must be given exactly once.
# --generate-notes counts too: on a rehearsal it would list the development repository's pull requests.
NOTES_FLAGS = re.compile(r"(?<![\w-])(?:--notes(?:-file|-from-tag|-start-tag)?|--generate-notes|-n|-F)(?![\w-])")
NOTES_VAR = re.compile(r"\"\$(?:\{(\w+)\}|(\w+))\"")
SHELL_VAR = re.compile(r"(?<!\\)\$(?:\{(\w+)\}|(\w+))")
COMMAND_SUBSTITUTION = re.compile(r"\$\([^)]*\)")
URL = re.compile(r"https?://[^\s)\"'>\]]+")
PUBLIC_LINK = f"https://github.com/{PUBLIC_REPOSITORY}/blob/$RELEASE_TAG/"
NOTES_FORBIDDEN: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"before publishing", re.IGNORECASE), "draft-only wording, false once published"),
    (re.compile(r"draft built", re.IGNORECASE), "draft-only wording, false once published"),
    (re.compile(r"\$\{?GITHUB_REPOSITORY\b"), "names the development repository on a rehearsal"),
    (re.compile(r"\$\{?GH_REPO\b"), "names the development repository on a rehearsal"),
)


def _shell_word(token: str) -> str:
    """The text of one quoted shell word; only \\" is unescaped, so an escaped \\$ stays literal."""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        inner = token[1:-1]
        return inner.replace('\\"', '"') if token[0] == '"' else inner
    return token


def _assignments(script: str, name: str, end: int) -> list[str]:
    """The values assigned to shell variable *name* before offset *end*: a whole ``"$(...)"``
    (whose command may hold quotes of its own), a quoted word, or a bare word. An append
    (``name+=``), an ``export``/``declare``/``local``/``readonly`` assignment and a ``printf -v
    name`` each count too, so a second write to the notes is never missed."""
    value = r"(\"\$\([^)]*\)\"|\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S*)"
    prefix = r"(?:(?:export|declare|local|readonly)(?:[ \t]+-\w+)*[ \t]+)?"
    pattern = re.compile(rf"^[ \t]*{prefix}{re.escape(name)}\+?={value}", re.MULTILINE)
    printf_v = re.compile(rf"\bprintf[ \t]+-v[ \t]*{re.escape(name)}\b(.*)")
    return [m.group(1) for m in pattern.finditer(script, 0, end)] + [
        m.group(1) for m in printf_v.finditer(script, 0, end)
    ]


def notes_problems(wf: Workflow, forbidden: tuple[tuple[re.Pattern[str], str], ...] = NOTES_FORBIDDEN) -> list[str]:
    """The release notes read true both on the draft and once published (#309): they name
    SECURITY.md, the commit (``$GITHUB_SHA``), the wheel and its SHA-256 read from the ``.sha256``
    file, end with a ``Known issues:`` line pointing at the README's Known limits, hold no
    draft-only wording, never name the development repository, and link only the public repository
    at the release tag. The whole script of the step that runs ``gh release create`` is read, since
    multi-line notes span several lines; they may be inline or a ``"$var"`` assigned earlier in it.
    Fail-closed: the notes are given once (no second ``--notes``, ``--notes-file`` or
    ``--generate-notes``), double-quoted so the shell fills in their values, and a variable is
    written once: any other bare mention of its name before the release counts as a second
    write."""
    steps = [s for job in _jobs(wf).values() for s in _steps(job) if "gh release create" in str(s.get("run", ""))]
    if len(steps) != 1:
        return [f"{len(steps)} steps run gh release create, not one, so the release notes cannot be read"]
    script = str(steps[0]["run"]).replace("\\\n", " ")
    create = script.index("gh release create")
    arg = NOTES_ARG.search(script, create)
    if arg is None:
        return ['the release notes are missing: gh release create has no --notes "..." (--notes-file is not read)']
    flags = NOTES_FLAGS.findall(script, create)
    if len(flags) != 1:
        return [f"the release notes are given {len(flags)} times ({', '.join(flags)}), not once with --notes"]
    if arg.group(1).startswith("'"):
        return ["the release notes are single-quoted, so the shell never fills in their values"]
    notes = _shell_word(arg.group(1))
    var = NOTES_VAR.fullmatch(arg.group(1))
    if var is not None:
        name = var.group(1) or var.group(2)
        values = _assignments(script, name, arg.start())
        if len(values) != 1:
            return [
                f"the release notes are missing: ${name} is assigned {len(values)} times before the release, not once"
            ]
        if not values[0].startswith('"'):
            return [f"${name} is not double-quoted, so the shell never fills in the notes' values"]
        # Fail-closed: any other bare mention of the name before the release (a same-line or
        # conditional append, typeset, read, a quoted printf -v) is a possible second write.
        before = script[: arg.start()].replace(values[0], "", 1)
        writes = len(re.findall(rf"(?<![\w${{-]){re.escape(name)}(?![\w-])", before))
        if writes != 1:
            return [f"${name} is written {writes} times before the release, not once"]
        notes = _shell_word(values[0])

    def reads(needle: str) -> bool:
        """A variable or command substitution in the notes takes its value from text holding *needle*."""
        names = {m.group(1) or m.group(2) for m in SHELL_VAR.finditer(notes)}
        sources = COMMAND_SUBSTITUTION.findall(notes) + [v for n in names for v in _assignments(script, n, arg.start())]
        return any(needle in source for source in sources)

    def names(variable: str) -> bool:
        return any((m.group(1) or m.group(2)) == variable for m in SHELL_VAR.finditer(notes))

    problems: list[str] = []
    if "SECURITY.md" not in notes:
        problems.append("the notes do not say how to verify the wheel before installing it (SECURITY.md)")
    if not names("GITHUB_SHA"):
        problems.append("the notes do not name the commit the release was built from ($GITHUB_SHA)")
    if not reads(WHEEL_GLOB):
        problems.append(f"the notes do not name the wheel ({WHEEL_GLOB})")
    if not reads(".sha256"):
        problems.append("the notes do not give the wheel's SHA-256 read from its .sha256 file")
    lines = [line.strip() for line in notes.splitlines() if line.strip()]
    if not lines or not lines[-1].startswith("Known issues:"):
        problems.append("the notes do not end with a 'Known issues:' line")
    elif "Known limits" not in lines[-1]:
        problems.append("the 'Known issues:' line does not point at the README's Known limits section")
    for pattern, why in forbidden:
        problems += [f"the notes hold {m.group()!r}: {why}" for m in pattern.finditer(notes)]
    problems += [
        f"the notes link {url}, not the public repository at the release tag ({PUBLIC_LINK})"
        for url in URL.findall(notes)
        if not url.startswith(PUBLIC_LINK)
    ]
    return problems


def _step_index(steps: list[dict[str, Any]], match: Callable[[dict[str, Any]], bool]) -> int | None:
    return next((i for i, step in enumerate(steps) if match(step)), None)


def integrity_step_problems(wf: Workflow) -> list[str]:
    """The steps that keep the artifact honest (#231): every checkout takes only
    ``persist-credentials: false`` (no ``ref``, so the build is of the commit that ran it, the
    pushed tag); the attest and release jobs each check the downloaded wheel against its SHA-256
    before they attest or attach it; the attestation's subject is the wheel itself."""
    problems: list[str] = []
    jobs = _jobs(wf)
    for name, job in jobs.items():
        for index, step in enumerate(_steps(job), 1):
            if _action(str(step.get("uses", ""))) == "actions/checkout" and step.get("with") != CHECKOUT_WITH:
                problems.append(
                    f"{name}: step {index}: checkout takes {step.get('with')!r}, not only {CHECKOUT_WITH!r}"
                    " (a ref or repository builds some other commit; credentials must not persist)"
                )
    users: dict[str, tuple[str, Callable[[dict[str, Any]], bool]]] = {
        "attest": ("attests it", lambda s: _action(str(s.get("uses", ""))) == "actions/attest"),
        "release": ("attaches it", lambda s: "gh release create" in str(s.get("run", ""))),
    }
    for name, (what, uses_wheel) in users.items():
        steps = _steps(jobs.get(name) or {})
        download = _step_index(steps, lambda s: _action(str(s.get("uses", ""))) == "actions/download-artifact")
        use = _step_index(steps, uses_wheel)
        checks = [
            i
            for i, s in enumerate(steps)
            if str(s.get("run", "")).strip() == HASH_CHECK and s.get("working-directory") == "dist"
        ]
        if download is None or use is None or not any(download < i < use for i in checks):
            problems.append(f"{name}: no '{HASH_CHECK}' step in dist between the download and the step that {what}")
    subjects = [
        step.get("with", {}).get("subject-path")
        for job in jobs.values()
        for step in _steps(job)
        if _action(str(step.get("uses", ""))) == "actions/attest"
    ]
    if subjects != [f"dist/{WHEEL_GLOB}"]:
        problems.append(f"the attested subject-path is {subjects!r}, not the wheel dist/{WHEEL_GLOB}")
    return problems


ALL_WORKFLOW_CHECKS: tuple[Callable[[Workflow], list[str]], ...] = (
    unpinned_uses,
    pin_comment_problems,
    build_tool_problems,
    permission_problems,
    trigger_problems,
    expressions_in_run,
    attestation_problems,
    draft_problems,
    notes_problems,
    integrity_step_problems,
)


# --- the real files --------------------------------------------------------------


@pytest.fixture(scope="module")
def release() -> Workflow:
    return read_workflow(RELEASE.read_text(encoding="utf-8"), str(RELEASE))


def test_release_workflow_reads_with_guardians_reader(release: Workflow) -> None:
    assert release.doc["name"] == "Release"
    assert set(_jobs(release)) == {"build", "attest", "release"}


@pytest.mark.parametrize("check", ALL_WORKFLOW_CHECKS, ids=lambda c: c.__name__)
def test_real_release_workflow_passes(release: Workflow, check: Callable[[Workflow], list[str]]) -> None:
    assert check(release) == []


def test_checkout_and_setup_python_reuse_tests_workflow_pins(release: Workflow) -> None:
    tests = read_workflow(TESTS_WORKFLOW.read_text(encoding="utf-8"), str(TESTS_WORKFLOW))
    assert pin_reuse_problems(release, tests) == []
    used = {_action(ref) for job in _jobs(release).values() for ref in _uses(job)}
    assert set(REUSED_FROM_CI) <= used


def test_requirements_release_is_hash_locked() -> None:
    assert requirement_problems(REQUIREMENTS.read_text(encoding="utf-8")) == []


def test_build_job_never_gets_a_write_scope_or_an_oidc_token(release: Workflow) -> None:
    assert _jobs(release)["build"]["permissions"] == {"contents": "read"}


def test_checks_are_idempotent(release: Workflow) -> None:
    before = hashlib.sha256(RELEASE.read_bytes()).hexdigest()
    first = [check(release) for check in ALL_WORKFLOW_CHECKS]
    again = read_workflow(RELEASE.read_text(encoding="utf-8"), str(RELEASE))
    assert again == release
    assert [check(again) for check in ALL_WORKFLOW_CHECKS] == first
    assert hashlib.sha256(RELEASE.read_bytes()).hexdigest() == before


# --- planted copies --------------------------------------------------------------


def _planted(tmp_path: Path, old: str, new: str) -> Workflow:
    text = RELEASE.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"the planted text must occur exactly once: {old!r}"
    planted = tmp_path / "release.yml"
    planted.write_text(text.replace(old, new), encoding="utf-8")
    return read_workflow(planted.read_text(encoding="utf-8"), str(planted))


ATTEST_PIN = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
ATTEST_IF = "    if: github.repository == 'thomascburns/ssc-guardian'\n"
RELEASE_IF = f"    if: ${{{{ {RELEASE_CONDITION} }}}}\n"
BUILD_IF = f"    if: {BUILD_CONDITION}\n"
WHEEL_LINE = '          wheel="$(ls ssc_guardian-*-py3-none-any.whl)"\n'
EPOCH_LINE = "          export SOURCE_DATE_EPOCH\n"
NOTES_FLAG = '--notes "$notes"'
GH_CREATE = '          gh release create "$RELEASE_TAG"'
OLD_NOTES_FLAG = (
    '--notes "Draft built by the release workflow from $GITHUB_SHA. Verify the wheel before publishing (SECURITY.md)."'
)
SECURITY_LINK = f"in [SECURITY.md]({PUBLIC_LINK}SECURITY.md)"

PLANTS = [
    pytest.param(unpinned_uses, ATTEST_PIN, "actions/attest@v4", "actions/attest@v4", id="unpinned-uses-tag"),
    pytest.param(unpinned_uses, ATTEST_PIN, "actions/attest@1e69f48", "@1e69f48", id="unpinned-uses-short-sha"),
    pytest.param(pin_comment_problems, " # v4.2.2", "", "version comment", id="pin-without-version-comment"),
    pytest.param(
        pin_comment_problems,
        ATTEST_PIN,
        "actions/attest@0000000000000000000000000000000000000000",
        "not the reviewed commit",
        id="pin-not-reviewed",
    ),
    pytest.param(
        build_tool_problems,
        "pip install --require-hashes",
        "pip install",
        "--require-hashes",
        id="missing-require-hashes",
    ),
    pytest.param(
        build_tool_problems,
        "-r requirements-release.txt",
        "build setuptools",
        "requirements-release.txt",
        id="unlocked",
    ),
    pytest.param(
        build_tool_problems, "build --wheel --no-isolation", "build --wheel", "isolation", id="isolated-build"
    ),
    pytest.param(build_tool_problems, " --only-binary :all:", "", "--only-binary", id="sdist-allowed"),
    pytest.param(
        build_tool_problems,
        EPOCH_LINE,
        EPOCH_LINE + "          pip download --no-deps -d dist setuptools\n",
        "outside the locked route",
        id="pip-download",
    ),
    pytest.param(
        build_tool_problems,
        EPOCH_LINE,
        EPOCH_LINE + "          uv build --wheel\n",
        "outside the locked route",
        id="uv-build",
    ),
    pytest.param(
        permission_problems,
        "permissions:\n  contents: read\n\nconcurrency",
        "permissions:\n  contents: write\n\nconcurrency",
        "top-level",
        id="top-level-write",
    ),
    pytest.param(
        permission_problems,
        "permissions:\n  contents: read\n\nconcurrency",
        "permissions: write-all\n\nconcurrency",
        "top-level",
        id="top-level-write-all",
    ),
    pytest.param(
        permission_problems,
        "    timeout-minutes: 15\n    permissions:\n      contents: read\n",
        "    timeout-minutes: 15\n    permissions:\n      contents: read\n      id-token: write\n",
        "build: id-token",
        id="oidc-in-build-job",
    ),
    pytest.param(
        permission_problems,
        "      contents: read\n      id-token: write\n",
        "      contents: write\n      id-token: write\n",
        "attest: contents",
        id="contents-write-in-attest-job",
    ),
    pytest.param(
        trigger_problems, "on:\n  push:\n", "on:\n  pull_request_target:\n  push:\n", "pull_request_target", id="prt"
    ),
    pytest.param(
        trigger_problems, "on:\n  push:\n", "on:\n  pull_request:\n  push:\n", "pull_request", id="pull-request"
    ),
    pytest.param(
        trigger_problems,
        '    tags:\n      - "v*-reference"\n',
        "    branches:\n      - main\n",
        "tags only",
        id="push-to-main",
    ),
    pytest.param(trigger_problems, BUILD_IF, "", "build: runs when", id="tag-push-runs-in-this-repository"),
    pytest.param(
        trigger_problems,
        BUILD_IF,
        "    if: github.event_name == 'workflow_dispatch' || github.repository == 'thomascburns/ssc-guardian'\n",
        "build: runs when",
        id="manual-run-in-public-repository",
    ),
    pytest.param(
        trigger_problems,
        "  attest:\n    needs: build\n",
        "  attest:\n",
        "attest: does not need build",
        id="attest-not-gated-by-build",
    ),
    pytest.param(
        expressions_in_run,
        'gh release create "$RELEASE_TAG"',
        'gh release create "${{ inputs.tag }}"',
        "inside run",
        id="expression-in-run",
    ),
    pytest.param(attestation_problems, ATTEST_IF, "", "not only when", id="attest-in-every-repository"),
    pytest.param(
        attestation_problems,
        ATTEST_IF,
        f"    if: github.repository == '{OTHER_REPOSITORY}'\n",
        "not only when",
        id="attest-in-another-repository",
    ),
    pytest.param(
        attestation_problems,
        ATTEST_IF,
        "    if: github.repository == 'thomascburns/ssc-guardian' || true\n",
        "not only when",
        id="attest-or-true",
    ),
    pytest.param(
        attestation_problems, RELEASE_IF, "    if: ${{ !cancelled() }}\n", "not only after", id="draft-unconditional"
    ),
    pytest.param(
        attestation_problems,
        RELEASE_IF,
        RELEASE_IF.replace(" && github.repository != 'thomascburns/ssc-guardian'", ""),
        "not only after",
        id="public-draft-with-skipped-attestation",
    ),
    pytest.param(
        attestation_problems,
        RELEASE_IF,
        "    if: ${{ !cancelled() && (needs.attest.result == 'success' || needs.attest.result == 'skipped'"
        " || github.repository != 'thomascburns/ssc-guardian') }}\n",
        "not only after",
        id="safeguard-ored-away",
    ),
    pytest.param(
        attestation_problems,
        RELEASE_IF,
        RELEASE_IF.replace("needs.build.result == 'success' && ", ""),
        "not only after",
        id="draft-after-failed-build",
    ),
    pytest.param(
        attestation_problems,
        "      - build\n      - attest\n",
        "      - build\n",
        "wait for attest",
        id="no-attest-need",
    ),
    pytest.param(draft_problems, "            --draft \\\n", "", "draft", id="draft-off"),
    pytest.param(draft_problems, "--draft \\", "--draft=false \\", "draft", id="draft-false"),
    pytest.param(draft_problems, ' "$wheel.sha256"', "", "SHA-256", id="sha256-not-attached"),
    pytest.param(
        draft_problems,
        WHEEL_LINE,
        WHEEL_LINE + '          gh api -X PATCH "repos/$GH_REPO/releases/1" -F draft=false\n',
        "changes a release",
        id="publish-through-gh-api",
    ),
    pytest.param(
        draft_problems,
        WHEEL_LINE,
        WHEEL_LINE + '          gh release upload "$RELEASE_TAG" extra.txt\n',
        "changes a release",
        id="upload-after-creation",
    ),
    pytest.param(
        draft_problems,
        WHEEL_LINE,
        WHEEL_LINE
        + '          gh api graphql -f query=\'mutation { updateRelease(input: {releaseId: "1", isDraft: false})'
        + " { release { id } } }'\n",
        "changes a release",
        id="publish-through-graphql",
    ),
    pytest.param(
        trigger_problems,
        '      - "v*-reference"\n',
        '      - "v*-reference"\n      - "*"\n',
        "tag pattern",
        id="any-tag-pushed",
    ),
    pytest.param(notes_problems, NOTES_FLAG, OLD_NOTES_FLAG, "Draft built", id="notes-old-draft-text"),
    pytest.param(notes_problems, NOTES_FLAG, OLD_NOTES_FLAG, "before publishing", id="notes-old-before-publishing"),
    pytest.param(notes_problems, SECURITY_LINK, "on the project page", "SECURITY.md", id="notes-without-security"),
    pytest.param(
        notes_problems,
        PUBLIC_LINK + "SECURITY.md",
        "https://github.com/$GITHUB_REPOSITORY/blob/$RELEASE_TAG/SECURITY.md",
        "$GITHUB_REPOSITORY",
        id="notes-link-through-github-repository",
    ),
    pytest.param(
        notes_problems,
        PUBLIC_LINK + "SECURITY.md",
        "https://github.com/$GH_REPO/blob/$RELEASE_TAG/SECURITY.md",
        "$GH_REPO",
        id="notes-link-through-gh-repo",
    ),
    pytest.param(
        notes_problems,
        PUBLIC_LINK + "SECURITY.md",
        "https://example.invalid/SECURITY.md",
        "not the public repository",
        id="notes-link-elsewhere",
    ),
    pytest.param(notes_problems, "commit $GITHUB_SHA.", "the tagged commit.", "$GITHUB_SHA", id="notes-without-commit"),
    pytest.param(notes_problems, "          - Wheel: $wheel\n", "", "name the wheel", id="notes-without-wheel"),
    pytest.param(notes_problems, "          - SHA-256: $sha256\n", "", "SHA-256", id="notes-without-sha256"),
    pytest.param(
        notes_problems,
        "\n\n          Known issues: see [Known limits]",
        " See [Known limits]",
        "Known issues:",
        id="notes-without-known-issues",
    ),
    pytest.param(
        notes_problems,
        "Known issues: see [Known limits]",
        "Known issues: none",
        "Known limits",
        id="known-issues-no-pointer",
    ),
    pytest.param(notes_problems, " \\\n            " + NOTES_FLAG, "", "notes are missing", id="notes-flag-missing"),
    pytest.param(notes_problems, NOTES_FLAG, "--notes-file notes.md", "notes are missing", id="notes-file"),
    pytest.param(
        notes_problems,
        WHEEL_LINE,
        WHEEL_LINE + '          notes="other"\n',
        "assigned 2 times",
        id="notes-assigned-twice",
    ),
    pytest.param(
        notes_problems,
        GH_CREATE,
        '          notes+=" Draft built"\n' + GH_CREATE,
        "assigned 2 times",
        id="notes-appended",
    ),
    pytest.param(
        notes_problems,
        GH_CREATE,
        '          export notes="Draft built"\n' + GH_CREATE,
        "assigned 2 times",
        id="notes-exported-again",
    ),
    pytest.param(
        notes_problems,
        GH_CREATE,
        '          printf -v notes "Draft built"\n' + GH_CREATE,
        "assigned 2 times",
        id="notes-printf-v",
    ),
    pytest.param(
        notes_problems,
        GH_CREATE,
        '          [ "$GH_REPO" != thomascburns/ssc-guardian ] || notes+=" Draft built"\n' + GH_CREATE,
        "written 2 times",
        id="notes-conditional-append",
    ),
    pytest.param(
        notes_problems,
        GH_CREATE,
        '          read -r notes <<<"Draft built"\n' + GH_CREATE,
        "written 2 times",
        id="notes-read",
    ),
    pytest.param(
        notes_problems, NOTES_FLAG, NOTES_FLAG + ' --notes "Draft built"', "given 2 times", id="second-notes-flag"
    ),
    pytest.param(
        notes_problems, NOTES_FLAG, NOTES_FLAG + " --notes-file draft.md", "given 2 times", id="notes-file-appended"
    ),
    pytest.param(
        notes_problems, NOTES_FLAG, NOTES_FLAG + " --generate-notes", "given 2 times", id="generate-notes-appended"
    ),
    pytest.param(
        notes_problems, NOTES_FLAG, "--notes 'Built from $GITHUB_SHA'", "single-quoted", id="inline-single-quoted"
    ),
    pytest.param(
        notes_problems,
        '          notes="Software',
        "          notes='Software'\n          unused=\"Software",
        "not double-quoted",
        id="notes-variable-single-quoted",
    ),
]

HASH_STEP = (
    f"      - name: Check the wheel against its SHA-256\n        working-directory: dist\n        run: {HASH_CHECK}\n"
)
ATTEST_STEP = f"      - uses: {ATTEST_PIN} # v4.2.2\n        with:\n          subject-path: dist/{WHEEL_GLOB}\n"
DRAFT_COMMENT = "      # A draft: the owner publishes"
ONE_WHEEL_BLOCK = (
    '          if [ "${#wheels[@]}" -ne 1 ]; then\n'
    '            echo "Expected exactly one ssc_guardian wheel, found ${#wheels[@]}." >&2\n'
    "            exit 1\n"
    "          fi\n"
)
CHECKOUT_STEP = (
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
    "        with:\n"
    "          persist-credentials: false\n"
)


@pytest.mark.parametrize(("check", "old", "new", "expected"), PLANTS)
def test_planted_copy_fails_its_check(
    tmp_path: Path, check: Callable[[Workflow], list[str]], old: str, new: str, expected: str
) -> None:
    problems = check(_planted(tmp_path, old, new))
    assert problems, "the planted defect went unnoticed"
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        pytest.param(HASH_STEP + ATTEST_STEP, ATTEST_STEP, "attest: no 'sha256sum -c", id="attest-hash-step-deleted"),
        pytest.param(HASH_STEP + DRAFT_COMMENT, DRAFT_COMMENT, "release: no 'sha256sum -c", id="release-hash-deleted"),
        pytest.param(
            HASH_STEP + ATTEST_STEP, ATTEST_STEP + HASH_STEP, "attest: no 'sha256sum -c", id="attest-hash-step-after"
        ),
        pytest.param(
            HASH_STEP + DRAFT_COMMENT,
            HASH_STEP.replace("sha256sum -c", "sha256sum") + DRAFT_COMMENT,
            "release: no 'sha256sum -c",
            id="release-hash-not-checked",
        ),
        pytest.param(
            f"subject-path: dist/{WHEEL_GLOB}\n",
            f"subject-path: dist/{WHEEL_GLOB}.sha256\n",
            "subject-path",
            id="hash-file-attested",
        ),
    ],
)
def test_hash_steps_and_attested_subject_are_present(
    release: Workflow, tmp_path: Path, old: str, new: str, expected: str
) -> None:
    assert integrity_step_problems(release) == []
    problems = integrity_step_problems(_planted(tmp_path, old, new))
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize(
    "new",
    [
        pytest.param(CHECKOUT_STEP + "          ref: main\n", id="ref-main"),
        pytest.param(CHECKOUT_STEP + "          repository: someone/fork\n", id="other-repository"),
        pytest.param(CHECKOUT_STEP.replace("false", "true"), id="credentials-persist"),
        pytest.param(CHECKOUT_STEP.split("        with:")[0], id="credentials-persist-by-default"),
    ],
)
def test_build_checkout_has_no_ref(release: Workflow, tmp_path: Path, new: str) -> None:
    build_checkouts = [
        s for s in _steps(_jobs(release)["build"]) if _action(str(s.get("uses", ""))) == "actions/checkout"
    ]
    assert [s.get("with") for s in build_checkouts] == [CHECKOUT_WITH]
    problems = integrity_step_problems(_planted(tmp_path, CHECKOUT_STEP, new))
    assert any(p.startswith("build: step 2: checkout takes") for p in problems), problems


def test_record_step_refuses_any_count_but_one_wheel(release: Workflow, tmp_path: Path) -> None:
    """Runs the step's own script under bash: one wheel gets its SHA-256; none or two is refused."""

    def run(workflow: Workflow, wheels: int) -> tuple[subprocess.CompletedProcess[str], Path]:
        dist = tmp_path / f"dist-{len(list(tmp_path.iterdir()))}"
        dist.mkdir()
        for n in range(wheels):
            (dist / f"ssc_guardian-1.0.{n}-py3-none-any.whl").write_bytes(f"wheel {n}".encode())
        return _run_step(_step_script(workflow, RECORD_STEP), tmp_path, dist, {}), dist

    result, dist = run(release, 1)
    assert result.returncode == 0, result.stderr
    wheel = dist / "ssc_guardian-1.0.0-py3-none-any.whl"
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert (dist / f"{wheel.name}.sha256").read_text().split() == [digest, wheel.name]
    for count in (0, 2):
        result, dist = run(release, count)
        assert result.returncode != 0 and "Expected exactly one ssc_guardian wheel" in result.stderr
        assert not list(dist.glob("*.sha256"))
    # Negative control: without the count check, two wheels pass and only the first is hashed.
    result, _dist = run(_planted(tmp_path, ONE_WHEEL_BLOCK, ""), 2)
    assert result.returncode == 0, result.stderr


def _step_script(release: Workflow, name: str) -> str:
    steps = [s for s in _steps(_jobs(release)["build"]) if s.get("name") == name]
    assert len(steps) == 1, f"the build job must have one step named {name!r}"
    run = steps[0]["run"]
    assert isinstance(run, str)
    return run


def _run_step(script_text: str, tmp_path: Path, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run a step's own script under bash the way GitHub does (-e, pipefail)."""
    script = tmp_path / "step.sh"
    script.write_text(script_text, encoding="utf-8")
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        cwd=cwd,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize(
    ("tag", "repository", "passes"),
    [
        pytest.param("v1.0.0-reference", PUBLIC_REPOSITORY, True, id="release-in-public"),
        pytest.param("v1.0.1-reference", PUBLIC_REPOSITORY, True, id="patch-in-public"),
        pytest.param("v1.0.1-rc1-reference", OTHER_REPOSITORY, True, id="rehearsal-off-public"),
        pytest.param("v1.0.1-rc1-reference", PUBLIC_REPOSITORY, False, id="rehearsal-in-public"),
        # Negative control (#327): a two-part tag is refused, release or rehearsal, in either repository.
        pytest.param("v1.1-reference", PUBLIC_REPOSITORY, False, id="two-part-release"),
        pytest.param("v1.0-reference", OTHER_REPOSITORY, False, id="two-part-release-off-public"),
        pytest.param("v1.0-rc1-reference", OTHER_REPOSITORY, False, id="two-part-rehearsal"),
        pytest.param("v1.0.1.1-reference", PUBLIC_REPOSITORY, False, id="four-part"),
        pytest.param("v1.0.1", PUBLIC_REPOSITORY, False, id="no-reference-suffix"),
        pytest.param("v1.0.1-reference; echo injected", OTHER_REPOSITORY, False, id="shell-text"),
    ],
)
def test_tag_step_accepts_only_release_tags_and_rehearsals_off_public(
    release: Workflow, tmp_path: Path, tag: str, repository: str, passes: bool
) -> None:
    script = _step_script(release, "Check the release tag")
    result = _run_step(script, tmp_path, tmp_path, {"RELEASE_TAG": tag, "GITHUB_REPOSITORY": repository})
    assert (result.returncode == 0) is passes, result.stdout + result.stderr
    if not passes:
        assert "Refusing" in result.stderr


@pytest.mark.parametrize(
    ("tag", "version", "passes"),
    [
        pytest.param("v1.0.0-reference", "1.0.0", True, id="release"),
        pytest.param("v1.0.1-reference", "1.0.1", True, id="patch-release"),
        pytest.param("v1.0.1-rc1-reference", "1.0.0.dev0", True, id="rehearsal-any-version"),
        pytest.param("v1.0.1-reference", "1.0.1.dev0", False, id="dev-version-under-release-tag"),
        pytest.param("v1.0.0-reference", "1.0.1", False, id="wrong-patch"),
        pytest.param("v1.0.1-reference", "1.0.0", False, id="patch-tag-old-wheel"),
        # A two-part tag is no longer padded to three parts (#327).
        pytest.param("v1.0-reference", "1.0.0", False, id="two-part-tag-not-padded"),
    ],
)
def test_version_step_refuses_a_wheel_that_does_not_match_its_tag(
    release: Workflow, tmp_path: Path, tag: str, version: str, passes: bool
) -> None:
    """Runs the step's own script under bash in a scratch dist/."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / f"ssc_guardian-{version}-py3-none-any.whl").write_bytes(b"")
    result = _run_step(_step_script(release, VERSION_STEP), tmp_path, dist, {"RELEASE_TAG": tag})
    assert (result.returncode == 0) is passes, result.stdout + result.stderr
    if not passes:
        assert "Refusing" in result.stderr


NOTES_SHA = "0123456789abcdef0123456789abcdef01234567"  # the commit a rehearsal is built from


def published_notes(release: Workflow, tmp_path: Path) -> tuple[str, str, str]:
    """Runs the release step's own script under bash with a stand-in ``gh`` that records its
    arguments, as a rehearsal in another repository would; returns (notes, wheel name, SHA-256)."""
    steps = [s for s in _steps(_jobs(release)["release"]) if s.get("name") == "Create the draft release"]
    assert len(steps) == 1
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "ssc_guardian-1.0.1-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    digest = hashlib.sha256(b"wheel").hexdigest()
    (dist / f"{wheel.name}.sha256").write_text(f"{digest}  {wheel.name}\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "gh"
    stub.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" > "$GH_ARGS"\n', encoding="utf-8")
    stub.chmod(0o755)
    record = tmp_path / "gh-args"
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "RELEASE_TAG": "v1.0.1-reference",
        "GITHUB_SHA": NOTES_SHA,
        "GH_REPO": OTHER_REPOSITORY,
        "GITHUB_REPOSITORY": OTHER_REPOSITORY,
        "GH_ARGS": str(record),
    }
    result = _run_step(str(steps[0]["run"]), tmp_path, dist, env)
    assert result.returncode == 0, result.stdout + result.stderr
    args = record.read_text(encoding="utf-8").split("\0")[:-1]
    assert args[:6] == ["release", "create", "v1.0.1-reference", wheel.name, f"{wheel.name}.sha256", "--draft"]
    assert args.count("--notes") == 1
    return args[args.index("--notes") + 1], wheel.name, digest


def test_release_step_passes_notes_that_stay_true_once_published(release: Workflow, tmp_path: Path) -> None:
    """The notes the release step passes (#309) name the wheel, its real SHA-256 and the commit,
    link SECURITY.md in the public repository at the tag, and end with the Known issues line."""
    notes, wheel_name, digest = published_notes(release, tmp_path)
    for text in (
        wheel_name,
        digest,
        NOTES_SHA,
        "https://github.com/thomascburns/ssc-guardian/blob/v1.0.1-reference/SECURITY.md",
    ):
        assert text in notes, text
    assert notes.splitlines()[-1].startswith("Known issues: see [Known limits](")
    # The running repository's name never reaches the notes.
    assert "$" not in notes
    assert OTHER_REPOSITORY not in notes and OTHER_REPOSITORY.split("/")[1] not in notes
    assert "before publishing" not in notes.lower() and "draft" not in notes.lower()


def _checked_in_version(pyproject: Path) -> str:
    """The ``[project]`` version of a ``pyproject.toml``; a missing or unreadable one fails clearly."""
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{pyproject}: cannot read the version: {exc}") from exc
    project = data.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version:
        raise ValueError(f"{pyproject}: no [project] version")
    return version


def test_checked_in_version_matches_the_release_tag(release: Workflow, tmp_path: Path) -> None:
    """The checked-in version, written as its three-part release tag, passes the workflow's tag
    step, so a `.dev0` or two-part version fails here; the version step then runs on that tag, which
    only shows the step accepts it, since the tag is built from the version (#294, #327)."""
    version = _checked_in_version(PYPROJECT)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / f"ssc_guardian-{version}-py3-none-any.whl").write_bytes(b"")
    tag = f"v{version}-reference"
    result = _run_step(
        _step_script(release, "Check the release tag"),
        tmp_path,
        tmp_path,
        {"RELEASE_TAG": tag, "GITHUB_REPOSITORY": PUBLIC_REPOSITORY},
    )
    assert result.returncode == 0, f"pyproject.toml version {version}: {result.stdout}{result.stderr}"
    result = _run_step(_step_script(release, VERSION_STEP), tmp_path, dist, {"RELEASE_TAG": tag})
    assert result.returncode == 0, f"pyproject.toml version {version}: {result.stdout}{result.stderr}"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param('[project]\nname = "ssc-guardian"\n', r"no \[project\] version", id="missing-version"),
        pytest.param("[project]\nversion = 1\n", r"no \[project\] version", id="version-not-text"),
        pytest.param('version = "1.0.0"\n', r"no \[project\] version", id="no-project-table"),
        pytest.param('[project\nversion = "1.0.0"\n', "cannot read the version", id="not-toml"),
        pytest.param(None, "cannot read the version", id="no-file"),
    ],
)
def test_version_read_fails_clearly_on_a_planted_pyproject(tmp_path: Path, text: str | None, message: str) -> None:
    planted = tmp_path / "pyproject.toml"
    if text is not None:
        planted.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        _checked_in_version(planted)


def test_planted_checkout_pin_differing_from_tests_workflow_fails(tmp_path: Path) -> None:
    tests = read_workflow(TESTS_WORKFLOW.read_text(encoding="utf-8"), str(TESTS_WORKFLOW))
    planted = _planted(
        tmp_path,
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@1111111111111111111111111111111111111111",
    )
    assert pin_reuse_problems(planted, tests) == ["build: actions/checkout@" + "1" * 40 + " is not tests.yml's pin"]


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        pytest.param("build==1.6.1", "build>=1.6.1", "not pinned", id="range-not-pin"),
        pytest.param(
            "    --hash=sha256:51cc11666391ab6f092070437ac747002ff46f3e4113a3622177ee6b488bfc53 \\\n"
            "    --hash=sha256:ecd351a4be9d35a9eaaba244a7687143c9c7d4aea6ac964e7e7ddab20cbcf4e7\n",
            "",
            "build==1.6.1",
            id="no-hash",
        ),
        pytest.param("setuptools==84.2.1", "# setuptools==84.2.1", "setuptools is not locked", id="backend-missing"),
    ],
)
def test_planted_requirements_fail(old: str, new: str, expected: str) -> None:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert text.count(old) == 1
    problems = requirement_problems(text.replace(old, new))
    assert any(expected in p for p in problems), problems
