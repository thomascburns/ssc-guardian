# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The documents a user follows to download, verify and pin Guardian name the checked-in release.

README.md, SECURITY.md, CONTRIBUTING.md, docs/gate-snippet.md and docs/claude-code-routing.md hold
the commands that download a release, verify its wheel and pin it in a commit gate, and the
sentences that name the reference release. Each release's version is written into them by hand,
so this guard reads ``pyproject.toml``'s ``[project] version`` and checks that every wheel file
name (``ssc_guardian-<version>-py3-none-any.whl``) and every release tag
(``v<version>-reference``) in them names that version. A tag starts with ``v`` and a digit, so
the rule name ``moving-reference`` is not one, and a glob such as ``ssc_guardian-*.whl`` is not a
wheel name. Each document must name at least one wheel or tag, so an emptied document is not a
silent pass. The changelogs, docs/changelog.md included, and output captured from an earlier
release are history and are not read.

It fails closed: an unreadable or malformed ``pyproject.toml``, a missing version, and a missing
or unreadable document are each a problem, never a pass. Each check runs on this checkout and on
planted copies under ``tmp_path``. It reads files only and gives the same result on a re-run.
No network.

A second guard (#353) checks that README.md, SECURITY.md, CONTRIBUTING.md and the release notes
in ``.github/workflows/release.yml`` call Guardian "a reference implementation", the owner's
name for it since 2026-11-19. It bans no phrase: "reference release" stays correct English, and
the 1.0.0 history keeps it. The notes are the text the release step assigns to ``notes``, read
with Guardian's own YAML reader; a missing document, an unreadable workflow and a release step
that assigns no notes are each a problem, never a pass.

A third guard (#354) checks the local-only paragraph in README.md and docs/index.html against the
client: each says Guardian's own requests identify the client only as the User-Agent
``ssc_guardian.net.Client`` sends by default (read from its signature, never copied here), and
each carries the pip exception; SECURITY.md carries the paragraph on pip's own User-Agent. None
of the three may say that a lookup carries only package names and versions, that Guardian reports
nothing about the user's machine, or that Guardian has its own pip. The site is read with its tags
removed. A missing document is a problem, never a pass.
"""

from __future__ import annotations

import html
import inspect
import re
import shutil
import tomllib
from collections.abc import Sequence
from pathlib import Path

import pytest

from ssc_guardian.net import Client
from ssc_guardian.yaml_subset import UnsupportedYamlError, parse, to_python

# doc_content: these tests read the published documents and pyproject.toml.
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
PYPROJECT = REPO / "pyproject.toml"
DOCUMENTS = (
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/gate-snippet.md",
    "docs/claude-code-routing.md",
)

_WHEEL = re.compile(r"ssc_guardian-(\d[\w.+]*?)-py3-none-any\.whl")
_TAG = re.compile(r"\bv(\d[\w.-]*?)-reference\b")


def release_doc_problems(pyproject: Path, root: Path, documents: Sequence[str] = DOCUMENTS) -> list[str]:
    """Return every wheel name or tag in ``documents`` that is not ``pyproject``'s version."""
    try:
        project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project")
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot read {pyproject.name}: {exc}"]
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version.strip():
        return [f"{pyproject.name} has no text [project] version"]

    problems: list[str] = []
    for name in documents:
        try:
            text = (root / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"cannot read {name}: {exc}")
            continue
        found = 0
        for number, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in (("wheel", _WHEEL), ("tag", _TAG)):
                for match in pattern.finditer(line):
                    found += 1
                    if match.group(1) != version:
                        problems.append(f"{name}:{number}: {kind} {match.group(0)} is not release {version}")
        if not found:
            problems.append(f"{name} names no release wheel or tag")
    return problems


def _copy(tmp_path: Path) -> Path:
    """Copy ``pyproject.toml`` and the documents into ``tmp_path``; return the copy's root."""
    shutil.copyfile(PYPROJECT, tmp_path / "pyproject.toml")
    for name in DOCUMENTS:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    return tmp_path


def _plant(root: Path, name: str, line: str) -> int:
    """Append ``line`` to ``root / name``; return its line number."""
    path = root / name
    text = path.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    text += line + "\n"
    path.write_text(text, encoding="utf-8")
    return text.count("\n")


def test_docs_name_the_checked_in_release() -> None:
    assert release_doc_problems(PYPROJECT, REPO) == []


def test_planted_old_wheel_name_fails(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    assert release_doc_problems(root / "pyproject.toml", root) == []
    number = _plant(root, "README.md", "uv tool install ./ssc_guardian-1.0.0-py3-none-any.whl")
    version = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert release_doc_problems(root / "pyproject.toml", root) == [
        f"README.md:{number}: wheel ssc_guardian-1.0.0-py3-none-any.whl is not release {version}"
    ]


def test_planted_old_tag_fails(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    number = _plant(root, "SECURITY.md", "gh release verify v1.0-reference -R thomascburns/ssc-guardian")
    version = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert release_doc_problems(root / "pyproject.toml", root) == [
        f"SECURITY.md:{number}: tag v1.0-reference is not release {version}"
    ]


def test_missing_document_fails_loudly(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    (root / "docs" / "gate-snippet.md").unlink()
    problems = release_doc_problems(root / "pyproject.toml", root)
    assert len(problems) == 1
    assert problems[0].startswith("cannot read docs/gate-snippet.md: ")


def test_document_naming_no_release_fails(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    assert release_doc_problems(root / "pyproject.toml", root) == ["CONTRIBUTING.md names no release wheel or tag"]


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(None, "cannot read pyproject.toml: ", id="missing"),
        pytest.param("[project\n", "cannot read pyproject.toml: ", id="malformed"),
        pytest.param('[project]\nname = "x"\n', "pyproject.toml has no text [project] version", id="no-version"),
    ],
)
def test_unreadable_pyproject_fails(tmp_path: Path, content: str | None, expected: str) -> None:
    root = _copy(tmp_path)
    pyproject = root / "pyproject.toml"
    if content is None:
        pyproject.unlink()
    else:
        pyproject.write_text(content, encoding="utf-8")
    problems = release_doc_problems(pyproject, root)
    assert len(problems) == 1
    assert problems[0].startswith(expected)


def test_release_docs_check_is_idempotent(tmp_path: Path) -> None:
    assert release_doc_problems(PYPROJECT, REPO) == release_doc_problems(PYPROJECT, REPO)
    root = _copy(tmp_path)
    _plant(root, "README.md", "ssc_guardian-1.0.0-py3-none-any.whl v1.0-reference")
    first = release_doc_problems(root / "pyproject.toml", root)
    assert first == release_doc_problems(root / "pyproject.toml", root)
    assert len(first) == 2


# --- "a reference implementation" (#353) -------------------------------------------

PHRASE = "reference implementation"
PHRASE_DOCUMENTS = ("README.md", "SECURITY.md", "CONTRIBUTING.md")
RELEASE_WORKFLOW = ".github/workflows/release.yml"
NOTES_STEP = "Create the draft release"
_NOTES = re.compile(r'^[ \t]*notes="((?:[^"\\]|\\.)*)"', re.MULTILINE)
_PHRASE = re.compile(r"reference\s+implementation", re.IGNORECASE)


def _says_phrase(text: str) -> bool:
    """True when ``text`` holds the phrase, in any case, even where a line break splits it."""
    return _PHRASE.search(text) is not None


def release_notes(workflow: Path) -> str:
    """The text the release step (``NOTES_STEP``) assigns to ``notes``, ``\\"`` unescaped.

    Raises OSError or UnicodeDecodeError for an unreadable file, UnsupportedYamlError for YAML
    Guardian's reader refuses, and LookupError when no single step assigns the notes once."""
    text = workflow.read_text(encoding="utf-8")
    doc = to_python(parse(text, str(workflow)))
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    job = jobs.get("release") if isinstance(jobs, dict) else None
    steps = job.get("steps") if isinstance(job, dict) else None
    scripts = [
        s.get("run")
        for s in (steps if isinstance(steps, list) else [])
        if isinstance(s, dict) and s.get("name") == NOTES_STEP
    ]
    if len(scripts) != 1 or not isinstance(scripts[0], str):
        raise LookupError(f"no single release step named {NOTES_STEP!r} with a run script")
    values = _NOTES.findall(scripts[0])
    if len(values) != 1:
        raise LookupError(f"the release step assigns notes {len(values)} times, not once")
    return str(values[0]).replace('\\"', '"')


def reference_implementation_problems(
    root: Path, documents: Sequence[str] = PHRASE_DOCUMENTS, workflow: str = RELEASE_WORKFLOW
) -> list[str]:
    """Each document under ``root``, and the release notes, that does not say ``PHRASE``."""
    problems: list[str] = []
    for name in documents:
        try:
            text = (root / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"cannot read {name}: {exc}")
            continue
        if not _says_phrase(text):
            problems.append(f"{name} does not say {PHRASE!r}")
    try:
        notes = release_notes(root / workflow)
    except (OSError, UnicodeDecodeError, UnsupportedYamlError, LookupError) as exc:
        problems.append(f"cannot read the release notes in {workflow}: {exc}")
    else:
        if not _says_phrase(notes):
            problems.append(f"the release notes in {workflow} do not say {PHRASE!r}")
    return problems


def _copy_phrase_documents(tmp_path: Path) -> Path:
    for name in (*PHRASE_DOCUMENTS, RELEASE_WORKFLOW):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    return tmp_path


def _take_phrase_out(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    planted, count = _PHRASE.subn("reference build", text)
    assert count, f"{path.name} held no phrase to take out"
    path.write_text(planted, encoding="utf-8")


def test_documents_call_guardian_a_reference_implementation(tmp_path: Path) -> None:
    assert reference_implementation_problems(REPO) == []
    # The notes are read from the release step itself, and say the phrase on their first line.
    assert PHRASE in release_notes(REPO / RELEASE_WORKFLOW).splitlines()[0]
    # Negative control: a planted copy with the phrase taken out fails, one document at a time.
    expected = {
        **{name: f"{name} does not say {PHRASE!r}" for name in PHRASE_DOCUMENTS},
        RELEASE_WORKFLOW: f"the release notes in {RELEASE_WORKFLOW} do not say {PHRASE!r}",
    }
    for name, problem in expected.items():
        root = _copy_phrase_documents(tmp_path / name.replace("/", "_"))
        assert reference_implementation_problems(root) == []
        _take_phrase_out(root / name)
        assert reference_implementation_problems(root) == [problem]


def test_phrase_split_by_a_line_break_still_counts(tmp_path: Path) -> None:
    root = _copy_phrase_documents(tmp_path)
    (root / "SECURITY.md").write_text("# Security\n\nThis is a reference\nimplementation.\n", encoding="utf-8")
    assert reference_implementation_problems(root) == []


def test_missing_phrase_document_fails_loudly(tmp_path: Path) -> None:
    root = _copy_phrase_documents(tmp_path)
    (root / "CONTRIBUTING.md").unlink()
    problems = reference_implementation_problems(root)
    assert len(problems) == 1
    assert problems[0].startswith("cannot read CONTRIBUTING.md: ")


@pytest.mark.parametrize(
    ("content", "detail"),
    [
        pytest.param(None, "", id="missing"),
        pytest.param("jobs: [unclosed\n", "", id="refused-yaml"),
        pytest.param("jobs:\n  release:\n    steps: []\n", "no single release step", id="no-step"),
        pytest.param(
            f"jobs:\n  release:\n    steps:\n      - name: {NOTES_STEP}\n        run: echo hi\n",
            "assigns notes 0 times",
            id="no-notes",
        ),
    ],
)
def test_unreadable_release_notes_fail_loudly(tmp_path: Path, content: str | None, detail: str) -> None:
    root = _copy_phrase_documents(tmp_path)
    workflow = root / RELEASE_WORKFLOW
    if content is None:
        workflow.unlink()
    else:
        workflow.write_text(content, encoding="utf-8")
    problems = reference_implementation_problems(root)
    assert len(problems) == 1
    assert problems[0].startswith(f"cannot read the release notes in {RELEASE_WORKFLOW}: ")
    assert detail in problems[0]


def test_reference_implementation_check_is_idempotent(tmp_path: Path) -> None:
    assert reference_implementation_problems(REPO) == reference_implementation_problems(REPO)
    root = _copy_phrase_documents(tmp_path)
    _take_phrase_out(root / "README.md")
    first = reference_implementation_problems(root)
    assert first == reference_implementation_problems(root) == [f"README.md does not say {PHRASE!r}"]


# --- the local-only paragraph (#354) ------------------------------------------------

LOCAL_ONLY_DOCUMENTS = ("README.md", "docs/index.html")
TRUST_DOCUMENT = "SECURITY.md"
PIP_EXCEPTION = "The one exception is ssc-guardian install, which installs packages with the standard pip."
PIP_TELLS_PYPI = "pip tells PyPI your Python version, operating-system version and processor type."
PIP_UNCHANGED = "Guardian does not change pip."
# Claims the code does not bear out (#354): Guardian's client sends its User-Agent, and pip sends its own.
UNTRUE_CLAIMS = ("carries only the names and versions", "reports nothing about your use", "Guardian's own pip")
_TAG_OR_TICK = re.compile(r"<[^>]+>|`")


def _client_name() -> object:
    """The User-Agent ``ssc_guardian.net.Client`` sends by default, read from its signature."""
    return inspect.signature(Client).parameters["user_agent"].default


def _plain(text: str) -> str:
    """``text`` with HTML tags and Markdown backticks removed, entities decoded and every run of
    whitespace made one space, so the site's ``<code>ssc-guardian</code>`` reads as the README's
    `` `ssc-guardian` ``."""
    return " ".join(html.unescape(_TAG_OR_TICK.sub("", text)).split())


def local_only_problems(root: Path) -> list[str]:
    """README.md and the site say the client identifies itself only as ``Client``'s default
    User-Agent and carry the pip exception; SECURITY.md carries the pip User-Agent paragraph; and
    none of the three makes a claim in ``UNTRUE_CLAIMS``. A missing document is a problem."""
    name = _client_name()
    if not isinstance(name, str) or not name:
        return [f"Client's user_agent default is {name!r}, not a name"]
    required = {
        **{
            document: (f"identify the client only as {name}.", PIP_EXCEPTION, PIP_TELLS_PYPI)
            for document in LOCAL_ONLY_DOCUMENTS
        },
        TRUST_DOCUMENT: (
            PIP_UNCHANGED,
            "the pinned pip identifies itself to PyPI with a User-Agent",
            f"Guardian's own client sends the User-Agent {name} and nothing about your machine.",
        ),
    }
    problems: list[str] = []
    for document, sentences in required.items():
        try:
            text = _plain((root / document).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"cannot read {document}: {exc}")
            continue
        problems += [f"{document} does not say {sentence!r}" for sentence in sentences if sentence not in text]
        problems += [f"{document} still says {claim!r}" for claim in UNTRUE_CLAIMS if claim in text]
    return problems


def _copy_local_only_documents(tmp_path: Path) -> Path:
    for name in (*LOCAL_ONLY_DOCUMENTS, TRUST_DOCUMENT):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    return tmp_path


def _replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"expected {old!r} once in {path.name}"
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_local_only_paragraph_matches_the_client(tmp_path: Path) -> None:
    assert local_only_problems(REPO) == []
    name = _client_name()
    # Edge case: the site's copy is matched with its tags removed.
    assert f"<code>{name}</code>" in (REPO / "docs/index.html").read_text(encoding="utf-8")
    # Negative control: a README without the pip sentence fails.
    root = _copy_local_only_documents(tmp_path / "no-pip")
    _replace_once(root / "README.md", "As it does for everyone, pip tells PyPI your\nPython version", "Python version")
    assert local_only_problems(root) == [f"README.md does not say {PIP_TELLS_PYPI!r}"]
    # Negative control: a copy naming a different client name fails.
    root = _copy_local_only_documents(tmp_path / "other-name")
    _replace_once(root / "docs/index.html", f"only as <code>{name}</code>.", "only as <code>guardian-client</code>.")
    assert local_only_problems(root) == [f"docs/index.html does not say {f'identify the client only as {name}.'!r}"]
    # Negative control: the old claim put back fails.
    root = _copy_local_only_documents(tmp_path / "old-claim")
    _replace_once(
        root / "README.md", "names at most the\npackages", "carries only the names and versions of the\npackages"
    )
    assert local_only_problems(root) == ["README.md still says 'carries only the names and versions'"]


def test_missing_local_only_document_fails_loudly(tmp_path: Path) -> None:
    root = _copy_local_only_documents(tmp_path)
    (root / TRUST_DOCUMENT).unlink()
    problems = local_only_problems(root)
    assert len(problems) == 1
    assert problems[0].startswith(f"cannot read {TRUST_DOCUMENT}: ")


def test_local_only_check_is_idempotent(tmp_path: Path) -> None:
    assert local_only_problems(REPO) == local_only_problems(REPO)
    root = _copy_local_only_documents(tmp_path)
    (root / "README.md").write_text("# Guardian\n", encoding="utf-8")
    first = local_only_problems(root)
    assert first == local_only_problems(root)
    assert len(first) == 3
