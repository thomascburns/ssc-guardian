# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Field grammars: strict match, no repair, a mismatch is a malformed-name violation (issue #2)."""

from __future__ import annotations

from typing import Any

import pytest

from ssc_guardian.findings import Ecosystem, ExitCode, FindingField, Level, Result, Rule, Verb, make_finding
from ssc_guardian.grammars import Field, MalformedValueError, check, matches, normalize_pypi_name, path_problem
from tests.refusal_sites import refuses

pytestmark = pytest.mark.unit

SHA = "0123456789abcdef0123456789abcdef01234567"

# field -> (values that match, values that must not)
BOUNDARIES: dict[Field, tuple[list[str], list[str]]] = {
    Field.PYPI_NAME: (
        ["a", "requests", "zope.interface", "typing_extensions", "A1-b_c.d", "x" * 200],
        [
            "",
            "-lead",
            "trail-",
            ".dot",
            "has space",
            "x" * 201,
            "requests\n",
            "naïve",
            "a/b",
            "\u212aeras",
            "reque\u017fts",
            "p\u0131p",
        ],
    ),
    Field.PEP440_VERSION: (
        ["1", "1.0", "2.32.3", "1!2.0", "1.0rc1", "1.0.post2", "1.0-1", "1.0.dev3", "1.0+local.7", "v1.0"],
        ["", "1.0 ", "1..0", "latest", "1.0+", "1.0\n", "1" * 129, ">=1.0", "1.0.po\u017ft1", "1.0rc\u0661"],
    ),
    Field.OWNER_REPO: (
        # Older accounts may have doubled or trailing hyphens (D12).
        ["actions/checkout", "a/b", "o-1/repo.name_x", f"{'o' * 39}/{'r' * 100}", "a-/b", "a--b/c"],
        # A leading hyphen would read as an option.
        ["", "actions", "actions/", "/checkout", "-a/b", "--a/b", "a/..", "a/.", f"{'o' * 40}/r", "a/b/c"],
    ),
    Field.ACTION: (
        ["actions/checkout", "github/codeql-action/init", "a/b/c/d"],
        ["", "actions", "a/b/", "a/b/../c", "a/b/./c", "a/b c", "a/b@v1"],
    ),
    Field.GIT_REF: (
        ["v4", "v4.2.2", "main", "release/1.x", SHA],
        ["", "-v1", ".hidden", "a..b", "a/", "/a", "a.lock", "a b", "v1\n", "x" * 256, "a//b"],
    ),
    Field.SHA: (
        [SHA],
        ["", SHA[:39], SHA + "0", SHA.upper(), SHA[:20] + SHA[20:].upper(), "g" * 40, SHA + "\n"],
    ),
    Field.ADVISORY_ID: (
        ["CVE-2025-30066", "GHSA-mrrh-fwg8-r2c3", "MAL-2025-1234", "PYSEC-2024-60", "CVE-2024-1234567"],
        [
            "",
            "cve-2025-30066",
            "GHSA-MRRH-FWG8-R2C3",
            "GHSA-aaaa-bbbb-cccc",
            "CVE-25-1",
            "OSV-2020-1",
            "CVE-2025-30066\n",
        ],
    ),
    Field.PATH: (
        [
            "/Users/dev/.venv",
            "/Users/dev/sw dev assets/.venv",
            "/r/.github/workflows/ci.yml",
            "/a" * 512,
            "/Users/u/Library/Mobile Documents/com~apple~CloudDocs/v",
            "/Users/u/Dropbox (Personal)/v",
            "/a/x-y z",
        ],
        [
            "",
            "/",
            "/a/../b",
            "/a/./b",
            "./a",
            "/a\nb",
            "/a\x1bb",
            "/a;rm",
            "/a$(x)",
            "/a" * 513,
            "//a",
            "/a`b",
            ".github/workflows/ci.yml",
            "relative/x",
            "--index-url=x",
            "/caf\u00e9",
            "/tmp/x --venv /Users/u/.venv",
            "/tmp/x --yes",
            "/a/b/",
        ],
    ),
    Field.DATE: (
        ["2026-11-02", "2024-02-29"],
        ["", "2026-11-2", "2026-13-01", "2025-02-29", "2026-11-02T00:00", "20261102"],
    ),
    Field.ACTION_STEP: (
        [f"actions/checkout@{SHA}", "github/codeql-action/init@v3", "a--b/c@release/1.x"],
        ["", "a/b", "a/b@", "@v1", "a/..@v1", "a/b/../c@v1", "-a/b@v1", "a/b@-v1", "a/b@v1 --yes", "a/b@v1@v2"],
    ),
    Field.OVERRIDE_ID: (
        ["0123456789abcdef0123456789abcdef"],
        [
            "",
            "0123456789abcdef",  # the 16-character form before D6
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
        ],
    ),
    # Owner's ruling, 2026-11-09, #127: the image a docker:// reference names, prefix dropped.
    Field.DOCKER_IMAGE: (
        [
            "alpine",
            "alpine:latest",
            "alpine:3.20",
            "library/alpine",
            "ghcr.io/owner/image:v1.2_rc-3",
            "GHCR.io/owner/image",  # a host is not case-sensitive; the path is
            "localhost/image",
            "localhost:5000/team/image:dev",
            "registry:5000/image",
            "my-registry.example.com:443/a/b/c",
            "a__b/c.d/e-f/g--h",
            f"alpine@sha256:{'a' * 64}",
            f"ghcr.io/owner/image:3.20@sha256:{'0123456789abcdef' * 4}",
            "a" * 255,
            "a:" + "T" * 128,  # the longest tag
        ],
        [
            "",
            "Alpine",  # an uppercase path
            "Library/alpine",  # not a host: no ".", no port, not localhost
            "ghcr.io/Owner/image",
            "library/../alpine",  # ".."
            "a..b/c",
            "./alpine",
            "/alpine",
            "alpine/",
            "alpine:la test",  # a space
            "alpine latest",
            "alpine:latest\n",  # a newline
            "alpine\n",
            f"alpine@sha256:{'a' * 63}",  # 63 hex
            f"alpine@sha256:{'a' * 65}",
            f"alpine@sha256:{'A' * 64}",
            "alpine:sha256:" + "a" * 64,  # sha256: inside a tag
            "alpine@sha512:" + "a" * 128,
            "a" * 256,  # 256 characters
            "a:" + "T" * 129,
            "alpine:.hidden",
            "alpine:-dash",
            "docker://alpine",  # the prefix is not part of it
            "-alpine",
            "alpıne",
            "alpine:laſest",
            "host:99999999/image",
        ],
    ),
}


def test_boundaries_cover_every_grammar() -> None:
    assert set(BOUNDARIES) == set(Field)


@pytest.mark.parametrize("field", list(Field))
def test_boundary_values_for_each_grammar(field: Field) -> None:
    good, bad = BOUNDARIES[field]
    assert [v for v in good if not matches(field, v)] == []
    assert [v for v in bad if matches(field, v)] == []


@pytest.mark.parametrize("value", [None, 1, b"requests", ["requests"]])
def test_non_string_never_matches(value: object) -> None:
    assert not matches(Field.PYPI_NAME, value)


def test_check_raises_without_repeating_the_value() -> None:
    hostile = "x\x1b]0;owned\x07"
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed pypi-name") as info:
        check(Field.PYPI_NAME, hostile)
    assert info.value.field is Field.PYPI_NAME
    assert info.value.value == hostile
    assert str(info.value) == "malformed pypi-name"
    assert check(Field.PYPI_NAME, "requests") == "requests"


def test_normalize_pypi_name() -> None:
    assert normalize_pypi_name("Zope__Interface.x-Y") == "zope-interface-x-y"
    with refuses("grammars.malformed-value"), pytest.raises(MalformedValueError, match="malformed pypi-name"):
        normalize_pypi_name("bad name")


def test_malformed_name_is_a_violation() -> None:
    finding = make_finding(Rule.COOLDOWN, Ecosystem.PYPI, place="/v/.venv", item="bad name!", version="1.0")
    assert finding.rule is Rule.MALFORMED_NAME
    assert finding.level is Level.VIOLATION
    assert finding.malformed_field is FindingField.ITEM
    assert finding.item is None  # never a guessed repair
    assert finding.version == "1.0"
    assert finding.place == "/v/.venv"
    assert Result(Verb.CHECK, findings=(finding,)).exit_code is ExitCode.VIOLATION


@pytest.mark.parametrize(
    ("kwargs", "which"),
    [
        ({"place": "/a/../b"}, FindingField.PLACE),
        ({"item": "requests", "version": "latest"}, FindingField.VERSION),
        ({"item": "requests", "evidence": ["CVE-1"]}, FindingField.EVIDENCE),
    ],
)
def test_each_malformed_field_is_named(kwargs: dict[str, Any], which: FindingField) -> None:
    finding = make_finding(Rule.KNOWN_VULNERABILITY, Ecosystem.PYPI, **kwargs)
    assert finding.rule is Rule.MALFORMED_NAME
    assert finding.malformed_field is which
    assert finding.evidence == ()
    assert finding.options == ()


def test_actions_item_and_version_use_actions_grammars() -> None:
    ok = make_finding(Rule.MOVING_REFERENCE, Ecosystem.GITHUB_ACTIONS, item="github/codeql-action/init", version="v3")
    assert ok.rule is Rule.MOVING_REFERENCE
    bad = make_finding(Rule.MOVING_REFERENCE, Ecosystem.GITHUB_ACTIONS, item="requests", version="v3")
    assert bad.rule is Rule.MALFORMED_NAME
    assert bad.malformed_field is FindingField.ITEM


def test_unpinned_image_item_uses_the_docker_image_grammar() -> None:
    # Owner's ruling, 2026-11-09, #127: an unpinned-image finding's item is the image.
    ok = make_finding(Rule.UNPINNED_IMAGE, Ecosystem.GITHUB_ACTIONS, place="/r/ci.yml", item="alpine:latest")
    assert (ok.rule, ok.item, ok.level) == (Rule.UNPINNED_IMAGE, "alpine:latest", Level.WARNING)
    # Kept as written in the ID: a tag is case-sensitive, so two tags are two findings.
    upper = make_finding(Rule.UNPINNED_IMAGE, Ecosystem.GITHUB_ACTIONS, place="/r/ci.yml", item="alpine:Latest")
    assert upper.id != ok.id
    # Any other rule's item is still an Action.
    assert make_finding(Rule.MOVING_REFERENCE, Ecosystem.GITHUB_ACTIONS, item="alpine:latest").rule is (
        Rule.MALFORMED_NAME
    )


@pytest.mark.parametrize(
    "image", ["Library/alpine", "library/../alpine", "alpine:la test", "alpine\n", f"alpine@sha256:{'a' * 63}"]
)
def test_malformed_image_is_a_violation_never_kept_as_the_item(image: str) -> None:
    bad = make_finding(Rule.UNPINNED_IMAGE, Ecosystem.GITHUB_ACTIONS, place="/r/ci.yml", item=image)
    assert (bad.rule, bad.malformed_field, bad.malformed_value) == (Rule.MALFORMED_NAME, FindingField.ITEM, image)
    # Never kept as the item, even when it reads as an Action ("Library/alpine").
    assert bad.item is None and bad.place == "/r/ci.yml"
    assert Result(Verb.CHECK, findings=(bad,)).exit_code is ExitCode.VIOLATION


@pytest.mark.parametrize(
    ("value", "words"),
    [
        ("/Users/dev/Client's App", 'contains "\'" (U+0027)'),
        ("/Users/dev/Caf\u00e9", "contains (U+00E9)"),
        ("/Users/dev/zero\u200bwidth", "contains (U+200B)"),
        ("/tmp/a\nb", "contains (U+000A)"),
        ("relative/path", "not an absolute path"),
        ("/", "not an absolute path"),
        ("/tmp/a -b", "space followed by '-'"),
        ("/tmp/./a", "'.' or '..' component"),
        ("/tmp/a/", "trailing '/'"),
        ("/" + "a" * 1100, "longer than 1024"),
    ],
)
def test_path_problem_names_the_cause(value: str, words: str) -> None:
    # D3: the message names what to fix, and never prints an invisible or lookalike character.
    assert not matches(Field.PATH, value)
    problem = path_problem(value)
    assert words in problem
    assert problem.isascii() and problem.isprintable()
