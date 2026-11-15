# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Field grammars (plan §3.2, R1-K7).

Every value that reaches output or a command is matched against one strict
pattern. A mismatch is never repaired or guessed: the caller gets
:class:`MalformedValueError`. For a finding's own fields (names, versions,
``owner/repo``, SHAs, advisory IDs, paths) the result model turns it into a
"malformed name" violation (exit 1); a malformed date or override ID leaves the
check unfinished (exit 2).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date
from enum import StrEnum


class Field(StrEnum):
    """The value kinds that have a grammar. The values are fixed JSON templates."""

    PYPI_NAME = "pypi-name"
    PEP440_VERSION = "pep440-version"
    OWNER_REPO = "owner-repo"
    ACTION = "action"
    GIT_REF = "git-ref"
    SHA = "sha"
    ADVISORY_ID = "advisory-id"
    PATH = "path"
    DATE = "date"
    OVERRIDE_ID = "override-id"
    ACTION_STEP = "action-step"
    DOCKER_IMAGE = "docker-image"


class MalformedValueError(ValueError):
    """A value does not match its field grammar.

    The message names the field only. The raw value is kept on the exception
    for text output, never in the message, so a log line cannot carry it.
    """

    def __init__(self, field: Field, value: object, *, site: str | None = None) -> None:
        super().__init__(f"malformed {field.value}")
        self.field = field
        self.value = value
        from ssc_guardian.findings import record_site  # findings imports this module

        record_site(site)


# re.ASCII wherever IGNORECASE is used: without it, [A-Z] also matches the Kelvin
# sign, the long s and the dotless i, and a lookalike name would pass.

# PEP 508 names; PEP 503 normalizes them for comparison.
_PYPI_NAME = re.compile(r"[A-Z0-9](?:[A-Z0-9._-]*[A-Z0-9])?", re.IGNORECASE | re.ASCII)

# PEP 440, from the specification's appendix (the pattern packaging uses).
_PEP440 = re.compile(
    r"""
    v?
    (?:
        (?:[0-9]+!)?
        [0-9]+(?:\.[0-9]+)*
        (?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?
        (?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?
        (?:[-_.]?dev[-_.]?[0-9]*)?
    )
    (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)

# GitHub owners: letters, digits and hyphens, at most 39. Older accounts may have doubled or
# trailing hyphens (D12); a leading hyphen is refused, since the name would read as an option.
_OWNER = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
_REPO = r"(?!\.\.?/|\.\.?$)[A-Za-z0-9._-]{1,100}"
_SEGMENT = r"(?!\.\.?(?:/|$))[A-Za-z0-9._-]+"
_OWNER_REPO = re.compile(rf"{_OWNER}/{_REPO}")
_ACTION = re.compile(rf"{_OWNER}/{_REPO}(?:/{_SEGMENT})*")

_GIT_REF = re.compile(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*")
_SHA = re.compile(r"[0-9a-f]{40}")

_GHSA_CHARS = "[23456789cfghjmpqrvwx]{4}"
_ADVISORY_ID = re.compile(
    rf"CVE-[0-9]{{4}}-[0-9]{{4,19}}|GHSA-{_GHSA_CHARS}-{_GHSA_CHARS}-{_GHSA_CHARS}|(?:MAL|PYSEC)-[0-9]{{4}}-[0-9]{{1,19}}"
)

# Absolute paths only. Components: portable characters plus space, "~" and
# parentheses (macOS folders such as "com~apple~CloudDocs" and "Dropbox (Personal)");
# no control characters, no quotes, no other shell metacharacters.
_PATH = re.compile(r"(?:/[A-Za-z0-9 ._+@,=~()-]+)+")  # no trailing "/": one place, one spelling
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_OVERRIDE_ID = re.compile(r"[0-9a-f]{32}")
# One step of an outer-Action chain (D14): ACTION@REF; the predicate checks each half exactly.
_ACTION_STEP = re.compile(r"[A-Za-z0-9._/-]+@[A-Za-z0-9._+/-]+")

# A Docker image as a ``docker://`` reference names it, the prefix dropped (owner's ruling,
# 2026-11-09, #127): an optional registry host, lowercase path components, an optional tag and
# an optional sha256 digest. The first component is a host only if it holds a "." or a port,
# or is "localhost", as Docker reads it; otherwise it is a path component and lowercase.
_IMAGE_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_IMAGE_PORT = r":[0-9]{1,5}"
_IMAGE_HOST = (
    rf"(?:localhost(?:{_IMAGE_PORT})?|{_IMAGE_LABEL}(?:\.{_IMAGE_LABEL})+(?:{_IMAGE_PORT})?"
    rf"|{_IMAGE_LABEL}{_IMAGE_PORT})"
)
_IMAGE_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_DOCKER_IMAGE = re.compile(
    rf"(?:{_IMAGE_HOST}/)?{_IMAGE_COMPONENT}(?:/{_IMAGE_COMPONENT})*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?"
)


def _git_ref_ok(value: str) -> bool:
    # A subset of git check-ref-format: no "..", no leading "-" or ".", no
    # component ending in ".lock" or ".".
    return ".." not in value and all(
        not part.startswith((".", "-")) and not part.endswith((".lock", ".")) for part in value.split("/")
    )


def _path_ok(value: str) -> bool:
    # No space before a "-": a fix command's argv joined with spaces by a careless
    # caller must not gain an option ("/tmp/x --venv /other" or "/tmp/x --yes").
    return " -" not in value and all(part not in {".", ".."} for part in value.split("/"))


def _action_step_ok(value: str) -> bool:
    # str.rpartition reads the string itself, never a subclass's override.
    action, _, ref = str.rpartition(value, "@")
    return matches(Field.ACTION, action) and matches(Field.GIT_REF, ref)


def _date_ok(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _always(_: str) -> bool:
    return True


# field -> (pattern, maximum length, further predicate)
_GRAMMARS: dict[Field, tuple[re.Pattern[str], int, Callable[[str], bool]]] = {
    Field.PYPI_NAME: (_PYPI_NAME, 200, _always),
    Field.PEP440_VERSION: (_PEP440, 128, _always),
    Field.OWNER_REPO: (_OWNER_REPO, 140, _always),
    Field.ACTION: (_ACTION, 255, _always),
    Field.GIT_REF: (_GIT_REF, 255, _git_ref_ok),
    Field.SHA: (_SHA, 40, _always),
    Field.ADVISORY_ID: (_ADVISORY_ID, 64, _always),
    Field.PATH: (_PATH, 1024, _path_ok),
    Field.DATE: (_DATE, 10, _date_ok),
    Field.OVERRIDE_ID: (_OVERRIDE_ID, 32, _always),
    Field.ACTION_STEP: (_ACTION_STEP, 511, _action_step_ok),
    Field.DOCKER_IMAGE: (_DOCKER_IMAGE, 255, _always),
}


def matches(field: Field, value: object) -> bool:
    """Whether ``value`` is a string that matches ``field``'s grammar exactly.

    ``fullmatch`` is used throughout: ``$`` would accept a trailing newline.
    """
    if not isinstance(value, str) or not value:
        return False
    pattern, max_len, predicate = _GRAMMARS[field]
    return len(value) <= max_len and pattern.fullmatch(value) is not None and predicate(value)


def check(field: Field, value: object) -> str:
    """Return ``value`` unchanged if it matches ``field``; raise :class:`MalformedValueError` otherwise."""
    if isinstance(value, str) and matches(field, value):
        return value
    raise MalformedValueError(field, value, site="grammars.malformed-value")


_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/ ._+@,=~()-")


def path_problem(value: str) -> str:
    """Why ``value`` fails the path grammar, in words a person can act on (D3; text output only).

    A refused character is named by its code point (and shown only if it is printable ASCII),
    so an invisible or lookalike character is never printed as itself.
    """
    bad = next((ch for ch in value if ch not in _PATH_CHARS), None)
    if bad is not None:
        quote = '"' if bad == "'" else "'"
        shown = f"{quote}{bad}{quote} " if bad.isascii() and bad.isprintable() else ""
        return f"it contains {shown}(U+{ord(bad):04X}), which a path may not hold"
    if not value.startswith("/") or value == "/":
        return "it is not an absolute path below /"
    if " -" in value:
        return "it has a space followed by '-'"
    if any(part in {"", ".", ".."} for part in value[1:].split("/")):
        return "it has an empty, '.' or '..' component, or a trailing '/'"
    if len(value) > _GRAMMARS[Field.PATH][1]:
        return f"it is longer than {_GRAMMARS[Field.PATH][1]} characters"
    return "it does not match the path grammar"


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalized form of a valid PyPI name."""
    return re.sub(r"[-_.]+", "-", check(Field.PYPI_NAME, name)).lower()
