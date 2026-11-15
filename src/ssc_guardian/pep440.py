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

"""PEP 440 versions, standard library only (plan §10.3: stdlib PEP 440 matching, N21).

:func:`parse` accepts exactly what the ``pep440-version`` grammar accepts and orders
versions as PEP 440 does: ``1.0.dev1 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1``, and
``1.0`` equals ``1.0.0``. :func:`canonical` is the one spelling the finding ID hashes
(D18). Range checks (:meth:`Specifier.contains`, :func:`satisfies_all`) compare public
versions by this order: a pre-release of a fixed version is still before the fix, and a
local build (``1.0+cpu``) is the release it was built from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ssc_guardian.grammars import Field, MalformedValueError, check

_PARTS = re.compile(
    r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)

_PRE_LABELS = {"a": "a", "alpha": "a", "b": "b", "beta": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}
_PRE_RANK = {"a": 0, "b": 1, "rc": 2}

# Sort keys for the optional parts. A missing pre-release sorts after every pre-release,
# except on a dev release of the release itself (1.0.dev1 < 1.0a1); a missing post-release
# sorts before every post-release; a missing dev part sorts after every dev release.
_PreKey = tuple[int, int, int]
_PRE_NONE: _PreKey = (3, 0, 0)
_PRE_DEV_ONLY: _PreKey = (-1, 0, 0)


@dataclass(frozen=True, eq=False)
class Version:
    """A parsed PEP 440 version. Equality and order are PEP 440's; ``text`` is kept as given."""

    text: str
    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: tuple[int | str, ...]
    _key: tuple[Any, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_key", self.public_key() + (_local_key(self.local),))

    def public_key(self) -> tuple[Any, ...]:
        release = list(self.release)
        while len(release) > 1 and release[-1] == 0:
            release.pop()
        if self.pre is not None:
            pre: _PreKey = (_PRE_RANK[self.pre[0]], self.pre[1], 0)
        elif self.post is None and self.dev is not None:
            pre = _PRE_DEV_ONLY
        else:
            pre = _PRE_NONE
        post = (0, 0) if self.post is None else (1, self.post)
        dev = (1, 0) if self.dev is None else (0, self.dev)
        return (self.epoch, tuple(release), pre, post, dev)

    @property
    def is_prerelease(self) -> bool:
        """A pre-release or a dev release: never offered as a replacement."""
        return self.pre is not None or self.dev is not None

    @property
    def public(self) -> Version:
        """The version without its local part (``1.0+cpu`` is ``1.0``)."""
        return Version(self.text.partition("+")[0], self.epoch, self.release, self.pre, self.post, self.dev, ())

    def __str__(self) -> str:
        return canonical_of(self)

    def __lt__(self, other: Version) -> bool:
        return self._key < other._key

    def __le__(self, other: Version) -> bool:
        return self._key <= other._key

    def __gt__(self, other: Version) -> bool:
        return self._key > other._key

    def __ge__(self, other: Version) -> bool:
        return self._key >= other._key

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)


def _local_key(local: tuple[int | str, ...]) -> tuple[tuple[int, int, str], ...]:
    # PEP 440: a local version sorts after its public version; numeric segments sort after
    # alphanumeric ones, and compare as numbers.
    return tuple((1, part, "") if isinstance(part, int) else (0, 0, part) for part in local)


def parse(text: str) -> Version:
    """Parse a version that matches the ``pep440-version`` grammar; raise
    :class:`~ssc_guardian.grammars.MalformedValueError` otherwise. Nothing is repaired."""
    match = _PARTS.fullmatch(check(Field.PEP440_VERSION, text))
    if match is None:  # the grammar and this pattern accept the same strings
        raise MalformedValueError(Field.PEP440_VERSION, text, site="pep440.malformed-version")
    pre = None
    if match.group("pre"):
        pre = (_PRE_LABELS[match.group("pre_l").lower()], int(match.group("pre_n") or 0))
    post = None
    if match.group("post"):
        post = int(match.group("post_n1") or match.group("post_n2") or 0)
    dev = int(match.group("dev_n") or 0) if match.group("dev") else None
    local: tuple[int | str, ...] = ()
    if match.group("local"):
        local = tuple(int(s) if s.isdigit() else s for s in re.split(r"[-_.]", match.group("local").lower()))
    return Version(
        text=text,
        epoch=int(match.group("epoch") or 0),
        release=tuple(int(p) for p in match.group("release").split(".")),
        pre=pre,
        post=post,
        dev=dev,
        local=local,
    )


def try_parse(text: object) -> Version | None:
    """:func:`parse`, or None for anything that is not a valid version (feed data)."""
    try:
        return parse(text) if isinstance(text, str) else None
    except MalformedValueError:
        return None


def canonical_of(version: Version) -> str:
    """PEP 440's normalized form with trailing zero release parts dropped (``1.0.0`` is ``1``),
    so every spelling of one version has one form."""
    release = list(version.release)
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    parts = [f"{version.epoch}!" if version.epoch else "", ".".join(str(p) for p in release)]
    if version.pre is not None:
        parts.append(f"{version.pre[0]}{version.pre[1]}")
    if version.post is not None:
        parts.append(f".post{version.post}")
    if version.dev is not None:
        parts.append(f".dev{version.dev}")
    if version.local:
        parts.append("+" + ".".join(str(s) for s in version.local))
    return "".join(parts)


def canonical(text: str) -> str:
    """The one spelling of a valid version (D18): ``1.0``, ``1.0.0`` and ``v1.0`` are ``1``."""
    return canonical_of(parse(text))


class Operator(StrEnum):
    EQ = "=="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="


# GitHub writes equality as "= 1.0"; PEP 440 writes "==".
_OPERATORS = {
    "=": Operator.EQ,
    "==": Operator.EQ,
    "!=": Operator.NE,
    "<": Operator.LT,
    "<=": Operator.LE,
    ">": Operator.GT,
    ">=": Operator.GE,
}
_CLAUSE = re.compile(r"\s*(==|!=|<=|>=|=|<|>)\s*(\S+)\s*", re.ASCII)


@dataclass(frozen=True)
class Specifier:
    """One comparison, such as ``< 2.0``. Wildcards (``== 1.*``) and ``~=`` are not accepted."""

    operator: Operator
    version: Version

    def contains(self, version: Version) -> bool:
        """Whether the public part of ``version`` meets this comparison, by PEP 440 order."""
        left, right = version.public, self.version.public
        return {
            Operator.EQ: left == right,
            Operator.NE: left != right,
            Operator.LT: left < right,
            Operator.LE: left <= right,
            Operator.GT: left > right,
            Operator.GE: left >= right,
        }[self.operator]


def parse_specifiers(text: str) -> tuple[Specifier, ...]:
    """Parse a comma-separated range (``>= 1.0, < 1.2.3``); raise ``ValueError`` on anything else."""
    clauses = text.split(",")
    specifiers = []
    for clause in clauses:
        match = _CLAUSE.fullmatch(clause)
        version = try_parse(match.group(2)) if match else None
        if match is None or version is None:
            raise ValueError("not a version range")
        specifiers.append(Specifier(_OPERATORS[match.group(1)], version))
    return tuple(specifiers)


def satisfies_all(version: Version, specifiers: tuple[Specifier, ...]) -> bool:
    return all(s.contains(version) for s in specifiers)
