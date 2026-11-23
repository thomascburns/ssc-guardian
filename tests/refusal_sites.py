# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``refuses``: a negative test names the refusal site it targets and fails unless that refusal
ended the block or reached its result (issues #117, #148, #164).

Every refusal in ``src/ssc_guardian`` passes ``site="<module>.<slug>"`` and records it when it is
built, but only while a ``refuses`` block runs (``findings.record_site``). The block fails unless
a refusal with the named site was built inside it and reached the test:

- a refusal exception reaches it when it comes out of Guardian's code into the tests: the
  frame where it stopped (the head of its traceback) is a test file's, whether the block
  itself, a ``pytest.raises`` inside it or a test helper caught it;
- an in-scope ``Skip`` or a violation ``Finding`` reaches it when the result the command returns
  lists it: that result is rendered (``render``) inside the block, or the test holds it (in its own
  variables, through lists, tuples, sets, dicts and dataclasses, a ``Result`` among them, and a
  ``Collector`` for the result it gives). A ``Result`` built and thrown away is neither. An exit 2 set by hand
  (``incomplete_exit``) reaches it when it is returned;
- a refusal built while Guardian handled another one (in its ``except`` clause), or a skip that
  names the refusal it is built from (``made_from``: ``ConfigFileError.skip``, or a failure kept to
  be listed later), stands for that one: when it reaches the test, so does the one it came from.
  ``Collector.check`` turning a refusal into a listed skip, ``cli.main`` turning one into exit 2,
  and ``check --repo`` listing each file it could not read are this. A refusal that the building
  code merely holds in a variable is not.

So a refusal built and then swallowed (caught, with nothing built from it) fails the block, also
when another refusal ended it. The test still asserts the outcome (the raise with ``match=``, or
exit 2). The test's variables are read from the test function's own frame, the nearest
``test_*`` function of a test file on the stack, so a helper context manager that runs the block
for the test still reads the test's.

``tests/integration/test_refusal_coverage.py`` reads every ``refuses("...")`` literal in the tests
and fails on a site that no test names, unless it is in the baseline or the exemptions.

Use it around the statement that fires the refusal::

    with refuses("pin.bad-sha"), pytest.raises(UsageError, match="..."):
        ...

or in a parametrize list, where each case's ``refuses("...")`` is used once by ``with case:``.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from collections.abc import Iterable
from contextvars import Token
from pathlib import Path
from types import FrameType, TracebackType
from typing import Literal

from ssc_guardian import findings

# The tests folder, as written and resolved, read once at import: a test may patch os.path, so
# nothing below calls the file system.
TESTS = tuple(dict.fromkeys(str(p) + os.sep for p in (Path(__file__).parent, Path(__file__).resolve().parent)))
# How far into the test's variables a returned refusal is looked for: a list of skips, an object
# holding one, a tuple of those.
_DEPTH = 4


def _in_tests(exc: BaseException) -> bool:
    """Whether ``exc`` was last caught in a test file: it came out of Guardian's code."""
    head = exc.__traceback__
    return head is not None and head.tb_frame.f_code.co_filename.startswith(TESTS)


def _test_frame(frame: FrameType | None) -> FrameType | None:
    """The nearest frame from ``frame`` outwards that runs a test: a ``test_*`` function of a test
    file. None when no test is on the stack; then no variable counts."""
    while frame is not None:
        code = frame.f_code
        if code.co_name.startswith("test_") and code.co_filename.startswith(TESTS):
            return frame
        frame = frame.f_back
    return None


def _held(values: Iterable[object]) -> list[object]:
    """Every skip or finding the test's variables ``values`` hold, through lists, tuples, sets,
    dicts and dataclasses, to :data:`_DEPTH`: a refusal a function returned to the test. A
    ``Collector`` counts for the result it gives, which drops a finding whose ID another holds."""
    found: list[object] = []
    seen: set[int] = set()
    level = list(values)
    for _ in range(_DEPTH):
        below: list[object] = []
        for value in level:
            if id(value) in seen or isinstance(value, str | bytes | int | float | Path | type):
                continue
            seen.add(id(value))
            if isinstance(value, findings.Skip | findings.Finding):
                found.append(value)
            elif isinstance(value, findings.Collector):
                below.append(_result_of(value))
            elif isinstance(value, list | tuple | set | frozenset):
                below += value
            elif isinstance(value, dict):
                below += value.values()
            elif dataclasses.is_dataclass(value):
                below += [getattr(value, f.name, None) for f in dataclasses.fields(value)]
        level = below
    return found


def _result_of(collector: findings.Collector) -> findings.Result | None:
    """The result ``collector`` gives, or None when it cannot give one (two findings share an ID):
    then it holds nothing that reached a result."""
    try:
        return collector.result()
    except (TypeError, ValueError):
        return None


def reached(
    built: list[findings.Built], ended: BaseException | None = None, held: Iterable[object] = ()
) -> list[findings.Built]:
    """The records in ``built`` whose refusal reached the test: by itself, or carried by one that
    did. ``ended`` is what the block raised, if anything; ``held`` the skips and findings the
    test's variables hold."""
    returned = list(held)
    done = [
        record
        for record in built
        if record.reached
        or any(record.owner is value for value in returned)
        or (isinstance(record.owner, BaseException) and (record.owner is ended or _in_tests(record.owner)))
    ]
    while True:
        carried = [exc for record in done for exc in record.carried]
        more = [r for r in built if all(r is not d for d in done) and any(r.owner is exc for exc in carried)]
        if not more:
            return done
        done += more


class Refuses:
    """The context manager ``refuses`` returns. Blocks may nest: an outer block also sees the
    refusals an inner one recorded."""

    def __init__(self, site: str) -> None:
        if not isinstance(site, str) or not site:
            raise TypeError("refuses takes one refusal site ID, a non-empty string")
        self.site = site
        self._built: list[findings.Built] = []
        self._token: Token[list[findings.Built] | None] | None = None

    def __enter__(self) -> Refuses:
        if self._token is not None:
            raise RuntimeError(f"refuses({self.site!r}) is already running")
        self._built = []
        self._token = findings._SITES.set(self._built)
        return self

    def __exit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> Literal[False]:
        assert self._token is not None
        findings._SITES.reset(self._token)
        self._token = None
        outer = findings._SITES.get()
        if outer is not None:
            outer.extend(self._built)
        if self.site not in self.fired:
            fired = ", ".join(sorted(set(self.fired))) or "none"
            raise AssertionError(f"refusal site {self.site!r} did not fire; sites that fired: {fired}") from exc
        test = _test_frame(sys._getframe(1))  # the test, also when a helper runs the with statement
        done = reached(self._built, exc, _held(test.f_locals.values() if test is not None else ()))
        if all(record.site != self.site for record in done):
            ended = ", ".join(sorted({str(r.site) for r in done if r.site})) or "none"
            raise AssertionError(
                f"refusal site {self.site!r} fired, but its refusal was swallowed: it did not end the block "
                f"or reach a result; refusals that did: {ended}"
            ) from exc
        return False  # whatever the block raised goes on to the test's own assertion

    @property
    def fired(self) -> tuple[str, ...]:
        """The sites the last run of this block recorded, in order."""
        return tuple(record.site for record in self._built if record.site is not None)


def refuses(site: str) -> Refuses:
    """A block that fails unless the refusal ``site`` is built inside it and reaches the test."""
    return Refuses(site)
