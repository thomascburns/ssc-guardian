# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``cli.confirm``: a change or prompt that cannot be shown is never a yes (issue #240; contracts §3)."""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import TextIO

import pytest

from ssc_guardian.cli import confirm
from ssc_guardian.findings import Verb

pytestmark = pytest.mark.unit


class _Tty(io.StringIO):
    """A terminal on stdin; ``tell()`` still 0 means it was never read."""

    def isatty(self) -> bool:
        return True


class _Broken(io.StringIO):
    """A stream whose reader has gone: each write or flush raises ``failure``."""

    def __init__(self, failure: BaseException, *, on: str = "write") -> None:
        super().__init__()
        self.failure = failure
        self.on = on

    def write(self, text: str) -> int:
        if self.on == "write":
            raise self.failure
        return super().write(text)

    def flush(self) -> None:
        if self.on == "flush":
            raise self.failure


def _closed() -> io.StringIO:
    stream = io.StringIO()
    stream.close()  # a write now raises ValueError
    return stream


@pytest.mark.parametrize("verb", [Verb.PIN, Verb.PROTECT, Verb.INSTALL, Verb.ACKNOWLEDGE])
@pytest.mark.parametrize(
    "make",
    [
        lambda: _Broken(BrokenPipeError()),
        lambda: _Broken(BrokenPipeError(), on="flush"),
        lambda: _Broken(OSError("EIO")),
        _closed,
    ],
    ids=["broken-pipe-on-write", "broken-pipe-on-flush", "oserror", "closed"],
)
def test_confirm_with_broken_stream_is_not_confirmed(verb: Verb, make: Callable[[], TextIO]) -> None:
    stdin = _Tty("y\n")
    assert confirm("write x", verb=verb, yes=False, stdin=stdin, stdout=make()) is False
    assert stdin.tell() == 0  # the answer to a question nobody saw is never read


@pytest.mark.parametrize("verb", [Verb.PIN, Verb.PROTECT, Verb.INSTALL, Verb.ACKNOWLEDGE])
def test_confirm_with_no_stream_is_not_confirmed(verb: Verb) -> None:
    stdin = _Tty("yes\n")
    assert confirm("write x", verb=verb, yes=False, stdin=stdin, stdout=None) is False
    assert stdin.tell() == 0


def test_confirm_with_working_stream_unchanged() -> None:
    shown = io.StringIO()
    assert confirm("write x\nand y", verb=Verb.PIN, yes=False, stdin=_Tty("y\n"), stdout=shown) is True
    assert shown.getvalue() == "write x\nand y\nProceed? [y/N] "
    assert confirm("write x", verb=Verb.PIN, yes=False, stdin=_Tty("n\n"), stdout=io.StringIO()) is False
    # --yes is unchanged: it confirms in advance without showing anything, so no stream is needed,
    # and an exception command still never confirms in advance.
    assert confirm("write x", verb=Verb.PIN, yes=True, stdin=None, stdout=None) is True
    assert confirm("write x", verb=Verb.ACKNOWLEDGE, yes=True, stdin=_Tty("y\n"), stdout=None) is False


def test_confirm_lets_a_keyboard_interrupt_through() -> None:
    stdin = _Tty("y\n")
    with pytest.raises(KeyboardInterrupt):
        confirm("write x", verb=Verb.PIN, yes=False, stdin=stdin, stdout=_Broken(KeyboardInterrupt()))
    assert stdin.tell() == 0


class _NotATty(io.StringIO):
    """A pipe on stdin: not a terminal; ``tell()`` still 0 means it was never read."""

    def isatty(self) -> bool:
        return False


@pytest.mark.parametrize("verb", [Verb.PIN, Verb.PROTECT, Verb.INSTALL])
def test_confirm_without_a_terminal_shows_the_change_and_is_not_confirmed(verb: Verb) -> None:
    # #284: a script sees what --yes would do; nothing is asked, stdin is never read.
    stdin, shown = _NotATty("y\n"), io.StringIO()
    assert confirm("write x\nand \x1b[31my\x07", verb=verb, yes=False, stdin=stdin, stdout=shown) is False
    assert shown.getvalue() == "write x\nand [31my\n"  # each line stripped of controls, as at a terminal
    assert "Proceed?" not in shown.getvalue()
    assert stdin.tell() == 0


def test_confirm_with_yes_prints_nothing_itself() -> None:
    # The handler prints the --yes record itself, so confirm never prints the change a second time.
    shown = io.StringIO()
    assert confirm("write x", verb=Verb.PIN, yes=True, stdin=_NotATty(""), stdout=shown) is True
    assert shown.getvalue() == ""


@pytest.mark.parametrize(
    "make", [lambda: _Broken(BrokenPipeError()), _closed, lambda: None], ids=["broken", "closed", "none"]
)
def test_confirm_without_a_terminal_and_a_broken_stream_is_not_confirmed(make: Callable[[], TextIO | None]) -> None:
    stdin = _NotATty("y\n")
    assert confirm("write x", verb=Verb.PIN, yes=False, stdin=stdin, stdout=make()) is False
    assert stdin.tell() == 0
