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

"""The Git commit an installed ssc-guardian was built from (plan §2.1 and §5, issue #7).

An installer that installs from a URL records it in the distribution's ``direct_url.json``
(PEP 610): ``uv tool install git+https://...@main`` and pip both write the exact commit they
built. That commit is the only source: it is reported for a Git install (``vcs_info.vcs`` is
``git``) whose ``commit_id`` matches the ``sha`` grammar, and for nothing else. No installed
distribution (the dev venv, which imports the package from ``src``), no file, or a non-VCS
install (a wheel, an editable or a local folder) means no commit, never an invented one. A
file that is present but cannot be read, is not JSON or is not PEP 610 data, or a Git
install whose ``commit_id`` does not match the ``sha`` grammar, is an error, not a guess: the
command still runs, reports no commit, and says so in one line on stderr.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from importlib import metadata
from typing import NoReturn, TextIO

from ssc_guardian import direct_url
from ssc_guardian.direct_url import DIRECT_URL, DirectUrlError
from ssc_guardian.findings import TOOL_NAME
from ssc_guardian.grammars import Field, matches

DISTRIBUTION = "ssc-guardian"
_MAX_BYTES = direct_url.MAX_BYTES


def git_commit(warn: Callable[[str], object]) -> str | None:
    """The Git commit the installed ssc-guardian was built from, or None.

    ``warn`` gets one plain line, once, when ``direct_url.json`` is present but unusable;
    the answer is then None. Reading has no side effects, so the same files give the same
    answer on every call.
    """
    try:
        distribution = metadata.distribution(DISTRIBUTION)
    except metadata.PackageNotFoundError:  # the dev venv: the package is imported from src
        return None
    try:
        return commit_from(distribution)
    except DirectUrlError as exc:
        warn(f"{TOOL_NAME}: {DIRECT_URL} could not be read ({exc}); no commit is reported.")
        return None


def commit_from(distribution: metadata.Distribution) -> str | None:
    """The commit ``distribution``'s ``direct_url.json`` names, or None when it names none.

    Raises :class:`DirectUrlError` for a file that is present but unusable.
    """
    text = _read(distribution)
    return None if text is None else parse_direct_url(text)


def parse_direct_url(text: str) -> str | None:
    """The Git commit in PEP 610 ``text``; None for a non-VCS or non-Git install.

    Raises :class:`DirectUrlError` when ``text`` is not JSON, a key PEP 610 requires is
    missing or has the wrong type (``url``, and exactly one of ``vcs_info``, ``archive_info``
    and ``dir_info``), or a Git install's commit does not match the ``sha``
    grammar (a short, uppercase or SHA-256 commit is not shortened, padded, lowercased or
    guessed at).
    """
    record = direct_url.parse(text)
    commit = record.commit_id
    if record.vcs != "git" or commit is None:  # archive_info or dir_info, or another VCS
        return None
    if not matches(Field.SHA, commit):
        raise DirectUrlError(
            "the Git commit is not 40 lowercase hex characters", site="version.git-commit-not-40-lowercase"
        )
    return commit


def _read(distribution: metadata.Distribution) -> str | None:
    """``direct_url.json`` as text, or None when the distribution has no such file.

    ``Distribution.read_text`` answers None for a file it cannot open (a permission error, a
    folder in its place) as well as for a missing one, so a distribution in a folder, which
    is every installed one, has the file read by :func:`.direct_url.read`, where only a
    missing file means None.
    """
    folder = getattr(distribution, "_path", None)  # PathDistribution's .dist-info folder
    if not isinstance(folder, os.PathLike):
        return distribution.read_text(DIRECT_URL)
    return direct_url.read(os.fspath(folder))


def version_line(version: str, commit: str | None) -> str:
    """``ssc-guardian <version>``, plus `` (<commit>)`` when there is one: the text output's footer."""
    return f"{TOOL_NAME} {version}" + (f" ({commit})" if commit else "")


def _to_stream(stream: TextIO | None, line: str) -> None:
    """One line on ``stream``. A closed or broken stream is ignored, as ``cli._say`` ignores
    it, so a warning can never change ``--version``'s exit code."""
    try:
        if stream is not None:
            stream.write(line + "\n")
            stream.flush()
    except Exception:  # nothing else to report to
        return


class VersionAction(argparse.Action):
    """``--version``: prints :func:`version_line` on stdout and exits 0, as argparse's own
    version action does.

    ``stdout`` and ``stderr`` are the streams given to ``cli.main``; None means the
    process's own, looked up when the flag is given. The commit is read then too, not when
    the parser is built, so any other command reads ``direct_url.json`` once, for its
    output's ``tool``, and reports a bad file once.
    """

    def __init__(
        self,
        option_strings: Sequence[str],
        version: str,
        dest: str = argparse.SUPPRESS,
        help: str = "show the version and exit",
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, help=help)
        self.version = version
        self.stdout = stdout
        self.stderr = stderr

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> NoReturn:
        err = self.stderr if self.stderr is not None else sys.stderr
        line = version_line(self.version, git_commit(lambda warning: _to_stream(err, warning))) + "\n"
        out = self.stdout if self.stdout is not None else sys.stdout
        try:  # as argparse's own: a failed write still exits 0
            if out is not None:
                out.write(line)
        except (AttributeError, OSError, ValueError):  # ValueError: a closed stream
            pass
        parser.exit()
