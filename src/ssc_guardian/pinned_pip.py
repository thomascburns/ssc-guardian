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

"""Guardian's own pip: one wheel, checked against a SHA-256 written here (plan §2.3, §3.1 step 3).

**Why pip 26.0.1.** The plan fixes Guardian's pip at the 26.0 line, the newest that supports
Python 3.9 (pip 26.2 needs 3.10, fact 3), and 26.0 takes ``--uploaded-prior-to`` as a fixed
datetime (fact 2). 26.0.1 is the newest 26.0.x release; PyPI received its wheel on
2026-02-05, far past the 21-day cooldown.

**Why this digest.** :data:`SHA256` is the digest PyPI's JSON API publishes for
``pip-26.0.1-py3-none-any.whl``, read on 2026-11-03 and checked against a copy of the wheel
obtained separately (virtualenv's wheel cache on the build Mac): the two agree. Changing the
version means changing :data:`VERSION`, :data:`URL` and :data:`SHA256` together, after the
same two-source check.

**Cache.** The wheel is downloaded from ``files.pythonhosted.org`` and kept at
``~/.cache/ssc-guardian/pip/<sha256>.whl``: the file name comes from the digest written
here and from nothing else. Every use reads the bytes and checks them again; a cached copy
that does not match is replaced by a fresh download, and a download that does not match is
refused (exit 2). Each run works on its own verified copy in a private folder.

**Running it.** :func:`run` is the one place Guardian starts a program (execution boundary
item 2): the venv's own Python, with a fixed argument list, no shell, a timeout and a clean
environment (no ``PIP_*`` and no ``PYTHON*`` variables, ``PIP_CONFIG_FILE`` set to the null
device, ``HOME`` and the working folder the run's private folder). A fixed bootstrap program
puts the wheel first on ``sys.path``, appends the package folders it is given as plain paths,
and runs pip's main module from the wheel.

**No installed code in the check step.** ``-S`` stops ``.pth`` files and ``sitecustomize``,
but a folder on ``sys.path`` is also a place to import from: pip's own code imports optional
modules when it finds them (its vendored rich imports ``attr``, urllib3 imports ``backports``,
packaging imports ``_manylinux``, pip imports ``keyring`` for a login). So the bootstrap puts a
finder ahead of the standard path finder that loads a top-level module only from the wheel
or the standard library; the package folders stay on ``sys.path`` only so pip can read the
installed packages' metadata, which loads no code. ``-B`` writes no bytecode.
"""

from __future__ import annotations

import hashlib
import os
import stat

# Runs only the venv's own Python (plan §2.3 boundary item 2); owner-approved, issue #6.
import subprocess  # nosec B404
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass

from ssc_guardian.findings import IncompleteCheckError, SkipReason
from ssc_guardian.grammars import Field, check
from ssc_guardian.net import Client

VERSION = "26.0.1"
FILENAME = f"pip-{VERSION}-py3-none-any.whl"
URL = (
    "https://files.pythonhosted.org/packages/de/f0/"
    f"c81e05b613866b76d2d1066490adf1a3dbc4ee9d9c839961c3fc8a6997af/{FILENAME}"
)
SHA256 = "bdb1b08f4274833d62c1aa29e20907365a2ceb950410df15fc9521bad440122b"
MAX_BYTES = 8 * 1024 * 1024  # the wheel is 1,787,723 bytes
TIMEOUT_SECONDS = 600.0

# The two ways the venv's Python runs: locked down for the check step (no site processing,
# so no .pth file and no installed package code runs; no bytecode written), normal mode for
# the install step.
LOCKED_DOWN = ("-I", "-S", "-B")
NORMAL = ("-I",)

# Run by the venv's Python as ``-c``: argv is the wheel, the number of package folders, the
# folders, then pip's own arguments. The wheel goes first, so ``import pip`` finds Guardian's
# pip and never one installed in the venv; empty entries (the current folder) are dropped. A
# top-level import is answered only from the wheel and the interpreter's own entries; a
# module found nowhere else is missing, never looked up in the package folders (built-in and
# frozen modules come first, as before). Submodules follow their package's own path.
BOOTSTRAP = """\
import importlib.machinery, runpy, sys
wheel, count = sys.argv[1], int(sys.argv[2])
folders = sys.argv[3:3 + count]
allowed = [wheel] + [p for p in sys.path if p]


class OnlyWheelAndStandardLibrary:
    @staticmethod
    def find_spec(name, path=None, target=None):
        if path is not None:
            return None
        spec = importlib.machinery.PathFinder.find_spec(name, allowed)
        if spec is None:
            raise ModuleNotFoundError("No module named %r" % name, name=name)
        return spec


sys.meta_path.insert(sys.meta_path.index(importlib.machinery.PathFinder), OnlyWheelAndStandardLibrary)
sys.path[:] = allowed + folders
sys.argv = ["pip"] + sys.argv[3 + count:]
runpy.run_module("pip", run_name="__main__", alter_sys=True)
"""


class PinnedPipError(IncompleteCheckError):
    """Guardian's pip could not be obtained or run as written here: the check is unfinished
    (exit 2) and nothing is installed."""

    def __init__(self, message: str, *, site: str | None = None) -> None:
        super().__init__(SkipReason.CHECK_ERROR, site=site)
        self.message = message

    def __str__(self) -> str:
        return self.message


def cache_dir(home: str) -> str:
    return os.path.join(home, ".cache", "ssc-guardian", "pip")


def matches_pin(data: bytes) -> bool:
    return hashlib.sha256(data).hexdigest() == SHA256


def wheel_bytes(client: Client, home: str) -> bytes:
    """The pinned wheel's bytes, checked against :data:`SHA256`: from the cache when its copy
    matches, otherwise downloaded, checked and cached. The cached copy is opened non-blocking
    and read only as a regular file, so a FIFO in its place is a miss, never a hung run."""
    cached = os.path.join(cache_dir(home), f"{SHA256}.whl")
    try:
        fd = os.open(cached, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("not a regular file")
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        data = b""
    if matches_pin(data):
        return data
    data = client.get(URL, accept="application/octet-stream", limit=MAX_BYTES).body
    if not matches_pin(data):
        raise PinnedPipError(
            f"the downloaded {FILENAME} does not match the SHA-256 Guardian pins",
            site="pinned_pip.does-not-match-sha-256",
        )
    _store(cached, data)
    return data


def _store(path: str, data: bytes) -> None:
    folder = os.path.dirname(path)
    _private_folders(folder)
    handle, temp = tempfile.mkstemp(dir=folder, prefix=".tmp-", suffix=".whl")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
        os.replace(temp, path)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise


def _private_folders(folder: str) -> None:
    """Make ``folder`` and every missing parent readable by this user only (``makedirs`` gives
    its mode to the last folder alone)."""
    missing: list[str] = []
    while not os.path.isdir(folder):
        missing.append(folder)
        folder = os.path.dirname(folder)
    for path in reversed(missing):
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:  # another run made it first
            continue


def place(client: Client, home: str, folder: str) -> str:
    """A verified copy of the wheel in ``folder`` (a run's private folder), which is what runs:
    a later change to the cache cannot reach this run."""
    path = os.path.join(folder, FILENAME)
    with open(path, "xb") as out:
        out.write(wheel_bytes(client, home))
    return path


def clean_environment(folder: str) -> dict[str, str]:
    """The child's whole environment: nothing inherited, so no ``PIP_*`` setting and no
    ``PYTHON*`` variable reaches it, no configuration file is read (fact 39), and its home is
    the run's private ``folder``, so no file in the person's home (``~/.netrc``) is read."""
    return {"PATH": "/usr/bin:/bin", "HOME": folder, "TMPDIR": folder, "PIP_CONFIG_FILE": os.devnull}


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


def run(
    python: str,
    mode: tuple[str, ...],
    wheel: str,
    folders: Sequence[str],
    args: Sequence[str],
    *,
    env: dict[str, str],
    cwd: str,
    timeout: float = TIMEOUT_SECONDS,
) -> Completed:
    """Run the pinned pip from ``wheel`` under the venv's ``python`` in ``mode``
    (:data:`LOCKED_DOWN` or :data:`NORMAL`), with ``folders`` added as plain paths, in the
    run's private folder ``cwd``."""
    if mode not in (LOCKED_DOWN, NORMAL):
        raise ValueError("the venv's Python runs locked down or in normal mode, nothing else")
    check(Field.PATH, python)
    argv = [python, *mode, "-c", BOOTSTRAP, wheel, str(len(folders)), *folders, *args]
    try:
        # A fixed argument list, no shell, the venv's own Python; owner-approved, issue #6.
        done = subprocess.run(  # nosec B603
            argv,
            env=env,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PinnedPipError(
            f"the venv's Python could not run Guardian's pip ({type(exc).__name__})",
            site="pinned_pip.venvs-python-could-not-run",
        ) from exc
    return Completed(
        done.returncode,
        done.stdout.decode("utf-8", errors="replace"),
        done.stderr.decode("utf-8", errors="replace"),
    )
