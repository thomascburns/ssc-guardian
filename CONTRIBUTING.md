# Contributing

Software Supply Chain Guardian (`ssc-guardian`) `v1.0.1-reference` is a reference implementation,
not for production, with no support or stability promise.

## Pull requests

**This repository does not accept pull requests from outside contributors while it is
published from a private development repository.** Guardian is built there and published here as
a short series of curated commits for each release, so a pull request here cannot be merged as it
stands.

There is a second reason. In CI, Guardian trusts the committed lock file (`.ssc-guardian.lock`)
as it is: an entry there is an allowed pin. A repository that takes pull requests from outside
contributors needs CI to re-verify the lock-file entries each pull request adds. That check is
held in reserve and is not part of v1.0.

## Issues

Issues are welcome: a bug, a wrong verdict (a finding that should not be there, or a missing
one), a gap in the documents, or a question or idea. A reply is not guaranteed.

Please include:

- the output of `ssc-guardian --version`;
- the command you ran and its exit code;
- the output, preferably with `--json`.

Before you post, remove anything private: tokens, private repository names, paths and package
names you do not want to publish. Guardian never prints a token, but a shell history or an
environment dump can.

## Running the tests

The tests need Python 3.11 or later and nothing else installed. On a Mac, `python3` is Apple's
Python 3.9, which the tests cannot use, so the first command has uv supply Python 3.11; any
Python 3.11 or later works instead (for example `python3.11 -m venv .venv`). From a clone of
this repository, make a virtual environment with the hash-locked test requirements, then run the
suite:

```sh
uv venv --python 3.11 .venv && .venv/bin/python -m ensurepip && .venv/bin/python -m pip install --require-hashes --no-deps -r requirements-test.txt
.venv/bin/python -m pytest
```

`ensurepip` installs the pip that comes with Python, so the setup downloads no pip that the
hashes do not cover. The tests import Guardian from `src/`, so it need not be installed. A few
tests reach the network and are skipped when the host is offline. The same install and test
commands run in CI (`.github/workflows/tests.yml`) on every push and pull request, on Linux with
Python 3.11, 3.12 and 3.13, the versions the package metadata names. Lint, type-check, security
lint and the dependency audit run as internal gates in the development repository.

## Security problems

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

Guardian is licensed under Apache-2.0; see [LICENSE](LICENSE).
