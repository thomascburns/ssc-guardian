# Changelog

What changed in each release of Software Supply Chain Guardian (`ssc-guardian`), for the people
who use it. The newest release comes first.

## 1.0.1 (2026-11-19)

### Fixed

- `check --envs` no longer exits 2 when the venv it checks is activated. The venv's own `bin`
  folder on `PATH` is no longer read as a place a base installation is reached from.
- `protect` no longer ends with "every installation … is protected" right after reporting an
  installation it cannot protect, such as a venv made with Apple's Python 3.9. When it writes
  nothing and an installation is still unprotected, it says how many cannot be protected as they
  stand and points at the report.
- A pip that ignores the cooldown on Python older than 3.10 is given a remedy that works there:
  recreate the venv with Python 3.10 or later, or, for a base installation such as Apple's
  Python, use a newer Python for this work. On Python 3.10 or later the remedy reads "upgrade pip
  or leave this installation out of the paths you name", since Guardian has no exclude setting.
- The text report's summary line uses the singular for a count of one: "1 violation, 1 warning,
  1 notice", not "1 violations, 1 warnings, 1 notices".
- An `unknown-age` skip names the package and its version as installed, for example
  `(my-tool 1.0.0)`, so the skip that Guardian's own wheel install gives under a `check --envs`
  path now says which package it is. `install --venv`'s skip for a file PyPI gives no upload time
  names the package and version too.

### Changed

- **For JSON readers:** `check --path <path>`, with both ecosystems in scope, where the path holds
  no Python environment, now gives one `pypi` `check-error` skip at the path, as `check --envs`
  already did; the text report says "no Python environment at or under the named path". It gave two
  generic skips before: one for `pypi` with no place, and one at the path with no ecosystem. So
  `skipped` holds one entry where it held two, and `summary.skipped_in_scope` drops from 2 to 1.
  The exit code is still 2.
- **For JSON readers:** `default-scope` is no longer a skip reason. No command in 1.0.0 emitted
  it, so no output changes. The out-of-scope reasons are now exactly `filtered`, `later-release`,
  `deeper-than-one-level` and `local-install`; every other reason is in scope.
- When `pin`, `protect` or `install` runs without `--yes` and without a terminal, it now shows the
  change it would make before it says the change was not confirmed. Nothing is written, as before.
- After a file Guardian could not use (a refused `.ssc-guardian.toml` or lock file, or a workflow
  it could not read), the repository's skip names that file, `(see <file>)`, in place of a bare
  "the check failed".
- A message already printed on standard error in a `check` run is not printed again, so GitHub's
  hourly rate limit is reported once.
- When the exemption for Guardian's own repository keeps it from blocking as young or
  little-used, one note on standard error says so.
- A `pin` message no longer carries an internal reference code.
- Help text: `install` describes `--venv`, `protect`'s installer argument has a description, and
  `--version` reads "show the version and exit".

### Releases and documentation

- Release tags have three parts from this release on, so 1.0.1 is tagged `v1.0.1-reference`, the
  same version the wheel and `ssc-guardian --version` give. The `v1.0-reference` tag of 1.0.0
  stays as it is.
- New: [reference.md](reference.md), the reference for users: each command and its flags, the
  exit codes, every rule and skip reason, the JSON format with a full example, the field
  grammars, the settings, overrides and the lock file.
- The README is rewritten, with a quick start that shows real output.
- [gate-snippet.md](gate-snippet.md) says where each release gives the wheel's SHA-256 and how to
  check it, and how to keep the commit gate in a versioned hooks folder.
- The test suite is published with the source and runs on every push and pull request;
  CONTRIBUTING.md says how to run it.
- CONTRIBUTING.md's test setup names a Python 3.11 or later for the venv, since `python3` on a
  Mac is Apple's Python 3.9, which the tests cannot use.
- The local-only statement in the README and on the overview site now says what each lookup
  carries, including what pip tells PyPI during `install`; SECURITY.md describes pip's own
  User-Agent.
- CI runs the test suite on Python 3.11, 3.12 and 3.13, the versions the package metadata names.
- The package metadata lists the project's links (source, issues, security policy and this
  changelog), classifiers and keywords.
- New issue form for a question or idea, and a pull-request template that explains why outside
  pull requests cannot be merged here.
- The published documents now say exactly what `check` reads, what `pin` does inside the cooldown,
  when an override ends and what Guardian verifies, and the project site links the release's
  source from its top.

### Added

- A NOTICE file, in the repository and the wheel, names the author for the credit the Apache
  License asks of anyone who reuses the code.

## 1.0.0 (2026-11-16)

The first release, a reference release (not for production), tagged `v1.0-reference`. On macOS
it checks the Python environments you name and a repository's GitHub Actions workflows: it holds
new releases for a cooldown (21 days by default), reports malware and known vulnerabilities from
OSV, GitHub's advisories and PyPI, pins Actions to commits it has verified and records them in a
lock file, writes the installers' own cooldown setting into environments (`protect`), installs
checked packages into a venv (`install`), and records a person's exceptions (`acknowledge` and
`override add`). It uses only Python's standard library, prints text or JSON from the same
findings, and exits 0, 1 or 2.
