# Software Supply Chain Guardian (`ssc-guardian`)

[![Tests](https://github.com/thomascburns/ssc-guardian/actions/workflows/tests.yml/badge.svg)](https://github.com/thomascburns/ssc-guardian/actions/workflows/tests.yml)

Guardian protects a developer's Mac and the developer's GitHub repositories from poisoned
updates. It holds new releases for a waiting period (a cooldown), checks threat feeds and known
vulnerabilities, pins GitHub Actions to verified commits, and explains every decision.

**This is a reference implementation (release `v1.0.1-reference`), not for production.** There
is no support or stability promise. Read the [known limits](#known-limits) before relying on it.

**Guardian runs entirely on your own machine.** It has no server, no account and no
telemetry, and it sends nothing to its author. Its only network traffic is lookups to five
public services, listed in the section "What Guardian runs and sends" of
[SECURITY.md](SECURITY.md#what-guardian-runs-and-sends). Each lookup names at most the
packages and Actions being checked, and Guardian's own requests identify the client only as
`ssc-guardian`. The one exception is `ssc-guardian install`, which installs packages with the
standard pip. Guardian does not change pip: it pins pip to one release and checks pip's wheel
against a SHA-256 written in Guardian's code. As it does for everyone, pip tells PyPI your
Python version, operating-system version and processor type. A GitHub token is optional; if
you give Guardian one, it goes only to GitHub.

The [overview for engineering leaders](https://thomascburns.github.io/ssc-guardian/) has diagrams.

What v1.0 covers:

- **Python on macOS:** the Python environments you name. `check` and `protect` look for them only
  at or under the paths you give with `--path`: the base installations there (in standard
  locations: python.org, Homebrew's Python, Apple's Python, pyenv, uv-managed, and through
  interpreters in `PATH` folders under a named path) and every virtual environment (venv).
  `check` also reads every package folder each one's Python loads, even one outside the named
  paths, such as the per-user folder or, for a venv that sees its base's packages, the base's main
  folder. `install` installs into venvs only.
- **GitHub Actions,** with the same rules as Python packages, except that a commit a workflow
  already pins, and the lock file lists, is a notice (exit 0) while it is inside its cooldown, not
  a violation. For a commit still inside its cooldown, `pin` records it in the lock file but
  leaves the workflows alone; run `pin` again once the commit is eligible.
- **uv:** cooldown setup and reporting. Checked installs go through pip.

Guardian uses only Python's standard library: it has no outside dependencies.

## Install

### Prerequisites

- **macOS.** `check --repo` also runs on Linux (see [known limits](#known-limits)).
- **Python 3.11 or later** for Guardian itself. uv supplies it when the Mac has none (Apple's
  Python is 3.9).
- **uv**, to install Guardian into its own environment.
- **gh**, the GitHub command-line tool. Only verifying the release needs it signed in
  (`gh auth login`); downloading works without signing in. Guardian also uses the sign-in, if
  present, for GitHub's higher request limit.
- **A GitHub token (optional, recommended for the GitHub Actions checks).** Guardian works
  without one, but GitHub then allows 60 requests an hour, and a run that uses them up reports a
  `rate-limit` skip and exits 2. Both kinds of check make GitHub requests: the GitHub Actions
  checks, and the malware advisories `check` and `install` read for Python packages. Guardian
  uses `GH_TOKEN`, else `GITHUB_TOKEN`, else runs `gh auth token`, but only from
  `/opt/homebrew/bin/gh` or `/usr/local/bin/gh` (where Homebrew installs gh), never through
  `PATH`.

### Download, verify, install

Download the wheel, verify it, then install that exact file:

```sh
gh release download v1.0.1-reference -R thomascburns/ssc-guardian -p 'ssc_guardian-*.whl'
gh attestation verify ssc_guardian-1.0.1-py3-none-any.whl -R thomascburns/ssc-guardian \
  --signer-workflow thomascburns/ssc-guardian/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.1-reference
uv tool install ./ssc_guardian-1.0.1-py3-none-any.whl
```

If your shell can't find `ssc-guardian`, run `uv tool update-shell` (it puts uv's tool folder,
`~/.local/bin` by default, on `PATH`) and open a new terminal.

Then name what to check: `ssc-guardian check --envs --path <folder>` checks every environment at
or under `<folder>`. Guardian searches only the paths you name; the [known limits](#known-limits)
show a loop over several venvs. [SECURITY.md](SECURITY.md) lists the verify commands and what they
check.

**Never install Guardian into a project's own venv.** Packages there can run code through
`.pth` files when the interpreter starts. `uv tool` and `uvx` give Guardian its own environment.

A venv made with Apple's Python 3.9 (`python3 -m venv` on a new Mac) comes with a pip that ignores
the cooldown. The newest pip that runs on 3.9, pip 26.0, takes only a fixed date, which goes stale
about weekly, so recreate the venv with uv's Python, for example `uv venv --python 3.11 --seed`.

## Quick start

Three Guardian commands on a project at `~/projects/app` with a new venv and one workflow that
uses `actions/checkout@v4`. The output is from a run of Guardian 1.0.0 on 2026-11-17 (UTC),
shortened where it shows `…`; the advisories and versions you see will differ. Guardian prints full
paths; your home folder is shown here as `~`.

**1. Write the cooldown into the venv.** Guardian shows the change and asks first:

```console
$ ssc-guardian protect pip --path ~/projects/app/.venv
Guardian will write its cooldown setting (and nothing else):
  ~/projects/app/.venv/pip.conf: (no setting) -> 2026-10-27T00:00:00+00:00
Proceed? [y/N] y
Written: ~/projects/app/.venv/pip.conf
ssc-guardian protect: 0 violations, 0 warnings, 0 notices; 1 checked, 0 skipped in scope, 0 out of scope
…
ssc-guardian 1.0.0, exit 0: every rule met in what was checked.
```

**2. Check the venv.** In this run the pip and setuptools that came with the new venv had known
vulnerabilities:

```console
$ ssc-guardian check --envs --path ~/projects/app/.venv
ssc-guardian check: 2 violations, 0 warnings, 0 notices; 2 checked, 0 skipped in scope, 1 out of scope

VIOLATION known-vulnerability pypi pip 26.0.1
…
VIOLATION known-vulnerability pypi setuptools 82.0.0
…
ssc-guardian 1.0.0, exit 1: at least one violation.
```

**3. Check the repository's workflows.** A tag such as `v4` can be moved to other code, so it is a
violation; the `fix:` line is the command that fixes it:

```console
$ cd ~/projects/app
$ ssc-guardian check --repo .
ssc-guardian: first use of actions/checkout in this repository: created 2019-07-19 (2678 days ago), 9023 stars, 2750 forks
ssc-guardian check: 1 violation, 0 warnings, 1 notice; 1 checked, 0 skipped in scope, 1 out of scope

VIOLATION moving-reference github-actions actions/checkout v4
  place: ~/projects/app/.github/workflows/ci.yml
  fix: actions/checkout v4: ssc-guardian pin actions/checkout@v4
  id: 220ace1b1db715bbf2a7cb7e4767a0dd

NOTICE first-use-publisher github-actions actions/checkout
  place: ~/projects/app
  id: 70529519298d987e7e3b5918cfccfc70
…
ssc-guardian 1.0.0, exit 1: at least one violation.
```

The same run with `--json` (an excerpt; [docs/reference.md](docs/reference.md#json-output) gives
the format and a full example):

```text
{
  …
  "command": "check",
  "exit_code": 1,
  "findings": [
    {
      …
      "item": "actions/checkout",
      …
      "level": "violation",
      …
      "options": [
        {
          "command": [
            "ssc-guardian",
            "pin",
            "actions/checkout@v4"
          ],
          …
          "kind": "replace",
          …
        }
      ],
      …
      "rule": "moving-reference",
      "version": "v4",
      …
    },
    …
  ],
  "format_version": "1.0",
  …
  "summary": {
    "checked": 1,
    "notices": 1,
    "skipped_in_scope": 0,
    "skipped_out_of_scope": 1,
    "violations": 1,
    "warnings": 0
  },
  …
}
```

## Commands

| Command | What it does | Changes anything? |
|---|---|---|
| `ssc-guardian check --envs --path <path>...` | Python: checks the environments at or under each named path. Works in any folder. | No |
| `ssc-guardian check --repo [dir]` | GitHub Actions: checks one repository's workflows (the form for commit gates and CI). With no folder, the current folder, which must be the repository's top folder (from a subfolder it exits 2). | No |
| `ssc-guardian check --path <path>...` | Both, from inside a repository: the Python environments at or under each named path, plus the workflows under those paths (and the local Actions they reach) in the repository holding the current folder. Outside a Git repository it exits 2 unless `--envs` is given. A `check` naming neither `--path` nor `--repo` is refused (exit 2). | No |
| `ssc-guardian protect [pip\|uv] --path <path>...` | Writes the installers' own cooldown setting into every environment at or under the named paths, and into uv's user config when a named path holds it (`--path ~/.config/uv`), or reports why it can't. `--path` is required. | Yes, after you confirm |
| `ssc-guardian install --venv <path> <packages>` | Checks everything pip would install, then installs exactly those files into the named venv. | Yes, after every check passes and you confirm |
| `ssc-guardian pin <owner/repo>@<ref>` | Verifies an Action version, records it in the lock file, then writes the pin. Inside the version's cooldown it writes only the lock entry, after you confirm, and reports the date the pin becomes eligible. | Yes, after every check passes and you confirm |
| `ssc-guardian acknowledge <owner/repo>` | Records a person's acceptance of a young or little-used Action repository. | Yes, after you confirm |
| `ssc-guardian override add` | Writes one override entry. | Yes, after you confirm |

- **Filters.** `check --language python` and `check --ecosystem pypi` or
  `check --ecosystem github-actions` narrow a check. Each can be repeated: repeats of one flag
  add up, and the two flags together keep only what both allow. Any other value is refused
  (exit 2).
- **Install targets.** `install` installs into a venv on Python 3.9 or later. A base Python
  (Apple's, Homebrew's, python.org's), a path that is not a venv, or a venv on an older Python
  is refused (exit 2).
- **Output.** Text by default; JSON with `--json`. Both come from the same findings.
- **Exit codes.** 0: every rule met in what was checked. 1: at least one violation. 2: a check
  could not finish. Once a violation is known the result is 1, and the unfinished checks are
  still listed. A failed check never gives 0.
- **Skipped is never clean.** Every report lists what it checked and what it skipped, and why.
- **Show before write.** Every command that writes shows the change first and writes when you
  confirm. `--yes` confirms in advance for `install`, `protect` and `pin`. `acknowledge` and
  `override add` never accept `--yes`: a person decides them at a terminal.
- **There is no remove command.** Removing a package is your decision.

[docs/reference.md](docs/reference.md) lists each command's flags, the exit codes, every rule and
skip reason, and the JSON format with a full example.

## Settings

| File | Where it lives | What it holds | Which commands read it |
|---|---|---|---|
| `config.toml` | `~/.config/ssc-guardian/` | Your settings and deny list; the only place for `pypi:` rules and `pypi:` deny entries | `check` (every form), `protect`, `install`, `pin`, `acknowledge`; never `override add` |
| `.ssc-guardian.toml` | The repository's top folder | The repository's settings, deny list and acknowledgments (written by `acknowledge`) | `check` (GitHub Actions), `pin`, `acknowledge` |
| `overrides.toml` | `~/.config/ssc-guardian/` | Overrides for Python packages, written by `override add` | `check` (Python), `protect`, `install` |
| `.ssc-guardian-overrides.toml` | The repository's top folder | Overrides for GitHub Actions, written by `override add` | `check` (GitHub Actions), `pin` |

Guardian reads your `~/.config/ssc-guardian/config.toml` for `check` (every form, `check --repo`
in CI included), `protect`, `install`, `pin` and `acknowledge`, never for `override add`. When it
checks a repository's GitHub Actions, it also reads that repository's `.ssc-guardian.toml`. Where
both set a value, the stricter one applies. Settings change the rules, never what a command reads:
`check` and `protect` search only the paths you name with `--path`. Allowed Action pins live in
`.ssc-guardian.lock`. Of Guardian's commands, only `ssc-guardian pin` writes it, but CI trusts
any committed change to it, so review every change.
[docs/reference.md](docs/reference.md#settings-files) gives every key of these files and of the
lock file.

A sample `config.toml`. Every key except `format` is optional; the comments say which values are
the built-in defaults and which are examples:

```toml
format = 1
deny = ["pypi:example-bad"]            # an example; the default is an empty list

[defaults]
cooldown_days = 21                     # built-in default
block_on = "strong"                    # built-in default; "never" | "strong" | "any"

[rules]
"pypi:requests" = { cooldown_days = 30 }   # an example, not a default
```

A sample `.ssc-guardian.toml`, read the same way:

```toml
format = 1
deny = ["github-actions:example/bad-action"]   # an example; the default is an empty list

[defaults]
cooldown_days = 21                     # built-in default
young_repository_days = 90             # built-in default; can only be raised
min_stars = 50                         # built-in default; can only be raised

[rules]
"github-actions:actions/checkout" = { cooldown_days = 30 }   # an example, not a default
```

Every rule names its ecosystem (`pypi:` or `github-actions:`). A deny entry blocks whatever any
other setting says.

### Errors you may see

- **An unprefixed rule or deny entry** is refused, never guessed.
- **A `pypi:` rule or deny entry in `.ssc-guardian.toml`** makes that file malformed, because the
  commands that check Python packages read no repository file; move the entry to `config.toml`.
  While the file is malformed, `check --repo`, `pin` and `acknowledge` stop (exit 2), and
  `check --path` inside the repository still checks the environments but lists the GitHub Actions
  as not checked. The message names the entry's line, except for an entry spelled with escapes.
- **The former `[scope]` table** (`venv_folders` or `ecosystems`) is refused, and the message
  names its line and the argument that replaces it.

## GitHub Actions: one example from March 2025

`tj-actions/changed-files` (CVE-2025-30066,
[GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)) called
`reviewdog/action-setup@v1` by tag (CVE-2025-30154,
[GHSA-qmg3-hpqr-gqvc](https://github.com/advisories/GHSA-qmg3-hpqr-gqvc)). Attackers moved that
tag, and the code ran inside every workflow that used tj-actions. Both CVEs are in CISA's Known
Exploited Vulnerabilities catalog
([CISA's alert](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)).

Guardian's answer, threat by threat:

- **Moving tag:** every reference must be a 40-hex commit SHA; `check --repo` reports a tag or
  branch reference, and `pin` pins it.
- **Malicious release:** every new commit has a cooldown. Inside it, `pin` records the commit in
  the lock file but leaves the workflows alone, so `check --repo` still reports the tag or branch
  as a violation; run `pin` again on or after the date it gives. A commit that a workflow already
  pins and the lock file lists is a notice (exit 0) while it is inside its cooldown.
- **Wrong publisher:** a young (created under 90 days ago) or little-used (under 50 stars) Action
  repository blocks until a person runs `acknowledge`. The one exemption, Guardian's own
  repository, is listed under [known limits](#known-limits).
- **Impostor commit:** the lock file is the list of allowed pins; `pin` accepts a commit only if
  a publisher tag points at it, GitHub's activity log shows it on a publisher branch, or it is in
  the publisher's default-branch history.
- **Nested Action:** references inside a pinned Action are read at its pinned commit and checked
  the same way; a moving reference inside one is a violation.
- **Known vulnerability:** every pin is checked against GitHub's reviewed advisories on every run.

Turn on GitHub's "Allow select actions" and "Require SHA pinning" settings as run-time
enforcement.

**Review lock-file changes.** CI trusts the committed lock file as it is: an entry added there
is an allowed pin, and its `trusted` date sets when that commit's cooldown starts, which CI takes
as written. Review every change to `.ssc-guardian.lock` in a pull request.

**zizmor.** If you already use zizmor on your workflows, the two overlap. Guardian's difference
is the cooldown, the verified pin list and the threat feeds.

## Usage patterns

How a repository uses Guardian is the adopter's choice. The documented patterns:

- **Per-repository commit gate and CI:** [docs/gate-snippet.md](docs/gate-snippet.md). Each
  repository pins its own Guardian version and wheel SHA-256; the gate checks the hash on every
  run. The same page has a CI example workflow.
- **Agent use:** [docs/agent-instructions.md](docs/agent-instructions.md) tells an AI agent how to
  run `ssc-guardian check` with `--path` or `--repo` and `--json`, and act on the result.
- **Who may weaken a rule:** [docs/authority-patterns.md](docs/authority-patterns.md) gives a
  Claude Code permission pattern and a CODEOWNERS pattern for the repository's Guardian files.
- **Route Claude Code package requests through Guardian:**
  [docs/claude-code-routing.md](docs/claude-code-routing.md).
- **The output formats and file formats:** [docs/reference.md](docs/reference.md), with
  [docs/contracts.md](docs/contracts.md) as the design record behind it.

## Known limits

### Scope and platform

- Reference implementation, not for production, no support or stability promise.
- macOS only, except that `check --repo` is supported on Linux too: the CI example in
  [docs/gate-snippet.md](docs/gate-snippet.md) runs it there.
- GitHub Enterprise Server is untested.
- Guardian does not search your Mac for venvs: name each one, or a folder that holds them, with
  `--path`, or loop in the shell, for example
  `for v in ~/projects/*/.venv; do ssc-guardian check --envs --path "$v"; done`.
- `install` installs into venvs only, never one whose interpreter is a copy
  (`python -m venv --copies`, or a tool that copies it), which Guardian cannot tell from a
  replaced one.
- Guardian doesn't check the Python interpreter program itself.
- Docker image contents, code an Action downloads while it runs, and npm code bundled in
  JavaScript Actions are not checked.
- Guardian does not read a publisher's own CI workflows, where the March 2025 hop ran; it
  catches that case on the consumer's side.

### Not yet (planned)

- Python and GitHub Actions only (Homebrew, npm, Cargo later).
- The repository settings report, guided setup (`init`), pre-commit hooks and dependency-file
  checks come in v1.1.

### What Guardian cannot enforce

- **An agent or program that runs as you can edit Guardian's files or code; your agent's
  permission settings and CI review are the enforcement points.**
- CI trusts the committed lock file: review lock-file changes.
- Guardian's own repository (`thomascburns/ssc-guardian`) is exempt from the young or
  little-used repository rule only, matched by its exact name and its numeric ID together;
  every other rule applies to it.
- A plain `pip` or `uv` run skips the compromise and vulnerability checks.
- A venv made after your last `protect` has no cooldown for plain `pip install` until you run
  `protect` (`check` reports it; `install --venv` always applies the cooldown).
- A variable that changes or removes the cooldown (`PIP_UPLOADED_PRIOR_TO`, `PIP_CONFIG_FILE`,
  `UV_EXCLUDE_NEWER`, `UV_NO_CONFIG` and the like), assigned inline for one command, dies with
  that command, so `check` cannot see it afterwards. Its only trace is the installed
  package, which the `cooldown` rule reports while the package is younger than the cooldown and
  not after.
- An index variable assigned inline for one command (`PIP_INDEX_URL`, `UV_INDEX_URL` and the
  like) can install a file from another index under a version number PyPI also has, and `check`
  cannot tell that file from PyPI's.
- Apple's Python can reach pip 26.0 at most, which takes only a fixed date, so its cooldown date
  goes stale about weekly. Apple's Python is a signed bundle, so `protect` cannot write that date.
  `protect` reports the value to set, and an administrator sets it.
- `brew upgrade` deletes the cooldown setting of Homebrew's Python (the next run reports it).
- Checks are true on the day they run.
- The cooldown buys time for detection; it does not guarantee detection.
- A patient lookalike Action is stopped only by GitHub's "Allow select actions" setting.

### Edge cases

- A fix is matched to the venv's Python as X.Y only, so a fix whose wheel requires a later patch
  release (`>=3.12.1` on a 3.12.4 venv) reads as no fit and ends no override in `check --envs`
  or `install`; pip may still install it on a loose request.
- Guardian's own install from the release wheel (`uv tool install ./<wheel>`) has no PyPI upload
  date, so a `check --envs` path that covers uv's tool folder (`~/.local/share/uv/tools` by
  default), such as `--path ~`, always exits 2 with an `unknown-age` skip that names
  `ssc-guardian`. Name the venvs or folders to check instead of your home folder.
- A file added to an old release on PyPI is as young as its own upload, so `check --envs` dates
  an installed package by the newest file of its release that could be the one installed: in a
  venv, any file that fits the venv's Python and this Mac. Outside a venv, Guardian goes by the
  tags in the package's own `WHEEL` file, which whoever published the wheel wrote, so outside a
  venv a young file added to an old release can pass the cooldown by claiming the old file's tags.
- Nested Actions are checked to a combined depth of 10 levels below the workflow file, and at
  most 500 unique nested references per run; past a limit the run fails.
- `check --envs` looks for a venv's project uv files from the venv's parent folder up; a venv
  kept elsewhere (`UV_PROJECT_ENVIRONMENT`) is not covered; project uv files are checked only
  when a uv program is found.
- In CI, a default-branch `.ssc-guardian-overrides.toml` over 1 MB is not returned whole by
  GitHub's contents API, so `check --repo` stops with exit 2 (it fails closed). A malformed
  overrides file, by contrast, releases nothing and the check still reports its findings.

## About these documents

Guardian is built in a private development repository and published here as curated commits.
A section reference (§) that names no document, such as "plan §5", is to its v1.0 plan, which
stays in the development repository and is not published. One that names a document, such as
"docs/contracts.md §10", is to that document. An issue number such as #255 is in the development
repository's tracker, which is not public; it is not an issue in this repository.

To use Guardian, read [docs/reference.md](docs/reference.md), the reference for users.
[docs/contracts.md](docs/contracts.md) is the frozen design record behind it: the same contracts
with the decisions that shaped them, and a legend for the codes it uses (D1, Q2, T5 and others).
[docs/changelog.md](docs/changelog.md) lists what changed in each release.

## License and credit

Copyright 2026 Thomas C. Burns. Licensed under Apache-2.0; see [LICENSE](LICENSE). You may copy,
change and reuse any part of this repository under that license. If you do, keep the copyright
and license notices in the files you take, include LICENSE and [NOTICE](NOTICE), and mark the
files you changed.
