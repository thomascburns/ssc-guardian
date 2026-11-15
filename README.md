# Software Supply Chain Guardian (`ssc-guardian`)

Guardian protects a developer's Mac and the developer's GitHub repositories from poisoned
updates. It holds new releases for a waiting period (a cooldown), checks threat feeds and known
vulnerabilities, pins GitHub Actions to verified commits, and explains every decision.

**This is a reference release (`v1.0-reference`), not for production.** There is no support
or stability promise. Read the [known limits](#known-limits) before relying on it.

What v1.0 covers:

- **Python on macOS:** the Python environments you name. `check` and `protect` act only on the
  paths you give with `--path`: the base installations at or under them (in standard locations:
  python.org, Homebrew's Python, Apple's Python, pyenv, uv-managed, and through interpreters in
  `PATH` folders under a named path), each one's main and per-user package folders, and every
  virtual environment (venv) at or under them. `install` installs into venvs only.
- **GitHub Actions,** with the same rules as Python packages, except that a pinned commit still
  inside its cooldown is a notice (exit 0), not a violation; `pin` records it in the lock file
  while it waits.
- **uv:** cooldown setup and reporting. Checked installs go through pip.

Guardian uses only Python's standard library: it has no outside dependencies.

## Install

You need uv and `gh`, signed in (`gh auth login`). Download the wheel, verify it, then install
that exact file:

```sh
gh release download v1.0-reference -R thomascburns/ssc-guardian -p 'ssc_guardian-*.whl'
gh attestation verify ssc_guardian-1.0.0-py3-none-any.whl -R thomascburns/ssc-guardian \
  --signer-workflow thomascburns/ssc-guardian/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0-reference
uv tool install ./ssc_guardian-1.0.0-py3-none-any.whl
```

If your shell can't find `ssc-guardian`, run `uv tool update-shell` (it puts uv's tool folder,
`~/.local/bin` by default, on `PATH`) and open a new terminal.

Then name what to check: `ssc-guardian check --envs --path <folder>` checks every environment at
or under `<folder>`. Guardian looks nowhere you don't name; the [known limits](#known-limits) show
a loop over several venvs.

Guardian needs Python 3.11 or later. uv supplies it when the Mac has none (Apple's Python is
3.9). [SECURITY.md](SECURITY.md) lists the verify commands and what they check.

**Never install Guardian into a project's own venv.** Packages there can run code through
`.pth` files when the interpreter starts. `uv tool` and `uvx` give Guardian its own environment.

## Commands

| Command | What it does | Changes anything? |
|---|---|---|
| `ssc-guardian check --path <path>...` | Checks the Python environments at or under each named path, plus the workflows under it in the current repository if run inside one. Outside a Git repository it exits 2 unless `--envs` is given. A `check` naming neither `--path` nor `--repo` is refused (exit 2). | No |
| `ssc-guardian check --envs --path <path>...` | Only the Python environments at or under the named paths. | No |
| `ssc-guardian check --repo [dir]` | Only one repository's workflows (the form for commit gates and CI). | No |
| `ssc-guardian protect [pip\|uv] --path <path>...` | Writes the installers' own cooldown setting into every environment at or under the named paths, and into uv's user config when a named path holds it (`--path ~/.config/uv`), or reports why it can't. `--path` is required. | Yes, after you confirm |
| `ssc-guardian install --venv <path> <packages>` | Checks everything pip would install, then installs exactly those files into the named venv. | Yes, after every check passes and you confirm |
| `ssc-guardian pin <owner/repo>@<ref>` | Verifies an Action version, records it in the lock file, then writes the pin. Inside the version's cooldown it writes only the lock entry, after you confirm, and reports the date the pin becomes eligible. | Yes, after every check passes and you confirm |
| `ssc-guardian acknowledge <owner/repo>` | Records a person's acceptance of a young or little-used Action repository. | Yes, after you confirm |
| `ssc-guardian override add` | Writes one override entry. | Yes, after you confirm |

- **Output.** Text by default; JSON with `--json`. Both come from the same findings.
- **Exit codes.** 0: every rule met in what was checked. 1: at least one violation. 2: a check
  could not finish. Once a violation is known the result is 1, and the unfinished checks are
  still listed. A failed check never gives 0.
- **Skipped is never clean.** Every report lists what it checked and what it skipped, and why.
- **Show before write.** Every command that writes shows the change first and writes when you
  confirm. `--yes` confirms in advance for `install`, `protect` and `pin`. `acknowledge` and
  `override add` never accept `--yes`: a person decides them at a terminal.
- **There is no remove command.** Removing a package is your decision.

## Settings

Guardian reads your `~/.config/ssc-guardian/config.toml` for `check` (every form, `check --repo`
in CI included), `protect`, `install`, `pin` and `acknowledge`, but not `override add`, and a
repository's `.ssc-guardian.toml` when it checks that repository's GitHub Actions; where both set a value, the
stricter one applies. A sample `.ssc-guardian.toml` (every key except
`format` is optional; the values shown are the built-in defaults where one exists):

```toml
format = 1
deny = ["github-actions:example/bad-action"]

[defaults]
cooldown_days = 21
block_on = "strong"          # "never" | "strong" | "any"
young_repository_days = 90   # can only be raised
min_stars = 50               # can only be raised

[rules]
"github-actions:actions/checkout" = { cooldown_days = 30 }
```

Every rule names its ecosystem (`pypi:` or `github-actions:`); an unprefixed rule is refused,
never guessed. A deny entry blocks whatever any other setting says. **`pypi:` rules and deny
entries belong in `config.toml` only:** the commands that check Python packages read no
repository file, so a `pypi:` entry in `.ssc-guardian.toml` makes that file malformed until the
entry is moved: `check --repo`, `pin` and `acknowledge` stop (exit 2), and `check --path` inside
the repository still checks the environments but lists the GitHub Actions as not checked. The
message names the entry's line, except for an entry spelled with escapes.

Your `config.toml` holds the Python settings. Settings change the rules, never what a command
reads: `check` and `protect` act only on the paths you name with `--path`. A file that still holds
the former `[scope]` table (`venv_folders` or `ecosystems`) is refused, and the message names its
line and the argument that replaces it:

```toml
format = 1
deny = ["pypi:example-bad"]

[rules]
"pypi:requests" = { cooldown_days = 30 }
```

Overrides are written only by `ssc-guardian override add`: those for GitHub Actions go to the
repository's `.ssc-guardian-overrides.toml`, and those for Python packages to
`~/.config/ssc-guardian/overrides.toml`. Allowed Action pins live in `.ssc-guardian.lock` and are
written only by `ssc-guardian pin`. [docs/contracts.md](docs/contracts.md) §10 and §11 give every
key.

## GitHub Actions: the March 2025 reference case

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
- **Malicious release:** every new commit has a cooldown: `pin` records a commit still inside it
  in the lock file but leaves the workflows alone, and `check --repo` reports a pinned one as a
  notice (exit 0).
- **Wrong publisher:** a young (created under 90 days ago) or little-used (under 50 stars) Action
  repository blocks until a person runs `acknowledge`.
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
  Claude Code permission pattern and a CODEOWNERS pattern for Guardian's files.
- **Route Claude Code package requests through Guardian:**
  [docs/claude-code-routing.md](docs/claude-code-routing.md).
- **The output formats and file formats:** [docs/contracts.md](docs/contracts.md).

## Known limits

- Reference release, not for production, no support or stability promise.
- macOS only, except that `check --repo` also runs in Linux CI, as the development
  repository's CI runs Guardian's test suite there.
- Python and GitHub Actions only (Homebrew, npm, Cargo later).
- The repository settings report, guided setup (`init`), pre-commit hooks and dependency-file
  checks come in v1.1.
- `install` installs into venvs only, never one whose interpreter is a copy
  (`python -m venv --copies`, or a tool that copies it), which Guardian cannot tell from a
  replaced one.
- A fix is matched to the venv's Python as X.Y only, so a fix whose wheel requires a later patch
  release (`>=3.12.1` on a 3.12.4 venv) reads as no fit and ends no override in `check --envs`
  or `install`; pip may still install it on a loose request.
- Guardian doesn't check the Python interpreter program itself.
- Guardian does not search your Mac for venvs: name each one, or a folder that holds them, with
  `--path`, or loop in the shell, for example
  `for v in ~/projects/*/.venv; do ssc-guardian check --envs --path "$v"; done`.
- **An agent or program that runs as you can edit Guardian's files or code; your agent's
  permission settings and CI review are the enforcement points.**
- CI trusts the committed lock file: review lock-file changes.
- A plain `pip` or `uv` run skips the compromise and vulnerability checks.
- A venv made after your last `protect` has no cooldown for plain `pip install` until you run
  `protect` (`check` reports it; `install --venv` always applies the cooldown).
- A variable assigned inline for one command that changes or removes the cooldown
  (`PIP_UPLOADED_PRIOR_TO`, `PIP_CONFIG_FILE`, `UV_EXCLUDE_NEWER`, `UV_NO_CONFIG` and the like)
  dies with that command, so `check` cannot see it afterwards. Its only trace is the installed
  package, which the `cooldown` rule reports while the package is younger than the cooldown and
  not after.
- A file added to an old release on PyPI is as young as its own upload, so `check --envs` dates
  an installed package by the newest file of its release that could be the one installed: in a
  venv, any file that fits the venv's Python and this Mac. Outside a venv, Guardian goes by the
  tags in the package's own `WHEEL` file, which whoever published the wheel wrote, so outside a
  venv a young file added to an old release can pass the cooldown by claiming the old file's tags.
- An index variable assigned inline for one command (`PIP_INDEX_URL`, `UV_INDEX_URL` and the
  like) can install a file from another index under a version number PyPI also has, and `check`
  cannot tell that file from PyPI's.
- Apple's Python can reach pip 26.0 at most, which takes only a fixed date, so its cooldown date
  goes stale about weekly. `protect` cannot write it (a signed bundle): it reports the value, and
  an administrator sets it.
- `brew upgrade` deletes the cooldown setting of Homebrew's Python (the next run reports it).
- Checks are true on the day they run.
- The cooldown buys time for detection; it does not guarantee detection.
- Docker image contents, code an Action downloads while it runs, and npm code bundled in
  JavaScript Actions are not checked.
- Nested Actions are checked to a combined depth of 10 levels below the workflow file, and at
  most 500 unique nested references per run; past a limit the run fails.
- A patient lookalike Action is stopped only by GitHub's "Allow select actions" setting.
- GitHub Enterprise Server is untested.
- Guardian does not read a publisher's own CI workflows, where the March 2025 hop ran; it
  catches that case on the consumer's side.
- `check --envs` looks for a venv's project uv files from the venv's parent folder up; a venv
  kept elsewhere (`UV_PROJECT_ENVIRONMENT`) is not covered; project uv files are checked only
  when a uv program is found.
- In CI, a default-branch `.ssc-guardian-overrides.toml` over 1 MB is not returned whole by
  GitHub's contents API, so `check --repo` stops with exit 2 (it fails closed) instead of
  releasing nothing and reporting the findings.
- Future Rust support is check-before-build: approved crates still run their build code, and
  Guardian states this.

## About these documents

Guardian is built in a private development repository and published here as curated commits.
A section reference (§) that names no document, such as "plan §5", is to its v1.0 plan, which
stays in the development repository and is not published. One that names a document, such as
"docs/contracts.md §10", is to that document. An issue number such as #255 is in the development
repository's tracker, which is not public; it is not an issue in this repository.

## License and credit

Apache-2.0; see [LICENSE](LICENSE). Credit: Thomas C. Burns and Software Supply Chain Guardian.
