# Per-repository commit gate and CI example

Each repository that adopts Guardian pins its own Guardian version and the wheel's SHA-256. The
gate downloads the wheel once into a local cache folder, checks its SHA-256 on every run, and
only then runs `ssc-guardian check --repo .`. A mismatch stops the gate and runs nothing.

`uvx` cannot require a hash itself, so the gate checks it. To upgrade, change the version and
the hash together.

## The commit gate

Save this as `.git/hooks/pre-commit` in the repository and make it executable
(`chmod +x .git/hooks/pre-commit`), or call it from the repository's own commit gate.

The gate is only as trustworthy as the hash you pin. Take it from a wheel you have already
verified with `gh attestation verify` ([SECURITY.md](../SECURITY.md)):
`shasum -a 256 ssc_guardian-1.0.0-py3-none-any.whl`, and put it in `GUARDIAN_SHA256`.

```sh
#!/bin/sh
# ssc-guardian commit gate: pinned version, wheel SHA-256 checked on every run.
set -eu

GUARDIAN_TAG="v1.0-reference"
GUARDIAN_WHEEL="ssc_guardian-1.0.0-py3-none-any.whl"
GUARDIAN_SHA256="<the wheel's SHA-256>"

CACHE="$HOME/.cache/ssc-guardian-gate/$GUARDIAN_TAG"
WHEEL="$CACHE/$GUARDIAN_WHEEL"

if [ ! -f "$WHEEL" ]; then
    mkdir -p "$CACHE"
    (cd "$CACHE" && gh release download "$GUARDIAN_TAG" -R thomascburns/ssc-guardian -p "$GUARDIAN_WHEEL")
fi

ACTUAL=$(shasum -a 256 "$WHEEL" | cut -d ' ' -f 1)
if [ "$ACTUAL" != "$GUARDIAN_SHA256" ]; then
    echo "ssc-guardian gate: $WHEEL has SHA-256 $ACTUAL, expected $GUARDIAN_SHA256." >&2
    echo "ssc-guardian gate: stopped; nothing was run." >&2
    exit 2
fi

cd "$(git rev-parse --show-toplevel)"
exec uvx --from "$WHEEL" ssc-guardian check --repo .
```

- The first run downloads the wheel; later runs use the cached file and check its hash again.
- The gate checks the working tree, not the staged snapshot: an unstaged change to a workflow or
  a Guardian file is checked though it isn't committed, and a staged version that differs from it
  isn't. Stage the whole change before you commit.
- A mismatch exits 2 before Guardian runs. Find out why the file changed before you delete it
  from the cache and download it again.
- `ssc-guardian check --repo .` exits 0 when every rule is met, 1 on a violation and 2 when a
  check could not finish. A Git pre-commit hook that exits with anything but 0 stops the commit.
- To upgrade, change `GUARDIAN_TAG`, `GUARDIAN_WHEEL` and `GUARDIAN_SHA256` together.

## CI example

This workflow downloads the wheel, checks its SHA-256, installs it into a venv of its own and
runs `check --repo`. An exit code of 1 or 2 fails the build. Put the same verified SHA-256 in
`GUARDIAN_SHA256`.

```yaml
name: ssc-guardian

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    env:
      GUARDIAN_TAG: v1.0-reference
      GUARDIAN_WHEEL: ssc_guardian-1.0.0-py3-none-any.whl
      GUARDIAN_SHA256: "<the wheel's SHA-256>"
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.11"
      - name: Download and verify ssc-guardian
        run: |
          cd "$RUNNER_TEMP"
          curl -sSfL -o "$GUARDIAN_WHEEL" "https://github.com/thomascburns/ssc-guardian/releases/download/$GUARDIAN_TAG/$GUARDIAN_WHEEL"
          echo "$GUARDIAN_SHA256  $GUARDIAN_WHEEL" | sha256sum -c -
      - name: Install ssc-guardian into its own venv
        working-directory: ${{ runner.temp }}
        run: |
          python -I -m venv "$RUNNER_TEMP/ssc-guardian"
          "$RUNNER_TEMP/ssc-guardian/bin/python" -I -m pip install --no-deps "$RUNNER_TEMP/$GUARDIAN_WHEEL"
      - name: Check the repository
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          "$RUNNER_TEMP/ssc-guardian/bin/ssc-guardian" check --repo .
```

- Pin every Action by its commit SHA, as above; `ssc-guardian pin` writes such pins and records
  them in the lock file. The two pins shown are examples: verify them with `ssc-guardian pin`
  before you use them.
- Guardian has no outside dependencies, so `--no-deps` installs the one checked file.
- The install step runs from the temp folder with `-I`, so a pull request cannot swap pip or venv.
- The workflow token needs only `contents: read`. In CI, Guardian reads the default branch's
  settings and overrides through the GitHub API with that token; if it cannot read them, the
  result is exit 2.
- Run Guardian before any step that runs code from the pull request (an install step, the
  tests), or in a separate job: such code runs as the same user and could change what Guardian
  reads.
- With branch protection that requires this check, see
  [authority-patterns.md](authority-patterns.md) for the CODEOWNERS pattern.
