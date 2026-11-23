# Security

Software Supply Chain Guardian (`ssc-guardian`) `v1.0.1-reference` is a reference implementation,
not for production, with no support or stability promise.

## Verify a release before you install it

Each release is built by the release workflow in this repository, which attaches an artifact
attestation to the wheel (keyless Sigstore signing through GitHub; there is no named key).
Releases are immutable once published: the tag cannot be moved, and files are attached only
while a release is still a draft.

```sh
gh release download v1.0.1-reference -R thomascburns/ssc-guardian -p 'ssc_guardian-*.whl'
gh attestation verify ssc_guardian-1.0.1-py3-none-any.whl -R thomascburns/ssc-guardian \
  --signer-workflow thomascburns/ssc-guardian/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.1-reference
gh release verify v1.0.1-reference -R thomascburns/ssc-guardian
gh release verify-asset v1.0.1-reference ssc_guardian-1.0.1-py3-none-any.whl -R thomascburns/ssc-guardian
```

- `gh attestation verify` checks the wheel you downloaded against the artifact attestation made
  by this repository's release workflow, run for the release tag.
- `gh release verify` checks the release attestation GitHub makes for an immutable release.
- `gh release verify-asset` checks that the file you downloaded is the one in the release's
  attestation.
- `gh release verify` and `gh release verify-asset` work only once the release is published, not
  on a draft.

Then install that exact file: `uv tool install ./ssc_guardian-1.0.1-py3-none-any.whl`.

A commit gate or CI job that runs Guardian should pin the wheel's SHA-256 and check it on every
run, so a changed file stops the gate before anything runs:
[docs/gate-snippet.md](docs/gate-snippet.md).

## Fixes are new releases

A defect found after a release is published is never fixed by editing that release. A new patch
release, with a new tag, replaces it.

## What Guardian runs and sends

Guardian runs exactly these programs, and nothing else:

1. Its own Python interpreter.
2. A venv's own Python, only inside `ssc-guardian install --venv`: first locked down (`-I -S`)
   with the pinned pip for the check, which runs no installed code; then in normal mode
   (`-I`) for the install, only after every check passes and you confirm. `check` and `protect`
   never run it.
3. `gh auth token`, only from `/opt/homebrew/bin/gh` or `/usr/local/bin/gh`, only when the file is
   owned by root or the user and writable by no one else, and only when `GH_TOKEN` and
   `GITHUB_TOKEN` are unset. Never from `PATH`.

Every other program Guardian finds while scanning (interpreters, pip, scripts) is read from disk,
never run.

For `install`, Guardian uses the standard pip, unchanged. It pins pip to one release, downloads
pip's wheel from PyPI and checks it against a SHA-256 written in Guardian's code.

On the network, Guardian's own client talks over HTTPS to five services only: `api.github.com`,
`api.osv.dev`, `pypi.org`, `files.pythonhosted.org` (the pinned pip wheel) and `www.cisa.gov`.
Any other address, a redirect included, is refused. Every request is a GET except one: OSV's
batch query, a POST of package names. GitHub receives GET requests only. Your GitHub token goes
only to `api.github.com` over HTTPS, is never sent again after a redirect to another host, and
never appears on screen, in a log or in JSON output.

In `install`, the pinned pip fetches PyPI index pages and wheels with pip's own network client and
redirect rules; every file it installs is bound to the SHA-256 Guardian checked
(`--require-hashes`).

Guardian does not change pip. Like any pip, the pinned pip identifies itself to PyPI with a
User-Agent that names pip's version, your Python version and implementation, your operating
system and its version, your processor type and OpenSSL's version, and, when present, the
versions of setuptools and rustc. Guardian's own client sends the User-Agent `ssc-guardian` and
nothing about your machine.

## What Guardian cannot enforce

Guardian's exception commands need a person at a terminal. That is a speed bump, not a lock: a
program can obtain a terminal (`script(1)`). Nor can Guardian stop a program that runs as you from
editing your Guardian settings, override and lock files, or Guardian's own installed code. The
enforcement points are your agent's permission settings and CI with protected branches: see
[docs/authority-patterns.md](docs/authority-patterns.md) and
[docs/claude-code-routing.md](docs/claude-code-routing.md). The README lists the
[known limits](README.md#known-limits).

## Report a vulnerability

Report a suspected vulnerability in Guardian privately, through GitHub's private vulnerability
reporting for this repository. Do not open a public issue for it.
