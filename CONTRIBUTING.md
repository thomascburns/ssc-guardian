# Contributing

Software Supply Chain Guardian (`ssc-guardian`) `v1.0-reference` is a reference release, not
for production, with no support or stability promise.

## Pull requests

**This repository does not accept pull requests from outside contributors at launch.**
Guardian is built in a private development repository and published here as a short series of
curated commits for each release, so a pull request here cannot be merged as it stands.

There is a second reason. In CI, Guardian trusts the committed lock file (`.ssc-guardian.lock`)
as it is: an entry there is an allowed pin. A repository that takes pull requests from outside
contributors needs CI to re-verify the lock-file entries each pull request adds. That check is
held in reserve and is not part of v1.0.

## Issues

Issues are welcome: a bug, a wrong verdict (a finding that should not be there, or a missing
one), or a gap in the documents. A reply is not guaranteed.

Please include:

- the output of `ssc-guardian --version`;
- the command you ran and its exit code;
- the output, preferably with `--json`.

Before you post, remove anything private: tokens, private repository names, paths and package
names you do not want to publish. Guardian never prints a token, but a shell history or an
environment dump can.

## Security problems

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

Guardian is licensed under Apache-2.0; see [LICENSE](LICENSE).
