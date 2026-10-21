<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: the files a project provides, no contributor licence agreement, adopting a seeded project. -->
# Contributing

This page tells which contributions this repository accepts. It is for maintainers who want to enroll a project.

We accept one type of pull request: a pull request that enrolls, changes, pauses or removes one project under `projects/<name>/`. We do not accept other changes, for example to `tools/`, `templates/`, `infra/` or `docs/`.

To enroll a project, follow the [README](README.md), or give a coding agent the prompt in [Enroll with a coding agent](README.md#enroll-with-a-coding-agent). To adopt a project that we seeded, follow [docs/project-yaml.md](docs/project-yaml.md#seeded-projects).

You make contributions under the Apache License 2.0 ([LICENSE](LICENSE), section 5). There is no separate contributor licence agreement. The driver in `infra/base-builder/driver/`, which takes no contributions, is under MIT OR Apache-2.0, so that a program under version 2 of the GNU GPL can be linked with it ([NOTICE](NOTICE)). A contribution to a file whose SPDX line says MIT OR Apache-2.0, or to a file or lines that NOTICE says are MIT OR Apache-2.0, is made under both licences.

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public issue for it.

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
