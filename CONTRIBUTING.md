<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: the files a project provides, no contributor licence agreement, adopting a seeded project. -->
# Contributing

This repository takes one kind of contribution: a pull request that enrolls, edits, pauses or withdraws a project under `projects/<name>/`. We do not accept other changes, including changes to `tools/`, `templates/`, `infra/` or `docs/`.

Contributions are made under the Apache License 2.0 ([LICENSE](LICENSE), section 5). There is no separate contributor licence agreement.

## Enrolling a project

Follow the [README](README.md), or ask a coding agent to follow [.claude/skills/add-project/SKILL.md](.claude/skills/add-project/SKILL.md). In short:

1. Add `projects/<name>/` with a `project.yaml` (start from [templates/project.yaml](templates/project.yaml)), a `Dockerfile` and a `build.sh` (start from [templates/](templates/)). One project per pull request.
2. Run `tools/validate.py` and fix anything it reports.
3. Run `tools/check <name>` and make sure it builds every fuzz target you want verified.
4. Open a pull request and fill in the checklist. Only a project's core maintainers can enroll it; we confirm this before merging.

The email addresses in `project.yaml` are public.

## Adopting a seeded project

We seed some projects ourselves, on branches named `draft-generic-oss-fuzz-<name>`, with `primary_contact: n/a`. To adopt one, copy its `projects/<name>/` into a pull request against `main`, set `primary_contact` to your project's security contact, and fill in the checklist as for any enrollment.

## Changing or leaving

Edit `projects/<name>/` in a pull request to change an enrollment, set `disabled: true` in `project.yaml` to pause the project, or remove `projects/<name>/` to withdraw it.

## Reporting a security issue

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
