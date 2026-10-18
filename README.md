<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: rewritten for OSS Verifier, which proves theorems about fuzz targets instead of scanning. -->
# OSS Verifier

OSS Verifier is a Theorem program that verifies open-source software. We prove theorems about the compiled fuzz targets of a project. For example, we prove that no input makes a fuzz target crash, hang or fail a sanitizer check. This page is for a maintainer who wants to enroll a project, and for curious readers. A coding agent starts at [AGENTS.md](AGENTS.md).

## Who can enroll

A core maintainer of an open-source project can enroll the project. [docs/eligibility.md](docs/eligibility.md) tells which projects we accept.

## Enroll a project

> **WARNING:** `tools/check` builds the project's `Dockerfile` with network access. Use it only on a project that you trust.

1. Fork this repository.
2. Make the directory `projects/<name>/` from [templates/](templates/): `project.yaml`, `Dockerfile` and `build.sh`.
3. In `project.yaml`, tell us which patches to send you ([docs/patches.md](docs/patches.md)).
4. Run `tools/validate.py projects/<name>`. Correct each problem that it shows.
5. Run `tools/check --twice <name>`. Make sure that it builds each fuzz target.
6. Open a pull request. Complete its checklist.

A coding agent can do steps 2 to 5 with you. Tell it to read [AGENTS.md](AGENTS.md). [docs/enrollment.md](docs/enrollment.md) gives each step in full, with an example.

## After we merge

1. We build the fuzz targets and record the SHA-256 of each binary in a lock.
2. We state theorems about these binaries and prove them ([docs/what-gets-proven.md](docs/what-gets-proven.md)).
3. We send each finding to `primary_contact` privately ([docs/disclosure.md](docs/disclosure.md)).
4. We publish the proofs when `publish` tells us to ([docs/publishing.md](docs/publishing.md)).

## Pause or leave

To pause the project, set `disabled: true` in `project.yaml`. To leave, remove `projects/<name>/`. Make each change in a pull request.

## More information

[docs/faq.md](docs/faq.md) answers common questions, and [docs/glossary.md](docs/glossary.md) defines the terms. [docs/reproducing.md](docs/reproducing.md) tells how to rebuild a binary and compare it with the lock. [SECURITY.md](SECURITY.md) tells how to report a vulnerability in this repository. Use of OSS Verifier is subject to the [OSS Verifier terms](https://theorem.dev/oss-verifier/terms/). We accept only enrollment pull requests ([CONTRIBUTING.md](CONTRIBUTING.md)).
