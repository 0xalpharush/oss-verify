<!-- Adapted from OSS Scanner's templates/threat_model.md (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, Apache-2.0. Modified 2026 by Theorem Labs, PBC: the sections of a patch style. -->
<!-- Template: copy to your repository (and set patch_style: in project.yaml) or place a copy at projects/<name>/patch_style.md. Free text; we read it before we write a patch for you. -->
# Patch style

## What you care about
- e.g. "memory safety in the parser comes first; the CLI tools matter less"

## How you rate severity (optional)
- e.g. "any out-of-bounds write is critical; an out-of-bounds read is high; a crash on input over 1 GiB is low"

## Patch format
- e.g. "minimal: just enough to fix the bug, with a regression test under tests/" or "merge-ready: follow CONTRIBUTING.md and clang-format, and add a test"

## Where and how to send patches
- By default patches go to `primary_contact`, with the report they belong to.
- e.g. "attach the patch to the report; do not open a pull request"

## Anything to leave alone
- e.g. "the deprecated v1 API, which we are removing"
