<!-- Adapted from OSS Scanner's templates/threat_model.md (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, Apache-2.0. Modified 2026 by Theorem Labs, PBC: free text about the form of a patch. -->
<!-- Template: copy to your repository (and set patch_style: in project.yaml) or place a copy at projects/<name>/patch_style.md. Free text; we read it before we write a patch for you. A choice that a field in project.yaml gives (disable_remediation, patches) goes in that field only (docs/patches.md). -->
# Patch style

## Code style
- e.g. "follow .clang-format; keep the existing naming"

## Tests
- e.g. "add a regression test under tests/ that fails without the patch"

## Commit format
- e.g. "one commit for each patch; a subject line under 72 characters; a Signed-off-by line"

## Contribution policy
- e.g. "our policy on AI-generated contributions: https://example.org/CONTRIBUTING.md#ai"

## Where and how to send patches
- By default, a patch goes to `primary_contact`, as an attachment to its finding.
- e.g. "attach the patch to the report; do not open a pull request"
