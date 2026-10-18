<!-- Adapted from OSS Scanner's .github/PULL_REQUEST_TEMPLATE.md (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: OSS Verifier's checklist (terms, tools/check, build files, patch style). -->
## Enroll `projects/<name>`

I have verified each of the following before submitting this project:

- [ ] I am a core maintainer of this project.
- [ ] I accept the [OSS Verifier terms](https://theorem.dev/oss-verifier/terms/).
- [ ] `project.yaml` follows the README (one project per PR; `tools/validate.py` passes locally).
- [ ] `tools/check <name>` builds every fuzz target I want verified.
- [ ] `primary_contact` is the email address of the primary security contact.
- [ ] A `Dockerfile` and a `build.sh` are present, in one of two places: next to `project.yaml` in this repo, or in the project's repository, with `dockerfile:` naming the Dockerfile's path and `build.sh` beside it.
- [ ] `patch_style.md` is written for this project (optional), placed in the same way: next to `project.yaml` in this repo, or in the repository at the path `patch_style:` names.

To change an enrollment, edit `projects/<name>/`; to pause the project, set `disabled: true`; to withdraw it, remove `projects/<name>/`.

Context (optional): anything about the project or its build that a reviewer should know, such as which fuzz targets matter most to you.
