<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: rewritten for OSS Verifier, which builds fuzz targets for proofs instead of scanning; the projects table is generated. -->
# OSS Verifier

OSS Verifier is Theorem's program for formally verifying open-source software. This repository is where a project enrolls. A pull request adds one directory, `projects/<name>/`, that says how to build the project's fuzz targets as static riscv64 Linux programs. We then state theorems about those exact binaries, such as "no input makes this fuzz target crash, hang or trip its sanitizer", and prove them in [oss-verifier-proofs](https://github.com/theorem-labs/oss-verifier-proofs). [docs/what-gets-proven.md](docs/what-gets-proven.md) says what a proof covers and what it does not.

Use of OSS Verifier is subject to the [OSS Verifier terms](https://theorem.dev/oss-verifier/terms/).

## How to sign up

A core maintainer enrolls a project by opening a pull request that adds one directory:

```
projects/<name>
```

It holds a `project.yaml` (who you are and what to build), a `Dockerfile` (where the source and its dependencies come from) and a `build.sh` (how to build the fuzz targets), and optionally a `patch_style.md` (how you want patches), harness sources of your own, and build-only patches. A coding agent can do most of this with you: point it at [AGENTS.md](AGENTS.md). [docs/enrollment.md](docs/enrollment.md) walks through enrollment from start to finish.

### project.yaml

Start from [templates/project.yaml](templates/project.yaml); [docs/project-yaml.md](docs/project-yaml.md) describes every field.

```
repo: https://github.com/example/project#v1.2.3  # required: the git repository; #branch or #tag to follow, #<commit> to fix one
primary_contact: security@example.org            # required: findings and build problems go here (one address)
auto_ccs:                                        # optional: more addresses on every report
  - maintainer@example.org
homepage: https://example.org                    # optional
language: c                                      # required: c or c++
sanitizers: [address, undefined]                 # optional: the sanitizer builds besides the plain one (this is the default)
fuzz_targets: [example_fuzzer]                   # optional: the fuzz targets to verify (default: every one the build produces)
publish: after_fixes                             # optional: when we publish the proofs (docs/publishing.md)
disabled: false                                  # optional: true pauses the project without removing it
```

The email addresses in `project.yaml` are public. Use addresses you are happy to see published, such as a security alias. To receive reports encrypted, add your armored OpenPGP public key as `pgp:`. Reports then go to `primary_contact` only, so `pgp` cannot be combined with `auto_ccs`.

### Dockerfile and build.sh

They follow OSS-Fuzz's conventions ([templates/Dockerfile](templates/Dockerfile), [templates/build.sh](templates/build.sh)), on our builder image instead of OSS-Fuzz's:

* The `Dockerfile` starts `FROM` the builder ([infra/base-builder/](infra/base-builder/)), fetches your source at the commit `tools/check` passes as `COMMIT`, fetches and builds any dependencies, and copies `build.sh` (and any harness sources or patches) into `$SRC`. It is the only step with network access.
* `build.sh` builds each fuzz target into `$OUT`, with `$CC`, `$CFLAGS` and `$LIB_FUZZING_ENGINE` as under OSS-Fuzz. It runs once per build, with no network: plain, and one build per sanitizer.

The builder cross-compiles for static riscv64 Linux with clang 20.1.8, musl and lld, so an OSS-Fuzz `build.sh` does not run unchanged: it has to be ported. [docs/build-contract.md](docs/build-contract.md) says exactly what the builder provides and what a build must do.

You can keep the two files in exactly one of two places:

* **here**, next to `project.yaml`, as `projects/<name>/Dockerfile` and `projects/<name>/build.sh`; or
* **in your own repository**: set `dockerfile:` to the Dockerfile's path (we suggest `.oss-verifier/Dockerfile`) and keep `build.sh` beside it. Your repository is then the build context, so you can change the build without a pull request here.

`patch_style.md` works the same way: next to `project.yaml`, or in your repository at the path `patch_style:` names. It tells us what you care about, how you rate severity, and how you want patches ([templates/patch_style.md](templates/patch_style.md)).

Harness sources of your own (`*.c`, `*.cc`, `*.cpp`, `*.h`, `*.hh`, `*.hpp`) and build-only patches (`*.patch`, applied in the order a `series` file lists) can also sit next to `project.yaml`. A patch here may only change how the project builds; a patch that fixes a bug never goes here.

Before opening a pull request, run:

* `tools/validate.py`, which checks `projects/<name>/` against the rules above.
* `tools/check <name>`, which builds your project the way we will and lists the fuzz targets it found. `tools/check --twice <name>` builds it a second time from scratch and checks that every byte is the same.

These tools need git, Docker, and Python 3 with PyYAML (`pip install pyyaml`).

## What happens after the merge

1. We build the project as `tools/check` does and pin each binary by its SHA-256, with the commit it was built from, in the project's lock in the proofs repository.
2. We state theorems about those binaries and work on their proofs ([docs/what-gets-proven.md](docs/what-gets-proven.md)).
3. A finding, such as an input on which a fuzz target crashes, goes privately to `primary_contact` and any CCs. We set no disclosure deadline and do not publish findings ([docs/disclosure.md](docs/disclosure.md)). Where we can, we include a patch written the way `patch_style.md` asks.
4. We publish the proofs when `publish` says ([docs/publishing.md](docs/publishing.md)).

You can edit your project at any time with a pull request. To leave, set `disabled: true` to pause, or remove `projects/<name>/` to withdraw the project.

## Security considerations

* `tools/check` runs your project's Dockerfile with network access, as `docker build` would. Only check projects you trust, or use a machine with nothing to lose.
* The builds themselves run with no network (`docker run --network=none`).

## Projects

<!-- BEGIN projects table: generated by tools/projects_table.py from projects/*/project.yaml; do not edit -->
| project | repository | ref | fuzz targets | build files | enrolled by |
|---|---|---|---|---|---|
| [cjson](projects/cjson/) | https://github.com/DaveGamble/cJSON | v1.7.18 | cjson_read_fuzzer | here | seeded by us; provisional |
<!-- END projects table -->

## Learn more

* [docs/enrollment.md](docs/enrollment.md): enrollment, start to finish.
* [docs/build-contract.md](docs/build-contract.md): what the builder provides and what a build must do.
* [docs/what-gets-proven.md](docs/what-gets-proven.md): the statements and what a proof covers.
* [docs/memory-policy.md](docs/memory-policy.md) and [docs/exit-codes.md](docs/exit-codes.md): two details of the statements.
* [docs/publishing.md](docs/publishing.md) and [docs/disclosure.md](docs/disclosure.md): what we publish, and when.
* [STATUS.md](STATUS.md): what in this repository works today, and what does not yet.

---

**Maintenance status:** this repository is maintained by [Theorem](https://theorem.dev). We review and merge enrollment pull requests (changes under `projects/<name>/`) only; we do not accept other contributions, including changes to `tools/`, `templates/` or `infra/`. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to enroll, [SECURITY.md](SECURITY.md) to report a vulnerability in this repository, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
