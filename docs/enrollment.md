# Enrolling a project

This guide tells a maintainer how to enroll a project, step by step. The example is a C library, `example`, that builds with CMake.

## Before you start

Make sure of these points:

* You are a core maintainer of the project, and it meets the conditions in [eligibility.md](eligibility.md).
* You have git, Docker, and Python 3 with PyYAML (`pip install pyyaml`).
* You know the project's fuzz targets, or you are ready to write some.

A coding agent can do steps 1 to 7 with you. Tell it to read [AGENTS.md](../AGENTS.md), which leads to the skill in [.claude/skills/add-project/](../.claude/skills/add-project/SKILL.md).

## Step 1. Decide what "correct" means

A proof covers what the fuzz targets check ([what-gets-proven.md](what-gets-proven.md)). Before you write files, answer these questions:

1. Which inputs come from an attacker, and how large can they be?
2. Which outcomes are expected? Each one must end as `return 0` in the fuzz target ([exit-codes.md](exit-codes.md#what-a-statement-accepts)).
3. Must the library survive a refused allocation? If yes, add an allocation-failure fuzz target ([exit-codes.md](exit-codes.md#allocation-failure)).
4. Which properties, apart from "no crash", can a fuzz target assert? An example is a round trip.

Start from the existing fuzz targets: the project's own, or its OSS-Fuzz fuzz targets. Put each new fuzz target in the project directory.

## Step 2. Make the project directory

1. Fork this repository.
2. Make the directory `projects/<name>/`. Use only `a-z 0-9 . _ -` in the name.
3. Copy [templates/project.yaml](../templates/project.yaml) into it.
4. Copy [templates/Dockerfile](../templates/Dockerfile) and [templates/build.sh](../templates/build.sh), either into the project directory or into your repository.

[project-yaml.md](project-yaml.md#the-files-in-the-project-directory) lists each file that the project directory can hold.

## Step 3. Write project.yaml

Fill in the fields. [project-yaml.md](project-yaml.md) describes each field. For `example`:

```yaml
repo: https://github.com/example/example#v1.2.3
primary_contact: security@example.org
language: c
fuzz_targets: [example_fuzzer]
```

The email addresses in `project.yaml` are public. Use an address that you are glad to publish, such as a security alias.

## Step 4. Write the Dockerfile

The `Dockerfile` gets the source and the dependencies. It is the only step with network access. For `example`, in the project directory:

```dockerfile
ARG BASE_BUILDER=oss-verifier-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/example
COPY build.sh $SRC/
WORKDIR $SRC/example
```

Do not write a commit id in the `Dockerfile`. `tools/check` gives `REPO` and `COMMIT`. [build-contract.md](build-contract.md#what-the-dockerfile-must-do) gives each rule.

## Step 5. Write build.sh

`build.sh` builds the library and links each fuzz target into `$OUT`. It runs once for each build, with no network. For `example`:

```bash
#!/bin/bash -eu
cmake -S . -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build "$WORK/build" -j"$(nproc)"
$CC $CFLAGS -I. -c fuzz/example_fuzzer.c -o "$WORK/example_fuzzer.o"
$CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE "$WORK/build/libexample.a"
```

The builder is a cross-compiler for static riscv64 Linux programs. Thus an OSS-Fuzz `build.sh` does not run without changes: port it. [build-contract.md](build-contract.md) tells what the builder gives and what a build must do.

## Step 6. Choose which patches we send

With each finding, we can send a patch. Tell us which patches you want in `project.yaml`:

* To get findings without patches, set `disable_remediation: true`.
* To choose which patches our agents write, add a `patches` block.

[patches.md](patches.md) tells how to choose. For free text about code style, tests and commit format, write a `patch_style.md`.

## Step 7. Check the project directory

> **WARNING:** `tools/check` builds the project's `Dockerfile` with network access, as `docker build` does. Use it only on a project that you trust ([SECURITY.md](../SECURITY.md)).

1. Run `tools/validate.py projects/<name>`.
2. Correct each problem that it shows.
3. Run `tools/check --twice <name>`.
4. Make sure that it lists each fuzz target that you want us to verify.
5. Make sure that it tells you that the second build has the same bytes.

`tools/check` builds each build, finds the fuzz targets and writes the manifest. With `--twice`, it then builds everything again from the start and compares each byte. Without `--no-shell`, it ends in a shell in the project image, with no network and the binaries in `/out`.

## Step 8. Open the pull request

1. Push your branch to your fork.
2. Open a pull request against `main` of this repository.
3. Complete the checklist of the pull request.

These checks run on the pull request:

* **Validate** runs `tools/validate.py` on your project directory.
* **Build** runs `tools/check` once. It is advisory: a GitHub runner can run out of disk or time on a build that works on a larger machine. It does not run `--twice`, because a runner has too little time. Run `--twice` yourself.
* **Triage** writes a comment with what a reviewer examines by hand. Examples are the repository's licence and activity, whether you seem to maintain it, and whether its security policy gives your `primary_contact`. The comment does not decide.
* **Terms** makes sure that you accepted the [OSS Verifier terms](https://theorem.dev/oss-verifier/terms/).

## After we merge

1. We build the project as `tools/check` does.
2. We pin each binary in the project's lock in the proofs repository.
3. We state theorems about the binaries and work on their proofs.
4. We send each finding to `primary_contact` privately ([disclosure.md](disclosure.md)).
5. We publish the proofs when `publish` tells us to ([publishing.md](publishing.md)).

## Change, pause or leave

Make each change in a pull request:

* To change the enrollment, edit `projects/<name>/`.
* To pause the project, set `disabled: true`.
* To leave, remove `projects/<name>/`.

## Adopt a seeded project

We added some projects ourselves, with `primary_contact: n/a`, on branches named `draft-generic-oss-fuzz-<name>`. To adopt one:

1. Copy its `projects/<name>/` into a branch of your fork.
2. Set `primary_contact` to your project's security contact.
3. Remove the two comment lines that tell that we seeded the project.
4. Do steps 6 to 8 above.

The build files of a draft branch come from the build recipe of oss-fuzz-theorems 2026.10.0-rc.2 (`tools/port.py`). They make that release's binaries again, byte for byte. Keep them, or write your own. If a draft branch has no build files, its commit message tells why. Add a `Dockerfile` and a `build.sh` before you open the pull request.
