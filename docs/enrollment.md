# Enrollment, start to finish

## Who can enroll

A project's core maintainers. One project per pull request, and the pull request changes nothing outside `projects/<name>/`. We confirm, before merging, that whoever opened it maintains the project and that `primary_contact` is its security contact.

## 1. Decide what "correct" means

A proof covers what the fuzz targets check ([what-gets-proven.md](what-gets-proven.md)). Before writing anything, settle:

* which inputs are untrusted, and how large they can be;
* which outcomes are expected, and must therefore end as `return 0` rather than a crash, an `exit()` or another return value ([exit-codes.md](exit-codes.md));
* whether the library must survive running out of memory (then it needs an allocation-failure fuzz target of its own; [memory-policy.md](memory-policy.md));
* which properties beyond "does not crash" a fuzz target can assert, such as a round trip.

Existing fuzz targets, the project's own or OSS-Fuzz's, are usually the place to start. Fuzz targets you write for this go in `projects/<name>/`.

A coding agent can do steps 1 to 5 with you: point it at [AGENTS.md](../AGENTS.md), which leads to the skill in [.claude/skills/add-project/](../.claude/skills/add-project/SKILL.md).

## 2. Add projects/<name>/

Fork this repository and add a directory named after the project (`a-z 0-9 . _ -`):

* `project.yaml`, from [templates/project.yaml](../templates/project.yaml) ([project-yaml.md](project-yaml.md) describes every field);
* a `Dockerfile` and a `build.sh`, from [templates/](../templates/), here or in your repository at the path `dockerfile:` names;
* optionally a `patch_style.md`, from [templates/patch_style.md](../templates/patch_style.md);
* optionally harness sources, and build-only patches with their `series`.

## 3. Port the build

The builder cross-compiles static riscv64 Linux programs with clang 20, musl and lld ([build-contract.md](build-contract.md)). Starting from the project's OSS-Fuzz `build.sh`, if it has one: build the library statically with `$CC` and `$CFLAGS`, compile each fuzz target, and link it into `$OUT` with `$LIB_FUZZING_ENGINE`. Dependencies are fetched in the `Dockerfile`, which is the only step with network access.

## 4. Check it

    tools/validate.py                  # the rules for projects/<name>/
    tools/check --no-shell <name>      # builds every build, lists the fuzz targets, writes the manifest
    tools/check --twice <name>         # builds it all again from scratch and compares every byte

They need git, Docker, and Python 3 with PyYAML. `tools/check` runs your Dockerfile with network access, as `docker build` would. Without `--no-shell` it ends in a shell in the project image, with no network and the binaries at `/out`.

## 5. Open the pull request

Fill in the checklist in the pull request template. Four checks run on it:

* **Validate** runs `tools/validate.py` on your `projects/<name>/`.
* **Build** runs `tools/check` on it. It is advisory: GitHub's machines can run out of disk or time on a build that works elsewhere.
* **Triage** comments with what a reviewer would look up by hand: the repository's standing, licence and activity, whether you appear to maintain it, whether its security policy names your `primary_contact`, and whether `projects/<name>/` follows the rules. It informs the review and decides nothing.
* **Terms** checks that you ticked the box accepting the [OSS Verifier terms](https://theorem.dev/oss-verifier/terms/).

## 6. After the merge

We build the project as `tools/check` does, pin each binary in the project's lock in the proofs repository, state theorems about the binaries and work on their proofs. A finding goes privately to `primary_contact` ([disclosure.md](disclosure.md)). The proofs are published when `publish` says ([publishing.md](publishing.md)).

## Changing, pausing, leaving

Edit `projects/<name>/` in a pull request to change anything. Set `disabled: true` to pause the project, or remove `projects/<name>/` to withdraw it.

## Adopting a project we seeded

We seed some projects ourselves from oss-fuzz-theorems, with `primary_contact: n/a`: on `main` as a provisional set, and on branches named `draft-generic-oss-fuzz-<name>`, one project each. To adopt one, copy its `projects/<name>/` into a pull request against `main`, set `primary_contact`, remove the two comment lines that say it was seeded, and fill in the checklist as for any enrollment. A seeded project without a `Dockerfile` and `build.sh` needs them added and checked first ([STATUS.md](../STATUS.md)).
