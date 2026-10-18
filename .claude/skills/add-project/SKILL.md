---
name: add-project
description: Enroll an open-source project in OSS Verifier with its maintainer. Use when a maintainer asks to add, enroll or sign up a project for formal verification. Also use it to write fuzz targets that say what "correct" means for a library, or to choose which patches OSS Verifier sends. Also use it to port an OSS-Fuzz build to the OSS Verifier builder. Makes projects/<name>/ (project.yaml, Dockerfile, build.sh, fuzz targets) and a pull request that the maintainer opens.
---

# Enroll a project in OSS Verifier

This skill is for a coding agent that helps a maintainer enroll a project. It gives the steps, the questions to ask and the checks to run.

The result is one directory, `projects/<name>/`, and a pull request that the maintainer opens. Theorem then proves theorems about the binaries that these files build. Each answer about what "correct" means goes into the code and comments of the fuzz targets. No separate document holds it.

Before you start, read these documents: `docs/enrollment.md`, `docs/project-yaml.md`, `docs/build-contract.md`, `docs/exit-codes.md` and `docs/patches.md`. Work only in `projects/<name>/`.

## 1. Ask what "correct" means

Ask the maintainer each question. Do not guess an answer.

1. **Untrusted input.** Which functions get input that an attacker controls, for example a parser, a decoder or a protocol handler? Which inputs are trusted, for example the configuration?
2. **Input size.** How large can a real input be? The driver refuses an input file of 64 MiB or more.
3. **Expected outcomes.** Which outcomes are expected, for example an error code for malformed input, a size limit or a refused option? Each one must end as `return 0`. A statement accepts only the exit statuses 0 and 2.
4. **Refused allocations.** Must the library survive a refused allocation? If yes, add an allocation-failure fuzz target (`docs/exit-codes.md`, "Allocation failure").
5. **Properties.** Which properties must always be true, apart from "no crash"? Examples are a round trip (`decode(encode(x)) == x`), an invariant of a data structure, agreement between two APIs, and a limit on the size of an output.

## 2. Ask which patches to send

Ask each question. Write each answer into `project.yaml` (`docs/patches.md`). Leave out a key if the maintainer accepts its default.

1. Do you want findings without patches? If yes, set `disable_remediation: true`. Then skip the other questions in this step.
2. `findings`: patches only for failures that a fuzz target can cause (`fuzz_failures`), or also for bugs that we find while we prove (`all`)?
3. `out_of_scope`: a fuzz target gets to behaviour that you do not support. Make the fuzz target narrower (`harness`), or change the library (`library`)?
4. `allocation_failure`: the same choice for a refused allocation (`harness` or `library`).
5. `documentation`: also patches that change only the documentation (`true` or `false`)?
6. `refactoring`: changes that make the code easier to verify. None (`none`), only changes that keep the behaviour (`equivalent`), or also changes to behaviour that looks like a bug (`minor`)?
7. `equivalence_proof`: send a refactoring patch only with a proof that the behaviour does not change (`required`), or also without one (`not_required`)?
8. Does the project have a contribution policy, for example about AI-generated patches? Our agents obey it. Record a link to it in `patch_style.md`.
9. Which code style, tests and commit format must a patch have? Write the answer in `patch_style.md`, as free text.

Do not repeat in `patch_style.md` a choice that a field in `project.yaml` gives.

## 3. Write the fuzz targets

Start from the project's existing fuzz targets: its own, and those in its OSS-Fuzz directory. A fuzz target defines `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. Then write the fuzz targets that the answers to step 1 need. Put each one in `projects/<name>/` (`*.c`, `*.cc`, `*.cpp`, `*.h`, `*.hh`, `*.hpp`).

- **API driver.** Read the input as a small program. Let each byte or field select the next call and its arguments. Thus one fuzz target explores sequences of API calls. Make the decoding total: each input means a sequence, and the end of the input ends the sequence.
- **Properties.** Write each property as an `assert`, or as a check followed by `abort()`, after the calls. Above it, write a comment that tells, in the maintainer's words, what it checks and why it must be true. A proof that the fuzz target halts with status 0 or 2 is then a proof of each property, for each input.
- **Expected outcomes.** Change each expected outcome into `return 0`, narrowly. Examine the library's error code, or catch the one exception type that the API documents.
- **One area for each fuzz target.** Write one fuzz target for each group of properties or each API area. Each fuzz target gets its own statements.
- **Sanitizer configuration.** Put code that needs a different sanitizer configuration in a separate fuzz target.

> **WARNING:** Do not catch all exceptions, install a signal handler or call `_exit`. Such code hides the failures that the statements must show.

Give each file a header that tells what it is and its licence. A file copied from the project's repository keeps the project's licence and tells so.

## 4. Port the build

Copy `templates/Dockerfile` and `templates/build.sh` into `projects/<name>/`. Port the project's build (`docs/build-contract.md`).

- In the `Dockerfile`, start with `FROM ${BASE_BUILDER}`.
- Declare `ARG REPO` and `ARG COMMIT`.
- Run `fetch-commit $SRC/<name>`. Add `--submodules` if the repository has submodules.
- In the `Dockerfile`, get each dependency at a fixed version. Copy `build.sh` and the fuzz target sources into `$SRC`.
- Never write a commit id in the `Dockerfile`.
- In `build.sh`, build the library statically with `$CC`, `$CXX`, `$CFLAGS` and `$CXXFLAGS`. CMake finds `$CMAKE_TOOLCHAIN_FILE` without help.
- In `build.sh`, compile each fuzz target. Link it into `$OUT` with `$LIB_FUZZING_ENGINE`, through `$CC` or `$CXX`.
- Make static riscv64 Linux programs. Do not use shared libraries, run a compiled program, use the network in `build.sh`, or strip a binary after the link.

If a dependency needs a patch to build, make it a build patch in `projects/<name>/`. List it in `series`. A change that fixes a bug in the project is not a build patch. It never goes in the project directory.

## 5. Write project.yaml

Start from `templates/project.yaml` (`docs/project-yaml.md`). Fill in these fields:

- `repo`, with `#<tag or branch>`;
- `primary_contact`, the security contact, which is public;
- `language`, from the list in `docs/project-yaml.md`;
- `fuzz_targets`, each fuzz target that you wrote or kept;
- the answers to step 2: `disable_remediation` and `patches`;
- each other field that the maintainer wants, for example `auto_ccs`, `pgp`, `patch_style` and `publish`.

Ask about `publish`: `after_fixes` (the default), `eager` or `never` (`docs/publishing.md`).

## 6. Check

> **WARNING:** `tools/check` builds the `Dockerfile` with network access. Read the `Dockerfile` before you run `tools/check`.

1. Run `tools/validate.py projects/<name>`. Correct each problem.
2. Run `tools/check --no-shell --twice <name>`. Correct each problem.
3. Make sure that the fuzz targets that `tools/check` finds in each build are those in `fuzz_targets`.
4. Make sure that `tools/check` tells you that the second build has the same bytes.

## 7. Prepare the pull request

1. Make a branch that changes only `projects/<name>/`.
2. Write the pull request description from `.github/PULL_REQUEST_TEMPLATE.md`.
3. In the context note, give a summary of what each fuzz target checks, in a few lines.
4. Show the branch and the description to the maintainer.
5. Let the maintainer open the pull request. Only the maintainer can confirm "I am a core maintainer" and "I accept the OSS Verifier terms".

When you finish, each file that you made is in `projects/<name>/`.
