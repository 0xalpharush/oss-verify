---
name: add-project
description: Enroll an open-source C or C++ project in OSS Verifier with its maintainer. Use when a maintainer asks to add, enroll or sign up their project for formal verification, to write fuzz targets that say what "correct" means for their library, or to port their OSS-Fuzz build to the OSS Verifier builder. Produces projects/<name>/ (project.yaml, Dockerfile, build.sh, fuzz targets) and a pull request the maintainer opens.
---

# Add a project to OSS Verifier

You are helping a project's maintainer enroll it. The result is one directory, `projects/<name>/`, and a pull request that adds it. Theorem then proves theorems about the binaries those files build (docs/what-gets-proven.md). Everything the maintainer tells you about what "correct" means ends up in the fuzz targets' code and comments: there is no separate document for it.

Read docs/enrollment.md, docs/build-contract.md and docs/exit-codes.md before you start. Work only in `projects/<name>/`.

## 1. Ask what "correct" means

Ask the maintainer, and do not guess:

1. **Untrusted input.** Which functions take input an attacker controls (a parser, a decoder, a protocol handler)? Which are trusted (configuration, the API's own callers)?
2. **Input size.** How large can a real input be? The driver refuses input files of 64 MiB or more.
3. **Intended exits.** Which outcomes are expected and fine: an error code for malformed input, a size limit, a rejected option? Each must become `return 0` in the fuzz target. A statement accepts only exit statuses 0 and 2, so a fuzz target that returns 1, calls `exit()`, or aborts on an expected outcome makes its statement false.
4. **Out of memory.** Must the library survive allocation failure? If so, it needs a separate allocation-failure fuzz target (docs/memory-policy.md). Tell the maintainer that the builder does not provide that target's driver yet, and record the wish in the pull request's context note.
5. **Properties beyond not crashing.** What should always hold? A round trip (`decode(encode(x)) == x`), an invariant of a data structure, agreement between two APIs, a bound on output size.

## 2. Write the fuzz targets

Start from the project's existing fuzz targets: its own and its OSS-Fuzz directory's. A target is a C or C++ file defining `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. Then write the ones the answers above call for, as files in `projects/<name>/` (`*.c`, `*.cc`, `*.cpp`, `*.h`, `*.hh`, `*.hpp`):

- **An API driver** reads the input as a small program: each byte or field picks the next call and its arguments, so that one fuzz target explores sequences of API calls. Keep the decoding total: every input means some sequence, and running out of input ends it.
- **Encode each property as an `assert`** (or an explicit check followed by `abort()`) after the calls, with a comment above it saying, in the maintainer's terms, what it checks and why it must hold. A proof that the fuzz target halts with status 0 or 2 is then a proof of every such property for every input.
- **Turn expected outcomes into `return 0`**, narrowly: check the library's error code or catch the one exception type the API documents. Never a catch-all, never a signal handler, never `_exit`.
- One fuzz target per property group or API area is better than one that does everything: each gets its own statements.
- Anything that needs a different sanitizer configuration is a fuzz target of its own.

Give each file a header saying what it is and under which licence; a file copied from the project's repository keeps the project's licence and says so.

## 3. Port the build

Copy templates/Dockerfile and templates/build.sh into `projects/<name>/` and port the project's build (docs/build-contract.md):

- The `Dockerfile` starts `FROM ${BASE_BUILDER}`, declares `ARG REPO` and `ARG COMMIT`, runs `fetch-commit $SRC/<name>` (with `--submodules` if needed), fetches dependencies at fixed versions, and copies `build.sh` and the fuzz targets' sources into `$SRC`. Never write a commit id into it.
- `build.sh` builds the library statically with `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS` (CMake finds `$CMAKE_TOOLCHAIN_FILE` by itself), compiles each fuzz target, and links it into `$OUT` with `$LIB_FUZZING_ENGINE` through `$CC` or `$CXX`.
- The targets are static riscv64 Linux programs, cross-compiled with clang 20 and musl: no shared libraries, no running what you compiled, no network in `build.sh`, no stripping after the link.
- If a dependency needs a patch to build, keep it build-only, beside `project.yaml`, listed in `series`. A patch that fixes a bug in the project goes to the maintainer, never here.

## 4. Write project.yaml

From templates/project.yaml (docs/project-yaml.md): `repo` with `#<tag or branch>`, `primary_contact` (the security contact; it is public), `language` (`c` or `c++`), `fuzz_targets` (every target you wrote or kept), and anything else the maintainer wants (`auto_ccs`, `pgp`, `patch_style`, `publish`). Ask about `publish`: `after_fixes` (the default), `eager` or `never` (docs/publishing.md).

## 5. Check

Run, and fix everything they report:

    tools/validate.py projects/<name>
    tools/check --no-shell <name>
    tools/check --no-shell --twice <name>

`tools/check` lists the fuzz targets it found in each build: they must be the ones in `fuzz_targets`. It runs the Dockerfile with network access; say so before running it on a project you have not read.

## 6. The pull request

Prepare a branch with only `projects/<name>/` changed and a pull request description from .github/PULL_REQUEST_TEMPLATE.md. Show both to the maintainer and let them open it: opening a pull request is theirs to do, and only they can tick "I am a core maintainer" and "I accept the OSS Verifier terms". In the context note, summarise what each fuzz target checks, in a few lines.

When you finish, the only files you have created are in `projects/<name>/`.
