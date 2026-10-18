# project.yaml

This page describes each field of `projects/<name>/project.yaml` and each file in the project directory. It is for a maintainer, or a coding agent, who writes a project directory.

Start from [templates/project.yaml](../templates/project.yaml). `tools/validate.py` checks each rule on this page. We use the same rules when we import a project.

The field names come from OSS Scanner if it has the field, then from OSS-Fuzz. We made new names only for fields that neither has.

## The fields

| field | required | value | default |
|---|---|---|---|
| `repo` | yes | the git repository, with an optional `#<ref>` | the default branch |
| `primary_contact` | yes | the one email address that gets findings and build problems | |
| `language` | yes | the language of the code that we build ([below](#language)) | |
| `dockerfile` | if no `Dockerfile` is in the project directory | the path of the `Dockerfile` in your repository | |
| `auto_ccs` | no | more email addresses, copied on each report | none |
| `homepage` | no | the project's home page | |
| `pgp` | no | your armored OpenPGP public key | |
| `disabled` | no | `true` pauses the project | `false` |
| `sanitizers` | no | the sanitizer builds in addition to `plain` | `[address, undefined]` |
| `fuzz_targets` | no | the fuzz targets to verify | each fuzz target that the build makes |
| `patch_style` | no | the path of your `patch_style.md` in your repository | |
| `disable_remediation` | no | `true`: send findings without patches | `false` |
| `patches` | no | which patches our agents write ([below](#patches)) | the defaults in [patches.md](patches.md) |
| `budgets` | no | the memory budgets of the statements | today's values |
| `proofs` | no | where we publish the proofs | the proofs repository |
| `publish` | no | when we publish the proofs: `eager`, `after_fixes` or `never` | `after_fixes` |

`tools/validate.py` refuses each field that is not in this table.

### repo

Give exactly one git repository, as an `https://` URL. We clone it anonymously.

After `#`, give one of these:

* A branch or a tag. Each build uses the commit that the branch or tag names at that time.
* A full commit id: 40 hexadecimal digits, or 64 for a SHA-256 repository. Each build then uses exactly that commit.

The lock in the proofs repository records the commit of each build. It is the only place that records it. `tools/validate.py` warns you about a ref that looks like a shortened commit id.

### primary_contact, auto_ccs and pgp

These fields work as they do in OSS Scanner.

* `primary_contact` gets each finding and each build problem.
* `auto_ccs` lists more addresses. Each report goes to them too.
* `pgp` holds your armored OpenPGP public key. We then encrypt each report to this key, and send it to `primary_contact` only. Thus you cannot use `pgp` with `auto_ccs`.

The addresses are public. Use an address that you are glad to publish, such as a security alias.

A seeded project has `primary_contact: n/a` until a maintainer adopts it. `tools/validate.py` warns about it, and the triage comment on a pull request shows it.

### language

Give the language of the code that we build: the library and its fuzz targets.

Today the builder builds these languages:

| `language` | the code |
|---|---|
| `c` | C |
| `c++` | C++, or C and C++ together |

<!-- PENDING: the other languages that the toolchain supports. Add a row for each one here, and nowhere else. -->
**Other languages: pending.** We are making sure which other languages the toolchain supports. This table will list them.

This table is the only list of languages in these documents.

### dockerfile

Use `dockerfile` only if the `Dockerfile` is in your repository. We recommend the path `.oss-verifier/Dockerfile`.

* If the `Dockerfile` and `build.sh` are in the project directory, do not set `dockerfile`. The build context is then the project directory.
* If you set `dockerfile`, the build context is your repository at the commit that we build. Put `build.sh` next to the `Dockerfile`, unless the `Dockerfile` makes `$SRC/build.sh`. Then put your fuzz target sources, build patches and `sources` file in your repository too. Only `project.yaml` and `patch_style.md` can then be in the project directory.

A seeded project can have no build files yet. `tools/validate.py` warns about it, and `tools/check` cannot build it.

### sanitizers

Each build makes a different set of binaries, with its own statements.

| build | we make it when | sanitizer |
|---|---|---|
| `plain` | always | none |
| `ubsan` | `sanitizers` contains `undefined` | UndefinedBehaviorSanitizer |
| `asan` | `sanitizers` contains `address` | AddressSanitizer |
| `asan-ubsan` | `sanitizers` contains both | both |

[build-contract.md](build-contract.md#the-builds) gives the flags of each build.

### fuzz_targets

Give the names of the fuzz targets that `build.sh` puts in `$OUT`. If you do not give this field, we verify each fuzz target that the build makes. A fuzz target is an executable in `$OUT` whose symbol table defines `LLVMFuzzerTestOneInput`. It must be in each build.

The manifest and the lock record the list that a build used. Thus "each fuzz target" cannot change what a proof is about without a record. A build that does not make a fuzz target in this list fails.

### patch_style

Give the path of your `patch_style.md` in your repository. Do not use this field if `patch_style.md` is in the project directory. `patch_style.md` holds free text about how you want patches: code style, tests and commit format ([patches.md](patches.md#patch-style)).

### disable_remediation

Set `disable_remediation: true` to get findings without patches. OSS-Fuzz uses the same name. If you do not give this field, we send a patch with each finding when we have one.

### patches

This block tells our agents which patches to write. Each key is optional. [patches.md](patches.md) tells how to choose.

```yaml
patches:
  findings: fuzz_failures       # or all
  out_of_scope: harness         # or library
  allocation_failure: harness   # or library
  documentation: false          # or true
  refactoring: none             # or equivalent, or minor
  equivalence_proof: required   # or not_required
```

The values in this example are the defaults. `tools/validate.py` refuses an unknown key or value. It warns you if you give `patches` with `disable_remediation: true`.

### budgets

The memory budgets of the statements ([what-gets-proven.md](what-gets-proven.md#memory-budgets)). These are the defaults:

```yaml
budgets:
  halts: 16GiB               # each build that runs alone
  agrees:                    # for each sanitizer: [plain side, sanitizer side]
    address: [2GiB, 512GiB]  # also for asan-ubsan
    undefined: [16GiB, 512GiB]
```

Give a size as a positive number of bytes, or as a number followed by `KiB`, `MiB`, `GiB` or `TiB`. Give a budget under `agrees` only for a sanitizer that the project uses. Give only the values that you want to change.

### proofs

Give the place where we publish the proofs: `repo`, an `https://` URL with `#<branch>`, and `path`, a directory in that repository. Most projects do not use this field. [publishing.md](publishing.md) gives the default.

### publish

Tell us when to publish the proofs ([publishing.md](publishing.md)).

## The files in the project directory

| file | when |
|---|---|
| `Dockerfile` | if `dockerfile` is not set |
| `build.sh` | with a `Dockerfile` in the project directory |
| `patch_style.md` | optional, if `patch_style` is not set |
| `*.c` `*.cc` `*.cpp` `*.h` `*.hh` `*.hpp` | optional: your own fuzz targets and their helpers |
| `*.patch` and `series` | optional: build patches |
| `sources` | optional: other source trees and files of the build, each pinned by commit or SHA-256 ([build-contract.md](build-contract.md#builds-ported-from-oss-fuzz-theorems)) |
| a file that `sources` copies | optional: a file that the build needs, under any name |

`series` lists the build patches, one file name on each line, in the order in which we apply them. We ignore empty lines and lines that start with `#`. List each patch exactly once.

A build patch can only change how the project builds. For example, it can make the build static, set up cross-compilation, correct a version stamp or make a generated file. A change that fixes a bug is not a build patch. It never goes in the project directory ([patches.md](patches.md)).

Each file must obey these rules:

* It is a regular file. Symbolic links and subdirectories are not permitted.
* Its name uses only `A-Z a-z 0-9 . _ -` and starts with a letter or digit.
* It is UTF-8 text.
* Its size is at most 128 KiB for `project.yaml`.
* Its size is at most 256 KiB for `build.sh`, a fuzz target source or a build patch.
* Its size is at most 64 KiB for each other file.

The project directory holds at most 64 files. Its name uses only `a-z 0-9 . _ -`, starts with a letter or digit, and has at most 63 characters.
