# project.yaml

`projects/<name>/project.yaml` says who maintains a project, where its source is, and what to build. Start from [templates/project.yaml](../templates/project.yaml). `tools/validate.py` checks every rule on this page, and we apply the same rules when we import a project.

The field names are OSS Scanner's where it has the field, then OSS-Fuzz's, and ours only for what neither has.

| field | required | meaning | default |
|---|---|---|---|
| `repo` | yes | One git repository, as an `https://` URL. Add `#<ref>`: a branch or tag to follow, or a full commit id to verify exactly that commit. | the default branch |
| `primary_contact` | yes | The one address findings and build problems go to. It is public. | |
| `language` | yes | `c` or `c++`: the language of the code we build. | |
| `dockerfile` | unless a `Dockerfile` is beside `project.yaml` | The Dockerfile's path in your repository. A project we seeded may have no build files yet. | |
| `auto_ccs` | no | Addresses we copy on every report. Not with `pgp`. | none |
| `homepage` | no | The project's home page. | |
| `pgp` | no | Your armored OpenPGP public key. Reports are then encrypted to it and go to `primary_contact` only. | |
| `disabled` | no | `true` pauses the project without removing it. | `false` |
| `sanitizers` | no | The sanitizer builds besides the plain one: a subset of `[address, undefined]`. | `[address, undefined]` |
| `fuzz_targets` | no | The fuzz targets to verify. | every fuzz target the build produces |
| `patch_style` | no | The path of your `patch_style.md` in your repository, if it is not beside `project.yaml`. | |
| `budgets` | no | Memory budgets ([memory-policy.md](memory-policy.md)). | today's values |
| `proofs` | no | Where the proofs are published: `repo` and `path` ([publishing.md](publishing.md)). | `repo: https://github.com/theorem-labs/oss-verifier-proofs#<name>`, `path: projects/<name>` |
| `publish` | no | When the proofs are published: `eager`, `after_fixes` or `never` ([publishing.md](publishing.md)). | `after_fixes` |

No other field is allowed. Some settings are the operators' to make, never a pull request's; there are none yet, and `tools/validate.py` will refuse any that are added later.

## The fields

**`repo`.** Exactly one repository, cloned anonymously over https. A branch or tag after `#` is what updates follow: each build resolves it to the commit it names at that moment. A full commit id (40 or, for a SHA-256 repository, 64 hex digits) means "verify exactly this commit". The commit a build used is recorded with its binaries in the lock in the proofs repository, which is the only place it is kept. `tools/validate.py` warns about a ref that looks like a shortened commit id.

**`primary_contact`, `auto_ccs`, `pgp`.** As in OSS Scanner. Use a security alias you are happy to see published. A project we seeded ourselves says `primary_contact: n/a` until a maintainer adopts it; `tools/validate.py` warns about it, and the triage comment on a pull request flags it.

**`language`.** `c` or `c++`, the language of the library and its fuzz targets as we build them.

**`dockerfile`.** Leave it out when the `Dockerfile` and `build.sh` sit beside `project.yaml`: the build context is then `projects/<name>/`, and the Dockerfile fetches your source. Set it when they live in your repository (we suggest `.oss-verifier/Dockerfile`): the build context is then your repository at the commit being built, and `build.sh` is expected beside the Dockerfile, unless the Dockerfile creates `$SRC/build.sh` itself. In that case harness sources and patches belong in your repository too, and nothing but `project.yaml` and `patch_style.md` may sit here.

A project we seeded ourselves (`primary_contact: n/a`) may have no build files yet: we add a `Dockerfile` and a `build.sh` only once they have been checked to build. `tools/validate.py` warns about such a project, and `tools/check` cannot build it. [STATUS.md](../STATUS.md) lists them.

**`sanitizers`.** Each build is a separate set of binaries with its own statements:

| build | made when | sanitizer flags |
|---|---|---|
| `plain` | always | none |
| `ubsan` | `undefined` is listed | `-fsanitize=undefined`, trapping |
| `asan` | `address` is listed | `-fsanitize=address`, with the sealed static runtime |
| `asan-ubsan` | both are listed | both |

[build-contract.md](build-contract.md) gives the flags in full.

**`fuzz_targets`.** The names of fuzz targets as `build.sh` writes them into `$OUT`. Left out, it means every fuzz target the build produces: an executable in `$OUT` whose symbol table defines `LLVMFuzzerTestOneInput`, present in every build. Either way the list a build resolved to is written into its manifest and the lock, so "every fuzz target" never silently changes what a proof covers. A target named here that a build does not produce fails the build.

**`patch_style`.** Where your `patch_style.md` is in your repository. Like `dockerfile`, it is one place or the other: in your repository, or beside `project.yaml`.

**`budgets`.** The memory budgets the statements use ([memory-policy.md](memory-policy.md)). The default, today's values, is:

```yaml
budgets:
  halts: 16GiB               # each build run alone
  agrees:                    # per sanitizer: [plain side, sanitizer side]
    address: [2GiB, 512GiB]  # also used for asan-ubsan
    undefined: [16GiB, 512GiB]
```

A size is a positive number of bytes, or a number followed by `KiB`, `MiB`, `GiB` or `TiB`. A budget under `agrees` must be for one of the project's sanitizers. Set only what you want to change.

**`proofs`.** Where the proofs about the project are pushed: `repo`, an https URL with `#<branch>`, and `path`, a directory in that repository. Most projects leave it out.

**`publish`.** When the proofs are pushed to `proofs.repo` ([publishing.md](publishing.md)).

## Files beside project.yaml

| file | when |
|---|---|
| `Dockerfile` | unless `dockerfile:` is set |
| `build.sh` | with a `Dockerfile` beside `project.yaml` |
| `patch_style.md` | optional, unless `patch_style:` is set |
| `*.c` `*.cc` `*.cpp` `*.h` `*.hh` `*.hpp` | optional: harness sources of your own, such as a fuzz target that checks a property |
| `*.patch` and `series` | optional: patches that change only how the project builds |

`series` lists the patches, one file name per line, in the order they are applied; blank lines and lines starting with `#` are ignored. Every patch must be listed exactly once. A patch here may make the build static, cross-compile, fix a version stamp or generate a file; a patch that fixes a bug never goes here.

Every file must be a regular file (no symbolic links, no subdirectories) with a plain name (`A-Z a-z 0-9 . _ -`, starting with a letter or digit), UTF-8 text, and at most 128 KiB for `project.yaml`, 256 KiB for a harness source or a patch, and 64 KiB for anything else. A project's directory holds at most 64 files. Its name is `a-z 0-9 . _ -`, starting with a letter or digit, at most 63 characters.
