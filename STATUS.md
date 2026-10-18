# Status

This repository is being prepared and is not open for enrollment yet. This page says what works today, how it was checked, and what does not work yet.

## Works, and how it was checked

* **`tools/validate.py`** and the rules in [docs/project-yaml.md](docs/project-yaml.md): `python3 -m unittest discover -s tools/tests`.
* **The builder and `tools/check`**, on the cjson pilot: `tools/check --twice --lock <harness.yaml> cjson`, with oss-fuzz-theorems 2026.10.0-rc.2's `projects/cjson/cjson_read_fuzzer/harness.yaml`, builds all four binaries byte for byte as that release pins them, and a second build from scratch is identical:

  | build | bytes | sha256 |
  |---|---:|---|
  | plain | 72,792 | `b40ed189a37beb50da46f04a457ec144b05319a845fa3b0639d7a117ffd1696d` |
  | ubsan | 73,120 | `73d8f136684412bc2827dd90598b3b66fa023b78537ce674aa5007e9be78cbd0` |
  | asan | 606,648 | `09e0835df41a2bab7c8e4af1e6b990748fde19337e65f5b2993ae8be5e9d3a5f` |
  | asan-ubsan | 604,408 | `57f377d242bdd8fa074ec06428b9785e4d6357af953724e1c9a0533f271847d8` |

  The same holds for the md4c and wasm3 drafts (below), each against its `harness.yaml` in that release.
* **The driver's exit statuses** ([docs/exit-codes.md](docs/exit-codes.md)): `OV_DOCKER_TESTS=1 python3 -m unittest tools/tests/test_builder.py` builds a C and a C++ fuzz target with the templates' commands and runs all four builds of each under qemu-riscv64.
* **The workflows** in `.github/`: actionlint finds nothing, and the step that takes `projects/<name>/` from a pull request has been run against a local repository with good and bad pull requests.

## Not yet, or not checked

* **The toolchain image** that the builder is built `FROM` (`ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@sha256:6a6b4816…`) is not public yet. Until it is, `tools/check` and the Build workflow work only on a machine that already has it.
* **The builder image is not published.** `tools/check` builds it from `infra/base-builder/` and passes it to each Dockerfile as `BASE_BUILDER`; the Dockerfiles' default, `oss-verifier-base-builder`, is that local name. Once it is pushed, that default should be its digest.
* **The workflows have not run on GitHub**: they are linted, not exercised there.
* **Build systems:** the builder has been checked with CMake builds only (cjson, md4c, wasm3 and the test fixture). It writes no Meson cross file yet, and no autotools build has been ported yet.
* **C++:** a C++ fuzz target builds and runs (the test fixture), but no C++ project's binaries have been compared with oss-fuzz-theorems' yet.
* **Allocation-failure fuzz targets:** the builder has no driver for them yet ([docs/memory-policy.md](docs/memory-policy.md)).
* **The proofs repository** (oss-verifier-proofs) does not exist yet. The lock is to be written from `tools/check`'s manifest, and the triage comment's "Proofs index" row assumes the index layout of oss-fuzz-theorems.
* **Placeholders** to replace before this repository opens: the [terms](https://theorem.dev/oss-verifier/terms/) URL, the CODEOWNERS team `@theorem-labs/oss-verifier-maintainers`, and the contact in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Seeded projects

`tools/seed.py` writes a `project.yaml` from oss-fuzz-theorems 2026.10.0-rc.2's metadata, only where that metadata says everything needed. A seeded project says `primary_contact: n/a` until its maintainers adopt it ([CONTRIBUTING.md](CONTRIBUTING.md)). Its `Dockerfile` and `build.sh` are added only once `tools/check` has built them.

### On main: a provisional set

Provisional: the launch set is not decided. These are cjson, the pilot, and nine candidates for that set that `tools/seed.py` can seed.

| project | fuzz targets | build files |
|---|---|---|
| cjson | cjson_read_fuzzer | yes: reproduces the release's binaries |
| boost-beast | http_request | not yet; the repository is Boost's, with submodules, and the release built a modified copy of this harness that is not published yet |
| dovecot | fuzz-message-parser | not yet |
| h2o | h2o-fuzzer-url | not yet |
| hunspell | parserfuzzer | not yet |
| libtorrent | bdecode_node | not yet |
| myanmar-tools | zawgyi_detector_fuzz_target | not yet |
| opencensus-cpp | b3_fuzzer, cloud_trace_context_fuzzer, grpc_tags_bin_fuzzer, grpc_trace_bin_fuzzer, trace_context_fuzzer | not yet |
| powerdns | fuzz_target_dnslabeltext_parseRFC1035CharString | not yet |
| tink-cc | tink_encrypt_fuzzer (from OSS-Fuzz's repository) | not yet |

Candidates not on main yet:

* **boost-json**: which of its fuzz targets to verify first is not decided.
* **resiprocate** and **simdutf**: the release's build patches the library's own source (`rutil/Log.cxx`; `include/simdutf/internal/isadetection.h`), so its binaries are not of the library as upstream wrote it.

Fuzz targets we wrote ourselves for some of these libraries are left out until their sources are published.

### Draft branches

Each is `main` plus one seeded project, regenerated with `tools/seed.py --branch` when `main` changes.

| branch | build files | checked |
|---|---|---|
| `draft-generic-oss-fuzz-md4c` | yes | `tools/check --twice --lock`: the release's four binaries, byte for byte |
| `draft-generic-oss-fuzz-wasm3` | yes | the same |
| `draft-generic-oss-fuzz-inih` | not yet | a Meson build: the builder writes no Meson cross file yet |
| `draft-generic-oss-fuzz-hwloc` | not yet | an autotools build, not ported yet |

### Everything else

[docs/seeded-projects.tsv](docs/seeded-projects.tsv) says, for each of the release's 1,381 projects, whether it can be seeded and why not. 312 can. Of the rest, 1,040 were not built by the release (781 in a language other than C or C++, 120 too large, 78 not built yet, 32 with no harness, 17 held, 6 excluded, 3 needing model support, 3 with no compiler), 25 have no harness whose build leaves the library's own source alone, and 4 have no full commit recorded.

## Not decided yet

* The launch set on main.
* Whether the `asan` and `asan-ubsan` builds should have a smaller `halts` budget ([docs/memory-policy.md](docs/memory-policy.md)).
