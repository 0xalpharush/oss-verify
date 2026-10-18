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
* **Builds ported from oss-fuzz-theorems 2026.10.0-rc.2** ([docs/build-contract.md](docs/build-contract.md#builds-ported-from-oss-fuzz-theorems)): `tools/verify_ports.py` ported the build of each of the 312 projects `tools/seed.py` can seed, and checked it with `tools/check --no-shell --lock` against the release's `harness.yaml` for every fuzz target in its `project.yaml`. **303 reproduce** the release's binaries: every binary of all four builds, 2,800 in all, byte for byte. Of the other 9, varnish fails: its git server serves only git's "dumb" HTTP protocol, from which fetching the commit fails. numactl is not ported: its build-only patch, autoreconf's output, is 1.2 MB, and a patch may be at most 256 KiB. 7 have not been checked yet (below). [tools/seeds/builds.tsv](tools/seeds/builds.tsv) has the result for each project, and [docs/seeded-projects.tsv](docs/seeded-projects.tsv) repeats it. The builds that reproduce are C and C++ builds with CMake (164 projects), autotools (73), Meson (24), Makefiles, header-only libraries (22), and the release's direct compiles of a library's sources (34). `tools/check --twice` built h2o, hunspell, myanmar-tools, boost-beast and tink-cc from scratch a second time: identical.
* **The driver's exit statuses** ([docs/exit-codes.md](docs/exit-codes.md)): `OV_DOCKER_TESTS=1 python3 -m unittest tools/tests/test_builder.py` builds a C and a C++ fuzz target with the templates' commands and runs all four builds of each under qemu-riscv64.
* **Allocation-failure fuzz targets** ([docs/exit-codes.md](docs/exit-codes.md#allocation-failure)): the same test builds the allocation-failure variants of its two fuzz targets and checks the allocation mask, counting mode and `std::bad_alloc` in all four builds. cjson's `build.sh` builds one, `cjson_read_fuzzer_allocation_failure`, beside `cjson_read_fuzzer`, whose four binaries still match the release's. On an input whose run makes 21 allocations, counting mode reports 21 in every build, and failing any one of them, or all, still exits with 0.
* **The workflows** in `.github/`: actionlint finds nothing, and the step that takes `projects/<name>/` from a pull request has been run against a local repository with good and bad pull requests.

## Not yet, or not checked

* **The toolchain image** that the builder is built `FROM` (`ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@sha256:6a6b4816…`) is not public yet. Until it is, `tools/check` and the Build workflow work only on a machine that already has it.
* **The builder image is not published.** `tools/check` builds it from `infra/base-builder/` and passes it to each Dockerfile as `BASE_BUILDER`; the Dockerfiles' default, `oss-verifier-base-builder`, is that local name. Once it is pushed, that default should be its digest.
* **The workflows have not run on GitHub**: they are linted, not exercised there.
* **Hand-written build files:** a `build.sh` written for this builder by hand has been tried with CMake builds only (cjson, md4c, wasm3 and the test fixture). The ported builds use the release's recipes for the other build systems; the builder offers no Meson cross file or autotools settings of its own to a hand-written `build.sh` yet.
* **Ported builds not checked yet:** arrow, libarchive, open62541, openssh, openssl, skia and wget2; their checks are still running.
* **Allocation-failure fuzz targets** have no statement yet: cjson's is built, but it is not in cjson's `fuzz_targets`, so it is not verified.
* **The proofs repository** (oss-verifier-proofs) does not exist yet. The lock is to be written from `tools/check`'s manifest, and the triage comment's "Proofs index" row assumes the index layout of oss-fuzz-theorems.
* **Placeholders** to replace before this repository opens: the [terms](https://theorem.dev/oss-verifier/terms/) URL, the CODEOWNERS team `@theorem-labs/oss-verifier-maintainers`, and the contact in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Seeded projects

`tools/seed.py` writes a `project.yaml` from oss-fuzz-theorems 2026.10.0-rc.2's metadata, only where that metadata says everything needed. A seeded project says `primary_contact: n/a` until its maintainers adopt it ([CONTRIBUTING.md](CONTRIBUTING.md)). Its `Dockerfile` and `build.sh` are added only once `tools/check` has built them and they reproduce the release's binaries.

### On main: a provisional set

Provisional: the launch set is not decided. These are cjson, the pilot, and nine candidates for that set that `tools/seed.py` can seed. Every one has build files that reproduce the release's binaries: cjson's written by hand, the others ported from the release's recipe.

| project | fuzz targets | binaries checked |
|---|---|---:|
| cjson | cjson_read_fuzzer | 4 |
| boost-beast | http_request | 4 |
| dovecot | fuzz-message-parser | 4 |
| h2o | h2o-fuzzer-url | 4 |
| hunspell | parserfuzzer | 4 |
| libtorrent | bdecode_node | 4 |
| myanmar-tools | zawgyi_detector_fuzz_target | 4 |
| opencensus-cpp | b3_fuzzer, cloud_trace_context_fuzzer, grpc_tags_bin_fuzzer, grpc_trace_bin_fuzzer, trace_context_fuzzer | 20 |
| powerdns | fuzz_target_dnslabeltext_parseRFC1035CharString | 4 |
| tink-cc | tink_encrypt_fuzzer (from OSS-Fuzz's repository) | 4 |

Candidates not on main yet:

* **boost-json**: which of its fuzz targets to verify first is not decided.
* **resiprocate** and **simdutf**: the release's build patches the library's own source (`rutil/Log.cxx`; `include/simdutf/internal/isadetection.h`), so its binaries are not of the library as upstream wrote it.

Fuzz targets we wrote ourselves for some of these libraries are left out until their sources are published.

### Draft branches

One for each of the other 302 projects `tools/seed.py` can seed: `draft-generic-oss-fuzz-<name>` is `main` plus that project, regenerated with `tools/seed.py --branch` when `main` changes. 293 have build files that reproduce the release's binaries (md4c's and wasm3's written by hand, the others ported), kept on `main` in `tools/seeds/<name>/`. 9 have only a `project.yaml`, and the commit message says why: varnish's port fails and numactl's cannot be made yet (above), and 7 are not checked yet.

### Everything else

[docs/seeded-projects.tsv](docs/seeded-projects.tsv) says, for each of the release's 1,381 projects, whether it can be seeded and why not, and for each one that can, how its ported build fared. 312 can. Of the rest, 1,040 were not built by the release (781 in a language other than C or C++, 120 too large, 78 not built yet, 32 with no harness, 17 held, 6 excluded, 3 needing model support, 3 with no compiler), 25 have no harness whose build leaves the library's own source alone, and 4 have no full commit recorded.

## Not decided yet

* The launch set on main.
* Whether the `asan` and `asan-ubsan` builds should have a smaller `halts` budget ([docs/memory-policy.md](docs/memory-policy.md)).
* How a statement about an allocation-failure fuzz target treats the driver's counting mode, in which such a target exits with the number of allocations it counted ([docs/exit-codes.md](docs/exit-codes.md#allocation-failure)).
