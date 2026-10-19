# Status (internal engineering status)

**Internal.** This page is the engineering status of the repository, for the people who build it. It is not documentation for maintainers. It moves out of the repository before the repository becomes public.

The repository is not open for enrollment yet. This page tells what works today, how we checked it, and what does not work yet.

## Works, and how it was checked

* **`tools/validate.py`** and the rules in [docs/project-yaml.md](docs/project-yaml.md): `python3 -m unittest discover -s tools/tests`.
* **The builder and `tools/check`**, on the cjson pilot: `tools/check --twice --lock <harness.yaml> cjson`, with the oss-fuzz-theorems 2026.10 release's `projects/cjson/cjson_read_fuzzer/harness.yaml`, builds all four binaries byte for byte as that release pins them, and a second build from scratch is identical:

  | build | bytes | sha256 |
  |---|---:|---|
  | plain | 72,792 | `b40ed189a37beb50da46f04a457ec144b05319a845fa3b0639d7a117ffd1696d` |
  | ubsan | 73,120 | `73d8f136684412bc2827dd90598b3b66fa023b78537ce674aa5007e9be78cbd0` |
  | asan | 606,648 | `09e0835df41a2bab7c8e4af1e6b990748fde19337e65f5b2993ae8be5e9d3a5f` |
  | asan-ubsan | 604,408 | `57f377d242bdd8fa074ec06428b9785e4d6357af953724e1c9a0533f271847d8` |

  The same holds for the md4c and wasm3 drafts (below), each against its `harness.yaml` in that release.
* **Builds ported from the oss-fuzz-theorems 2026.10 release** ([docs/build-contract.md](docs/build-contract.md#builds-ported-from-oss-fuzz-theorems)): `tools/verify_ports.py` ported the build of each of the 312 projects `tools/seed.py` can seed, and checked it with `tools/check --no-shell --lock` against the release's `harness.yaml` for every fuzz target in its `project.yaml`. **311 reproduce** the release's binaries: every binary of all four builds, 3,156 in all, byte for byte. numactl's among them runs autoreconf in its `build.sh` in place of the release's 1.2 MB patch of autoreconf's output, which a project directory cannot hold; in the toolchain image autoreconf writes exactly what the patch does. The one that does not, varnish, fails: its git server, code.vinyl-cache.org, serves only git's "dumb" HTTP protocol and fails to serve some of the objects of varnish's repository and of its VTest2 dependency, so neither commit can be fetched. GitHub's varnishcache/varnish-cache has varnish's commit, but no mirror of VTest2 has its. Most were checked with earlier versions of the builder. Its changes since (the allocation-failure engines, fetching by a full clone from a server that will not serve one commit, the release's path for a ported build's compiler, which only openssl records, and a toolchain chosen by the lock, the release's for every port) do not change what those projects compile and link; openssl, numactl and dnsmasq were checked again after the ones that concern them, and cjson, md4c and wasm3 after every one. [tools/seeds/builds.tsv](tools/seeds/builds.tsv) has the result for each project, and [docs/seeded-projects.tsv](docs/seeded-projects.tsv) repeats it. The builds that reproduce are C and C++ builds with CMake (167 projects), autotools (76), Meson (24), Makefiles, header-only libraries (22), and the release's direct compiles of a library's sources (37). `tools/check --twice` built h2o, hunspell, myanmar-tools, boost-beast and tink-cc from scratch a second time: identical.
* **The driver's exit statuses** ([docs/build-contract.md](docs/build-contract.md#the-driver)): `OV_DOCKER_TESTS=1 python3 -m unittest tools/tests/test_builder.py` builds a C and a C++ fuzz target with the templates' commands and runs all four builds of each under qemu-riscv64.
* **Allocation-failure fuzz targets** ([docs/build-contract.md](docs/build-contract.md#allocation-failure-fuzz-targets)): the same test builds the allocation-failure variants of its two fuzz targets, with the published engine, which ignores counting mode, and with the counting one, and checks the allocation mask, counting mode and `std::bad_alloc` in all four builds. It also builds cJSON's fuzz target with both engines (a test fixture): `cjson_read_fuzzer` keeps the release's four binaries, an input whose run makes 21 allocations has 21 counted in every build, and failing any one of them, or all, still exits with 0.
* **The workflows** in `.github/`: actionlint finds nothing, and the step that takes `projects/<name>/` from a pull request has been run against a local repository with good and bad pull requests.
* **The rebuild block** that `tools/check --twice` writes into the manifest: `tools/tests/test_check.py` runs `tools/check` with the builds replaced, for both results. A real `tools/check --twice cjson` wrote `result: identical`, with the release's four SHA-256s in both builds. The second build's image ids differed from the first's, and its toolchain did not.

## Not yet, or not checked

* **ubsan_checks**, in a provisional format (add, remove, reason) until its final format is agreed: `tools/validate.py` checks the names (clang 20's, probed in the toolchain image for riscv64 trap mode) and requires a reason. With today's toolchain (`fixed` in infra/toolchains.tsv), `tools/check` refuses the field. The builder's path for a list (OV_UBSAN_CHECKS) is tested with today's clang in tools/tests/test_builder.py, and used only once a toolchain row says `checks`. The trap-mode exceptions (vptr, function) are pending probes of the toolchain, and the skill's suggested removals are to come.
* **The next driver contract** (status 3 when a call returns -1; halts statements accept 0, 2 and 3) is documented as a note in docs/build-contract.md and the skill's step 3.7. The vendored driver does not change until the next toolchain version brings it; projects with proofs stay on today's driver.
* **docs/dsl.md** describes the format; its runtime is not in this repository yet, and the arming of the allocation mask in the new shape is pending.
* **DSL drivers** are not in this repository yet. When they come, they have the `LLVMFuzzerTestOneInput` shape (the skill's step 3.1 and 3.7, and docs/build-contract.md), and main carries only that shape. Proven API drivers keep their earlier whole-program shape until they are proved again: their locks name the recipe commit that builds them. The details of the operations are to come.
* **The toolchain image** that the builder is built `FROM` (`ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@sha256:6a6b4816…`) is not public yet. Until it is, `tools/check` and the Build workflow work only on a machine that already has it.
* **The builder image is not published.** `tools/check` builds it from `infra/base-builder/` and passes it to each Dockerfile as `BASE_BUILDER`; the Dockerfiles' default, `oss-verify-base-builder`, is that local name. Once it is pushed, that default should be its digest.
* **The workflows have not run on GitHub**: they are linted, not exercised there.
* **Hand-written build files:** a `build.sh` written for this builder by hand has been tried with CMake builds only (cjson, md4c, wasm3 and the test fixture). The ported builds use the release's recipes for the other build systems; the builder offers no Meson cross file or autotools settings of its own to a hand-written `build.sh` yet.
* **Allocation-failure fuzz targets** have no statement yet, and no project builds one.
* **Languages other than C and C++.** `tools/validate.py` accepts OSS-Fuzz's names (`rust`, `python`, `go`, `jvm`, `javascript`), with their source suffixes, and `sanitizers: []` as the default for `go` and `jvm`. The builder has only the C and C++ toolchain, so `tools/check` refuses the others, and `tools/seed.py` seeds C and C++ projects only. The Rust and Python builders are not in `infra/toolchains.tsv`: their images are not published. Rust keeps all four builds; its `ubsan` build uses rustc's `-Zub-checks`. R is pending and likely address-only: its UBSan build meets undefined behaviour inside R itself. `tools/validate.py` does not accept `r` yet.
* **docs/faq.md** has questions marked "To be confirmed": rechecks before a report and findings in dependencies, and where findings are kept.
* **Asserts compiled out in CMake builds.** A library built with CMake's `Release` build type, as cjson's and many ported builds are, is compiled with `NDEBUG`, so its `assert`s are compiled out and a failed one is not caught, where OSS-Fuzz's build of the same fuzz target often keeps them. Building it otherwise would change the bytes of the release's binaries, so this is a known exception to what the statements catch ([docs/what-gets-proven.md](docs/what-gets-proven.md)) until the next toolchain vintage ([docs/build-contract.md](docs/build-contract.md#toolchains)).
* **The proofs repository** (oss-verify-proofs) does not exist yet. The lock is to be written from `tools/check`'s manifest, and the triage comment's "Proofs index" row assumes the index layout of oss-fuzz-theorems.
* **Placeholders** to replace before this repository opens: the [terms](https://theorem.dev/oss-verify/terms/) URL and the contact in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Seeded projects

`tools/seed.py` writes a `project.yaml` from the oss-fuzz-theorems 2026.10 release's metadata, only where that metadata says everything needed. A seeded project says `primary_contact: n/a` until its maintainers adopt it ([CONTRIBUTING.md](CONTRIBUTING.md)). It is published only because it has no findings: a finding for it is sent nowhere unless someone hands it over by hand, and nothing is sent automatically ([docs/what-gets-proven.md](docs/what-gets-proven.md#findings)). Its `Dockerfile` and `build.sh` are added only once `tools/check` has built them and they reproduce the release's binaries.

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

* **boost-json**: its proof is about `fuzz_parse`, but about other builds of it than the release's: their bytes differ from the release's only in the `__FILE__` path prefix their build recorded. Whether to put it on main, and with which bytes, is not decided.
* **resiprocate** and **simdutf**: the release's build patches the library's own source (`rutil/Log.cxx`; `include/simdutf/internal/isadetection.h`), so its binaries are not of the library as upstream wrote it.

Fuzz targets we wrote ourselves for some of these libraries are left out until their sources are published.

### Draft branches

One for each of the other 302 projects `tools/seed.py` can seed: `draft-generic-oss-fuzz-<name>` is `main` plus that project, regenerated with `tools/seed.py --branch` when `main` changes. 301 have build files that reproduce the release's binaries (md4c's and wasm3's written by hand, the others ported), kept on `main` in `tools/seeds/<name>/`. varnish has only a `project.yaml`, since its port fails (above), as its commit message says.

### Everything else

[docs/seeded-projects.tsv](docs/seeded-projects.tsv) says, for each of the release's 1,381 projects, whether it can be seeded and why not, and for each one that can, how its ported build fared. 312 can. Of the rest, 1,040 were not built by the release (781 in a language other than C or C++, 120 too large, 78 not built yet, 32 with no harness, 17 held, 6 excluded, 3 needing model support, 3 with no compiler), 25 have no harness whose build leaves the library's own source alone, and 4 have no full commit recorded.

## Not decided yet

* The launch set on main.
* Whether the `asan` and `asan-ubsan` builds should have a smaller `halts` budget ([docs/what-gets-proven.md](docs/what-gets-proven.md#memory-budgets)).
