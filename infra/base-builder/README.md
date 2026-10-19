# The builder image

Every project's `Dockerfile` starts `FROM` this image. It is a toolchain image plus OSS-Fuzz's interface: by default the one the oss-fuzz-theorems 2026.10 release built its binaries in, pinned by digest (`ARG TOOLCHAIN` in the [Dockerfile](Dockerfile)); `tools/check` passes the toolchain a project's lock names, or the newest in [infra/toolchains.tsv](../toolchains.tsv) ([docs/build-contract.md](../../docs/build-contract.md#toolchains)). [docs/build-contract.md](../../docs/build-contract.md) is the contract a project builds against; this page says what is where.

| path in the image | what it is |
|---|---|
| `/usr/local/bin/compile` | [compile](compile): runs `$SRC/build.sh` for the build `$SANITIZER` names, with that build's compilers and flags |
| `/usr/local/bin/fetch-commit` | [fetch-commit](fetch-commit): checks out `$REPO` at `$COMMIT`, for a project's Dockerfile |
| `/usr/local/lib/oss-verify/toolchain.sh` | [toolchain.sh](toolchain.sh): the compiler wrappers and flags of each build |
| `/usr/local/lib/oss-verify/link-fuzz-target` | [link-fuzz-target](link-fuzz-target): how a fuzz target is linked |
| `/usr/local/lib/oss-verify/driver/` | [driver/](driver/): the driver that `$LIB_FUZZING_ENGINE` links into every fuzz target, and the adapter `$LIB_ALLOCATION_FAILURE_ENGINE` links into an allocation-failure fuzz target |
| `/usr/local/bin/lay-out-sources` | [lay-out-sources](lay-out-sources): lays out a project's other source trees and files from its `sources` file |
| `/usr/local/lib/oss-verify/recipes.sh` | [recipes.sh](recipes.sh): the release's build recipes (CMake, autotools, Meson, blind and header-only builds, the C++ runtime group), for ported builds |
| `/usr/local/lib/oss-verify/release-target.sh` | [release-target.sh](release-target.sh): builds one release target as the release's build body does, for ported builds |
| `/usr/local/lib/oss-verify/rust/` | [rust/](rust/): the recipe of a Rust fuzz target ([recipes.sh](rust/recipes.sh)), the generator of its static library crate ([gen-shim.py](rust/gen-shim.py)) and the Rust half of its adapter ([oft-rust-rt](rust/oft-rust-rt/)); the C half is [driver/plugin_rust.h](driver/plugin_rust.h) |
| `/usr/local/lib/oss-verify/python/` | [python/](python/): the recipe of a Python fuzz target ([recipes.sh](python/recipes.sh)), its module closure and freezer, its harness object ([atheris_host.c](python/atheris_host.c)), the stand-in for atheris and CPython's patch; its adapter is [driver/python_tier_plugin.h](driver/python_tier_plugin.h) |
| `$SRC`, `$WORK`, `$OUT` | `/src`, `/work`, `/out`, as in OSS-Fuzz |

The toolchain image provides clang 20.1.8 for `riscv64-linux-musl`, lld, the musl sysroot (`/opt/musl-sysroot`, with static libraries a project may link) and the sealed static AddressSanitizer runtime, on Alpine Linux with CMake, Meson, Ninja, the autotools and git. The Rust toolchain image adds Rust nightly-2025-07-16, its sealed standard library and the standard library's crates. The Python toolchain image adds the CPython 3.11.13 tarball and a native CPython 3.11.13 built from it.

`tools/check` builds this image locally, tagged `oss-verify-base-builder:<hash of this directory>-<toolchain digest>`. It is not published yet, so a project's Dockerfile names it by that local tag, which `tools/check` passes as `BASE_BUILDER`.

`driver/`, `toolchain.sh`, `recipes.sh`, `release-target.sh` and the order of a fuzz target's link come from the build recipe of the oss-fuzz-theorems 2026.10 release; each file says what it keeps and what it leaves out. With them, the builder makes that release's binaries again, byte for byte.
