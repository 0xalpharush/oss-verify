# The builder image

Every project's `Dockerfile` starts `FROM` this image. It is the toolchain image that oss-fuzz-theorems 2026.10.0-rc.2 built its binaries in, pinned by digest (`ARG TOOLCHAIN` in the [Dockerfile](Dockerfile)), plus OSS-Fuzz's interface. [docs/build-contract.md](../../docs/build-contract.md) is the contract a project builds against; this page says what is where.

| path in the image | what it is |
|---|---|
| `/usr/local/bin/compile` | [compile](compile): runs `$SRC/build.sh` for the build `$SANITIZER` names, with that build's compilers and flags |
| `/usr/local/bin/fetch-commit` | [fetch-commit](fetch-commit): checks out `$REPO` at `$COMMIT`, for a project's Dockerfile |
| `/usr/local/lib/oss-verifier/toolchain.sh` | [toolchain.sh](toolchain.sh): the compiler wrappers and flags of each build |
| `/usr/local/lib/oss-verifier/link-fuzz-target` | [link-fuzz-target](link-fuzz-target): how a fuzz target is linked |
| `/usr/local/lib/oss-verifier/driver/` | [driver/](driver/): the driver that `$LIB_FUZZING_ENGINE` links into every fuzz target |
| `/usr/local/bin/lay-out-sources` | [lay-out-sources](lay-out-sources): lays out a project's other source trees and files from its `sources` file |
| `/usr/local/lib/oss-verifier/recipes.sh` | [recipes.sh](recipes.sh): the release's build recipes (CMake, autotools, Meson, blind and header-only builds, the C++ runtime group), for ported builds |
| `/usr/local/lib/oss-verifier/release-target.sh` | [release-target.sh](release-target.sh): builds one release target as the release's build body does, for ported builds |
| `$SRC`, `$WORK`, `$OUT` | `/src`, `/work`, `/out`, as in OSS-Fuzz |

The toolchain image provides clang 20.1.8 for `riscv64-linux-musl`, lld, the musl sysroot (`/opt/musl-sysroot`, with static libraries a project may link) and the sealed static AddressSanitizer runtime, on Alpine Linux with CMake, Meson, Ninja, the autotools and git.

`tools/check` builds this image locally, tagged `oss-verifier-base-builder:<hash of this directory>`. It is not published yet, so a project's Dockerfile names it by that local tag, which `tools/check` passes as `BASE_BUILDER`.

`driver/`, `toolchain.sh`, `recipes.sh`, `release-target.sh` and the order of a fuzz target's link come from the build recipe of oss-fuzz-theorems release 2026.10.0-rc.2; each file says what it keeps and what it leaves out. With them, the cjson pilot reproduces that release's four cjson binaries byte for byte ([STATUS.md](../../STATUS.md)).
