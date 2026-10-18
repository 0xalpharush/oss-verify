# The build contract

A project's `Dockerfile` and `build.sh` follow OSS-Fuzz's conventions, on our builder image instead of OSS-Fuzz's. This page says what the builder provides, what the two files must do, and how `tools/check` turns them into binaries. `tools/check` builds exactly as we do.

An OSS-Fuzz `Dockerfile` and `build.sh` do not run here unchanged, and we do not promise that they will. They assume OSS-Fuzz's x86-64 base image, packages installed with apt, a native clang and often shared libraries; ours is a cross-compiler for static riscv64 Linux programs. Every build is ported. The port is usually short: the cmake or configure call, the fuzz targets' compile and link lines, and where the dependencies come from.

## The steps

1. **The builder image** ([infra/base-builder/](../infra/base-builder/)) is built `FROM` the pinned toolchain image.
2. **The project image** is built from the project's `Dockerfile`, `FROM` the builder, with `--build-arg COMMIT=<full commit id>` (the commit `repo#ref` resolved to), `REPO` and `BASE_BUILDER`. This is the only step with network access.
3. **Each build** runs `compile` in a fresh container of the project image with no network (`docker run --network=none`): once for each of `plain`, `ubsan`, `asan` and `asan-ubsan` that `project.yaml` asks for. `compile` sets up that build's compilers and flags and runs `$SRC/build.sh`, which builds every fuzz target into `$OUT`.
4. **The fuzz targets** are found in each build's `$OUT`, and their binaries collected as `out/<target>/<target>.<build>`, with a manifest of their SHA-256s.

## The builder

The toolchain image is the one oss-fuzz-theorems 2026.10.0-rc.2 built its binaries in, `ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@sha256:6a6b4816865c7ec61801ae0fcab6d9c81a599ffcb20616576a9c668abd8b0a7b`. It provides clang 20.1.8 for `riscv64-linux-musl`, lld, the musl sysroot at `/opt/musl-sysroot` (with static builds of common libraries a project may link), and a sealed static AddressSanitizer runtime, on Alpine Linux with CMake, Meson, Ninja, the autotools and git. The builder adds OSS-Fuzz's interface. Its driver, compiler wrappers and flags come from that release's build recipe, and with them the builder reproduces that release's binaries byte for byte ([STATUS.md](../STATUS.md) lists the projects checked).

Every binary is a static riscv64 Linux program for RV64G (`-march=rv64g -mabi=lp64d`), linked with lld against musl.

## What build.sh is given

| variable | value |
|---|---|
| `$SRC`, `$WORK`, `$OUT` | `/src` (the sources and `build.sh`), `/work` (scratch), `/out` (where the fuzz targets go), as in OSS-Fuzz |
| `$CC`, `$CXX` | clang and clang++ for this build: cross-compilers for `riscv64-linux-musl` with this build's sanitizer runtime. A link that names `$LIB_FUZZING_ENGINE` is a fuzz target's link (below) |
| `$CFLAGS` | the common flags, this build's sanitizer flags, `-Wno-unused-command-line-argument` and `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` |
| `$CXXFLAGS` | `$CFLAGS -stdlib=libc++` |
| `$LIB_FUZZING_ENGINE` | the driver, which takes libFuzzer's place in every fuzz target ([exit-codes.md](exit-codes.md)) |
| `$LIB_ALLOCATION_FAILURE_ENGINE` | the driver of an allocation-failure fuzz target, in which allocations fail as the input says ([exit-codes.md](exit-codes.md#allocation-failure)) |
| `$SANITIZER` | `none`, `undefined`, `address` or `address-undefined` |
| `$ARCHITECTURE`, `$FUZZING_ENGINE` | `riscv64`; `none` (OSS-Fuzz's name for a driver that runs inputs from files) |
| `$CMAKE_TOOLCHAIN_FILE` | a CMake toolchain file for this build, which CMake 3.21 and later pick up by themselves |
| `$AR`, `$NM`, `$RANLIB`, `$STRIP`, `$OBJCOPY` | the LLVM tools, as `riscv64-linux-musl-ar` and so on (also on `PATH`) |
| `$SOURCE_DATE_EPOCH` | `1756684800`, for anything that stamps a date |

`build.sh` runs with `bash -eux`, from the Dockerfile's `WORKDIR`.

## The builds

The common compile flags are

    -march=rv64g -mabi=lp64d -Os -g -ffunction-sections -fdata-sections -fno-stack-protector -Wdate-time
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-reallocarray -fno-builtin-free
    -fno-builtin-aligned_alloc -fno-builtin-posix_memalign -fno-builtin-memalign -fno-builtin-valloc
    -fno-builtin-strdup -fno-builtin-strndup

The `-fno-builtin-*` flags keep every allocation an ordinary call in all four builds, so that the optimiser cannot remove or merge an allocation in one build and keep it in another.

| build | `$SANITIZER` | sanitizer flags | a detected error |
|---|---|---|---|
| `plain` | `none` | none | none |
| `ubsan` | `undefined` | `-fsanitize=undefined -fno-sanitize-recover=all -fsanitize-trap=all -fno-sanitize=function` | `SIGILL` (status 132), nothing printed |
| `asan` | `address` | `-fsanitize=address`, with the sealed static runtime | `abort()` (status 134), nothing printed |
| `asan-ubsan` | `address-undefined` | both | either |

The UBSan builds trap, with no runtime. With these flags clang 20 checks, as oss-fuzz-theorems measured for the same compiler and flags, `alignment`, `array-bounds`, `bool`, `builtin`, `enum`, `float-cast-overflow`, `integer-divide-by-zero`, `nonnull-attribute`, `null`, `object-size`, `pointer-overflow`, `return`, `returns-nonnull-attribute`, `shift-base`, `shift-exponent`, `signed-integer-overflow`, `unreachable` and `vla-bound`. It does not check `function` (turned off), `vptr` (it needs a runtime), or what clang leaves out of `undefined` by default: unsigned overflow, implicit conversions, `local-bounds`, float division by zero, nullability.

As that release's documentation describes it, the sealed AddressSanitizer runtime reads no environment variable, so `ASAN_OPTIONS` has no effect. The driver sets `allocator_may_return_null=1`, so `malloc` returns NULL when memory is refused, as in the plain build. A detection aborts without printing a report. Leak detection is off, the runtime installs no signal handlers, and at start-up it reserves well over 100 GiB of address space; under a shell limit such as `ulimit -v` that reservation fails and the program waits forever.

The driver is compiled without sanitizer flags in every build; the library and the fuzz targets get the build's flags. In every build `getenv()` returns NULL, `getpid()` and `getppid()` return 1, and `mkstemp()` and its relatives use a fixed name in the current directory, so that a program depends only on its input file.

## What the Dockerfile must do

Start from [templates/Dockerfile](../templates/Dockerfile).

* `FROM ${BASE_BUILDER}`, with `ARG BASE_BUILDER=oss-verifier-base-builder`. `tools/check` passes the builder it built.
* Declare `ARG REPO` and `ARG COMMIT`, and fetch the source at exactly that commit: `RUN fetch-commit $SRC/<name>` (with `--submodules` if it has any). Never write a commit id into the Dockerfile: `tools/check` supplies it, and the proofs repository's lock records it.
* Fetch and build anything else the build needs: dependencies, at fixed versions. Dependencies a sanitizer build should instrument are built by `build.sh` with each build's flags; libraries from the sysroot are linked as they are, uninstrumented. `tools/check` records the commit of every git checkout under `$SRC` in its manifest.
* `COPY build.sh $SRC/`, and any harness sources and patches from `projects/<name>/`. Patches are applied in the order `series` lists.

When the Dockerfile lives in the project's own repository (`dockerfile:` in `project.yaml`), the build context is that repository at the commit being built: `COPY . $SRC/<name>` takes the source from it.

## What build.sh must do

Start from [templates/build.sh](../templates/build.sh).

* Build the library statically with `$CC`, `$CXX`, `$CFLAGS` and `$CXXFLAGS`. CMake picks up `$CMAKE_TOOLCHAIN_FILE` by itself. Another build system needs the same things, the cross-compilers, the sysroot and static libraries, said its own way; so far the builder has been tried with CMake builds only ([STATUS.md](../STATUS.md)).
* Compile each fuzz target, and link it into `$OUT` through `$CC` or `$CXX` with `$LIB_FUZZING_ENGINE`:

      $CC $CFLAGS -c fuzz/example_fuzzer.c -o "$WORK/example_fuzzer.o"
      $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE libexample.a

* Do not run what it compiles. The programs are for riscv64, and a build that runs one works only on a machine that runs riscv64 programs transparently (some do, through binfmt_misc and qemu), so its result would depend on the machine.
* Do not change a fuzz target after linking it (no `strip`, no `objcopy`): its published bytes are made at link time.
* Be deterministic: no dates (`$SOURCE_DATE_EPOCH` is set, and `-Wdate-time` warns about `__DATE__` and `__TIME__`), and no version strings derived from the git history, which differs between a full and a shallow clone.

## How a fuzz target is linked

A link through `$CC` or `$CXX` that names `$LIB_FUZZING_ENGINE` is made the way the release recipe makes it ([link-fuzz-target](../infra/base-builder/link-fuzz-target)):

    <compiler> -static -no-pie -Wl,--gc-sections <driver> [<silent reports>] <the link's own arguments> <seals>

The driver's objects come first, wherever the link named `$LIB_FUZZING_ENGINE`, and the getenv, getpid and mkstemp seals come last; in the AddressSanitizer builds, `-Wl,--defsym=__sanitizer_silent_reports=1` makes a detection abort without a report. The link is made twice. The file `build.sh` asked for keeps its symbols, so that the fuzz target can be found by its symbol table. A second link adds `-Wl,--strip-all`, and its output is the published binary: `compile` saves it as `$OUT/.stripped/<sha256 of the first>`.

## The fuzz targets

A fuzz target is an executable in a build's `$OUT` whose ELF symbol table defines `LLVMFuzzerTestOneInput`. That is OSS-Fuzz's rule, except that it reads the symbol table instead of searching the file's bytes. A fuzz target must be in every build. `fuzz_targets` in `project.yaml` names the ones to verify; without it, every one found is verified. `tools/check` collects each one's published binary as `out/<target>/<target>.<build>`. Anything else in `$OUT` is ignored.

## The manifest

`tools/check` writes `manifest.yaml` beside `out/`, marked as generated:

* `repo`, `ref` and `commit`: the repository, the ref `project.yaml` names, and the full commit it resolved to;
* `oss_verifier`: this repository's commit, and whether `tools/`, `infra/` or the project's directory differed from it;
* `builder`: the toolchain image's digest, and the local ids of the builder and project images;
* `sources`: every git checkout under `$SRC` in the project image, and the commit it is at;
* `builds` and `fuzz_targets`: what was built, with "every fuzz target" resolved to a list;
* `targets.<target>.builds.<build>`: `file`, `bytes` and `sha256` of each binary, the shape of the `builds:` section of an oss-fuzz-theorems `harness.yaml`.

The lock in the proofs repository is to be written from the manifest, and it is the only place the resolved commit is kept. `tools/check --lock <file>` builds the commit a lock names and compares every binary with it; the lock may be a manifest, or an oss-fuzz-theorems `harness.yaml`.

## Reproducibility

`tools/check --twice` builds everything a second time from scratch (`docker build --no-cache`, a fresh fetch, every build compiled again) and fails if any byte differs. These decide the bytes, as we found in reproducing the release's binaries:

* **The source paths.** An AddressSanitizer build records the path of every source file it instruments, so a file compiled at `/src/a/x.c` and at `/src/b/x.c` makes different binaries. The plain and UBSan builds do not depend on it.
* **The order of the link.** The driver first and the seals last, as `$LIB_FUZZING_ENGINE` arranges.
* **The layout of the archives.** Linking the fuzz target's object before the library's archives, as OSS-Fuzz does, can lay out the program differently from linking one archive that holds the library and the fuzz target, as the release did. A port that must match the release's bytes links the way it did.
* **Stripping at link time.** Stripping the binary afterwards gives different bytes from `-Wl,--strip-all`.

## Builds ported from oss-fuzz-theorems

A project seeded from oss-fuzz-theorems 2026.10.0-rc.2 can have its build ported from that release's recipe by `tools/port.py`, which writes three generated files beside `project.yaml`:

* `Dockerfile`: fetches the project at `COMMIT` into `$SRC/upstream/<name>`, then runs `lay-out-sources` on `sources`.
* `sources`: where each source tree goes, as the release's source manifest says: a copy of the checkout per release target, any other tree or file pinned by commit or sha256, the release's own files for a target, and its build-only patches. It is the only place a dependency's pin is kept; a Dockerfile never holds one.
* `build.sh`: for each fuzz target, the release's pin for it (its `build_lib`, `LIB_ARCHIVE` and helpers), run by [release-target.sh](../infra/base-builder/release-target.sh) with the release's recipes ([recipes.sh](../infra/base-builder/recipes.sh)), under `sh -e` as the release ran it.

`release-target.sh` gives each target the layout the release built in: its tree in `/work/ext/<target>/src`, its build directory in `/work/build/lib/<build>/<target>`, the release's files for it in `/work/targets/<target>`, and compiler wrappers that give the compiler the neutral `/src/...` paths a binary records. The internal paths matter as well as the neutral ones: the source locations of UBSan's checks keep the internal path, so in an `asan-ubsan` build a header that both uses `__FILE__` and holds a UBSan check makes one string literal more, which the AddressSanitizer build instruments, than the same build at the neutral path. With that layout, a ported build reproduces the release's binaries; [STATUS.md](../STATUS.md) says for which projects that has been checked.

## Patches

A patch beside `project.yaml` may only change how the project builds: static linking, cross-compilation, a version stamp, a generated file. `series` lists the patches in the order they are applied. A patch that fixes a bug never goes here: it goes to the project ([disclosure.md](disclosure.md)).
