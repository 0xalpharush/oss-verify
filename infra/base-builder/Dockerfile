# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The oss-verify builder: the pinned toolchain image plus the interface a project's Dockerfile and build.sh are
# written against, in OSS-Fuzz's names ($SRC, $WORK, $OUT, $CC, $CFLAGS, $LIB_FUZZING_ENGINE, $SANITIZER, compile).
# docs/build-contract.md describes it.
#
# The toolchain is the image the oss-fuzz-theorems 2026.10 release built its binaries in (its toolchain/toolchain.lock):
# clang 20.1.8 for riscv64-linux-musl, lld, musl, and the sealed static AddressSanitizer runtime.
ARG TOOLCHAIN=ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@sha256:6a6b4816865c7ec61801ae0fcab6d9c81a599ffcb20616576a9c668abd8b0a7b
FROM ${TOOLCHAIN}

COPY toolchain.sh link-fuzz-target recipes.sh release-target.sh /usr/local/lib/oss-verify/
COPY driver/ /usr/local/lib/oss-verify/driver/
COPY python/ /usr/local/lib/oss-verify/python/
COPY compile fetch-commit lay-out-sources /usr/local/bin/
RUN chmod 0755 /usr/local/bin/compile /usr/local/bin/fetch-commit /usr/local/bin/lay-out-sources \
               /usr/local/lib/oss-verify/link-fuzz-target \
 && mkdir -p /src /work /out

ENV SRC=/src \
    WORK=/work \
    OUT=/out \
    SANITIZER=none
WORKDIR /src
CMD ["compile"]
