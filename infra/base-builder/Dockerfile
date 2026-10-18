# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The oss-verifier builder: the pinned toolchain image plus the interface a project's Dockerfile and build.sh are
# written against, in OSS-Fuzz's names ($SRC, $WORK, $OUT, $CC, $CFLAGS, $LIB_FUZZING_ENGINE, $SANITIZER, compile).
# docs/build-contract.md describes it.
#
# The toolchain is the image oss-fuzz-theorems 2026.10.0-rc.2 built its binaries in (its toolchain/toolchain.lock):
# clang 20.1.8 for riscv64-linux-musl, lld, musl, and the sealed static AddressSanitizer runtime.
ARG TOOLCHAIN=ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain@sha256:6a6b4816865c7ec61801ae0fcab6d9c81a599ffcb20616576a9c668abd8b0a7b
FROM ${TOOLCHAIN}

COPY toolchain.sh link-fuzz-target /usr/local/lib/oss-verifier/
COPY driver/ /usr/local/lib/oss-verifier/driver/
COPY compile fetch-commit /usr/local/bin/
RUN chmod 0755 /usr/local/bin/compile /usr/local/bin/fetch-commit /usr/local/lib/oss-verifier/link-fuzz-target \
 && mkdir -p /src /work /out

ENV SRC=/src \
    WORK=/work \
    OUT=/out \
    SANITIZER=none
WORKDIR /src
CMD ["compile"]
