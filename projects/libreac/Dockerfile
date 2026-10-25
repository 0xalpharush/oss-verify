# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Modified by Theorem Labs, 2026-10-25: copies the modified fuzz targets over fuzz/.
#
# libreac on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
# The fuzz targets are libreac's own, in fuzz/ of the checkout. The fuzz_*.c and fuzz.h files here are modified
# copies of them: each property has a mutant record, and some checks are stronger. They replace the files in
# fuzz/, so build.sh and the paths in the mutant records stay fuzz/<file>.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/libreac
COPY build.sh $SRC/
COPY fuzz_*.c fuzz.h $SRC/libreac/fuzz/
WORKDIR $SRC/libreac
