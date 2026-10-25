# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The property-checks fixture, for tools/tests/test_properties.py: the source is the build context.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
COPY lib.c lib.h fuzz_prop.c $SRC/prop/
COPY build.sh $SRC/
WORKDIR $SRC/prop
