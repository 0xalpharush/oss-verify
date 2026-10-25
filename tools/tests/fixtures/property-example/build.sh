#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The property-checks fixture, for tools/tests/test_properties.py: a library of two functions and one fuzz target.
$CC $CFLAGS -c lib.c -o "$WORK/lib.o"
$CC $CFLAGS -c fuzz_prop.c -o "$WORK/fuzz_prop.o"
$CC $CFLAGS "$WORK/fuzz_prop.o" "$WORK/lib.o" -o "$OUT/fuzz_prop" $LIB_FUZZING_ENGINE
