/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * The adapter between cli.c and an OSS-Fuzz-style fuzz target, the other half of $LIB_FUZZING_ENGINE.
 * As the oss-fuzz-theorems 2026.10 release recipe builds each targets/<t>/plugin.c, with one name for every
 * target: nothing in a fuzz target's binary uses it.
 */
#define OFT_TARGET_NAME "fuzz_target"
#include "ossfuzz_adapter.h"
