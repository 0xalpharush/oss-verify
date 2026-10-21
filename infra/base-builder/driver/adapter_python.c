/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * The adapter between cli.c and a Python fuzz target: ossfuzz_adapter.h, with python_tier_plugin.h's description of
 * a failure. As the oss-fuzz-theorems 2026.10 release recipe builds a Python target's plugin.c, with one name for every
 * target: nothing in a fuzz target's binary uses it.
 */
#define OFT_TARGET_NAME "fuzz_target"
#include "ossfuzz_adapter.h"
#include "python_tier_plugin.h"
