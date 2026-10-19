/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The adapter between cli.c and a Rust fuzz target: ossfuzz_adapter.h, with plugin_rust.h's two exit statuses. As the
 * oss-fuzz-theorems 2026.10 release recipe builds a Rust target's plugin.c, with one name for every target: nothing in
 * a fuzz target's binary uses it.
 */
#define OFT_TARGET_NAME "fuzz_target"
#include "ossfuzz_adapter.h"
#include "plugin_rust.h"
