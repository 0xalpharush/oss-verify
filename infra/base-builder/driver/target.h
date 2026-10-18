/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * What cli.c needs from an adapter (adapter.c, through ossfuzz_adapter.h).
 * From the oss-fuzz-theorems 2026.10.0-rc.2 release recipe (src/target.h). The code is unchanged.
 */
#ifndef TARGET_H
#define TARGET_H
#include <stddef.h>
const char *target_name(void);
void target_alloc_init(unsigned int fail_bitmap);
unsigned target_alloc_count(void);
int target_run(const unsigned char *config, size_t config_len,
               const unsigned char *payload, size_t payload_len);
#endif
