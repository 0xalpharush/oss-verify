/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Grow a buffer by allocating a new one and copying, never with realloc.
 * From the oss-fuzz-theorems 2026.10.0-rc.2 release recipe (src/grow_buf.h). The code is unchanged.
 */
#ifndef GROW_BUF_H
#define GROW_BUF_H
#include <stdlib.h>
#include <string.h>
static inline void *grow_buf(void *old, size_t used, size_t newcap) {
  void *nb = malloc(newcap);
  if (!nb) return NULL;
  if (used) memcpy(nb, old, used);
  free(old);
  return nb;
}
#endif
