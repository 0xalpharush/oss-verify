/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linked into every fuzz target with -Wl,--wrap=getenv: getenv() returns NULL, so that the program depends only on
 * its input file, not on its environment.
 * From the oss-fuzz-theorems 2026.10 release recipe (src/wrap_getenv.c). The code is unchanged.
 */
#include <stddef.h>

char *__real_getenv(const char *name);

char *__wrap_getenv(const char *name) {
  (void)name;
  return NULL;
}
