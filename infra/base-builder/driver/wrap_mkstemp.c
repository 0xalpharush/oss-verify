/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Linked into every fuzz target with -Wl,--wrap= for mkstemp, mkostemp, mkstemps and mkostemps: the six X's of the
 * template become 000000 and the file is created in the current directory under the template's last component, so
 * that the program depends only on its input file. A template without six X's (before its suffix) fails, as it
 * would with the C library.
 * From the oss-fuzz-theorems 2026.10 release recipe (src/wrap_mkstemp.c). The code is that of its release
 * builds; the configuration those builds do not use is left out.
 */
#include <fcntl.h>
#include <stddef.h>
#include <string.h>

#define OFT_XS 6

static const char SEAL[OFT_XS] = {'0', '0', '0', '0', '0', '0'};

static int seal_open(char *template, int suffixlen) {
  if (template == NULL || suffixlen < 0) return -1;
  size_t len = strlen(template);
  if (len < (size_t)suffixlen + OFT_XS) return -1;
  char *xs = template + len - (size_t)suffixlen - OFT_XS;
  for (int i = 0; i < OFT_XS; i++) {
    if (xs[i] != 'X') return -1;
  }
  memcpy(xs, SEAL, OFT_XS);
  char *slash = strrchr(template, '/');
  if (slash != NULL) {
    memmove(template, slash + 1, strlen(slash + 1) + 1);
  }
  return open(template, O_WRONLY | O_CREAT | O_TRUNC, 0600);
}

int __wrap_mkstemp(char *template) { return seal_open(template, 0); }
int __wrap_mkostemp(char *template, int flags) {
  (void)flags;
  return seal_open(template, 0);
}
int __wrap_mkstemps(char *template, int suffixlen) {
  return seal_open(template, suffixlen);
}
int __wrap_mkostemps(char *template, int suffixlen, int flags) {
  (void)flags;
  return seal_open(template, suffixlen);
}
