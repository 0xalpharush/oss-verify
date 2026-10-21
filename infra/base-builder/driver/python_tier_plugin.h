/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * The adapter's half of a Python fuzz target (python/atheris_host.c is the harness's). It is compiled with the
 * driver, twice: loud, and with -DHARNESS_QUIET. Thus the description of a failure is here, not in atheris_host.c,
 * whose one object is in both binaries. Loud: one line on standard error. Quiet: nothing.
 *
 * From the build recipe of the oss-fuzz-theorems 2026.10 release (src/python_tier_plugin.h), in its release spelling.
 * The code is unchanged; the comments are new.
 */
#ifndef OFT_PYTHON_TIER_PLUGIN_H
#define OFT_PYTHON_TIER_PLUGIN_H
#include <stdio.h>
void oft_py_report(const char *what, const char *type, const char *file, int line);
void oft_py_report(const char *what, const char *type, const char *file, int line) {
#ifdef HARNESS_QUIET
  (void)what; (void)type; (void)file; (void)line;
#else
  fprintf(stderr, "oft-py: %s: uncaught %s at %s:%d\n", what, type, file, line);
#endif
}
int oft_py_quiet(void);
int oft_py_quiet(void) {
#ifdef HARNESS_QUIET
  return 1;
#else
  return 0;
#endif
}
#endif
