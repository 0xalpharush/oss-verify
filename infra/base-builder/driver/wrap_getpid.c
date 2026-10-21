/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Linked into every fuzz target with -Wl,--wrap=getpid -Wl,--wrap=getppid: both return 1, so that the program
 * depends only on its input file.
 * From the oss-fuzz-theorems 2026.10 release recipe (src/wrap_getpid.c). The code is unchanged.
 */
#include <sys/types.h>
#include <unistd.h>

pid_t __wrap_getpid(void);
pid_t __wrap_getpid(void)
{
  return 1;
}

pid_t __wrap_getppid(void);
pid_t __wrap_getppid(void)
{
  return 1;
}
