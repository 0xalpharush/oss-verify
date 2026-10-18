/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * One behaviour per first byte, so that the test can check every exit status the driver documents
 * (docs/exit-codes.md) in every build. */
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "example.h"

int example_run(const unsigned char *data, size_t size) {
  if (size == 0) return 0;
  switch (data[0]) {
    case 'r': return 1;                                   /* a return value other than 0 or -1: 78 */
    case 'm': return -1;                                  /* -1 is allowed: 0 */
    case 'x': exit(3);                                    /* exit() in the target: 77 */
    case 'a': abort();                                    /* abort(): 134 */
    case 's': { volatile int *p = 0; return *p; }         /* a segmentation fault: 139 */
    case 'n': { volatile unsigned long zero = 0; int *p = (int *)zero; return *p; }  /* a null load UBSan checks */
    case 'o': { volatile int big = INT_MAX; volatile int sum = big + (int)size; (void)sum; return 0; }  /* signed overflow */
    case 'h': {                                           /* a heap read one past the end */
      unsigned char *copy = malloc(size);
      if (copy == NULL) return 0;
      memcpy(copy, data, size);
      volatile unsigned char past = copy[size];
      free(copy);
      return past == 255 ? 0 : 0;
    }
  }
  return 0;
}
