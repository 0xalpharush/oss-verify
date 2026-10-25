/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * A fuzz target for tools/tests/test_properties.py, with one property check of each kind that tools/check names.
 * The test's seeds are "two" (02 03) and "zero" (00 00). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 2)
		return 0;
	uint8_t *copy = malloc(size);
	/* not a property: malloc failed */
	if (!copy)
		abort();
	memcpy(copy, data, size);
	int a = copy[0], b = copy[1];
	free(copy);
	/* lib_add adds. The mutant is met: 2 - 3 is not 5.
	 * mutant: lib.c:4 `a + b` -> `a - b`
	 * input: two */
	if (lib_add(a, b) != a + b)
		abort();
	/* The sign of a positive number is 1. The mutant is not met: on "two", 2 > 1 too.
	 * mutant: lib.c:5 `a > 0` -> `a > 1`
	 * input: two */
	if (a > 0 && lib_sign(a) != 1)
		abort();
	if (a == 0xff) {
		/* No seed starts with ff, and no mutant is recorded. */
		if (lib_sign(-a) != -1)
			abort();
	}
	// mutant: lib.c:5 `a < 0` -> `a <= 0`
	// input: missing
	if (b > 0 && lib_sign(-b) != -1)
		abort();
	// mutant: lib.c:4 `a + b`
	if (lib_sign(0) != 0)
		abort();
	return 0;
}
