/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The adapter of an allocation-failure fuzz target, which $LIB_ALLOCATION_FAILURE_ENGINE links in place of adapter.c
 * (docs/exit-codes.md#allocation-failure). link-fuzz-target links copies of the object files and archives the link
 * names, the project's code, with their calls of these allocators renamed to the ones below:
 *
 *     malloc calloc realloc reallocarray aligned_alloc posix_memalign memalign strdup strndup
 *     operator new and operator new[], each with its nothrow and aligned forms
 *
 * While LLVMFuzzerTestOneInput runs, each such call is counted from 0, over all of a run's calls, and the n-th fails
 * if bit n of the input's allocation mask is set: it returns NULL with errno ENOMEM (posix_memalign returns ENOMEM;
 * operator new throws std::bad_alloc, and its nothrow form returns NULL). Calls after the 32nd never fail. Nothing
 * else is counted: not the driver's allocations, not LLVMFuzzerInitialize's, and not those the C or C++ library
 * makes inside a function the project called. So a run makes the same calls, counted the same way, in every build.
 *
 * target_alloc_count() is the number of calls counted, which the driver reports as the exit status of a run whose
 * config word asks for it. Otherwise this is adapter.c: the same ossfuzz_adapter.h, around the same fuzz target.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ossfuzz_adapter.h's target_run, calling ov_test_one_input below in place of the fuzz target; its allocation hooks,
 * which do nothing, renamed out of the way. */
#define OFT_TARGET_NAME "fuzz_target"
#define LLVMFuzzerTestOneInput ov_test_one_input
#define target_alloc_init ov_unused_alloc_init
#define target_alloc_count ov_unused_alloc_count
#include "ossfuzz_adapter.h"
#undef LLVMFuzzerTestOneInput
#undef target_alloc_init
#undef target_alloc_count

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
void target_alloc_init(unsigned int fail_bitmap);
unsigned target_alloc_count(void);

static unsigned int ov_mask;
static unsigned ov_count;
static int ov_armed;

void target_alloc_init(unsigned int fail_bitmap) {
  ov_mask = fail_bitmap;
  ov_count = 0;
}

unsigned target_alloc_count(void) { return ov_count; }

int ov_test_one_input(const uint8_t *data, size_t size) {
  ov_armed = 1;
  int rc = LLVMFuzzerTestOneInput(data, size);
  ov_armed = 0;
  return rc;
}

/* Whether this call fails. Only calls made while the fuzz target runs are counted. */
static int ov_fails(void) {
  if (!ov_armed) return 0;
  unsigned n = ov_count++;
  return n < 32 && ((ov_mask >> n) & 1u);
}

/* The C allocators. */
void *__ov_malloc(size_t size);
void *__ov_calloc(size_t count, size_t size);
void *__ov_realloc(void *pointer, size_t size);
void *__ov_reallocarray(void *pointer, size_t count, size_t size);
void *__ov_aligned_alloc(size_t alignment, size_t size);
int __ov_posix_memalign(void **pointer, size_t alignment, size_t size);
void *__ov_memalign(size_t alignment, size_t size);
char *__ov_strdup(const char *string);
char *__ov_strndup(const char *string, size_t size);
void *reallocarray(void *pointer, size_t count, size_t size);
void *memalign(size_t alignment, size_t size);

void *__ov_malloc(size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return malloc(size);
}

void *__ov_calloc(size_t count, size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return calloc(count, size);
}

void *__ov_realloc(void *pointer, size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return realloc(pointer, size);
}

void *__ov_reallocarray(void *pointer, size_t count, size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return reallocarray(pointer, count, size);
}

void *__ov_aligned_alloc(size_t alignment, size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return aligned_alloc(alignment, size);
}

int __ov_posix_memalign(void **pointer, size_t alignment, size_t size) {
  if (ov_fails()) return ENOMEM;
  return posix_memalign(pointer, alignment, size);
}

void *__ov_memalign(size_t alignment, size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return memalign(alignment, size);
}

char *__ov_strdup(const char *string) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return strdup(string);
}

char *__ov_strndup(const char *string, size_t size) {
  if (ov_fails()) { errno = ENOMEM; return NULL; }
  return strndup(string, size);
}

/* C++'s operator new and new[] (riscv64, where size_t is unsigned long), in their mangled names. Each is in a section
 * of its own, which the link drops from a program that is not C++. */
typedef struct ov_nothrow ov_nothrow;
void *_Znwm(size_t size);
void *_Znam(size_t size);
void *_ZnwmRKSt9nothrow_t(size_t size, const ov_nothrow *tag);
void *_ZnamRKSt9nothrow_t(size_t size, const ov_nothrow *tag);
void *_ZnwmSt11align_val_t(size_t size, size_t alignment);
void *_ZnamSt11align_val_t(size_t size, size_t alignment);
void *_ZnwmSt11align_val_tRKSt9nothrow_t(size_t size, size_t alignment, const ov_nothrow *tag);
void *_ZnamSt11align_val_tRKSt9nothrow_t(size_t size, size_t alignment, const ov_nothrow *tag);
__attribute__((noreturn)) void _ZSt17__throw_bad_allocv(void); /* std::__throw_bad_alloc() */

void *__ov__Znwm(size_t size);
void *__ov__Znam(size_t size);
void *__ov__ZnwmRKSt9nothrow_t(size_t size, const ov_nothrow *tag);
void *__ov__ZnamRKSt9nothrow_t(size_t size, const ov_nothrow *tag);
void *__ov__ZnwmSt11align_val_t(size_t size, size_t alignment);
void *__ov__ZnamSt11align_val_t(size_t size, size_t alignment);
void *__ov__ZnwmSt11align_val_tRKSt9nothrow_t(size_t size, size_t alignment, const ov_nothrow *tag);
void *__ov__ZnamSt11align_val_tRKSt9nothrow_t(size_t size, size_t alignment, const ov_nothrow *tag);

void *__ov__Znwm(size_t size) {
  if (ov_fails()) _ZSt17__throw_bad_allocv();
  return _Znwm(size);
}

void *__ov__Znam(size_t size) {
  if (ov_fails()) _ZSt17__throw_bad_allocv();
  return _Znam(size);
}

void *__ov__ZnwmRKSt9nothrow_t(size_t size, const ov_nothrow *tag) {
  return ov_fails() ? NULL : _ZnwmRKSt9nothrow_t(size, tag);
}

void *__ov__ZnamRKSt9nothrow_t(size_t size, const ov_nothrow *tag) {
  return ov_fails() ? NULL : _ZnamRKSt9nothrow_t(size, tag);
}

void *__ov__ZnwmSt11align_val_t(size_t size, size_t alignment) {
  if (ov_fails()) _ZSt17__throw_bad_allocv();
  return _ZnwmSt11align_val_t(size, alignment);
}

void *__ov__ZnamSt11align_val_t(size_t size, size_t alignment) {
  if (ov_fails()) _ZSt17__throw_bad_allocv();
  return _ZnamSt11align_val_t(size, alignment);
}

void *__ov__ZnwmSt11align_val_tRKSt9nothrow_t(size_t size, size_t alignment, const ov_nothrow *tag) {
  return ov_fails() ? NULL : _ZnwmSt11align_val_tRKSt9nothrow_t(size, alignment, tag);
}

void *__ov__ZnamSt11align_val_tRKSt9nothrow_t(size_t size, size_t alignment, const ov_nothrow *tag) {
  return ov_fails() ? NULL : _ZnamSt11align_val_tRKSt9nothrow_t(size, alignment, tag);
}
