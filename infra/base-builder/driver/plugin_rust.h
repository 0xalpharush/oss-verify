/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The C half of the adapter of a Rust fuzz target (rust/oft-rust-rt is the Rust half). It adds two exit statuses to
 * ossfuzz_adapter.h's, which it includes unchanged:
 *
 *   79  a Rust panic
 *   2   a Rust allocation failure, the status the driver gives when it has no memory
 *
 * The loud build writes one line on standard error, made with snprintf into a buffer on the stack and one write(2), so
 * that the allocation-failure path does not allocate. HARNESS_QUIET writes nothing.
 *
 * With OFT_RUST_QUIET_STDIO, it also defines the byte that the sealed standard library of a quiet-stdio build reads:
 * 1 in the quiet link, 0 in the loud one.
 *
 * From the build recipe of the oss-fuzz-theorems 2026.10 release (src/plugin_rust.h), in its release spelling. The
 * code is unchanged but for the names of the three functions that the Rust half and this file share, which change no
 * byte of a binary; the comments are new.
 */
#ifndef OFT_PLUGIN_RUST_H
#define OFT_PLUGIN_RUST_H

#include "ossfuzz_adapter.h"

#define OFT_RUST_PANICKED 79
#define OFT_RUST_ALLOC_FAILED 2

void oft_rust_install_hooks(void);

__attribute__((noreturn)) void oft_rust_panicked(const char *file, size_t file_len,
                                                 unsigned line, unsigned col);
__attribute__((noreturn)) void oft_rust_alloc_failed(size_t size, size_t align);

#ifdef HARNESS_QUIET
#define OFT_RUST_DIAG(...) ((void)0)
#else
#define OFT_RUST_DIAG(...)                                        \
  do {                                                           \
    char oft_b[512];                                             \
    int oft_n = snprintf(oft_b, sizeof oft_b, __VA_ARGS__);      \
    if (oft_n > (int)sizeof oft_b - 1) oft_n = sizeof oft_b - 1;  \
    if (oft_n > 0) (void)!write(2, oft_b, (size_t)oft_n);         \
  } while (0)
#endif

void oft_rust_panicked(const char *file, size_t file_len, unsigned line, unsigned col) {
  OFT_RUST_DIAG("oft-rust: panic at %.*s:%u:%u\n", (int)(file_len > 400 ? 400 : file_len),
                file, line, col);
  fflush(stdout);
  _exit(OFT_RUST_PANICKED);
}

void oft_rust_alloc_failed(size_t size, size_t align) {
  OFT_RUST_DIAG("oft-rust: allocation of %zu bytes (align %zu) failed\n", size, align);
  fflush(stdout);
  _exit(OFT_RUST_ALLOC_FAILED);
}

/* Before main, so that the hooks also cover LLVMFuzzerInitialize and the first call. */
__attribute__((constructor)) static void oft_rust_ctor(void) { oft_rust_install_hooks(); }

#ifdef OFT_RUST_QUIET_STDIO
#ifdef HARNESS_QUIET
const unsigned char oft_rust_quiet_stdio = 1;
#else
const unsigned char oft_rust_quiet_stdio = 0;
#endif
#endif

#endif /* OFT_PLUGIN_RUST_H */
