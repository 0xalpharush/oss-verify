// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

//! The Rust half of the adapter of a Rust fuzz target: a panic and an allocation failure end the program with the
//! driver's exit statuses (docs/build-contract.md), not with SIGABRT, which in the AddressSanitizer builds is the
//! signal of a detection.
//!
//!   79  a panic: a failed assert!, an unwrap, an overflow check or a UB check
//!   2   an allocation failure, the status the driver gives when it has no memory
//!
//! Each hook is a plain fn, so installing them allocates nothing and makes no system call. Each calls into C
//! (driver/plugin_rust.h), which writes one line in the loud build and calls _exit. libfuzzer-sys installs a panic
//! hook that calls abort() after the previous hook; ours, installed before main, is that previous hook, and exits
//! first.
#![feature(alloc_error_hook)]

use std::alloc::Layout;
use std::panic::PanicHookInfo;

extern "C" {
    fn oft_rust_panicked(file: *const u8, file_len: usize, line: u32, col: u32) -> !;
    fn oft_rust_alloc_failed(size: usize, align: usize) -> !;
}

fn panic_hook(info: &PanicHookInfo<'_>) {
    let (file, line, col) = match info.location() {
        Some(l) => (l.file(), l.line(), l.column()),
        None => ("", 0, 0),
    };
    unsafe { oft_rust_panicked(file.as_ptr(), file.len(), line, col) }
}

fn alloc_hook(layout: Layout) {
    unsafe { oft_rust_alloc_failed(layout.size(), layout.align()) }
}

/// Called once, from plugin_rust.h's constructor, before main.
#[no_mangle]
pub extern "C" fn oft_rust_install_hooks() {
    std::panic::set_hook(Box::new(panic_hook));
    std::alloc::set_alloc_error_hook(alloc_hook);
}
