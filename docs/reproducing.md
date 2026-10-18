# Reproducing a binary

This page tells how to rebuild a binary and compare it with the lock, and how to run a binary on an input. It is for readers who want to check our claims themselves.

## Why the bytes matter

A statement is about the exact bytes of one binary. The lock in the proofs repository pins these bytes with their SHA-256, together with the commit and the toolchain. If you rebuild the binary and get the same SHA-256, the statement is about the program that you built.

We pin only binaries that two clean builds reproduce. Before we pin a binary, we build it two times from the start and compare each byte. `tools/check --twice` makes the same test.

## What you need

* git, Docker, and Python 3 with PyYAML (`pip install pyyaml`);
* a checkout of this repository;
* the lock of the project;
* the toolchain image that the lock names ([build-contract.md](build-contract.md#toolchains)).

## Rebuild a binary and compare it with the lock

> **WARNING:** `tools/check` builds the project's `Dockerfile` with network access, as `docker build` does. Use it only on a project that you trust ([SECURITY.md](../SECURITY.md)).

1. Get the project's lock from the proofs repository.
2. Check out this repository at the commit that the lock gives in `oss_verifier.commit`.
3. Run `tools/check --no-shell --lock <lock> <name>`.
4. Read the last line of the output.

`tools/check` builds the commit that the lock names, with the toolchain that the lock names. It then compares the SHA-256 of each binary with the lock:

* `matches the lock` tells you that each binary that the lock pins has the same bytes.
* `DIFFERENT FROM THE LOCK` lists each binary that has different bytes.

`tools/check` also accepts a `harness.yaml` of oss-fuzz-theorems 2026.10.0-rc.2 as a lock. Use this to check a binary of that release.

If the bytes differ, open an issue in this repository. Include the output of `tools/check`.

## Run a binary on an input

Each binary is a static Linux program for riscv64. Run it on a riscv64 machine, or with `qemu-riscv64` on another Linux machine:

    qemu-riscv64 out/<target>/<target>.<build> <input file>

The driver reads the input file in a format of its own ([exit-codes.md](exit-codes.md)). To give it an OSS-Fuzz testcase, put six zero bytes in front of the testcase:

    { printf '\0\0\0\0\0\0'; cat testcase; } > input

> **WARNING:** Do not limit the address space of an `asan` or `asan-ubsan` binary, for example with `ulimit -v`. At start, the AddressSanitizer runtime reserves more than 100 GiB of address space. If it cannot, it waits forever.

The exit status tells the result. [exit-codes.md](exit-codes.md#the-exit-statuses) lists each status.
