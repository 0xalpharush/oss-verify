# The driver and its exit statuses

This page describes the driver that each fuzz target is linked with: its input format, its exit statuses and its allocation-failure mode. It is for people who write fuzz targets and for people who run binaries.

## The driver

The driver takes the place of libFuzzer. Each fuzz target is linked with it through `$LIB_FUZZING_ENGINE` ([infra/base-builder/driver/](../infra/base-builder/driver/)). Run a binary with one argument, the input file:

    <binary> <input file>

The driver reads the whole input file. It divides the file into four parts:

    [u16 config word][config bytes][u32 allocation mask][payload]

The two integers are little-endian.

* The low 15 bits of the config word give the length of the config bytes. The top bit, bit 15, asks for counting mode ([below](#counting-mode)).
* The driver calls `LLVMFuzzerTestOneInput` on the payload `(config[0] & 3) + 1` times. With no config bytes, it calls it once.
* The driver writes each return value on standard output.
* A fuzz target linked with `$LIB_FUZZING_ENGINE` ignores the allocation mask. An allocation-failure fuzz target uses it ([below](#allocation-failure)).

Thus an OSS-Fuzz testcase needs six zero bytes in front of it: `00 00 00 00 00 00`.

## The exit statuses

| status | meaning |
|---:|---|
| 0 | each call of the fuzz target returned 0 or -1 |
| 2 | the driver refused the input and did not call the fuzz target ([below](#status-2)) |
| 77 | the fuzz target called `exit()` |
| 78 | a call of the fuzz target returned a value that is not 0 or -1 |
| 132 | `SIGILL`: an UndefinedBehaviorSanitizer check failed (the check traps in these builds) |
| 134 | `abort()`: a failed `assert()`, an AddressSanitizer detection, or an uncaught C++ exception |
| 139 | `SIGSEGV`: a crash |

### Status 2

The driver refuses the input with status 2 for these causes:

* the number of arguments is not one;
* it cannot open or read the input file;
* the file is shorter than its six-byte header;
* the file is 64 MiB or larger;
* it gets no memory to read the file into.

A sanitizer detection writes nothing. AddressSanitizer aborts silently. UndefinedBehaviorSanitizer has no runtime and traps ([build-contract.md](build-contract.md#the-builds)).

`tools/tests/test_builder.py` checks each status in all four builds, on a C fuzz target and a C++ fuzz target. It also shows a special case: UndefinedBehaviorSanitizer does not check a `volatile` access for a null pointer. Thus a load through a `volatile` null pointer crashes with 139 in each build. A load through a pointer that is not `volatile` traps with 132 in the UBSan builds.

## What a statement accepts

A statement accepts only the statuses **0 and 2**. Thus each expected outcome must end as `return 0`. Examples of expected outcomes are malformed input that the library rejects, a size limit, and an error code from the library.

> **WARNING:** Do not return 1 for an input that is not of interest, as some OSS-Fuzz fuzz targets do. That return value makes the statement false.

The fuzz target is the place to tell what "correct" means ([what-gets-proven.md](what-gets-proven.md#write-correct-into-the-fuzz-target)).

## What the driver does not intercept

The driver changes a call of `exit()`, during a call of the fuzz target, into status 77. An `atexit` handler does this. The driver does not intercept `_exit`, `_Exit` or `quick_exit`, which do not run `atexit` handlers. A fuzz target that calls one of them ends the process with the status that it gave. `test_builder.py` shows this.

> **WARNING:** Do not install a handler for `SIGABRT`, `SIGSEGV` or another signal in a fuzz target. A handler hides a sanitizer detection.

The driver itself never intercepts a signal or `abort()`.

## Allocation failure

An allocation-failure fuzz target shows that the library survives refused allocations. In it, the allocations fail as the allocation mask of the input tells them to. The other fuzz targets do not get refused allocations ([what-gets-proven.md](what-gets-proven.md#allocation-failure)).

The fuzz target must change an out-of-memory stop into a normal exit, and only that stop. To do this, catch `std::bad_alloc`, or use the library's own hooks for allocation failure.

> **WARNING:** Do not catch all exceptions. Do not install a `SIGABRT` handler. Such code hides failures that the statements must show.

To make an allocation-failure fuzz target, link the object files of a fuzz target again, into a different binary, with `$LIB_ALLOCATION_FAILURE_ENGINE`:

    $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_allocation_failure" $LIB_ALLOCATION_FAILURE_ENGINE libexample.a

The fuzz target that you link with `$LIB_FUZZING_ENGINE` does not change. The allocation-failure link is different in two ways ([link-fuzz-target](../infra/base-builder/link-fuzz-target)):

* The driver uses [allocation_failure.c](../infra/base-builder/driver/allocation_failure.c) in place of `adapter.c`.
* The link uses copies of its object files and archives. In these copies, each call of an allocation function goes to the driver. These are the allocation functions:

      malloc calloc realloc reallocarray aligned_alloc posix_memalign memalign strdup strndup
      operator new, operator new[] (C++), with their nothrow and aligned forms

Compile the sources of the fuzz target before the link. Then link the object files. The link refuses a source file.

While `LLVMFuzzerTestOneInput` runs, the driver counts these calls from 0, over all calls of the fuzz target in a run. Call n fails if bit n of the allocation mask is set:

* `malloc` and the other functions return `NULL` and set `errno` to `ENOMEM`;
* `posix_memalign` returns `ENOMEM`;
* `operator new` throws `std::bad_alloc`, and its nothrow form returns `NULL`.

Calls after the 32nd never fail. The driver counts no other allocations. It does not count its own allocations, or those of `LLVMFuzzerInitialize`. It does not count the allocations that the C or C++ library makes inside a function that the project called. Thus an input makes the same calls fail in all four builds. The builds compile with `-fno-builtin-malloc` and the related flags, so the compiler keeps each call.

### Counting mode

In counting mode, the driver exits with a count in place of the status of the fuzz target. A statement accepts only 0 and 2. Thus a published allocation-failure fuzz target ignores counting mode: with `$LIB_ALLOCATION_FAILURE_ENGINE`, it exits as it does without counting mode.

A fuzz target linked with `$LIB_FUZZING_ENGINE` counts nothing. In counting mode it exits with 0, whatever it returned.

To find which allocations an input makes, link a sweep or test build with `$LIB_ALLOCATION_COUNTING_ENGINE`. We never publish such a build. It is the same as `$LIB_ALLOCATION_FAILURE_ENGINE`, with one difference. In counting mode, it exits with the number of calls that it counted, or 251 if there were more.

`tools/tests/test_builder.py` checks the mask, counting mode and `std::bad_alloc` in all four builds, with each engine. It also builds cJSON's fuzz target with both engines ([tools/tests/fixtures/cjson](../tools/tests/fixtures/cjson/build.sh)). The test shows three results. The fuzz target keeps the release's bytes. An input that makes 21 allocations gets the same count in each build. If any one allocation fails, or all fail, the fuzz target still exits with 0.
