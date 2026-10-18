# Exit codes

Every fuzz target is linked with the same small driver, `$LIB_FUZZING_ENGINE` ([infra/base-builder/driver/](../infra/base-builder/driver/)), in place of libFuzzer. A binary is run as `<binary> <input-file>`. The driver reads the input file whole and splits it as

    [u16 config word][config bytes][u32 allocation mask][payload]

with both integers little-endian. The low 15 bits of the config word are the length of the config bytes. The driver calls `LLVMFuzzerTestOneInput` on the payload `(config[0] & 3) + 1` times (once when there is no config) and prints each return value on standard output. An OSS-Fuzz testcase therefore needs the six bytes `00 00 00 00 00 00` in front of it. An OSS-Fuzz harness ignores the allocation mask; an allocation-failure entry point uses it (below).

## The statuses

| status | meaning |
|---:|---|
| 0 | every call of the fuzz target returned 0 or -1 |
| 2 | the driver refused the input without calling the fuzz target: a wrong argument count, an input file it cannot open or read, one shorter than its six-byte header or of 64 MiB or more, or no memory to read it into |
| 77 | the fuzz target called `exit()` |
| 78 | a call returned a value other than 0 or -1 |
| 134 | `abort()`: a failed `assert()`, an AddressSanitizer detection, or an uncaught C++ exception |
| 132 | `SIGILL`: a failed UndefinedBehaviorSanitizer check, which traps in these builds |
| 139 | `SIGSEGV`: a crash |

A sanitizer detection prints nothing: AddressSanitizer aborts silently, and UndefinedBehaviorSanitizer has no runtime and traps ([build-contract.md](build-contract.md)).

`tools/tests/test_builder.py` checks each of these statuses, in all four builds, on a C and a C++ fuzz target built with the builder. One detail it shows: UBSan does not check a `volatile` access for a null pointer, so a load through a volatile null pointer is a crash (139) even in the UBSan builds, where a non-volatile one traps (132).

## What a statement accepts

Statements accept only the statuses **0 and 2**. Anything the fuzz target treats as an expected outcome must therefore end as `return 0`: rejecting malformed input, hitting a limit, a library error code. The fuzz target is the place to say what "correct" means ([what-gets-proven.md](what-gets-proven.md)). A fuzz target that returns 1 for "not interesting" input, as some OSS-Fuzz harnesses do, makes its statement false.

## What the driver does not intercept

The driver turns a call of `exit()` during a call of the fuzz target into status 77, with an `atexit` handler. It does not intercept `_exit`, `_Exit` or `quick_exit`, which skip `atexit` handlers: a fuzz target that calls one of them ends the process with whatever status it passed (`test_builder.py` shows it). Extending the interception to those, by link-time wrapping, and an opt-in hook with which a fuzz target declares which exit statuses are acceptable, belong to the toolchain, not to this repository.

The driver never intercepts a signal or `abort()`. Doing so would hide a sanitizer's detection, and a harness must not do it either: no `SIGABRT` handler, no `SIGSEGV` handler.

## Allocation failure

A project that wants its library held to surviving allocation failure adds a separate fuzz target for it. In that target, the library's allocations fail as the input's allocation mask says. The fuzz target turns the resulting out-of-memory stops into normal exits, and only those: it catches `std::bad_alloc`, or uses the library's own allocation-failure hooks. No catch-all handler, no `SIGABRT` handler. The other fuzz targets are left alone ([memory-policy.md](memory-policy.md)).

To make one, link the fuzz target's object files a second time, into a binary of its own, with `$LIB_ALLOCATION_FAILURE_ENGINE` in place of `$LIB_FUZZING_ENGINE`:

    $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_allocation_failure" $LIB_ALLOCATION_FAILURE_ENGINE libexample.a

The fuzz target linked with `$LIB_FUZZING_ENGINE` is unchanged, byte for byte. The allocation-failure link differs from it in two ways ([link-fuzz-target](../infra/base-builder/link-fuzz-target)):

* The driver's adapter is [allocation_failure.c](../infra/base-builder/driver/allocation_failure.c) instead of `adapter.c`.
* The object files and archives the link names, the project's code, are linked as copies in which every call of `malloc`, `calloc`, `realloc`, `reallocarray`, `aligned_alloc`, `posix_memalign`, `memalign`, `strdup`, `strndup`, and C++'s `operator new` and `operator new[]` (with their nothrow and aligned forms) goes to that adapter. A link that compiles a source file itself is refused: compile the fuzz target first, and link its object file.

While `LLVMFuzzerTestOneInput` runs, the adapter counts those calls from 0, over all of a run's calls of the fuzz target. The n-th call fails if bit n of the allocation mask is set: it returns `NULL` with `errno` set to `ENOMEM` (`posix_memalign` returns `ENOMEM`), and `operator new` throws `std::bad_alloc` (its nothrow form returns `NULL`). Calls after the 32nd never fail. Nothing else is counted: not the driver's allocations, not `LLVMFuzzerInitialize`'s, and not those the C or C++ library makes inside a function the project called (such as `fopen`, or a `std::string` member compiled into the C++ library). So an input makes the same calls fail in all four builds. The builds compile with `-fno-builtin-malloc` and the like, so the compiler keeps every call.

Bit 15 of the config word asks for counting mode. There, an allocation-failure fuzz target exits with the number of calls it counted (251 if there were more), whatever the fuzz target returned; an OSS-Fuzz-style fuzz target, which counts nothing, exits with 0. Counting mode lets a fuzzer or a person find the allocations an input makes. How a statement about an allocation-failure fuzz target treats counting mode is not decided yet ([STATUS.md](../STATUS.md)).

`tools/tests/test_builder.py` checks the mask, counting mode and `std::bad_alloc` in all four builds, on the allocation-failure variants of its C and C++ fuzz targets. cjson's `build.sh` builds one, `cjson_read_fuzzer_allocation_failure`.
