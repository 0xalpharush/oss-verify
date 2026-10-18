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

The builder does not provide such a target's driver yet: the one it links today, for OSS-Fuzz-style fuzz targets, ignores the allocation mask ([STATUS.md](../STATUS.md)).
