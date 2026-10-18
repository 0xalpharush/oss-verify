# What gets proven

This repository says how to build a project's fuzz targets. The statements about them, and their proofs, are in [oss-verifier-proofs](https://github.com/theorem-labs/oss-verifier-proofs): one branch per project, holding Rocq statements about that project's binaries, their proofs, and the lock that pins the binaries. This page summarises what the statements say; the Rocq definitions there are what counts.

## About binaries, in a model of Linux

A statement is about the exact bytes of one fuzz target's binary in one build, `out/<target>/<target>.<build>`, pinned by its SHA-256 in the lock. It is stated over [linux-process-semantics](https://github.com/theorem-labs/linux-process-semantics), a formal model of a riscv64 Linux process, and it quantifies over every input the process could be given: the input file and its contents (or its absence), the arguments, the environment, and the rest of the process's world as the model defines it.

## The two main statements

* **Halts.** On every input on which the build stays within its memory budget ([memory-policy.md](memory-policy.md)), every execution exits with an accepted status, 0 or 2 ([exit-codes.md](exit-codes.md)). So it does not crash, fail an assertion, hang, or trip its sanitizer, on any such input.
* **Agrees.** On every input on which the plain build stays within its budget, neither the plain build nor the sanitizer build reaches an error, and the two have the same observable behaviour: the same bytes written and the same exit status. A sanitizer report aborts or traps, so this rules out every error that build's sanitizer checks.

Each project's branch in the proofs repository lists the statements for each fuzz target and build, and which are proved.

## Everything the fuzz target would catch, with a short list of exceptions

The statements catch everything the fuzz target would catch when OSS-Fuzz runs it, a crash, a hang, a failed assertion or a sanitizer report, on every input instead of the inputs a fuzzer happens to try. There are exceptions, and this is the whole list. Each is a limit of how the fuzz target is run here that cannot be lifted in these builds; none is a choice made per project.

* **Leaks.** Leak detection is off in the AddressSanitizer builds (`detect_leaks=0`): LeakSanitizer's check at exit cannot run in the sealed static runtime. A leak, which OSS-Fuzz reports, is not an error here.
* **Three UndefinedBehaviorSanitizer checks.** The UBSan builds trap on a failed check, with no runtime, and make clang's `undefined` checks ([build-contract.md](build-contract.md#the-builds)). OSS-Fuzz's UBSan builds also check `function`, which needs type metadata the trap mode does not keep, `vptr`, which needs a runtime, and `unsigned-integer-overflow`, which is not undefined behaviour and which correct code relies on. These builds do not.
* **No MemorySanitizer.** There is no MemorySanitizer build, so a read of uninitialised memory is not checked; OSS-Fuzz runs one for some projects. MemorySanitizer needs every library in the program, the C and C++ libraries included, built with it, which this static riscv64 toolchain does not provide.
* **One thread.** The process model runs a single thread. A fuzz target that starts a thread leaves the model, and its statements cannot be proved until the model covers threads.
* **Inputs below 64 MiB.** The driver refuses an input file of 64 MiB or more with status 2, so larger inputs are not covered.
* **The AddressSanitizer allocator's size classes.** On riscv64 the AddressSanitizer allocator refuses a request once the request's size class holds 3.5 GiB, less than the 16 GiB the plain build may use. An input that needs more of one size class is refused memory in the AddressSanitizer builds while the plain build is not, which is why their budgets differ ([memory-policy.md](memory-policy.md)).

*Draft, to be audited against the toolchain and the process model.*

## Say what "correct" means in the fuzz target

A statement covers what the fuzz target checks. A fuzz target that only feeds its input to the library proves only that the library does not crash, hang or trip a sanitizer on it. A fuzz target that checks a property, such as `decompress(compress(x)) == x` with `assert`, makes a proof of its halts statement a proof of that property for every input it covers. So whatever can be said in the fuzz target should be: the Rocq side keeps only what a fuzz target cannot express.

There are three kinds of fuzz target:

* the project's own, from its repository;
* OSS-Fuzz's, from the project's OSS-Fuzz directory;
* ones we write with the project, kept in `projects/<name>/`, including drivers that call the library's API in sequences the input describes. Anything that needs a different sanitizer runtime configuration becomes a fuzz target of its own.

## What a proof covers, and what it does not

A proof covers:

* the binary's own bytes: the library, the fuzz target and the driver as compiled for that build;
* every input within the budget, including every input file up to 64 MiB (the driver refuses larger ones with status 2);
* in a sanitizer build, every check that build makes ([build-contract.md](build-contract.md#the-builds)).

It does not cover:

* the library's source in general: another compiler, other flags, another architecture, or OSS-Fuzz's own x86-64 builds;
* the exceptions above, and errors no sanitizer checks, here or in OSS-Fuzz, such as an access through another live object;
* code no sanitizer instruments: the C library, the compiler's runtime libraries and the sanitizer runtime itself, which a sanitizer statement covers only as uninstrumented code, as OSS-Fuzz's builds leave them uninstrumented too;
* inputs that need more memory than the budget;
* what the process model leaves out. The model's documentation says where it is narrower than Linux.

## Where the claims come from

Every public claim traces back to three pinned inputs: the project's source commit, the commit of this repository that holds the build recipe, and the digest of the toolchain image. A published proof checks against the released process model, that recipe and the project's upstream source as it is, with no patch that changes the library ([publishing.md](publishing.md)).
