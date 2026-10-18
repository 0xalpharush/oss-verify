# What gets proven

This repository says how to build a project's fuzz targets. The statements about them, and their proofs, are in [oss-verifier-proofs](https://github.com/theorem-labs/oss-verifier-proofs): one branch per project, holding Rocq statements about that project's binaries, their proofs, and the lock that pins the binaries. This page summarises what the statements say; the Rocq definitions there are what counts.

## About binaries, in a model of Linux

A statement is about the exact bytes of one fuzz target's binary in one build, `out/<target>/<target>.<build>`, pinned by its SHA-256 in the lock. It is stated over [linux-process-semantics](https://github.com/theorem-labs/linux-process-semantics), a formal model of a riscv64 Linux process, and it quantifies over every input the process could be given: the input file and its contents (or its absence), the arguments, the environment, and the rest of the process's world as the model defines it.

## The two main statements

* **Halts.** On every input on which the build stays within its memory budget ([memory-policy.md](memory-policy.md)), every execution exits with an accepted status, 0 or 2 ([exit-codes.md](exit-codes.md)). So it does not crash, fail an assertion, hang, or trip its sanitizer, on any such input.
* **Agrees.** On every input on which the plain build stays within its budget, neither the plain build nor the sanitizer build reaches an error, and the two have the same observable behaviour: the same bytes written and the same exit status. A sanitizer report aborts or traps, so this rules out every error that build's sanitizer checks.

Each project's branch in the proofs repository lists the statements for each fuzz target and build, and which are proved.

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
* errors the build's sanitizers do not check: an unsigned overflow, a memory leak, a read of uninitialised memory, or an access through another live object;
* code no sanitizer instruments: the C library, the compiler's runtime libraries and the sanitizer runtime itself, which a sanitizer statement covers only as uninstrumented code;
* inputs that need more memory than the budget;
* what the process model leaves out. The model's documentation says where it is narrower than Linux.

## Where the claims come from

Every public claim traces back to three pinned inputs: the project's source commit, the commit of this repository that holds the build recipe, and the digest of the toolchain image. A published proof checks against the released process model, that recipe and the project's upstream source as it is, with no patch that changes the library ([publishing.md](publishing.md)).
