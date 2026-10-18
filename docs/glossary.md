# Glossary

This page defines the terms that the OSS Verifier documents use. It is for every reader. Each document uses each term with the meaning given here.

**Allocation-failure fuzz target.** A fuzz target in which allocations fail as the input tells them to. It shows that the library survives refused allocations ([exit-codes.md](exit-codes.md#allocation-failure)).

**Binary.** One fuzz target, compiled for one build. We publish the stripped bytes of each binary and pin their SHA-256 in the lock.

**Budget.** The quantity of memory that a build can use in a statement. An input that needs more memory is not in the statement ([what-gets-proven.md](what-gets-proven.md#memory-budgets)).

**Build.** One of the four ways we compile each fuzz target: `plain`, `ubsan`, `asan` and `asan-ubsan`. Each build makes its own binaries and has its own statements.

**Build patch.** A file in the project directory that changes only how the project builds. A build patch never fixes a bug, and we never send one to you.

**Builder.** The Docker image that builds each project. `tools/check` makes it from [infra/base-builder/](../infra/base-builder/) and a toolchain image.

**Core maintainer.** A person who maintains the project and can merge changes into it. Only a core maintainer can enroll a project ([eligibility.md](eligibility.md)).

**Draft branch.** A branch named `draft-generic-oss-fuzz-<name>` that holds a seeded project. A maintainer can adopt it ([enrollment.md](enrollment.md#adopt-a-seeded-project)).

**Driver.** The code that reads the input file and calls the fuzz target. It takes the place of libFuzzer ([exit-codes.md](exit-codes.md)).

**Finding.** A failure that we find while we work on a proof: for example, an input on which a fuzz target crashes. We send each finding to the project privately ([disclosure.md](disclosure.md)).

**Fuzz target.** A function `LLVMFuzzerTestOneInput` and the program that the build makes from it. OSS-Fuzz also calls it a harness.

**Lock.** The file in the proofs repository that pins each binary of a project: its SHA-256, the commit, and the toolchain.

**Manifest.** The file `manifest.yaml` that `tools/check` writes. It lists each binary and its SHA-256 ([build-contract.md](build-contract.md#the-manifest)).

**Patch.** A change to your project that our agents write and send to you, usually with a finding. It can remove a failure, correct the documentation, or make the code easier to verify ([patches.md](patches.md)).

**Process model.** The formal model of a riscv64 Linux process, [linux-process-semantics](https://github.com/theorem-labs/linux-process-semantics), that the statements use.

**Project directory.** The directory `projects/<name>/` in this repository. It holds `project.yaml` and, usually, the build files.

**Proof.** A machine-checked proof of a statement, in Rocq.

**Proofs repository.** The repository [oss-verifier-proofs](https://github.com/theorem-labs/oss-verifier-proofs), which holds the statements, the proofs and the locks.

**Seeded project.** A project that we added ourselves, with `primary_contact: n/a`. No maintainer has adopted it yet.

**Statement.** A theorem about one binary, for example that the binary always halts with an accepted exit status ([what-gets-proven.md](what-gets-proven.md)).

**Toolchain.** The Docker image with the compiler, the C library and the sanitizer runtimes. The builder is made from a toolchain ([build-contract.md](build-contract.md#toolchains)).

**Vintage.** The toolchain that a project's binaries are built with. The lock pins the vintage.
