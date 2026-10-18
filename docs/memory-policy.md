# Memory policy and budgets

A program can run out of memory, and a statement about it has to say what happens then. These are the rules the statements follow.

## The rules

* **Exhaustion is part of the statement.** A memory request is refused only when the build has spent its budget (below). When that happens the program may be killed for lack of memory, and that is allowed. Every run must still halt.
* **Surviving a refused allocation is the job of a separate fuzz target.** A project that wants its library held to recovering from allocation failure adds an allocation-failure entry point, in which allocations fail as the input says ([exit-codes.md](exit-codes.md#allocation-failure)). The other fuzz targets are not asked to survive refusals.
* **Refusals during start-up are not considered.** A statement does not cover the program being refused memory before it reaches the fuzz target.
* **No statement lets an allocation fail at random**, and there is no project.yaml setting for out-of-memory behaviour.

## Budgets

A budget is an amount of memory a build may allocate. It is a premise of the statement: an input that needs more is not covered, rather than a failure.

```yaml
budgets:
  halts: 16GiB               # each build run alone
  agrees:                    # per sanitizer: [plain side, sanitizer side]
    address: [2GiB, 512GiB]  # also used for asan-ubsan
    undefined: [16GiB, 512GiB]
```

* `halts` is the budget of each build run on its own, in the statement that it halts with an accepted status.
* `agrees.<sanitizer>` is the pair of budgets in the statement that a sanitizer build behaves as the plain build does: the plain build's, which is the premise, and the sanitizer build's, which is generous because a sanitizer needs memory of its own. `address` applies to the `asan` and `asan-ubsan` builds, and `undefined` to `ubsan`.
* The plain side of `address` is 2 GiB because the sealed AddressSanitizer allocator caps each size class well below 16 GiB. The address space the AddressSanitizer runtime reserves at start-up, well over 100 GiB, is not charged to any budget.

These are the values oss-fuzz-theorems 2026.10.0-rc.2 uses, and the defaults. A project may set its own in `project.yaml` ([project-yaml.md](project-yaml.md)): a size is a positive number of bytes, or a number with `KiB`, `MiB`, `GiB` or `TiB`. Set only what you want to change.

**Not decided yet:** whether the `asan` and `asan-ubsan` builds should have a smaller `halts` budget. Their allocator refuses a request once one size class holds a few GiB, which is less than 16 GiB, so an input could be refused memory in those builds while still within the budget. [STATUS.md](../STATUS.md) tracks the open questions.
