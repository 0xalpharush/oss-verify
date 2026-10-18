# Frequently asked questions

This page answers common questions about OSS Verifier. It is for maintainers and other readers. [glossary.md](glossary.md) defines the terms.

## Is OSS Verifier a fuzzer?

No. A fuzzer runs a fuzz target on many inputs. We prove theorems about the compiled fuzz target, for each input. We use the same fuzz targets as OSS-Fuzz ([what-gets-proven.md](what-gets-proven.md)).

## Must my project be in OSS-Fuzz?

No. You can use the project's own fuzz targets, its OSS-Fuzz fuzz targets, or new ones ([eligibility.md](eligibility.md)).

## Does my OSS-Fuzz build.sh work here?

Not without changes. Our builder is a cross-compiler for static riscv64 Linux programs. Port the build ([build-contract.md](build-contract.md)). The port is usually short.

## Which languages can you build?

The `language` field in [project-yaml.md](project-yaml.md#language) lists them.

## Why riscv64?

The process model, which the statements use, is a model of a riscv64 Linux process.

## What happens if you find a bug?

We send it privately to `primary_contact`, with a patch if you want one. We set no disclosure deadline, and we do not publish findings ([disclosure.md](disclosure.md)).

## Do you publish my proofs?

Yes, when the `publish` field tells us to. We never publish a statement that shows a finding that is not public ([publishing.md](publishing.md)).

## Can I choose which patches you send?

Yes. Use `disable_remediation` and the `patches` block in `project.yaml` ([patches.md](patches.md)).

## Can a coding agent enroll my project?

A coding agent can do most of the work with you. Tell it to read [AGENTS.md](../AGENTS.md). You open the pull request yourself.

## How can I check a binary myself?

Rebuild it with `tools/check --lock`. Then compare its SHA-256 with the lock ([reproducing.md](reproducing.md)).

## How do I pause or leave?

To pause, set `disabled: true` in `project.yaml`. To leave, remove `projects/<name>/`. Make each change in a pull request.
