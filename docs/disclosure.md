# Disclosure

This page tells what we do with a finding. It is for maintainers and for security readers.

When we work on a proof, we can find a failure instead. An example is an input on which a fuzz target crashes, hangs, fails an assertion or fails a sanitizer check. We call this failure a finding.

## Our rules

* **We send the finding to you privately.** We send it to `primary_contact` and to each address in `auto_ccs`. If you set `pgp`, we encrypt the finding to your key and send it to `primary_contact` only.
* **There is no disclosure deadline.** We do not set a date on which a finding becomes public.
* **We do not publish findings.** You decide if and when a finding becomes public.
* **What we publish does not show the finding.** Until the finding is public, we hold back the statements that it affects. No file name, comment, patch or statement that we publish describes it ([publishing.md](publishing.md)).

Each finding contains the input, the build and the binary, the steps to reproduce it, and a patch if you want one ([patches.md](patches.md)).

## Seeded projects

A seeded project has `primary_contact: n/a`, because no maintainer has adopted it yet. We publish a seeded project only because it has no findings.

* We send a finding for a seeded project to no one. Nothing goes automatically to the project, to its security contact or to another person.
* There is no deadline.
* The finding stays with us until a person gives it to the project by hand.
* While the finding stands, we do not publish the project's statements and proofs.

## A vulnerability in this repository

To report a vulnerability in this repository or its tools, follow [SECURITY.md](../SECURITY.md).
