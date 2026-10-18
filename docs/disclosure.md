# Disclosure

Working on a proof sometimes finds a bug instead: an input on which a fuzz target crashes, hangs, fails an assertion or trips its sanitizer. This page says what we do with it.

* **It goes to you, privately.** A finding is sent to `primary_contact` and every address in `auto_ccs`. With `pgp` set, it is encrypted to that key and goes to `primary_contact` only. It includes the input, the build and binary it was found in, how to reproduce it, and, where we have one, a proposed patch written the way your `patch_style.md` asks.
* **There is no disclosure deadline.** We do not set a date by which a finding becomes public.
* **We do not publish findings.** Making a finding public, and when, is up to you.
* **Nothing we publish gives it away.** Until a finding is public, the statements it affects are held back, and no file name, comment, patch or statement we publish describes it ([publishing.md](publishing.md)).

A project we seeded ourselves, which no maintainer has adopted yet (`primary_contact: n/a`), is different: it is published only because it has no findings. A finding for such a project is sent nowhere. Nothing goes to the project, its security contact or anyone else automatically, and there is no deadline; the finding stays with us unless someone hands it over by hand. While it stands, the project's statements and proofs are not published.

To report a vulnerability in this repository or its tools, see [SECURITY.md](../SECURITY.md).
