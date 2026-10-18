# Publishing proofs

This page tells when and where we publish the statements and proofs about a project, and what we publish. It is for maintainers.

## When: `publish`

The `publish` field in `project.yaml` tells us when to publish:

| value | we publish the proofs |
|---|---|
| `after_fixes` (the default) | when each patch that we sent you is public or in your project |
| `eager` | while we work on them |
| `never` | never outside Theorem |

Each value obeys these rules:

* We publish nothing that shows a finding that is not public yet ([disclosure.md](disclosure.md)). We hold back the statements that the finding affects until it is public. What we publish does not tell why.
* We publish a seeded project only while it has no findings.

## Where: `proofs`

By default, we publish to the branch with the project's name in [oss-verifier-proofs](https://github.com/theorem-labs/oss-verifier-proofs), in the directory `projects/<name>`:

```yaml
proofs:
  repo: https://github.com/theorem-labs/oss-verifier-proofs#<name>
  path: projects/<name>
```

Most projects do not set this field.

## What we publish

We publish three items:

* the statements about the project's binaries;
* the proofs of these statements;
* the lock: the SHA-256 of each binary, the commit that we built it from, and the toolchain.

We write the lock from the manifest of `tools/check` ([build-contract.md](build-contract.md#the-manifest)). Thus you can rebuild each binary and compare it with the lock ([reproducing.md](reproducing.md)).

A published proof rests on public inputs only:

* the released process model;
* the build files in this repository, at a published commit;
* your project's source as it is.

A published build never contains a patch that changes your library. It can contain build patches only ([project-yaml.md](project-yaml.md#the-files-in-the-project-directory)).
