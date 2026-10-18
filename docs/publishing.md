# Publishing proofs

The statements and proofs about a project are pushed to the repository and directory its `project.yaml` names, when its `publish` field says.

## When: `publish`

| value | the proofs are pushed |
|---|---|
| `after_fixes` (the default) | once every patch we sent you is public or upstreamed |
| `eager` | as the proofs progress |
| `never` | never outside Theorem |

Whatever `publish` says, we publish nothing that describes a finding that is not public yet ([disclosure.md](disclosure.md)): the statements a finding affects are held back until it is, and nothing published says why. A project we seeded ourselves (`primary_contact: n/a`) is published only while it has no findings at all.

## Where: `proofs`

By default, the branch named after the project in [oss-verifier-proofs](https://github.com/theorem-labs/oss-verifier-proofs), directory `projects/<name>`:

```yaml
proofs:
  repo: https://github.com/theorem-labs/oss-verifier-proofs#<name>
  path: projects/<name>
```

Most projects leave it out.

## What is published, and what it rests on

The project's statements, their proofs, and the lock: the SHA-256 of every binary they are about, with the commit it was built from. The lock is the only place that commit is recorded. It is to be written from the manifest `tools/check` produces ([build-contract.md](build-contract.md#the-manifest)), so anyone can rebuild the binaries and compare.

A published proof checks against stock inputs: the released process model, the build recipe in this repository at a published commit, and the project's upstream source as it is. A patch that changes the library is never part of a published build; only build-only patches are ([project-yaml.md](project-yaml.md#files-beside-projectyaml)).
