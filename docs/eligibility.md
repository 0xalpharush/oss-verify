# Which projects we accept

This page tells which projects OSS Verifier accepts. It is for a maintainer who decides whether to enroll a project.

## Who can enroll a project

Only a core maintainer of a project can enroll it. Before we merge an enrollment pull request, we make sure of these points:

* The person who opened the pull request maintains the project.
* `primary_contact` is the project's security contact. For example, the project's security policy gives this address.
* The person accepts the [OSS Verifier terms](https://theorem.dev/oss-verifier/terms/).

The triage comment on the pull request helps us to examine these points. A comment does not decide; a person reviews each enrollment.

## What a project needs

A project must have all of these:

1. **Open source in a public git repository.** We get the source anonymously over `https`.
2. **One repository.** One project directory names one repository. Fetch the other parts of the build, such as dependencies, in the `Dockerfile`.
3. **At least one fuzz target.** A fuzz target is a function `LLVMFuzzerTestOneInput`. You can use the project's own fuzz targets, its OSS-Fuzz fuzz targets, or new ones that you write.
4. **A build that our builder can do.** The builder makes static Linux programs for riscv64. The `language` field in [project-yaml.md](project-yaml.md#language) lists the languages that it can build today.
5. **A security contact.** We send each finding to this address ([disclosure.md](disclosure.md)).

## What we can decline

We can decline a project that we cannot build, or that we cannot verify with the tools that we have today. If we decline a project, we tell you why in the pull request.

## Projects that we seeded

We added some projects ourselves, on draft branches. A core maintainer can adopt such a project ([enrollment.md](enrollment.md#adopt-a-seeded-project)).
