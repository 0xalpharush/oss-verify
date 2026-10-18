# Patches and how to choose them

This page tells which patches we send with findings, and how you choose them. It is for maintainers.

A finding is a failure that we find while we work on a proof ([disclosure.md](disclosure.md)). With each finding, we can send a patch: a change to your project that removes the failure. Our agents write the patches. Review each patch as you review any other contribution.

## What a finding contains

Each finding contains these items:

* the input that causes the failure;
* the build and the binary in which it occurs;
* the steps to reproduce it ([reproducing.md](reproducing.md));
* a patch, if we have one and you want patches.

## Get findings without patches

Set `disable_remediation: true` in `project.yaml`. We then send each finding without a patch. OSS-Fuzz uses the same field name.

## Choose which patches we write

The `patches` block in `project.yaml` tells our agents which patches to write. Each key is optional. If you do not give a key, we use its default, which is the first value below.

```yaml
patches:
  findings: fuzz_failures       # or all
  out_of_scope: harness         # or library
  allocation_failure: harness   # or library
  documentation: false          # or true
  refactoring: none             # or equivalent, or minor
  equivalence_proof: required   # or not_required
```

| key | value | we write patches for |
|---|---|---|
| `findings` | `fuzz_failures` | failures that a fuzz target can cause |
| | `all` | also bugs that we find while we prove, which no fuzz target can cause |
| `out_of_scope` | `harness` | a fuzz target that gets to behaviour that you do not support: we make the fuzz target narrower |
| | `library` | the same case: we change the library so that it handles the behaviour |
| `allocation_failure` | `harness` | a fuzz target that fails when an allocation is refused: we change the fuzz target |
| | `library` | the same case: we change the library so that it survives the refused allocation |
| `documentation` | `false` | no patches that change only the documentation |
| | `true` | also patches that change only the documentation |
| `refactoring` | `none` | no changes that only make the code easier to verify |
| | `equivalent` | changes that make the code easier to verify and keep its behaviour the same |
| | `minor` | such changes, and also changes to behaviour that looks like a bug |
| `equivalence_proof` | `required` | a refactoring patch only together with a proof that the behaviour does not change |
| | `not_required` | a refactoring patch without such a proof |

`tools/validate.py` refuses an unknown key or value. If you set `disable_remediation: true`, we ignore the `patches` block.

## Your contribution policy

Our agents obey your project's own contribution policy, as OSS-Fuzz does. For example, if your policy does not accept AI-generated patches, we send findings without patches. Tell us about such a policy in `patch_style.md`, or link to it there.

## Patch style

`patch_style.md` is free text about the form of a patch. Write about these subjects:

* the code style;
* the tests that a patch must add or pass;
* the commit format;
* how and where to send patches, if you want something other than an attachment to the report.

Do not repeat in `patch_style.md` a choice that a field in `project.yaml` gives. A choice that a field gives goes only in that field. Put `patch_style.md` in the project directory, or in your repository at the path that `patch_style` gives. Start from [templates/patch_style.md](../templates/patch_style.md).

## Build patches

The project directory can hold build patches. A build patch changes only how the project builds ([project-yaml.md](project-yaml.md#the-files-in-the-project-directory)). We never send a build patch to you. A patch that we send never goes in the project directory.
