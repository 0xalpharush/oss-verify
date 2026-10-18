<!-- Adapted from OSS Scanner (https://github.com/anthropics/oss-scanner), Copyright 2026 Anthropic PBC, under the Apache License 2.0. Modified 2026 by Theorem Labs, PBC: who maintains this repository, how to report, and what happens to findings about enrolled projects. -->
# Security Policy

Thank you for helping us keep the OSS Verifier enrollment repository and its tools secure.

## Reporting a vulnerability in this repository

This repository is maintained by [Theorem](https://theorem.dev). Please report a vulnerability in this repository, its tools (`tools/`), its builder image (`infra/base-builder/`) or its workflows (`.github/`) privately, by opening a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository. Please do not open a public issue or pull request for a vulnerability.

## Findings about an enrolled project

What we find while verifying a project, such as an input on which one of its fuzz targets crashes, goes privately to that project's `primary_contact`. We set no disclosure deadline and we do not publish findings: see [docs/disclosure.md](docs/disclosure.md).
