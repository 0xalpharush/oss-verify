# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/validate.py:  python3 -m unittest discover -s tools/tests"""
import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import validate  # noqa: E402

KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBF...\n-----END PGP PUBLIC KEY BLOCK-----\n"
MINIMAL = "repo: https://github.com/example/project#v1.0\nprimary_contact: security@example.org\nlanguage: c\n"


class ProjectDir:
    """A projects/<name>/ directory in a temporary directory, removed afterwards."""

    def __init__(self, files, name="example"):
        self.scratch = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.scratch.name) / name
        self.path.mkdir()
        for file, content in files.items():
            target = self.path / file
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        self.scratch.cleanup()


def check(yaml_text, files=None, name="example"):
    """Run check_project on a directory holding project.yaml and `files` (default: a Dockerfile and a build.sh)."""
    if files is None:
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
    with ProjectDir({"project.yaml": yaml_text, **files}, name) as directory:
        return validate.check_project(directory)


class ValidProjects(unittest.TestCase):
    def test_minimal(self):
        problems, warnings, summary = check(MINIMAL)
        self.assertEqual(problems, [])
        self.assertEqual(warnings, [])
        self.assertIn("builds: plain ubsan asan asan-ubsan", summary)
        self.assertIn("fuzz targets: all", summary)

    def test_every_field(self):
        text = (
            "repo: https://github.com/example/project#0123456789abcdef0123456789abcdef01234567\n"
            "primary_contact: security@example.org\nhomepage: https://example.org\nlanguage: c++\n"
            "disabled: false\nsanitizers: [address]\nfuzz_targets: [a_fuzzer, b-fuzzer.x]\npublish: eager\n"
            "disable_remediation: false\n"
            "patches:\n  findings: all\n  out_of_scope: library\n  allocation_failure: harness\n  documentation: true\n"
            "  refactoring: equivalent\n  equivalence_proof: not_required\n"
            "budgets:\n  halts: 16GiB\n  agrees:\n    address: [2GiB, 512GiB]\n"
            "proofs:\n  repo: https://github.com/example/proofs#main\n  path: projects/example\n"
            f"pgp: |\n  {KEY.replace(chr(10), chr(10) + '  ')}\n"
        )
        files = {
            "Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n", "patch_style.md": "# Patches\n", "sources": "# none\n",
            "driver.c": "int x;\n", "driver.h": "", "more.cpp": "", "0001-static.patch": "--- a\n+++ b\n",
            "series": "# order\n0001-static.patch\n",
        }
        problems, warnings, summary = check(text, files)
        self.assertEqual(problems, [])
        self.assertEqual(warnings, [])
        self.assertIn("builds: plain asan", summary)
        self.assertIn("fuzz targets: a_fuzzer, b-fuzzer.x", summary)

    def test_dockerfile_in_repository(self):
        problems, _, summary = check(MINIMAL + "dockerfile: .oss-verifier/Dockerfile\n", {"patch_style.md": "x"})
        self.assertEqual(problems, [])
        self.assertIn("in the repository at .oss-verifier/Dockerfile", summary)

    def test_seeded_project_warns(self):
        problems, warnings, _ = check(MINIMAL.replace("security@example.org", "n/a"))
        self.assertEqual(problems, [])
        self.assertTrue(any("primary_contact is n/a" in warning for warning in warnings))

    def test_seeded_project_without_build_files_warns(self):
        problems, warnings, summary = check(MINIMAL.replace("security@example.org", "n/a"), {})
        self.assertEqual(problems, [])
        self.assertTrue(any("no build files yet" in warning for warning in warnings))
        self.assertIn("Dockerfile: none yet", summary)

    def test_files_the_sources_file_copies_may_have_any_name(self):
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/sh\n", "list.sha256": "00  x\n",
                 "sources": "copy\ttargets/t/list.sha256\tlist.sha256\n"}
        problems, _, _ = check(MINIMAL, files)
        self.assertEqual(problems, [])
        problems, _, _ = check(MINIMAL, {**files, "sources": "# copies nothing\n"})
        self.assertTrue(any("list.sha256: only project.yaml" in problem for problem in problems), problems)

    def test_dockerfile_without_build_sh_warns(self):
        problems, warnings, _ = check(MINIMAL, {"Dockerfile": "FROM x\n"})
        self.assertEqual(problems, [])
        self.assertTrue(any("no build.sh" in warning for warning in warnings))

    def test_short_commit_warns(self):
        problems, warnings, _ = check(MINIMAL.replace("#v1.0", "#abc1234"))
        self.assertEqual(problems, [])
        self.assertTrue(any("shortened commit" in warning for warning in warnings))


class Builds(unittest.TestCase):
    def test_builds_follow_sanitizers(self):
        self.assertEqual(validate.builds_of({}), ["plain", "ubsan", "asan", "asan-ubsan"])
        self.assertEqual(validate.builds_of({"sanitizers": ["undefined", "address"]}), ["plain", "ubsan", "asan", "asan-ubsan"])
        self.assertEqual(validate.builds_of({"sanitizers": ["address"]}), ["plain", "asan"])
        self.assertEqual(validate.builds_of({"sanitizers": ["undefined"]}), ["plain", "ubsan"])
        self.assertEqual(validate.builds_of({"sanitizers": []}), ["plain"])

    def test_sizes(self):
        self.assertEqual(validate.size_in_bytes("16GiB"), 16 << 30)
        self.assertEqual(validate.size_in_bytes("512GiB"), 512 << 30)
        self.assertEqual(validate.size_in_bytes(1024), 1024)
        for bad in ("0", "16GB", "-1", "1.5GiB", True, 0, None, "", "16 GiB"):
            self.assertIsNone(validate.size_in_bytes(bad), bad)


class Problems(unittest.TestCase):
    def assertProblem(self, text, fragment, files=None, name="example"):
        problems, _, summary = check(text, files, name)
        self.assertIsNone(summary)
        self.assertTrue(any(fragment in problem for problem in problems), f"{fragment!r} not in {problems}")

    def test_keys(self):
        self.assertProblem(MINIMAL + "threat_model: x.md\n", "unknown field 'threat_model'")
        self.assertProblem("repo: https://github.com/a/b\nlanguage: c\n", "missing primary_contact")
        self.assertProblem("repo: https://github.com/a/b\nprimary_contact: a@b.cd\n", "missing language")
        with mock.patch.object(validate, "OPERATOR_KEYS", ("budget_usd",)):
            self.assertProblem(MINIMAL + "budget_usd: 5\n", "set by the operators")

    def test_types(self):
        self.assertProblem(MINIMAL + "disabled: yes please\n", "disabled must be true or false")
        self.assertProblem(MINIMAL.replace("language: c", "language: [c]"), "language must be a string")
        self.assertProblem(MINIMAL + "budgets: 16GiB\n", "budgets must be a mapping")
        self.assertProblem(MINIMAL + "proofs: [a]\n", "proofs must be a mapping")
        self.assertProblem("- a\n- b\n", "not a mapping")

    def test_urls(self):
        for repo in ("http://github.com/a/b", "[https://github.com/a/b]", "https://", "git@github.com:a/b",
                     "https://github.com/a/b#bad ref", "https://github.com/a/b#x#y"):
            self.assertProblem(MINIMAL.replace("https://github.com/example/project#v1.0", repo), "repo must be")
        self.assertProblem(MINIMAL + "homepage: ftp://example.org\n", "homepage must be")

    def test_addresses(self):
        self.assertProblem(MINIMAL.replace("security@example.org", "nobody"), "bad email")
        self.assertProblem(MINIMAL + "auto_ccs: a@b.cd\n", "auto_ccs must be a list")
        self.assertProblem(MINIMAL + "auto_ccs: [a@b.cd, nope]\n", "bad email 'nope'")

    def test_pgp(self):
        key = KEY.replace("\n", "\n  ")
        self.assertProblem(MINIMAL + f"auto_ccs: [a@b.cd]\npgp: |\n  {key}\n", "pgp and auto_ccs")
        self.assertProblem(MINIMAL + "pgp: '0xDEADBEEF'\n", "pgp must be one armored public key")
        private = key.replace("PUBLIC KEY BLOCK-----\n  mQ", "PUBLIC KEY BLOCK-----\n  PRIVATE KEY mQ")
        self.assertProblem(MINIMAL + f"pgp: |\n  {private}\n", "pgp must be one armored public key")

    def test_build_fields(self):
        self.assertProblem(MINIMAL.replace("language: c", "language: rust"), "language must be one of")
        self.assertProblem(MINIMAL + "sanitizers: address\n", "sanitizers must be a list")
        self.assertProblem(MINIMAL + "sanitizers: [memory]\n", "'memory' is not one of")
        self.assertProblem(MINIMAL + "sanitizers: [address, address]\n", "names a sanitizer twice")
        self.assertProblem(MINIMAL + "fuzz_targets: []\n", "non-empty list")
        self.assertProblem(MINIMAL + "fuzz_targets: [a, a]\n", "names a fuzz target twice")
        self.assertProblem(MINIMAL + "fuzz_targets: ['../x']\n", "is not a fuzz target name")
        self.assertProblem(MINIMAL + "publish: sometimes\n", "publish must be one of")

    def test_budgets(self):
        self.assertProblem(MINIMAL + "budgets: {oom: 1GiB}\n", "unknown field 'oom'")
        self.assertProblem(MINIMAL + "budgets: {halts: 16GB}\n", "budgets.halts must be a size")
        self.assertProblem(MINIMAL + "budgets: {agrees: [1]}\n", "budgets.agrees must be a mapping")
        self.assertProblem(MINIMAL + "budgets: {agrees: {memory: [1, 2]}}\n", "'memory' is not one of")
        self.assertProblem(MINIMAL + "budgets: {agrees: {address: [2GiB]}}\n", "must be two sizes")
        self.assertProblem(
            MINIMAL + "sanitizers: [undefined]\nbudgets: {agrees: {address: [2GiB, 512GiB]}}\n",
            "is not one of this project's sanitizers",
        )

    def test_patch_preferences(self):
        self.assertProblem(MINIMAL + "disable_remediation: yes please\n", "disable_remediation must be true or false")
        self.assertProblem(MINIMAL + "patches: [all]\n", "patches must be a mapping")
        self.assertProblem(MINIMAL + "patches: {style: minimal}\n", "patches: unknown field 'style'")
        self.assertProblem(MINIMAL + "patches: {findings: some}\n", "patches.findings must be one of fuzz_failures, all")
        self.assertProblem(MINIMAL + "patches: {refactoring: true}\n", "patches.refactoring must be one of none")
        self.assertProblem(MINIMAL + "patches: {documentation: yes-ish}\n", "patches.documentation must be true or false")
        self.assertProblem(MINIMAL + "patches: {equivalence_proof: maybe}\n", "patches.equivalence_proof must be one of")
        problems, warnings, _ = check(MINIMAL + "disable_remediation: true\npatches: {findings: all}\n")
        self.assertEqual(problems, [])
        self.assertTrue(any("patches has no effect while disable_remediation is true" in warning for warning in warnings))

    def test_proofs(self):
        self.assertProblem(MINIMAL + "proofs: {branch: x}\n", "unknown field 'branch'")
        self.assertProblem(MINIMAL + "proofs: {repo: 'git://x/y'}\n", "proofs.repo must be")
        self.assertProblem(MINIMAL + "proofs: {path: ../escape}\n", "proofs.path must be")

    def test_dockerfile_placement(self):
        self.assertProblem(MINIMAL, "a Dockerfile is required", {})
        self.assertProblem(MINIMAL + "dockerfile: Dockerfile\n", "one place only")
        self.assertProblem(MINIMAL + "dockerfile: /abs/Dockerfile\n", "relative path inside your repository", {})
        self.assertProblem(MINIMAL + "dockerfile: .oss-verifier/Dockerfile\n", "build.sh belongs there", {"build.sh": "x"})
        self.assertProblem(MINIMAL + "dockerfile: d/Dockerfile\n", "x.c belongs there", {"x.c": "int x;"})
        self.assertProblem(MINIMAL + "patch_style: style.md\n", "one place only",
                           {"Dockerfile": "FROM x", "build.sh": "x", "patch_style.md": "x"})

    def test_files(self):
        base = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
        self.assertProblem(MINIMAL, "only project.yaml, Dockerfile", {**base, "notes.txt": "x"})
        self.assertProblem(MINIMAL, "a file name may use only", {**base, "-x.c": "x"})
        self.assertProblem(MINIMAL, "Dockerfile is empty", {**base, "Dockerfile": " \n"})
        self.assertProblem(MINIMAL, "build.sh is empty", {**base, "build.sh": ""})
        self.assertProblem(MINIMAL, "larger than 64 KiB", {**base, "Dockerfile": "x" * (64 * 1024 + 1)})
        self.assertProblem(MINIMAL, "larger than 256 KiB", {**base, "build.sh": "x" * (256 * 1024 + 1)})
        self.assertProblem(MINIMAL, "larger than 256 KiB", {**base, "big.c": "x" * (256 * 1024 + 1)})
        self.assertProblem(MINIMAL, "not UTF-8", {**base, "bad.c": b"\xff\xfe"})
        many = {**base, **{f"f{i}.c": "" for i in range(validate.MAX_FILES)}}
        self.assertProblem(MINIMAL, "at most 64 files", many)

    def test_patches(self):
        base = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
        patch = "--- a/x\n+++ b/x\n"
        self.assertProblem(MINIMAL, "need a series file", {**base, "a.patch": patch})
        self.assertProblem(MINIMAL, "series lists 'b.patch'", {**base, "a.patch": patch, "series": "a.patch\nb.patch\n"})
        self.assertProblem(MINIMAL, "more than once", {**base, "a.patch": patch, "series": "a.patch\na.patch\n"})
        self.assertProblem(MINIMAL, "a.patch is not listed", {**base, "a.patch": patch, "series": "# none\n"})
        problems, warnings, _ = check(MINIMAL, {**base, "a.patch": "not a diff\n", "series": "a.patch\n"})
        self.assertEqual(problems, [])
        self.assertTrue(any("does not look like a patch" in warning for warning in warnings))

    def test_directory(self):
        self.assertProblem(MINIMAL, "the directory name must be", name="Bad_Name")
        self.assertProblem("repo: [unclosed\n", "does not parse")
        self.assertProblem(MINIMAL + "#" * (validate.MAX_CONFIG_BYTES + 1) + "\n", "project.yaml is larger than")

    def test_symbolic_links_and_directories(self):
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            os.symlink("/etc/passwd", directory / "harness.c")
            problems, _, _ = validate.check_project(directory)
            self.assertTrue(any("only regular files" in problem for problem in problems), problems)
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            (directory / "sub").mkdir()
            problems, _, _ = validate.check_project(directory)
            self.assertTrue(any("only regular files" in problem for problem in problems), problems)
        with ProjectDir({"real.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            os.symlink(directory / "real.yaml", directory / "project.yaml")
            problems, _, _ = validate.check_project(directory)
            self.assertTrue(any("project.yaml is one" in problem for problem in problems), problems)
        with ProjectDir({"project.yaml": MINIMAL}) as directory:
            link = directory.parent / "linked"
            os.symlink(directory, link)
            problems, _, _ = validate.check_project(link)
            self.assertTrue(any("projects/linked is one" in problem for problem in problems), problems)


class Output(unittest.TestCase):
    def test_printable(self):
        self.assertEqual(validate.printable("a\x1b[31mb\n\x07"), "a\\x1b[31mb\\x0a\\x07")

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["validate.py", *map(str, args)]):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = validate.main()
        return code, out.getvalue(), err.getvalue()

    def test_main(self):
        with ProjectDir({"project.yaml": MINIMAL.replace("security@example.org", "n/a"),
                         "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            code, out, err = self.run_main(directory)
            self.assertEqual(code, 0)
            self.assertIn("ok: 1 project(s)", out)
            self.assertIn("example: warning: primary_contact is n/a", out)
        with ProjectDir({"project.yaml": "repo: http://x\x1b\n"}, "bad") as directory:
            code, out, err = self.run_main(directory)
            self.assertEqual(code, 1)
            self.assertIn("bad: ", err)
            self.assertNotIn("\x1b", err)

    def test_repository_projects_pass(self):
        """Every project in this repository passes, so a pull request starts from a clean tree."""
        code, out, err = self.run_main()
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
