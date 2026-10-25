# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check_checks.py and .github/scripts/review-comment that need no Docker:  python3 -m pytest tools/tests"""
import importlib.machinery
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_checks  # noqa: E402
import validate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
REVIEW_COMMENT = ROOT / ".github" / "scripts" / "review-comment"
LOADER = importlib.machinery.SourceFileLoader("review_comment", str(REVIEW_COMMENT))
SPEC = importlib.util.spec_from_loader("review_comment", LOADER)
review_comment = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(review_comment)

SOURCE = b"""\
/* abort() in a comment is not a check */
#define CHECK(x) do { if (!(x)) abort(); } while (0)
static void helper(void) { abort(); }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
\tif (size > 4 &&
\t    data[0] == 'x')
\t\tabort();   /* "abort()" in a string: */ puts("abort()");
\tif (size == 1) {
\t\tlog_it();
\t\tabort();
\t} else if (size == 2) {
\t\tabort();
\t}
\tswitch (data[0]) {
\tdefault:
\t\tabort();
\t}
\tfor (int i = 0; i < 2; i++) { abort(); }
\treturn 0;
}
"""


class FindChecks(unittest.TestCase):
    def setUp(self):
        self.checks = {check.line: check for check in check_checks.find_checks("/src/x/fuzz.c", SOURCE)}

    def test_the_calls(self):
        # Not the comment, the string, or the macro definition.
        self.assertEqual(sorted(self.checks), [3, 7, 10, 12, 16, 18])

    def test_guards(self):
        self.assertEqual(self.checks[7].guard, (5, 6))  # the first byte of `size > 4 &&`
        self.assertEqual(self.checks[7].text, "if (size > 4 &&")
        self.assertEqual(self.checks[10].guard, (8, 6))  # after another statement of the block
        self.assertEqual(self.checks[12].guard, (11, 13))  # else if
        for unguarded in (3, 16, 18):  # a helper, a default:, a loop
            self.assertIsNone(self.checks[unguarded].guard, unguarded)


class Coverage(unittest.TestCase):
    def test_counts_add_up_across_targets(self):
        coverage = check_checks.Coverage()
        export = {"data": [{"files": [{"filename": "/src/f.c", "segments": [
            [1, 1, 5, True, True, False], [2, 3, 0, True, True, False], [2, 10, 5, True, False, False],
            [4, 1, 0, False, False, False]]}]}]}
        coverage.add(export)
        coverage.add(export)
        self.assertEqual(coverage.count("/src/f.c", 1, 7), 10)
        self.assertEqual(coverage.count("/src/f.c", 2, 3), 0)
        self.assertEqual(coverage.count("/src/f.c", 2, 12), 10)
        self.assertIsNone(coverage.count("/src/f.c", 5, 1))
        self.assertIsNone(coverage.count("/src/other.c", 1, 1))

    def test_fuzz_target_files(self):
        export = {"data": [{"functions": [{"name": "LLVMFuzzerTestOneInput", "filenames": ["/src/a/f.c", "/x.h"]},
                                          {"name": "helper", "filenames": ["/src/lib.c"]}]}]}
        self.assertEqual(check_checks.fuzz_target_files(export), {"/src/a/f.c"})


class Report(unittest.TestCase):
    def test_code_cannot_be_ended_by_its_text(self):
        self.assertEqual(check_checks.code("a`b"), "``a`b``")
        self.assertEqual(check_checks.code("x\x1b[31m"), "`x [31m`")
        self.assertEqual(check_checks.cell("a|b"), "`a\\|b`")
        self.assertTrue(check_checks.code("y" * 500, 10).endswith("…`"))

    def test_runs(self):
        self.assertFalse(check_checks.Run("t", "s", 2, "coverage").failed())
        self.assertTrue(check_checks.Run("t", "s", 134, "coverage").failed())
        self.assertTrue(check_checks.Run("t", "s", None, "coverage").failed())
        self.assertIn("abort()", check_checks.describe(check_checks.Run("t", "s", 134, "asan")))

    def test_seeds_get_the_driver_header(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            with zipfile.ZipFile(directory / "demo_seed_corpus.zip", "w") as archive:
                archive.writestr("one", b"\x01")
                archive.writestr("two", b"\x02\x03")
            names = check_checks.write_seeds(directory, ["demo", "none"], directory / "inputs")
            self.assertEqual(names, {"demo": ["one", "two"]})
            self.assertEqual((directory / "inputs" / "demo" / "1").read_bytes(), b"\0" * 6 + b"\x02\x03")


class Mutants(unittest.TestCase):
    def test_validate(self):
        base = "repo: https://github.com/a/b\nprimary_contact: a@b.cd\nlanguage: c\n"
        for good in ("fuzz/sabotage", "mutants"):
            self.assertEqual(list(validate.check_types(validate.yaml.safe_load(base + f"mutants: {good}\n"))), [])
        for bad in ("../x", "/abs", "[a]"):
            problems = list(validate.check_types(validate.yaml.safe_load(base + f"mutants: {bad}\n")))
            self.assertTrue(problems, bad)


class ReviewComment(unittest.TestCase):
    def comment(self, review, why="", checks="### report\n"):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--why", why, "--checks", str(directory / "checks.md")],
                                  capture_output=True, text=True, check=True).stdout

    def test_the_marker_comes_first_once(self):
        text = self.comment("Thanks.\n<!-- oss-verify-review -->\n")
        self.assertTrue(text.startswith(review_comment.MARKER + "\n"))
        self.assertEqual(text.count(review_comment.MARKER), 1)
        self.assertIn("<details>", text)
        self.assertIn("### report", text)

    def test_no_review(self):
        text = self.comment("", why="the review is not set up in this repository yet")
        self.assertIn("did not run on this push: the review is not set up", text)

    def test_a_credential_is_never_posted(self):
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOngifQ.c2lnbmF0dXJl"
        for leak in (token, "sk-ant-oat01-abcdefghijkl", "ghs_" + "a" * 36):
            text = self.comment(f"Here: {leak}")
            self.assertNotIn(leak, text)
            self.assertIn("looks like a credential", text)


if __name__ == "__main__":
    unittest.main()
