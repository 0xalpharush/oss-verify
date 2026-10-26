# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check_checks.py and .github/scripts/review-comment and review-run that need no Docker:
python3 -m pytest tools/tests"""
import base64
import html.parser
import itertools
import json
import os
import importlib.machinery
import importlib.util
import pathlib
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import time
import zipfile

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_checks  # noqa: E402
import check_records  # noqa: E402
import validate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
REVIEW_COMMENT = ROOT / ".github" / "scripts" / "review-comment"
LOADER = importlib.machinery.SourceFileLoader("review_comment", str(REVIEW_COMMENT))
SPEC = importlib.util.spec_from_loader("review_comment", LOADER)
review_comment = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(review_comment)

class Shifts(unittest.TestCase):
    def test_a_patch_moves_the_lines_after_its_hunks(self):
        patch = (b"diff --git a/fuzz/f.c b/fuzz/f.c\n--- a/fuzz/f.c\n+++ b/fuzz/f.c\n"
                 b"@@ -10,3 +10,2 @@\n a\n-b\n c\n@@ -40 +39,3 @@\n-x\n+y\n+z\n+w\n")
        shifts = check_checks.hunk_shifts(patch, "/src/p")
        self.assertEqual(shifts, {"/src/p/fuzz/f.c": [(11, -1), (40, -1), (41, 1), (41, 1), (41, 1)]})

        def check(line):
            return check_records.Check(line, None, path="/src/p/fuzz/f.c")
        self.assertEqual(check_checks.moved(check(5), shifts), 5)
        self.assertEqual(check_checks.moved(check(20), shifts), 19)
        self.assertEqual(check_checks.moved(check(50), shifts), 51)
        # A check in the trailing context of a hunk moves too.
        near = check_checks.hunk_shifts(b"+++ b/fuzz/f.c\n@@ -10,7 +10,6 @@\n a\n b\n-c\n d\n e\n f\n g\n", "/src/p")
        self.assertEqual(check_checks.moved(check(15), near), 14)

    def test_two_files(self):
        patch = (b"--- a/fuzz/f.c\n+++ b/fuzz/f.c\n@@ -10,1 +10,1 @@\n-x\n+y\n"
                 b"--- a/src/lib.c\n+++ b/src/lib.c\n@@ -5 +5,2 @@\n-p\n+q\n+r\n")
        shifts = check_checks.hunk_shifts(patch, "/src/p")
        self.assertEqual(shifts["/src/p/fuzz/f.c"], [(10, -1), (11, 1)])
        self.assertEqual(check_checks.moved(check_records.Check(40, None, path="/src/p/fuzz/f.c"), shifts), 40)

    def test_record_patches_apply_on_the_last_lines(self):
        import subprocess, tempfile
        for ending in (b"\n", b""):
            data = b"a\nb\nc\nd\ne" + ending
            for line in range(1, 6):
                with tempfile.TemporaryDirectory() as directory:
                    directory = pathlib.Path(directory)
                    (directory / "f.c").write_bytes(data)
                    record = check_records.Record("f.c", line, "abcde"[line - 1], "X", "s")
                    changed, _ = check_records.mutate(data, record)
                    import difflib
                    diff = b"".join(difflib.diff_bytes(difflib.unified_diff, check_checks.diff_lines(data),
                                                       check_checks.diff_lines(changed), b"a/f.c", b"b/f.c"))
                    (directory / "p").write_bytes(b"diff --git a/f.c b/f.c\n" + diff)
                    subprocess.run(["git", "apply", "p"], cwd=directory, check=True, capture_output=True)
                    self.assertEqual((directory / "f.c").read_bytes(), changed, (line, ending))

    def test_record_patches_split_on_newlines_only(self):
        data = "int x;\n/* \u00c5 */\nif (a) abort();\n".encode()
        record = check_records.Record("fuzz/f.c", 3, "(a)", "(!a)", "s")
        changed, _ = check_records.mutate(data, record)
        import difflib
        before = [line + b"\n" for line in data.split(b"\n")]
        after = [line + b"\n" for line in changed.split(b"\n")]
        diff = b"".join(difflib.diff_bytes(difflib.unified_diff, before, after, b"a/f", b"b/f"))
        self.assertIn("\u00c5".encode(), diff)
        self.assertEqual(diff.count(b"\n-"), 1)


class Positions(unittest.TestCase):
    def test_the_reader_gives_columns_for_coverage(self):
        source = "int f(int a) {\n\tif (a > 4 &&\n\t    a < 9)\n\t\tabort();\n\treturn 0;\n}\n"
        (found,) = check_records.find_checks(source, "/src/x/f.c")
        self.assertEqual((found.path, found.line, found.column, found.guard_at), ("/src/x/f.c", 4, 3, (2, 2)))
        self.assertEqual(found.text, "if (a > 4 &&")


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
        self.assertTrue(check_checks.Run("t", "s", 2, "coverage").passed())
        self.assertTrue(check_checks.Run("t", "s", 134, "coverage").caught())
        # A run stopped at the time limit neither passes nor catches a breakage.
        self.assertFalse(check_checks.Run("t", "s", None, "coverage").passed())
        self.assertFalse(check_checks.Run("t", "s", None, "coverage").caught())
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
    def comment(self, review, checks="### report\n", *extra):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md"), *extra],
                                  capture_output=True, text=True, check=True).stdout

    def kept(self, previous, head, run="https://github.com/theorem-labs/oss-verify/actions/runs/7"):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "previous.md").write_text(previous)
            return self.comment("", "### new report\n", "--head", head, "--run", run,
                                "--previous", str(pathlib.Path(directory) / "previous.md"))

    def meta(self, text):
        return review_comment.META.match(text.split("\n")[1])

    def test_the_marker_comes_first_once(self):
        text = self.comment("Thanks.\n<!-- oss-verify-review -->\n")
        self.assertTrue(text.startswith(review_comment.MARKER + "\n"))
        self.assertEqual(text.count(review_comment.MARKER), 1)
        self.assertEqual(self.meta(text).group("status"), "review")
        self.assertIn("<details>", text)
        self.assertIn("### report", text)

    def test_no_review(self):
        text = self.comment("")
        self.assertIn("did not run on this push: it wrote no comment", text)
        self.assertEqual(self.meta(text).group("status"), "none")

    def test_a_review_with_details_is_posted_whole(self):
        text = self.comment("Thanks.\n\n<details><summary>x</summary>y</details>\n\n1. Fix X.\n\n2. Fix Y.\n")
        self.assertIn("1. Fix X.", text)
        self.assertIn("2. Fix Y.", text)
        self.assertEqual(text.count("<sub>Claude wrote this review"), 1)

    def test_a_credential_is_never_posted(self):
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOngifQ.c2lnbmF0dXJl"
        for leak in (token, "sk-ant-oat01-abcdefghijkl", "ghs_" + "a" * 36):
            text = self.comment(f"Here: {leak}")
            self.assertNotIn(leak, text)
            self.assertIn("looks like a credential", text)

    def test_the_commit_is_in_the_metadata_and_the_footer(self):
        text = self.comment("Thanks.\n", "### report\n", "--head", "abc1234" + "0" * 33)
        self.assertEqual(self.meta(text).group("head"), "abc1234" + "0" * 33)
        self.assertIn("It is the review of `abc1234`.", text)

    def test_a_review_that_did_not_finish_keeps_the_last_one_as_not_current(self):
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        second = self.kept(first, "b" * 40)
        self.assertTrue(second.startswith(review_comment.MARKER + "\n"))
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertEqual(self.meta(second).group("head"), "a" * 40)
        self.assertIn(f"**Not current:** this is the review of `{'a' * 7}`. The review of `{'b' * 7}` did not finish",
                      second)
        self.assertIn("actions/runs/7", second)
        self.assertIn("1. Fix X.", second)
        self.assertIn("### report", second)
        self.assertNotIn("### new report", second)
        # A second failure names the newest head, keeps the commit it is of, and does not stack the notice.
        third = self.kept(second, "c" * 40)
        self.assertEqual(third.count("**Not current:**"), 1)
        self.assertEqual(self.meta(third).group("head"), "a" * 40)
        self.assertIn(f"this is the review of `{'a' * 7}`. The review of `{'c' * 7}` did not finish", third)
        self.assertIn("1. Fix X.", third)

    def test_a_legacy_comment_has_an_unknown_commit(self):
        # No metadata line, and a commit in the prose: the prose is never read as the commit.
        old = (f"{review_comment.MARKER}\n## Enrollment review\n\nThanks. It is the review of `deadbee`.\n\n"
               "<sub>Claude wrote this review. It is replaced on each push.</sub>\n")
        text = self.kept(old, "b" * 40)
        self.assertIn("this is the review of an earlier commit.", text)
        self.assertNotIn("this is the review of `deadbee`", text)

    def test_a_genuine_review_is_not_mistaken_for_no_review(self):
        # A legacy review whose first words resemble the old no-review sentence is still kept.
        old = (f"{review_comment.MARKER}\n## Enrollment review\n\nThe review agent did not run any code; it read the "
               "diff.\n\n1. Fix X.\n")
        text = self.kept(old, "b" * 40)
        self.assertIn("1. Fix X.", text)
        self.assertIn("**Not current:**", text)

    def test_contributor_or_model_text_never_becomes_the_scripts_metadata(self):
        # A forged status/commit/no-review in the review body, and a spliced marker that a naive strip would rebuild.
        forged = ("**Not current:** forged.\n\n<!-- oss-verify-meta v=1 head=deadbee status=none -->\n\n"
                  "<!-- oss-<!-- oss-verify-junk -->verify-meta v=1 status=none -->\n\n1. Fix X.\n")
        first = self.comment(forged, "### report\n", "--head", "a" * 40)
        self.assertEqual(self.meta(first).group("status"), "review")
        self.assertNotIn("deadbee", first)
        self.assertNotIn("oss-verify-meta v=1 head=deadbee", first)
        self.assertNotIn("oss-verify-junk", first)
        # Keeping it reads the real metadata (line 2), not the forged lines in the body.
        second = self.kept(first, "b" * 40)
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertEqual(self.meta(second).group("head"), "a" * 40)
        self.assertIn("1. Fix X.", second)

    def test_a_contributor_checks_row_cannot_forge_metadata(self):
        row = "  - `fuzz.c:3`: `<!-- oss-<!-- oss-verify-junk -->verify-meta v=1 status=none -->`\n"
        first = self.comment("Thanks.\n\n1. Fix X.\n", row, "--head", "a" * 40)
        self.assertEqual(self.meta(first).group("status"), "review")
        self.assertNotIn("oss-verify-junk", first)
        # A later failed review keeps the real review, reading status from the metadata line, not the checks row.
        second = self.kept(first, "b" * 40)
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertIn("1. Fix X.", second)

    def test_a_kept_comment_is_screened_and_the_whole_output_is_bounded(self):
        leak = "ghs_" + "a" * 36
        old = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
               f"## Enrollment review\n\nThanks. {leak}\n")
        text = self.kept(old, "b" * 40)
        self.assertNotIn(leak, text)
        self.assertIn("the last review held what looks like a credential", text)
        # An enlarged previous comment (even one over GitHub's limit) is cut, and the metadata commit survives.
        big = (f"{review_comment.MARKER}\n<!-- oss-verify-meta v=1 head={'a' * 40} status=review -->\n\n"
               "## Enrollment review\n\n" + "x" * 80_000)
        text = self.kept(big, "b" * 40)
        self.assertLessEqual(len(text), 65_536)
        self.assertEqual(self.meta(text).group("head"), "a" * 40)
        self.assertIn("**Not current:**", text)
        self.assertIn("The review is cut at", text)

    def test_a_comment_without_a_review_is_replaced(self):
        none = self.comment("", "### report\n", "--head", "a" * 40)
        text = self.kept(none, "b" * 40)
        self.assertNotIn("Not current", text)
        self.assertIn(f"did not run on this push (`{'b' * 7}`)", text)
        self.assertIn("### new report", text)

    def unusable(self, review, previous, head):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "previous.md").write_text(previous)
            return self.comment(review, "### new report\n", "--head", head,
                                "--previous", str(pathlib.Path(directory) / "previous.md"))

    def test_an_unusable_review_keeps_the_last_one(self):
        # Blank, credential-shaped or marker-only: the review job "succeeded", but there is nothing to post.
        first = self.comment("Thanks.\n\n1. Fix X.\n", "### report\n", "--head", "a" * 40)
        for review in (" \n\t\n", "Here: ghs_" + "b" * 36, "<!-- oss-verify-review -->\n"):
            text = self.unusable(review, first, "b" * 40)
            self.assertEqual(self.meta(text).group("status"), "stale", review)
            self.assertIn("1. Fix X.", text)
            self.assertNotIn("ghs_" + "b" * 36, text)

    def test_a_credential_in_the_checks_is_refused_and_the_review_kept(self):
        # A contributor's source line, rendered into a checks row by tools/check_checks.py.
        leak = "ghs_" + "A" * 36
        first = self.comment("Thanks.\n\n1. Fix X.\n", f"  - `fuzz.c:3`: `{leak}`\n", "--head", "a" * 40)
        self.assertNotIn(leak, first)
        self.assertEqual(self.meta(first).group("status"), "review")
        self.assertIn("1. Fix X.", first)
        self.assertIn("The report held what looks like a credential", first)
        # So a later failed review still keeps it.
        second = self.kept(first, "b" * 40)
        self.assertEqual(self.meta(second).group("status"), "stale")
        self.assertIn("1. Fix X.", second)

    def test_only_the_whole_legacy_no_review_sentence_means_no_review(self):
        legacy = f"{review_comment.MARKER}\n## Enrollment review\n\n"
        similar = self.kept(legacy + "The review agent did not run on this push's test machine; it read the diff.\n\n"
                            "1. Fix X.\n", "b" * 40)
        self.assertIn("1. Fix X.", similar)
        self.assertEqual(self.meta(similar).group("status"), "stale")
        for why in ("it wrote no comment", "the review job ended with the result failure"):
            none = self.kept(legacy + f"The review agent did not run on this push: {why}. A person at Theorem reviews "
                             "the enrollment.\n\n<sub>Claude wrote this review.</sub>\n", "b" * 40)
            self.assertEqual(self.meta(none).group("status"), "none", why)

    def test_neutralize_is_linear_and_a_fixed_point(self):
        # It removes only a comment that is complete and names this script; it never rewrites anything else.
        hostile = "<!--oss-verify" * 5_000  # 70,000 characters, no -->
        started = time.monotonic()
        self.assertEqual(review_comment.neutralize(hostile), hostile)
        self.assertLess(time.monotonic() - started, 1.0)
        for sample in (hostile, "<!-- oss-<!-- oss-verify-junk -->verify-meta v=1 status=none -->",
                       "a <!-- keep --> b <!-- oss-verify-x --> c <!-- tail", "<!-<!--oss-verify-->- oss-verify-x -->"):
            once = review_comment.neutralize(sample)
            self.assertEqual(review_comment.neutralize(once), once, sample)
            self.assertFalse(self.holds_a_complete_marker(once), sample)

    def holds_a_complete_marker(self, text):
        """Whether a complete HTML comment naming this script is left. A forward scan, not a regular expression: the
        obvious one backtracks for minutes on 70,000 characters that hold no -->."""
        at = 0
        while (start := text.find("<!--", at)) != -1:
            end = text.find("-->", start + 4)
            if end == -1:
                return False
            if "oss-verify" in text[start:end + 3].lower():
                return True
            at = end + 3
        return False


class CredentialArguments(unittest.TestCase):
    """The workflow and its helpers give credentials to commands through env/pipes, never as a process's argument."""

    def test_build_yaml_keeps_the_three_credentials_out_of_argv(self):
        steps = [step for job in yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())["jobs"]
                 .values() for step in job["steps"] if "run" in step]
        for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OTEL_COLLECTOR_TOKEN"):
            used = 0
            for step in steps:
                variable = re.escape(f'"${name}"')
                # The forms a builtin or a pipe reads, not argv: printf into a process substitution, a test, a pattern.
                rest = re.sub(rf"<\(printf '[^']*' {variable}\)|\[ -[zn] {variable} \]|\*{variable}\*", "",
                              step["run"])
                used += step["run"].count(f"${name}")
                self.assertNotIn(f"${name}", rest, f"{step.get('name')}: ${name} is an argument")
            self.assertGreater(used, 0, name)

    def test_the_helpers_use_no_argv_form_for_the_github_token(self):
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        # env NAME=value puts the value in env's argument vector; -c http.extraheader= puts the header in git's.
        self.assertNotIn("env GITHUB_TOKEN=", gather)
        self.assertIn('GITHUB_TOKEN="${GH_TOKEN:-}" keep', gather)
        self.assertNotIn("-c http.extraheader=", take)
        self.assertIn("--config-env=http.extraheader=", take)

    def test_the_helpers_production_definitions_keep_the_token_out_of_argv(self):
        # The production keep, the triage call and fetch_head, taken from the scripts and run under strace with a fake
        # python3 and git that record their arguments and environment: the token reaches the environment only.
        if not shutil.which("strace"):
            self.skipTest("strace is not installed (the tests workflow installs it)")
        gather = (ROOT / ".github" / "scripts" / "review-gather").read_text()
        take = (ROOT / ".github" / "scripts" / "take-project").read_text()
        keep = re.search(r"^keep\(\) \{.*\}$", gather, re.M).group(0)
        call = re.search(r"^.*\bkeep triage-today\.md .*$", gather, re.M).group(0)
        fetch = re.search(r"^fetch_head\(\) \{\n.*?^\}$", take, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            (directory / "out").mkdir()
            for name in ("git", "python3"):
                (bin / name).write_text(f'#!/bin/bash\nprintf "%s\\n" "$@" >> {directory}/{name}-argv\n'
                                        f"env >> {directory}/{name}-env\n")
                (bin / name).chmod(0o755)
            secret = "ghs_" + "Q" * 36
            auth = base64.b64encode(f"x-access-token:{secret}".encode()).decode()
            script = "\n".join(["set -euo pipefail", f"out={directory}/out REPO=o/r PR=1 sha={'a' * 40} fetched=false",
                                keep, call, fetch, "fetch_head", "fetch_head"])
            run = subprocess.run(["strace", "-f", "-qq", "-s", "8192", "-e", "trace=execve", "-o",
                                  str(directory / "trace"), "bash", "-c", script], cwd=directory,
                                 env={**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": secret},
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            trace = (directory / "trace").read_text()
            self.assertIn("python3", trace)
            self.assertIn("--config-env=http.extraheader=", trace)
            for value in (secret, auth):
                self.assertNotIn(value, trace)
                self.assertNotIn(value, run.stdout + run.stderr)
            self.assertIn(f"GITHUB_TOKEN={secret}", (directory / "python3-env").read_text())
            self.assertIn(f"Authorization: Basic {auth}", (directory / "git-env").read_text())
            # fetch_head fetches once, however often it is called.
            self.assertEqual((directory / "git-argv").read_text().split("\n").count("fetch"), 1)
            # Nor in what keep gathered (python3-env and git-env are the fakes' deliberate captures of the environment).
            gathered = sorted((directory / "out").iterdir())
            self.assertTrue(gathered)
            for path in gathered:
                for value in (secret, auth):
                    self.assertNotIn(value, path.read_text(), path.name)


class PostingStep(unittest.TestCase):
    """build.yaml's own "Post the comment" step, run with a fake gh: what it sends GitHub."""
    OLD = "Thanks.\n\n1. Fix X.\n"

    def post(self, review, existing=True):
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build.yaml").read_text())
        name = "Post the comment, or update the one already there"
        matches = [s for s in workflow["jobs"]["comment"]["steps"] if s.get("name") == name]
        # Exactly one, so this cannot run a same-name copy instead of the step the job really uses.
        self.assertEqual(len(matches), 1, f"{len(matches)} steps named {name!r}")
        step = matches[0]
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            bin = directory / "bin"
            bin.mkdir()
            first = subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", "/dev/stdin", "--head", "a" * 40],
                                   input=self.OLD, capture_output=True, text=True, check=True).stdout
            (directory / "existing.md").write_text(first)
            (bin / "gh").write_text(
                "#!/bin/bash\n"
                f'case "$*" in\n'
                f'  *"--method PATCH"*) cat > {directory}/patch.json ;;\n'
                f'  *"--method POST"*) cat > {directory}/post.json ;;\n'
                f'  *"--paginate"*) {"echo 4242" if existing else "true"} ;;\n'
                f'  *"issues/comments/4242"*) cat {directory}/existing.md ;;\n'
                '  *) echo "unexpected gh $*" >&2; exit 1 ;;\n'
                "esac\n")
            (bin / "gh").chmod(0o755)
            (directory / "temp").mkdir()
            environment = {**os.environ, "PATH": f"{bin}:{os.environ['PATH']}", "GH_TOKEN": "x", "REPO": "o/r",
                           "PR": "8", "REVIEW": review, "CHECKS": "### new report\n", "HEAD_SHA": "b" * 40,
                           "RUN_URL": "https://github.com/o/r/actions/runs/7", "RUNNER_TEMP": str(directory / "temp"),
                           "GITHUB_OUTPUT": str(directory / "output")}
            run = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=ROOT, env=environment, capture_output=True,
                                 text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            sent = directory / ("patch.json" if existing else "post.json")
            return json.loads(sent.read_text())["body"]

    def status(self, body):
        return review_comment.META.match(body.split("\n")[1]).group("status")

    def test_an_unusable_review_keeps_the_posted_one(self):
        # The review job succeeded with text that cannot be posted: the step still fetches and keeps the last review.
        for review in ("", " \n\t\n", "Here: ghs_" + "b" * 36, "<!-- oss-verify-review -->\n"):
            body = self.post(review)
            self.assertEqual(self.status(body), "stale", repr(review))
            self.assertIn("1. Fix X.", body)
            self.assertNotIn("ghs_" + "b" * 36, body)

    def test_a_usable_review_replaces_the_posted_one(self):
        body = self.post("Thanks again.\n\n2. Fix Y.\n")
        self.assertEqual(self.status(body), "review")
        self.assertIn("2. Fix Y.", body)
        self.assertNotIn("1. Fix X.", body)
        self.assertIn("### new report", body)

    def test_without_a_posted_comment_it_posts_one(self):
        self.assertEqual(self.status(self.post(" \n", existing=False)), "none")


class Screening(unittest.TestCase):
    """review-comment's credential scan and its cuts."""
    OLD = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|sk-ant-[A-Za-z0-9_-]{8,}|gh[opsu]_[A-Za-z0-9]{20,}"
                     r"|github_pat_[A-Za-z0-9_]{20,}")

    def test_the_scan_finds_what_the_regular_expression_found(self):
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOngifQ.c2lnbmF0dXJl"
        for text in (jwt, f"a {jwt} b", "sk-ant-oat01-abcdefghijkl", "x sk-ant-abcdefgh", "ghs_" + "a" * 20,
                     "ghp_" + "a" * 19 + "_", "github_pat_" + "a" * 20, "github_pat_-github_pat_" + "a" * 20,
                     "gho_" + "-" * 20 + "ghu_" + "B" * 20, "eyJ" + "a" * 10 + ".", "eyJ" + "a" * 9 + "." + "b" * 10,
                     "eyJ" + "a" * 10 + ". " + "b" * 10, "eyJ" + "a" * 10 + "." + "b" * 10, "sk-ant-" + "a" * 7,
                     "eyJ" * 30, "plain words", ""):
            self.assertEqual(review_comment.credential(text), bool(self.OLD.search(text)), text)
        # And on random text over the characters these patterns turn on.
        import random
        rng = random.Random(36)
        pieces = ["eyJ", "sk-ant-", "gho_", "ghs_", "github_pat_", ".", "-", "_", " ", "a", "B", "7", "aaaaaaaaaa"]
        for _ in range(20_000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randrange(1, 14)))
            self.assertEqual(review_comment.credential(text), bool(self.OLD.search(text)), text)

    def test_the_scan_is_linear(self):
        # Inputs that hold no credential, built to make a backtracking scan reread the text at every prefix.
        for hostile in ("eyJ" * 100_000, "eyJ" + "a" * 300_000, "ghs_" * 75_000, "github_pat_-" * 25_000,
                        ("eyJ" + "a" * 9 + ".") * 20_000):
            self.assertFalse(self.OLD.search(hostile[:2_000]))
            started = time.monotonic()
            self.assertFalse(review_comment.credential(hostile))
            self.assertLess(time.monotonic() - started, 1.0, hostile[:20])

    def comment(self, review, checks="### report\n", *extra):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / "review.md").write_text(review)
            (directory / "checks.md").write_text(checks)
            return subprocess.run([sys.executable, str(REVIEW_COMMENT), "--review", str(directory / "review.md"),
                                   "--checks", str(directory / "checks.md"), "--head", "a" * 40, *extra],
                                  capture_output=True, text=True, check=True).stdout

    def generated_before_the_review(self, text):
        """What this script writes, which must all come before the review the model wrote."""
        review_at = text.rindex("\n\n") if "\n\n" in text else len(text)
        return text[:review_at]

    def test_what_the_script_writes_comes_before_the_review(self):
        # The review is last, so nothing it leaves open has anything of this script's after it to hide.
        text = self.comment("The model's text.", "### report\n")
        self.assertTrue(text.rstrip().endswith("The model's text."))
        head = self.generated_before_the_review(text)
        for mine in (review_comment.MARKER, "oss-verify-meta", review_comment.HEADING, "Claude wrote this review",
                     review_comment.CHECKS_SUMMARY, "### report"):
            self.assertIn(mine, head, mine)

    def test_no_character_of_the_review_or_the_checks_is_changed(self):
        # Markdown code holds characters that look like markup, spaced and unspaced. Each must arrive as written.
        for text in ("Use `a<b` here.", "Use `a < b` here.", "```c\nif (a<b) return a;\n```",
                     "See `<div title=\"x >`.", "`<!-- not mine -->`", "a <b> b </b> c", "&#", "<b", "1<2 and 3>2"):
            posted = self.comment(text, "### report\n")
            self.assertIn(text, posted, text)
            posted = self.comment("Thanks.", text)
            self.assertIn(text, posted, text)

    def test_nothing_in_the_checks_can_close_its_fence(self):
        # The fence is longer than any run of backticks in the report, so the report cannot end it early.
        for report in ("```\nnot a close\n", "`````\nlonger\n", "a ``` b ```` c", "<!-- open", '<div title="x >'):
            text = self.comment("Thanks.", report)
            bar = re.search(r"\n(`{3,})text\n", text).group(1)
            self.assertNotIn(bar, report)
            self.assertIn(report.strip(), text)
            # The report is between the fences, and the review follows the closing one.
            after = text.split(f"\n{bar}\n", 1)[1]
            self.assertIn("Thanks.", after)

    def test_the_whole_comment_stays_within_githubs_limit(self):
        for review, checks in ((("<!--" * 11_000 + "-->"), "### report\n" + "<!--" * 2_000),
                               ("x" * 90_000, "y" * 90_000), ("`" * 30_000, "`" * 30_000)):
            text = self.comment(review, checks)
            self.assertLessEqual(len(text), 65_536, (len(review), len(checks)))
            self.assertIn("Claude wrote this review", text)

    def test_nothing_generated_ever_follows_the_review(self):
        # The review-last guarantee: in every path, including a cut review and a kept comment, the review or the kept
        # body is the last block, and the note about a cut comes before it.
        long = "R" * (review_comment.MAX_REVIEW + 50)
        for text in (self.comment("The model's text.", "### report\n"), self.comment(long, "### report\n"),
                     self.comment("", "### report\n"),
                     review_comment.not_current(f"{review_comment.MARKER}\n"
                                                f"{review_comment.meta_line('a' * 40, 'review')}\n\n"
                                                "## Enrollment review\n\nOLD_BODY <b", "b" * 40, "")):
            blocks = text.strip().split("\n\n")
            last = blocks[-1]
            for mine in (review_comment.MARKER, "oss-verify-meta", review_comment.HEADING, "Claude wrote this review",
                         review_comment.CHECKS_SUMMARY, "is cut at", "**Not current:**", "did not run on this push"):
                self.assertNotIn(mine, last, f"{mine} follows the review")
        text = self.comment(long, "### report\n")
        self.assertLess(text.index("The review is cut at"), text.index("R" * 100))

    def test_nothing_in_the_report_can_end_the_fence(self):
        # A closing fence must use the same character as the opening one and be at least as long, so a tilde line
        # cannot end a backtick fence, and a backtick line cannot either, because the fence is longer than any run.
        for report in ("~~~\nstill inside\n~~~\n", "```   \nstill inside\n", "   ```\nstill inside\n",
                       "``````\nstill inside\n", "a``````b\nstill inside\n", "~~~text\nstill inside\n"):
            text = self.comment("REVIEW_SENTINEL", report)
            bar = re.search(r"\n(`{3,})text\n", text).group(1)
            inside = text.split(f"{bar}text\n", 1)[1].split(f"\n{bar}\n", 1)[0]
            self.assertIn("still inside", inside)
            for line in report.split("\n"):
                if line.strip() and set(line.strip()) == {"`"}:
                    self.assertLess(len(line.strip()), len(bar), line)
            self.assertTrue(text.strip().endswith("REVIEW_SENTINEL"))

    def test_a_marker_spanning_a_blank_line_is_removed_whole(self):
        # GitHub ends an HTML comment at its -->, as the scan does, even across a blank line: rendering the case
        # through GitHub's Markdown endpoint showed the text after the --> and hid the text inside the comment. So a
        # marker that spans a blank line is one span to both, and the scan removes all of it.
        review = "Thanks.\n\n<!-- oss-verify-meta v=1\n\nstatus=none -->\n\nAFTER_MARKER"
        out = review_comment.neutralize(review)
        self.assertNotIn("oss-verify-meta", out)
        self.assertNotIn("status=none", out)
        self.assertIn("Thanks.", out)
        self.assertIn("AFTER_MARKER", out)
        # A comment that does not name this script keeps every character, blank line and all.
        plain = "Thanks.\n\n<!-- plain\n\nstill -->\n\nAFTER_PLAIN"
        self.assertEqual(review_comment.neutralize(plain), plain)

    def test_a_marker_inside_a_code_span_is_removed_too(self):
        # The cost of the one transformation, stated: a marker inside Markdown code goes like any other. Code that
        # does not name this script is untouched, and the comment's own text is what a review would show.
        span = "See `<!-- oss-verify-meta v=1 status=none -->` here."
        self.assertEqual(review_comment.neutralize(span), "See ` ` here.")
        self.assertEqual(review_comment.neutralize("See `<!-- plain -->` here."), "See `<!-- plain -->` here.")

    def test_neutralize_removes_only_a_complete_marker_of_this_script(self):
        # An independent implementation of the rule, by regular expression rather than by scan, on inputs small enough
        # that its backtracking does not matter.
        def expected(text):
            return re.sub(r"<!--.*?-->", lambda m: " " if "oss-verify" in m.group().lower() else m.group(), text,
                          flags=re.S)
        rng = random.Random(37)
        pieces = ["<!--", "-->", "oss-verify", "OSS-Verify", "<!", "x", " ", "\n", "-", ">", "`"]
        for _ in range(20_000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 12)))
            got = review_comment.neutralize(text)
            self.assertEqual(got, expected(text), text)
            self.assertEqual(review_comment.neutralize(got), got, text)
            # Nothing but those spans goes: what is left, with spaces put back, is a subsequence of the input.
            if "oss-verify" not in text.lower():
                self.assertEqual(got, text, text)

    def test_a_cut_says_so_before_the_text_it_cut(self):
        text = self.comment("x" * (review_comment.MAX_REVIEW + 10), "y" * (review_comment.MAX_CHECKS + 10))
        for note in ("The checks report is cut at 20,000 characters", "The review is cut at 40,000 characters"):
            self.assertIn(note, text)
            self.assertLess(text.index(note), text.rindex("x" * 100), note)


class ReviewRun(unittest.TestCase):
    """review-run with a fake claude, and a collector on 127.0.0.1 that takes one token."""
    TOKEN = "collector-token-not-a-secret"
    SECRETS = (TOKEN, "sk-ant-oat01-notasecret", "ghs_notasecretnotasecret", "dotted-not-a-secret")

    def setUp(self):
        import http.server
        import threading
        self.headers = []
        self.answers = []
        test = self

        class Collector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                test.headers.append((self.path, self.headers.get("Authorization")))
                right = self.headers.get("Authorization") == f"Bearer {test.TOKEN}"
                self.send_response(test.answers.pop(0) if test.answers else 200 if right else 401)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        bin = self.directory / "bin"
        bin.mkdir()
        # Each command review-run runs records its arguments; claude records its arguments and environment too.
        for command in ("python3", "curl", "jq", "awk", "realpath", "tail", "wc", "env"):
            real = shutil.which(command)
            (bin / command).write_text(f"#!/bin/bash\nprintf '%s\\0' {command} \"$@\" >> {self.directory}/argv\n"
                                       f"exec {real} \"$@\"\n")
        (bin / "claude").write_text(
            f"#!/bin/bash\nprintf '%s\\0' claude \"$@\" >> {self.directory}/argv\n"
            f"cat /proc/$$/environ > {self.directory}/environ\n"
            'echo \'{"is_error": false, "result": "Thanks."}\'\n')
        for script in bin.iterdir():
            script.chmod(0o755)
        (self.directory / "review").mkdir()

    def run_review(self, **environment):
        base = {"PATH": f"{self.directory / 'bin'}:{os.environ['PATH']}", "HOME": os.environ["HOME"], "PR": "8",
                "NAME": "libreac", "GH_TOKEN": "ghs_notasecretnotasecret",
                "ANTHROPIC_API_KEY": "sk-ant-oat01-notasecret", "CLAUDE_CODE_EFFORT": "x",
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://elsewhere", "A.B": "dotted-not-a-secret",
                "BASH_FUNC_f%%": "() { echo dotted-not-a-secret; }"}
        return subprocess.run([str(ROOT / ".github" / "scripts" / "review-run"), "review"], cwd=self.directory,
                              env={**base, **environment}, capture_output=True, text=True)

    def collector(self, **environment):
        return {"OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{self.server.server_port}/",
                "OTEL_COLLECTOR_TOKEN": self.TOKEN, **environment}

    def child(self):
        entries = (self.directory / "environ").read_bytes().split(b"\0")
        return dict(entry.decode().split("=", 1) for entry in entries if entry)

    def test_no_value_is_an_argument_and_the_environment_is_the_allow_list(self):
        out = self.run_review(**self.collector())
        self.assertEqual(out.returncode, 0, out.stderr)
        argv = (self.directory / "argv").read_text()
        self.assertIn("claude", argv)
        for secret in self.SECRETS:
            self.assertNotIn(secret, argv)
            self.assertNotIn(secret, out.stdout + out.stderr)
        child = self.child()
        self.assertEqual(set(child), {"PATH", "HOME", "LANG", "ANTHROPIC_API_KEY", "CLAUDE_CODE_EFFORT",
                                      "CLAUDE_CODE_ENABLE_TELEMETRY", "OTEL_LOGS_EXPORTER", "OTEL_METRICS_EXPORTER",
                                      "OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_EXPORTER_OTLP_ENDPOINT",
                                      "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_RESOURCE_ATTRIBUTES"})
        self.assertEqual(child["OTEL_EXPORTER_OTLP_HEADERS"], f"Authorization=Bearer {self.TOKEN}")
        self.assertEqual(child["CLAUDE_CODE_ENABLE_TELEMETRY"], "1")
        self.assertNotIn("theorem.credential", child["OTEL_RESOURCE_ATTRIBUTES"])
        # Before the review and after it.
        self.assertEqual(self.headers, [("/v1/logs", f"Bearer {self.TOKEN}")] * 2)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")

    def test_the_ci_label_only_with_the_ci_service_account(self):
        self.run_review(**self.collector(ANTHROPIC_SERVICE_ACCOUNT_ID="svac_01WdHTLcJPEfiPttcuLK1hGT",
                                         ANTHROPIC_IDENTITY_TOKEN_FILE="/x/jwt"))
        self.assertTrue(self.child()["OTEL_RESOURCE_ATTRIBUTES"].endswith(",theorem.credential=oss-verify-ci"))
        self.run_review(**self.collector(ANTHROPIC_SERVICE_ACCOUNT_ID="svac_other",
                                         ANTHROPIC_IDENTITY_TOKEN_FILE="/x/jwt"))
        self.assertNotIn("theorem.credential", self.child()["OTEL_RESOURCE_ATTRIBUTES"])

    def test_a_token_the_collector_refuses_stops_the_review(self):
        out = self.run_review(**self.collector(OTEL_COLLECTOR_TOKEN="wrong-token-not-a-secret"))
        self.assertEqual(out.returncode, 1)
        self.assertIn("answered 401", out.stderr)
        self.assertNotIn("wrong-token-not-a-secret", out.stdout + out.stderr)
        self.assertFalse((self.directory / "environ").exists())

    def test_a_curlrc_never_prints_the_token(self):
        (self.directory / ".curlrc").write_text(f"verbose\ntrace-ascii {self.directory}/trace\n")
        out = self.run_review(**self.collector(CURL_HOME=str(self.directory)))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn(self.TOKEN, out.stdout + out.stderr)
        self.assertFalse((self.directory / "trace").exists())

    def test_a_token_refused_after_the_review_keeps_the_review_and_fails(self):
        self.answers = [200, 401]
        out = self.run_review(**self.collector())
        self.assertEqual(out.returncode, 3, out.stderr)
        self.assertIn("answered 401", out.stderr)
        self.assertIn("usage is likely lost", out.stderr)
        self.assertNotIn(self.TOKEN, out.stdout + out.stderr)
        self.assertEqual((self.directory / "review" / "comment.md").read_text(), "Thanks.\n")

    def test_a_collector_that_does_not_answer_stops_the_review(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        out = self.run_review(**self.collector(OTEL_EXPORTER_OTLP_ENDPOINT=f"http://127.0.0.1:{port}"))
        self.assertEqual(out.returncode, 1)
        self.assertIn("answered 000", out.stderr)
        self.assertFalse((self.directory / "environ").exists())

    def test_without_the_collector_nothing_is_exported(self):
        out = self.run_review()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(set(self.child()), {"PATH", "HOME", "LANG", "ANTHROPIC_API_KEY", "CLAUDE_CODE_EFFORT"})
        self.assertEqual(self.headers, [])


if __name__ == "__main__":
    unittest.main()
