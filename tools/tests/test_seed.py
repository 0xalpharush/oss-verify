# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/seed.py:  python3 -m unittest discover -s tools/tests

They run offline, on fixtures/seed: a made-up release checkout (release/) and build recipe (recipe/).
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import projects_table  # noqa: E402
import seed  # noqa: E402
import validate  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "seed"
RELEASE = FIXTURE / "release"
RECIPE = seed.load_recipe(FIXTURE / "recipe")
IDENTITY = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.org",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.org"}
CEE = (
    "# Seeded by Theorem from oss-fuzz-theorems 2026.10.0-rc.2 (tools/seed.py), not enrolled by the project's\n"
    "# maintainers: provisional (STATUS.md). To adopt it, set primary_contact and remove these lines.\n"
    "repo: https://example.org/cee#1111111111111111111111111111111111111111\n"
    "primary_contact: n/a\n"
    "homepage: https://example.org/cee\n"
    "language: c\n"
    "sanitizers: [address, undefined]\n"
    "fuzz_targets: [cee_fuzzer]\n"
)


class Rules(unittest.TestCase):
    def test_a_c_project(self):
        found, text = seed.generate("cee", RELEASE, RECIPE, offline=True)
        self.assertEqual(found.reason, "")
        self.assertEqual(text, CEE)
        problems, warnings, _ = self.validate(text)
        self.assertEqual(problems, [])
        self.assertTrue(any("no build files yet" in warning for warning in warnings))

    def test_the_cxx_runtime_makes_it_cxx(self):
        found = seed.assess("plus", RELEASE, RECIPE)
        self.assertEqual((found.reason, found.language, found.targets), ("", "c++", ["plus_fuzzer"]))
        self.assertIn("plus_fuzzer: the harness is in OSS-Fuzz's repository, not the project's", found.notes)

    def test_our_own_harnesses_are_left_out(self):
        found = seed.assess("ours", RELEASE, RECIPE)
        self.assertIn("ours, not published yet", found.reason)
        self.assertEqual(found.kind, "only our own harnesses")

    def test_projects_the_release_did_not_build(self):
        found = seed.assess("snake", RELEASE, RECIPE)
        self.assertEqual(found.reason, "the release did not build it (status language-pending: python)")
        self.assertEqual(seed.assess("missing", RELEASE, RECIPE).reason, "not a project of the release")

    def test_a_patch_to_the_library_source(self):
        found = seed.assess("patched", RELEASE, RECIPE)
        self.assertIn("0001-lib-edit.patch edits src/lib.c, the library's own source", found.reason)
        self.assertEqual(found.kind, "every harness's build patches the library's own source")
        without = seed.assess("patched", RELEASE, None)
        self.assertIn("give --recipe", without.reason)

    def test_version_stamps_and_the_sanitizers_every_harness_has(self):
        found = seed.assess("stamped", RELEASE, RECIPE)
        self.assertEqual(found.reason, "")
        self.assertEqual(found.targets, ["stamped_fuzzer", "stamped_two"])
        self.assertEqual(found.sanitizers, ["undefined"])
        self.assertEqual(found.language, "c")
        self.assertTrue(any("reproducible build), none to its own source" in note for note in found.notes))

    def test_quoting(self):
        found, text = seed.generate("odd", RELEASE, RECIPE, offline=True)
        self.assertIn("fuzz_targets: ['1.0']\n", text)
        self.assertNotIn("homepage", text)
        self.assertEqual(yaml.safe_load(text)["fuzz_targets"], ["1.0"])
        self.assertEqual(found.language, "c++")

    def test_offline_names_the_commit(self):
        found = seed.assess("cee", RELEASE, RECIPE)
        self.assertEqual(found.version, "1.0")
        self.assertIsNone(seed.tag_for(found, offline=True))

    def test_file_kinds(self):
        for path, kind in [("fuzz/x.c", "harness"), ("test/fuzzers/y.cc", "harness"), ("src/fuzzStack.cxx", "harness"),
                           ("CMakeLists.txt", "build"), ("cmake/detect.c", "build"), ("m4/x.m4", "build"),
                           ("IGRAPH_VERSION", "build"), ("src/lib.c", "source"), ("include/x.h", "source")]:
            self.assertEqual(seed.file_kind(path), kind, path)
        edit = "--- a/src/lib.c\n+++ b/src/lib.c\n"
        create = "--- /dev/null\n+++ b/src/generated.c\n"
        delete = "--- a/src/old.c\n+++ /dev/null\n"
        self.assertEqual(seed.library_edit("Portability.", edit), "src/lib.c")
        self.assertIsNone(seed.library_edit("Reproducible build.", edit))
        self.assertIsNone(seed.library_edit("Build adaptation.", create))
        self.assertIsNone(seed.library_edit("Build adaptation.", delete))
        self.assertEqual(seed.library_edit("Portability.", delete), "src/old.c")
        self.assertEqual(seed.series_of("https://Example.org/Cee.git", "a" * 40), "example.org/cee/" + "a" * 40)

    @staticmethod
    def validate(text):
        with tempfile.TemporaryDirectory() as scratch:
            directory = pathlib.Path(scratch) / "cee"
            directory.mkdir()
            (directory / "project.yaml").write_text(text)
            return validate.check_project(directory)


class Report(unittest.TestCase):
    def test_report(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = pathlib.Path(scratch) / "seeded.tsv"
            counts = seed.report(RELEASE, RECIPE, path)
            lines = path.read_text().splitlines()
        self.assertTrue(lines[0].startswith("# generated by tools/seed.py"))
        self.assertEqual(lines[1], "project\tseedable\tfuzz_targets\treason or notes")
        rows = {line.split("\t")[0]: line.split("\t") for line in lines[2:]}
        self.assertEqual(rows["cee"][1:3], ["yes", "cee_fuzzer"])
        self.assertEqual(rows["snake"][1], "no")
        self.assertEqual(counts["seedable"], 4)


class Repository(unittest.TestCase):
    """--check and --branch, in a throwaway git repository."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.scratch.name) / "repo"
        projects = self.root / "projects" / "enrolled"
        projects.mkdir(parents=True)
        (projects / "project.yaml").write_text(
            "repo: https://example.org/enrolled\nprimary_contact: security@example.org\nlanguage: c\n")
        (projects / "Dockerfile").write_text("FROM x\n")
        (projects / "build.sh").write_text("#!/bin/bash\n")
        (self.root / "README.md").write_text(f"# A test\n\n{projects_table.BEGIN}\n{projects_table.END}\n")
        self.seeds = pathlib.Path(self.scratch.name) / "seeds"
        (self.seeds / "cee").mkdir(parents=True)
        (self.seeds / "cee" / "Dockerfile").write_text("FROM x\n")
        (self.seeds / "cee" / "build.sh").write_text("#!/bin/bash -eu\n")
        (self.seeds / "cee" / "build.sh").chmod(0o755)
        self.environment = mock.patch.dict(os.environ, IDENTITY)
        self.environment.start()
        self.run_git("init", "-q", "-b", "main")
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "main")

    def tearDown(self):
        self.environment.stop()
        self.scratch.cleanup()

    def run_git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True).stdout

    def test_branch(self):
        main = self.run_git("rev-parse", "main").strip()
        _, text = seed.generate("cee", RELEASE, RECIPE, offline=True)
        branch, commit = seed.make_branch("cee", text, ["Co-Authored-By: Someone <someone@example.org>"],
                                          root=self.root, seeds=self.seeds)
        self.assertEqual(branch, "draft-generic-oss-fuzz-cee")
        self.assertEqual(self.run_git("rev-parse", branch).strip(), commit)
        self.assertEqual(self.run_git("rev-parse", f"{commit}^").strip(), main)
        listing = self.run_git("ls-tree", "-r", commit)
        files = {line.split("\t")[1]: line.split()[0] for line in listing.splitlines()}
        self.assertEqual(files["projects/cee/build.sh"], "100755")
        self.assertEqual(files["projects/cee/Dockerfile"], "100644")
        self.assertIn("projects/enrolled/project.yaml", files)
        self.assertEqual(self.run_git("show", f"{commit}:projects/cee/project.yaml"), text)
        readme = self.run_git("show", f"{commit}:README.md")
        self.assertIn("| [cee](projects/cee/) | https://example.org/cee |", readme)
        self.assertIn("| [enrolled](projects/enrolled/) |", readme)
        message = self.run_git("log", "-1", "--format=%B", commit)
        self.assertTrue(message.startswith("Draft: seed projects/cee from oss-fuzz-theorems 2026.10.0-rc.2\n\n"))
        self.assertIn("Co-Authored-By: Someone <someone@example.org>", message)
        # The working tree, the index and HEAD are as they were.
        self.assertEqual(self.run_git("status", "--porcelain"), "")
        self.assertEqual(self.run_git("rev-parse", "HEAD").strip(), main)
        self.assertFalse((self.root / "projects" / "cee").exists())
        # Running it again replaces the branch.
        _, again = seed.make_branch("cee", text, [], root=self.root, seeds=self.seeds)
        self.assertEqual(self.run_git("rev-parse", branch).strip(), again)
        with self.assertRaises(seed.SeedError):
            seed.make_branch("enrolled", text, [], root=self.root, seeds=self.seeds)

    def test_check(self):
        projects = self.root / "projects"
        (projects / "cee").mkdir()
        (projects / "cee" / "project.yaml").write_text(CEE)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(seed.check(RELEASE, RECIPE, offline=True, projects=projects), 0)
            (projects / "cee" / "project.yaml").write_text(CEE.replace("[cee_fuzzer]", "[other]"))
            self.assertEqual(seed.check(RELEASE, RECIPE, offline=True, projects=projects), 1)
            tagged = CEE.replace("#1111111111111111111111111111111111111111", "#v1.0")
            (projects / "cee" / "project.yaml").write_text(tagged)
            self.assertEqual(seed.check(RELEASE, RECIPE, offline=True, projects=projects), 0)


if __name__ == "__main__":
    unittest.main()
