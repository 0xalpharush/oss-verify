# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/seed.py:  python3 -m unittest discover -s tools/tests

They run offline, on fixtures/seed: a made-up release checkout (release/) and build recipe (recipe/).
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import seed  # noqa: E402
import validate  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "seed"
RELEASE = FIXTURE / "release"
RECIPE = seed.load_recipe(FIXTURE / "recipe")
IDENTITY = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.org",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.org"}
CEE = (
    "# Seeded by Theorem from the oss-fuzz-theorems 2026.10 release (tools/seed.py), not enrolled by the project's\n"
    "# maintainers: provisional. To adopt it, set primary_contact and remove these lines (docs/project-yaml.md).\n"
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

    def test_a_harness_built_from_another_commit_is_left_out(self):
        with tempfile.TemporaryDirectory() as scratch:
            release = pathlib.Path(scratch) / "release"
            shutil.copytree(RELEASE, release)
            harness = release / "projects/stamped/stamped_two/harness.yaml"
            harness.write_text(harness.read_text() + "library: {repository: 'https://example.org/stamped', commit: '"
                               + "6" * 40 + "'}\n")
            found = seed.assess("stamped", release, RECIPE)
        self.assertEqual(found.targets, ["stamped_fuzzer"])
        self.assertIn("left out: stamped_two (built from another commit of the library, 666666666666)", found.notes)

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


class Targets(unittest.TestCase):
    def test_a_harness_is_mapped_to_the_release_s_target_that_builds_it(self):
        targets = {"demo-one": {"one.c"}, "demo": {"first.c"}, "demo-pcd_aes_fuzzer": {"pcd_aes_fuzzer.cc", "pcd_aes_oft.cc"},
                   "demo-dep-lib": set(), "other-two": {"two.c"}}
        self.assertEqual(seed.target_of("demo", "one", "one.c", targets), "demo-one")  # by name
        self.assertEqual(seed.target_of("demo", "first_fuzzer", "first.c", targets), "demo")  # by its source
        self.assertEqual(seed.target_of("demo", "first", None, targets), "demo")  # by the file named after it
        self.assertEqual(seed.target_of("demo", "aes_fuzzer", None, targets), "demo-pcd_aes_fuzzer")  # a file holding it
        self.assertIsNone(seed.target_of("demo", "two", None, targets))  # another project's
        targets["demo-aes_fuzzer_two"] = {"aes_fuzzer_two.c"}
        self.assertIsNone(seed.target_of("demo", "aes_fuzzer", None, targets))  # two files hold it


class Repositories(unittest.TestCase):
    def test_a_repository_the_release_names_by_a_url_git_cannot_fetch(self):
        mirror = {"https://example.org/stamped": "https://example.org/mirror/stamped"}
        with mock.patch.dict(seed.REPOSITORIES, mirror):
            stamped = seed.assess("stamped", RELEASE, RECIPE)
        self.assertEqual(stamped.repo, "https://example.org/mirror/stamped")
        self.assertEqual(stamped.release_repo, "https://example.org/stamped")
        self.assertIn("repo: the release names https://example.org/stamped, from which git cannot fetch the commit over "
                      "https; https://example.org/mirror/stamped serves it", stamped.notes)
        # The release's patches are still found, under the repository as the release names it.
        self.assertTrue(any("1 patch(es) to the library's tree" in note for note in stamped.notes))


class Report(unittest.TestCase):
    def test_report(self):
        builds = {"cee": ("reproduces", "all binaries match the release's"), "plus": ("fails", "configure fails")}
        with tempfile.TemporaryDirectory() as scratch:
            path = pathlib.Path(scratch) / "seeded.tsv"
            counts = seed.report(RELEASE, RECIPE, path, builds)
            lines = path.read_text().splitlines()
        self.assertTrue(lines[0].startswith("# generated by tools/seed.py"))
        self.assertEqual(lines[1], "project\tseedable\tfuzz_targets\tbuild\tbuild notes\treason or notes")
        rows = {line.split("\t")[0]: line.split("\t") for line in lines[2:]}
        self.assertEqual(rows["cee"][1:5], ["yes", "cee_fuzzer", "reproduces", "all binaries match the release's"])
        self.assertEqual(rows["plus"][3:5], ["fails", "configure fails"])
        self.assertEqual(rows["odd"][3:5], ["not checked", "-"])
        self.assertEqual(rows["snake"][1:5], ["no", "-", "-", "-"])
        self.assertEqual(counts["seedable"], 4)
        self.assertEqual(counts["seedable, build reproduces"], 1)
        self.assertEqual(counts["seedable, build not checked"], 2)

    def test_read_builds(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = pathlib.Path(scratch) / "builds.tsv"
            path.write_text("# generated\nproject\tresult\tdetail\ncee\treproduces\tall match\nplus\tfails\n")
            self.assertEqual(seed.read_builds(path), {"cee": ("reproduces", "all match"), "plus": ("fails", "")})
            self.assertEqual(seed.read_builds(pathlib.Path(scratch) / "none.tsv"), {})


class Tags(unittest.TestCase):
    """The tag of a pinned commit, from git ls-remote or from tools/seeds/tags.tsv."""

    PIN = seed.Seed(name="ex", repo="https://example.org/ex", commit="a" * 40, version="1.0")

    def test_the_cache_reads_back(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = pathlib.Path(scratch) / "tags.tsv"
            tags = {("https://example.org/b", "b" * 40): "v2", ("https://example.org/a", "a" * 40): ""}
            seed.write_tags(tags, path)
            self.assertEqual(seed.read_tags(path), tags)
            self.assertEqual(seed.read_tags(pathlib.Path(scratch) / "none.tsv"), {})

    def test_a_cached_pin_is_not_looked_up(self):
        with mock.patch.object(seed, "look_up_tag", side_effect=AssertionError("looked up")):
            self.assertEqual(seed.tag_for(self.PIN, False, {(self.PIN.repo, self.PIN.commit): "v1.0"}), "v1.0")
            self.assertIsNone(seed.tag_for(self.PIN, False, {(self.PIN.repo, self.PIN.commit): ""}))
            self.assertIsNone(seed.tag_for(self.PIN, True, {}))
        tags = {}
        with mock.patch.object(seed, "look_up_tag", return_value="1.0") as look:
            self.assertEqual(seed.tag_for(self.PIN, False, tags), "1.0")
            self.assertEqual(seed.tag_for(self.PIN, False, tags), "1.0")
        self.assertEqual(look.call_count, 1)
        self.assertEqual(tags, {(self.PIN.repo, self.PIN.commit): "1.0"})

    def test_new_pins_are_looked_up_in_parallel(self):
        pins = [seed.Seed(name=f"p{i}", repo=f"https://example.org/p{i}", commit=f"{i:040x}", version="1")
                for i in range(20)]
        pins += [seed.Seed(name="again", repo=pins[0].repo, commit=pins[0].commit, version="1"),
                 seed.Seed(name="unversioned", repo="https://example.org/u", commit="c" * 40)]
        asked = []

        def look(pin):
            asked.append(pin.name)
            if pin.name == "p3":
                raise seed.SeedError("p3: cannot list the tags")
            return "v1" if pin.name == "p5" else ""

        tags = {(pins[1].repo, pins[1].commit): "v9"}
        with mock.patch.object(seed, "look_up_tag", side_effect=look):
            errors = seed.look_up_tags(pins, tags)
        self.assertEqual(errors, ["p3: cannot list the tags"])
        self.assertEqual(sorted(asked), sorted(f"p{i}" for i in range(20) if i != 1))
        self.assertEqual(len(tags), 19)
        self.assertEqual(tags[(pins[5].repo, pins[5].commit)], "v1")
        self.assertEqual(tags[(pins[1].repo, pins[1].commit)], "v9")
        self.assertNotIn((pins[3].repo, pins[3].commit), tags)

    def test_lookups_run_together_but_few_on_one_host(self):
        github = [seed.Seed(name=f"g{i}", repo=f"https://github.com/o/g{i}", commit=f"{i:040x}", version="1")
                  for i in range(9)]
        other = [seed.Seed(name=f"x{i}", repo=f"https://git.example.org/x{i}", commit=f"{i + 100:040x}", version="1")
                 for i in range(4)]
        lock, running, most = threading.Lock(), {}, {}
        both = threading.Event()

        def look(pin):
            host = pin.repo.split("/")[2]
            with lock:
                running[host] = running.get(host, 0) + 1
                most[host] = max(most.get(host, 0), running[host])
                if len(running) == 2 and all(running.values()):
                    both.set()
            time.sleep(0.05)
            with lock:
                running[host] -= 1
            return ""

        with mock.patch.object(seed, "look_up_tag", side_effect=look), \
                mock.patch.object(seed, "HOST_JOBS", {"github.com": 3}), mock.patch.object(seed, "OTHER_HOST_JOBS", 1):
            self.assertEqual(seed.look_up_tags(github + other, {}), [])
        self.assertLessEqual(most["github.com"], 3)
        self.assertEqual(most["git.example.org"], 1)
        self.assertTrue(both.is_set(), "the two hosts were never asked at the same time")

    def test_a_slow_server_times_out(self):
        with mock.patch.object(seed.subprocess, "run", side_effect=subprocess.TimeoutExpired("git", 60)):
            with self.assertRaisesRegex(seed.SeedError, "took more than"):
                seed.look_up_tag(self.PIN)


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
        (self.root / "README.md").write_text("# A test\n")
        self.seeds = pathlib.Path(self.scratch.name) / "seeds"
        self.builds = {"cee": ("reproduces", "all binaries match the release's"),
                       "plus": ("fails", "configure: no C compiler")}
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
                                          root=self.root, seeds=self.seeds, builds=self.builds)
        self.assertEqual(branch, "draft-generic-oss-fuzz-cee")
        self.assertEqual(self.run_git("rev-parse", branch).strip(), commit)
        self.assertEqual(self.run_git("rev-parse", f"{commit}^").strip(), main)
        listing = self.run_git("ls-tree", "-r", commit)
        files = {line.split("\t")[1]: line.split()[0] for line in listing.splitlines()}
        self.assertEqual(files["projects/cee/build.sh"], "100755")
        self.assertEqual(files["projects/cee/Dockerfile"], "100644")
        self.assertIn("projects/enrolled/project.yaml", files)
        self.assertEqual(self.run_git("show", f"{commit}:projects/cee/project.yaml"), text)
        # The draft differs from main only in projects/cee/.
        self.assertEqual(self.run_git("diff", "--name-only", main, commit).split(),
                         ["projects/cee/Dockerfile", "projects/cee/build.sh", "projects/cee/project.yaml"])
        message = self.run_git("log", "-1", "--format=%B", commit)
        self.assertTrue(message.startswith("Draft: seed projects/cee from the oss-fuzz-theorems 2026.10 release\n\n"
                                           "Build files: tools/check builds them and reproduces"))
        self.assertIn("Co-Authored-By: Someone <someone@example.org>", message)
        # The working tree, the index and HEAD are as they were.
        self.assertEqual(self.run_git("status", "--porcelain"), "")
        self.assertEqual(self.run_git("rev-parse", "HEAD").strip(), main)
        self.assertFalse((self.root / "projects" / "cee").exists())
        # Running it again replaces the branch.
        _, again = seed.make_branch("cee", text, [], root=self.root, seeds=self.seeds, builds=self.builds)
        self.assertEqual(self.run_git("rev-parse", branch).strip(), again)
        self.assertEqual(self.run_git("rev-list", "--parents", "-n1", again).split()[1:], [main])
        # A draft that was pushed as it would be made again is kept as it is.
        self.run_git("update-ref", f"refs/remotes/origin/{branch}", again)
        _, kept = seed.make_branch("cee", text, [], root=self.root, seeds=self.seeds, builds=self.builds)
        self.assertEqual(kept, again)
        # Once main has moved on, the new draft is one commit on the new main, which replaces what was pushed.
        (self.root / "NOTES").write_text("more\n")
        self.run_git("add", "NOTES")
        self.run_git("commit", "-q", "-m", "more")
        main = self.run_git("rev-parse", "main").strip()
        _, moved = seed.make_branch("cee", text, [], root=self.root, seeds=self.seeds, builds=self.builds)
        self.assertEqual(self.run_git("rev-list", "--parents", "-n1", moved).split()[1:], [main])
        self.assertEqual(self.run_git("diff", "--name-only", main, moved).split(),
                         ["projects/cee/Dockerfile", "projects/cee/build.sh", "projects/cee/project.yaml"])
        with self.assertRaises(seed.SeedError):
            seed.make_branch("enrolled", text, [], root=self.root, seeds=self.seeds, builds=self.builds)

    def test_rebase(self):
        """Once main moves, a draft moves onto it as it is, with no lookup; a stale draft is refused."""
        _, text = seed.generate("cee", RELEASE, RECIPE, offline=True)
        options = {"root": self.root, "seeds": self.seeds, "builds": self.builds}
        _, first = seed.make_branch("cee", text, ["Co-Authored-By: Someone <someone@example.org>"], **options)
        message = self.run_git("log", "-1", "--format=%B", first)
        project = self.run_git("rev-parse", f"{first}:projects/cee").strip()
        (self.root / "NOTES").write_text("more\n")
        self.run_git("add", "NOTES")
        self.run_git("commit", "-q", "-m", "more")
        main = self.run_git("rev-parse", "main").strip()
        with mock.patch.object(seed, "look_up_tag", side_effect=AssertionError("looked up")):
            branch, moved = seed.rebase_branch("cee", **options)
        self.assertEqual(self.run_git("rev-parse", branch).strip(), moved)
        self.assertEqual(self.run_git("rev-list", "--parents", "-n1", moved).split()[1:], [main])
        self.assertEqual(self.run_git("rev-parse", f"{moved}:projects/cee").strip(), project)
        self.assertEqual(self.run_git("log", "-1", "--format=%B", moved), message)
        self.assertEqual(self.run_git("diff", "--name-only", main, moved).split(),
                         ["projects/cee/Dockerfile", "projects/cee/build.sh", "projects/cee/project.yaml"])
        self.assertEqual(self.run_git("status", "--porcelain"), "")
        # A pushed draft that is on main already is kept as it is.
        self.run_git("update-ref", f"refs/remotes/origin/{branch}", moved)
        self.assertEqual(seed.rebase_branch("cee", **options)[1], moved)
        # A draft that a reseed would make otherwise is refused, and left as it is.
        (self.seeds / "cee" / "build.sh").write_text("#!/bin/bash -eux\n")
        with self.assertRaisesRegex(seed.SeedError, "needs a full reseed: its build files"):
            seed.rebase_branch("cee", **options)
        (self.seeds / "cee" / "build.sh").write_text("#!/bin/bash -eu\n")
        with mock.patch.object(seed, "HEADER", "# Another header\n"):
            with self.assertRaisesRegex(seed.SeedError, "needs a full reseed: its project.yaml"):
                seed.rebase_branch("cee", **options)
        with mock.patch.object(seed.release_tag, "NAME", "another release"):
            with self.assertRaisesRegex(seed.SeedError, "needs a full reseed: its commit message"):
                seed.rebase_branch("cee", **options)
        self.assertEqual(self.run_git("rev-parse", branch).strip(), moved)
        with self.assertRaisesRegex(seed.SeedError, "no such branch"):
            seed.rebase_branch("plus", **options)

    def test_rebase_refuses_a_draft_that_changes_more(self):
        _, text = seed.generate("cee", RELEASE, RECIPE, offline=True)
        options = {"root": self.root, "seeds": self.seeds, "builds": self.builds}
        branch, commit = seed.make_branch("cee", text, [], **options)
        self.run_git("checkout", "-q", branch)
        (self.root / "README.md").write_text("# Changed\n")
        self.run_git("commit", "-q", "--amend", "-a", "--no-edit")
        self.run_git("checkout", "-q", "main")
        with self.assertRaisesRegex(seed.SeedError, "changes more than projects/cee/"):
            seed.rebase_branch("cee", **options)

    def test_branch_status(self):
        """A draft without build files says why it has none; build files the results do not vouch for are refused."""
        _, text = seed.generate("plus", RELEASE, RECIPE, offline=True)
        _, commit = seed.make_branch("plus", text, [], root=self.root, seeds=self.seeds, builds=self.builds)
        message = " ".join(self.run_git("log", "-1", "--format=%B", commit).split())
        self.assertIn("No build files yet: the build ported from the release's fails (configure: no C compiler).",
                      message)
        files = self.run_git("ls-tree", "-r", "--name-only", commit).split()
        self.assertEqual([path for path in files if path.startswith("projects/plus/")], ["projects/plus/project.yaml"])
        _, text = seed.generate("odd", RELEASE, RECIPE, offline=True)
        _, commit = seed.make_branch("odd", text, [], root=self.root, seeds=self.seeds, builds=self.builds)
        self.assertIn("has not been ported", self.run_git("log", "-1", "--format=%B", commit))
        _, text = seed.generate("cee", RELEASE, RECIPE, offline=True)
        with self.assertRaises(seed.SeedError):
            seed.make_branch("cee", text, [], root=self.root, seeds=self.seeds, builds={"cee": ("differs", "x")})
        with self.assertRaises(seed.SeedError):
            seed.make_branch("plus", text, [], root=self.root, seeds=self.seeds, builds={"plus": ("reproduces", "")})

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
