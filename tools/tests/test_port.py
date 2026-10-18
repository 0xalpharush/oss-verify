# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/port.py, infra/base-builder/lay-out-sources and the vendored recipes.sh:
python3 -m unittest discover -s tools/tests"""
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import port  # noqa: E402
import validate  # noqa: E402

BUILDER = pathlib.Path(__file__).resolve().parents[2] / "infra" / "base-builder"
COMMIT = "1" * 40
OSS_FUZZ = "2" * 40
BLOB = "3" * 40


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


class Fixture:
    """A release checkout, its recipe and its assets for one project, demo, with three fuzz targets."""

    def __init__(self, root):
        self.checkout, self.recipe, self.assets = root / "release", root / "recipe", root / "assets"
        write(self.checkout / "projects/demo/project.yaml", """
            schema: oss-fuzz-theorems/project/1
            project: demo
            homepage: https://example.org/demo
            language: c
            status: available
            library: {repository: 'https://github.com/example/demo', commit: '%s', version: '1.0'}
            harnesses:
            - {name: demo_fuzzer, status: included, origin: upstream}
            - {name: first-fuzzer, status: included, origin: upstream}
            - {name: shared_fuzzer, status: included, origin: oss-fuzz}
            """ % COMMIT)
        for harness, source, origin in (("demo_fuzzer", "fuzz/demo_fuzzer.c", "upstream"),
                                        ("first-fuzzer", "fuzz/first.c", "upstream"),
                                        ("shared_fuzzer", "projects/demo/shared_fuzzer.c", "oss-fuzz")):
            write(self.checkout / f"projects/demo/{harness}/harness.yaml", """
                schema: oss-fuzz-theorems/harness/1
                harness: %s
                origin: %s
                source: {files: [source/x.c], from: {path: %s}}
                builds:
                  plain: {file: x.plain, bytes: 1, sha256: aa, uninstrumented: []}
                  ubsan: {file: x.ubsan, bytes: 1, sha256: aa, uninstrumented: []}
                  asan: {file: x.asan, bytes: 1, sha256: aa, uninstrumented: []}
                  asan-ubsan: {file: x.asan-ubsan, bytes: 1, sha256: aa, uninstrumented: []}
                modifications: []
                """ % (harness, origin, source))
        pin = """
            URL=https://github.com/example/demo.git
            COMMIT=%s
            BUILD_IMAGE=builder
            . /work/tools/ossfuzz/recipes.sh
            %s
            build_lib() {
              oft_build_cmake
              oft_build_harness "%s"
              oft_seal_getenv
            }
            LIB_ARCHIVE="lib/liboft.a"
            LIB_CFLAGS=""
            """
        write(self.recipe / "targets/demo-demo_fuzzer/pin", pin % (COMMIT, 'DEPENDS="demo-dep-lib"', "fuzz/demo_fuzzer.c"))
        write(self.recipe / "targets/demo/pin", pin % (COMMIT, '[ "${COMMIT:?}" = x ] || true', "fuzz/first.c"))
        write(self.recipe / "targets/demo-shared_fuzzer/pin", pin % (COMMIT, "", "shared_fuzzer.c"))
        write(self.recipe / "targets/demo-shared_fuzzer/seal_extra.c", "int seal;\n")
        write(self.recipe / "targets/demo-dep-lib/pin", pin % (COMMIT, "", "none.c"))
        for target in ("demo-demo_fuzzer", "demo", "demo-shared_fuzzer"):
            write(self.recipe / f"targets/{target}/plugin.c", '#include "ossfuzz_adapter.h"\n')
        write(self.recipe / "patches/series.tsv", f"""
            # the kept patches
            series\torder\tpatch\tclass\tsha256\ttargets
            github.com/example/demo/{COMMIT}\t1\t0001-build.patch\tBuild adaptation.\t00\tdemo
            """)
        write(self.recipe / f"patches/github.com/example/demo/{COMMIT}/0001-build.patch",
              "--- a/CMakeLists.txt\n+++ b/CMakeLists.txt\n@@ -1 +1 @@\n-x\n+y\n")
        write(self.recipe / "MANIFEST.tsv", f"""
            path\tsha256\tbytes\tmode\tkind\twhy
            targets/demo-shared_fuzzer/shared_fuzzer.c\t{"4" * 64}\t10\t644\tupstream\tsrc-asset git https://github.com/google/oss-fuzz.git {OSS_FUZZ} projects/demo/shared_fuzzer.c {BLOB}; named in the pin
            """)
        pins = ",".join(f"{t}=ext/{t}/src" for t in ("demo-demo_fuzzer", "demo", "demo-shared_fuzzer", "demo-dep-lib"))
        write(self.assets / "demo-src.MANIFEST.tsv", f"""
            # oft-upstream-sources/1
            tree\tkind\tsource\tid\tpins\tdetail
            demo-src/git/demo\tgit\thttps://github.com/example/demo.git\t{COMMIT}\t{pins}\t{{"materialise":["checkout"]}}
            demo-src/git/oss-fuzz\tgit-subtree\thttps://github.com/google/oss-fuzz.git\t{OSS_FUZZ}\tdemo-shared_fuzzer=provenance,demo-shared_fuzzer=recipe\t{{"materialise":["provenance","recipe-file"]}}
            """)


class Port(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.fixture = Fixture(pathlib.Path(self.scratch.name))
        self.release = port.Release(self.fixture.checkout, self.fixture.recipe, self.fixture.assets)

    def tearDown(self):
        self.scratch.cleanup()

    def test_targets_are_mapped_by_name_and_by_harness_source(self):
        files, _ = port.plan("demo", self.release)
        build = files["build.sh"]
        self.assertIn("# demo_fuzzer: the release's target demo-demo_fuzzer\n(\nov_target_begin demo-demo_fuzzer demo-dep-lib\n", build)
        self.assertIn("# first-fuzzer: the release's target demo\n(\nov_target_begin demo\n", build)
        self.assertIn("ov_target_build shared_fuzzer\n", build)

    def test_pins_are_kept_less_their_tree_and_recipes_lines(self):
        build = port.plan("demo", self.release)[0]["build.sh"]
        self.assertNotIn("URL=", build)
        self.assertNotIn(f"COMMIT={COMMIT}", build)
        self.assertNotIn("BUILD_IMAGE", build)
        self.assertNotIn("/work/tools/ossfuzz/recipes.sh", build)
        self.assertIn('  oft_build_harness "fuzz/first.c"\n', build)
        self.assertIn("ov_target_dependency demo-dep-lib <<'OV_PIN_END'\n", build)
        # The pin that reads $COMMIT gets it from the checkout, not from a constant.
        self.assertIn('COMMIT=$(git -C "$SRC/upstream/demo" rev-parse HEAD)\n', build)
        self.assertTrue(build.startswith("#!/bin/sh -e\n"))

    def test_sources_lay_out_trees_files_and_patches(self):
        files, _ = port.plan("demo", self.release)
        lines = [line for line in files["sources"].splitlines() if not line.startswith("#")]
        self.assertEqual(lines[0], "tree\text/demo-dep-lib/src\tupstream/demo")
        self.assertIn("link\text/demo-demo_fuzzer/src\text/demo-dep-lib/src", lines)
        # The patched target has a tree of its own.
        self.assertIn("tree\text/demo/src\tupstream/demo", lines)
        self.assertIn("patch\text/demo/src\tdemo.0001-build.patch", lines)
        self.assertEqual(files["series"], "demo.0001-build.patch\n")
        self.assertIn("copy\ttargets/demo-shared_fuzzer/seal_extra.c\tdemo-shared_fuzzer.seal_extra.c", lines)
        self.assertIn(f"file\ttargets/demo-shared_fuzzer/shared_fuzzer.c\thttps://raw.githubusercontent.com/google/oss-fuzz/"
                      f"{OSS_FUZZ}/projects/demo/shared_fuzzer.c\t{'4' * 64}", lines)
        self.assertIn("RUN fetch-commit $SRC/upstream/demo\n", files["Dockerfile"])
        self.assertNotIn(COMMIT, files["Dockerfile"])

    def test_the_port_passes_the_rules(self):
        files, _ = port.plan("demo", self.release)
        directory = pathlib.Path(self.scratch.name) / "out" / "demo"
        port.write(directory, files)
        (directory / "project.yaml").write_text(
            "repo: https://github.com/example/demo#" + COMMIT + "\nprimary_contact: n/a\nlanguage: c\n")
        problems, _, _ = validate.check_project(directory)
        self.assertEqual(problems, [])
        self.assertTrue(os.access(directory / "build.sh", os.X_OK))

    def test_what_cannot_be_ported_says_why(self):
        (self.fixture.recipe / "targets/demo/shims").mkdir()
        with self.assertRaisesRegex(port.Unsupported, "a directory or link of its own files"):
            port.plan("demo", self.release)
        (self.fixture.recipe / "targets/demo/shims").rmdir()
        manifest = self.fixture.assets / "demo-src.MANIFEST.tsv"
        manifest.write_text(manifest.read_text() + "demo-src/archive/x\tvendor-tree\thttps://x\tid\tdemo=ext/demo/src/oft-vendor/x\t{}\n")
        with self.assertRaisesRegex(port.Unsupported, "of kind vendor-tree"):
            port.plan("demo", self.release)


class LayOutSources(unittest.TestCase):
    def test_local_directives(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            src, root, files = scratch / "src", scratch / "work", scratch / "src" / "project"
            checkout = src / "upstream" / "demo"
            (checkout / ".git").mkdir(parents=True)
            (checkout / "CMakeLists.txt").write_text("x\n")
            os.symlink("CMakeLists.txt", checkout / "link")
            files.mkdir()
            (files / "shim.c").write_text("int shim;\n")
            (files / "0001.patch").write_text("--- a/CMakeLists.txt\n+++ b/CMakeLists.txt\n@@ -1 +1 @@\n-x\n+y\n")
            (files / "series").write_text("0001.patch\n")
            (files / "sources").write_text(
                "# a comment\ntree\text/a/src\tupstream/demo\nlink\text/b/src\text/a/src\n"
                "copy\ttargets/a/shim.c\tshim.c\npatch\text/a/src\t0001.patch\n")
            done = subprocess.run([sys.executable, str(BUILDER / "lay-out-sources"), str(files / "sources"), str(root)],
                                  env={**os.environ, "SRC": str(src)}, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual((root / "ext/a/src/CMakeLists.txt").read_text(), "y\n")
            self.assertFalse((root / "ext/a/src/.git").exists())
            self.assertTrue((root / "ext/a/src/link").is_symlink())
            self.assertEqual(os.readlink(root / "ext/b/src"), str(root / "ext/a/src"))
            self.assertEqual((root / "targets/a/shim.c").read_text(), "int shim;\n")

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            for text, error in (("tree\t../x\tupstream\n", "not a relative path"),
                                ("file\tx\thttp://example.org/x\t00\n", "only https"),
                                ("unknown\tx\n", "not a directive")):
                (scratch / "sources").write_text(text)
                done = subprocess.run([sys.executable, str(BUILDER / "lay-out-sources"), str(scratch / "sources"),
                                       str(scratch / "root")], env={**os.environ, "SRC": str(scratch)},
                                      capture_output=True, text=True)
                self.assertNotEqual(done.returncode, 0, text)
                self.assertIn(error, done.stderr, text)


class VendoredRecipes(unittest.TestCase):
    def test_recipes_sh_is_the_release_s_but_for_its_substitution(self):
        """Below its header, recipes.sh undoes to the release's file, whose sha256 the header names."""
        text = (BUILDER / "recipes.sh").read_text(encoding="utf-8")
        marker = "# Its comments were blanked by the release, which is why many lines hold only spaces.\n"
        body = text[text.index(marker) + len(marker):]
        original = body.replace(" /usr/local/lib/oss-verifier/driver/wrap_", " /work/src/wrap_")
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),
                         "b5ab933ca8a32fc3604a5ba9f0b655058d5dec93a0f46e382d172effd3d16399")


if __name__ == "__main__":
    unittest.main()
