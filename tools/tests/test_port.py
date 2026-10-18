# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/port.py, infra/base-builder/lay-out-sources and the vendored recipes.sh:
python3 -m unittest discover -s tools/tests"""
import hashlib
import importlib.machinery
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import types
import unittest
import zipfile

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
        self.assertTrue(files["Dockerfile"].startswith("# Generated by tools/port.py"))
        self.assertNotIn(COMMIT, files["Dockerfile"])

    def test_files_in_subdirectories_are_stored_flat_and_keep_their_mode(self):
        script = self.fixture.recipe / "targets/demo/oft-stub/xml2-config"
        write(script, "#!/bin/sh\n")
        script.chmod(0o755)
        files, executable = port.plan("demo", self.release)
        self.assertIn("demo.oft-stub.xml2-config", files)
        self.assertIn("demo.oft-stub.xml2-config", executable)
        self.assertIn("copy\ttargets/demo/oft-stub/xml2-config\tdemo.oft-stub.xml2-config", files["sources"])

    def test_the_port_passes_the_rules(self):
        files, executable = port.plan("demo", self.release)
        directory = pathlib.Path(self.scratch.name) / "out" / "demo"
        port.write(directory, files, executable)
        (directory / "project.yaml").write_text(
            "repo: https://github.com/example/demo#" + COMMIT + "\nprimary_contact: n/a\nlanguage: c\n")
        problems, _, _ = validate.check_project(directory)
        self.assertEqual(problems, [])
        self.assertTrue(os.access(directory / "build.sh", os.X_OK))

    def test_what_cannot_be_ported_says_why(self):
        os.symlink("pin", self.fixture.recipe / "targets/demo/linked")
        with self.assertRaisesRegex(port.Unsupported, "a link or special file of its own"):
            port.plan("demo", self.release)
        (self.fixture.recipe / "targets/demo/linked").unlink()
        manifest = self.fixture.assets / "demo-src.MANIFEST.tsv"
        original = manifest.read_text()
        manifest.write_text(original + "demo-src/svn/x\tsvn\thttps://x\tid\tdemo=ext/demo/src/x\t{}\n")
        with self.assertRaisesRegex(port.Unsupported, "of kind svn"):
            port.plan("demo", self.release)
        manifest.write_text(original + "demo-src/archive/x\tvendor-file\thttp://example.org/x\tsha256:00\t"
                            "demo=ext/demo/src/x\t{}\n")
        with self.assertRaisesRegex(port.Unsupported, "not over https"):
            port.plan("demo", self.release)

    def test_other_trees_and_files(self):
        manifest = self.fixture.assets / "demo-src.MANIFEST.tsv"
        placements = {"demo=ext/demo/vendor-archives/ab": {"members_to": "ext/demo/src/oft-vendor/zlib", "strip": 1,
                                                          "select": ["!.github"]}}
        manifest.write_text(manifest.read_text() + "\n".join([
            f"demo-src/git/sub\tgit\thttps://github.com/example/sub.git\t{'5' * 40}\tdemo=ext/demo/src/third_party/sub"
            '\t{"materialise":["checkout"]}',
            "demo-src/git/super\tgitlink\thttps://github.com/example/sub.git\t" + "5" * 40 + "\t-\t{}",
            "demo-src/archive/f\tvendor-file\thttps://example.org/data.txt\tsha256:" + "6" * 64 +
            "\tdemo=ext/demo/src/data/data.txt\t{}",
            "demo-src/archive/z\tvendor-tree\thttps://example.org/zlib.tar.gz\tsha256:ab\tdemo=ext/demo/vendor-archives/ab"
            "\t" + json.dumps({"placements": placements}),
        ]) + "\n")
        lines = [line for line in port.plan("demo", self.release)[0]["sources"].splitlines() if not line.startswith("#")]
        demo = lines.index("tree\text/demo/src\tupstream/demo")
        self.assertEqual(lines[demo + 1:demo + 4], [
            "file\text/demo/src/data/data.txt\thttps://example.org/data.txt\t" + "6" * 64,
            "archive\text/demo/src/oft-vendor/zlib\thttps://example.org/zlib.tar.gz\tab\t1\t!.github",
            f"git\text/demo/src/third_party/sub\thttps://github.com/example/sub.git\t{'5' * 40}",
        ])
        self.assertIn("file\text/demo/vendor-archives/ab\thttps://example.org/zlib.tar.gz\tab", lines)

    def test_a_harness_with_no_recorded_source_is_found_by_its_name(self):
        harness = self.fixture.checkout / "projects/demo/first-fuzzer/harness.yaml"
        harness.write_text(harness.read_text().replace("source: {files: [source/x.c], from: {path: fuzz/first.c}}",
                                                       "source: {files: []}"))
        pin = self.fixture.recipe / "targets/demo/pin"
        pin.write_text(pin.read_text().replace("fuzz/first.c", "fuzz/first-fuzzer.c"))
        self.release = port.Release(self.fixture.checkout, self.fixture.recipe, self.fixture.assets)
        self.assertIn("# first-fuzzer: the release's target demo\n", port.plan("demo", self.release)[0]["build.sh"])


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


def lay_out_sources():
    """infra/base-builder/lay-out-sources, loaded as a module."""
    loader = importlib.machinery.SourceFileLoader("lay_out_sources", str(BUILDER / "lay-out-sources"))
    module = types.ModuleType(loader.name)
    loader.exec_module(module)
    return module


class Archives(unittest.TestCase):
    """The archive rules the release laid its vendored trees out by."""

    def tar(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as tar:
            for name, text in (("pkg-1.0/a.c", "a"), ("pkg-1.0/.github/ci.yml", "x"), ("pkg-1.0/fuzz/f.c", "f"),
                               ("pkg-1.0/src/fuzz/g.c", "g"), ("pkg-1.0/tool.sh", "t")):
                info = tarfile.TarInfo(name)
                info.size = len(text)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                tar.addfile(info, io.BytesIO(text.encode()))
            link = tarfile.TarInfo("pkg-1.0/b.c")
            link.type, link.linkname = tarfile.SYMTYPE, "a.c"
            tar.addfile(link)
        return data.getvalue()

    def test_strip_and_patterns(self):
        module = lay_out_sources()
        members = lambda *patterns: sorted(rel for rel, *_ in module.members(self.tar(), 1, patterns))
        self.assertEqual(members(), [".github/ci.yml", "a.c", "b.c", "fuzz/f.c", "src/fuzz/g.c", "tool.sh"])
        self.assertEqual(members("!.github", "!fuzz"), ["a.c", "b.c", "tool.sh"])
        self.assertEqual(members("!fuzz/"), [".github/ci.yml", "a.c", "b.c", "src/fuzz/g.c", "tool.sh"])
        self.assertEqual(members("src/", "*.sh"), ["src/fuzz/g.c", "tool.sh"])
        taken = {rel: (kind, content, executable) for rel, kind, content, executable in module.members(self.tar(), 1, ())}
        self.assertEqual(taken["b.c"], ("link", "a.c", False))
        self.assertEqual(taken["tool.sh"], ("file", b"t", True))

    def test_zip(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("pkg/x.c", "x")
            archive.writestr("pkg/compatibility/y.c", "y")
        module = lay_out_sources()
        self.assertEqual([rel for rel, *_ in module.members(data.getvalue(), 1, ("!compatibility/",))], ["x.c"])


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
