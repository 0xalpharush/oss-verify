# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/check that need no Docker, with the builds replaced:  python3 -m unittest discover -s tools/tests"""
import contextlib
import importlib.machinery
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_build  # noqa: E402
import manifest  # noqa: E402
import validate  # noqa: E402

TOOLS = pathlib.Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("check_tool", str(TOOLS / "check"))
SPEC = importlib.util.spec_from_loader("check_tool", LOADER)
check_tool = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(check_tool)

BUILDS = ["plain", "ubsan", "asan", "asan-ubsan"]
COMMIT = "a" * 40
TOOLCHAIN = "example.org/toolchain@sha256:" + "0" * 64


def entries(sha256s):
    """collect()'s entries for one fuzz target, `demo_fuzzer`, with these SHA-256s, one for each build."""
    return {"demo_fuzzer": {build: {"file": f"demo_fuzzer.{build}", "bytes": 1000 + i, "sha256": sha256}
                            for i, (build, sha256) in enumerate(zip(BUILDS, sha256s))}}


FIRST = entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64])


class Rebuild(unittest.TestCase):
    """manifest.rebuild: the block that tools/check --twice adds to the manifest."""

    def block(self, second):
        return manifest.rebuild(FIRST, second, list(second), host="host", at="2026-10-19T00:00:00Z",
                                builder={"toolchain": TOOLCHAIN, "image": "sha256:b", "project_image": "sha256:p"},
                                builds=BUILDS)

    def test_identical(self):
        block, differences, matched = self.block(entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64]))
        self.assertEqual((differences, matched), ([], 4))
        self.assertEqual(block, {
            "kind": "same-host", "host": "host", "at": "2026-10-19T00:00:00Z",
            "builder": {"toolchain": TOOLCHAIN, "image": "sha256:b", "project_image": "sha256:p"},
            "builds": BUILDS, "targets": {"demo_fuzzer": {"builds": FIRST["demo_fuzzer"]}}, "result": "identical",
        })

    def test_differs(self):
        block, differences, matched = self.block(entries(["1" * 64, "2" * 64, "f" * 64, "4" * 64]))
        self.assertEqual(block["result"], "differs")
        self.assertEqual(matched, 3)
        self.assertEqual(len(differences), 1)
        self.assertIn("demo_fuzzer.asan: sha256 " + "f" * 64, differences[0])
        # Its own SHA-256 for every binary, not the first build's.
        self.assertEqual(block["targets"]["demo_fuzzer"]["builds"]["asan"]["sha256"], "f" * 64)

    def test_a_different_set_of_binaries_differs(self):
        second = entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64])
        second["other_fuzzer"] = {"plain": {"file": "other_fuzzer.plain", "bytes": 1, "sha256": "5" * 64}}
        del second["demo_fuzzer"]["ubsan"]
        block, differences, _ = self.block(second)
        self.assertEqual(block["result"], "differs")
        self.assertEqual(differences, ["demo_fuzzer.ubsan: in the lock, not in this build",
                                       "other_fuzzer.plain: in this build, not in the lock"])


class Twice(unittest.TestCase):
    """tools/check --twice writes the rebuild block after its comparison, identical or not, and exits 3 if the builds
    differ."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        root = pathlib.Path(self.scratch.name)
        self.project = root / "demo"
        self.project.mkdir()
        (self.project / "project.yaml").write_text(
            "repo: https://example.org/demo\nprimary_contact: security@example.org\nlanguage: c\n")
        (self.project / "Dockerfile").write_text("FROM x\n")
        (self.project / "build.sh").write_text("#!/bin/bash\n")
        self.work = root / "work"

    def check(self, second):
        calls = []

        def build_all(*args, **kwargs):
            calls.append(yaml.safe_load((self.work / "manifest.yaml").read_text()) if calls else None)
            if len(calls) == 1:
                return "builder", "project", ["demo_fuzzer"], FIRST
            return "builder-twice", "project-twice", ["demo_fuzzer"], second

        argv = ["tools/check", "--twice", "--no-shell", "--toolchain", TOOLCHAIN, "--dir", str(self.work),
                str(self.project)]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(check_tool, "build_all", build_all))
            stack.enter_context(mock.patch.object(check_build, "resolve", lambda repo, ref: COMMIT))
            stack.enter_context(mock.patch.object(check_build, "image_id", lambda tag: f"sha256:{tag}"))
            stack.enter_context(mock.patch.object(check_build, "sources", lambda tag: {}))
            stack.enter_context(mock.patch.object(check_build, "oss_verify_state", lambda job: None))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = check_tool.main()
        # While the second build ran, the manifest had no rebuild block yet.
        self.assertEqual(len(calls), 2)
        self.assertNotIn("rebuild", calls[1])
        data = yaml.safe_load((self.work / "manifest.yaml").read_text())
        return code, data

    def test_identical(self):
        code, data = self.check(entries(["1" * 64, "2" * 64, "3" * 64, "4" * 64]))
        self.assertEqual(code, 0)
        self.assertEqual(list(data)[-1], "rebuild")
        rebuild = data["rebuild"]
        self.assertEqual(rebuild["result"], "identical")
        self.assertEqual(rebuild["kind"], "same-host")
        self.assertEqual(rebuild["builder"], {"toolchain": TOOLCHAIN, "image": "sha256:builder-twice",
                                              "project_image": "sha256:project-twice"})
        self.assertEqual(rebuild["builds"], BUILDS)
        self.assertEqual(rebuild["targets"], data["targets"])
        self.assertRegex(rebuild["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        # The first build's fields are as they are without --twice.
        self.assertEqual(data["builder"],
                         {"toolchain": TOOLCHAIN, "image": "sha256:builder", "project_image": "sha256:project"})
        self.assertEqual(data["targets"], {"demo_fuzzer": {"builds": FIRST["demo_fuzzer"]}})
        self.assertEqual(manifest.load_lock(self.work / "manifest.yaml")[0], COMMIT)

    def test_a_language_with_no_builder_yet(self):
        text = (self.project / "project.yaml").read_text().replace("language: c", "language: rust")
        (self.project / "project.yaml").write_text(text)
        with mock.patch.object(sys, "argv", ["tools/check", "--no-shell", str(self.project)]), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stop:
            check_tool.main()
        self.assertIn("which the builder cannot build yet", str(stop.exception.code))

    def test_differs(self):
        code, data = self.check(entries(["1" * 64, "e" * 64, "3" * 64, "4" * 64]))
        self.assertEqual(code, check_tool.DIFFERENT)
        self.assertEqual(data["rebuild"]["result"], "differs")
        self.assertEqual(data["rebuild"]["targets"]["demo_fuzzer"]["builds"]["ubsan"]["sha256"], "e" * 64)
        self.assertEqual(data["targets"]["demo_fuzzer"]["builds"]["ubsan"]["sha256"], "2" * 64)


class UbsanSettings(unittest.TestCase):
    """The UBSan checks that tools/check gives compile, by the toolchain's row in infra/toolchains.tsv."""

    def job(self, checks=None):
        return check_build.Job(name="demo", directory=pathlib.Path("/nowhere"), repo="https://example.org/demo",
                               ref="", dockerfile="", builds=BUILDS, fuzz_targets=None, ubsan_checks=checks)

    def test_a_fixed_toolchain_keeps_its_flags(self):
        with mock.patch.object(check_build, "ubsan_mode", return_value="fixed"):
            self.assertIsNone(check_tool.ubsan_settings(self.job(), TOOLCHAIN))
            with contextlib.redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit) as stop:
                check_tool.ubsan_settings(self.job(["null"]), TOOLCHAIN)
        self.assertEqual(stop.exception.code, 2)
        self.assertIn("keeps the release's fixed UBSan flags", error.getvalue())

    def test_a_toolchain_that_applies_the_checks(self):
        with mock.patch.object(check_build, "ubsan_mode", return_value="checks"):
            checks, left_out = check_tool.ubsan_settings(self.job(), TOOLCHAIN)
            self.assertEqual(checks, [check for check in validate.DEFAULT_UBSAN_CHECKS if check not in ("function", "vptr")])
            self.assertEqual(left_out, ["function", "vptr"])
            # A project's checks in effect (the default, changed): less those that trap mode leaves out.
            self.assertEqual(check_tool.ubsan_settings(self.job(["null", "alignment", "vptr"]), TOOLCHAIN)[0],
                             ["null", "alignment"])

    def test_today_s_toolchains_keep_the_fixed_flags(self):
        self.assertEqual(check_build.ubsan_mode(check_build.newest_toolchain()), "fixed")
        self.assertEqual(check_build.ubsan_mode(TOOLCHAIN), "fixed")


if __name__ == "__main__":
    unittest.main()
