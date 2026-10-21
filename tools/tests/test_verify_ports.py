# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/verify_ports.py that need no Docker, with docker replaced:  python3 -m unittest discover -s tools/tests"""
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_build  # noqa: E402
import verify_ports  # noqa: E402

COMMIT = "0123456789abcdef" * 2 + "01234567"
BUILDER = "oss-verify-base-builder:0123456789abcdef-toolchain"


class Host:
    """A Docker host: images by tag, and running containers as {name: (image, labels)}."""

    def __init__(self, images, containers):
        self.images = set(images)
        self.containers = dict(containers)

    def run(self, argv, **kwargs):
        assert argv[0] == "docker", argv
        stdout = ""
        if argv[1:3] == ["image", "rm"]:
            self.images -= set(argv[3:])
        elif argv[1] == "ps":
            kind, _, value = argv[argv.index("--filter") + 1].partition("=")
            if kind == "ancestor":
                match = lambda image, labels: image == value
            else:
                key, _, wanted = value.partition("=")
                match = lambda image, labels: labels.get(key) == wanted
            stdout = "\n".join(sorted(name for name, (image, labels) in self.containers.items() if match(image, labels)))
        elif argv[1] == "kill":
            for name in argv[2:]:
                self.containers.pop(name)
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, stdout, "")


class TwoRuns(unittest.TestCase):
    """Two tools/check runs of one project with the same inputs (the same projects/<name>/ and infra/, as two heads
    that differ only in tools/ have), in two work directories, on one Docker host. Cleaning up after one leaves the
    other's image and containers alone."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = pathlib.Path(scratch.name)
        (root / "demo").mkdir()
        (root / "demo" / "project.yaml").write_text("repo: x\n")
        self.job = check_build.Job(name="demo", directory=root / "demo", repo="https://example.org/demo", ref="",
                                   dockerfile="", builds=["plain"], fuzz_targets=None, ubsan_checks=None, language="c")
        self.mine, self.theirs = root / "mine" / "check", root / "theirs" / "check"
        self.tags = {}
        containers = {}
        for who, home in (("mine", self.mine), ("theirs", self.theirs)):
            home.mkdir(parents=True)
            tag = check_build.project_tag(self.job, COMMIT, BUILDER, home)
            check_build.record_image(home / check_build.IMAGES, tag)
            self.tags[who] = tag
            label = dict([check_build.work_label(home)[1].split("=", 1)])
            containers[f"c-{who}"] = (tag, label)
        self.host = Host(self.tags.values(), containers)
        patch = mock.patch.object(verify_ports.subprocess, "run", self.host.run)
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_runs_have_different_tags(self):
        self.assertNotEqual(self.tags["mine"], self.tags["theirs"])
        self.assertEqual(self.tags["mine"], check_build.project_tag(self.job, COMMIT, BUILDER, self.mine))

    def test_clean_up_leaves_the_other_run_alone(self):
        verify_ports.clean_up(self.mine)
        self.assertEqual(self.host.images, {self.tags["theirs"]})
        self.assertEqual(set(self.host.containers), {"c-theirs"})

    def test_a_crashed_runs_leftovers_are_cleaned_up_before_its_directory_goes(self):
        options = types.SimpleNamespace(work=self.mine.parent.parent / "ports", checkout=pathlib.Path("/nowhere"))
        leftover = options.work / "demo" / "check"  # verify()'s layout: <work>/<name>/check
        leftover.mkdir(parents=True)
        tag = check_build.project_tag(self.job, COMMIT, BUILDER, leftover.absolute())
        check_build.record_image(leftover / check_build.IMAGES, tag)
        self.host.images.add(tag)
        self.host.containers["c-leftover"] = (tag, dict([check_build.work_label(leftover.absolute())[1].split("=", 1)]))
        release = types.SimpleNamespace(patches=None, harnesses=None)
        with mock.patch.object(verify_ports.seed, "generate", lambda *args, **kwargs: (
                types.SimpleNamespace(reason="stop here"), None)):
            self.assertEqual(verify_ports.verify("demo", options, release)[0], "not-ported")
        self.assertEqual(self.host.images, set(self.tags.values()))
        self.assertEqual(set(self.host.containers), {"c-mine", "c-theirs"})

    def test_nothing_recorded_removes_no_image(self):
        empty = self.mine.parent / "empty"
        empty.mkdir()
        verify_ports.clean_up(empty)
        self.assertEqual(self.host.images, set(self.tags.values()))
        self.assertEqual(set(self.host.containers), {"c-mine", "c-theirs"})


class Record(unittest.TestCase):
    def test_recorded_in_order_each_once(self):
        with tempfile.TemporaryDirectory() as scratch:
            record = pathlib.Path(scratch) / check_build.IMAGES
            for tag in ("a:1", "a:1-twice", "a:1"):
                check_build.record_image(record, tag)
            self.assertEqual(check_build.recorded_images(record), ["a:1", "a:1-twice"])


if __name__ == "__main__":
    unittest.main()
