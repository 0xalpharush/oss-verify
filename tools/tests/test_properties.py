# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/properties.py, the property checks of tools/check:  python3 -m pytest tools/tests

The tests of the C reader and of the mutant runs need no Docker. One test builds tests/fixtures/property-example and
runs the whole step; it needs Docker, the toolchain image and a static qemu-riscv64:

    OV_DOCKER_TESTS=1 python3 -m pytest tools/tests/test_properties.py
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_build  # noqa: E402
import manifest  # noqa: E402
import properties  # noqa: E402
import validate  # noqa: E402
from test_manifest import PT_DYNAMIC, PT_INTERP, PT_LOAD, elf  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "property-example"
BUILDS = {build: validate.BUILDS[build] for build in validate.BUILDS}


def checks(text):
    """{abort() line: (guard, records, not a property, problems)} of a source."""
    return {check.line: (check.guard, [str(record) for record in check.records], check.not_property, check.problems)
            for check in properties.find_checks(text)}


class Reader(unittest.TestCase):
    """find_checks: each abort() call, its guard, and the records in its comment."""

    def test_comments_strings_and_directives_are_not_code(self):
        code, comments = properties.blank('a = "abort()"; /* abort() */ b = \'"\'; // abort()\n#define X abort()\nc;\n')
        self.assertNotIn("abort", code)
        self.assertEqual(len(comments), 2)
        self.assertEqual(code.count("\n"), 3)
        self.assertIn("c;", code)

    def test_guards(self):
        source = "\n".join([
            "int f(int a, int b) {",            # 1
            "  if (a)",                          # 2
            "    abort();",                      # 3
            "  if (a > 1 &&",                    # 4
            "      b > 2) {",                    # 5
            "    abort();",                      # 6
            "  }",                               # 7
            "  if (b) {",                        # 8
            "    g();",                          # 9
            "  } else {",                        # 10
            "    abort();",                      # 11
            "  }",                               # 12
            "  if (b == 3) g(); else if (a == 4) std::abort();",  # 13
            "  switch (a +",                     # 14
            "          b) {",                    # 15
            "  case 1: break;",                  # 16
            "  default: abort();",               # 17
            "  }",                               # 18
            "  g();",                            # 19
            "  abort();",                        # 20
            "  while (a--) __builtin_abort();",  # 21
            "}",                                 # 22
            "void abort(void);",                 # 23
            "[[noreturn]] void abort();",        # 24
        ])
        found = checks(source)
        self.assertEqual({line: guard for line, (guard, *_) in found.items()},
                         {3: (2, 2), 6: (4, 5), 11: (8, 8), 13: (13, 13), 17: (14, 15), 20: (20, 20), 21: (21, 21)})

    def test_records(self):
        source = "\n".join([
            "/* A comment that is not the check's. */",            # 1
            "int x;",                                               # 2
            "/* The sum is right.",                                 # 3
            " * mutant: src/a.c:12 `a + b` -> `a - b`",             # 4
            " * input: seed-1",                                     # 5
            " * mutant: src/a.c:13 `return 0;` -> ``",              # 6
            " * input: seed two */",                                # 7
            "if (sum(a, b) != a + b)",                              # 8
            "\tabort();",                                           # 9
            "// mutant: fuzz/x.c:3 `<` -> `<=`",                     # 10
            "// input: s",                                          # 11
            "if (x) abort();",                                      # 12
            "if (y)   /* not a property: malloc failed */",         # 13
            "\tabort();",                                           # 14
            "/* mutant: a.c:1 `a` -> `b` */",                       # 15
            "if (z) abort();",                                      # 16
            "/* input: s */",                                       # 17
            "if (w) abort();",                                      # 18
            "/* mutant: a.c `a` -> `b`",                            # 19
            "   input: s */",                                       # 20
            "if (v) abort();",                                      # 21
            "if (u) abort();",                                      # 22
        ])
        found = checks(source)
        self.assertEqual(found[9][1], ["src/a.c:12 `a + b` -> `a - b` on seed-1", "src/a.c:13 `return 0;` -> `` on seed two"])
        self.assertEqual(found[9][3], [])
        self.assertEqual(found[12][1], ["fuzz/x.c:3 `<` -> `<=` on s"])
        self.assertEqual(found[14][2], "malloc failed")
        self.assertEqual(found[14][1], [])
        self.assertEqual(found[16][1], [])
        self.assertIn("has no `input:` line", found[16][3][0])
        self.assertIn("no `mutant:` line before it", found[18][3][0])
        self.assertIn("is not `mutant:", found[21][3][0])
        # The check on line 22 is right after another: no comment is its own.
        self.assertEqual(found[22], ((22, 22), [], None, []))

    def test_mutate(self):
        record = properties.Record("a.c", 2, "x + 1", "x - 1", "s")
        self.assertEqual(properties.mutate(b"one\nreturn x + 1;\nthree\n", record), (b"one\nreturn x - 1;\nthree\n", None))
        self.assertIn("occurs 2 times", properties.mutate(b"\nx + 1 + x + 1\n", record)[1])
        self.assertIn("occurs 0 times", properties.mutate(b"\nx\n", record)[1])
        self.assertIn("has 1 lines, not 2", properties.mutate(b"x + 1", record)[1])

    def test_safe_path(self):
        self.assertTrue(properties.safe_path("src/a.c"))
        for path in ("/etc/passwd", "../a.c", "src/../../a.c", "", "a\\b.c"):
            self.assertFalse(properties.safe_path(path), path)


class Qemu(unittest.TestCase):
    """find_qemu takes only a qemu-riscv64 with no program interpreter: it runs inside the project image."""

    def test_only_a_static_qemu(self):
        with tempfile.TemporaryDirectory() as scratch:
            for segments, ok in (((PT_LOAD,), True), ((PT_LOAD, PT_DYNAMIC), True), ((PT_LOAD, PT_INTERP), False)):
                path = pathlib.Path(scratch) / "qemu"
                path.write_bytes(elf(segments=segments))
                found, why = properties.find_qemu(path)
                self.assertEqual(found is not None, ok, segments)
                self.assertEqual(why is None, ok)


class FakeImage:
    """In place of properties.Image: the files of the image, and a status for each run."""

    def __init__(self, files, status):
        self.workdir, self.files, self.status, self.runs_made = "/src/p", files, status, []

    def read(self, path):
        return self.files.get(path)

    def runs(self, jobs, binaries, inputs, coverage=False):
        self.runs_made.append((binaries, jobs))
        return [(self.status(pathlib.Path(binaries), binary, data), None) for binary, data, _ in jobs]


class Mutants(unittest.TestCase):
    """mutants(): each record built and run, plain first, until it is met."""

    def setUp(self):
        self.home = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.compiled = []

        def compile_build(tag, build, sanitizer, out, ubsan=None, *, labels, before=None, quiet=False):
            volumes, script, args = before
            self.assertEqual(script, properties.REPLACE)
            replacement = volumes[1].split(":")[0]
            self.compiled.append((build, args[0], pathlib.Path(replacement).read_bytes()))
            if self.broken:
                raise check_build.Failed(f"compile exited 1 in the {build} build")
            out.mkdir(parents=True, exist_ok=True)

        self.broken = False
        self.enterContext(mock.patch.object(check_build, "compile_build", compile_build))
        self.enterContext(mock.patch.object(check_build, "empty_directory",
                                            lambda path, tag, *, labels: path.mkdir(parents=True, exist_ok=True)))

    def run_records(self, records, status, files=None):
        target = properties.Target("t", {"s": b"", "u": b""}, "t.c", numbers={"s": "0/0", "u": "0/1"})
        target.checks = [properties.Check(10 + n, (9 + n, 9 + n), [record]) for n, record in enumerate(records)]
        image = FakeImage(files or {"src/a.c": b"int f(int a) {\n  return a + 1;\n}\n"}, status)
        findings = properties.mutants({"t": target}, image, "tag", self.home, BUILDS, None, [], self.home)
        return findings, image

    @staticmethod
    def statuses(unchanged=0, **mutant):
        """A status function: `unchanged` for the built targets, mutant[build] (default 0) for a mutant's."""
        def status(binaries, binary, data):
            if binaries.parent.parent.name == "mutants":
                return mutant.get(binaries.name.replace("-", "_"), 0)
            return unchanged
        return status

    def test_met_in_the_plain_build(self):
        findings, _ = self.run_records([properties.Record("src/a.c", 2, "a + 1", "a - 1", "s")],
                                       self.statuses(plain=134))
        self.assertEqual(findings, [])
        self.assertEqual([build for build, _, _ in self.compiled], ["plain"])
        self.assertEqual(self.compiled[0][1:], ("/src/p/src/a.c", b"int f(int a) {\n  return a - 1;\n}\n"))

    def test_met_only_in_an_asan_build(self):
        findings, _ = self.run_records([properties.Record("src/a.c", 2, "a + 1", "a - 1", "s")],
                                       self.statuses(asan=134))
        self.assertEqual(findings, [])
        self.assertEqual([build for build, _, _ in self.compiled], ["plain", "ubsan", "asan"])

    def test_not_met(self):
        findings, _ = self.run_records([properties.Record("src/a.c", 2, "a + 1", "a - 1", "s")], self.statuses())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, properties.NOT_MET)
        self.assertEqual(findings[0].where, "t.c:10")
        self.assertIn("unchanged plain 0 ubsan 0 asan 0 asan-ubsan 0; mutant plain 0 ubsan 0 asan 0 asan-ubsan 0",
                      findings[0].detail)
        self.assertEqual(len(self.compiled), 4)

    def test_the_unchanged_target_must_pass(self):
        findings, _ = self.run_records([properties.Record("src/a.c", 2, "a + 1", "a - 1", "s")],
                                       self.statuses(unchanged=134, plain=134))
        self.assertIn("the unchanged target does not exit 0 or 2", findings[0].detail)
        self.assertEqual(self.compiled, [])

    def test_a_record_that_does_not_fit(self):
        records = [properties.Record("src/a.c", 2, "a * 1", "a", "s"), properties.Record("src/b.c", 1, "x", "y", "s"),
                   properties.Record("../a.c", 1, "x", "y", "s"), properties.Record("src/a.c", 2, "a + 1", "a", "v")]
        findings, _ = self.run_records(records, self.statuses(plain=134))
        details = [finding.detail for finding in findings]
        self.assertTrue(any("occurs 0 times" in detail for detail in details))
        self.assertTrue(any("is not a path relative to the image's WORKDIR" in detail for detail in details))
        self.assertTrue(any("src/b.c is not in the project image" in detail for detail in details))
        self.assertTrue(any("has no file named v" in detail for detail in details))
        self.assertEqual(len(findings), 4)
        self.assertEqual(self.compiled, [])

    def test_a_mutant_that_does_not_build(self):
        self.broken = True
        findings, _ = self.run_records([properties.Record("src/a.c", 2, "a + 1", "a -", "s")], self.statuses())
        self.assertIn("the mutant does not build: compile exited 1 in the plain build", findings[0].detail)

    def test_one_build_for_records_that_share_a_mutant(self):
        record = properties.Record("src/a.c", 2, "a + 1", "a - 1", "s")
        findings, _ = self.run_records([record, properties.Record("src/a.c", 2, "a + 1", "a - 1", "u")],
                                       self.statuses(plain=134))
        self.assertEqual(findings, [])
        self.assertEqual(len(self.compiled), 1)


class Step(unittest.TestCase):
    """check(): what it reports when it cannot look, and the Markdown it writes."""

    def job(self, language):
        return check_build.Job(name="demo", directory=pathlib.Path("/nonexistent"), repo="r", ref="", dockerfile="",
                               builds=list(BUILDS), fuzz_targets=None, language=language)

    def test_another_language_is_not_checked(self):
        report = properties.check(self.job("rust"), "tag", pathlib.Path("/nonexistent"), ["t"], BUILDS, None, None, [])
        self.assertEqual([finding.kind for finding in report.findings], [properties.NOT_CHECKED])
        self.assertIn("C and C++", report.findings[0].detail)

    def test_no_qemu_is_not_checked(self):
        with mock.patch.object(properties, "find_qemu", return_value=(None, "no static qemu-riscv64")):
            report = properties.check(self.job("c"), "tag", pathlib.Path("/nonexistent"), ["t"], BUILDS, None, None, [])
        self.assertEqual(str(report.findings[0]), "not checked: no static qemu-riscv64")

    def test_markdown_shows_what_the_pull_request_chooses_as_code(self):
        report = properties.Report(targets=1, checks=2)
        report.findings.append(properties.Finding("a|b", "x.c:3", properties.NOT_MET, "`x` -> `y|z` on s\n#"))
        report.findings.append(properties.Finding("t", "x.c:4", properties.UNREACHED, "no seed runs its guard (line 4)"))
        report.information.append(properties.Finding("t", "x.c:5", properties.NOT_A_PROPERTY, "<b>malloc</b>"))
        text = properties.markdown(report, strict=False)
        rows = [line for line in text.splitlines() if line.startswith("| ")][1:]
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row.count("|"), 4, row)
            self.assertNotIn("<", row)
        self.assertIn("1 unreached", text)
        self.assertIn("They are warnings", text)
        self.assertIn("They fail tools/check", properties.markdown(report, strict=True))


def docker_ready():
    """Whether Docker runs and the pinned toolchain image is here."""
    try:
        return subprocess.run(["docker", "image", "inspect", check_build.toolchain()], capture_output=True).returncode == 0
    except OSError:
        return False


QEMU, _ = properties.find_qemu(os.environ.get("OV_QEMU_RISCV64"))


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready() and QEMU,
                     "set OV_DOCKER_TESTS=1, with Docker, the toolchain image and a static qemu-riscv64 (on PATH, or "
                     "in OV_QEMU_RISCV64), to run the property checks of the fixture")
class Fixture(unittest.TestCase):
    """The whole step on tests/fixtures/property-example: one property check of each kind."""

    TAG = "oss-verify-test/property-example:latest"

    def test_findings(self):
        work = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(prefix="ov-test-properties.")))
        directory = work / "project"
        shutil.copytree(FIXTURE, directory)
        with zipfile.ZipFile(directory / "fuzz_prop_seed_corpus.zip", "w") as archive:
            archive.writestr("two", b"\x02\x03")
            archive.writestr("zero", b"\x00\x00")
        job = check_build.Job(name="property-example", directory=directory, repo="https://example.invalid/p", ref="",
                              dockerfile="", builds=list(BUILDS), fuzz_targets=None, language="c")
        builder = check_build.build_builder()
        self.addCleanup(subprocess.run, ["docker", "image", "rm", self.TAG], capture_output=True)
        check_build.build_project(job, "0" * 40, builder, self.TAG, work)
        labels = check_build.work_label(work)
        raw = {}
        for build, sanitizer in BUILDS.items():
            raw[build] = work / "raw" / build
            check_build.compile_build(self.TAG, build, sanitizer, raw[build], labels=labels)
        targets, problems = manifest.resolve_targets({build: manifest.discover(path) for build, path in raw.items()})
        self.assertEqual((targets, problems), (["fuzz_prop"], []))
        _, missing = manifest.collect(raw, targets, work / "out")
        self.assertEqual(missing, [])

        report = properties.check(job, self.TAG, work, targets, BUILDS, None, QEMU, labels)
        found = [(finding.where, finding.kind) for finding in report.findings]
        self.assertEqual(found, [
            ("fuzz_prop.c:30", properties.NOT_MET),
            ("fuzz_prop.c:34", properties.NO_RECORD),
            ("fuzz_prop.c:34", properties.UNREACHED),
            ("fuzz_prop.c:39", properties.NOT_MET),
            ("fuzz_prop.c:42", properties.BAD_RECORD),
        ], "\n".join(map(str, report.findings)))
        self.assertIn("unchanged plain 0 ubsan 0 asan 0 asan-ubsan 0; mutant plain 0 ubsan 0 asan 0 asan-ubsan 0",
                      report.findings[0].detail)
        self.assertIn("has no file named missing", report.findings[3].detail)
        self.assertEqual([str(item) for item in report.information],
                         ["fuzz_prop fuzz_prop.c:17 not a property: malloc failed"])
        self.assertEqual(report.checks, 5)
