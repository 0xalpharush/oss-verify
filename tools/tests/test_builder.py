# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example and tests/fixtures/cjson with the builder and run what they make. Needs Docker and the
toolchain image (and, for cJSON, the network):

    OV_DOCKER_TESTS=1 python3 -m unittest discover -s tools/tests

The fixture's Dockerfile and build.sh are templates/Dockerfile and templates/build.sh (in its C and C++ forms). Its
fuzz targets do one thing per first input byte, and the test checks the exit status of each in every build against
docs/build-contract.md. Running the riscv64 binaries needs qemu-riscv64 (static) on this machine; without it, that part
is skipped.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_build  # noqa: E402
import manifest  # noqa: E402
import validate  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
TAG = "oss-verify-test/example:latest"
QEMU = shutil.which("qemu-riscv64-static") or shutil.which("qemu-riscv64")
BUILDS = list(validate.BUILDS)

# Payload first byte -> exit status in each build (plain, ubsan, asan, asan-ubsan), after the six-byte header.
# A load through a null pointer is a segmentation fault ('s'), except where UBSan's null check catches it first ('n'):
# clang does not check a volatile access ('s') for null.
EXPECTED = {
    "": (0, 0, 0, 0),
    "z": (0, 0, 0, 0),
    "m": (0, 0, 0, 0),
    "r": (78, 78, 78, 78),
    "x": (77, 77, 77, 77),
    # Only exit() is turned into 77: _exit, _Exit and quick_exit end the process with the target's own status.
    "u": (5, 5, 5, 5),
    "U": (6, 6, 6, 6),
    "k": (7, 7, 7, 7),
    "a": (134, 134, 134, 134),
    "s": (139, 139, 139, 139),
    "n": (139, 132, 139, 132),
    "o": (0, 132, 0, 132),
    "h": (0, 0, 134, 134),
}
CXX_ONLY = {"t": (134, 134, 134, 134)}  # an uncaught C++ exception

# The allocation-failure variants are the same objects linked with $LIB_ALLOCATION_FAILURE_ENGINE (example_fuzzer_af,
# example_fuzzer_cc_af), which ignores counting mode, and with $LIB_ALLOCATION_COUNTING_ENGINE (example_fuzzer_count,
# example_fuzzer_cc_count), in which counting mode makes the status the number of allocations counted. With no
# allocation mask they behave as their fuzz targets do (the cases above). These inputs set the mask (bit n: the n-th
# allocation fails) or ask for counting mode (bit 15 of the config word). 'h' allocates once, with malloc; 'N', in the
# C++ fuzz target, once with new[]; 'r' allocates nothing and returns 1. Input -> (header, payload, {fuzz target:
# statuses in each build}); a fuzz target not named has the status of the one before it in its group.
HEAP, ZERO, ONE, ABORT, BAD = (0, 0, 134, 134), (0, 0, 0, 0), (1, 1, 1, 1), (134, 134, 134, 134), (78, 78, 78, 78)
FAIL_FIRST, COUNT, COUNT_FAIL_FIRST, COUNT_FAIL_SECOND = (b"\0\0\1\0\0\0", b"\0\x80\0\0\0\0", b"\0\x80\1\0\0\0",
                                                         b"\0\x80\2\0\0\0")
TARGETS = ("example_fuzzer", "example_fuzzer_cc", "example_fuzzer_af", "example_fuzzer_cc_af", "example_fuzzer_count",
           "example_fuzzer_cc_count")


def statuses(fuzz_target, af, count, cxx_af=None, cxx_count=None, cxx=None):
    """The statuses of a case for each fuzz target: those of the C ones, and of the C++ ones where they differ."""
    cxx = fuzz_target if cxx is None else cxx
    return dict(zip(TARGETS, (fuzz_target, cxx, af, af if cxx_af is None else cxx_af, count,
                              count if cxx_count is None else cxx_count)))


ALLOCATION_FAILURE = {
    "af-h-fails": (FAIL_FIRST, "h", statuses(HEAP, ZERO, ZERO)),  # the heap read is never reached
    "af-h-count": (COUNT_FAIL_FIRST, "h", statuses(HEAP, ZERO, ONE)),
    "af-z-count": (COUNT, "z", statuses(ZERO, ZERO, ZERO)),
    "af-r-count": (COUNT, "r", statuses(ZERO, BAD, ZERO)),  # counting mode ignored: the return value counts
    "af-N-count": (COUNT, "N", statuses(ZERO, ZERO, ZERO, cxx_count=ONE)),
    "af-N-fails": (FAIL_FIRST, "N", statuses(ZERO, ZERO, ZERO, cxx_af=ABORT, cxx_count=ABORT)),  # std::bad_alloc
    "af-N-second": (COUNT_FAIL_SECOND, "N", statuses(ZERO, ZERO, ZERO, cxx_count=ONE)),
}

# Runs every case in one container: prints "<target> <build> <case> <status>" per line.
RUNNER = r"""
cd /in
for t in example_fuzzer example_fuzzer_cc example_fuzzer_af example_fuzzer_cc_af example_fuzzer_count example_fuzzer_cc_count; do
  for b in plain ubsan asan asan-ubsan; do
    for c in /in/case-*; do
      q /bin/$t.$b "$c" > /dev/null 2>&1; echo "$t $b ${c#/in/case-} $?"
    done
    q /bin/$t.$b /in/short > /dev/null 2>&1; echo "$t $b short $?"
    q /bin/$t.$b /in/missing > /dev/null 2>&1; echo "$t $b missing $?"
    q /bin/$t.$b > /dev/null 2>&1; echo "$t $b no-argument $?"
    printf '%s ' "$t $b calls"; q /bin/$t.$b /in/three-calls | tr '\n' ,; echo
  done
done
"""


def docker_ready():
    """Whether Docker runs and the pinned toolchain image is here."""
    try:
        return subprocess.run(["docker", "image", "inspect", check_build.toolchain()], capture_output=True).returncode == 0
    except OSError:
        return False


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class Builder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-builder.")
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, "0" * 40, builder, TAG, cls.work)
        cls.raw = {}
        for build in BUILDS:
            cls.raw[build] = cls.work / "raw" / build
            check_build.compile_build(TAG, build, validate.BUILDS[build], cls.raw[build])
        cls.found = {build: manifest.discover(directory) for build, directory in cls.raw.items()}
        cls.targets, cls.problems = manifest.resolve_targets(cls.found)
        cls.entries, cls.missing = manifest.collect(cls.raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", TAG], capture_output=True)

    def test_discovery(self):
        self.assertEqual(self.problems, [])
        self.assertEqual(self.missing, [])
        self.assertEqual(self.targets, sorted(TARGETS))
        for build in BUILDS:
            self.assertTrue((self.raw[build] / "tool").is_file(), "the non-target executable was built")
            self.assertNotIn("tool", self.found[build])

    def test_published_bytes_are_stripped(self):
        for target in self.targets:
            for build in BUILDS:
                path = self.work / "out" / target / f"{target}.{build}"
                self.assertFalse(manifest.has_symbol_table(path), path)
                self.assertEqual(self.entries[target][build]["sha256"], manifest.sha256_of(path))
                self.assertTrue(manifest.has_symbol_table(self.raw[build] / target))

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_exit_statuses(self):
        inputs = self.work / "in"
        inputs.mkdir()
        cases = {**EXPECTED, **CXX_ONLY}
        for case in cases:
            (inputs / f"case-{case or 'empty'}").write_bytes(b"\0" * 6 + case.encode())
        for case, (header, payload, _) in ALLOCATION_FAILURE.items():
            (inputs / f"case-{case}").write_bytes(header + payload.encode())
        (inputs / "short").write_bytes(b"\0\0\0")
        # A config word of 1, config byte 2: three calls.
        (inputs / "three-calls").write_bytes(b"\x01\x00\x02\0\0\0\0z")
        binaries = self.work / "bin"
        binaries.mkdir()
        for target in self.targets:
            for build in BUILDS:
                shutil.copy(self.work / "out" / target / f"{target}.{build}", binaries)
        runner = f"q() {{ timeout 60 /qemu \"$@\"; }}\n{RUNNER}"
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", TAG, "-c", runner.replace("/bin/", "/bin2/")],
            capture_output=True, text=True, check=True,
        )
        results = {}
        for line in done.stdout.splitlines():
            target, build, case, status = line.split(" ", 3)
            results[(target, build, case)] = status
        for target in self.targets:
            expected = {**EXPECTED, **(CXX_ONLY if "_cc" in target else {})}
            expected.update({case: statuses[target] for case, (_, _, statuses) in ALLOCATION_FAILURE.items()})
            for case, statuses in expected.items():
                for build, status in zip(BUILDS, statuses):
                    with self.subTest(target=target, build=build, case=case):
                        self.assertEqual(results[(target, build, case or "empty")], str(status))
            for build in BUILDS:
                for case in ("short", "missing", "no-argument"):
                    self.assertEqual(results[(target, build, case)], "2", (target, build, case))
                self.assertEqual(results[(target, build, "calls")], "0,0,0,", (target, build))


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class UbsanChecks(unittest.TestCase):
    """The UBSan checks that tools/check gives compile on a toolchain that applies a project's ubsan_checks."""

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_only_the_given_checks_trap(self):
        tag = "oss-verify-test/example-ubsan:latest"
        with tempfile.TemporaryDirectory(prefix="ov-test-ubsan.") as scratch:
            work = pathlib.Path(scratch)
            job = check_build.Job(name="example", directory=FIXTURE, repo="https://example.invalid/example", ref="",
                                  dockerfile="", builds=["ubsan"], fuzz_targets=None)
            try:
                check_build.build_project(job, "0" * 40, check_build.build_builder(), tag, work)
                raw = work / "raw"
                # null only: the null load traps, and the signed overflow, which the fixed flags catch, does not.
                check_build.compile_build(tag, "ubsan", "undefined", raw, (["null"], ["function", "vptr"]))
                inputs = work / "in"
                inputs.mkdir()
                for case in "no":
                    (inputs / f"case-{case}").write_bytes(b"\0" * 6 + case.encode())
                runner = ('for c in /in/*; do timeout 60 /qemu /raw/example_fuzzer "$c" > /dev/null 2>&1; '
                          'echo "${c#/in/} $?"; done')
                done = subprocess.run(
                    ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
                     "-v", f"{raw}:/raw:ro", "--entrypoint", "sh", tag, "-c", runner],
                    capture_output=True, text=True, check=True,
                )
            finally:
                subprocess.run(["docker", "image", "rm", tag], capture_output=True)
        results = dict(line.split() for line in done.stdout.splitlines())
        self.assertEqual(results, {"case-n": "132", "case-o": "0"})


CJSON = pathlib.Path(__file__).resolve().parent / "fixtures" / "cjson"
CJSON_TAG = "oss-verify-test/cjson:latest"
# cJSON 1.7.18, as the oss-fuzz-theorems 2026.10 release built it.
CJSON_COMMIT = "acc76239bee01d8e9c858ae2cab296704e52d916"
# That release's cjson_read_fuzzer binaries (its projects/cjson/cjson_read_fuzzer/harness.yaml).
CJSON_RELEASE = {
    "plain": "b40ed189a37beb50da46f04a457ec144b05319a845fa3b0639d7a117ffd1696d",
    "ubsan": "73d8f136684412bc2827dd90598b3b66fa023b78537ce674aa5007e9be78cbd0",
    "asan": "09e0835df41a2bab7c8e4af1e6b990748fde19337e65f5b2993ae8be5e9d3a5f",
    "asan-ubsan": "57f377d242bdd8fa074ec06428b9785e4d6357af953724e1c9a0533f271847d8",
}
# An input for cjson_read_fuzzer (flags 1010: minify, no termination required, formatted, unbuffered) on which a run
# makes 21 allocations: cJSON's, through its hooks, and the harness's copy for minifying.
CJSON_INPUT = b'1010{"a":[1,2,{"b":"c"}],"d":"e","f":[true,false,null,1.5e3]}\0'
CJSON_ALLOCATIONS = 21
CJSON_RUNNER = r"""
for b in plain ubsan asan asan-ubsan; do
  for t in cjson_read_fuzzer_allocation_failure cjson_read_fuzzer_allocation_counting; do
    for c in /in/*; do q /bin2/$t.$b "$c" > /dev/null 2>&1; echo "$t $b ${c#/in/} $?"; done
  done
done
"""


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class AllocationFailureOnCjson(unittest.TestCase):
    """fixtures/cjson: cJSON's own fuzz target, as projects/cjson builds it, and its allocation-failure variants.
    Building cJSON needs the network."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ov-test-cjson.")
        cls.work = pathlib.Path(cls.scratch.name)
        job = check_build.Job(name="cjson", directory=CJSON, repo="https://github.com/DaveGamble/cJSON", ref="",
                              dockerfile="", builds=BUILDS, fuzz_targets=None)
        builder = check_build.build_builder()
        check_build.build_project(job, CJSON_COMMIT, builder, CJSON_TAG, cls.work)
        raw = {}
        for build in BUILDS:
            raw[build] = cls.work / "raw" / build
            check_build.compile_build(CJSON_TAG, build, validate.BUILDS[build], raw[build])
        found = {build: manifest.discover(directory) for build, directory in raw.items()}
        cls.targets, _ = manifest.resolve_targets(found)
        cls.entries, _ = manifest.collect(raw, cls.targets, cls.work / "out")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        subprocess.run(["docker", "image", "rm", CJSON_TAG], capture_output=True)

    def test_the_fuzz_target_keeps_the_release_s_bytes(self):
        self.assertEqual(self.targets, ["cjson_read_fuzzer", "cjson_read_fuzzer_allocation_counting",
                                        "cjson_read_fuzzer_allocation_failure"])
        for build, sha256 in CJSON_RELEASE.items():
            self.assertEqual(self.entries["cjson_read_fuzzer"][build]["sha256"], sha256, build)

    @unittest.skipUnless(QEMU, "no qemu-riscv64 on this machine")
    def test_allocations(self):
        inputs = self.work / "in"
        inputs.mkdir()
        mask = lambda n: (1 << n).to_bytes(4, "little")
        (inputs / "count").write_bytes(b"\0\x80" + bytes(4) + CJSON_INPUT)
        for n in range(32):
            (inputs / f"fail-{n:02d}").write_bytes(b"\0\0" + mask(n) + CJSON_INPUT)
        (inputs / "fail-all").write_bytes(b"\0\0" + b"\xff" * 4 + CJSON_INPUT)
        for n in (0, 5, 12, 20, 21):
            (inputs / f"count-fail-{n:02d}").write_bytes(b"\0\x80" + mask(n) + CJSON_INPUT)
        binaries = self.work / "bin"
        binaries.mkdir()
        for target in self.targets:
            for build in BUILDS:
                shutil.copy(self.work / "out" / target / f"{target}.{build}", binaries)
        runner = f"q() {{ timeout 60 /qemu \"$@\"; }}\n{CJSON_RUNNER}"
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "-v", f"{QEMU}:/qemu:ro", "-v", f"{inputs}:/in:ro",
             "-v", f"{binaries}:/bin2:ro", "--entrypoint", "sh", CJSON_TAG, "-c", runner],
            capture_output=True, text=True, check=True,
        )
        results = {tuple(line.split(" ")[:3]): line.split(" ")[3] for line in done.stdout.splitlines()}
        for build in BUILDS:
            for case in sorted(path.name for path in inputs.iterdir()):
                published = results[("cjson_read_fuzzer_allocation_failure", build, case)]
                counting = results[("cjson_read_fuzzer_allocation_counting", build, case)]
                with self.subTest(build=build, case=case):
                    # cJSON survives each allocation failing, and a published build ignores counting mode.
                    self.assertEqual(published, "0")
                    if case == "count":
                        self.assertEqual(counting, str(CJSON_ALLOCATIONS))  # the same count in every build
                    elif case.startswith("count-fail-"):
                        n = int(case.rsplit("-", 1)[1])  # the run stops allocating after the one that fails
                        self.assertEqual(counting, str(min(n + 1, CJSON_ALLOCATIONS)))
                    else:
                        self.assertEqual(counting, "0")


if __name__ == "__main__":
    unittest.main()
