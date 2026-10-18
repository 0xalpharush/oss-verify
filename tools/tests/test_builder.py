# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Build tests/fixtures/example with the builder and run what it makes. Needs Docker and the toolchain image:

    OV_DOCKER_TESTS=1 python3 -m unittest discover -s tools/tests

The fixture's Dockerfile and build.sh are templates/Dockerfile and templates/build.sh (in its C and C++ forms). Its
fuzz targets do one thing per first input byte, and the test checks the exit status of each in every build against
docs/exit-codes.md. Running the riscv64 binaries needs qemu-riscv64 (static) on this machine; without it, that part is
skipped.
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
TAG = "oss-verifier-test/example:latest"
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

# The allocation-failure variants, example_fuzzer_af and example_fuzzer_cc_af, are the same objects linked with
# $LIB_ALLOCATION_FAILURE_ENGINE. With no allocation mask they behave as their fuzz targets do (the cases above). These
# inputs set the mask (bit n: the n-th allocation fails) or ask for counting mode (bit 15 of the config word: the
# status is the number of allocations counted). 'h' allocates once, with malloc; 'N', in the C++ fuzz target, once
# with new[]. Input -> (header, payload, {fuzz target: statuses in each build}).
HEAP, ZERO, ONE, ABORT = (0, 0, 134, 134), (0, 0, 0, 0), (1, 1, 1, 1), (134, 134, 134, 134)
FAIL_FIRST, COUNT, COUNT_FAIL_FIRST, COUNT_FAIL_SECOND = (b"\0\0\1\0\0\0", b"\0\x80\0\0\0\0", b"\0\x80\1\0\0\0",
                                                         b"\0\x80\2\0\0\0")
ALLOCATION_FAILURE = {
    "af-h-fails": (FAIL_FIRST, "h", {"example_fuzzer": HEAP, "example_fuzzer_cc": HEAP,
                                     "example_fuzzer_af": ZERO, "example_fuzzer_cc_af": ZERO}),
    "af-h-count": (COUNT_FAIL_FIRST, "h", {"example_fuzzer": HEAP, "example_fuzzer_cc": HEAP,
                                           "example_fuzzer_af": ONE, "example_fuzzer_cc_af": ONE}),
    "af-z-count": (COUNT, "z", {"example_fuzzer": ZERO, "example_fuzzer_cc": ZERO,
                                "example_fuzzer_af": ZERO, "example_fuzzer_cc_af": ZERO}),
    "af-N-count": (COUNT, "N", {"example_fuzzer": ZERO, "example_fuzzer_cc": ZERO,
                                "example_fuzzer_af": ZERO, "example_fuzzer_cc_af": ONE}),
    "af-N-fails": (FAIL_FIRST, "N", {"example_fuzzer": ZERO, "example_fuzzer_cc": ZERO,
                                     "example_fuzzer_af": ZERO, "example_fuzzer_cc_af": ABORT}),  # std::bad_alloc
    "af-N-second": (COUNT_FAIL_SECOND, "N", {"example_fuzzer": ZERO, "example_fuzzer_cc": ZERO,
                                             "example_fuzzer_af": ZERO, "example_fuzzer_cc_af": ONE}),
}

# Runs every case in one container: prints "<target> <build> <case> <status>" per line.
RUNNER = r"""
cd /in
for t in example_fuzzer example_fuzzer_cc example_fuzzer_af example_fuzzer_cc_af; do
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
        self.assertEqual(self.targets, ["example_fuzzer", "example_fuzzer_af", "example_fuzzer_cc",
                                        "example_fuzzer_cc_af"])
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


if __name__ == "__main__":
    unittest.main()
