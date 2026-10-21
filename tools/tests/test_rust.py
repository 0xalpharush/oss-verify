# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for infra/base-builder/rust/gen-shim.py, which need no Docker:  python3 -m pytest tools/tests

It writes the static library crate of one cargo-fuzz [[bin]] of tests/fixtures/rust-example's crate.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
RUST = TESTS.parent.parent / "infra" / "base-builder" / "rust"
CRATE = TESTS / "fixtures" / "rust-example" / "crate"


def gen_shim(src, out, *more):
    return subprocess.run([sys.executable, str(RUST / "gen-shim.py"), "--src", str(src), "--fuzz-dir", "fuzz",
                           "--bin", "example_fuzzer", "--out", str(out), "--rt", "/tmp/oft-rust/oft-rust-rt", *more],
                          capture_output=True, text=True)


class GenShim(unittest.TestCase):
    def test_the_shim(self):
        with tempfile.TemporaryDirectory() as scratch:
            src, out = pathlib.Path(scratch) / "src", pathlib.Path(scratch) / "shim"
            shutil.copytree(CRATE, src)
            (src / ".oft-scratch-copy").touch()
            done = gen_shim(src, out, "--profile-env", "CARGO_PROFILE_RELEASE_LTO=false")
            self.assertEqual(done.returncode, 0, done.stderr)
            manifest = tomllib.loads((out / "Cargo.toml").read_text())
            # The package names are those of each project's Cargo.lock; the library is "oft", a static library.
            self.assertEqual(manifest["package"]["name"], "oft-rust-shim")
            self.assertEqual(manifest["lib"], {"name": "oft", "crate-type": ["staticlib"],
                                               "path": str(src / "fuzz/fuzz_targets/oft_shim_example_fuzzer.rs"),
                                               "test": False, "doctest": False})
            self.assertEqual(manifest["dependencies"]["oft-rust-rt"], {"path": "/tmp/oft-rust/oft-rust-rt"})
            self.assertEqual(manifest["dependencies"]["example"], {"path": str(src)})
            self.assertEqual(manifest["dependencies"]["libfuzzer-sys"], "=0.4.10")
            self.assertEqual(manifest["profile"]["release"], {"lto": False, "panic": "abort", "debug": False})
            self.assertIn("workspace", manifest)
            # The library's root is the bin's source, without #![no_main], with the adapter's Rust half linked.
            root = (src / "fuzz/fuzz_targets/oft_shim_example_fuzzer.rs").read_text()
            self.assertNotIn("#![no_main]", root)
            self.assertTrue(root.endswith("extern crate oft_rust_rt as _;\n"))
            self.assertTrue(root.startswith((CRATE / "fuzz/fuzz_targets/example_fuzzer.rs").read_text()
                                            .replace("#![no_main]\n", "").rstrip("\n")))
            record = json.loads((out / "shim.json").read_text())
            self.assertEqual((record["bin"], record["no_main_lines"]), ("example_fuzzer", 1))

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as scratch:
            src, out = pathlib.Path(scratch) / "src", pathlib.Path(scratch) / "shim"
            shutil.copytree(CRATE, src)
            # A tree that is not marked as a scratch copy is never written into.
            done = gen_shim(src, out)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("scratch", done.stderr)
            (src / ".oft-scratch-copy").touch()
            done = gen_shim(src, out, "--profile-env", "CARGO_PROFILE_RELEASE_PANIC=unwind")
            self.assertEqual(done.returncode, 3)
            self.assertIn("REFUSED(profile-env-panic)", done.stderr)
            (src / "fuzz" / "build.rs").write_text("fn main() {}\n")
            done = gen_shim(src, out)
            self.assertEqual(done.returncode, 3)
            self.assertIn("REFUSED(fuzz-package-build-script)", done.stderr)


if __name__ == "__main__":
    unittest.main()
