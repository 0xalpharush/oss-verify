# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/manifest.py:  python3 -m unittest discover -s tools/tests"""
import hashlib
import os
import pathlib
import struct
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import manifest  # noqa: E402


def elf(symbols=(), e_type=2, symtab=True, wide=True):
    """A minimal little-endian ELF file. `symbols` is a list of (name, info, shndx)."""
    strtab = b"\0" + b"".join(name.encode() + b"\0" for name, _, _ in symbols)
    entries, offset = [], 1
    for name, info, shndx in symbols:
        if wide:
            entries.append(struct.pack("<IBBHQQ", offset, info, 0, shndx, 0, 0))
        else:
            entries.append(struct.pack("<IIIBBH", offset, 0, 0, info, 0, shndx))
        offset += len(name) + 1
    table = (struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0) if wide else struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)) + b"".join(entries)
    header_size, section_size, symbol_size = (64, 64, 24) if wide else (52, 40, 16)
    body = table + strtab
    sections_at = header_size + len(body)
    count = 3 if symtab else 1
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1, 1]) + bytes(9)
    if wide:
        header = ident + struct.pack("<HHIQQQIHHHHHH", e_type, 243, 1, 0, 0, sections_at, 0, header_size, 0, 0,
                                     section_size, count, 0)
        null = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        sym = struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, header_size, len(table), 2, 1, 8, symbol_size)
        strs = struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, header_size + len(table), len(strtab), 0, 0, 1, 0)
    else:
        header = ident + struct.pack("<HHIIIIIHHHHHH", e_type, 243, 1, 0, 0, sections_at, 0, header_size, 0, 0,
                                     section_size, count, 0)
        null = struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        sym = struct.pack("<IIIIIIIIII", 0, 2, 0, 0, header_size, len(table), 2, 1, 4, symbol_size)
        strs = struct.pack("<IIIIIIIIII", 0, 3, 0, 0, header_size + len(table), len(strtab), 0, 0, 1, 0)
    return header + body + null + (sym + strs if symtab else b"")


GLOBAL_FUNC, LOCAL_FUNC, GLOBAL_OBJECT, WEAK_FUNC = 0x12, 0x02, 0x11, 0x22
ENTRY = "LLVMFuzzerTestOneInput"


class Scratch(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.scratch.name)

    def tearDown(self):
        self.scratch.cleanup()

    def write(self, relative, data, mode=0o755):
        path = self.dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, mode)
        return path


class Discovery(Scratch):
    def test_the_symbol_table_rule(self):
        cases = {
            "target": (elf([(ENTRY, GLOBAL_FUNC, 1)]), 0o755, True),
            "weak": (elf([(ENTRY, WEAK_FUNC, 1)]), 0o755, True),
            "pie": (elf([(ENTRY, GLOBAL_FUNC, 1)], e_type=3), 0o755, True),
            "elf32": (elf([(ENTRY, GLOBAL_FUNC, 1)], wide=False), 0o755, True),
            "undefined": (elf([(ENTRY, GLOBAL_FUNC, 0)]), 0o755, False),
            "local": (elf([(ENTRY, LOCAL_FUNC, 1)]), 0o755, False),
            "object": (elf([(ENTRY, GLOBAL_OBJECT, 1)]), 0o755, False),
            "other": (elf([("main", GLOBAL_FUNC, 1)]), 0o755, False),
            "stripped": (elf(symtab=False), 0o755, False),
            "relocatable": (elf([(ENTRY, GLOBAL_FUNC, 1)], e_type=1), 0o755, False),
            "not-executable": (elf([(ENTRY, GLOBAL_FUNC, 1)]), 0o644, False),
            "script": (b"#!/bin/sh\necho LLVMFuzzerTestOneInput\n", 0o755, False),
            "truncated": (elf([(ENTRY, GLOBAL_FUNC, 1)])[:70], 0o755, False),
        }
        for name, (data, mode, expected) in cases.items():
            path = self.write(f"out/{name}", data, mode)
            self.assertEqual(manifest.is_fuzz_target(path), expected, name)
        os.symlink(self.dir / "out/target", self.dir / "out/link")
        (self.dir / "out/.stripped").mkdir()
        found = manifest.discover(self.dir / "out")
        self.assertEqual(sorted(found), ["elf32", "pie", "target", "weak"])
        self.assertTrue(manifest.has_symbol_table(self.dir / "out/target"))
        self.assertFalse(manifest.has_symbol_table(self.dir / "out/stripped"))

    def test_resolve_targets(self):
        found = {"plain": {"a": 1, "b": 1}, "asan": {"a": 1, "b": 1}}
        self.assertEqual(manifest.resolve_targets(found), (["a", "b"], []))
        self.assertEqual(manifest.resolve_targets(found, ["b"]), (["b"], []))
        targets, problems = manifest.resolve_targets({"plain": {"a": 1, "b": 1}, "asan": {"a": 1}})
        self.assertEqual(targets, ["a"])
        self.assertEqual(problems, ["fuzz target b is in the plain build but not in the asan build"])
        targets, problems = manifest.resolve_targets(found, ["a", "c"])
        self.assertEqual(targets, ["a"])
        self.assertIn("fuzz target c, which project.yaml lists, is not in any build", problems)
        targets, problems = manifest.resolve_targets({"plain": {}})
        self.assertEqual(targets, [])
        self.assertTrue(problems and "no fuzz target" in problems[0])


class Collection(Scratch):
    def test_collect_takes_the_stripped_twin(self):
        unstripped = elf([(ENTRY, GLOBAL_FUNC, 1)])
        twin = elf(symtab=False) + b"twin"
        for build in ("plain", "asan"):
            self.write(f"raw/{build}/fuzzer", unstripped)
            self.write(f"raw/{build}/.stripped/{hashlib.sha256(unstripped).hexdigest()}", twin)
        raw = {build: self.dir / "raw" / build for build in ("plain", "asan")}
        entries, problems = manifest.collect(raw, ["fuzzer"], self.dir / "out")
        self.assertEqual(problems, [])
        self.assertEqual((self.dir / "out/fuzzer/fuzzer.asan").read_bytes(), twin)
        self.assertEqual(entries["fuzzer"]["plain"], {
            "file": "fuzzer.plain", "bytes": len(twin), "sha256": hashlib.sha256(twin).hexdigest(),
        })

    def test_collect_needs_a_twin_without_symbols(self):
        unstripped = elf([(ENTRY, GLOBAL_FUNC, 1)])
        self.write("raw/plain/a", unstripped)
        self.write("raw/plain/b", unstripped + b"b")
        self.write(f"raw/plain/.stripped/{hashlib.sha256(unstripped + b'b').hexdigest()}", unstripped)
        _, problems = manifest.collect({"plain": self.dir / "raw/plain"}, ["a", "b"], self.dir / "out")
        self.assertEqual(len(problems), 2)
        self.assertIn("a in the plain build has no stripped twin", problems[0])
        self.assertIn("the stripped twin of b in the plain build has a symbol table", problems[1])


class Locks(Scratch):
    ENTRIES = {"fuzzer": {"plain": {"file": "fuzzer.plain", "bytes": 3, "sha256": "aa"},
                          "asan": {"file": "fuzzer.asan", "bytes": 4, "sha256": "bb"}}}

    def test_manifest_round_trip(self):
        data = manifest.manifest(
            project="p", repo="https://x/y", ref="v1", commit="c" * 40, oss_verify=None,
            builder={"toolchain": "example.org/toolchain@sha256:" + "1" * 64},
            sources={}, builds=["plain", "asan"], targets=["fuzzer"], entries=self.ENTRIES,
        )
        manifest.write_manifest(self.dir / "manifest.yaml", data)
        text = (self.dir / "manifest.yaml").read_text()
        self.assertTrue(text.startswith("# Generated by tools/check; do not edit.\n"))
        commit, pins, toolchain = manifest.load_lock(self.dir / "manifest.yaml")
        self.assertEqual(commit, "c" * 40)
        self.assertEqual(toolchain, "example.org/toolchain@sha256:" + "1" * 64)
        self.assertEqual(pins[("fuzzer", "asan")]["sha256"], "bb")
        self.assertEqual(manifest.compare(self.ENTRIES, pins, ["plain", "asan"]), ([], [], 2))

    def test_harness_yaml(self):
        harness = {"schema": "oss-fuzz-theorems/harness/1", "harness": "fuzzer",
                   "library": {"commit": "d" * 40},
                   "builds": {"plain": {"file": "fuzzer.plain", "bytes": 3, "sha256": "aa"},
                              "ubsan": {"file": "fuzzer.ubsan", "bytes": 5, "sha256": "cc"},
                              "asan": {"file": "fuzzer.asan", "bytes": 4, "sha256": "00"}}}
        (self.dir / "harness.yaml").write_text(yaml.safe_dump(harness))
        commit, pins, toolchain = manifest.load_lock(self.dir / "harness.yaml")
        self.assertEqual(commit, "d" * 40)
        self.assertIsNone(toolchain)  # no project.yaml two directories up
        # The release's harness.yaml is projects/<name>/<harness>/harness.yaml; its project.yaml names the builder.
        harness_dir = self.dir / "projects" / "p" / "fuzzer"
        harness_dir.mkdir(parents=True)
        (harness_dir / "harness.yaml").write_text(yaml.safe_dump(harness))
        (harness_dir.parent / "project.yaml").write_text("build:\n  builder: example.org/tc@sha256:" + "2" * 64 + "\n")
        self.assertEqual(manifest.load_lock(harness_dir / "harness.yaml")[2], "example.org/tc@sha256:" + "2" * 64)
        differences, extras, matched = manifest.compare(self.ENTRIES, pins, ["plain", "asan"])
        self.assertEqual(matched, 1)
        self.assertEqual(extras, [])
        self.assertEqual(len(differences), 1)
        self.assertIn("fuzzer.asan: sha256 bb", differences[0])
        differences, extras, matched = manifest.compare(self.ENTRIES, pins, ["plain", "ubsan", "asan"])
        self.assertIn("fuzzer.ubsan: in the lock, not in this build", differences)

    def test_extras_and_bad_locks(self):
        _, extras, _ = manifest.compare(self.ENTRIES, {("fuzzer", "plain"): {"sha256": "aa"}}, ["plain", "asan"])
        self.assertEqual(extras, ["fuzzer.asan: in this build, not in the lock"])
        for text in ("- a\n", "schema: something/else\n", "harness: x\nbuilds: {plain: {bytes: 1}}\n", "a: [\n"):
            (self.dir / "lock.yaml").write_text(text)
            with self.assertRaises(manifest.LockError, msg=text):
                manifest.load_lock(self.dir / "lock.yaml")


if __name__ == "__main__":
    unittest.main()
