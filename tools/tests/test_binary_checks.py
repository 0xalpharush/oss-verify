# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checks of the binaries that need no Docker: tools/check_links.py, tools/model_release.py and
tools/check_binaries.py. python3 -m pytest tools/tests"""
import hashlib
import os
import pathlib
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_binaries  # noqa: E402
import check_links  # noqa: E402
import model_release  # noqa: E402
from check_build import Failed  # noqa: E402

UNIMP = struct.pack("<I", check_links.TRAP)
NOP = struct.pack("<I", 0x00000013)  # addi x0, x0, 0
ASAN = ["__asan_init", "__asan_version_mismatch_check_v8", "__asan_load4"]


def elf_object(text=b"", defined=(), undefined=(), files=(), local=(), comment=False):
    """A minimal 64-bit little-endian relocatable ELF file: a .text section with `text`, a symbol table with the global
    functions `defined`, the local functions `local`, the undefined symbols `undefined` and the STT_FILE symbols
    `files`, and with `comment`, a .comment section as a compiler writes."""
    names = [b"", b".text", b".symtab", b".strtab", b".shstrtab"] + ([b".comment"] if comment else [])
    shstrtab = b"\0".join(names) + b"\0"
    offsets = {name: shstrtab.index(name + b"\0") if name else 0 for name in names}
    strtab, symbols = b"\0", [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]

    def symbol(name, info, shndx):
        nonlocal strtab
        symbols.append(struct.pack("<IBBHQQ", len(strtab), info, 0, shndx, 0, 0))
        strtab += name.encode() + b"\0"

    for name in files:
        symbol(name, 4, 0xFFF1)  # STT_FILE, LOCAL, ABS
    for name in local:
        symbol(name, 2, 1)  # STT_FUNC, LOCAL, .text
    for name in defined:
        symbol(name, (1 << 4) | 2, 1)  # STT_FUNC, GLOBAL, .text
    for name in undefined:
        symbol(name, 1 << 4, 0)  # NOTYPE, GLOBAL, undefined
    symtab = b"".join(symbols)
    blobs = [text, symtab, strtab, shstrtab] + ([b"clang version 20.1.8\0"] if comment else [])
    data, at = bytearray(64), []
    for blob in blobs:
        at.append(len(data))
        data += blob
    shoff = len(data)
    headers = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
               struct.pack("<IIQQQQIIQQ", offsets[b".text"], 1, 0x6, 0, at[0], len(text), 0, 0, 4, 0),
               struct.pack("<IIQQQQIIQQ", offsets[b".symtab"], 2, 0, 0, at[1], len(symtab), 3, 1, 8, 24),
               struct.pack("<IIQQQQIIQQ", offsets[b".strtab"], 3, 0, 0, at[2], len(strtab), 0, 0, 1, 0),
               struct.pack("<IIQQQQIIQQ", offsets[b".shstrtab"], 3, 0, 0, at[3], len(shstrtab), 0, 0, 1, 0)]
    if comment:
        headers.append(struct.pack("<IIQQQQIIQQ", offsets[b".comment"], 1, 0x30, 0, at[4], len(blobs[4]), 0, 0, 1, 1))
    data += b"".join(headers)
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack("<HHIQQQIHHHHHH", 1, 0xF3, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), 4)
    data[:64] = header
    return bytes(data)


def archive(members):
    """A System V ar archive of {name: bytes}, with a long-name table for names longer than 15 bytes."""
    longnames, out = b"", [b"!<arch>\n"]
    entries = []
    for name, body in members.items():
        if len(name) > 15:
            entries.append((f"/{len(longnames)}", body))
            longnames += name.encode() + b"/\n"
        else:
            entries.append((name + "/", body))
    if longnames:
        entries.insert(0, ("//", longnames))
    for name, body in entries:
        out.append(f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(body):<10}`\n".encode())
        out.append(body + (b"\n" if len(body) % 2 else b""))
    return b"".join(out)


def map_line(address, size, text):
    return f"{address:>16x} {address:>16x} {size:>8x} {4:>5}         {text}"


def good(name="f"):
    """An object instrumented by AddressSanitizer, compiled from C."""
    return elf_object(NOP, defined=[name], undefined=ASAN, files=["lib.c"], comment=True)


class MapParsing(unittest.TestCase):
    def test_input_sections_and_members(self):
        text = "\n".join([
            "             VMA              LMA     Size Align Out     In      Symbol",
            map_line(0x10000, 0x40, ".text"),
            map_line(0x10000, 0x10, "/opt/musl-sysroot/usr/lib/crt1.o:(.text)"),
            map_line(0x10010, 0x20, "/work/build/libfoo.a(foo.c.o):(.text.foo)"),
            map_line(0x10010, 0, "        foo"),  # a symbol line, indented further
            map_line(0x10030, 0x8, "<internal>:(.rodata.str1.1)"),
            map_line(0, 0x2b, "/opt/rt/libclang_rt.asan_static.a(asan_rtl_static.cpp.o):(.debug_info)"),
        ])
        self.assertEqual(check_links.parse_map(text), [
            ("/opt/musl-sysroot/usr/lib/crt1.o", None, ".text", 0x10),
            ("/work/build/libfoo.a", "foo.c.o", ".text.foo", 0x20),
        ])


class Archives(unittest.TestCase):
    def test_members_with_long_names(self):
        a, b = elf_object(NOP), elf_object(NOP * 2)
        members = check_links.ar_members(archive({"a.o": a, "a_very_long_member_name.c.o": b}))
        self.assertEqual(members, [("a.o", a), ("a_very_long_member_name.c.o", b)])

    def test_not_an_archive(self):
        self.assertEqual(check_links.ar_members(b"\x7fELF"), [])


class Objects(unittest.TestCase):
    def test_facts(self):
        facts = check_links.object_facts(elf_object(NOP + UNIMP + UNIMP, defined=["f"], undefined=ASAN,
                                                    files=["lib.c"], local=["core::ub_checks::precondition_check"],
                                                    comment=True))
        self.assertEqual((facts.code, facts.traps, facts.asan, facts.ub_checks), (12, 2, True, 1))
        self.assertEqual((facts.defined, facts.files, facts.compiled), (["f"], ["lib.c"], True))

    def test_only_the_constructor_symbols_mark_asan(self):
        # An uninstrumented object may still declare a public AddressSanitizer function.
        facts = check_links.object_facts(elf_object(NOP, defined=["f"], undefined=["__asan_poison_memory_region"]))
        self.assertFalse(facts.asan)

    def test_extended_section_numbering(self):
        data = bytearray(elf_object(NOP, defined=["f"], undefined=ASAN, comment=True))
        shoff, = struct.unpack_from("<Q", data, 40)
        shnum, = struct.unpack_from("<H", data, 60)
        struct.pack_into("<Q", data, shoff + 32, shnum)  # section 0's sh_size holds the count
        struct.pack_into("<H", data, 60, 0)
        facts = check_links.object_facts(bytes(data))
        self.assertEqual((facts.code, facts.asan), (4, True))

    def test_not_elf(self):
        self.assertIsNone(check_links.object_facts(b"not an object"))
        self.assertTrue(check_links.object_facts(b"BC\xc0\xde....").bitcode)


class Kinds(unittest.TestCase):
    def test_runtime_kinds(self):
        lib = "/opt/musl-sysroot/usr/lib/"
        rt = "/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/"
        self.assertEqual(check_links.runtime_kind(lib + "crt1.o"), "libc")
        self.assertEqual(check_links.runtime_kind(lib + "libc.a"), "libc")
        self.assertEqual(check_links.runtime_kind(lib + "libm.a"), "libc")
        self.assertEqual(check_links.runtime_kind(lib + "libc++.a"), "cxx-runtime")
        self.assertEqual(check_links.runtime_kind(lib + "libunwind.a"), "cxx-runtime")
        self.assertEqual(check_links.runtime_kind(rt + "libclang_rt.builtins.a"), "compiler-rt")
        self.assertEqual(check_links.runtime_kind(rt + "clang_rt.crtbegin.o"), "compiler-rt")
        self.assertEqual(check_links.runtime_kind(rt + "libclang_rt.asan.a"), "sanitizer-runtime")
        self.assertEqual(check_links.runtime_kind(lib + "libz.a"), "image-library")
        self.assertIsNone(check_links.runtime_kind("/opt/other/thing.o"))


class Records(unittest.TestCase):
    """Reading a record that a build wrote: never through a symbolic link, and the kept bytes checked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = pathlib.Path(self.tmp.name)
        self.directory = self.raw / ".records" / ("a" * 64)
        self.directory.mkdir(parents=True)
        (self.raw / ".records" / "store").mkdir()
        for name, text in (("map", ""), ("inputs.tsv", ""), ("driver", "/tmp/ov/cli.o\n")):
            (self.directory / name).write_text(text)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_complete_record(self):
        record = check_links.read_record(self.raw, "a" * 64)
        self.assertEqual(record.driver, {"/tmp/ov/cli.o"})
        self.assertIsNone(record.quiet)

    def test_links_are_refused(self):
        secret = self.raw / "secret"
        secret.write_text("x")
        (self.directory / "map").unlink()
        (self.directory / "map").symlink_to(secret)
        with self.assertRaises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)
        (self.directory / "map").unlink()
        (self.directory / "map").write_text("")
        (self.directory / "quiet").symlink_to(secret)
        self.assertIsNone(check_links.read_record(self.raw, "a" * 64).quiet)
        os.rename(self.raw / ".records", self.raw / "elsewhere")
        (self.raw / ".records").symlink_to(self.raw / "elsewhere")
        with self.assertRaises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_a_fifo_is_not_read(self):
        (self.directory / "map").unlink()
        os.mkfifo(self.directory / "map")
        with self.assertRaises(check_links.RecordError):
            check_links.read_record(self.raw, "a" * 64)

    def test_the_kept_bytes_are_checked(self):
        record = check_links.read_record(self.raw, "a" * 64)
        body = b"object"
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        self.assertEqual(record.store(digest), body)
        (self.raw / ".records" / "store" / digest).write_bytes(b"other")
        with self.assertRaises(check_links.RecordError):
            record.store(digest)


class Analyse(unittest.TestCase):
    """check_links.analyse on records made by hand: the uninstrumented lists and the instrumentation verdicts."""

    LIBC = "/opt/musl-sysroot/usr/lib/libc.a"
    CRT1 = "/opt/musl-sysroot/usr/lib/crt1.o"
    ASAN_RT = "/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/libclang_rt.asan.a"
    ZLIB = "/opt/musl-sysroot/usr/lib/libz.a"
    IMAGE = {LIBC: "c" * 64, CRT1: "1" * 64, ASAN_RT: "a" * 64, ZLIB: "f" * 64}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = pathlib.Path(self.tmp.name)
        (self.raw / ".records" / "store").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def keep(self, body):
        digest = hashlib.sha256(body).hexdigest()
        (self.raw / ".records" / "store" / digest).write_bytes(body)
        return digest

    def record(self, archives, runtimes=(LIBC, CRT1), driver=("/tmp/ov/cli.o",), loose=None, renamed=None):
        """A Record whose link took `runtimes` from the image, the members of `archives` ({archive path: {member:
        bytes}}), the objects `loose` ({path: bytes}) and the driver."""
        taken, inputs = [], {}
        for path in runtimes:
            taken.append((path, None, ".text", 4))
            inputs[path] = (path, self.IMAGE.get(path, "e" * 64), 1)
        for path, members in archives.items():
            body = archive(members)
            inputs[path] = (path, self.keep(body), len(body))
            taken += [(path, name, ".text", 4) for name in members]
        for path, body in (loose or {}).items():
            inputs[path] = (path, self.keep(body), len(body))
            taken.append((path, None, ".text", 4))
        for path in driver:
            taken.append((path, None, ".text", 4))
            inputs[path] = (path, "d" * 64, 1)
        return check_links.Record(taken, inputs, set(driver), renamed or {}, self.raw, None)

    def analyse(self, records, **options):
        return check_links.analyse(records, self.IMAGE, **options)

    def test_lists_the_image_files_in_path_order_and_not_the_driver(self):
        plain = self.record({"/work/libproject.a": {"lib.c.o": elf_object(NOP, defined=["f"], comment=True)}})
        result = self.analyse({"plain": plain})["plain"]
        self.assertEqual(result["uninstrumented"], [
            {"name": "crt1.o", "kind": "libc", "sha256": "1" * 64},
            {"name": "libc.a", "kind": "libc", "sha256": "c" * 64},
        ])
        self.assertEqual(result["instrumented"]["result"], "plain")

    def test_asan_wants_every_object_instrumented(self):
        bad = elf_object(NOP, defined=["g"], files=["other.c"], comment=True)
        result = self.analyse({"asan": self.record({"/work/libproject.a": {"lib.c.o": good()}},
                                                   runtimes=(self.LIBC, self.ASAN_RT))})["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass")
        self.assertIn({"name": "libclang_rt.asan.a", "kind": "sanitizer-runtime", "sha256": "a" * 64},
                      result["uninstrumented"])
        result = self.analyse({"asan": self.record({"/work/libproject.a": {"lib.c.o": good(), "other.c.o": bad}})})
        self.assertEqual(result["asan"]["instrumented"]["result"], "fail")
        self.assertIn("libproject.a(other.c.o)", result["asan"]["instrumented"]["detail"])

    def test_a_member_the_archive_does_not_hold(self):
        record = self.record({"/work/libproject.a": {"lib.c.o": good()}})
        record.taken.append(("/work/libproject.a", "gone.o", ".text", 4))
        result = self.analyse({"asan": record})["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        self.assertIn("libproject.a(gone.o)", result["instrumented"]["detail"])

    def test_asan_lists_hand_written_assembly_from_its_dwarf(self):
        asm = elf_object(NOP, defined=["memcpy_fast"])  # no STT_FILE, no compiler mark: clang's output for a .S
        record = self.record({"/work/libproject.a": {"lib.c.o": good(), "memcpy.S.o": asm}})
        units = lambda objects: [("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")] * len(objects)
        result = self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        self.assertIn({"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"},
                      result["uninstrumented"])
        # C with its marks stripped: its DWARF says C, so it is the project's code, uninstrumented.
        units = lambda objects: [("DW_LANG_C11", "src/arch/memcpy.c", "/src/lib")] * len(objects)
        result = self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        # No DWARF at all, or a source outside every checkout of the image.
        self.assertEqual(self.analyse({"asan": record}, dwarf_units=lambda objects: [None])["asan"]
                         ["instrumented"]["result"], "fail")
        units = lambda objects: [("DW_LANG_Mips_Assembler", "/tmp/x.S", "/")] * len(objects)
        self.assertEqual(self.analyse({"asan": record}, dwarf_units=units, checkouts=["/src/lib"])["asan"]
                         ["instrumented"]["result"], "fail")

    def test_a_file_of_the_image_with_no_kind_leaves_no_list(self):
        """A list that leaves a file out would say that the build links less uninstrumented code than it does."""
        unknown = "/opt/musl-sysroot/usr/lib64/libmystery.a"
        self.IMAGE[unknown] = "b" * 64
        try:
            for build in ("plain", "asan"):
                record = self.record({"/work/l.a": {"a.o": good()}}, runtimes=(self.LIBC, self.CRT1, unknown))
                result = self.analyse({build: record})[build]
                self.assertIsNone(result["uninstrumented"], build)
                self.assertEqual(result["instrumented"]["result"], "error", build)
                self.assertIn("libmystery.a", result["instrumented"]["detail"])
                # The report shows an error, so nobody reads the missing list as a clean one.
                block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                         "targets": {"t": {build: {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                                   "quiet_loud": {"result": "pass"},
                                                   "instrumented": result["instrumented"]}}}}
                text = check_binaries.report(block, {"t": {build: None}}, [build])
                self.assertIn("**not decided**", text)
                self.assertIn("not recorded", text)
        finally:
            del self.IMAGE[unknown]

    def test_a_link_that_took_no_file_of_the_image_leaves_no_list(self):
        """Every static link takes the C library, and the facts hold a list of at least one entry."""
        record = self.record({"/work/l.a": {"a.o": good()}}, runtimes=())
        result = self.analyse({"asan": record})["asan"]
        self.assertIsNone(result["uninstrumented"])
        self.assertEqual(result["instrumented"]["result"], "error")
        self.assertIn("C library", result["instrumented"]["detail"])

    def test_the_fortran_runtime_has_a_kind(self):
        for name in ("libFortranRuntime.a", "libgfortran.a", "libflang_rt.runtime.a"):
            self.assertEqual(check_links.runtime_kind("/opt/fortran/lib/" + name), "fortran-runtime", name)

    def test_one_rust_allocator_shim_is_exempt(self):
        shim = elf_object(NOP, defined=["__rust_alloc", "__rust_dealloc"], comment=True)
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim}})})["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass")
        result = self.analyse({"asan": self.record({"/work/l.a": {"a.o": good(), "shim.o": shim, "s2.o": shim}})})
        self.assertEqual(result["asan"]["instrumented"]["result"], "fail")

    def test_a_seal_compiled_from_the_driver_sources_is_the_drivers(self):
        seal = elf_object(NOP, defined=["__wrap_getenv"], comment=True, files=["wrap_getenv.c"])
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={"/work/b/wrap_getenv.o": seal})
        self.assertEqual(self.analyse({"asan": record})["asan"]["instrumented"]["result"], "pass")
        # The same name, with a function that is not a __wrap_ interposer: the project's code, uninstrumented.
        other = elf_object(NOP, defined=["__wrap_getenv", "helper"], comment=True, files=["wrap_getenv.c"])
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={"/work/b/wrap_getenv.o": other})
        self.assertEqual(self.analyse({"asan": record})["asan"]["instrumented"]["result"], "fail")

    def test_ubsan_wants_more_traps_than_plain_in_each_archive(self):
        def build(lib, dep):
            return self.record({"/work/b/libproject.a": {"lib.o": elf_object(lib, defined=["f"], comment=True)},
                                "/work/b/libdep.a": {"dep.o": elf_object(dep, defined=["g"], comment=True)}})
        plain = build(NOP * 4, NOP * 4)
        ubsan = build(NOP + UNIMP * 3, NOP + UNIMP)
        self.assertEqual(self.analyse({"plain": plain, "ubsan": ubsan})["ubsan"]["instrumented"]["result"], "pass")
        # The dependency's flags lost the sanitizer: the library's traps must not hide it.
        partly = build(NOP + UNIMP * 3, NOP * 4)
        result = self.analyse({"plain": plain, "ubsan": partly})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail")
        self.assertIn("libdep.a: 0", result["detail"])

    def test_ubsan_compares_each_loose_object_too(self):
        def build(fuzzer, other):
            return self.record({"/work/l.a": {"a.o": elf_object(NOP * 4, defined=["f"], comment=True)}},
                               loose={"/work/b/fuzzer.o": elf_object(fuzzer, defined=["g"], comment=True),
                                      "/work/b/other.o": elf_object(other, defined=["h"], comment=True)})
        plain = build(NOP * 4, NOP * 4)
        # Only the fuzz target's own object got the sanitizer: its traps must not stand for the other object's.
        partly = build(NOP + UNIMP * 3, NOP * 4)
        result = self.analyse({"plain": plain, "ubsan": partly})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "fail")
        self.assertIn("other.o: 0", result["detail"])

    def test_ubsan_without_a_plain_build_decides_nothing(self):
        ubsan = self.record({"/work/l.a": {"a.o": elf_object(NOP + UNIMP, defined=["f"], comment=True)}})
        result = self.analyse({"ubsan": ubsan})["ubsan"]["instrumented"]
        self.assertEqual(result["result"], "error")
        self.assertIn("no plain build", result["detail"])

    def test_assembly_without_dwarf_is_named_by_its_source(self):
        """The toolchain assembles a .S without -g, so the object carries no DWARF and no other mark."""
        asm = elf_object(NOP, defined=["memcpy_fast"])
        record = self.record({"/work/l.a": {"a.o": good(), "memcpy.S.o": asm}})
        asked = []

        def sources(wanted):
            asked.extend(wanted)
            return ["src/arch/memcpy.S"] * len(wanted)

        result = self.analyse({"asan": record}, dwarf_units=lambda objects: [None], assembly_sources=sources)["asan"]
        self.assertEqual(asked, [("memcpy.S.o", ["memcpy_fast"])])
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        self.assertIn({"name": "memcpy.S.o", "kind": "assembly", "source": "src/arch/memcpy.S"},
                      result["uninstrumented"])
        # No source of the project carries its name and its functions: the object is not shown to be assembly.
        result = self.analyse({"asan": record}, dwarf_units=lambda objects: [None],
                              assembly_sources=lambda wanted: [None] * len(wanted))["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        self.assertIn("no DWARF", result["instrumented"]["detail"])

    def test_an_allocation_failure_copy_stands_for_its_original(self):
        copy = "/tmp/ov/af.abc/3-libz.a"
        uninstrumented_zlib = archive({"adler32.o": elf_object(NOP, defined=["adler32"], comment=True)})
        record = self.record({"/work/l.a": {"a.o": good()}}, loose={copy: uninstrumented_zlib},
                             renamed={copy: (self.ZLIB, self.IMAGE[self.ZLIB])})
        record.taken = [entry for entry in record.taken if entry[0] != copy] + [(copy, "adler32.o", ".text", 4)]
        result = self.analyse({"asan": record})["asan"]
        self.assertEqual(result["instrumented"]["result"], "pass", result)
        self.assertIn({"name": "libz.a", "kind": "image-library", "sha256": "f" * 64}, result["uninstrumented"])

    def test_a_changed_image_file_is_examined_as_the_projects_code(self):
        changed = archive({"x.o": elf_object(NOP, defined=["x"], comment=True)})
        record = self.record({"/work/l.a": {"a.o": good()}, "/opt/musl-sysroot/usr/lib/libnew.a": {}},
                             loose={})
        record.inputs["/opt/musl-sysroot/usr/lib/libnew.a"] = ("/opt/musl-sysroot/usr/lib/libnew.a", self.keep(changed),
                                                              len(changed))
        record.taken.append(("/opt/musl-sysroot/usr/lib/libnew.a", "x.o", ".text", 4))
        result = self.analyse({"asan": record})["asan"]
        self.assertEqual(result["instrumented"]["result"], "fail")
        self.assertIn("libnew.a(x.o)", result["instrumented"]["detail"])

    def test_no_record(self):
        result = self.analyse({"asan": "compile recorded no link of it"})["asan"]
        self.assertIsNone(result["uninstrumented"])
        self.assertEqual(result["instrumented"]["result"], "error")
        # A Go program's plain build has no map, by design.
        result = self.analyse({"plain": "its link has no map (a program linked by Go's linker)"})["plain"]
        self.assertEqual(result["instrumented"]["result"], "plain")

    def test_dwarfdump_output(self):
        text = "\n".join([
            "== /objects/0.o",
            "0x0000000b: DW_TAG_compile_unit",
            '              DW_AT_name\t("src/arch/memcpy.S")',
            '              DW_AT_comp_dir\t("/src/lib")',
            "              DW_AT_language\t(DW_LANG_Mips_Assembler)",
            "0x00000030:   DW_TAG_label",
            '                DW_AT_name\t("loop")',
            "== /objects/1.o",
        ])
        self.assertEqual(check_links.parse_dwarfdump(text),
                         {"/objects/0.o": ("DW_LANG_Mips_Assembler", "src/arch/memcpy.S", "/src/lib")})


class ModelRelease(unittest.TestCase):
    RELEASE = ("schema: oss-fuzz-theorems/release/1\nrelease: 2026.10.0\nsemantics:\n"
               "  name: rocq-linux-process-semantics-core\n"
               "  repository: https://github.com/theorem-labs/rocq-linux-process-semantics\n"
               "  commit: f1006fe8178338a499b5e5c41be83006c4edd058\n")

    def test_reads_the_model_from_release_yaml(self):
        model = model_release.release_model(text=self.RELEASE)
        self.assertEqual((model["release"], model["commit"]), ("2026.10.0", "f1006fe8178338a499b5e5c41be83006c4edd058"))
        self.assertEqual(model["repository"], "https://github.com/theorem-labs/rocq-linux-process-semantics")

    def test_refuses_a_release_yaml_that_names_no_model(self):
        for text in ("release: x\n", self.RELEASE.replace("f1006fe8", "zz"),
                     self.RELEASE.replace("https://github.com", "file://"), "- a list\n"):
            with self.assertRaises(Failed):
                model_release.release_model(text=text)

    def test_code_without_comments(self):
        text = 'Definition a := 1. (* one (* nested *) *)\n\n  Definition   b := "(* not a comment *)".\n'
        self.assertEqual(model_release.rocq_code(text), ["Definition a := 1.",
                                                         'Definition b := "(* not a comment *)".'])
        self.assertEqual(model_release.code_sha256(text), model_release.code_sha256(text.replace("one", "uno")))
        self.assertNotEqual(model_release.code_sha256(text), model_release.code_sha256(text.replace("1.", "2.")))

    def test_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "A.v").write_text("Definition a := 1.\n")
            files = {"A.v": model_release.code_sha256("(* a comment *) Definition a := 1.")}
            self.assertEqual(model_release.stale(root, files), [])
            self.assertEqual(model_release.stale(root, {**files, "B.v": "0" * 64}), ["B.v"])
            (root / "A.v").write_text("Definition a := 2.\n")
            self.assertEqual(model_release.stale(root, files), ["A.v"])


class Runs(unittest.TestCase):
    """check_binaries' reading of the runs: quiet and loud, the system calls' floors, and the report."""

    QEMU = "qemu-riscv64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.results = pathlib.Path(self.tmp.name)
        self.inputs = [(check_binaries.EMPTY, check_binaries.HEADER), ("seed1", check_binaries.HEADER + b"x")]
        for kind in "lq":
            for n in range(2):
                self.write(f"{kind}{n}.calls", "exec")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, value):
        (self.results / name).write_text(f"{value}\n")

    def test_seed_inputs(self):
        corpus = self.results / "t_seed_corpus.zip"
        with zipfile.ZipFile(corpus, "w") as archive_file:
            for n in range(12):
                archive_file.writestr(f"s{n}", b"%d" % n)
        inputs = check_binaries.seed_inputs(self.results, "t")
        self.assertEqual(len(inputs), check_binaries.MAX_SEEDS + 1)
        self.assertEqual(inputs[0], (check_binaries.EMPTY, check_binaries.HEADER))
        self.assertEqual(inputs[1], ("s0", check_binaries.HEADER + b"0"))

    def test_quiet_and_loud(self):
        for n, (loud, quiet, written) in enumerate([(0, 0, 0), (2, 2, 0)]):
            self.write(f"l{n}.status", loud)
            self.write(f"q{n}.status", quiet)
            self.write(f"q{n}.out", written)
            self.write(f"q{n}.err", 0)
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"], "pass")
        self.write("q1.status", 0)
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results)
        self.assertEqual(result["result"], "fail")
        self.assertIn("exits 2, the quiet twin 0", result["detail"])
        self.write("q1.status", 2)
        self.write("q0.out", 5)
        self.assertIn("wrote 5 bytes", check_binaries.quiet_loud(True, "", self.inputs, self.results)["detail"])
        self.write("q0.out", 0)
        self.assertEqual(check_binaries.quiet_loud(False, "no adapter", self.inputs, self.results)["result"],
                         "not-run")
        # A check that did not run must not read as a clean one.
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "x"}, "inputs": {"t": ["a"]},
                 "targets": {"t": {"plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                                             "quiet_loud": {"result": "not-run", "detail": "no quiet twin: a Go "
                                                                                           "program"},
                                             "instrumented": {"result": "plain"}}}}}
        text = check_binaries.report(block, {"t": {"plain": [{"name": "libc.a", "kind": "libc"}]}}, ["plain"])
        self.assertIn("**not decided** (not run)", text)
        self.assertIn("quiet and loud: `no quiet twin: a Go program`", text)
        # A run that never started: its status is the tracer's, and decides nothing.
        self.write("l0.calls", "")
        self.write("l1.calls", "")
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results)["result"], "error")

    def test_a_run_that_never_reached_its_input_decides_nothing(self):
        """Two binaries that both die before main agree on every status and write nothing."""
        for n in range(2):
            self.write(f"l{n}.status", 2)
            self.write(f"q{n}.status", 2)
            self.write(f"q{n}.out", 0)
            self.write(f"q{n}.err", 0)
        whole = {check_binaries.EMPTY, "seed1"}
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results, whole)["result"], "pass")
        result = check_binaries.quiet_loud(True, "", self.inputs, self.results, set())
        self.assertEqual(result["result"], "error")
        self.assertIn("not a whole run of the input", result["detail"])
        # A difference still fails, whether or not the run reached its input.
        self.write("q0.status", 0)
        self.assertEqual(check_binaries.quiet_loud(True, "", self.inputs, self.results, set())["result"], "fail")

    def test_a_linked_result_is_not_read(self):
        secret = self.results / "secret"
        secret.write_text("0\n")
        (self.results / "l0.status").symlink_to(secret)
        self.assertIsNone(check_binaries.read_number(self.results, "l0.status"))

    def test_system_calls_need_whole_runs(self):
        traces = {0: '7 openat(AT_FDCWD,"input.bin",O_RDONLY|O_LARGEFILE) = 3\n7 read(3,0x1,65536) = 6\n',
                  1: '7 openat(AT_FDCWD,"input.bin",O_RDONLY|O_LARGEFILE) = 3\n7 read(3,0x1,65536) = 7\n'}
        for n, text in traces.items():
            self.write(f"l{n}.status", 0)
            (self.results / f"l{n}.trace").write_text(text)
        verdicts = {"calls": 12, "names": ["openat", "read", "exit_group"], "unmodeled": [], "exited": True,
                    "verdict": "pass", "host_log": "present", "child_records": 0}
        seen = {}

        def check_trace(model, text, *, stance, require_exit, binary, lengths):
            seen.update(stance=stance, lengths=lengths)
            return dict(verdicts)

        saved = check_binaries.syscall_shapes.check_trace
        check_binaries.syscall_shapes.check_trace = check_trace
        run = lambda stale="", qemu=self.QEMU: check_binaries.system_calls(object(), stale, qemu, "bin", self.inputs,
                                                                           self.results)
        try:
            self.assertEqual(run()["result"], "pass")
            self.assertEqual(seen, {"stance": "off", "lengths": "exec\n"})
            self.assertEqual(run(qemu="qemu-riscv64 version 9.1.0")["result"], "error")
            verdicts["calls"] = 3
            self.assertEqual(run()["result"], "error")
            verdicts["calls"] = 12
            # A call the trace cannot decide is reported with its own reason, and a failure is still a failure when
            # the host-side log is missing.
            verdicts.update(verdict="undecided", undecided=[{"call": "connect", "why": "the address is not printed"}])
            self.assertIn("connect: the address is not printed", run()["detail"])
            verdicts.update(host_log="missing")
            self.assertIn("host-side log", run()["detail"])
            verdicts.update(unmodeled=[{"call": "uname", "why": "not in the model's table"}])
            self.assertEqual(run()["result"], "fail")
            verdicts.update(host_log="present", verdict="pass", undecided=[], unmodeled=[])
            (self.results / "l1.trace").write_text("7 read(3,0x1,65536) = 7\n")
            result = run()
            self.assertEqual(result["result"], "error")
            self.assertIn("does not open and read input.bin", result["detail"])
            verdicts["unmodeled"] = [{"call": "uname", "why": "not in the model's table"}]
            result = run()
            self.assertEqual(result["result"], "fail")
            self.assertEqual(result["unmodeled"][0]["inputs"], [check_binaries.EMPTY, "seed1"])
            self.assertEqual(run(stale="the rules are old")["result"], "stale")
        finally:
            check_binaries.syscall_shapes.check_trace = saved

    def test_a_trace_that_cannot_be_read_fails_one_binary_only(self):
        self.write("l0.status", 0)
        (self.results / "l0.trace").write_text("7 exit_group(0)\n")
        saved = check_binaries.syscall_shapes.check_trace

        def raises(*arguments, **options):
            raise TypeError("kind_reason() missing 2 required positional arguments")

        check_binaries.syscall_shapes.check_trace = raises
        try:
            result = check_binaries.system_calls(object(), "", self.QEMU, "bin", self.inputs, self.results)
        finally:
            check_binaries.syscall_shapes.check_trace = saved
        self.assertEqual(result["result"], "error")
        self.assertIn("kind_reason", result["detail"])
        # And a check that raises anywhere gives that binary an error, not the step.
        def fails(binary, stale):
            raise ValueError("not a RISC-V program")
        self.assertEqual(check_binaries.guarded(fails, "bin", ""),
                         {"result": "error", "detail": "fails: ValueError: not a RISC-V program"})

    def test_report_names_the_four_checks_per_binary(self):
        block = {"model": {"name": "m", "commit": "f" * 40, "release": "2026.10.0"}, "inputs": {"t": ["a", "b"]},
                 "targets": {"t": {
                     "plain": {"elf": {"result": "pass"}, "system_calls": {"result": "pass"},
                               "quiet_loud": {"result": "pass"}, "instrumented": {"result": "plain"}},
                     "asan": {"elf": {"result": "pass"},
                              "system_calls": {"result": "fail", "detail": "uname: not in the table"},
                              "quiet_loud": {"result": "pass"}, "instrumented": {"result": "pass"}}}}}
        listing = {"t": {"plain": [{"name": "libc.a", "kind": "libc"}], "asan": None}}
        text = check_binaries.report(block, listing, ["plain", "asan"])
        self.assertIn("| ELF and instructions | system calls | quiet and loud | instrumented |", text)
        self.assertIn("| `t.plain` | pass | pass | pass | not instrumented (plain) | 1 files |", text)
        self.assertIn("| `t.asan` | pass | **fail** | pass | pass | not recorded |", text)
        self.assertIn("`t.asan`, system calls: `uname: not in the table`", text)


if __name__ == "__main__":
    unittest.main()
