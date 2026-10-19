# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""pyfreeze.py: write oft_frozen.h, the frozen modules of a Python fuzz target, from pyclosure.py's manifest.

    pyfreeze.py --manifest M.tsv --harness H.py --shim SHIMDIR --stdlib LIBDIR --out oft_frozen.h

Each `freeze` row, the encodings modules that the interpreter needs at start (CPython 3.11 does not freeze the
encodings package), and the atheris stand-in each become one marshalled code object, compiled as CPython compiles
its own frozen modules (compile(text, "<frozen NAME>", "exec", optimize=0, dont_inherit=True)), in an array named
_oft_M_<n>, so that no name collides with Python/frozen.c's. The harness is compiled the same way, as OFT_MAIN_CODE
and OFT_MAIN_SIZE; atheris_host.c runs it as __main__. The table is a struct _frozen[] (the 3.11 layout: name, code,
size, is_package, get_code) for PyImport_FrozenModules.

From the build recipe of the oss-fuzz-theorems 2026.10 release (tools/python/pyfreeze.py), in its release mode. The
code is unchanged but for the release spelling of the names; the comments are new.
"""
import argparse
from _sha256 import sha256  # not hashlib, which logs on import that the native Python has no _blake2
import marshal
import os
import sys

ENCODINGS = ["encodings", "encodings.aliases", "encodings.utf_8", "encodings.ascii", "encodings.latin_1"]
MPFX = "_oft_M_"


def compile_and_marshal(name, text):
    code = compile(text, "<frozen %s>" % name, "exec", optimize=0, dont_inherit=True)
    return marshal.dumps(code)


def emit_array(out, var, data):
    out.write("static const unsigned char %s[] = {\n" % var)
    for n in range(0, len(data), 24):
        out.write(",".join(str(b) for b in data[n:n + 24]))
        out.write(",\n")
    out.write("};\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--harness", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--stdlib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--closure", choices=("union", "dynamic"), default="union",
                    help="union = static+dynamic (the default the tier ships); dynamic = only what the seed runs imported")
    a = ap.parse_args()

    mods = {}  # name -> (path, is_pkg)
    for e in ENCODINGS:
        rel = e.replace(".", "/")
        p = os.path.join(a.stdlib, rel, "__init__.py") if e == "encodings" else os.path.join(a.stdlib, rel + ".py")
        mods[e] = (p, e == "encodings")
    mods["atheris"] = (os.path.join(a.shim, "atheris", "__init__.py"), True)
    with open(a.manifest) as f:
        for ln in f:
            if ln.startswith("#"):
                continue
            name, kind, seen, ispkg, path = ln.rstrip("\n").split("\t")
            if kind != "freeze" or name == "atheris":
                continue
            if a.closure == "dynamic" and seen == "static":
                continue
            mods[name] = (path, ispkg == "1")
    total = 0
    with open(a.out + ".tmp", "w") as out:
        out.write("/* written by pyfreeze.py; do not edit */\n")
        entries = []
        for i, name in enumerate(sorted(mods)):
            path, ispkg = mods[name]
            with open(path, "rb") as f:
                text = f.read()
            data = compile_and_marshal(name, text)
            total += len(data)
            var = MPFX + str(i)
            out.write("/* %s <- %s (%d B source, sha256 %s) */\n" % (
                name, path, len(text), sha256(text).hexdigest()[:16]))
            emit_array(out, var, data)
            entries.append((name, var, ispkg))
        with open(a.harness, "rb") as f:
            htext = f.read()
        hdata = marshal.dumps(compile(htext, os.path.basename(a.harness), "exec", optimize=0, dont_inherit=True))
        total += len(hdata)
        out.write("/* __main__ <- %s (sha256 %s) */\n" % (a.harness, sha256(htext).hexdigest()[:16]))
        mvar = MPFX + "main"
        emit_array(out, mvar, hdata)
        out.write("#define OFT_MAIN_CODE %s\n#define OFT_MAIN_SIZE sizeof(%s)\n" % (mvar, mvar))
        out.write("static struct _frozen oft_frozen_modules[] = {\n")
        # OFT_PY_NO_ZIPIMPORT: an entry with NULL code excludes CPython's own frozen zipimport (Python/import.c
        # look_up_frozen consults these entries first), and _PyImportZip_Init lets that import fail, so that the
        # main phase does not import `time` and call tzset and localtime at start. No build defines it today.
        out.write('#ifdef OFT_PY_NO_ZIPIMPORT\n    {"zipimport", NULL, 0, 0, NULL},\n#endif\n')
        for name, var, ispkg in entries:
            out.write('    {"%s", %s, (int)sizeof(%s), %d, NULL},\n' % (name, var, var, 1 if ispkg else 0))
        out.write("    {0, 0, 0, 0, 0}\n};\n")
    os.replace(a.out + ".tmp", a.out)
    print("pyfreeze: %d modules + __main__, %d marshalled bytes -> %s" % (len(entries), total, a.out))
    if len(entries) < len(ENCODINGS) + 1:
        sys.exit("pyfreeze: fewer modules than the fixed set -- refusing")


if __name__ == "__main__":
    main()
