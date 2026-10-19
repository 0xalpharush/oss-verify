# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""pyclosure.py: the module closure that a frozen Python fuzz target needs.

Run it with the native Python of the CPython tree that the fuzz target is built from (its standard library is the
one that is frozen):

  pyclosure.py --harness H.py --path DIR [--path DIR ...] --shim SHIMDIR
               --target-builtins FILE --target-frozen FILE
               [--seed FILE ...] [--seed-dir DIR ...] --out MANIFEST.tsv [--allow-missing NAME ...]
               [--also MODULE ...] [--lazy-stdlib]

Two instruments, and their union, because each misses what the other sees:
  static   modulefinder over the harness, with sys.path = the atheris stand-in + the project's paths + the standard
           library: each `import` statement reachable by name, also in functions and conditions that no seed reaches.
           It finds too much (a `try: import x except ImportError` counts).
  dynamic  a new interpreter (-s -S) that runs the harness as __main__, calls the recorded TestOneInput on each seed,
           and lists sys.modules and each name that import looked up. It sees importlib.import_module(<a computed
           name>), which the static pass cannot.
--also and --lazy-stdlib add modules to the static pass as if they were imported (LAZY_CJK's comment tells why).

The kind of each name:
  builtin        in the inittab of the cross build (its Modules/config.c)
  frozen-stdlib  frozen by CPython itself in the target (_imp._frozen_module_names)
  freeze         a .py file, which pyfreeze.py freezes into the binary
  MISSING-EXT    a C extension that the target does not link: an error, unless --allow-missing NAME (an optional
                 accelerator with a pure-Python fallback, for example)
  badmodule      modulefinder could not find it (names of other platforms, such as nt and winreg): recorded, not
                 frozen
Exit status 1 for a MISSING-EXT that is not allowed, or when an instrument saw nothing.

From the build recipe of the oss-fuzz-theorems 2026.10 release (tools/python/pyclosure.py). The code is unchanged but
for the release spelling of the atheris stand-in's names; the comments are new.
"""
import argparse
import json
import modulefinder
import os
import subprocess
import sys
import sysconfig

DRIVER = r'''
import sys
if sys.flags.hash_randomization:
    sys.exit("pyclosure driver: hash randomization is ON; the run needs PYTHONHASHSEED=0")
paths, harness, seeds, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
for p in reversed(paths.split("\n")):
    sys.path.insert(0, p)
before = set(sys.modules)
class _OftSpecRecorder:
    # Each name that the import machinery looks up, also with importlib.util.find_spec(),
    # module_from_spec() and exec_module(), which never enter sys.modules (Python-Markdown's
    # htmlparser.py makes a private copy of html.parser this way).
    names = set()
    @classmethod
    def find_spec(cls, name, path=None, target=None):
        cls.names.add(name)
        return None
sys.meta_path.insert(0, _OftSpecRecorder)
g = {"__name__": "__main__", "__builtins__": __builtins__}
with open(harness, "rb") as f:
    src = f.read()
exec(compile(src, harness, "exec"), g)
import atheris
cb = atheris._oft_test_one_input
results = []
for s in [x for x in seeds.split("\n") if x]:
    with open(s, "rb") as f:
        data = f.read()
    try:
        cb(data)
        results.append((s, "ok"))
    except BaseException as e:
        results.append((s, type(e).__name__))
sys.meta_path.remove(_OftSpecRecorder)
mods = {}
for name, m in list(sys.modules.items()):
    mods[name] = [getattr(m, "__file__", None), hasattr(m, "__path__"), name in before]
import importlib.util
specs = {}
for name in sorted(_OftSpecRecorder.names):
    if name in mods:
        continue
    try:
        sp = importlib.util.find_spec(name)
    except Exception:
        sp = None
    if sp is not None and sp.origin not in (None, "built-in", "frozen"):
        specs[name] = [sp.origin, sp.submodule_search_locations is not None]
import json
with open(out, "w") as f:
    json.dump({"modules": mods, "seeds": results, "looked_up_specs": specs}, f)
'''


class _Finder(modulefinder.ModuleFinder):
    """modulefinder fails on a spec with no loader (a namespace package reached by name: `spec.loader.is_package`
    on None, as python-tabulate's does). Such a name is recorded as not found (a badmodule)."""

    def find_module(self, name, path, parent=None):
        try:
            return super().find_module(name, path, parent)
        except AttributeError as e:
            raise ImportError("loader-less spec for %s: %s" % (name, e)) from None


def stdlib_paths():
    p = sysconfig.get_paths()
    out = [p["stdlib"], p["platstdlib"]]
    dyn = os.path.join(p["platstdlib"], "lib-dynload")
    if os.path.isdir(dyn):
        out.append(dyn)
    return out


# The standard library's imports by a computed name, which neither instrument sees unless a seed takes that path. The
# `idna` codec looks up `punycode` with `__import__("encodings." + name)`; validators' fuzz target reached it on 2 of 702
# corpus inputs and on no seed. So each pure-Python codec module is frozen, whatever the seeds do, and so is
# `_strptime`, which time.strptime and datetime.strptime import from C. The CJK codec modules are left out: they import
# C modules that the build does not link, so freezing them would change nothing.
LAZY_CJK = {"big5", "big5hkscs", "cp932", "cp949", "cp950", "euc_jis_2004", "euc_jisx0213", "euc_jp", "euc_kr",
            "gb18030", "gb2312", "gbk", "hz", "iso2022_jp", "iso2022_jp_1", "iso2022_jp_2", "iso2022_jp_2004",
            "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "johab", "shift_jis", "shift_jis_2004",
            "shift_jisx0213"}


def lazy_stdlib():
    import encodings
    d = os.path.dirname(encodings.__file__)
    names = sorted("encodings." + n[:-3] for n in os.listdir(d)
                   if n.endswith(".py") and n != "__init__.py" and n[:-3] not in LAZY_CJK)
    if len(names) < 90:
        sys.exit("pyclosure: only %d encodings modules found in %s -- refusing (the lazy set examined nothing)"
                 % (len(names), d))
    return names + ["_strptime"]


def read_names(path):
    with open(path) as f:
        return {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", required=True)
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--shim", required=True)
    ap.add_argument("--target-builtins", required=True)
    ap.add_argument("--target-frozen", required=True)
    ap.add_argument("--seed", action="append", default=[])
    ap.add_argument("--seed-dir", action="append", default=[])
    ap.add_argument("--allow-missing", action="append", default=[])
    ap.add_argument("--also", action="append", default=[],
                    help="a module the static pass must include with its closure, as if imported")
    ap.add_argument("--lazy-stdlib", action="store_true",
                    help="--also every LAZY_STDLIB module (see there): the stdlib's imports by computed name")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    for d in a.seed_dir:
        a.seed += sorted(os.path.join(d, n) for n in os.listdir(d) if os.path.isfile(os.path.join(d, n)))
    builtins = read_names(a.target_builtins)
    frozen = read_names(a.target_frozen)
    if not builtins or not frozen:
        sys.exit("pyclosure: empty target builtin or frozen list -- refusing (instrument examined nothing)")
    search = [a.shim] + a.path + stdlib_paths()

    # static
    mf = _Finder(path=search)
    mf.run_script(a.harness)
    also = list(a.also) + (lazy_stdlib() if a.lazy_stdlib else [])
    for name in also:
        try:
            mf.import_hook(name)
        except ImportError as e:
            sys.exit("pyclosure: --also %s: %s" % (name, e))
    static = {}
    for name, m in mf.modules.items():
        if name == "__main__":
            continue
        static[name] = (m.__file__, m.__path__ is not None)
    bad = sorted(mf.badmodules)

    # dynamic, in a new interpreter: no site, no user site, and an environment with only PYTHONHASHSEED=0 (the
    # binaries set hash_seed=0). Not -I: -I implies -E, which ignores PYTHONHASHSEED.
    dump = a.out + ".dynamic.json"
    env = {"PYTHONHASHSEED": "0", "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    r = subprocess.run([sys.executable, "-s", "-S", "-c", DRIVER, "\n".join([a.shim] + a.path),
                        a.harness, "\n".join(a.seed), dump], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        sys.exit("pyclosure: the dynamic run failed (rc %d)" % r.returncode)
    with open(dump) as f:
        dj = json.load(f)
    dynamic = {n: (v[0], v[1]) for n, v in dj["modules"].items() if n != "__main__"}
    # Names looked up (find_spec) but never registered in sys.modules: loaded
    # privately via module_from_spec/exec_module. They are part of the closure too.
    for n, v in dj.get("looked_up_specs", {}).items():
        dynamic.setdefault(n, (v[0], v[1]))
    if not static or not dynamic:
        sys.exit("pyclosure: an instrument saw no modules -- refusing")

    rows, missing = [], []
    for name in sorted(set(static) | set(dynamic)):
        f, ispkg = static.get(name) or dynamic.get(name)
        seen = "both" if (name in static and name in dynamic) else ("static" if name in static else "dynamic")
        if name in builtins:
            kind = "builtin"
        elif name in frozen or name.split(".")[0] in ("_frozen_importlib", "_frozen_importlib_external"):
            kind = "frozen-stdlib"
        elif f and f.endswith(".py"):
            kind = "freeze"
        elif f:
            kind = "MISSING-EXT"
        elif name in sys.builtin_module_names:
            kind = "MISSING-EXT"  # builtin in the native interpreter, not in the target
            f = "<native builtin>"
        else:
            kind = "namespace"
        if kind == "MISSING-EXT" and seen == "static":
            # Found only by modulefinder, which finds too much (an import in a function deep in the standard
            # library: pickle._test -> doctest -> unittest -> asyncio -> _socket). Not linked; recorded. At run time
            # such an import raises ModuleNotFoundError like any missing module.
            kind = "MISSING-EXT-static-only"
        if kind == "MISSING-EXT" and name not in a.allow_missing:
            missing.append(name)
        rows.append((name, kind, seen, "1" if ispkg else "0", f or ""))
    with open(a.out, "w") as o:
        o.write("# name\tkind\tseen_by\tis_pkg\tfile\n")
        for row in rows:
            o.write("\t".join(row) + "\n")
        for b in bad:
            o.write("\t".join((b, "badmodule", "static", "0", "")) + "\n")
    counts = {}
    for row in rows:
        counts[row[1]] = counts.get(row[1], 0) + 1
    outcomes = {}
    for _, res in dj["seeds"]:
        outcomes[res] = outcomes.get(res, 0) + 1
    print("pyclosure: static=%d dynamic=%d union=%d kinds=%s badmodules=%d seed-outcomes=%s" % (
        len(static), len(dynamic), len(rows), json.dumps(counts, sort_keys=True), len(bad),
        json.dumps(outcomes, sort_keys=True)))
    if missing:
        sys.exit("pyclosure: C extension(s) the target does not link: " + " ".join(missing))


if __name__ == "__main__":
    main()
