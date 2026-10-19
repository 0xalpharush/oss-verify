# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""apply.py TREE PATCH...: apply CPython's patches for Python fuzz targets to TREE.

Each PATCH is a unified diff (the text above its first `--- ` line is its description, and is ignored here). Each hunk
is applied where its old side (context and removed lines) occurs in the file, and it must occur exactly once: if it
occurs nowhere or twice, nothing more is applied (exit status 1). Paths come from the `+++ ` line, less its first
component (-p1). A tree that already has a patch applied is refused too.

From the build recipe of the oss-fuzz-theorems 2026.10 release (tools/python/patches/apply.py). The code is
unchanged; the comments are new.
"""
import sys


def hunks(text):
    lines = text.splitlines(keepends=True)
    i = 0
    cur = None
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            path = lines[i + 1][4:].split("\t")[0].strip()
            cur = path.split("/", 1)[1]
            i += 2
            continue
        if ln.startswith("@@ ") and cur is not None:
            old, new = [], []
            i += 1
            while i < len(lines) and lines[i][:1] in (" ", "-", "+", "\\"):
                t = lines[i]
                if t.startswith("\\"):
                    i += 1
                    continue
                body = t[1:]
                if t[0] in " -":
                    old.append(body)
                if t[0] in " +":
                    new.append(body)
                i += 1
            yield cur, "".join(old), "".join(new)
            continue
        i += 1


def main():
    tree = sys.argv[1]
    n = 0
    for patch in sys.argv[2:]:
        with open(patch) as f:
            text = f.read()
        hs = list(hunks(text))
        if not hs:
            sys.exit("apply.py: %s has no hunks -- refusing (a patch that applies nothing must not read as applied)" % patch)
        for path, old, new in hs:
            p = tree + "/" + path
            with open(p) as f:
                s = f.read()
            c = s.count(old)
            if c != 1:
                sys.exit("apply.py: %s: hunk anchor occurs %d times in %s (want exactly 1) -- refusing" % (patch, c, path))
            s = s.replace(old, new)
            with open(p, "w") as f:
                f.write(s)
            n += 1
        print("apply.py: applied %s (%d hunk(s))" % (patch, len(hs)))
    if n == 0 and len(sys.argv) > 2:
        sys.exit("apply.py: nothing applied")


if __name__ == "__main__":
    main()
