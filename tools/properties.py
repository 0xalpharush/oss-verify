# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The property checks of a project's fuzz targets, for tools/check: which ones no seed reaches, and which ones no
recorded mutant shows can fail (.claude/skills/add-project/SKILL.md, steps 3.2 to 3.4).

tools/check imports this module; it is not run on its own. For each fuzz target, after the builds:

    1. Find the property checks: each abort() call in the source file that defines LLVMFuzzerTestOneInput, which the
       plain build's debug information names. Only C and C++ are read. A check written through a macro is not found.
    2. Find what decides each check (its guard): the condition of the `if`, `while` or `for` that it is the body of
       (also through `else`), or the `switch` line of a `case` or `default` label. An abort() that nothing guards is
       its own guard.
    3. Compile one more plain build, at -O0 (a `clang` first on PATH adds -O0 after every other argument), and run
       each seed of <target>_seed_corpus.zip (with the driver's six-byte header) through it under qemu-riscv64, in the
       project image with no network. qemu logs each block of code that it translates (-d in_asm). The source lines
       of those addresses, inlined callers included, are the lines that the seeds ran. A check is reached when a seed
       ran a line of its guard. The four builds do not change.
    4. Read the records in the comment of each check (docs/build-contract.md, "Property checks"). For each mutant,
       copy the one changed file over the image's, compile the builds one at a time (plain first) until each record
       that uses the mutant is met, and run the record's input in each build. A record is met when the mutant exits
       with a status other than 0 and 2 in at least one build, and the unchanged target exits 0 or 2 in all of them.

The result is a list of findings, one line each: unreached, no mutant record, mutant not met, bad mutant record, no
seed corpus, and not checked (the step could not look). A stop marked `not a property: <reason>` is listed as
information only.
"""
import bisect
import concurrent.futures
import dataclasses
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

import check_build
import manifest
import validate

# The header the driver reads in front of the payload: no config bytes, no allocation mask bit set.
HEADER = b"\0" * 6
# Seconds for one run of a seed, and for one run of a mutant's input (an AddressSanitizer report under qemu can take
# minutes). A run that takes longer is killed: status 137.
SEED_LIMIT = 120
MUTANT_LIMIT = 300
# The statuses a statement accepts with today's driver.
ACCEPTED = (0, 2)
LANGUAGES = ("c", "c++")
ENTRY = "LLVMFuzzerTestOneInput"
# The runs of one container. Each job is three lines: "<id> <cov|run> <seconds>", the binary under /ov-bin, the input
# under /ov-in. A cov run also writes the addresses of the code qemu translated to /ov-w/<id>.pcs.
RUNNER = r"""ulimit -c 0
while read -r id mode limit && IFS= read -r bin && IFS= read -r input; do
  if [ "$mode" = cov ]; then
    timeout -s KILL "$limit" /ov-qemu -d in_asm -D "/ov-w/$id.log" "/ov-bin/$bin" "/ov-in/$input" > /dev/null 2>&1
    status=$?
    grep -oE '^0x[0-9a-f]+' "/ov-w/$id.log" 2> /dev/null | sort -u > "/ov-w/$id.pcs"
    rm -f "/ov-w/$id.log"
  else
    timeout -s KILL "$limit" /ov-qemu "/ov-bin/$bin" "/ov-in/$input" > /dev/null 2>&1
    status=$?
  fi
  echo "$id $status"
done < /ov-w/jobs > /ov-w/statuses
"""
# The source line of each address in /ov-w/pcs, and first of LLVMFuzzerTestOneInput, as JSON lines.
SYMBOLIZE = r"""entry=$(llvm-nm --defined-only "/ov-bin/$1" | awk '$NF == "LLVMFuzzerTestOneInput" { print "0x" $1; exit }')
[ -n "$entry" ] || { echo "no LLVMFuzzerTestOneInput in the symbol table" >&2; exit 1; }
{ echo "$entry"; cat /ov-w/pcs; } | llvm-symbolizer --obj="/ov-bin/$1" --output-style=JSON > /ov-w/lines.json
"""

# Before `compile`: a clang and a clang++ first on PATH that add -O0 after every other argument, so that each check
# keeps its own code and line. The builder's compiler shims run clang and clang++ by name.
OPTIMIZATION_OFF = r"""mkdir -p /tmp/ov-O0
for cc in clang clang++; do
  real=$(command -v "$cc") || continue
  printf '#!/bin/sh\nexec %s "$@" -O0\n' "$real" > "/tmp/ov-O0/$cc"
  chmod +x "/tmp/ov-O0/$cc"
done
export PATH="/tmp/ov-O0:$PATH"
"""
# Before `compile`: the mutant's file over the image's ($1).
REPLACE = 'cp /ov-replacement "$1"'

UNREACHED = "unreached"
NO_RECORD = "no mutant record"
NOT_MET = "mutant not met"
BAD_RECORD = "bad mutant record"
NO_CORPUS = "no seed corpus"
NOT_CHECKED = "not checked"
NOT_A_PROPERTY = "not a property"

CONDITIONS = frozenset({"if", "while", "for", "switch"})
ABORT = re.compile(r"(?:\bstd\s*::\s*|::\s*)?\b(?:__builtin_)?abort\s*\(\s*\)")
LABEL = re.compile(r"(?:case\b.*|default)\s*$", re.S)
MUTANT = re.compile(r"mutant:\s*(?P<path>[^\s`]+):(?P<line>[0-9]+)\s+`(?P<old>[^`]*)`\s*->\s*`(?P<new>[^`]*)`\s*")
INPUT = re.compile(r"input:\s*(?P<name>\S(?:.*\S)?)\s*")
EXEMPT = re.compile(r"not a property:\s*(?P<reason>\S(?:.*\S)?)\s*")


@dataclasses.dataclass
class Record:
    """One mutant and the input that must catch it, from the comment of a property check."""
    path: str
    line: int
    old: str
    new: str
    input: str

    def mutant(self):
        return (self.path, self.line, self.old, self.new)

    def __str__(self):
        return f"{self.path}:{self.line} `{self.old}` -> `{self.new}` on {self.input}"


@dataclasses.dataclass
class Check:
    """An abort() call in a fuzz target's source: its line, the lines of its guard, and what its comment records."""
    line: int
    guard: tuple
    records: list = dataclasses.field(default_factory=list)
    not_property: str = None
    problems: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Finding:
    """One line of the result. `where` is file:line, or "" for the whole target."""
    target: str
    where: str
    kind: str
    detail: str = ""

    def __str__(self):
        return " ".join(part for part in (self.target, self.where, self.kind + (f": {self.detail}" if self.detail
                                                                              else "")) if part)


@dataclasses.dataclass
class Report:
    findings: list = dataclasses.field(default_factory=list)
    information: list = dataclasses.field(default_factory=list)
    checks: int = 0
    targets: int = 0
    seconds: float = 0.0

    def count(self, kind):
        return sum(1 for finding in self.findings if finding.kind == kind)


# --- Reading C and C++ ---------------------------------------------------------------------------------------------


def blank(text):
    """Return (code, comments): `text` with each comment, string literal, character literal and preprocessor line
    replaced by spaces (newlines kept, so offsets and lines stay), and the (start, end) offsets of each comment."""
    code = list(text)
    comments = []
    n = len(text)

    def wipe(start, end):
        for k in range(start, end):
            if code[k] != "\n":
                code[k] = " "

    i, line_start = 0, True
    while i < n:
        c = text[i]
        if c == "\n":
            line_start = True
            i += 1
            continue
        if line_start and c in " \t":
            i += 1
            continue
        if line_start and c == "#":
            j = i
            while j < n and not (text[j] == "\n" and text[j - 1] != "\\"):
                j += 1
            wipe(i, j)
            i = j
            continue
        line_start = False
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append((i, j))
            wipe(i, j)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments.append((i, j))
            wipe(i, j)
            i = j
        elif c == '"' or (c == "'" and not (i and text[i - 1].isdigit())):  # 1'000 is a C++ digit separator
            j = i + 1
            while j < n and text[j] not in (c, "\n"):
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            wipe(i, j)
            i = j
        else:
            i += 1
    return "".join(code), comments


def previous(code, position):
    """The offset of the last character before `position` that is not white space, or -1."""
    k = position - 1
    while k >= 0 and code[k].isspace():
        k -= 1
    return k


def word_before(code, end):
    """The identifier that ends at offset `end` (inclusive), and its start; ("", end + 1) if there is none."""
    start = end
    while start >= 0 and (code[start].isalnum() or code[start] == "_"):
        start -= 1
    return code[start + 1:end + 1], start + 1


def matching(code, close, opener, closer):
    """The offset of the `opener` that the `closer` at offset `close` ends, or -1."""
    depth = 0
    for k in range(close, -1, -1):
        if code[k] == closer:
            depth += 1
        elif code[k] == opener:
            depth -= 1
            if depth == 0:
                return k
    return -1


def condition(code, close, words=CONDITIONS):
    """(start, end) of `<word> (...)` whose `)` is at `close`, if <word> is one of `words`; else None."""
    start = matching(code, close, "(", ")")
    if start < 0:
        return None
    word, begin = word_before(code, previous(code, start))
    return (begin, close) if word in words else None


def case_guard(code, colon):
    """The `switch (...)` of the case or default label whose colon is at `colon`, or None."""
    k = colon - 1
    while k >= 0 and code[k] not in ";{}":
        k -= 1
    if not LABEL.fullmatch(code[k + 1:colon].strip()):
        return None
    depth = 0
    for opener in range(k, -1, -1):
        if code[opener] == "}":
            depth += 1
        elif code[opener] == "{":
            if depth == 0:
                before = previous(code, opener)
                return condition(code, before, {"switch"}) if before >= 0 and code[before] == ")" else None
            depth -= 1
    return None


def else_guard(code, at):
    """The condition of the `if` whose `else` starts at `at`, when its body is a block; else None."""
    k = previous(code, at)
    if k < 0 or code[k] != "}":
        return None
    before = previous(code, matching(code, k, "{", "}"))
    return condition(code, before, {"if"}) if before >= 0 and code[before] == ")" else None


def guard_of(code, at):
    """(start, end) offsets of the code that decides whether the abort() at `at` runs, or None if nothing does."""
    j = previous(code, at)
    if j < 0:
        return None
    if code[j] == "{":
        k = previous(code, j)
        if k < 0:
            return None
        if code[k] == ")":
            return condition(code, k)
        if code[k] == ":":
            return case_guard(code, k)
        word, start = word_before(code, k)
        return else_guard(code, start) if word == "else" else None
    if code[j] == ")":
        return condition(code, j)
    if code[j] == ":":
        return case_guard(code, j)
    word, start = word_before(code, j)
    return else_guard(code, start) if word == "else" else None


def is_call(code, at):
    """True if the abort() at `at` is a statement, not a declaration such as `void abort()`."""
    j = previous(code, at)
    if j < 0 or code[j] in ";{}):":
        return True
    return word_before(code, j)[0] in ("else", "do")


def clean(line):
    """A comment line without its markers: leading spaces, `//`, `/*` and `*`, and a trailing `*/`."""
    line = line.strip()
    if line.endswith("*/"):
        line = line[:-2]
    return line.lstrip(" \t/*").strip()


def parse_records(lines, check):
    """Read the records and the `not a property` line from a check's comment lines into `check`."""
    pending = None
    for text in lines:
        if pending is not None:
            found = INPUT.fullmatch(text)
            if found:
                pending.input = found["name"]
                check.records.append(pending)
            else:
                check.problems.append(f"the line after `mutant: {pending.path}:{pending.line} ...` is not `input: "
                                      "<file name in the seed corpus>`")
            pending = None
            continue
        if text.startswith("mutant:"):
            found = MUTANT.fullmatch(text)
            if not found:
                check.problems.append("a `mutant:` line is not `mutant: <path>:<line> `<old>` -> `<new>``")
            elif not found["old"]:
                check.problems.append(f"the mutant at {found['path']}:{found['line']} replaces nothing (`<old>` is "
                                      "empty)")
            else:
                pending = Record(found["path"], int(found["line"]), found["old"], found["new"], "")
        elif text.startswith("input:"):
            check.problems.append("an `input:` line has no `mutant:` line before it")
        elif EXEMPT.fullmatch(text):
            check.not_property = EXEMPT.fullmatch(text)["reason"]
    if pending is not None:
        check.problems.append(f"`mutant: {pending.path}:{pending.line} ...` has no `input:` line after it")


def find_checks(text):
    """The property checks of a C or C++ source: [Check], in the order of their lines."""
    code, comments = blank(text)
    starts = [0] + [k + 1 for k, c in enumerate(text) if c == "\n"]

    def line_of(offset):
        return bisect.bisect_right(starts, offset)

    code_lines = {line_of(k) for k, c in enumerate(code) if not c.isspace()}
    pieces = {}  # line -> [comment text on that line]
    for start, end in comments:
        first = line_of(start)
        for offset, part in enumerate(text[start:end].split("\n")):
            pieces.setdefault(first + offset, []).append(part)

    def above(line):
        """The comment lines directly above `line`, with no code and no empty line between."""
        lines = []
        line -= 1
        while line >= 1 and line in pieces and line not in code_lines:
            lines.append(line)
            line -= 1
        return lines[::-1]

    checks = []
    for found in ABORT.finditer(code):
        if not is_call(code, found.start()):
            continue
        line = line_of(found.start())
        guard = guard_of(code, found.start())
        first, last = (line_of(guard[0]), line_of(guard[1])) if guard else (line, line)
        lines = sorted(set(above(first)) | set(range(first, last + 1)) | set(above(line)) | {line})
        check = Check(line, (first, last))
        parse_records([clean(part) for number in lines for part in pieces.get(number, [])], check)
        checks.append(check)
    return checks


def mutate(data, record):
    """The bytes of a file with the record's one replacement made, or (None, why) if the record does not fit them."""
    lines = data.split(b"\n")
    if not 1 <= record.line <= len(lines):
        return None, f"{record.path} has {len(lines)} lines, not {record.line}"
    old, new = record.old.encode(), record.new.encode()
    count = lines[record.line - 1].count(old)
    if count != 1:
        return None, f"`{record.old}` occurs {count} times on {record.path}:{record.line}, not once"
    lines[record.line - 1] = lines[record.line - 1].replace(old, new)
    return b"\n".join(lines), None


def safe_path(path):
    """True if `path` is a relative path that stays below the directory it is relative to."""
    parts = pathlib.PurePosixPath(path).parts
    return bool(parts) and not path.startswith("/") and ".." not in parts and "\\" not in path


# --- Running in the project image ----------------------------------------------------------------------------------


def find_qemu(given=None):
    """The qemu-riscv64 to run the binaries with: `given`, else qemu-riscv64-static or qemu-riscv64 on PATH. It must be
    a program with no program interpreter (a static or static-pie qemu), as it runs inside the project image. Return
    (path, None) or (None, why)."""
    candidates = [given] if given else [shutil.which("qemu-riscv64-static"), shutil.which("qemu-riscv64")]
    for path in filter(None, candidates):
        parsed = manifest.read_elf(path)
        if parsed is None:
            continue
        with open(path, "rb") as handle:
            types = manifest.program_header_types(handle, parsed[0])
        if types is not None and manifest.PT_INTERP not in types:
            return pathlib.Path(path).resolve(), None
    if given:
        return None, f"{given} is not a qemu-riscv64 with no program interpreter (a static build)"
    return None, ("no static qemu-riscv64 on this machine: install qemu-user-static, or give one with "
                  "--qemu-riscv64 <path>")


class Image:
    """Runs in containers of the project image, with no network, as this user, with the run's work label."""

    def __init__(self, tag, labels, qemu, scratch, workers):
        self.tag, self.labels, self.qemu, self.scratch, self.workers = tag, labels, qemu, scratch, workers
        self.files = {}
        self.workdir = check_build.output("docker", "image", "inspect", "--format", "{{.Config.WorkingDir}}",
                                          tag).strip() or "/"

    def docker(self, mounts, script, *args):
        """Run `sh -c script` in a fresh container. Raise check_build.Failed if it fails."""
        volumes = [arg for host, inside, mode in mounts for arg in ("-v", f"{host}:{inside}:{mode}")]
        done = subprocess.run(
            ["docker", "run", "--rm", "--network=none", *self.labels, "-u", f"{os.getuid()}:{os.getgid()}",
             *volumes, "--entrypoint", "sh", self.tag, "-c", script, "sh", *args],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
        if done.returncode != 0:
            raise check_build.Failed(f"docker run exited {done.returncode}: {done.stderr.strip()[-500:]}")
        return done.stdout

    def read(self, path):
        """The bytes of a file in the image (absolute, or relative to its WORKDIR), or None if there is none."""
        path = path if path.startswith("/") else f"{self.workdir.rstrip('/')}/{path}"
        if path not in self.files:
            done = subprocess.run(
                ["docker", "run", "--rm", "--network=none", *self.labels, "--entrypoint", "cat", self.tag, "--", path],
                stdin=subprocess.DEVNULL, capture_output=True)
            self.files[path] = done.stdout if done.returncode == 0 else None
        return self.files[path]

    def relative(self, path):
        """`path` relative to the image's WORKDIR when it is below it."""
        root = self.workdir.rstrip("/") + "/"
        return path[len(root):] if path.startswith(root) else path

    def runs(self, jobs, binaries, inputs, coverage=False):
        """Run each job (binary below `binaries`, input below `inputs`, seconds) under qemu, several containers at a
        time. Return [(status, addresses)] in the order of `jobs`; addresses is a set of hex strings for a coverage
        run, else None."""
        shards = [list(range(k, len(jobs), self.workers)) for k in range(min(self.workers, len(jobs)))]

        def shard(numbers):
            with tempfile.TemporaryDirectory(dir=self.scratch) as scratch:
                scratch = pathlib.Path(scratch)
                (scratch / "jobs").write_text("".join(
                    f"{n} {'cov' if coverage else 'run'} {jobs[n][2]}\n{jobs[n][0]}\n{jobs[n][1]}\n" for n in numbers))
                self.docker([(self.qemu, "/ov-qemu", "ro"), (binaries, "/ov-bin", "ro"), (inputs, "/ov-in", "ro"),
                             (scratch, "/ov-w", "rw")], RUNNER)
                statuses = dict(line.split() for line in (scratch / "statuses").read_text().splitlines())
                results = {}
                for n in numbers:
                    pcs = None
                    if coverage:
                        listing = scratch / f"{n}.pcs"
                        pcs = set(listing.read_text().split()) if listing.exists() else set()
                    results[n] = (int(statuses[str(n)]), pcs)
                return results

        merged = {}
        with concurrent.futures.ThreadPoolExecutor(max(1, len(shards))) as pool:
            for results in pool.map(shard, shards):
                merged.update(results)
        return [merged[n] for n in range(len(jobs))]

    def lines(self, binaries, binary, addresses):
        """({file: {lines}} that the addresses run, inlined callers included; the source file of
        LLVMFuzzerTestOneInput)."""
        with tempfile.TemporaryDirectory(dir=self.scratch) as scratch:
            scratch = pathlib.Path(scratch)
            (scratch / "pcs").write_text("".join(f"{pc}\n" for pc in sorted(addresses)))
            self.docker([(binaries, "/ov-bin", "ro"), (scratch, "/ov-w", "rw")], SYMBOLIZE, binary)
            rows = [json.loads(line) for line in (scratch / "lines.json").read_text().splitlines() if line.strip()]
        entry = next((frame.get("StartFileName") or frame.get("FileName")
                      for frame in (rows[0].get("Symbol") or []) if frame.get("FunctionName") == ENTRY), None)
        ran = {}
        for row in rows[1:]:
            for frame in row.get("Symbol") or []:
                if frame.get("FileName") and frame.get("Line"):
                    ran.setdefault(frame["FileName"], set()).add(frame["Line"])
        return ran, entry


# --- The step ------------------------------------------------------------------------------------------------------


def seeds(directory, target):
    """{name: bytes} of the inputs of projects/<name>/<target>_seed_corpus.zip, or None if there is none. tools/check
    has already checked its limits (tools/validate.py)."""
    path = directory / f"{target}_seed_corpus.zip"
    if not path.is_file():
        return None
    found, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(path.read_bytes())) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            data = archive.open(entry).read(validate.MAX_CORPUS_EXPANDED - total + 1)
            total += len(data)
            if total > validate.MAX_CORPUS_EXPANDED:
                break
            found[entry.filename] = data
    return found


@dataclasses.dataclass
class Target:
    """What the step knows about one fuzz target."""
    name: str
    seeds: dict = None
    source: str = ""          # the file that defines LLVMFuzzerTestOneInput, relative to WORKDIR if below it
    checks: list = dataclasses.field(default_factory=list)
    numbers: dict = dataclasses.field(default_factory=dict)  # seed name -> its file name under inputs/<n>/


def check(job, tag, work, targets, builds, ubsan, qemu, labels):
    """Find, reach and mutate the property checks of each fuzz target. `work` is the run's work directory, with raw/
    and out/ from the build; `builds` maps each build to its SANITIZER value. Return a Report."""
    began = time.monotonic()
    report = Report(targets=len(targets))
    if job.language not in LANGUAGES:
        report.findings.append(Finding("", "", NOT_CHECKED, f"property checks are read in C and C++ fuzz targets "
                                       f"only, and this project is in {job.language}"))
        return report
    qemu, why = find_qemu(qemu)
    if qemu is None:
        report.findings.append(Finding("", "", NOT_CHECKED, why))
        return report
    home = work / "properties"
    shutil.rmtree(home, ignore_errors=True)
    (home / "inputs").mkdir(parents=True)
    workers = max(1, (os.cpu_count() or 2) // 2)
    image = Image(tag, labels, qemu, home, workers)
    first = next(iter(builds))
    # The reach is read from a plain build at -O0: with optimization, the compiler merges the abort() calls of a
    # function, and the branch of a check then often has line 0 in the debug information.
    coverage = home / "O0"
    try:
        check_build.compile_build(tag, "plain -O0", builds.get("plain", "none"), coverage, labels=labels,
                                  before=([], OPTIMIZATION_OFF, []), quiet=True)
    except check_build.Failed as failure:
        report.findings.append(Finding("", "", NOT_CHECKED, f"the plain build at -O0, which the reach of the checks "
                                                            f"is read from, does not build ({failure})"))
        coverage = None

    found = {}
    for number, name in enumerate(targets):
        target = found[name] = Target(name, seeds(job.directory, name))
        inputs = home / "inputs" / str(number)
        inputs.mkdir()
        for k, (seed, data) in enumerate(sorted((target.seeds or {}).items())):
            (inputs / str(k)).write_bytes(HEADER + data)
            target.numbers[seed] = f"{number}/{k}"

    def reach(name):
        """Run the seeds of one target, read its source, and return its findings."""
        target, findings = found[name], []
        if "\n" in name:
            return [Finding(name, "", NOT_CHECKED, "the target's name has a line break")]
        addresses = set()
        if coverage is not None:
            if not (coverage / name).is_file():
                return [Finding(name, "", NOT_CHECKED, "the plain build at -O0 did not make this target")]
            jobs = [(name, target.numbers[seed], SEED_LIMIT) for seed in sorted(target.numbers)]
            for _, pcs in image.runs(jobs, coverage, home / "inputs", coverage=True):
                addresses |= pcs
        ran, entry = image.lines(coverage or work / "raw" / first, name, addresses)
        if not entry:
            return [Finding(name, "", NOT_CHECKED, f"the build has no debug information that names the source of "
                                                   f"{ENTRY}")]
        target.source = image.relative(entry)
        text = image.read(entry)
        if text is None:
            return [Finding(name, "", NOT_CHECKED, f"{target.source}, the source of {ENTRY}, is not in the project "
                                                   "image")]
        target.checks = find_checks(text.decode("utf-8", errors="replace"))
        if target.seeds is None:
            findings.append(Finding(name, "", NO_CORPUS, f"{name}_seed_corpus.zip is not in the project directory"))
        lines = ran.get(entry, set())
        for item in target.checks:
            where = f"{target.source}:{item.line}"
            if item.not_property is not None:
                report.information.append(Finding(name, where, NOT_A_PROPERTY, item.not_property))
                continue
            first_line, last_line = item.guard
            if coverage is not None and not lines & set(range(first_line, last_line + 1)):
                guard = f"line {first_line}" if first_line == last_line else f"lines {first_line}-{last_line}"
                findings.append(Finding(name, where, UNREACHED, f"no seed runs its guard ({guard})"))
            for problem in item.problems:
                findings.append(Finding(name, where, BAD_RECORD, problem))
            if not item.records and not item.problems:
                findings.append(Finding(name, where, NO_RECORD))
        return findings

    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        futures = {name: pool.submit(reach, name) for name in targets}
        for name in targets:
            try:
                report.findings.extend(futures[name].result())
            except Exception as failure:  # noqa: BLE001 - one target's failure is that target's finding
                report.findings.append(Finding(name, "", NOT_CHECKED, f"{type(failure).__name__}: {failure}"))
    report.checks = sum(1 for target in found.values() for item in target.checks if item.not_property is None)
    report.findings.extend(mutants(found, image, tag, work, builds, ubsan, labels, home))
    order = {name: number for number, name in enumerate(targets)}

    def place(finding):
        file, _, line = finding.where.rpartition(":")
        return (order.get(finding.target, -1), file, int(line) if line.isdigit() else 0, finding.kind)

    report.findings.sort(key=place)
    report.information.sort(key=place)
    report.seconds = time.monotonic() - began
    return report


def mutants(found, image, tag, work, builds, ubsan, labels, home):
    """Run each mutant record of each property check. Return the findings: each record that is not met."""
    findings = []
    uses = {}  # mutant -> [(target, check, record)]
    for target in found.values():
        for item in target.checks:
            if item.not_property is not None:
                continue
            where = f"{target.source}:{item.line}"
            for record in item.records:
                why = None
                if not safe_path(record.path):
                    why = f"{record.path} is not a path relative to the image's WORKDIR ({image.workdir})"
                elif record.input not in target.numbers:
                    why = f"{target.name}_seed_corpus.zip has no file named {record.input}"
                if why:
                    findings.append(Finding(target.name, where, NOT_MET, f"{record}: {why}"))
                else:
                    uses.setdefault(record.mutant(), []).append((target, where, record))
    if not uses:
        return findings

    # The unchanged targets, on each input that a record names, in each build.
    pairs = sorted({(target.name, record.input) for used in uses.values() for target, _, record in used})
    jobs = [(f"{name}/{name}.{build}", found[name].numbers[seed], MUTANT_LIMIT)
            for name, seed in pairs for build in builds]
    statuses = iter(status for status, _ in image.runs(jobs, work / "out", home / "inputs"))
    unchanged = {pair: {build: next(statuses) for build in builds} for pair in pairs}

    def show(by_build):
        return " ".join(f"{build} {by_build.get(build, '-')}" for build in builds)

    def run_mutant(number, mutant, used):
        path, _, _, _ = mutant
        data = image.read(path)
        changed, why = (None, f"{path} is not in the project image") if data is None else mutate(data, used[0][2])
        if why:
            return [Finding(target.name, where, NOT_MET, f"{record}: {why}") for target, where, record in used]
        directory = home / "mutants" / str(number)
        directory.mkdir(parents=True)
        replacement = directory / "file"
        replacement.write_bytes(changed)
        results = {id(record): {} for _, _, record in used}
        waiting = [entry for entry in used
                   if all(status in ACCEPTED for status in unchanged[(entry[0].name, entry[2].input)].values())]
        failure = None
        for build, sanitizer in builds.items():
            if not waiting:
                break
            out = directory / build
            try:
                check_build.compile_build(
                    tag, build, sanitizer, out, ubsan, labels=labels, quiet=True,
                    before=(["-v", f"{replacement}:/ov-replacement:ro"], REPLACE,
                            [f"{image.workdir.rstrip('/')}/{path}"]))
            except check_build.Failed as error:
                failure = f"the mutant does not build: {error}"
                break
            jobs = [(target.name, target.numbers[record.input], MUTANT_LIMIT) for target, _, record in waiting]
            for (target, _, record), (status, _) in zip(waiting, image.runs(jobs, out, home / "inputs")):
                results[id(record)][build] = status
            check_build.empty_directory(out, tag, labels=labels)
            waiting = [entry for entry in waiting if all(status in ACCEPTED
                                                         for status in results[id(entry[2])].values())]
        shutil.rmtree(directory, ignore_errors=True)
        lost = []
        for target, where, record in used:
            before, after = unchanged[(target.name, record.input)], results[id(record)]
            if not all(status in ACCEPTED for status in before.values()):
                lost.append(Finding(target.name, where, NOT_MET, f"{record}: the unchanged target does not exit 0 or "
                                    f"2 on the input ({show(before)})"))
            elif not any(status not in ACCEPTED for status in after.values()):
                because = failure or f"unchanged {show(before)}; mutant {show(after)}"
                lost.append(Finding(target.name, where, NOT_MET, f"{record}: {because}"))
        return lost

    def attempt(item):
        number, (mutant, used) = item
        try:
            return run_mutant(number, mutant, used)
        except Exception as failure:  # noqa: BLE001 - a mutant that cannot be run is not met
            return [Finding(target.name, where, NOT_MET, f"{record}: {type(failure).__name__}: {failure}")
                    for target, where, record in used]

    workers = max(1, (os.cpu_count() or 2) // 4)
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        for lost in pool.map(attempt, enumerate(sorted(uses.items()))):
            findings.extend(lost)
    return findings


# --- The result ----------------------------------------------------------------------------------------------------


def summary_line(report):
    """One sentence with the counts."""
    return (f"{report.checks} property checks in {report.targets} fuzz targets: {report.count(UNREACHED)} unreached, "
            f"{report.count(NO_RECORD)} with no mutant record, {report.count(NOT_MET)} with a mutant record that is "
            f"not met, {report.count(BAD_RECORD)} bad mutant records, {report.count(NO_CORPUS)} targets with no seed "
            f"corpus, {report.count(NOT_CHECKED)} not checked; {len(report.information)} stops marked as not a "
            f"property. The step took {report.seconds:.0f} s.")


def markdown_text(text):
    """Text from the pull request as Markdown code, with each unusual byte as %XX (see tools/check markdown_name)."""
    safe = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-/:,()= ")
    return "`" + "".join(chr(byte) if byte in safe else f"%{byte:02X}" for byte in text.encode()) + "`"


def markdown(report, strict):
    """The Markdown section of the step summary: the counts, then one row for each finding and each stop that is not
    a property. Only the counts, the kinds and the statuses are shown as they are; each name, path and record from the
    pull request is code with unusual bytes as %XX."""
    effect = ("They fail tools/check (--strict-properties)." if strict else
              "They are warnings: tools/check does not fail for them. A maintainer must fix each one before the "
              "enrollment is merged (.claude/skills/add-project/SKILL.md, steps 3.3 and 3.4).")
    rows = [f"### Property checks\n\n{summary_line(report)} {effect if report.findings else ''}".rstrip() + "\n"]
    if report.findings or report.information:
        rows += ["| target | check | finding |", "|---|---|---|"]
        for finding in report.findings + report.information:
            detail = finding.kind + (f": {markdown_text(finding.detail)}" if finding.detail else "")
            rows.append(f"| {markdown_text(finding.target) if finding.target else ''} | "
                        f"{markdown_text(finding.where) if finding.where else ''} | {detail} |")
    return "\n".join(rows) + "\n"
