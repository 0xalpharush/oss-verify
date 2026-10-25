#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The step of `tools/check --checks`: what the checks of a project's fuzz targets catch, on its own seed inputs.

A property of a fuzz target is a check that calls abort() (step 3.2 of .claude/skills/add-project/SKILL.md), and a
proof says no more than its checks. This step measures what steps 3.3 and 3.4 of that skill ask for:

1. Reach. It builds the fuzz targets again with coverage (tools/checks/compile-check), runs each one on each input of
   its seed corpus, and lists each check `if (<condition>) abort();` whose condition no seed input evaluates.
2. Breakage. For each patch in the directory that project.yaml's `mutants` names, it builds the coverage build and the
   project's most checking sanitizer build again with the patch applied, runs each fuzz target on each seed input, and
   says whether a run fails: an exit status other than 0 and 2, or no end within RUN_TIMEOUT seconds. The coverage
   build also says which checks fired. Then it lists each check that no patch makes fire.

docs/build-contract.md, "The checks of a fuzz target", says what it measures and what it does not. It works for C and
C++ fuzz targets. It runs the riscv64 binaries with qemu-riscv64-static (on Ubuntu, apt install qemu-user-static),
inside a container of the project image with no network. The coverage build needs compiler-rt's source for the
toolchain's LLVM version, which it downloads once and checks.
"""
import bisect
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

import check_build
from check_build import Failed, step

TOOLS = pathlib.Path(__file__).resolve().parent
CHECKS_DIR = TOOLS / "checks"
# compiler-rt's source for each LLVM version a toolchain image has: the URL and its SHA-256. The profile runtime must
# be of the same version as the compiler, which writes the profile's format.
COMPILER_RT = {
    "20.1.8": ("https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.8/compiler-rt-20.1.8.src.tar.xz",
               "15277402f6fd63397c0917a5c7171cda82d16d226094b828c1ed0f58f73b9c69"),
}
# The longest a run of a fuzz target on one input may take, in seconds. A run that takes longer counts as a failure.
RUN_TIMEOUT = 120
# The exit statuses of a run that passes (docs/build-contract.md, "Exit statuses").
PASSES = (0, 2)
# The status of a run that tools/checks/run-seeds stopped at the time limit (SIGKILL).
KILLED = 137
# The driver's header in front of each seed input: no config bytes and no allocation mask (docs/build-contract.md).
HEADER = b"\0" * 6
# The sanitizer builds, the most checking first: a breakage patch is also run on the first one the project has.
SANITIZER_BUILDS = (("asan-ubsan", "address-undefined"), ("asan", "address"), ("ubsan", "undefined"))
MAX_PATCH_BYTES = 256 * 1024
MAX_PATCHES = 200
LANGUAGES = ("c", "c++")
STATUS_NAMES = {134: "abort()", 132: "a UBSan trap", 139: "a segmentation fault", 77: "exit()",
                78: "a return value other than 0 or -1"}


@dataclasses.dataclass
class Check:
    """One abort() call in a fuzz target's source. `guard` is the position of the first byte of the condition of the
    `if` that guards it, or None if no `if (...)` guards it (a `default:` of a switch, an else branch, a helper)."""

    path: str  # as the coverage build names it: the path in the project image
    line: int
    column: int
    guard: tuple | None
    text: str  # the source line of the guard, or of the call


@dataclasses.dataclass
class Run:
    """The result of running one fuzz target on one seed input: its exit status, or None if it took too long."""

    target: str
    seed: str
    status: int | None
    build: str  # "coverage", or the sanitizer build's name

    def failed(self):
        return self.status not in PASSES


# ── reading C and C++ ────────────────────────────────────────────────────────────────────────────────────────────────

_LITERAL = re.compile(rb'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
_TOKEN = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*|\S")
_ABORT = re.compile(rb"\babort\s*\(\s*\)")


def blank_literals(source):
    """`source` (bytes) with each comment and each string and character literal replaced by spaces, newlines kept, so
    that each byte keeps its line and column."""
    return _LITERAL.sub(lambda m: re.sub(rb"[^\n]", b" ", m.group()), source)


def find_checks(path, source):
    """Each abort() call in `source` (bytes), with the `if` that guards it."""
    code = blank_literals(source)
    starts = [0] + [m.end() for m in re.finditer(rb"\n", code)]
    lines = source.split(b"\n")

    def position(offset):
        line = bisect.bisect_right(starts, offset)
        return line, offset - starts[line - 1] + 1

    tokens = [(m.group(), m.start()) for m in _TOKEN.finditer(code)]
    index = {offset: i for i, (_, offset) in enumerate(tokens)}
    checks = []
    for match in _ABORT.finditer(code):
        line, column = position(match.start())
        if code[starts[line - 1]:match.start()].lstrip().startswith(b"#"):
            continue  # in a macro definition: its uses are the checks, which this does not find
        guard = guard_of(tokens, index[match.start()])
        where = position(guard) if guard is not None else (line, column)
        text = lines[where[0] - 1].decode("utf-8", "replace").strip()
        checks.append(Check(path, line, column, where if guard is not None else None, text))
    return checks


def _match_back(tokens, close, opener, closer):
    """The index of the token that opens the bracket closed at tokens[close], or None."""
    depth = 0
    for i in range(close, -1, -1):
        if tokens[i][0] == closer:
            depth += 1
        elif tokens[i][0] == opener:
            depth -= 1
            if depth == 0:
                return i
    return None


def guard_of(tokens, i):
    """The offset of the first byte of the condition of the `if` that guards the call at tokens[i], or None.

    It walks back from the call: `if (<condition>) abort();` and `if (<condition>) { ...; abort(); }` have a guard. A
    call after other statements of a block takes the guard of the block. Any other form (`else`, `case`, `default`, a
    loop, a function body) has none."""
    j = i - 1
    while j >= 0:
        token = tokens[j][0]
        if token == b")":
            opened = _match_back(tokens, j, b"(", b")")
            if opened and tokens[opened - 1][0] == b"if" and opened + 1 < j:
                return tokens[opened + 1][1]
            return None
        if token == b"{":
            if j > 0 and tokens[j - 1][0] == b")":
                j -= 1
                continue
            return None
        if token in (b";", b"}"):
            # An earlier statement of the same block: the `{` that opens the block decides.
            depth = 0
            while j >= 0:
                if tokens[j][0] == b"}":
                    depth += 1
                elif tokens[j][0] == b"{":
                    if depth == 0:
                        break
                    depth -= 1
                j -= 1
            continue
        return None
    return None


# ── coverage ─────────────────────────────────────────────────────────────────────────────────────────────────────────

class Coverage:
    """The counts of llvm-cov's segments, by file, summed over the fuzz targets: how many times each region ran."""

    def __init__(self):
        self.segments = {}
        self._keys = {}

    def add(self, export):
        """Add the counts of one `llvm-cov export -format=text` (a fuzz target's runs) to these."""
        self._keys.clear()
        for data in export.get("data", []):
            for entry in data.get("files", []):
                mine = self.segments.setdefault(entry["filename"], {})
                for line, column, count, has_count, *_ in entry.get("segments", []):
                    if has_count:
                        mine[(line, column)] = (mine.get((line, column)) or 0) + count
                    else:
                        mine.setdefault((line, column), None)

    def count(self, path, line, column):
        """How many times the code at (line, column) of `path` ran, or None if no target's coverage maps it."""
        mine = self.segments.get(path)
        if not mine:
            return None
        if path not in self._keys:
            self._keys[path] = sorted(mine)
        keys = self._keys[path]
        at = bisect.bisect_right(keys, (line, column)) - 1
        return mine[keys[at]] if at >= 0 else None


def fuzz_target_files(export):
    """The source files that define LLVMFuzzerTestOneInput in one llvm-cov export."""
    return {name for data in export.get("data", []) for function in data.get("functions", [])
            if function.get("name") == "LLVMFuzzerTestOneInput" for name in function.get("filenames", [])[:1]}


# ── running ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def qemu():
    """The path of a static qemu-riscv64, which runs inside the project image too, or raise Failed."""
    found = shutil.which("qemu-riscv64-static")
    if not found:
        raise Failed("--checks runs the riscv64 binaries with qemu-riscv64-static, which is not installed "
                     "(on Ubuntu, apt install qemu-user-static)")
    return pathlib.Path(found).resolve()


def write_seeds(directory, targets, inputs):
    """Write each target's seed inputs, from projects/<name>/<target>_seed_corpus.zip, to inputs/<target>/<n>, each
    with the driver's header in front. Return {target: [the name of input n in its zip file]}; a target with no corpus
    has no entry."""
    shutil.rmtree(inputs, ignore_errors=True)
    names = {}
    for target in targets:
        corpus = directory / f"{target}_seed_corpus.zip"
        if not corpus.is_file():
            continue
        (inputs / target).mkdir(parents=True)
        names[target] = []
        with zipfile.ZipFile(corpus) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    (inputs / target / str(len(names[target]))).write_bytes(HEADER + archive.read(info))
                    names[target].append(info.filename)
    return names


def run_all(tag, binaries, inputs, names, build, results, *, labels):
    """Run each fuzz target in the directory `binaries` on each of its seed inputs (write_seeds), in a container of the
    project image with no network (tools/checks/run-seeds). Keep each run's status and profile in `results`. Return
    [Run]."""
    check_build.empty_directory(results, tag, labels=labels)
    command = ["docker", "run", "--rm", "--init", "--network=none", *labels, "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}",
               "-v", f"{qemu()}:/ovc-qemu:ro", "-v", f"{CHECKS_DIR}:/ovc:ro", "-v", f"{binaries}:/bins:ro",
               "-v", f"{inputs}:/inputs:ro", "-v", f"{results}:/results", "--entrypoint", "/ovc/run-seeds", tag,
               str(os.cpu_count() or 2), str(RUN_TIMEOUT)]
    if check_build.run(*command, quiet=True) != 0:
        raise Failed(f"could not run the fuzz targets of the {build} build on their seed inputs")
    runs = []
    for target in sorted(names):
        if not (binaries / target).is_file():
            continue
        for n, seed in enumerate(names[target]):
            status = results / target / f"{n}.status"
            text = status.read_text().strip() if status.is_file() else ""
            runs.append(Run(target, seed, int(text) if text.isdigit() and text != str(KILLED) else None, build))
    return runs


# ── the builds ───────────────────────────────────────────────────────────────────────────────────────────────────────

def llvm_version(tag, labels):
    """The version of the toolchain's clang, for example 20.1.8."""
    text = check_build.output("docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "clang", tag,
                              "--version")
    found = re.search(r"clang version (\d+\.\d+\.\d+)", text)
    if not found:
        raise Failed(f"cannot read the toolchain's clang version from: {text.strip()[:200]}")
    return found.group(1)


def compiler_rt(version):
    """compiler-rt's source for this LLVM version, downloaded once into the cache and checked. Return its directory."""
    if version not in COMPILER_RT:
        raise Failed(f"--checks has no compiler-rt source for LLVM {version} (tools/check_checks.py, COMPILER_RT)")
    url, sha256 = COMPILER_RT[version]
    home = check_build.CACHE / f"compiler-rt-{version}"
    source = home / f"compiler-rt-{version}.src"
    if (source / "lib" / "profile").is_dir():
        return source
    step(f"download compiler-rt {version}'s source, for the coverage build")
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise Failed(f"{url} does not have the SHA-256 {sha256}")
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
        archive.extractall(home, filter="data")
    return source


def compile_check(tag, out, sanitizer, *, labels, patch=None, runtime=None):
    """Build into `out` with tools/checks/compile-check: the build `sanitizer` names, with the coverage changes if
    `runtime` (compiler-rt's source) is given, and with the breakage `patch` applied if given. Return whether it built."""
    check_build.empty_directory(out, tag, labels=labels)
    mounts = ["-v", f"{CHECKS_DIR}:/ovc:ro", "-v", f"{out}:/out"]
    if patch is not None:
        mounts += ["-v", f"{patch}:/ovc-mutant.patch:ro"]
    if runtime is not None:
        mounts += ["-v", f"{runtime}:/ovc-rt:ro", "-e", "OVC_COVERAGE=1"]
    command = ["docker", "run", "--rm", "--init", "--network=none", *labels, "-e", f"SANITIZER={sanitizer}",
               "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}", *mounts, "--entrypoint", "/ovc/compile-check", tag]
    return check_build.run(*command, quiet=True) == 0


def export_coverage(tag, binaries, profiles, *, labels):
    """Merge each target's profiles and export its coverage with llvm-cov, in the project image. Return {target:
    export}; a target with no profile has none."""
    exports = {}
    for target, binary in sorted(binaries.items()):
        mine = profiles / target
        if not mine.is_dir() or not any(mine.glob("*.profraw")):
            continue
        script = ('llvm-profdata merge -sparse -o /tmp/merged.profdata /profiles/*.profraw && '
                  'llvm-cov export -format=text -instr-profile=/tmp/merged.profdata /binary')
        text = check_build.output("docker", "run", "--rm", "--network=none", *labels, "-v", f"{mine}:/profiles:ro",
                                  "-v", f"{binary}:/binary:ro", "--entrypoint", "sh", tag, "-c", script)
        exports[target] = json.loads(text)
    return exports


def image_files(tag, paths, *, labels):
    """The bytes of these files of the project image: {path: bytes}."""
    if not paths:
        return {}
    done = subprocess.run(["docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "tar", tag, "-cf", "-",
                           "--", *sorted(paths)], stdin=subprocess.DEVNULL, capture_output=True)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(done.stdout)) as archive:
        for member in archive.getmembers():
            if member.isfile():
                files["/" + member.name.lstrip("/")] = archive.extractfile(member).read()
    return files


def mutant_patches(tag, directory, *, labels):
    """The breakage patches in `directory` of the project image (relative to its WORKDIR): {name: bytes}, each regular
    file named *.patch at its top level. Raise Failed if the directory is not there."""
    script = 'cd -- "$1" && for f in *.patch; do [ -f "$f" ] && [ ! -L "$f" ] && printf "%s\\0" "$f"; done; true'
    done = subprocess.run(["docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "sh", tag, "-c", script,
                           "sh", directory], stdin=subprocess.DEVNULL, capture_output=True)
    if done.returncode != 0:
        raise Failed(f"mutants: {directory} is not a directory of the project image")
    names = sorted(name.decode("utf-8", "replace") for name in done.stdout.split(b"\0") if name)[:MAX_PATCHES]
    workdir = check_build.output("docker", "image", "inspect", "--format", "{{.Config.WorkingDir}}", tag).strip() or "/"
    base = pathlib.PurePosixPath(workdir) / directory
    files = image_files(tag, [str(base / name) for name in names], labels=labels)
    return {name: files[str(base / name)][:MAX_PATCH_BYTES] for name in names if str(base / name) in files}


# ── the report ───────────────────────────────────────────────────────────────────────────────────────────────────────

_SAFE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def code(text, limit=120):
    """`text` from the project as Markdown code: control characters removed, at most `limit` characters, in a code
    span that no backtick in it can end."""
    text = _SAFE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def shown(path):
    """A path of the project image as the report shows it: without the leading /src/."""
    return path.removeprefix("/src/")


def describe(run):
    """What a failed run did, in words."""
    if run.status is None:
        return f"did not end within {RUN_TIMEOUT} seconds"
    return f"exit status {run.status}" + (f" ({STATUS_NAMES[run.status]})" if run.status in STATUS_NAMES else "")


def cell(text, limit=60):
    """`text` from the project as Markdown code in a table cell, where a | would end the cell."""
    return code(text, limit).replace("|", "\\|")


def lines_by_file(checks):
    """Checks as `file`: lines 1, 2, 3, one entry per file."""
    files = {}
    for check in checks:
        files.setdefault(shown(check.path), []).append(check.line)
    return [f"{code(path)}: line{'s' if len(lines) > 1 else ''} {', '.join(map(str, sorted(lines)))}"
            for path, lines in sorted(files.items())]


# ── the step ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def measure(tag, binaries, inputs, names, results, *, labels):
    """Run the coverage build's binaries on the seed inputs. Return (runs, Coverage, exports)."""
    runs = run_all(tag, binaries, inputs, names, "coverage", results, labels=labels)
    exports = export_coverage(tag, {target: binaries / target for target in names if (binaries / target).is_file()},
                              results, labels=labels)
    coverage = Coverage()
    for export in exports.values():
        coverage.add(export)
    return runs, coverage, exports


def checks(job, tag, targets, work, raw, *, labels):
    """Run the step, and return its report as Markdown."""
    lines = ["### The checks of the fuzz targets", ""]
    if job.language not in LANGUAGES:
        return "\n".join(lines + [f"`--checks` measures C and C++ fuzz targets only; this project is in "
                                  f"{job.language}.", ""])
    home = work / "checks"
    home.mkdir(parents=True, exist_ok=True)
    inputs = home / "inputs"
    seeds = write_seeds(job.directory, targets, inputs)
    runtime = compiler_rt(llvm_version(tag, labels))

    step("--checks: the coverage build, and each fuzz target on each seed input")
    if not compile_check(tag, home / "coverage", "none", labels=labels, runtime=runtime):
        raise Failed("the coverage build failed (tools/checks/compile-check)")
    base_runs, base, exports = measure(tag, home / "coverage", inputs, seeds, home / "results", labels=labels)

    # The checks: the abort() calls in each file that defines LLVMFuzzerTestOneInput, and in the other files of its
    # directory that the coverage build compiled.
    defining = set().union(*(fuzz_target_files(export) for export in exports.values())) if exports else set()
    directories = {str(pathlib.PurePosixPath(path).parent) for path in defining}
    harness = sorted(path for path in base.segments if str(pathlib.PurePosixPath(path).parent) in directories)
    sources = image_files(tag, harness, labels=labels)
    found = [check for path in harness for check in find_checks(path, sources.get(path, b""))]
    guarded = [check for check in found if check.guard is not None]
    unguarded = [check for check in found if check.guard is None]
    unreached = [check for check in guarded if base.count(check.path, *check.guard) == 0]
    unmapped = [check for check in guarded if base.count(check.path, *check.guard) is None]

    sanitizer = next(((build, value) for build, value in SANITIZER_BUILDS if build in job.builds), None)
    sanitizer_base = (run_all(tag, raw / sanitizer[0], inputs, seeds, sanitizer[0], home / "results-sanitizer",
                              labels=labels) if sanitizer else [])
    failing = [run for run in base_runs + sanitizer_base if run.failed()]
    passing = {(run.build, run.target, run.seed) for run in base_runs + sanitizer_base if not run.failed()}

    no_corpus = [target for target in targets if target not in seeds]
    lines.append(f"Each fuzz target ran on each input of its seed corpus ({sum(map(len, seeds.values()))} inputs), "
                 "in a coverage build" + (f" and in the {sanitizer[0]} build" if sanitizer else "") +
                 ". docs/build-contract.md, \"The checks of a fuzz target\", says how this works.")
    lines.append("")
    if no_corpus:
        lines.append(f"- **No seed corpus:** {', '.join(code(t) for t in no_corpus)}. Step 3.3 of the add-project "
                     "skill asks for one for each fuzz target.")
    if failing:
        lines.append(f"- **Seed inputs that fail on the unchanged library:** {len(failing)}.")
        lines += [f"  - {code(run.target)} on {code(run.seed, 60)}, {run.build} build: {describe(run)}"
                  for run in failing[:20]]
    lines.append(f"- **Checks:** {len(guarded)} checks of the form `if (...) abort();` in "
                 f"{', '.join(code(shown(path)) for path in harness) or 'no file'}.")
    if unreached:
        lines.append(f"- **Checks that no seed input reaches:** {len(unreached)}. Step 3.3 asks for an input that "
                     "reaches each check. Add one to the seed corpus.")
        lines += [f"  - {code(f'{shown(c.path)}:{c.line}')}, under {code(c.text, 90)}" for c in unreached]
    else:
        lines.append("- **Checks that no seed input reaches:** none.")
    if unguarded:
        lines.append(f"- **Not measured:** {len(unguarded)} `abort()` calls that no `if (...)` guards, for example in "
                     "a `default:` of a switch or an `else` branch: " + "; ".join(lines_by_file(unguarded)) + ".")
    if unmapped:
        lines.append(f"- **Not measured:** {len(unmapped)} checks that the coverage build did not compile: "
                     + "; ".join(lines_by_file(unmapped)) + ".")

    if not job.mutants:
        lines += ["- **Breakage patches:** none, because project.yaml has no `mutants` directory. Step 3.4 of the "
                  "add-project skill asks for a one-line breakage patch for each check, in that directory.", ""]
        return "\n".join(lines)

    patches = mutant_patches(tag, job.mutants, labels=labels)
    patch_dir = home / "patches"
    shutil.rmtree(patch_dir, ignore_errors=True)
    patch_dir.mkdir(parents=True)
    rows, fired_any, uncaught = [], set(), []
    for name, body in patches.items():
        step(f"--checks: the breakage patch {name}")
        patch = patch_dir / re.sub(r"[^A-Za-z0-9._-]", "_", name)
        patch.write_bytes(body)
        out = home / "mutant"
        if not compile_check(tag, out / "coverage", "none", labels=labels, patch=patch, runtime=runtime):
            rows.append((name, "does not apply or does not build", ""))
            uncaught.append(name)
            continue
        runs, coverage, _ = measure(tag, out / "coverage", inputs, seeds, home / "mutant-results", labels=labels)
        if sanitizer and compile_check(tag, out / sanitizer[0], sanitizer[1], labels=labels, patch=patch):
            runs += run_all(tag, out / sanitizer[0], inputs, seeds, sanitizer[0], home / "mutant-results-sanitizer",
                            labels=labels)
            builds = ("coverage", sanitizer[0])
        else:
            builds = ("coverage",)
        caught = [run for run in runs if run.failed() and (run.build, run.target, run.seed) in passing]
        fired = [check for check in found if coverage.count(check.path, check.line, check.column)]
        fired_any.update((check.path, check.line, check.column) for check in fired)
        if caught:
            first = caught[0]
            result = f"caught: {cell(first.target)} on {cell(first.seed)}, {first.build} build, {describe(first)}"
        else:
            result = f"**not caught** by any seed input ({' and '.join(builds)} builds)"
            uncaught.append(name)
        rows.append((name, result, ", ".join(cell(f"{shown(c.path)}:{c.line}") for c in fired) or "none"))

    lines.append(f"- **Breakage patches** in {code(job.mutants)}: {len(patches)}, of which {len(uncaught)} no seed "
                 "input catches. Step 3.4 asks for an input that catches each one. Add it to the seed corpus.")
    if rows:
        lines += ["", "  | patch | result | checks that fired |", "  |---|---|---|"]
        lines += [f"  | {cell(name)} | {result} | {fired} |" for name, result, fired in rows]
        lines.append("")
    never = [check for check in guarded if (check.path, check.line, check.column) not in fired_any]
    if never:
        lines.append(f"- **Checks that no breakage patch makes fire:** {len(never)} of {len(guarded)}. Step 3.4 asks "
                     "for a one-line breakage patch for each check, and an input on which the check fires: "
                     + "; ".join(lines_by_file(never)) + ".")
    lines.append("")
    return "\n".join(lines)
