#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Port projects from the oss-fuzz-theorems 2026.10 release and check each port against the release's binaries.

    tools/verify_ports.py --from CHECKOUT --recipe RECIPE --assets ASSETS --work DIR --results FILE [NAME ...]

For each NAME (default: every project tools/seed.py can seed), in parallel:

  1. tools/seed.py --offline writes its project.yaml, naming the release's commit;
  2. tools/port.py writes its Dockerfile, build.sh and sources;
  3. tools/check --no-shell builds it, with each of the release's harness.yaml files for its fuzz targets as a lock.

It appends one row per project to FILE, a tab-separated file with these columns, and skips a project FILE already
has a row for:

    project  result  detail

where result is one of
    reproduces    every binary of every build is byte for byte the release's
    differs       it builds, but some binaries differ from the release's (detail says which)
    fails         it does not build (detail gives the step and the last lines of its log)
    not-ported    tools/port.py cannot port it yet (detail says why)

Each project's files and log stay in DIR/<name>/; its images and the builds' raw output are removed when it is done.
A check still running after --timeout seconds is stopped, with its containers, and the project fails. It stops
starting projects when the file system holding DIR has less than --min-free-gb free.

Needs what tools/check needs, and the toolchain image. Set OFT_MAKE_JOBS to bound each build's parallelism.
"""
import argparse
import concurrent.futures
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import threading

import check_build
import port
import release_tag
import seed
import validate

TOOLS = pathlib.Path(__file__).resolve().parent
LOCK = threading.Lock()


def free_gb(path):
    usage = shutil.disk_usage(path)
    return usage.free / (1 << 30)


def one_line(text, limit=400):
    """Text for one TSV cell: no tabs or newlines, bounded."""
    text = re.sub(r"\s+", " ", validate.printable(text).replace("\\x09", " ").replace("\\x0a", " ")).strip()
    return text[:limit]


def verdict(code, log):
    """The result and detail of one tools/check run, from its exit code and log."""
    differences = re.findall(r"^  (\S+\.\S+: sha256 \S+ \(\d+ bytes\), the lock has \S+ \(\S+ bytes\))$", log, re.M)
    missing = re.findall(r"^  (\S+: in the lock, not in this build)$", log, re.M)
    if code == 0 and "matches the lock" in log:
        return "reproduces", "all binaries match the release's"
    if code == 3:
        shown = differences + missing
        return "differs", f"{len(shown)} binaries differ: " + "; ".join(shown[:6])
    failed = re.search(r"^BUILD FAILED: (.*)$", log, re.M)
    tail = [line for line in log.splitlines()[-400:] if re.search(r"error|Error|ERROR|FAILED|not found|No such", line)]
    detail = (failed.group(1) if failed else f"tools/check exited {code}") + (" | " + " | ".join(tail[-4:]) if tail else "")
    return "fails", detail


def locks_for(checkout, name, targets):
    return [checkout / "projects" / name / target / "harness.yaml" for target in targets]


def images(work):
    """The project images that the tools/check run in `work` built: the tags it recorded, which name its work
    directory. Never the images of another run of the same project. docker skips a recorded tag that was never built."""
    return check_build.recorded_images(work / check_build.IMAGES)


def remove_images(work):
    """Remove the project images that the tools/check run in `work` built (never any other)."""
    listing = images(work)
    if listing:
        subprocess.run(["docker", "image", "rm", "-f", *listing], capture_output=True)


def stop_containers(work):
    """Kill the containers that the tools/check run in `work` started, by their label (never any other)."""
    label = f"label={check_build.WORK_LABEL}={work.absolute()}"
    running = subprocess.run(["docker", "ps", "-q", "--filter", label], capture_output=True, text=True).stdout.split()
    if running:
        subprocess.run(["docker", "kill", *sorted(running)], capture_output=True)


def clean_up(work):
    """Stop the containers and remove the images of the tools/check run in `work`: after it ends, and before its work
    directory is deleted for a new run, for a run that this script did not live to clean up after."""
    stop_containers(work)
    remove_images(work)


def run_check(arguments, log, timeout):
    """Run tools/check in a process group of its own. Return its exit code, or None if it ran out of time (and was
    killed, with everything it started)."""
    process = subprocess.Popen(arguments, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        return None


def verify(name, options, release):
    """Port and check one project. Return (result, detail)."""
    directory = options.work / name / "project" / name
    work = options.work / name / "check"
    log_file = options.work / name / "log"
    clean_up(work)
    shutil.rmtree(options.work / name, ignore_errors=True)
    directory.mkdir(parents=True)
    seeded, text = seed.generate(name, options.checkout, (release.patches, release.harnesses), offline=True)
    if text is None:
        return "not-ported", f"not seedable: {seeded.reason}"
    (directory / "project.yaml").write_text(text, encoding="utf-8")
    port = subprocess.run([sys.executable, str(TOOLS / "port.py"), "--from", str(options.checkout), "--recipe",
                           str(options.recipe), "--assets", str(options.assets), "--out", str(directory.parent), name],
                          capture_output=True, text=True)
    if port.returncode != 0:
        return "not-ported", port.stderr.strip().removeprefix(f"{name}: not ported: ")
    problems, _, _ = validate.check_project(directory)
    if problems:
        return "not-ported", "the port breaks the enrollment rules: " + "; ".join(problems)
    locks = [arg for lock in locks_for(options.checkout, name, seeded.targets) for arg in ("--lock", str(lock))]
    with open(log_file, "w", encoding="utf-8") as log:
        code = run_check([str(TOOLS / "check"), "--no-shell", *locks, "--dir", str(work), str(directory)], log,
                         options.timeout)
    if code is None:
        result = "fails", f"tools/check was still running after {options.timeout} seconds, and was stopped"
    else:
        result = verdict(code, log_file.read_text(encoding="utf-8", errors="replace"))
    clean_up(work)
    shutil.rmtree(work / "raw", ignore_errors=True)
    shutil.rmtree(work / "twice", ignore_errors=True)
    shutil.rmtree(work / "src", ignore_errors=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="projects to port and check (default: every seedable one)")
    parser.add_argument("--from", dest="checkout", type=pathlib.Path, required=True)
    parser.add_argument("--recipe", type=pathlib.Path, required=True)
    parser.add_argument("--assets", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path, required=True, help="where each project's files and log go")
    parser.add_argument("--results", type=pathlib.Path, required=True, help="the TSV of results, appended to")
    parser.add_argument("--jobs", type=int, default=8, help="projects at once (default 8)")
    parser.add_argument("--min-free-gb", type=float, default=300, help="stop starting projects below this (default 300)")
    parser.add_argument("--timeout", type=int, default=4 * 3600, help="seconds one project's check may take (default 4 h)")
    options = parser.parse_args()
    release_tag.check(options.checkout)
    release = port.Release(options.checkout, options.recipe, options.assets)
    names = options.names or sorted(
        path.parent.name for path in (options.checkout / "projects").glob("*/project.yaml")
        if not seed.assess(path.parent.name, options.checkout, (release.patches, release.harnesses)).reason)
    done = set()
    if options.results.exists():
        done = {line.split("\t", 1)[0] for line in options.results.read_text().splitlines() if line and not line.startswith(("#", "project\t"))}
    else:
        options.results.write_text("# generated by tools/verify_ports.py; do not edit\nproject\tresult\tdetail\n")
    todo = [name for name in names if name not in done]
    options.work.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()

    def task(name):
        if stop.is_set():
            return
        if free_gb(options.work) < options.min_free_gb:
            stop.set()
            print(f"stopping: less than {options.min_free_gb} GB free", flush=True)
            return
        try:
            result, detail = verify(name, options, release)
        except Exception as error:  # a crash of this script on one project is recorded, and the others go on
            result, detail = "fails", f"verify_ports crashed: {type(error).__name__}: {error}"
        with LOCK:
            with open(options.results, "a", encoding="utf-8") as handle:
                handle.write(f"{name}\t{result}\t{one_line(detail)}\n")
            print(f"{name}: {result}: {one_line(detail, 160)}", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=options.jobs) as pool:
        list(pool.map(task, todo))
    return 2 if stop.is_set() else 0


if __name__ == "__main__":
    sys.exit(main())
