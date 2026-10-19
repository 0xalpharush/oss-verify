#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Seed projects/<name>/project.yaml from the metadata of the oss-fuzz-theorems 2026.10 release.

    tools/seed.py --from CHECKOUT [--recipe RECIPE] [--offline] NAME ...    write projects/NAME/project.yaml
    tools/seed.py --from CHECKOUT [--recipe RECIPE] [--offline] --check     check every seeded project here
    tools/seed.py --from CHECKOUT [--recipe RECIPE] --report FILE           say which projects can be seeded, and why
    tools/seed.py --from CHECKOUT [--recipe RECIPE] [--offline] --branch NAME ...
                                                                            (re)create draft-generic-oss-fuzz-NAME
    tools/seed.py --rebase [NAME ...]                                       move drafts onto main, as they are

CHECKOUT is a checkout of oss-fuzz-theorems (https://github.com/theorem-labs/oss-fuzz-theorems) at the release that
tools/release_tag.py names; this reads its projects/<name>/project.yaml and projects/<name>/<harness>/harness.yaml.
RECIPE is that release's build recipe (recipe.tar.zst, in its -src assets) unpacked; its patches/series.tsv says which
patches the release applied to each library. Without it, a harness whose library the release patched is left out.

A project is seeded only where the release's metadata says everything project.yaml needs, and only with the fuzz
targets whose binaries were built from the library as upstream wrote it:

  - The release built the project (status available) from an https repository at a full commit.
  - fuzz_targets: the harnesses the release included that come from the project or from OSS-Fuzz. Harnesses we wrote
    are not published yet, so they are left out. So is a harness whose build applied a patch that edits the library's
    own source; a patch to build files, version stamps or generated files, or to a harness, is allowed and noted. So
    is a harness the release built from another commit of the library than the project's.
  - repo: the repository at the tag v<version> or <version> if it names the commit the release built (git ls-remote;
    with --offline nothing is looked up), else at that commit.
  - language: c++ if a harness is C++ or a build links the C++ library (libc++), c if every harness is C and no build
    links it, otherwise the release's (OSS-Fuzz's) language.
  - sanitizers: the sanitizer builds the release made of every one of those harnesses.

Every file is checked with tools/validate.py before it is written.

--branch makes draft-generic-oss-fuzz-<name> from the current main: main's tree plus projects/<name>/ (its project.yaml,
and the build files in tools/seeds/<name>/ if there are any; those are kept there only once tools/check has built
them and reproduced the release's binaries), as one commit whose parent is main. A draft pushed to origin exactly as
it would be made again is kept; any other replaces the branch, and is pushed with --force-with-lease, never --force.
The commit message says how the project builds, from tools/seeds/builds.tsv (what tools/verify_ports.py found when it
ported the release's build and checked it). It uses git plumbing and leaves the working tree and the index alone;
running it again replaces the branch. --trailer adds a line to the end of the commit message.

The tag that names a pinned commit comes from git ls-remote, asked of TAG_JOBS repositories at once with a timeout
each, and is kept in tools/seeds/tags.tsv: a pinned commit's tag does not change, so a reseed asks only about new pins.

--rebase moves each draft onto the current main as it is: its projects/<name>/ and its commit message, checked with
tools/validate.py, and nothing looked up. It refuses a draft that a reseed would now make otherwise from main: other
build files than tools/seeds/<name>/, another seeded header, or another message. Use --rebase whenever main moves, and
--branch only when the release's metadata, tools/seeds/ or the rules of seeding change.

--report writes one row per project of the release, with tools/seeds/builds.tsv's result for each seedable one.

Exit codes: 0 if everything asked for was done (or, with --check, every seeded project is up to date); 1 otherwise.
"""
import argparse
import concurrent.futures
import contextlib
import dataclasses
import difflib
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap

import yaml

import check_build
import release_tag
import validate

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEEDS = ROOT / "tools" / "seeds"
BUILDS = SEEDS / "builds.tsv"
# The tag that names each pinned commit, as git ls-remote found it: a pinned commit's tag does not change.
TAGS = SEEDS / "tags.tsv"
TAG_JOBS = 8  # repositories asked at once
TAG_TIMEOUT = 60  # seconds for one git ls-remote
BRANCH = "draft-generic-oss-fuzz-{name}"
REMOTE = "origin"  # where drafts are pushed
HEADER = (
    f"# Seeded by Theorem from {release_tag.NAME} (tools/seed.py), not enrolled by the project's\n"
    "# maintainers: provisional. To adopt it, set primary_contact and remove these lines (docs/project-yaml.md).\n"
)
LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# Where a harness came from, in the release's harness.yaml: from the project's repository or from OSS-Fuzz's.
ORIGINS = ("upstream", "oss-fuzz")
CXX_SUFFIXES = (".cc", ".cpp", ".cxx", ".c++", ".C", ".hpp", ".hh", ".hxx")
CXX_RUNTIME = ("libc++.a", "libc++abi.a")
LIBRARY_PATCHES = re.compile(r"with (\d+) patch(?:es)? to the library")

# A patch may change how a project builds, or its harness, and leave the library as upstream wrote it. These say which
# files are which: a path with "fuzz" in it is a harness or its helpers; these names, suffixes and directories are
# build files.
HARNESS_PATH = re.compile(r"fuzz", re.I)
BUILD_NAMES = {
    "CMakeLists.txt", "meson.build", "meson_options.txt", "meson.options", "configure.ac", "configure.in", "configure",
    "Makefile.am", "Makefile.in", "Makefile", "GNUmakefile", "aclocal.m4", "autogen.sh", "bootstrap", "SHA256SUMS",
    "VERSION", "version.txt", "package_version",
}
BUILD_SUFFIXES = (".cmake", ".m4", ".am", ".ac", ".mk", ".py", ".sh", ".gn", ".gni", ".bzl", ".bazel")
BUILD_DIRECTORIES = {"build-aux", "m4", "cmake", "auto"}
VERSION_FILE = re.compile(r"[A-Z0-9_]*VERSION")
# Libraries the release names by a URL git cannot fetch the commit it built from over https (it fetched them over
# git://), and an https repository that serves that commit. A seeded project's repo must be one tools/check can fetch.
REPOSITORIES = {
    "https://thekelleys.org.uk/dnsmasq": "https://thekelleys.org.uk/git/dnsmasq",
    "https://git.ghostscript.com/ghostpdl": "https://github.com/ArtifexSoftware/ghostpdl",
    "https://git.ghostscript.com/jbig2dec": "https://github.com/ArtifexSoftware/jbig2dec",
    "https://people.freedesktop.org/~dvdhrm/libtsm": "https://github.com/Aetf/libtsm",
}
# The release's classes of patch. Version stamps and generated constants are build-only by what they are; a patch
# of any other class is build-only only if every file it edits is a build file or a harness.
VERSION_STAMPS = "Reproducible build."
BUILD_ADAPTATION = "Build adaptation."


class SeedError(Exception):
    """An input that cannot be read, or a step that cannot be done."""


@dataclasses.dataclass
class Patch:
    """One patch the release applied: to the tree `series` (host/path/commit), in the builds of `targets`."""

    series: str
    name: str
    kind: str
    targets: list
    edits: str | None  # the first file of the library's own source it edits, if any


@dataclasses.dataclass
class Seed:
    """What can be seeded of one project: the fields of its project.yaml, or the reason it cannot be."""

    name: str
    reason: str = ""  # why it cannot be seeded; empty if it can
    kind: str = ""  # the reason, in a few words, for the report's counts
    notes: list = dataclasses.field(default_factory=list)
    repo: str = ""
    release_repo: str = ""  # the repository as the release names it, which its patches are filed under
    commit: str = ""
    version: str = ""
    homepage: str = ""
    language: str = ""
    sanitizers: list = dataclasses.field(default_factory=list)
    targets: list = dataclasses.field(default_factory=list)


def read_yaml(path):
    """Parse a YAML file of the release."""
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=LOADER)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise SeedError(f"cannot read {path}: {error}") from None


def file_kind(path):
    """Whether a file a patch edits is a harness, a build file, or the library's own source."""
    parts = path.split("/")
    if any(HARNESS_PATH.search(part) for part in parts):
        return "harness"
    name = parts[-1]
    if (name in BUILD_NAMES or name.endswith(BUILD_SUFFIXES) or VERSION_FILE.fullmatch(name)
            or any(part in BUILD_DIRECTORIES for part in parts[:-1])):
        return "build"
    return "source"


def library_edit(kind, text):
    """The first file of the library's own source that a patch of this class edits, or None. A file the patch creates is
    not counted (a generated file or build glue), nor one a build adaptation deletes (a unit left out of the build)."""
    if kind == VERSION_STAMPS:
        return None
    for old, new in re.findall(r"^--- (\S+).*\n\+\+\+ (\S+)", text, re.M):
        if old == "/dev/null":
            continue
        if new == "/dev/null":
            if kind == BUILD_ADAPTATION:
                continue
            path = old
        else:
            path = new
        path = path.split("/", 1)[1] if path.startswith(("a/", "b/")) else path
        if file_kind(path) == "source":
            return path
    return None


def load_recipe(recipe):
    """The patches the release applied ({series: [Patch]}), and the harness file each build target compiles
    ({target: {file name}}), from an unpacked release recipe."""
    series_file = recipe / "patches" / "series.tsv"
    try:
        lines = [line.rstrip("\n").split("\t") for line in series_file.read_text(encoding="utf-8").splitlines()]
    except OSError as error:
        raise SeedError(f"cannot read {series_file}: {error}") from None
    rows = [line for line in lines if line and not line[0].startswith("#")]
    if not rows or rows[0][:4] != ["series", "order", "patch", "class"]:
        raise SeedError(f"{series_file} is not a patch series of the release recipe")
    head, patches = rows[0], {}
    for row in rows[1:]:
        entry = dict(zip(head, row))
        path = recipe / "patches" / entry["series"] / entry["patch"]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            raise SeedError(f"cannot read {path}: {error}") from None
        # The recipe spells a tree's host and path in lower case.
        patches.setdefault(entry["series"].lower(), []).append(Patch(
            series=entry["series"], name=entry["patch"], kind=entry["class"],
            targets=[target for target in entry.get("targets", "").split(",") if target],
            edits=library_edit(entry["class"], text),
        ))
    harnesses = {}
    for pin in sorted((recipe / "targets").glob("*/pin")):
        found = re.findall(r'^\s*oft_build_harness "([^"]+)"', pin.read_text(encoding="utf-8", errors="replace"), re.M)
        harnesses[pin.parent.name] = {pathlib.PurePosixPath(path).name for path in found}
    return patches, harnesses


def series_of(repository, commit):
    """The recipe's name for a library's tree: its repository's host and path, and the commit, in lower case."""
    path = repository.split("://", 1)[-1]
    path = path[:-4] if path.endswith(".git") else path
    return f"{path.rstrip('/')}/{commit}".lower()


def target_of(project, harness, source, recipe_targets):
    """The release's build target for one harness, or None if it cannot be told."""
    if f"{project}-{harness}" in recipe_targets:
        return f"{project}-{harness}"
    # The release named some targets after the project alone (its first harness), or after the harness less a suffix:
    # the harness's source file tells which. Where the release records no source, the file named after the harness,
    # or failing that the one file whose name holds the harness's.
    ours = [target for target in recipe_targets if target == project or target.startswith(f"{project}-")]
    if source:
        candidates = [target for target in ours if source in recipe_targets[target]]
    else:
        candidates = [target for target in ours
                      if any(pathlib.PurePosixPath(file).stem == harness for file in recipe_targets[target])]
        if not candidates:
            candidates = [target for target in ours
                          if any(harness in pathlib.PurePosixPath(file).stem for file in recipe_targets[target])]
    return candidates[0] if len(candidates) == 1 else None


def harness_source(harness_yaml):
    """The file name of a harness's source, from the release's harness.yaml, or None."""
    source = harness_yaml.get("source") or {}
    origin = (source.get("from") or {}).get("path")
    files = source.get("files") or []
    if origin:
        return pathlib.PurePosixPath(origin).name
    if files:
        return pathlib.PurePosixPath(files[0]).name
    return None


def build_sanitizers(builds):
    """The sanitizers of project.yaml that a harness's builds in the release cover."""
    if {"asan", "ubsan", "asan-ubsan"} <= builds:
        return {"address", "undefined"}
    return ({"address"} if "asan" in builds else set()) | ({"undefined"} if "ubsan" in builds else set())


def assess(name, checkout, recipe):
    """Decide what can be seeded of one project of the release. `recipe` is load_recipe()'s result, or None."""
    seed = Seed(name)
    project_file = checkout / "projects" / name / "project.yaml"
    if not project_file.is_file():
        seed.reason, seed.kind = "not a project of the release", "not a project"
        return seed
    project = read_yaml(project_file)
    if not isinstance(project, dict):
        seed.reason, seed.kind = "its project.yaml is not a mapping", "unreadable"
        return seed
    if project.get("status") != "available":
        why = project.get("reason")
        seed.reason = f"the release did not build it (status {project.get('status')}" + (f": {why})" if why else ")")
        seed.kind = f"not built by the release ({project.get('status')})"
        return seed
    library = project.get("library") or {}
    seed.repo = str(library.get("repository") or "")
    seed.commit = str(library.get("commit") or "")
    seed.version = str(library.get("version") or "")
    if seed.repo.endswith(".git"):
        seed.repo = seed.repo[:-4]
    if not validate.is_https_url(seed.repo) or "#" in seed.repo:
        seed.reason = f"its library repository is not one https URL ({seed.repo or 'none'})"
        seed.kind = "no https repository"
        return seed
    if not validate.FULL_COMMIT.fullmatch(seed.commit):
        seed.reason, seed.kind = "the release records no full commit for its library", "no full commit"
        return seed
    seed.release_repo, seed.repo = seed.repo, REPOSITORIES.get(seed.repo, seed.repo)
    if seed.repo != seed.release_repo:
        seed.notes.append(f"repo: the release names {seed.release_repo}, from which git cannot fetch the commit over "
                          f"https; {seed.repo} serves it")
    homepage = project.get("homepage")
    if isinstance(homepage, str) and validate.is_https_url(homepage):
        seed.homepage = homepage
    elif homepage:
        seed.notes.append("homepage is not an https URL: left out")

    patches, recipe_targets = recipe if recipe else ({}, {})
    own = patches.get(series_of(seed.release_repo, seed.commit), [])
    included = [entry for entry in project.get("harnesses") or [] if entry.get("status") == "included"]
    kept, cxx, all_c, sanitizers, left_out = [], False, True, None, []
    for entry in included:
        harness = str(entry.get("name"))
        harness_file = checkout / "projects" / name / harness / "harness.yaml"
        details = read_yaml(harness_file) if harness_file.is_file() else None
        if not isinstance(details, dict):
            left_out.append(f"{harness} (no harness.yaml)")
            continue
        if details.get("origin") not in ORIGINS:
            left_out.append(f"{harness} (ours, not published yet)")
            continue
        if not validate.TARGET.fullmatch(harness):
            left_out.append(f"{harness} (not a fuzz target name project.yaml accepts)")
            continue
        builds = details.get("builds") or {}
        if "plain" not in builds:
            left_out.append(f"{harness} (no plain build)")
            continue
        built_from = str((details.get("library") or {}).get("commit") or seed.commit)
        if built_from != seed.commit:
            left_out.append(f"{harness} (built from another commit of the library, {built_from[:12]})")
            continue
        counted = sum(int(match) for line in details.get("modifications") or []
                      for match in LIBRARY_PATCHES.findall(str(line)))
        if counted:
            if recipe is None:
                left_out.append(f"{harness} (the release patched the library; give --recipe to see how)")
                continue
            target = target_of(name, harness, harness_source(details), recipe_targets)
            if target is None:
                applied = [patch for patch in own if any(t.startswith(f"{name}-") for t in patch.targets)]
            else:
                applied = [patch for patch in own if target in patch.targets]
            if not own:
                left_out.append(f"{harness} (the release counts {counted} patch(es) to the library, and the recipe has "
                                "none for its tree)")
                continue
            if len(applied) < counted:
                applied = own  # the recipe names fewer patches for this harness than the release counts
            edits = [patch for patch in applied if patch.edits]
            if edits:
                left_out.append(f"{harness} (the release's patch {edits[0].name} edits {edits[0].edits}, the library's "
                                "own source)")
                continue
            kinds = ", ".join(sorted({patch.kind.rstrip(".").lower() for patch in applied}))
            seed.notes.append(f"{harness}: the release applied {counted} patch(es) to the library's tree ({kinds}), "
                              "none to its own source")
        source = details.get("source") or {}
        if source.get("modified"):
            seed.notes.append(f"{harness}: the release modified this harness" +
                              ("; its copy is not published yet" if source.get("pending") else ""))
        if details.get("origin") == "oss-fuzz":
            seed.notes.append(f"{harness}: the harness is in OSS-Fuzz's repository, not the project's")
        files = [pathlib.PurePosixPath(path).name for path in source.get("files") or []]
        origin_path = (source.get("from") or {}).get("path")
        names = files or ([pathlib.PurePosixPath(origin_path).name] if origin_path else [])
        if any(file.endswith(CXX_SUFFIXES) for file in names):
            cxx = True
        elif not names or not all(file.endswith(".c") for file in names):
            all_c = False
        for build in builds.values():
            unlisted = (build or {}).get("uninstrumented")
            if unlisted is None:
                all_c = False
            elif any((item or {}).get("name") in CXX_RUNTIME for item in unlisted):
                cxx = True
        covered = build_sanitizers(set(builds))
        sanitizers = covered if sanitizers is None else sanitizers & covered
        kept.append(harness)

    for entry in left_out:
        seed.notes.append(f"left out: {entry}")
    if not kept:
        seed.reason = "no harness to seed" + (": " + "; ".join(left_out) if left_out else "")
        if any("edits" in entry for entry in left_out):
            seed.kind = "every harness's build patches the library's own source"
        elif any("give --recipe" in entry for entry in left_out):
            seed.kind = "patched library (no --recipe)"
        elif left_out and all("ours, not published" in entry for entry in left_out):
            seed.kind = "only our own harnesses"
        else:
            seed.kind = "no harness to seed"
        return seed
    seed.targets = kept
    seed.sanitizers = [sanitizer for sanitizer in validate.SANITIZERS if sanitizer in sanitizers]
    if cxx:
        seed.language = "c++"
    elif all_c:
        seed.language = "c"
    else:
        seed.language = str(project.get("language"))
    if seed.language not in validate.LANGUAGES:
        seed.reason, seed.kind = f"its language is {seed.language}, not c or c++", "not c or c++"
    return seed


def tag_names(seed):
    """The tags that may name the release's commit: v<version> and <version>, where each is a valid ref."""
    if not seed.version:
        return []
    return [name for name in (f"v{seed.version}", seed.version)
            if validate.URL.fullmatch(f"https://x#{name}") and not validate.FULL_COMMIT.fullmatch(name)]


def look_up_tag(seed):
    """Ask the project's repository which of tag_names(seed) names the release's commit: that name, or ""."""
    names = tag_names(seed)
    wanted = [f"refs/tags/{name}{peel}" for name in names for peel in ("", "^{}")]
    try:
        done = subprocess.run(check_build.git("ls-remote", "--tags", "--", seed.repo, *wanted),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace",
                              timeout=TAG_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise SeedError(f"{seed.name}: git ls-remote {seed.repo} took more than {TAG_TIMEOUT} s") from None
    if done.returncode != 0:
        raise SeedError(f"{seed.name}: cannot list the tags of {seed.repo}: {done.stderr.strip()[-1500:]}")
    refs = dict(reversed(line.split("\t", 1)) for line in done.stdout.splitlines() if "\t" in line)
    for name in names:
        if (refs.get(f"refs/tags/{name}^{{}}") or refs.get(f"refs/tags/{name}")) == seed.commit:
            return name
    return ""


def read_tags(path=TAGS):
    """What earlier lookups found: {(repo, commit): its tag, or "" if no tag that we look for names it}."""
    tags = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "repo\t")):
                repo, commit, tag = (line.split("\t") + ["", ""])[:3]
                tags[(repo, commit)] = tag
    return tags


def write_tags(tags, path=TAGS):
    rows = ["# generated by tools/seed.py: the tag that names each pinned commit (empty: none does); do not edit",
            "repo\tcommit\ttag", *(f"{repo}\t{commit}\t{tag}" for (repo, commit), tag in sorted(tags.items()))]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def look_up_tags(seeds, tags, jobs=TAG_JOBS):
    """Fill in `tags` for each seed whose pin it does not know, asking `jobs` repositories at once. Return the errors;
    a pin that could not be looked up stays unknown."""
    todo = {}
    for seed in seeds:
        if tag_names(seed) and (seed.repo, seed.commit) not in tags:
            todo.setdefault((seed.repo, seed.commit), seed)
    errors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(look_up_tag, seed): key for key, seed in todo.items()}
        for future in concurrent.futures.as_completed(futures):
            try:
                tags[futures[future]] = future.result()
            except SeedError as error:
                errors.append(str(error))
    return errors


def tag_for(seed, offline, tags=None):
    """The tag to name the release's commit by (v<version> or <version>), or None to name the commit itself. `tags`,
    if given, holds what earlier lookups found, and gets what this one finds."""
    if offline or not tag_names(seed):
        return None
    key = (seed.repo, seed.commit)
    if tags is None:
        return look_up_tag(seed) or None
    if key not in tags:
        tags[key] = look_up_tag(seed)
    return tags[key] or None


def plain(value, flow=False):
    """`value` as a YAML scalar: plain if it reads back as itself, else single-quoted."""
    probe = f"k: [{value}]" if flow else f"k: {value}"
    expected = {"k": [value] if flow else value}
    try:
        if value and yaml.safe_load(probe) == expected:
            return value
    except yaml.YAMLError:
        pass
    return "'" + value.replace("'", "''") + "'"


def render(seed, ref):
    """The text of a seeded project.yaml."""
    lines = [
        f"repo: {plain(f'{seed.repo}#{ref}')}",
        "primary_contact: n/a",
        *([f"homepage: {plain(seed.homepage)}"] if seed.homepage else []),
        f"language: {plain(seed.language)}",
        f"sanitizers: [{', '.join(seed.sanitizers)}]",
        f"fuzz_targets: [{', '.join(plain(target, flow=True) for target in seed.targets)}]",
    ]
    return HEADER + "\n".join(lines) + "\n"


def checked(seed, text):
    """Raise SeedError unless `text` is a valid project.yaml that says what `seed` does."""
    config = yaml.safe_load(text)
    problems = validate.check_config(config, {})
    if problems:
        raise SeedError(f"{seed.name}: the seeded project.yaml breaks the rules: {'; '.join(problems)}")
    if config.get("fuzz_targets") != seed.targets or validate.sanitizers_of(config) != seed.sanitizers:
        raise SeedError(f"{seed.name}: the seeded project.yaml does not read back as written")
    return text


def generate(name, checkout, recipe, offline, tags=None, found=None):
    """(Seed, project.yaml text or None). `found` is assess()'s Seed for the project, if it is known already."""
    seed = found or assess(name, checkout, recipe)
    if seed.reason:
        return seed, None
    ref = tag_for(seed, offline, tags) or seed.commit
    return seed, checked(seed, render(seed, ref))


def git(*args, root=ROOT, env=None, data=None):
    """Run git in the repository at `root` and return its standard output, as bytes if `data` is bytes."""
    done = subprocess.run(["git", "-C", str(root), *args], input=data, capture_output=True, env=env,
                          text=not isinstance(data, bytes))
    if done.returncode != 0:
        error = done.stderr if isinstance(done.stderr, str) else done.stderr.decode(errors="replace")
        raise SeedError(f"git {' '.join(args[:2])} failed: {error.strip()}")
    return done.stdout


def seed_files(name, seeds=SEEDS):
    """The build files tools/check has built for a draft project: {file name: (bytes, git mode)}."""
    directory = seeds / name
    if not directory.is_dir():
        return {}
    files = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.is_symlink():
            raise SeedError(f"tools/seeds/{name}/{path.name} is not a regular file")
        files[path.name] = (path.read_bytes(), "100755" if os.access(path, os.X_OK) else "100644")
    return files


def read_builds(path=BUILDS):
    """What tools/verify_ports.py found for each project it ported and checked: {name: (result, detail)}."""
    builds = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "project\t")):
                name, result, detail = (line.split("\t") + ["", ""])[:3]
                builds[name] = (result, detail)
    return builds


def build_status(name, builds, seeds=SEEDS):
    """What a draft's commit message says of its build files."""
    result, detail = builds.get(name, ("", ""))
    if seed_files(name, seeds):
        if result != "reproduces":
            raise SeedError(f"tools/seeds/{name}/ has build files, but tools/seeds/builds.tsv does not say they "
                            "reproduce the release's binaries")
        return ("Build files: tools/check builds them and reproduces the release's binaries of these fuzz targets "
                "byte for byte.")
    if result == "reproduces":
        raise SeedError(f"{name}: its port reproduces the release's binaries, but tools/seeds/{name}/ has no build files")
    why = {
        "differs": "the build ported from the release's builds, but not every binary is the release's",
        "fails": "the build ported from the release's fails",
        "not-ported": "tools/port.py cannot port the release's build",
    }.get(result)
    if why is None:
        return "No build files yet: the release's build has not been ported and checked."
    return f"No build files yet: {why} ({detail})." if detail and detail != "-" else f"No build files yet: {why}."


class Plumbing:
    """git cat-file --batch and git mktree --batch, kept running: each object read or tree written costs no new
    process. Trees are lists of (mode, name, object id) entries."""

    def __init__(self, root=ROOT):
        self.root = root
        hash_name = git("rev-parse", "--show-object-format", root=root).strip()
        self.hash = getattr(hashlib, hash_name)
        self.reader = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.maker = subprocess.Popen(["git", "-C", str(root), "mktree", "--batch"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def close(self):
        for process in (self.reader, self.maker):
            process.stdin.close()
            process.wait()
            process.stdout.close()

    def read(self, rev):
        """(type, bytes) of the object that `rev` names, or None if it names none."""
        self.reader.stdin.write(rev.encode() + b"\n")
        self.reader.stdin.flush()
        header = self.reader.stdout.readline().split()
        if len(header) != 3:
            return None
        data = self.reader.stdout.read(int(header[2]))
        self.reader.stdout.read(1)
        return header[1].decode(), data

    def tree(self, rev):
        """The entries of the tree that `rev` names: [(mode, name, id)]."""
        found = self.read(rev)
        if found is None or found[0] != "tree":
            raise SeedError(f"{rev} is not a tree")
        data, entries, at, size = found[1], [], 0, self.hash().digest_size
        while at < len(data):
            space = data.index(b" ", at)
            nul = data.index(b"\0", space)
            entries.append((data[at:space].decode(), data[space + 1:nul].decode(), data[nul + 1:nul + 1 + size].hex()))
            at = nul + 1 + size
        return entries

    def commit(self, rev):
        """(tree, [parents], message) of the commit that `rev` names, or None."""
        found = self.read(rev)
        if found is None or found[0] != "commit":
            return None
        head, _, message = found[1].decode(errors="replace").partition("\n\n")
        fields = [line.split(" ", 1) for line in head.splitlines() if " " in line]
        return (next(value for key, value in fields if key == "tree"),
                [value for key, value in fields if key == "parent"], message)

    def mktree(self, entries):
        """Write a tree of these entries. Return its id."""
        kinds = {"40000": "tree", "040000": "tree", "160000": "commit"}
        text = "".join(f"{mode} {kinds.get(mode, 'blob')} {oid}\t{name}\n" for mode, name, oid in entries)
        self.maker.stdin.write(text.encode() + b"\n")
        self.maker.stdin.flush()
        return self.maker.stdout.readline().decode().strip()

    def blob_id(self, data):
        """The id that git gives a blob of these bytes."""
        return self.hash(b"blob %d\0" % len(data) + data).hexdigest()


class Drafts:
    """Makes draft branches from the current main with git plumbing, leaving the working tree and the index alone.
    Use it as a context manager: the branches are updated, all at once, when it closes."""

    def __init__(self, root=ROOT, seeds=SEEDS, builds=None):
        self.root, self.seeds = root, seeds
        self.builds = read_builds() if builds is None else builds
        self.main = git("rev-parse", "--verify", "refs/heads/main", root=root).strip()
        self.plumbing = Plumbing(root)
        self.root_entries = self.plumbing.tree(f"{self.main}^{{tree}}")
        projects = [oid for mode, name, oid in self.root_entries if name == "projects"]
        self.projects = self.plumbing.tree(projects[0]) if projects else []
        self.refs = dict(line.split(" ", 1)[::-1] for line in git(
            "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads/draft-generic-oss-fuzz-*",
            f"refs/remotes/{REMOTE}/draft-generic-oss-fuzz-*", root=root).splitlines())
        self.updates = {}
        self.ancestors = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            if self.updates and exc[0] is None:
                git("update-ref", "--stdin", root=self.root,
                    data="".join(f"update refs/heads/{branch} {commit}\n" for branch, commit in self.updates.items()))
        finally:
            self.plumbing.close()

    def message(self, name, trailers=()):
        """The commit message of a draft: what the release seeds and how the project builds."""
        status = build_status(name, self.builds, self.seeds)
        message = f"Draft: seed projects/{name} from {release_tag.NAME}\n\n{textwrap.fill(status, 72)}\n"
        return message + ("\n" + "\n".join(trailers) + "\n" if trailers else "")

    def commit(self, name, project_tree, message):
        """Main plus projects/<name> as `project_tree`, as one commit: what was pushed, if that is it already."""
        if any(entry == name for _, entry, _ in self.projects):
            raise SeedError(f"projects/{name} is on main already: a draft is for a project main does not have")
        projects = self.plumbing.mktree([*self.projects, ("40000", name, project_tree)])
        tree = self.plumbing.mktree([entry for entry in self.root_entries if entry[1] != "projects"] +
                                    [("40000", "projects", projects)])
        branch = BRANCH.format(name=name)
        # The draft as it was pushed to origin, if that is this draft already: kept, so that it is not pushed again.
        pushed = self.refs.get(f"refs/remotes/{REMOTE}/{branch}")
        if pushed and self.plumbing.commit(pushed) == (tree, [self.main], message):
            commit = pushed
        else:
            commit = git("commit-tree", tree, "-p", self.main, "-F", "-", root=self.root, data=message).strip()
        self.updates[branch] = commit
        return branch, commit

    def seed(self, name, text, trailers):
        """(Re)make a draft from its seeded project.yaml and the build files in tools/seeds/<name>/."""
        files = {"project.yaml": (text.encode(), "100644"), **seed_files(name, self.seeds)}
        with tempfile.TemporaryDirectory(prefix="seed-branch.") as scratch:
            draft = pathlib.Path(scratch) / "projects" / name
            draft.mkdir(parents=True)
            for file, (data, mode) in files.items():
                (draft / file).write_bytes(data)
                if mode == "100755":
                    (draft / file).chmod(0o755)
            problems, _, _ = validate.check_project(draft)
            if problems:
                raise SeedError(f"{name}: the draft's projects/{name}/ breaks the rules: {'; '.join(problems)}")
            paths = "".join(f"{draft / file}\n" for file in files)
            blobs = git("hash-object", "-w", "--no-filters", "--stdin-paths", root=self.root, data=paths).split()
        project = self.plumbing.mktree([(mode, file, blob) for (file, (_, mode)), blob in zip(files.items(), blobs)])
        return self.commit(name, project, self.message(name, trailers))

    def rebase(self, name):
        """Move a draft onto the current main as it is: its projects/<name>/ and its message, checked with validate.py.
        Refuse a draft that is no longer what a reseed from main's tools/seeds/ would make."""
        branch = BRANCH.format(name=name)
        source = self.refs.get(f"refs/heads/{branch}") or self.refs.get(f"refs/remotes/{REMOTE}/{branch}")
        found = source and self.plumbing.commit(source)
        if not found:
            raise SeedError(f"{branch}: no such branch, here or on {REMOTE}")
        tree, parents, message = found
        if len(parents) != 1:
            raise SeedError(f"{branch}: not one commit on main")
        if parents[0] not in self.ancestors:
            self.ancestors[parents[0]] = subprocess.run(
                ["git", "-C", str(self.root), "merge-base", "--is-ancestor", parents[0], self.main]).returncode == 0
        if not self.ancestors[parents[0]]:
            raise SeedError(f"{branch}: its parent {parents[0][:12]} is not on main")
        # The draft is its parent plus projects/<name>/, and nothing else.
        old_root = self.plumbing.tree(tree)
        parent_root = self.plumbing.tree(f"{parents[0]}^{{tree}}")
        old_projects = self.plumbing.tree(next(oid for mode, entry, oid in old_root if entry == "projects"))
        parent_projects = next((self.plumbing.tree(oid) for mode, entry, oid in parent_root if entry == "projects"), [])
        project = [oid for mode, entry, oid in old_projects if entry == name]
        if (not project or [entry for entry in old_root if entry[1] != "projects"] !=
                [entry for entry in parent_root if entry[1] != "projects"] or
                [entry for entry in old_projects if entry[1] != name] != parent_projects):
            raise SeedError(f"{branch}: changes more than projects/{name}/")
        files = {entry: (mode, oid) for mode, entry, oid in self.plumbing.tree(project[0])}
        # Still what main's seed inputs make: its build files, the seeded header and the message.
        expected = {file: (mode, self.plumbing.blob_id(data))
                    for file, (data, mode) in seed_files(name, self.seeds).items()}
        if {file: found for file, found in files.items() if file != "project.yaml"} != expected:
            raise SeedError(f"{name}: needs a full reseed: its build files are not those in tools/seeds/{name}/")
        text = self.plumbing.read(files["project.yaml"][1])[1].decode() if "project.yaml" in files else ""
        if not text.startswith(HEADER):
            raise SeedError(f"{name}: needs a full reseed: its project.yaml does not start with the seeded header")
        if not message.startswith(self.message(name)):
            raise SeedError(f"{name}: needs a full reseed: its commit message is not what tools/seed.py writes now")
        with tempfile.TemporaryDirectory(prefix="seed-rebase.") as scratch:
            draft = pathlib.Path(scratch) / "projects" / name
            draft.mkdir(parents=True)
            for file, (mode, oid) in files.items():
                (draft / file).write_bytes(self.plumbing.read(oid)[1])
                if mode == "100755":
                    (draft / file).chmod(0o755)
            problems, _, _ = validate.check_project(draft)
        if problems:
            raise SeedError(f"{name}: the draft's projects/{name}/ breaks the rules: {'; '.join(problems)}")
        return self.commit(name, project[0], message)


def make_branch(name, text, trailers, root=ROOT, seeds=SEEDS, builds=None):
    """(Re)create the draft branch of one project. Return (branch, commit)."""
    with Drafts(root, seeds, builds) as drafts:
        return drafts.seed(name, text, trailers)


def rebase_branch(name, root=ROOT, seeds=SEEDS, builds=None):
    """Move the draft branch of one project onto the current main, as it is. Return (branch, commit)."""
    with Drafts(root, seeds, builds) as drafts:
        return drafts.rebase(name)


def seeded_here(projects=validate.PROJECTS):
    """The projects here that we seeded (primary_contact n/a), as {name: committed project.yaml text}."""
    found = {}
    for directory in sorted(path for path in projects.glob("*") if path.is_dir() and not path.is_symlink()):
        try:
            config = validate.load(directory)
        except (ValueError, OSError):
            continue
        if isinstance(config, dict) and config.get("primary_contact") == validate.NO_CONTACT:
            found[directory.name] = (directory / "project.yaml").read_text(encoding="utf-8")
    return found


def check(checkout, recipe, offline, projects=validate.PROJECTS, tags=None):
    """Regenerate every seeded project here and compare. Return the number that differ."""
    differing = 0
    seeds = {name: assess(name, checkout, recipe) for name in seeded_here(projects)}
    if not offline and tags is not None:
        for error in look_up_tags([seed for seed in seeds.values() if not seed.reason], tags):
            print(validate.printable(error), file=sys.stderr)
    for name, committed in seeded_here(projects).items():
        seed = seeds[name]
        if seed.reason:
            print(f"{name}: can no longer be seeded: {seed.reason}", file=sys.stderr)
            differing += 1
            continue
        ref = tag_for(seed, offline, tags)
        if offline:
            # Nothing is looked up: a committed tag is accepted if it is one tag_for() would look for.
            current = (yaml.safe_load(committed) or {}).get("repo", "")
            committed_ref = current.partition("#")[2] if isinstance(current, str) else ""
            ref = committed_ref if committed_ref in (f"v{seed.version}", seed.version) and seed.version else None
        text = checked(seed, render(seed, ref or seed.commit))
        if text != committed:
            differing += 1
            diff = difflib.unified_diff(committed.splitlines(True), text.splitlines(True),
                                        f"projects/{name}/project.yaml", "seeded", n=0)
            print(validate.printable("".join(diff)).replace("\\x0a", "\n"), file=sys.stderr, end="")
        else:
            print(f"{name}: up to date")
    return differing


def report(checkout, recipe, path, builds=None):
    """Write the TSV of every project of the release: whether it can be seeded, its fuzz targets, how its build ported
    from the release's fares (`builds`, as read_builds() reads them), and why."""
    builds = read_builds() if builds is None else builds
    rows = [f"# generated by tools/seed.py from {release_tag.NAME} and tools/seeds/builds.tsv; do not edit",
            "project\tseedable\tfuzz_targets\tbuild\tbuild notes\treason or notes"]
    counts = {}
    for project_file in sorted((checkout / "projects").glob("*/project.yaml")):
        seed = assess(project_file.parent.name, checkout, recipe)
        if seed.reason:
            rows.append(f"{seed.name}\tno\t-\t-\t-\t{seed.reason}")
            key = seed.kind or seed.reason
        else:
            result, detail = builds.get(seed.name, ("not checked", "-"))
            rows.append(f"{seed.name}\tyes\t{','.join(seed.targets)}\t{result}\t{detail or '-'}\t"
                        f"{'; '.join(seed.notes) or '-'}")
            key = "seedable"
            counts[f"seedable, build {result}"] = counts.get(f"seedable, build {result}", 0) + 1
        counts[key] = counts.get(key, 0) + 1
    pathlib.Path(path).write_text("\n".join(row.replace("\n", " ") for row in rows) + "\n", encoding="utf-8")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="projects of the release to seed")
    parser.add_argument("--from", dest="checkout", type=pathlib.Path,
                        help="a checkout of oss-fuzz-theorems at the release that tools/release_tag.py names")
    parser.add_argument("--recipe", type=pathlib.Path, help="that release's build recipe, unpacked")
    parser.add_argument("--offline", action="store_true", help="look nothing up: name each library by its commit")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check every seeded project here against the release")
    mode.add_argument("--report", type=pathlib.Path, help="write which projects can be seeded, and why, to this file")
    mode.add_argument("--branch", action="store_true", help="(re)create draft-generic-oss-fuzz-<name> for each name")
    mode.add_argument("--rebase", action="store_true",
                      help="move each draft (default: every local one) onto main as it is; no release needed")
    parser.add_argument("--trailer", action="append", default=[], help="a line to end each draft commit's message with")
    parser.add_argument("--out", type=pathlib.Path, help="write NAME/project.yaml under OUT instead of projects/")
    options = parser.parse_args()

    if options.rebase:
        if options.checkout or options.recipe or options.trailer or options.out:
            parser.error("--rebase takes only project names: it keeps each draft's files and message")
        return rebase(options.names)
    if options.checkout is None:
        parser.error("--from is required")
    if not (options.checkout / "projects").is_dir():
        parser.error(f"{options.checkout} has no projects/: it is not a checkout of oss-fuzz-theorems")
    release_tag.check(options.checkout)
    if (options.check or options.report) and options.names:
        parser.error("--check and --report take no project names")
    if not (options.check or options.report) and not options.names:
        parser.error("name at least one project")
    tags = read_tags()
    known = dict(tags)
    try:
        recipe = load_recipe(options.recipe) if options.recipe else None
        if options.check:
            return 1 if check(options.checkout, recipe, options.offline, tags=tags) else 0
        if options.report:
            counts = report(options.checkout, recipe, options.report)
            for key, count in sorted(counts.items(), key=lambda item: -item[1]):
                print(f"{count:6}  {key}")
            return 0
        seeds = {name: assess(name, options.checkout, recipe) for name in options.names}
        if not options.offline:
            for error in look_up_tags([seed for seed in seeds.values() if not seed.reason], tags):
                print(validate.printable(error), file=sys.stderr)
        failed = 0
        with contextlib.ExitStack() as stack:
            drafts = stack.enter_context(Drafts()) if options.branch else None
            for name in options.names:
                try:
                    seed, text = generate(name, options.checkout, recipe, options.offline, tags, seeds[name])
                    if text is None:
                        print(validate.printable(f"{name}: not seeded: {seed.reason}"), file=sys.stderr)
                        failed += 1
                        continue
                    if drafts:
                        branch, commit = drafts.seed(name, text, options.trailer)
                except SeedError as error:  # this project; the others go on
                    print(validate.printable(str(error)), file=sys.stderr)
                    failed += 1
                    continue
                if drafts:
                    print(f"{branch}: {commit}")
                else:
                    directory = (options.out or validate.PROJECTS) / name
                    directory.mkdir(parents=True, exist_ok=True)
                    (directory / "project.yaml").write_text(text, encoding="utf-8")
                    print(f"projects/{name}/project.yaml")
                for note in seed.notes:
                    print(validate.printable(f"  {name}: {note}"))
        return 1 if failed else 0
    except SeedError as error:
        print(validate.printable(str(error)), file=sys.stderr)
        return 1
    finally:
        if tags != known:
            write_tags(tags)


def rebase(names, root=ROOT, seeds=SEEDS):
    """--rebase: move each named draft (default: every local draft branch) onto main. Return the exit code."""
    prefix = "refs/heads/draft-generic-oss-fuzz-"
    names = names or [ref[len(prefix):] for ref in git("for-each-ref", "--format=%(refname)", prefix + "*",
                                                          root=root).split()]
    failed = 0
    try:
        with Drafts(root, seeds) as drafts:
            for name in names:
                try:
                    branch, commit = drafts.rebase(name)
                except SeedError as error:  # this draft; the others go on
                    print(validate.printable(str(error)), file=sys.stderr)
                    failed += 1
                    continue
                print(f"{branch}: {commit}")
    except SeedError as error:
        print(validate.printable(str(error)), file=sys.stderr)
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
