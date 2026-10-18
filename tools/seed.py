#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Seed projects/<name>/project.yaml from the metadata of oss-fuzz-theorems release 2026.10.0-rc.2.

    tools/seed.py --from CHECKOUT [--recipe RECIPE] [--offline] NAME ...    write projects/NAME/project.yaml
    tools/seed.py --from CHECKOUT [--recipe RECIPE] [--offline] --check     check every seeded project here
    tools/seed.py --from CHECKOUT [--recipe RECIPE] --report FILE           say which projects can be seeded, and why
    tools/seed.py --from CHECKOUT [--recipe RECIPE] [--offline] --branch NAME ...
                                                                            (re)create draft-generic-oss-fuzz-NAME

CHECKOUT is a checkout of oss-fuzz-theorems (https://github.com/theorem-labs/oss-fuzz-theorems) at release
2026.10.0-rc.2; this reads its projects/<name>/project.yaml and projects/<name>/<harness>/harness.yaml. RECIPE is that
release's build recipe (recipe.tar.zst, in its v2026.10.0-rc.2-src release) unpacked; its patches/series.tsv says which
patches the release applied to each library. Without it, a harness whose library the release patched is left out.

A project is seeded only where the release's metadata says everything project.yaml needs, and only with the fuzz
targets whose binaries were built from the library as upstream wrote it:

  - The release built the project (status available) from an https repository at a full commit.
  - fuzz_targets: the harnesses the release included that come from the project or from OSS-Fuzz. Harnesses we wrote
    are not published yet, so they are left out. So is a harness whose build applied a patch that edits the library's
    own source; a patch to build files, version stamps or generated files, or to a harness, is allowed and noted.
  - repo: the repository at the tag v<version> or <version> if it names the commit the release built (git ls-remote;
    with --offline nothing is looked up), else at that commit.
  - language: c++ if a harness is C++ or a build links the C++ library (libc++), c if every harness is C and no build
    links it, otherwise the release's (OSS-Fuzz's) language.
  - sanitizers: the sanitizer builds the release made of every one of those harnesses.

Every file is checked with tools/validate.py before it is written.

--branch makes draft-generic-oss-fuzz-<name> from the current main: main's tree plus projects/<name>/ (its project.yaml,
and the build files in tools/seeds/<name>/ if there are any; those are kept there only once tools/check has built
them), with README.md's projects table regenerated, as one commit whose parent is main. It uses git plumbing and leaves
the working tree and the index alone; running it again replaces the branch. --trailer adds a line to the end of the
commit message.

Exit codes: 0 if everything asked for was done (or, with --check, every seeded project is up to date); 1 otherwise.
"""
import argparse
import dataclasses
import difflib
import os
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml

import check_build
import projects_table
import validate

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEEDS = ROOT / "tools" / "seeds"
RELEASE = "2026.10.0-rc.2"
BRANCH = "draft-generic-oss-fuzz-{name}"
HEADER = (
    "# Seeded by Theorem from oss-fuzz-theorems 2026.10.0-rc.2 (tools/seed.py), not enrolled by the project's\n"
    "# maintainers: provisional (STATUS.md). To adopt it, set primary_contact and remove these lines.\n"
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
    if not source:
        return None
    # The release named some targets after the project alone (its first harness), or after the harness less a suffix.
    candidates = [target for target, files in recipe_targets.items()
                  if (target == project or target.startswith(f"{project}-")) and source in files]
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
    homepage = project.get("homepage")
    if isinstance(homepage, str) and validate.is_https_url(homepage):
        seed.homepage = homepage
    elif homepage:
        seed.notes.append("homepage is not an https URL: left out")

    patches, recipe_targets = recipe if recipe else ({}, {})
    own = patches.get(series_of(seed.repo, seed.commit), [])
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


def tag_for(seed, offline):
    """The tag to name the release's commit by (v<version> or <version>), or None to name the commit itself."""
    if offline or not seed.version:
        return None
    names = [name for name in (f"v{seed.version}", seed.version)
             if validate.URL.fullmatch(f"https://x#{name}") and not validate.FULL_COMMIT.fullmatch(name)]
    if not names:
        return None
    wanted = [f"refs/tags/{name}{peel}" for name in names for peel in ("", "^{}")]
    try:
        listing = check_build.output(*check_build.git("ls-remote", "--tags", "--", seed.repo, *wanted))
    except check_build.Failed as error:
        raise SeedError(f"{seed.name}: cannot list the tags of {seed.repo}: {error}") from None
    refs = dict(reversed(line.split("\t", 1)) for line in listing.splitlines() if "\t" in line)
    for name in names:
        if (refs.get(f"refs/tags/{name}^{{}}") or refs.get(f"refs/tags/{name}")) == seed.commit:
            return name
    return None


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


def generate(name, checkout, recipe, offline):
    """(Seed, project.yaml text or None)."""
    seed = assess(name, checkout, recipe)
    if seed.reason:
        return seed, None
    ref = tag_for(seed, offline) or seed.commit
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


def make_branch(name, text, trailers, root=ROOT, seeds=SEEDS):
    """(Re)create the draft branch of one project with git plumbing. Return (branch, commit)."""
    main = git("rev-parse", "--verify", "refs/heads/main", root=root).strip()
    if git("ls-tree", main, "--", f"projects/{name}", root=root).strip():
        raise SeedError(f"projects/{name} is on main already: a draft is for a project main does not have")
    files = {"project.yaml": (text.encode(), "100644"), **seed_files(name, seeds)}
    with tempfile.TemporaryDirectory(prefix="seed-branch.") as scratch:
        scratch = pathlib.Path(scratch)
        projects = scratch / "projects"
        projects.mkdir()
        for line in git("ls-tree", "-r", "-z", main, "--", "projects", root=root).split("\0"):
            if not line:
                continue
            meta, path = line.split("\t", 1)
            mode, kind, blob = meta.split()
            if kind != "blob":
                continue
            target = scratch / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git("cat-file", "blob", blob, root=root, data=b""))
            if mode == "100755":
                target.chmod(0o755)
        draft = projects / name
        draft.mkdir()
        for file, (data, mode) in files.items():
            (draft / file).write_bytes(data)
            if mode == "100755":
                (draft / file).chmod(0o755)
        problems, _, _ = validate.check_project(draft)
        if problems:
            raise SeedError(f"{name}: the draft's projects/{name}/ breaks the rules: {'; '.join(problems)}")
        readme = projects_table.render(git("show", f"{main}:README.md", root=root), projects)

        # A scratch index: the working tree and the repository's own index are never touched.
        env = {**os.environ, "GIT_INDEX_FILE": str(scratch / "index")}
        git("read-tree", main, root=root, env=env)
        for file, (data, mode) in files.items():
            blob = git("hash-object", "-w", "--stdin", root=root, data=data).decode().strip()
            git("update-index", "--add", "--cacheinfo", f"{mode},{blob},projects/{name}/{file}", root=root, env=env)
        blob = git("hash-object", "-w", "--stdin", root=root, data=readme.encode()).decode().strip()
        git("update-index", "--add", "--cacheinfo", f"100644,{blob},README.md", root=root, env=env)
        tree = git("write-tree", root=root, env=env).strip()
    message = f"Draft: seed projects/{name} from oss-fuzz-theorems {RELEASE}\n"
    if trailers:
        message += "\n" + "\n".join(trailers) + "\n"
    commit = git("commit-tree", tree, "-p", main, "-F", "-", root=root, data=message).strip()
    branch = BRANCH.format(name=name)
    git("update-ref", f"refs/heads/{branch}", commit, root=root)
    return branch, commit


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


def check(checkout, recipe, offline, projects=validate.PROJECTS):
    """Regenerate every seeded project here and compare. Return the number that differ."""
    differing = 0
    for name, committed in seeded_here(projects).items():
        seed = assess(name, checkout, recipe)
        if seed.reason:
            print(f"{name}: can no longer be seeded: {seed.reason}", file=sys.stderr)
            differing += 1
            continue
        ref = tag_for(seed, offline)
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


def report(checkout, recipe, path):
    """Write the TSV of every project of the release: whether it can be seeded, its fuzz targets, and why."""
    rows = ["# generated by tools/seed.py from oss-fuzz-theorems 2026.10.0-rc.2; do not edit",
            "project\tseedable\tfuzz_targets\treason or notes"]
    counts = {}
    for project_file in sorted((checkout / "projects").glob("*/project.yaml")):
        seed = assess(project_file.parent.name, checkout, recipe)
        if seed.reason:
            rows.append(f"{seed.name}\tno\t-\t{seed.reason}")
            key = seed.kind or seed.reason
        else:
            rows.append(f"{seed.name}\tyes\t{','.join(seed.targets)}\t{'; '.join(seed.notes) or '-'}")
            key = "seedable"
        counts[key] = counts.get(key, 0) + 1
    pathlib.Path(path).write_text("\n".join(row.replace("\n", " ") for row in rows) + "\n", encoding="utf-8")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="projects of the release to seed")
    parser.add_argument("--from", dest="checkout", type=pathlib.Path, required=True,
                        help="a checkout of oss-fuzz-theorems at release 2026.10.0-rc.2")
    parser.add_argument("--recipe", type=pathlib.Path, help="that release's build recipe, unpacked")
    parser.add_argument("--offline", action="store_true", help="look nothing up: name each library by its commit")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check every seeded project here against the release")
    mode.add_argument("--report", type=pathlib.Path, help="write which projects can be seeded, and why, to this file")
    mode.add_argument("--branch", action="store_true", help="(re)create draft-generic-oss-fuzz-<name> for each name")
    parser.add_argument("--trailer", action="append", default=[], help="a line to end each draft commit's message with")
    parser.add_argument("--out", type=pathlib.Path, help="write NAME/project.yaml under OUT instead of projects/")
    options = parser.parse_args()

    if not (options.checkout / "projects").is_dir():
        parser.error(f"{options.checkout} has no projects/: it is not a checkout of oss-fuzz-theorems")
    if (options.check or options.report) and options.names:
        parser.error("--check and --report take no project names")
    if not (options.check or options.report) and not options.names:
        parser.error("name at least one project")
    try:
        recipe = load_recipe(options.recipe) if options.recipe else None
        if options.check:
            return 1 if check(options.checkout, recipe, options.offline) else 0
        if options.report:
            counts = report(options.checkout, recipe, options.report)
            for key, count in sorted(counts.items(), key=lambda item: -item[1]):
                print(f"{count:6}  {key}")
            return 0
        failed = 0
        for name in options.names:
            seed, text = generate(name, options.checkout, recipe, options.offline)
            if text is None:
                print(validate.printable(f"{name}: not seeded: {seed.reason}"), file=sys.stderr)
                failed += 1
                continue
            if options.branch:
                branch, commit = make_branch(name, text, options.trailer)
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


if __name__ == "__main__":
    sys.exit(main())
