#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""gen-shim.py: make a buildable static library crate from one cargo-fuzz [[bin]].

    gen-shim.py --src SRC --fuzz-dir fuzz --bin NAME --out SHIMDIR --rt RTDIR [--profile-env "K=V ..."]

rustc does not make a static library from a [[bin]], and a cargo-fuzz package is a set of bins. So for one bin this
writes a package whose [lib] is a static library. The root of the library is a copy of the bin's own source, next to
the original, so that its modules and includes resolve as before. The copy has two changes:

  * the `#![no_main]` lines are removed;
  * a last line links the Rust half of the adapter (RTDIR): `extern crate oft_rust_rt as _;`.

The dependencies are those of the fuzz package's Cargo.toml (workspace inheritance resolved, relative paths made
absolute), plus the fuzz package itself if it has a [lib], plus the adapter. The package is a workspace of its own.
Its [profile.release] is the one cargo would use for the fuzz package (the workspace root's, if the fuzz package is
a member of a workspace), less debug information, with panic = "abort", and with the CARGO_PROFILE_RELEASE_* settings
of --profile-env applied over it.

SRC must be a scratch copy of the source tree (it holds a .oft-scratch-copy file), as this writes into it.

Writes SHIMDIR/Cargo.toml, the library root, and SHIMDIR/shim.json (what was made from what). Exit status 3 means the
bin has a shape that this does not handle; the message says which.

From the build recipe of the oss-fuzz-theorems 2026.10 release, in its release mode. The code that decides what is
written is unchanged but for the names of the two packages (SHIM_PACKAGE, RT_PACKAGE), which the release spelled with an
internal name. Cargo hashes a package's name into the metadata of each crate, so the binaries differ from the release's.
The comments are new, and its other modes are left out.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tomllib

MARKER = '.oft-scratch-copy'
# The package names of the library and of the adapter, as each project's Cargo.lock records them.
SHIM_PACKAGE = 'oft-rust-shim'
RT_PACKAGE = 'oft-rust-rt'


def refuse(cls, msg):
    print(f'gen-shim: REFUSED({cls}): {msg}', file=sys.stderr)
    sys.exit(3)


def toml_value(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return '[' + ', '.join(toml_value(x) for x in v) + ']'
    if isinstance(v, dict):
        return '{ ' + ', '.join(f'{json.dumps(k)} = {toml_value(x)}' for k, x in v.items()) + ' }'
    raise SystemExit(f'gen-shim: cannot serialise {v!r}')


def load(p):
    with open(p, 'rb') as f:
        return tomllib.load(f)


def find_workspace_root(fuzz_dir, fuzz_toml):
    """(directory, Cargo.toml, whether the fuzz package is a member) of the workspace that owns the fuzz package."""
    if 'workspace' in fuzz_toml:
        return fuzz_dir, fuzz_toml, False
    d = os.path.dirname(fuzz_dir)
    while True:
        p = os.path.join(d, 'Cargo.toml')
        if os.path.isfile(p):
            t = load(p)
            if 'workspace' in t:
                rel = os.path.relpath(fuzz_dir, d)
                ws = t['workspace']
                excluded = any(rel == e or rel.startswith(e.rstrip('/') + '/') for e in ws.get('exclude', []))
                return d, t, not excluded
        nd = os.path.dirname(d)
        if nd == d:
            return None, None, False
        d = nd


def absolutise(spec, base):
    if isinstance(spec, dict) and 'path' in spec:
        spec = dict(spec)
        spec['path'] = os.path.normpath(os.path.join(base, spec['path']))
    return spec


def resolve_dep(name, spec, fuzz_dir, ws_dir, ws_toml):
    if isinstance(spec, dict) and spec.get('workspace') is True:
        if ws_toml is None:
            refuse('workspace-dep-unresolved', f'{name} says workspace = true but no workspace root was found')
        base = ws_toml.get('workspace', {}).get('dependencies', {}).get(name)
        if base is None:
            refuse('workspace-dep-unresolved', f'{name} is not in [workspace.dependencies]')
        base = {'version': base} if isinstance(base, str) else dict(base)
        base = absolutise(base, ws_dir)
        extra = {k: v for k, v in spec.items() if k != 'workspace'}
        if 'features' in extra:
            base['features'] = sorted(set(base.get('features', [])) | set(extra.pop('features')))
        base.update(extra)
        return base
    return absolutise(spec, fuzz_dir)


def inherited(pkg, key, ws_toml, default=None):
    v = pkg.get(key, default)
    if isinstance(v, dict) and v.get('workspace'):
        v = (ws_toml or {}).get('workspace', {}).get('package', {}).get(key, default)
    return v


PROFILE_ENV_PREFIX = 'CARGO_PROFILE_RELEASE_'
PROFILE_ENV_DROPPED = ('debug', 'split-debuginfo')


def parse_profile_env(text):
    """'CARGO_PROFILE_RELEASE_LTO=false K=V ...' -> [(profile key, TOML value)], in order. Refuses a setting that it
    cannot apply as cargo would."""
    out = []
    for word in (text or '').split():
        if '=' not in word:
            refuse('profile-env-unparsed', f'{word!r} is not KEY=VALUE')
        k, v = word.split('=', 1)
        if not re.fullmatch(PROFILE_ENV_PREFIX + r'[A-Z][A-Z0-9_]*', k) or k.startswith(PROFILE_ENV_PREFIX + 'PACKAGE_'):
            refuse('profile-env-unparsed', f'{k} is not a CARGO_PROFILE_RELEASE_<KEY> setting this shim applies')
        key = k[len(PROFILE_ENV_PREFIX):].lower().replace('_', '-')
        if key == 'panic':
            refuse('profile-env-panic', f'{k}={v}: the build sets its own panic strategy (abort)')
        if v in ('true', 'false'):
            val = v == 'true'
        elif re.fullmatch(r'-?[0-9]+', v):
            val = int(v)
        elif re.fullmatch(r'[A-Za-z0-9._-]+', v):
            val = v
        else:
            refuse('profile-env-unparsed', f'{k}={v!r}: not a plain TOML scalar')
        out.append((key, val))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', required=True)
    ap.add_argument('--fuzz-dir', default='fuzz')
    ap.add_argument('--bin', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--rt', required=True)
    ap.add_argument('--profile-env', default='')
    a = ap.parse_args()
    profile_env = parse_profile_env(a.profile_env)

    if not os.path.isfile(os.path.join(a.src, MARKER)):
        raise SystemExit(f'gen-shim: {a.src} has no {MARKER} file: this writes into the tree, so give it a scratch '
                         'copy, never the checkout')

    fuzz_dir = os.path.normpath(os.path.join(a.src, a.fuzz_dir))
    ftoml_path = os.path.join(fuzz_dir, 'Cargo.toml')
    if not os.path.isfile(ftoml_path):
        refuse('no-fuzz-package', f'{ftoml_path} does not exist')
    ft = load(ftoml_path)
    ws_dir, ws_toml, fuzz_is_member = find_workspace_root(fuzz_dir, ft)

    bins = [b for b in ft.get('bin', []) if b.get('name') == a.bin]
    if len(bins) != 1:
        refuse('no-such-bin', f'{len(bins)} [[bin]] named {a.bin} in {ftoml_path}')
    b0 = bins[0]
    bin_path = os.path.join(fuzz_dir, b0.get('path', f'fuzz_targets/{a.bin}.rs'))
    if not os.path.isfile(bin_path):
        refuse('no-such-bin', f'{bin_path} does not exist')
    with open(bin_path, encoding='utf-8') as f:
        text = f.read()
    if os.path.isfile(os.path.join(fuzz_dir, 'build.rs')) or 'build' in ft.get('package', {}):
        refuse('fuzz-package-build-script', 'the fuzz package has its own build script, which the shim does not carry')
    if 'replace' in ft or (ws_toml and 'replace' in ws_toml):
        refuse('cargo-replace', '[replace] is not carried by the shim')

    n_nomain = len(re.findall(r'^[ \t]*#!\[no_main\][ \t]*$', text, flags=re.M))
    if 'fuzz_target!' not in text:
        refuse('no-fuzz-target-macro', f'{bin_path} has no fuzz_target!: not the cargo-fuzz shape this handles')
    body = re.sub(r'^[ \t]*#!\[no_main\][ \t]*\n', '', text, flags=re.M)
    body = body.rstrip('\n') + '\n'
    body += '\n// link the adapter\'s Rust half (gen-shim.py)\nextern crate oft_rust_rt as _;\n'
    root = os.path.join(os.path.dirname(bin_path), f'oft_shim_{a.bin}.rs')
    with open(root, 'w', encoding='utf-8') as f:
        f.write(body)

    pkg = ft.get('package', {})
    edition = inherited(pkg, 'edition', ws_toml, '2015')

    deps = {}
    for name, spec in ft.get('dependencies', {}).items():
        deps[name] = resolve_dep(name, spec, fuzz_dir, ws_dir, ws_toml)
    target_deps = {}
    for cfg, tbl in ft.get('target', {}).items():
        for name, spec in tbl.get('dependencies', {}).items():
            target_deps.setdefault(cfg, {})[name] = resolve_dep(name, spec, fuzz_dir, ws_dir, ws_toml)
    has_lib = 'lib' in ft or os.path.isfile(os.path.join(fuzz_dir, 'src', 'lib.rs'))
    if has_lib:
        deps[pkg['name']] = {'path': fuzz_dir}
    if RT_PACKAGE in deps:
        refuse('dep-name-collision', f'the project already has a dependency named {RT_PACKAGE}')
    deps[RT_PACKAGE] = {'path': a.rt}

    patches = {}
    for src_toml, base in ((ws_toml, ws_dir), (ft, fuzz_dir)):
        if not src_toml:
            continue
        for reg, tbl in src_toml.get('patch', {}).items():
            for name, spec in tbl.items():
                patches.setdefault(reg, {})[name] = absolutise(spec, base)

    prof_src = ws_toml if (fuzz_is_member and ws_toml) else ft
    prof_from = os.path.join(ws_dir, 'Cargo.toml') if (fuzz_is_member and ws_toml) else ftoml_path
    prof = dict(prof_src.get('profile', {}).get('release', {}))
    # Per-package overrides are kept; debug information is not (the binaries are stripped); panic is abort.
    prof.pop('debug', None)
    prof.pop('split-debuginfo', None)
    applied = []
    for key, val in profile_env:
        if key in PROFILE_ENV_DROPPED:
            continue
        prof[key] = val
        applied.append(f'{key} = {toml_value(val)}')
    prof['panic'] = 'abort'
    prof['debug'] = False

    os.makedirs(a.out, exist_ok=True)
    out = [f'# Generated by gen-shim.py from {os.path.relpath(ftoml_path, a.src)} [[bin]] {a.bin}.',
           '[package]', f'name = "{SHIM_PACKAGE}"', 'version = "0.0.0"',
           f'edition = {json.dumps(edition)}', 'publish = false',
           'autobins = false', 'autoexamples = false', 'autotests = false', 'autobenches = false', '']
    out += ['[lib]', 'name = "oft"', 'crate-type = ["staticlib"]', f'path = {json.dumps(root)}',
            'test = false', 'doctest = false', '']
    out.append('[dependencies]')
    for name, spec in deps.items():
        out.append(f'{json.dumps(name)} = {toml_value(spec)}')
    for cfg, tbl in target_deps.items():
        out += ['', f'[target.{json.dumps(cfg)}.dependencies]']
        for name, spec in tbl.items():
            out.append(f'{json.dumps(name)} = {toml_value(spec)}')
    if 'features' in ft:
        out += ['', '[features]']
        for k, v in ft['features'].items():
            out.append(f'{json.dumps(k)} = {toml_value(v)}')
    for reg, tbl in patches.items():
        out += ['', f'[patch.{json.dumps(reg)}]']
        for name, spec in tbl.items():
            out.append(f'{json.dumps(name)} = {toml_value(spec)}')
    pkg_over = prof.pop('package', None)
    out += ['', '[profile.release]']
    for k, v in prof.items():
        out.append(f'{k} = {toml_value(v)}')
    if pkg_over:
        for pname, pv in pkg_over.items():
            out += ['', f'[profile.release.package.{json.dumps(pname)}]']
            for k, v in pv.items():
                out.append(f'{k} = {toml_value(v)}')
    out += ['', '[workspace]']
    with open(os.path.join(a.out, 'Cargo.toml'), 'w') as f:
        f.write('\n'.join(out) + '\n')

    rel = lambda p: os.path.relpath(p, a.src) if p else None
    rec = {
        'fuzz_toml': rel(ftoml_path), 'bin': a.bin, 'bin_source': rel(bin_path),
        'bin_source_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'generated_root': rel(root), 'no_main_lines': n_nomain,
        'workspace_root': rel(ws_dir), 'fuzz_is_workspace_member': fuzz_is_member,
        'edition': edition, 'fuzz_pkg_has_lib': has_lib,
        'required_features': b0.get('required-features', []),
        'deps': sorted(deps), 'target_dep_cfgs': sorted(target_deps),
        'patches': {k: sorted(v) for k, v in patches.items()},
        'profile_release_from': rel(prof_from), 'profile_release': prof,
        'profile_env': a.profile_env.split(), 'profile_env_applied': applied,
        'project_lock': rel(next((c for c in (os.path.join(fuzz_dir, 'Cargo.lock'),
                                               os.path.join(ws_dir or fuzz_dir, 'Cargo.lock'))
                                  if os.path.isfile(c)), None)),
    }
    with open(os.path.join(a.out, 'shim.json'), 'w') as f:
        json.dump(rec, f, indent=1, sort_keys=True)
    print(json.dumps(rec, sort_keys=True))


if __name__ == '__main__':
    sys.exit(main())
