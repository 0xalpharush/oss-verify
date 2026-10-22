# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The oss-fuzz-theorems release that tools/seed.py, tools/port.py and tools/verify_ports.py follow.

TAG is the only place in this repository that pins the release's tag. To follow another release, change TAG, and
give the tools a checkout of that release. A checkout of this one is not public: what the tools wrote from it is in
tools/seeds/ and docs/seeded-projects.tsv. oss-verify-proofs is not such a checkout, although its release.yaml names
the same release. Text names the release as NAME.
"""
import pathlib

import yaml

TAG = "v2026.10.0-rc.2"
NAME = "the oss-fuzz-theorems 2026.10 release"


def check(checkout):
    """Exit if `checkout` is a checkout of another release than TAG: its release.yaml names another release."""
    path = pathlib.Path(checkout) / "release.yaml"
    if not path.is_file():
        return
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"cannot read {path}: {error}") from None
    found = data.get("release") if isinstance(data, dict) else None
    if f"v{found}" != TAG:
        raise SystemExit(f"{checkout} is a checkout of another release than the one tools/release_tag.py names")
