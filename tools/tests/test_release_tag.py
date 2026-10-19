# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/release_tag.py:  python3 -m unittest discover -s tools/tests"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import release_tag  # noqa: E402


class Check(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.checkout = pathlib.Path(self.scratch.name)

    def test_the_release_that_tag_names(self):
        (self.checkout / "release.yaml").write_text(f"release: {release_tag.TAG[1:]}\n")
        release_tag.check(self.checkout)

    def test_another_release(self):
        (self.checkout / "release.yaml").write_text("release: 1999.01.0\n")
        with self.assertRaises(SystemExit):
            release_tag.check(self.checkout)

    def test_a_checkout_with_no_release_yaml(self):
        release_tag.check(self.checkout)

    def test_the_name_has_no_tag(self):
        self.assertNotIn(release_tag.TAG[1:], release_tag.NAME)


if __name__ == "__main__":
    unittest.main()
