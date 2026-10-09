"""
Ensures the release tag guard only lets refs through that can never retarget the immutable 2.0.x image tags.
"""

import shutil
import subprocess
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "release-guard.sh"


def run_guard(ref_name: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv built by the test
        [shutil.which("bash"), str(GUARD), ref_name], capture_output=True, text=True, check=False
    )


class TestReleaseGuard(unittest.TestCase):
    def test_stable_release_is_accepted(self):
        for ref in ("v2.1.0", "v2.10.3", "v3.0.0"):
            with self.subTest(ref=ref):
                result = run_guard(ref)
                assert result.returncode == 0, result.stderr
                assert result.stdout == "prerelease=false\n"

    def test_prerelease_is_accepted_without_moving_floating_tags(self):
        for ref in ("v2.1.0-rc.1", "v3.0.0-beta"):
            with self.subTest(ref=ref):
                result = run_guard(ref)
                assert result.returncode == 0, result.stderr
                assert result.stdout == "prerelease=true\n"

    def test_versions_below_2_1_are_rejected(self):
        for ref in ("v2.0.0", "v2.0.1", "v2.0.0-rc.1", "v1.9.9", "v0.1.0"):
            with self.subTest(ref=ref):
                result = run_guard(ref)
                assert result.returncode == 1
                assert result.stdout == ""
                assert "2.0.0" in result.stderr

    def test_non_semver_refs_are_rejected(self):
        for ref in ("v2.1", "vfoo", "2.1.0", "v02.1.0", "v2.1.0+build", ""):
            with self.subTest(ref=ref):
                result = run_guard(ref)
                assert result.returncode == 1
                assert result.stdout == ""
