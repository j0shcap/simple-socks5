"""
Keeps the README environment-variable table and the CHANGELOG in step with the code.
"""

import re
import unittest
from pathlib import Path

from simple_socks5.argument_parser import __version__

ROOT = Path(__file__).resolve().parents[1]
ENV_VAR = r"SOCKS5_[A-Z_]+|LOGGING_LEVEL"


def readme_env_vars() -> set[str]:
    readme = (ROOT / "README.md").read_text()
    section = readme.split("### Environment variables", 1)[1].split("\n#", 1)[0]
    return set(re.findall(rf"^\| `({ENV_VAR})` \|", section, re.M))


def src_env_vars() -> set[str]:
    return {
        name
        for path in (ROOT / "src" / "simple_socks5").rglob("*.py")
        for name in re.findall(rf'"({ENV_VAR})"', path.read_text())
    }


class TestReadme(unittest.TestCase):
    def test_readme_env_table_matches_src(self):
        documented, used = readme_env_vars(), src_env_vars()
        self.assertTrue(documented)
        self.assertTrue(used)
        self.assertEqual(documented, used)


class TestChangelog(unittest.TestCase):
    def setUp(self):
        self.changelog = (ROOT / "CHANGELOG.md").read_text()

    def test_has_dated_section_for_current_version(self):
        self.assertRegex(self.changelog, rf"(?m)^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$")

    def test_unreleased_is_first_section(self):
        first_section = re.search(r"^## .*$", self.changelog, re.M).group(0)
        self.assertEqual(first_section, "## [Unreleased]")


if __name__ == "__main__":
    unittest.main()
