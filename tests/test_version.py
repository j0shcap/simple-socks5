"""
Keeps the two version sources in sync until the version is single-sourced, and checks what `--version` prints.
"""

import re
import subprocess
import sys
import unittest
from importlib.metadata import entry_points
from pathlib import Path

from simple_socks5.argument_parser import __version__
from simple_socks5.main import cli

ROOT = Path(__file__).resolve().parents[1]


def pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    # A regex rather than tomllib, which Python 3.10 lacks.
    project = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    version = re.search(r'^version\s*=\s*"([^"]+)"', project.group(1), re.M)
    return version.group(1)


class TestVersion(unittest.TestCase):
    def test_pyproject_version_matches_dunder_version(self):
        self.assertEqual(pyproject_version(), __version__)

    def test_cli_prints_version(self):
        result = subprocess.run(
            [sys.executable, "app.py", "--version"], cwd=ROOT, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"app.py {__version__}\n")

    def test_module_prints_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "simple_socks5", "--version"], cwd=ROOT, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # argparse's prog for -m differs across Python versions, so only the version is checked.
        self.assertTrue(result.stdout.endswith(f" {__version__}\n"), result.stdout)

    def test_console_script_points_at_cli(self):
        (script,) = entry_points(group="console_scripts", name="simple-socks5")
        self.assertIs(script.load(), cli)


if __name__ == "__main__":
    unittest.main()
