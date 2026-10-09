"""
Checks that __version__ comes from the installed package metadata, which pip takes from pyproject.toml, and what
`--version` prints.
"""

import importlib
import re
import subprocess
import sys
import unittest
from importlib.metadata import PackageNotFoundError, entry_points, version
from pathlib import Path
from unittest.mock import patch

from simple_socks5 import argument_parser
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
    def test_installed_version_matches_pyproject(self):
        # Fails after a version bump until `pip install -e .` is rerun.
        assert version("simple-socks5") == pyproject_version()
        assert __version__ == version("simple-socks5")

    def test_version_falls_back_when_not_installed(self):
        try:
            with patch("importlib.metadata.version", side_effect=PackageNotFoundError("simple-socks5")):
                importlib.reload(argument_parser)
            assert argument_parser.__version__ == "0+unknown"
        finally:
            importlib.reload(argument_parser)

    def test_cli_prints_version(self):
        result = subprocess.run([sys.executable, "app.py", "--version"], cwd=ROOT, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout == f"app.py {__version__}\n"

    def test_module_prints_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "simple_socks5", "--version"], cwd=ROOT, capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        # argparse's prog for -m differs across Python versions, so only the version is checked.
        assert result.stdout.endswith(f" {__version__}\n"), result.stdout

    def test_console_script_points_at_cli(self):
        (script,) = entry_points(group="console_scripts", name="simple-socks5")
        assert script.load() is cli


if __name__ == "__main__":
    unittest.main()
