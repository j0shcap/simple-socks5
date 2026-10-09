"""
Tests the logging level precedence: -L/--logging-level, then $LOGGING_LEVEL, then debug.
"""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

import pytest

from simple_socks5.argument_parser import parse_arguments


class TestLoggingLevelPrecedence(unittest.TestCase):
    def parse_error(self, argv, environ):
        """Runs parse_arguments expecting an argparse error; returns (exit code, stderr)."""
        stderr = io.StringIO()
        with redirect_stderr(stderr), pytest.raises(SystemExit) as caught:
            parse_arguments(argv, environ)
        return caught.value.code, stderr.getvalue()

    def test_flag_only(self):
        assert parse_arguments(["-L", "info"], {}).logging_level == "info"

    def test_env_only(self):
        assert parse_arguments([], {"LOGGING_LEVEL": "warning"}).logging_level == "warning"

    def test_flag_overrides_env(self):
        args = parse_arguments(["-L", "warning"], {"LOGGING_LEVEL": "debug"})
        assert args.logging_level == "warning"

    def test_neither_defaults_to_debug(self):
        assert parse_arguments([], {}).logging_level == "debug"

    def test_empty_env_is_unset(self):
        assert parse_arguments([], {"LOGGING_LEVEL": ""}).logging_level == "debug"

    def test_invalid_env_exits_2(self):
        for value in ("verbose", "INFO"):
            with self.subTest(value=value):
                code, stderr = self.parse_error([], {"LOGGING_LEVEL": value})
                assert code == 2
                assert "LOGGING_LEVEL" in stderr
                assert "invalid choice" in stderr
                assert repr(value) in stderr

    def test_invalid_env_ignored_when_flag_given(self):
        args = parse_arguments(["--logging-level", "error"], {"LOGGING_LEVEL": "verbose"})
        assert args.logging_level == "error"

    def test_invalid_flag_exits_2(self):
        code, stderr = self.parse_error(["-L", "verbose"], {})
        assert code == 2
        assert "invalid choice" in stderr

    def test_help_shows_effective_default(self):
        for environ, expected in (({}, "debug"), ({"LOGGING_LEVEL": "info"}, "info")):
            with self.subTest(environ=environ):
                stdout = io.StringIO()
                with redirect_stdout(stdout), pytest.raises(SystemExit):
                    parse_arguments(["-h"], environ)
                help_text = " ".join(stdout.getvalue().split())
                assert "$LOGGING_LEVEL" in help_text
                assert f"(default: {expected})" in help_text
                assert "None" not in help_text

    def test_other_defaults_unchanged(self):
        args = parse_arguments([], {})
        assert (args.host, args.port) == ("localhost", 1080)


if __name__ == "__main__":
    unittest.main()
