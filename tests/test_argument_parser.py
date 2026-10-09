"""
Tests the logging level precedence: -L/--logging-level, then $LOGGING_LEVEL, then debug.
"""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from simple_socks5.argument_parser import parse_arguments


class TestLoggingLevelPrecedence(unittest.TestCase):
    def parse_error(self, argv, environ):
        """Runs parse_arguments expecting an argparse error; returns (exit code, stderr)."""
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            parse_arguments(argv, environ)
        return caught.exception.code, stderr.getvalue()

    def test_flag_only(self):
        self.assertEqual(parse_arguments(["-L", "info"], {}).logging_level, "info")

    def test_env_only(self):
        self.assertEqual(parse_arguments([], {"LOGGING_LEVEL": "warning"}).logging_level, "warning")

    def test_flag_overrides_env(self):
        args = parse_arguments(["-L", "warning"], {"LOGGING_LEVEL": "debug"})
        self.assertEqual(args.logging_level, "warning")

    def test_neither_defaults_to_debug(self):
        self.assertEqual(parse_arguments([], {}).logging_level, "debug")

    def test_empty_env_is_unset(self):
        self.assertEqual(parse_arguments([], {"LOGGING_LEVEL": ""}).logging_level, "debug")

    def test_invalid_env_exits_2(self):
        for value in ("verbose", "INFO"):
            with self.subTest(value=value):
                code, stderr = self.parse_error([], {"LOGGING_LEVEL": value})
                self.assertEqual(code, 2)
                self.assertIn("LOGGING_LEVEL", stderr)
                self.assertIn("invalid choice", stderr)
                self.assertIn(repr(value), stderr)

    def test_invalid_env_ignored_when_flag_given(self):
        args = parse_arguments(["--logging-level", "error"], {"LOGGING_LEVEL": "verbose"})
        self.assertEqual(args.logging_level, "error")

    def test_invalid_flag_exits_2(self):
        code, stderr = self.parse_error(["-L", "verbose"], {})
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", stderr)

    def test_help_shows_effective_default(self):
        for environ, expected in (({}, "debug"), ({"LOGGING_LEVEL": "info"}, "info")):
            with self.subTest(environ=environ):
                stdout = io.StringIO()
                with redirect_stdout(stdout), self.assertRaises(SystemExit):
                    parse_arguments(["-h"], environ)
                help_text = " ".join(stdout.getvalue().split())
                self.assertIn("$LOGGING_LEVEL", help_text)
                self.assertIn(f"(default: {expected})", help_text)
                self.assertNotIn("None", help_text)

    def test_other_defaults_unchanged(self):
        args = parse_arguments([], {})
        self.assertEqual((args.host, args.port), ("localhost", 1080))


if __name__ == "__main__":
    unittest.main()
