"""
Tests that main() logs the startup advisories before serving.
"""
import io
import logging
import os
import unittest
from argparse import Namespace
from contextlib import redirect_stderr
from unittest.mock import patch

from src import logger as logger_module
from src.config import ProxyConfiguration
from src.main import main
from src.startup import DEFAULT_CREDENTIALS_MESSAGE, OPEN_PROXY_BANNER

BANNER_HEADLINE = OPEN_PROXY_BANNER[1].format(host="0.0.0.0")


class TestMainStartupAdvisories(unittest.TestCase):
    def setUp(self):
        class FreshConfig(ProxyConfiguration):
            pass

        environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        patchers = [
            patch("src.main.ProxyConfiguration", FreshConfig),
            patch("src.logger.ProxyConfiguration", FreshConfig),
            patch("src.logger.RotatingFileHandler", lambda *args, **kwargs: logging.NullHandler()),
            patch.dict(os.environ, environ, clear=True),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        server_patcher = patch("src.main.ThreadingTCPServer")
        self.server_class = server_patcher.start()
        self.addCleanup(server_patcher.stop)
        self.serve_forever = self.server_class.return_value.__enter__.return_value.serve_forever

    def tearDown(self):
        for logger in logger_module._loggers.values():
            logger.handlers.clear()
            logger.addHandler(logging.NullHandler())
            logger.setLevel(logging.NOTSET)

    def run_main(self, host="0.0.0.0", logging_level="info"):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            main(Namespace(host=host, port=1080, logging_level=logging_level))
        return stderr.getvalue()

    def test_banner_logged_before_serve_forever(self):
        stderr = io.StringIO()
        logged_before_serving = []
        self.serve_forever.side_effect = lambda: logged_before_serving.append(stderr.getvalue())

        with redirect_stderr(stderr):
            main(Namespace(host="0.0.0.0", port=1080, logging_level="info"))

        self.serve_forever.assert_called_once()
        self.assertIn(BANNER_HEADLINE, logged_before_serving[0])
        self.assertIn(DEFAULT_CREDENTIALS_MESSAGE, logged_before_serving[0])

    def test_banner_visible_at_warning_level(self):
        self.assertIn(BANNER_HEADLINE, self.run_main(logging_level="warning"))

    def test_disabled_logging_prints_nothing(self):
        self.assertEqual(self.run_main(logging_level="disabled"), "")

    def test_loopback_host_logs_no_banner(self):
        output = self.run_main(host="127.0.0.1")
        self.assertNotIn("OPEN PROXY", output)
        self.assertIn(DEFAULT_CREDENTIALS_MESSAGE, output)

    def test_password_never_logged(self):
        credentials = (("myusername", "mypassword"), ("admin", "p@ss:w0rd/%s\"'{}\\ü"))
        for (username, password), auth_required in [(c, a) for c in credentials for a in ("true", "false")]:
            with self.subTest(username=username, auth_required=auth_required), \
                    patch.dict(os.environ, {"SOCKS5_AUTH_REQUIRED": auth_required}), \
                    patch("src.constants.USERNAME", username), \
                    patch("src.constants.PASSWORD", password):
                output = self.run_main(logging_level="debug")
                self.assertIn("Server started", output)
                self.assertNotIn(password, output)


if __name__ == "__main__":
    unittest.main()
