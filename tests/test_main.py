"""
Tests that main() logs the startup advisories before serving, and shuts down gracefully on a signal.
"""

import io
import os
import signal
import socket
import subprocess
import sys
import threading
import unittest
from argparse import Namespace
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from simple_socks5.config import ProxyConfiguration
from simple_socks5.constants import SHUTDOWN_FORCE_CLOSE_TIMEOUT, SHUTDOWN_GRACE_PERIOD
from simple_socks5.main import GracefulShutdown, cli, main
from simple_socks5.startup import DEFAULT_CREDENTIALS_MESSAGE, OPEN_PROXY_BANNER

ROOT = Path(__file__).resolve().parents[1]
BANNER_HEADLINE = OPEN_PROXY_BANNER[1].format(host="0.0.0.0")


class TestMainStartupAdvisories(unittest.TestCase):
    def setUp(self):
        class FreshConfig(ProxyConfiguration):
            pass

        environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        patchers = [
            patch("simple_socks5.main.ProxyConfiguration", FreshConfig),
            patch("simple_socks5.logger.ProxyConfiguration", FreshConfig),
            patch.dict(os.environ, environ, clear=True),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        server_patcher = patch("simple_socks5.main.ThreadingTCPServer")
        self.server_class = server_patcher.start()
        self.addCleanup(server_patcher.stop)
        self.serve_forever = self.server_class.return_value.__enter__.return_value.serve_forever

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
        assert BANNER_HEADLINE in logged_before_serving[0]
        assert DEFAULT_CREDENTIALS_MESSAGE in logged_before_serving[0]

    def test_banner_visible_at_warning_level(self):
        assert BANNER_HEADLINE in self.run_main(logging_level="warning")

    def test_disabled_logging_prints_nothing(self):
        assert self.run_main(logging_level="disabled") == ""

    def test_loopback_host_logs_no_banner(self):
        output = self.run_main(host="127.0.0.1")
        assert "OPEN PROXY" not in output
        assert DEFAULT_CREDENTIALS_MESSAGE in output

    def test_password_never_logged(self):
        credentials = (("myusername", "mypassword"), ("admin", "p@ss:w0rd/%s\"'{}\\ü"))
        for (username, password), auth_required in [(c, a) for c in credentials for a in ("true", "false")]:
            with (
                self.subTest(username=username, auth_required=auth_required),
                patch.dict(
                    os.environ,
                    {"SOCKS5_AUTH_REQUIRED": auth_required, "SOCKS5_USERNAME": username, "SOCKS5_PASSWORD": password},
                ),
            ):
                output = self.run_main(logging_level="debug")
                assert "Server started" in output
                assert password not in output

    def test_signal_during_serve_forever_logs_shutdown_and_returns(self):
        server = self.server_class.return_value.__enter__.return_value
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum.name):
                shutdown_called = threading.Event()
                server.shutdown.side_effect = shutdown_called.set
                self.serve_forever.side_effect = lambda s=signum: signal.getsignal(s)(s, None)

                output = self.run_main()

                assert "Server shutting down..." in output
                assert "Server terminated." in output
                assert shutdown_called.wait(5)
                server.server_close.assert_called()

    def test_signal_handlers_restored_after_main(self):
        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        self.run_main()
        assert {signum: signal.getsignal(signum) for signum in previous} == previous

    def test_startup_failure_exits_1(self):
        self.server_class.side_effect = OSError("Address already in use")
        with pytest.raises(SystemExit) as caught:
            self.run_main()
        assert caught.value.code == 1

    def test_main_exits_on_invalid_handshake_timeout(self):
        with patch.dict(os.environ, {"SOCKS5_HANDSHAKE_TIMEOUT": "abc"}), pytest.raises(SystemExit) as caught:
            self.run_main()
        assert caught.value.code not in (0, None)
        assert "SOCKS5_HANDSHAKE_TIMEOUT" in str(caught.value.code)
        self.server_class.assert_not_called()

    def test_invalid_max_connections_exits_with_message(self):
        for raw in ("0", "abc"):
            with (
                self.subTest(raw=raw),
                patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": raw}),
                pytest.raises(SystemExit) as caught,
            ):
                self.run_main(logging_level="disabled")
            assert (
                caught.value.code
                == f"Invalid configuration: SOCKS5_MAX_CONNECTIONS must be a positive integer, got '{raw}'"
            )
            self.server_class.assert_not_called()


class FakeClock:
    def __init__(self, now=100.0):
        self.now = now

    def __call__(self):
        return self.now


class TestGracefulShutdown(unittest.TestCase):
    def setUp(self):
        self.server = MagicMock()
        self.server.wait_for_connections.return_value = True
        self.clock = FakeClock()
        self.shutdown = GracefulShutdown(self.server, grace=SHUTDOWN_GRACE_PERIOD, clock=self.clock)

    def wait_timeouts(self):
        return [c.args[0] for c in self.server.wait_for_connections.call_args_list]

    def test_handler_calls_shutdown_off_thread(self):
        release, called = threading.Event(), threading.Event()
        shutdown_threads = []

        def blocking_shutdown():
            shutdown_threads.append(threading.current_thread())
            called.set()
            release.wait(5)

        self.server.shutdown.side_effect = blocking_shutdown
        self.shutdown._handle(signal.SIGTERM, None)  # Returns while shutdown() is still blocked
        assert called.wait(5)
        release.set()
        assert shutdown_threads[0] is not threading.current_thread()

    def test_second_signal_is_ignored(self):
        self.shutdown._handle(signal.SIGTERM, None)
        self.clock.now += 3
        self.shutdown._handle(signal.SIGINT, None)
        self.shutdown.drain()

        self.server.shutdown.assert_called_once()
        assert self.wait_timeouts() == [SHUTDOWN_GRACE_PERIOD - 3 - SHUTDOWN_FORCE_CLOSE_TIMEOUT]

    def test_drain_idle_does_not_force_close(self):
        self.shutdown._handle(signal.SIGTERM, None)
        self.shutdown.drain()

        assert self.wait_timeouts() == [SHUTDOWN_GRACE_PERIOD - SHUTDOWN_FORCE_CLOSE_TIMEOUT]
        self.server.close_connections.assert_not_called()

    def test_drain_stuck_connections_force_closes_once(self):
        self.shutdown._handle(signal.SIGTERM, None)
        self.clock.now += 1

        def time_out(timeout):
            self.clock.now += timeout
            return False

        self.server.wait_for_connections.side_effect = time_out
        self.shutdown.drain()

        self.server.close_connections.assert_called_once()
        first_wait = SHUTDOWN_GRACE_PERIOD - 1 - SHUTDOWN_FORCE_CLOSE_TIMEOUT
        assert self.wait_timeouts() == [first_wait, SHUTDOWN_FORCE_CLOSE_TIMEOUT]

    def test_drain_never_waits_a_negative_timeout(self):
        self.shutdown._handle(signal.SIGTERM, None)
        self.clock.now += SHUTDOWN_GRACE_PERIOD + 1
        self.server.wait_for_connections.return_value = False
        self.shutdown.drain()

        assert self.wait_timeouts() == [0, 0]

    def test_drain_without_signal_uses_grace_from_now(self):
        self.shutdown.drain()

        assert self.wait_timeouts() == [SHUTDOWN_GRACE_PERIOD - SHUTDOWN_FORCE_CLOSE_TIMEOUT]

    def test_restore_reinstalls_previous_handlers(self):
        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        self.shutdown.install()
        try:
            for signum in previous:
                assert signal.getsignal(signum) == self.shutdown._handle
        finally:
            self.shutdown.restore()
        assert {signum: signal.getsignal(signum) for signum in previous} == previous


class TestCli(unittest.TestCase):
    def test_cli_passes_parsed_arguments_to_main(self):
        with patch("simple_socks5.main.main") as main_mock:
            cli(["-H", "0.0.0.0", "-P", "1081", "-L", "info"])
        main_mock.assert_called_once_with(Namespace(host="0.0.0.0", port=1081, logging_level="info"))

    def test_startup_failure_exits_1_without_site(self):
        # python -S skips the site module, which is what defines the exit() builtin.
        env = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        env["PYTHONPATH"] = str(ROOT / "src")
        with socket.socket() as taken:
            taken.bind(("127.0.0.1", 0))
            taken.listen()
            port = taken.getsockname()[1]
            result = subprocess.run(  # noqa: S603 - fixed argv built by the test
                [sys.executable, "-S", "-m", "simple_socks5", "-H", "127.0.0.1", "-P", str(port)],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        assert result.returncode == 1, result.stderr
        assert "Error starting server" in result.stdout + result.stderr
        assert "NameError" not in result.stderr


if __name__ == "__main__":
    unittest.main()
