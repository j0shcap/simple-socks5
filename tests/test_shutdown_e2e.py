"""
Runs app.py in a subprocess and checks that SIGTERM and SIGINT stop it gracefully with exit code 0.
"""
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from src.constants import SHUTDOWN_GRACE_PERIOD

APP = Path(__file__).resolve().parents[1] / "app.py"
STARTUP_TIMEOUT = 10.0  # seconds


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def socks_ready(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.sendall(b"\x05\x01\x00")
            return sock.recv(2) == b"\x05\x00"
    except OSError:
        return False


def trickle_server(stop: threading.Event) -> int:
    """Starts a TCP server that sends 1 KiB every 100 ms to one client; returns its port."""
    listener = socket.create_server(("127.0.0.1", 0))

    def serve():
        with listener:
            conn, _ = listener.accept()
            with conn:
                while not stop.is_set():
                    try:
                        conn.sendall(b"x" * 1024)
                    except OSError:
                        return
                    time.sleep(0.1)

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


@unittest.skipIf(sys.platform == "win32", "POSIX signals only")
class TestShutdownEndToEnd(unittest.TestCase):
    def start_proxy(self) -> tuple[subprocess.Popen, int]:
        port = free_port()
        env = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_") and k != "LOGGING_LEVEL"}
        cwd = tempfile.TemporaryDirectory()  # The app writes errors.log to its working directory
        self.addCleanup(cwd.cleanup)
        proc = subprocess.Popen(
            [sys.executable, str(APP), "-H", "127.0.0.1", "-P", str(port), "-L", "info"],
            cwd=cwd.name,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(proc.stderr.close)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)

        deadline = time.monotonic() + STARTUP_TIMEOUT
        while not socks_ready(port):
            if proc.poll() is not None or time.monotonic() > deadline:
                self.fail(f"Proxy did not start (exit code {proc.poll()}):\n{proc.stderr.read()}")
            time.sleep(0.1)
        return proc, port

    def assert_graceful_exit(self, proc: subprocess.Popen, signalled_at: float) -> str:
        returncode = proc.wait(timeout=SHUTDOWN_GRACE_PERIOD + 1)
        elapsed = time.monotonic() - signalled_at
        stderr = proc.stderr.read()
        self.assertEqual(returncode, 0, stderr)
        self.assertLess(elapsed, SHUTDOWN_GRACE_PERIOD + 1)
        self.assertIn("Server shutting down...", stderr)
        self.assertIn("Server terminated.", stderr)
        return stderr

    def test_sigterm_idle_exits_zero(self):
        proc, _ = self.start_proxy()
        proc.send_signal(signal.SIGTERM)
        self.assert_graceful_exit(proc, time.monotonic())

    def test_sigint_idle_exits_zero(self):
        proc, _ = self.start_proxy()
        proc.send_signal(signal.SIGINT)
        stderr = self.assert_graceful_exit(proc, time.monotonic())
        self.assertNotIn("KeyboardInterrupt", stderr)

    def test_sigterm_active_download_closes_client_and_exits_zero(self):
        proc, port = self.start_proxy()
        stop = threading.Event()
        self.addCleanup(stop.set)
        target_port = trickle_server(stop)

        client = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.addCleanup(client.close)
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(client.recv(2), b"\x05\x00")
        client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + target_port.to_bytes(2, "big"))
        self.assertEqual(client.recv(10)[:2], b"\x05\x00")
        self.assertTrue(client.recv(1024))  # The relay is flowing

        proc.send_signal(signal.SIGTERM)
        signalled_at = time.monotonic()

        # The listener closes once serve_forever() returns, well before the grace period ends.
        while socks_ready(port):
            self.assertLess(time.monotonic() - signalled_at, 2, "proxy still accepting after SIGTERM")
            time.sleep(0.05)

        try:
            while client.recv(65536):
                pass
        except ConnectionResetError:
            pass

        stderr = self.assert_graceful_exit(proc, signalled_at)
        self.assertIn("Closing 1 connection(s) still active after the grace period", stderr)


if __name__ == "__main__":
    unittest.main()
