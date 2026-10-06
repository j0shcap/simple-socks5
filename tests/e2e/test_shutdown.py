"""
Graceful shutdown: the server drains or closes in-flight tunnels, and app.py exits 0 on SIGTERM/SIGINT.

The signal tests run app.py in a subprocess, since only a real process can show the exit code.
"""
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from src.constants import SHUTDOWN_GRACE_PERIOD
from tests.e2e import socks_client as sc

APP = Path(__file__).resolve().parents[2] / "app.py"
STARTUP_TIMEOUT = 10.0  # seconds


def test_close_connections_ends_open_tunnel(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"
        assert not proxy.server.wait_for_connections(0)

        assert proxy.server.close_connections() == 1

        sc.assert_closed(tunnel)
        assert proxy.server.wait_for_connections(sc.TIMEOUT)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _socks_ready(address: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(address, timeout=1) as sock:
            return sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
    except (OSError, EOFError):
        return False


@pytest.fixture
def app_process(tmp_path):
    """Runs app.py on a free loopback port; yields (process, address)."""
    if sys.platform == "win32":
        pytest.skip("POSIX signals only")
    address = ("127.0.0.1", _free_port())
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_") and k != "LOGGING_LEVEL"}
    proc = subprocess.Popen(
        [sys.executable, str(APP), "-H", address[0], "-P", str(address[1]), "-L", "info"],
        cwd=tmp_path,  # The app writes errors.log to its working directory
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while not _socks_ready(address):
            if proc.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"app.py did not start (exit code {proc.poll()}):\n{proc.stderr.read()}")
            time.sleep(0.1)
        yield proc, address
    finally:
        proc.kill()
        proc.wait()
        proc.stderr.close()


def _assert_graceful_exit(proc: subprocess.Popen, signalled_at: float) -> str:
    returncode = proc.wait(timeout=SHUTDOWN_GRACE_PERIOD + 1)
    elapsed = time.monotonic() - signalled_at
    stderr = proc.stderr.read()
    assert returncode == 0, stderr
    assert elapsed < SHUTDOWN_GRACE_PERIOD + 1
    assert "Server shutting down..." in stderr
    assert "Server terminated." in stderr
    assert "KeyboardInterrupt" not in stderr
    return stderr


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT], ids=["SIGTERM", "SIGINT"])
def test_signal_idle_exits_zero(app_process, signum):
    proc, _ = app_process
    proc.send_signal(signum)
    _assert_graceful_exit(proc, time.monotonic())


def test_sigterm_active_download_closes_client_and_exits_zero(app_process, trickle_origin):
    proc, address = app_process
    with sc.open_tunnel(address, "127.0.0.1", trickle_origin.port) as tunnel:
        assert tunnel.recv(1024)  # The relay is flowing

        proc.send_signal(signal.SIGTERM)
        signalled_at = time.monotonic()

        # The listener closes once serve_forever() returns, well before the grace period ends.
        while _socks_ready(address):
            assert time.monotonic() - signalled_at < 2, "app.py still accepting after SIGTERM"
            time.sleep(0.05)

        tunnel.settimeout(SHUTDOWN_GRACE_PERIOD + 1)
        try:
            sc.recv_until_eof(tunnel)
        except ConnectionResetError:
            pass

        stderr = _assert_graceful_exit(proc, signalled_at)
    assert "Closing 1 connection(s) still active after the grace period" in stderr
