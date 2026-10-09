"""
Graceful shutdown: the server drains or closes in-flight tunnels, and app.py exits 0 on SIGTERM/SIGINT.

The signal tests run app.py in a subprocess, since only a real process can show the exit code.
"""

import signal
import subprocess
import time

import pytest

from simple_socks5.constants import SHUTDOWN_GRACE_PERIOD
from tests.e2e import socks_client as sc
from tests.e2e.app_process import run_app, socks_ready


def test_close_connections_ends_open_tunnel(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"
        assert not proxy.server.wait_for_connections(0)

        assert proxy.server.close_connections() == 1

        sc.assert_closed(tunnel)
        assert proxy.server.wait_for_connections(sc.TIMEOUT)


@pytest.fixture
def app_process(tmp_path):
    """Runs app.py on a free loopback port; yields (process, address)."""
    with run_app(tmp_path) as running:
        yield running


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
        while socks_ready(address):
            assert time.monotonic() - signalled_at < 2, "app.py still accepting after SIGTERM"
            time.sleep(0.05)

        tunnel.settimeout(SHUTDOWN_GRACE_PERIOD + 1)
        try:
            sc.recv_until_eof(tunnel)
        except ConnectionResetError:
            pass

        stderr = _assert_graceful_exit(proc, signalled_at)
    assert "Closing 1 connection(s) still active after the grace period" in stderr
