"""
python -m simple_socks5.healthcheck: healthy (exit 0) when a SOCKS5 server answers the greeting, else unhealthy
(exit 1).
"""

import logging
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from simple_socks5 import healthcheck
from tests.e2e.app_process import free_port
from tests.e2e.conftest import MakeProxy, ProxyHandle

REPO_ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def one_shot_server(reply: bytes) -> Iterator[int]:
    """Accepts one connection, reads the greeting, sends reply and closes. Yields the port."""
    with socket.create_server(("127.0.0.1", 0)) as server:

        def serve() -> None:
            conn, _ = server.accept()
            with conn:
                conn.recv(16)
                conn.sendall(reply)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield server.getsockname()[1]
        finally:
            thread.join(5)


def run_module(port: int) -> subprocess.CompletedProcess[str]:
    env = {"PATH": "", "SOCKS5_HEALTHCHECK_PORT": str(port)}
    return subprocess.run(
        [sys.executable, "-m", "simple_socks5.healthcheck"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


@pytest.mark.parametrize("auth_required", [False, True], ids=["auth_off", "auth_on"])
def test_ten_probes_log_nothing_above_debug(
    make_proxy: MakeProxy, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, auth_required: bool
) -> None:
    proxy = make_proxy(auth_required=auth_required)
    monkeypatch.setenv("SOCKS5_HEALTHCHECK_PORT", str(proxy.address[1]))
    caplog.set_level(logging.DEBUG, logger="simple_socks5")

    assert [healthcheck.main() for _ in range(10)] == [0] * 10
    assert proxy.server.wait_for_connections(5)

    assert [r for r in caplog.records if r.levelno > logging.DEBUG or r.exc_info] == []


def test_module_exit_codes(proxy: ProxyHandle) -> None:
    healthy = run_module(proxy.address[1])
    assert (healthy.returncode, healthy.stdout, healthy.stderr) == (0, "", "")
    assert proxy.server.wait_for_connections(5)

    unhealthy = run_module(free_port())
    assert unhealthy.returncode == 1
    assert unhealthy.stdout == ""
    assert len(unhealthy.stderr.splitlines()) == 1
    assert unhealthy.stderr.startswith("unhealthy: ")


@pytest.mark.parametrize("reply", [b"", b"\x05", b"HTTP/1.0 400 Bad Request\r\n\r\n"], ids=["closed", "short", "http"])
def test_unhealthy_without_a_socks5_reply(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], reply: bytes
) -> None:
    with one_shot_server(reply) as port:
        monkeypatch.setenv("SOCKS5_HEALTHCHECK_PORT", str(port))
        assert healthcheck.main() == 1
    assert capsys.readouterr().err.startswith("unhealthy: ")


@pytest.mark.parametrize("reply", [b"\x05\x00", b"\x05\xff", b"\x05\x02"])
def test_any_socks5_method_reply_is_healthy(reply: bytes) -> None:
    with one_shot_server(reply) as port:
        assert healthcheck.probe("127.0.0.1", port)


def test_unhealthy_on_invalid_port_env(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("SOCKS5_HEALTHCHECK_PORT", "70000")
    assert healthcheck.main() == 1
    assert "SOCKS5_HEALTHCHECK_PORT" in capsys.readouterr().err
