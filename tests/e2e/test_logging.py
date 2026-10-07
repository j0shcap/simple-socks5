"""
What the proxy logs for a whole connection: one CONNECTION and one CLOSED line, never a line per chunk.
"""
import logging
import re
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from src.server import TCPProxyServer
from tests.e2e import socks_client as sc

DOWNLOAD_SIZE = 10 * 1024 * 1024
REQUEST = b"GET /bytes/%d HTTP/1.0\r\n\r\n" % DOWNLOAD_SIZE


def _wait_for_closed_line(caplog, proxy) -> None:
    """CLOSED is logged on the handler thread after the client has already read EOF."""
    deadline = time.monotonic() + 5
    while not any(r.getMessage().startswith("CLOSED |") for r in caplog.records):
        assert time.monotonic() < deadline, "no CLOSED line within 5 s"
        time.sleep(0.01)
    assert proxy.server.wait_for_connections(5)


def _download(proxy, http_origin) -> bytes:
    with sc.open_tunnel(proxy.address, "127.0.0.1", http_origin.port) as tunnel:
        tunnel.sendall(REQUEST)
        return sc.recv_until_eof(tunnel)


def test_10mb_download_logs_one_connection_and_one_closed_line(proxy, http_origin, caplog):
    caplog.set_level(logging.INFO, logger="src")

    response = _download(proxy, http_origin)
    _wait_for_closed_line(caplog, proxy)

    messages = [r.getMessage() for r in caplog.records if r.name.startswith("src")]
    assert [m.split(" |")[0] for m in messages] == ["CONNECTION", "CLOSED"]
    up, down = map(int, re.search(r"up=(\d+) B down=(\d+) B", messages[1]).groups())
    assert up == len(REQUEST)
    assert down == len(response) > DOWNLOAD_SIZE


@pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO])
def test_no_per_chunk_lines_at_any_level(proxy, http_origin, caplog, level):
    caplog.set_level(level, logger="src")

    _download(proxy, http_origin)
    _wait_for_closed_line(caplog, proxy)

    records = [r for r in caplog.records if r.name.startswith("src")]
    assert not [r for r in records if "RELAY" in r.getMessage()]
    # A 10 MiB download is 160+ relay buffers; a handful of lines means none of them was logged
    assert len(records) < 10


@pytest.fixture
def handled(monkeypatch):
    """wait(): blocks until the proxy has finished with one connection and logged everything for it."""
    finished = threading.Semaphore(0)
    original_finish = TCPProxyServer.finish

    def finish(self):
        try:
            original_finish(self)
        finally:
            finished.release()

    monkeypatch.setattr(TCPProxyServer, "finish", finish)

    def wait(proxy) -> None:
        assert finished.acquire(timeout=5), "the proxy never finished the connection"
        # handle_error() and untracking run after finish()
        assert proxy.server.wait_for_connections(5)

    return SimpleNamespace(wait=wait)


def _reset_on_close(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


MID_HANDSHAKE_CASES = {
    "after connect": (False, lambda sock: None),
    "partial greeting": (False, lambda sock: sock.sendall(b"\x05")),
    "after method reply": (False, lambda sock: sc.greet(sock, [sc.METHOD_NO_AUTH])),
    "after method reply, RST": (False, lambda sock: (sc.greet(sock, [sc.METHOD_NO_AUTH]), _reset_on_close(sock))),
    "no acceptable method, auth required": (True, lambda sock: sc.greet(sock, [sc.METHOD_NO_AUTH])),
    "mid auth": (True, lambda sock: (sc.greet(sock, [sc.METHOD_USERPASS]), sock.sendall(b"\x01\x05us"))),
    "mid request, RST": (
        False,
        lambda sock: (
            sc.greet(sock, [sc.METHOD_NO_AUTH]),
            sock.sendall(b"\x05\x01\x00\x01\x7f"),
            _reset_on_close(sock),
        ),
    ),
}


@pytest.mark.parametrize("case", MID_HANDSHAKE_CASES)
def test_client_closing_mid_handshake_logs_nothing_above_debug(make_proxy, handled, caplog, case):
    auth_required, client_steps = MID_HANDSHAKE_CASES[case]
    proxy = make_proxy(auth_required=auth_required)
    caplog.set_level(logging.DEBUG, logger="src")

    with proxy.connect() as sock:
        client_steps(sock)
    handled.wait(proxy)

    problems = [r for r in caplog.records if r.levelno > logging.DEBUG or r.exc_info]
    assert problems == []
