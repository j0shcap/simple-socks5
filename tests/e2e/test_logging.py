"""
What the proxy logs for a whole connection: one CONNECTION and one CLOSED line, never a line per chunk.
"""
import logging
import re
import time

import pytest

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
