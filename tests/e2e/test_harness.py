import logging
import os
import socket
import threading
import time

import pytest

from src.server import TCPProxyServer, ThreadingTCPServer
from tests.e2e import socks_client as sc
from tests.e2e.origins import serve_in_thread


def _open_fds() -> int:
    return len(os.listdir("/dev/fd"))


def test_start_stop_50_times(caplog):
    # Captured exc_info tracebacks pin each handler's rfile/wfile (and so its fd) until the test
    # ends; keep records from being created so the fd count reflects the server alone.
    caplog.set_level(logging.CRITICAL + 1)
    threads_before = threading.active_count()
    fds_before = _open_fds()

    for _ in range(50):
        with serve_in_thread(ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer)) as server:
            address = server.server_address
            with socket.create_connection(address, timeout=sc.TIMEOUT) as sock:
                assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH

    deadline = time.monotonic() + 3
    while threading.active_count() > threads_before and time.monotonic() < deadline:
        time.sleep(0.01)
    assert threading.active_count() == threads_before
    assert _open_fds() == fds_before
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(address, timeout=sc.TIMEOUT)
