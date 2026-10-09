"""
Connection limit (SOCKS5_MAX_CONNECTIONS): connections over the limit are closed, the warning is rate-limited,
and a freed slot is reusable.
"""
import logging
import time
from contextlib import ExitStack

from tests.e2e import socks_client as sc

RECOVERY_DEADLINE = 2.0  # seconds for a closed tunnel's slot to be released


def _echo(tunnel) -> None:
    tunnel.sendall(b"ping")
    assert sc.recv_exact(tunnel, 4) == b"ping"


def test_limit_rejects_warns_once_and_recovers(monkeypatch, make_proxy, echo_origin, caplog):
    caplog.set_level(logging.WARNING, logger="simple_socks5.server")
    monkeypatch.setenv("SOCKS5_MAX_CONNECTIONS", "2")
    proxy = make_proxy()

    def open_tunnel():
        return sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port)

    with ExitStack() as stack:
        first = stack.enter_context(open_tunnel())
        second = stack.enter_context(open_tunnel())
        _echo(first)
        _echo(second)  # Both slots are now held by running handlers

        for _ in range(20):
            # Nothing is sent, so the close is a FIN, never a reset racing unread data
            with proxy.connect() as rejected:
                sc.assert_closed(rejected)

        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1, warnings
        assert "Connection limit of 2 reached" in warnings[0]

        first.close()
        started = time.monotonic()
        while True:
            try:
                with open_tunnel() as recovered:
                    _echo(recovered)
                break
            except (sc.Socks5Error, EOFError, ConnectionError):
                assert time.monotonic() - started <= RECOVERY_DEADLINE, "slot not released after a tunnel closed"
                time.sleep(0.05)

        _echo(second)
