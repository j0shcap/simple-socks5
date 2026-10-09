import logging
import select
import socket
import struct
import time
from contextlib import contextmanager

import pytest

from tests.e2e import socks_client as sc

QUIET_PERIOD = 0.3  # seconds to wait for something that must not arrive


@contextmanager
def _udp_association(proxy):
    """Opens a UDP association; yields (control, udp, relay_address)."""
    with proxy.connect() as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(sc.TIMEOUT)
        udp.bind(("127.0.0.1", 0))
        assert sc.greet(control, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(control, sc.CMD_UDP_ASSOCIATE, sc.ATYP_IPV4, "127.0.0.1", 0)
        reply = sc.read_reply(control)
        assert reply.rep == sc.REP_SUCCEEDED
        # BND.ADDR is the unspecified address today, so send to the proxy's host.
        yield control, udp, (proxy.address[0], reply.bnd_port)


def _assert_echo(udp, relay_address, origin_port, payload=b"ping"):
    udp.sendto(sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", origin_port) + payload, relay_address)
    response, _ = udp.recvfrom(65536)
    assert sc.parse_udp_header(response) == sc.UDPHeader(
        rsv=0, frag=0, atyp=sc.ATYP_IPV4, addr="127.0.0.1", port=origin_port, data=payload
    )


def _assert_nothing_received(sock):
    readable, _, _ = select.select([sock], [], [], QUIET_PERIOD)
    assert not readable, f"unexpected data or EOF on {sock}"


def test_udp_associate_echo(proxy, udp_echo_origin):
    with _udp_association(proxy) as (_control, udp, relay_address):
        _assert_echo(udp, relay_address, udp_echo_origin.port)


def test_udp_relay_lines_logged_at_debug_only(proxy, udp_echo_origin, caplog):
    caplog.set_level(logging.DEBUG, logger="simple_socks5")
    with _udp_association(proxy) as (_control, udp, relay_address):
        _assert_echo(udp, relay_address, udp_echo_origin.port)

    relay_records = [r for r in caplog.records if r.getMessage().startswith("RELAY | UDP")]
    assert len(relay_records) >= 2  # One per direction
    assert {r.levelno for r in relay_records} == {logging.DEBUG}


def test_association_logs_one_connection_and_one_closed_line(proxy, udp_echo_origin, caplog):
    caplog.set_level(logging.INFO, logger="simple_socks5")
    with _udp_association(proxy) as (control, udp, relay_address):
        _assert_echo(udp, relay_address, udp_echo_origin.port, payload=b"ping")
        _assert_echo(udp, relay_address, udp_echo_origin.port, payload=b"hello")
        control.close()
        assert proxy.server.wait_for_connections(sc.TIMEOUT)

    messages = [r.getMessage() for r in caplog.records if r.name.startswith("simple_socks5")]
    assert [m.split(" |")[0] for m in messages] == ["CONNECTION", "CLOSED"]
    assert "| up=9 B down=9 B |" in messages[1]


IPV4_HEADER = sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", 9)
IPV6_HEADER = sc.build_udp_header(sc.ATYP_IPV6, "::1", 9)
DOMAIN_HEADER = sc.build_udp_header(sc.ATYP_DOMAIN, "localhost", 9)
MALFORMED = {
    "empty": b"",
    "1 byte": b"\x00",
    "2 bytes": b"\x00\x00",
    "3 bytes": b"\x00\x00\x00",
    "IPv4 without port": IPV4_HEADER[:8],
    "IPv6 truncated": IPV6_HEADER[:12],
    "domain without length byte": DOMAIN_HEADER[:4],
    "domain truncated": DOMAIN_HEADER[:7],
    "domain without port": DOMAIN_HEADER[:-2],
}


@pytest.mark.parametrize(
    "make_datagram",
    [
        *[pytest.param(lambda _port, data=data: data, id=name) for name, data in MALFORMED.items()],
        # Addressed to the echo origin, so a relayed datagram would come back
        pytest.param(
            lambda port: b"\x00\x01" + sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", port)[2:] + b"bad", id="RSV not 0"
        ),
        pytest.param(
            lambda port: b"\x00\x00\x00\x09" + sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", port)[4:] + b"bad",
            id="ATYP 9",
        ),
        pytest.param(lambda port: sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", port, frag=1) + b"bad", id="FRAG 1"),
    ],
)
def test_malformed_datagram_is_dropped_and_association_survives(proxy, udp_echo_origin, make_datagram):
    with _udp_association(proxy) as (control, udp, relay_address):
        udp.sendto(make_datagram(udp_echo_origin.port), relay_address)

        _assert_echo(udp, relay_address, udp_echo_origin.port)
        _assert_nothing_received(udp)
        _assert_nothing_received(control)


def _assert_association_ended(proxy, udp, relay_address, origin_port):
    """The association ended within ~1 s: no more relaying, and the relay's UDP port is closed."""
    started = time.monotonic()
    assert proxy.server.wait_for_connections(1.5)
    assert time.monotonic() - started < 1.5

    # Sent only once the handler has returned: a datagram racing the FIN could still be relayed
    udp.sendto(sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", origin_port) + b"late", relay_address)
    _assert_nothing_received(udp)
    # Bound only after that check, so the test can't receive its own datagram
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
        rebind.bind(("", relay_address[1]))


def test_control_close_ends_association(proxy, udp_echo_origin):
    with _udp_association(proxy) as (control, udp, relay_address):
        _assert_echo(udp, relay_address, udp_echo_origin.port)
        control.close()
        _assert_association_ended(proxy, udp, relay_address, udp_echo_origin.port)


def test_control_reset_ends_association(proxy, udp_echo_origin):
    with _udp_association(proxy) as (control, udp, relay_address):
        _assert_echo(udp, relay_address, udp_echo_origin.port)
        control.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        control.close()
        _assert_association_ended(proxy, udp, relay_address, udp_echo_origin.port)


def test_close_connections_ends_udp_association(proxy):
    with _udp_association(proxy) as (control, _, _):
        assert proxy.server.close_connections() == 1
        assert proxy.server.wait_for_connections(sc.TIMEOUT)
        sc.assert_closed(control)


def test_idle_timeout_ends_association(monkeypatch, proxy):
    monkeypatch.setattr("simple_socks5.relays.udp_relay.UDP_RECV_TIMEOUT", 0.3)

    with _udp_association(proxy) as (control, _, _):
        assert proxy.server.wait_for_connections(2)
        assert sc.recv_until_eof(control) == b""
