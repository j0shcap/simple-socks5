import select
import socket
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


def test_udp_associate_echo(monkeypatch, proxy, udp_echo_origin):
    # The relay ignores control-connection close and only exits on its receive timeout (120 s).
    monkeypatch.setattr("src.relays.udp_relay.UDP_RECV_TIMEOUT", 0.5)

    with _udp_association(proxy) as (control, udp, relay_address):
        _assert_echo(udp, relay_address, udp_echo_origin.port)


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


@pytest.mark.parametrize("make_datagram", [
    *[pytest.param(lambda port, data=data: data, id=name) for name, data in MALFORMED.items()],
    # Addressed to the echo origin, so a relayed datagram would come back
    pytest.param(lambda port: b"\x00\x01" + sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", port)[2:] + b"bad",
                 id="RSV not 0"),
    pytest.param(lambda port: b"\x00\x00\x00\x09" + sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", port)[4:] + b"bad",
                 id="ATYP 9"),
    pytest.param(lambda port: sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", port, frag=1) + b"bad", id="FRAG 1"),
])
def test_malformed_datagram_is_dropped_and_association_survives(monkeypatch, proxy, udp_echo_origin, make_datagram):
    monkeypatch.setattr("src.relays.udp_relay.UDP_RECV_TIMEOUT", 0.5 + 2 * QUIET_PERIOD)

    with _udp_association(proxy) as (control, udp, relay_address):
        udp.sendto(make_datagram(udp_echo_origin.port), relay_address)

        _assert_echo(udp, relay_address, udp_echo_origin.port)
        _assert_nothing_received(udp)
        _assert_nothing_received(control)
