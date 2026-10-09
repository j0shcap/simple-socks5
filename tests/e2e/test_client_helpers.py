"""Self-tests for the raw SOCKS5 client, run over a socketpair (no proxy)."""

import socket

import pytest

from tests.e2e import socks_client as sc


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    a.settimeout(5.0)
    b.settimeout(5.0)
    yield a, b
    a.close()
    b.close()


def test_read_reply_ipv4_does_not_over_read(pair):
    server, client = pair
    server.sendall(b"\x05\x00\x00\x01" + bytes([10, 0, 0, 1]) + b"\x1f\x90" + b"NEXT")

    reply = sc.read_reply(client)

    assert reply == sc.Reply(ver=5, rep=0, rsv=0, atyp=sc.ATYP_IPV4, bnd_addr="10.0.0.1", bnd_port=8080)
    assert sc.recv_exact(client, 4) == b"NEXT"


def test_read_reply_ipv6_does_not_over_read(pair):
    server, client = pair
    server.sendall(b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + b"\x00\x50" + b"NEXT")

    reply = sc.read_reply(client)

    assert reply.atyp == sc.ATYP_IPV6
    assert reply.bnd_addr == "::1"
    assert reply.bnd_port == 80
    assert sc.recv_exact(client, 4) == b"NEXT"


def test_read_reply_domain(pair):
    server, client = pair
    server.sendall(b"\x05\x00\x00\x03\x0bexample.com\x01\xbb" + b"NEXT")

    reply = sc.read_reply(client)

    assert (reply.atyp, reply.bnd_addr, reply.bnd_port) == (sc.ATYP_DOMAIN, "example.com", 443)
    assert sc.recv_exact(client, 4) == b"NEXT"


def test_read_reply_eof_mid_reply_raises(pair):
    server, client = pair
    server.sendall(b"\x05\x00\x00\x01\x7f")
    server.shutdown(socket.SHUT_WR)

    with pytest.raises(EOFError):
        sc.read_reply(client)


def test_builders_match_rfc_bytes():
    assert sc.build_greeting([sc.METHOD_NO_AUTH, sc.METHOD_USERPASS]) == b"\x05\x02\x00\x02"
    assert sc.build_userpass("user", "pw") == b"\x01\x04user\x02pw"
    assert sc.build_userpass(b"\xff", b"", ver=5) == b"\x05\x01\xff\x00"
    assert sc.build_request(sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", 80) == (
        b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"
    )
    assert sc.build_request(sc.CMD_CONNECT, sc.ATYP_DOMAIN, "a.io", 443) == b"\x05\x01\x00\x03\x04a.io\x01\xbb"
    assert sc.build_request(sc.CMD_CONNECT, sc.ATYP_IPV6, "::1", 1) == (
        b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01\x00\x01"
    )
    assert sc.build_request(9, sc.ATYP_DOMAIN, b"\x09short", 1, ver=4) == b"\x04\x09\x00\x03\x09short\x00\x01"
    assert sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", 53) == b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35"


@pytest.mark.parametrize(
    ("atyp", "addr"),
    [(1, "192.0.2.7"), (3, "example.com"), (4, "2001:db8::1")],
)
def test_udp_header_round_trip(atyp, addr):
    datagram = sc.build_udp_header(atyp, addr, 4242) + b"payload"

    assert sc.parse_udp_header(datagram) == sc.UDPHeader(
        rsv=0, frag=0, atyp=atyp, addr=addr, port=4242, data=b"payload"
    )
