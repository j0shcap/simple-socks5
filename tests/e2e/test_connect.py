import hashlib
import socket

import pytest

from tests.e2e import socks_client as sc
from tests.e2e.origins import deterministic_payload

DOWNLOAD_SIZE = 4 * 1024 * 1024


def _assert_echo(tunnel: socket.socket) -> None:
    tunnel.sendall(b"ping")
    assert sc.recv_exact(tunnel, 4) == b"ping"


def test_connect_ipv4_echo(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        _assert_echo(tunnel)


def test_connect_domain_ipv4_literal_echo(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port, atyp=sc.ATYP_DOMAIN) as tunnel:
        _assert_echo(tunnel)


@pytest.mark.xfail(strict=False, reason="only the first getaddrinfo result is tried; localhost may be ::1")
def test_connect_domain_localhost_echo(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "localhost", echo_origin.port) as tunnel:
        _assert_echo(tunnel)


def test_connect_ipv6_echo(proxy, echo_origin_v6):
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV6, "::1", echo_origin_v6.port)

        reply = sc.read_reply(sock)

        assert (reply.rep, reply.atyp, reply.bnd_addr) == (sc.REP_SUCCEEDED, sc.ATYP_IPV6, "::1")
        _assert_echo(sock)


def test_download_sha256(proxy, http_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", http_origin.port) as tunnel:
        tunnel.sendall(b"GET /bytes/%d HTTP/1.0\r\n\r\n" % DOWNLOAD_SIZE)
        response = sc.recv_until_eof(tunnel)

    head, _, body = response.partition(b"\r\n\r\n")
    status_line, *header_lines = head.split(b"\r\n")
    headers = dict(line.split(b": ", 1) for line in header_lines)
    assert status_line.split(b" ")[1] == b"200"
    assert int(headers[b"Content-Length"]) == DOWNLOAD_SIZE
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(deterministic_payload(DOWNLOAD_SIZE)).hexdigest()


def test_connect_closed_port_replies_refused(proxy):
    with socket.socket() as placeholder:
        placeholder.bind(("127.0.0.1", 0))
        closed_port = placeholder.getsockname()[1]

    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", closed_port)

        assert sc.read_reply(sock).rep == sc.REP_CONNECTION_REFUSED
        sc.assert_closed(sock)


@pytest.mark.parametrize("cmd", [0x09, sc.CMD_BIND], ids=["unknown", "bind"])
def test_unsupported_command_replies_not_supported(proxy, echo_origin, cmd):
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, cmd, sc.ATYP_IPV4, "127.0.0.1", echo_origin.port)

        assert sc.read_reply(sock).rep == sc.REP_COMMAND_NOT_SUPPORTED
        sc.assert_closed(sock)
