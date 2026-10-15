import hashlib
import socket
from typing import NoReturn

import pytest

from tests.e2e import socks_client as sc
from tests.e2e.conftest import ProxyHandle
from tests.e2e.origins import Origin, deterministic_payload

DOWNLOAD_SIZE = 4 * 1024 * 1024


def _assert_echo(tunnel: socket.socket) -> None:
    tunnel.sendall(b"ping")
    assert sc.recv_exact(tunnel, 4) == b"ping"


def test_connect_ipv4_echo(proxy: ProxyHandle, echo_origin: Origin) -> None:
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        _assert_echo(tunnel)


def test_connect_domain_ipv4_literal_echo(proxy: ProxyHandle, echo_origin: Origin) -> None:
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port, atyp=sc.ATYP_DOMAIN) as tunnel:
        _assert_echo(tunnel)


def _localhost_addresses(port: int) -> list[str]:
    """localhost's addresses in the order the proxy tries them: it makes the same getaddrinfo() call."""
    infos = socket.getaddrinfo("localhost", port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return list(dict.fromkeys(str(sockaddr[0]) for *_, sockaddr in infos))


def _assert_localhost_reaches(proxy: ProxyHandle, origin: Origin, atyp: int, bnd_addr: str) -> None:
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_DOMAIN, "localhost", origin.port)

        reply = sc.read_reply(sock)

        assert (reply.rep, reply.atyp, reply.bnd_addr) == (sc.REP_SUCCEEDED, atyp, bnd_addr)
        _assert_echo(sock)


def test_connect_domain_localhost_echo(proxy: ProxyHandle, echo_origin: Origin) -> None:
    """An origin listening only on 127.0.0.1 is reachable as localhost when the name resolves to ::1 first."""
    addresses = _localhost_addresses(echo_origin.port)
    if addresses[:1] != ["::1"] or "127.0.0.1" not in addresses:
        pytest.skip(f"localhost resolves to {addresses} here, not ::1 then 127.0.0.1")
    _assert_localhost_reaches(proxy, echo_origin, sc.ATYP_IPV4, "127.0.0.1")


def test_connect_domain_localhost_v6_only_origin(proxy: ProxyHandle, echo_origin_v6: Origin) -> None:
    """The fallback in the other direction, for resolvers that return 127.0.0.1 first."""
    addresses = _localhost_addresses(echo_origin_v6.port)
    if not {"::1", "127.0.0.1"} <= set(addresses):
        pytest.skip(f"localhost resolves to {addresses} here, not both ::1 and 127.0.0.1")
    _assert_localhost_reaches(proxy, echo_origin_v6, sc.ATYP_IPV6, "::1")


def test_connect_ipv6_echo(proxy: ProxyHandle, echo_origin_v6: Origin) -> None:
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV6, "::1", echo_origin_v6.port)

        reply = sc.read_reply(sock)

        assert (reply.rep, reply.atyp, reply.bnd_addr) == (sc.REP_SUCCEEDED, sc.ATYP_IPV6, "::1")
        _assert_echo(sock)


def test_download_sha256(proxy: ProxyHandle, http_origin: Origin) -> None:
    with sc.open_tunnel(proxy.address, "127.0.0.1", http_origin.port) as tunnel:
        tunnel.sendall(b"GET /bytes/%d HTTP/1.0\r\n\r\n" % DOWNLOAD_SIZE)
        response = sc.recv_until_eof(tunnel)

    head, _, body = response.partition(b"\r\n\r\n")
    status_line, *header_lines = head.split(b"\r\n")
    headers = dict(line.split(b": ", 1) for line in header_lines)
    assert status_line.split(b" ")[1] == b"200"
    assert int(headers[b"Content-Length"]) == DOWNLOAD_SIZE
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(deterministic_payload(DOWNLOAD_SIZE)).hexdigest()


def test_connect_closed_port_replies_refused(proxy: ProxyHandle) -> None:
    with socket.socket() as placeholder:
        placeholder.bind(("127.0.0.1", 0))
        closed_port = placeholder.getsockname()[1]

    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", closed_port)

        assert sc.read_reply(sock).rep == sc.REP_CONNECTION_REFUSED
        sc.assert_closed(sock)


@pytest.mark.parametrize("cmd", [0x09, sc.CMD_BIND], ids=["unknown", "bind"])
def test_unsupported_command_replies_not_supported(proxy: ProxyHandle, echo_origin: Origin, cmd: int) -> None:
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, cmd, sc.ATYP_IPV4, "127.0.0.1", echo_origin.port)

        assert sc.read_reply(sock).rep == sc.REP_COMMAND_NOT_SUPPORTED
        sc.assert_closed(sock)


def _request_reply_code(proxy: ProxyHandle, request: bytes) -> int:
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sock.sendall(request)

        rep = sc.read_reply(sock).rep
        sc.assert_closed(sock)
        return rep


def test_unknown_atyp_replies_atyp_not_supported(proxy: ProxyHandle) -> None:
    request = sc.build_request(sc.CMD_CONNECT, 0x05, b"\x7f\x00\x00\x01", 80)
    assert _request_reply_code(proxy, request) == sc.REP_ATYP_NOT_SUPPORTED


def test_nxdomain_replies_host_unreachable(proxy: ProxyHandle) -> None:
    request = sc.build_request(sc.CMD_CONNECT, sc.ATYP_DOMAIN, "does-not-exist.invalid", 80)
    assert _request_reply_code(proxy, request) == sc.REP_HOST_UNREACHABLE


def test_non_utf8_domain_replies_host_unreachable(proxy: ProxyHandle) -> None:
    request = sc.build_request(sc.CMD_CONNECT, sc.ATYP_DOMAIN, b"\x02\xff\xfe", 80)
    assert _request_reply_code(proxy, request) == sc.REP_HOST_UNREACHABLE


def test_connect_by_ip_never_reverse_resolves(
    proxy: ProxyHandle, echo_origin: Origin, monkeypatch: pytest.MonkeyPatch
) -> None:
    lookups: list[str] = []

    def reverse_lookup(ip: str) -> NoReturn:
        lookups.append(ip)
        raise AssertionError(f"reverse DNS lookup for {ip}")

    monkeypatch.setattr(socket, "gethostbyaddr", reverse_lookup)
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        _assert_echo(tunnel)
    proxy.server.wait_for_connections(5)

    assert lookups == []
