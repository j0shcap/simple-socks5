"""
Destination policy: loopback, link-local and unspecified destinations are refused with REP 0x02 unless
SOCKS5_ALLOW_LOOPBACK=true. Every test here turns the policy on explicitly, since the fixtures turn it off.
"""
import logging

import pytest

from tests.e2e import socks_client as sc
from tests.e2e.test_udp import _assert_echo, _assert_nothing_received, _udp_association

DENIED = [
    pytest.param(sc.ATYP_IPV4, "127.5.5.5", id="127.5.5.5"),
    pytest.param(sc.ATYP_IPV4, "0.0.0.0", id="0.0.0.0"),
    pytest.param(sc.ATYP_IPV4, "169.254.169.254", id="cloud-metadata"),
    pytest.param(sc.ATYP_IPV6, "::1", id="::1"),
    pytest.param(sc.ATYP_IPV6, "fe80::1", id="fe80::1"),
    pytest.param(sc.ATYP_IPV6, "::ffff:127.0.0.1", id="ipv4-mapped-loopback"),
]
PRIVATE = ("10.255.255.1", 80)


def _connect_reply(proxy, atyp: int, addr, port: int) -> sc.Reply:
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, atyp, addr, port)
        reply = sc.read_reply(sock)
        if reply.rep != sc.REP_SUCCEEDED:
            sc.assert_closed(sock)
        return reply


@pytest.fixture
def policy_proxy(make_proxy):
    return make_proxy(allow_loopback=False)


def test_connect_to_loopback_origin_denied(policy_proxy, echo_origin):
    assert _connect_reply(policy_proxy, sc.ATYP_IPV4, "127.0.0.1", echo_origin.port).rep == sc.REP_NOT_ALLOWED


@pytest.mark.parametrize("atyp, addr", DENIED)
def test_connect_denied(policy_proxy, atyp, addr):
    # Refused before any socket exists, so no IPv6 stack is needed
    assert _connect_reply(policy_proxy, atyp, addr, 80).rep == sc.REP_NOT_ALLOWED


def test_connect_localhost_by_name_denied(policy_proxy, echo_origin):
    # The resolved address is checked, whichever of 127.0.0.1 and ::1 comes first
    assert _connect_reply(policy_proxy, sc.ATYP_DOMAIN, "localhost", echo_origin.port).rep == sc.REP_NOT_ALLOWED


@pytest.mark.parametrize("allow_loopback", [False, True], ids=["policy-on", "opt-out"])
def test_empty_domain_host_unreachable(make_proxy, allow_loopback):
    proxy = make_proxy(allow_loopback=allow_loopback)
    assert _connect_reply(proxy, sc.ATYP_DOMAIN, b"\x00", 80).rep == sc.REP_HOST_UNREACHABLE


def test_private_destination_not_denied(monkeypatch, policy_proxy):
    monkeypatch.setenv("SOCKS5_CONNECT_TIMEOUT", "0.5")
    assert _connect_reply(policy_proxy, sc.ATYP_IPV4, *PRIVATE).rep != sc.REP_NOT_ALLOWED


def test_opt_out_allows_loopback_ipv4(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"


def test_opt_out_allows_loopback_ipv6(proxy, echo_origin_v6):
    with sc.open_tunnel(proxy.address, "::1", echo_origin_v6.port) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"


@pytest.mark.parametrize("atyp, addr", DENIED)
def test_opt_out_lifts_every_denial(monkeypatch, proxy, atyp, addr):
    # Nothing listens there, so the connect may fail, but not because of the policy
    monkeypatch.setenv("SOCKS5_CONNECT_TIMEOUT", "0.5")
    assert _connect_reply(proxy, atyp, addr, 9).rep != sc.REP_NOT_ALLOWED


def test_udp_loopback_dropped_then_allowed_on_same_association(monkeypatch, policy_proxy, udp_echo_origin):
    with _udp_association(policy_proxy) as (control, udp, relay_address):
        udp.sendto(sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", udp_echo_origin.port) + b"ping", relay_address)
        _assert_nothing_received(udp)

        monkeypatch.setenv("SOCKS5_ALLOW_LOOPBACK", "true")
        _assert_echo(udp, relay_address, udp_echo_origin.port)


def test_denial_warning_rate_limited(policy_proxy, echo_origin, caplog):
    caplog.set_level(logging.INFO, logger="simple_socks5")
    for _ in range(100):
        assert _connect_reply(policy_proxy, sc.ATYP_IPV4, "127.0.0.1", echo_origin.port).rep == sc.REP_NOT_ALLOWED

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert 1 <= len(warnings) <= 2, [r.getMessage() for r in warnings]
    assert all("SOCKS5_ALLOW_LOOPBACK=true" in r.getMessage() for r in warnings)
    assert "127.0.0.1 -> 127.0.0.1:" in warnings[0].getMessage()
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
