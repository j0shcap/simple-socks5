import contextlib
import errno
import logging
import socket
import threading
import time
import unittest
from collections.abc import Callable
from ipaddress import ip_address
from unittest.mock import MagicMock, patch

import pytest

from simple_socks5 import resolver
from simple_socks5.constants import MAX_CONNECT_ATTEMPTS, AddressTypeCodes, ReplyCodes
from simple_socks5.errors import reply_code_for
from simple_socks5.exceptions import PolicyDeniedError
from simple_socks5.models import DetailedAddress
from simple_socks5.resolver import Candidate, connect_any, resolve
from simple_socks5.utils import WarningRateLimiter
from tests.env import strip_socks5_env

AddrInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int] | tuple[str, int, int, int]]


def v4(ip: str, port: int = 80) -> AddrInfo:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))


def v6(ip: str, port: int = 80, scope_id: int = 0) -> AddrInfo:
    return (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port, 0, scope_id))


class HangingLookup:
    """A getaddrinfo stand-in that blocks until released, recording the thread it ran on."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.started = threading.Event()
        self.threads: list[threading.Thread] = []

    def __call__(self, *_args: object) -> list[AddrInfo]:
        self.threads.append(threading.current_thread())
        self.started.set()
        self.release.wait(timeout=5)
        return [v4("93.184.216.34")]

    def finish(self) -> None:
        self.release.set()
        for thread in self.threads:
            thread.join(timeout=5)


@patch("simple_socks5.resolver.socket.getaddrinfo", autospec=True)
class TestResolve(unittest.TestCase):
    def test_resolve_returns_all_addresses_in_os_order(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [v6("::1"), v4("127.0.0.1")]

        assert resolve("localhost", 80) == [
            Candidate(socket.AF_INET6, ("::1", 80, 0, 0)),
            Candidate(socket.AF_INET, ("127.0.0.1", 80)),
        ]
        mock_getaddrinfo.assert_called_once_with("localhost", 80, socket.AF_UNSPEC, socket.SOCK_STREAM)

    def test_resolve_dedupes_repeated_sockaddrs(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [v4("10.0.0.1"), v6("2001:db8::1"), v4("10.0.0.1"), v4("10.0.0.2")]

        assert [c.ip for c in resolve("example.com", 80)] == ["10.0.0.1", "2001:db8::1", "10.0.0.2"]

    def test_resolve_keeps_ipv6_scope_id(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [v6("fe80::1", scope_id=3)]

        [candidate] = resolve("router.local", 80)

        assert candidate.sockaddr == ("fe80::1", 80, 0, 3)
        assert candidate.ip == "fe80::1"

    def test_resolve_empty_result_raises_gaierror(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = []

        with pytest.raises(socket.gaierror) as caught:
            resolve("example.com", 80)
        assert reply_code_for(caught.value) == ReplyCodes.HOST_UNREACHABLE

    def test_resolve_drops_non_str_sockaddrs_then_raises(self, mock_getaddrinfo: MagicMock) -> None:
        """A Python built without IPv6 support reports AF_INET6 results as (int, bytes) sockaddrs."""
        mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", (10, b"\x00" * 16))]

        with pytest.raises(socket.gaierror):
            resolve("example.com", 80)

    def test_resolve_nxdomain_propagates_gaierror(self, mock_getaddrinfo: MagicMock) -> None:
        nxdomain = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        mock_getaddrinfo.side_effect = nxdomain

        with pytest.raises(socket.gaierror) as caught:
            resolve("does-not-exist.invalid", 80)
        assert caught.value is nxdomain

    def test_unencodable_name_raises_gaierror_without_error_log(self, mock_getaddrinfo: MagicMock) -> None:
        """A name the idna codec rejects (empty or over-long label) is the client's mistake, not a proxy fault."""
        mock_getaddrinfo.side_effect = UnicodeError("label empty or too long")

        with self.assertNoLogs("simple_socks5.resolver", level="INFO"), pytest.raises(socket.gaierror) as caught:
            resolve("x..y", 80)
        assert reply_code_for(caught.value) == ReplyCodes.HOST_UNREACHABLE


@patch("simple_socks5.resolver.socket.getaddrinfo", autospec=True)
class TestBoundedLookup(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in (
            ("_lookup_slots", threading.BoundedSemaphore(1)),
            ("_saturated_warnings", WarningRateLimiter(10.0)),
            ("DNS_LOOKUP_TIMEOUT", 0.05),
        ):
            patcher = patch.object(resolver, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_lookup_timeout_raises_gaierror_and_thread_exits(self, mock_getaddrinfo: MagicMock) -> None:
        lookup = HangingLookup()
        mock_getaddrinfo.side_effect = lookup

        with pytest.raises(socket.gaierror) as caught:
            resolve("slow.example", 80)
        assert reply_code_for(caught.value) == ReplyCodes.HOST_UNREACHABLE

        lookup.finish()
        assert not any(t.is_alive() for t in lookup.threads)

    def test_unexpected_lookup_error_logs_traceback_and_raises_gaierror(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.side_effect = ValueError("boom")

        with self.assertLogs("simple_socks5.resolver", level="ERROR") as logs, pytest.raises(socket.gaierror):
            resolve("example.com", 80)
        [record] = logs.records
        assert record.exc_info is not None

    def test_lookup_slots_full_fails_fast_without_thread(self, mock_getaddrinfo: MagicMock) -> None:
        lookup = HangingLookup()
        mock_getaddrinfo.side_effect = lookup
        self.addCleanup(lookup.finish)
        with pytest.raises(socket.gaierror):
            resolve("slow.example", 80)  # still holds the only slot
        threads_before = threading.active_count()

        with self.assertLogs("simple_socks5.resolver", level="WARNING") as logs:
            for _ in range(3):
                with pytest.raises(socket.gaierror) as caught:
                    resolve("other.example", 80)
                assert reply_code_for(caught.value) == ReplyCodes.HOST_UNREACHABLE

        assert threading.active_count() == threads_before
        assert mock_getaddrinfo.call_count == 1
        assert [r.levelno for r in logs.records] == [logging.WARNING]

    def test_lookup_slot_released_after_timeout(self, mock_getaddrinfo: MagicMock) -> None:
        lookup = HangingLookup()
        mock_getaddrinfo.side_effect = lookup
        with pytest.raises(socket.gaierror):
            resolve("slow.example", 80)
        lookup.finish()

        mock_getaddrinfo.side_effect = None
        mock_getaddrinfo.return_value = [v4("10.0.0.1")]
        assert [c.ip for c in resolve("example.com", 80)] == ["10.0.0.1"]

    def test_lookup_slot_released_when_thread_start_fails(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [v4("10.0.0.1")]
        with (
            patch.object(threading.Thread, "start", side_effect=RuntimeError("can't start new thread")),
            pytest.raises(socket.gaierror),
        ):
            resolve("example.com", 80)

        assert [c.ip for c in resolve("example.com", 80)] == ["10.0.0.1"]


class FakeSocket:
    """A TCP socket whose connect() outcome is scripted per IP."""

    def __init__(self, factory: "FakeSockets", family: socket.AddressFamily) -> None:
        self.factory = factory
        self.family = family
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def connect(self, sockaddr: tuple[object, ...]) -> None:
        self.factory.connects.append(sockaddr)
        outcome = self.factory.outcomes.get(str(sockaddr[0]))
        if self.factory.connect_delay:
            threading.Event().wait(self.factory.connect_delay)
        if outcome is not None:
            raise outcome

    def close(self) -> None:
        self.closed = True


class FakeSockets:
    """Stands in for socket.socket; an IP missing from outcomes connects."""

    def __init__(self, outcomes: dict[str, OSError] | None = None, connect_delay: float = 0.0) -> None:
        self.outcomes = outcomes or {}
        self.connect_delay = connect_delay
        self.unsupported_families: set[socket.AddressFamily] = set()
        self.created: list[FakeSocket] = []
        self.connects: list[tuple[object, ...]] = []

    def __call__(self, family: socket.AddressFamily, _kind: socket.SocketKind) -> FakeSocket:
        if family in self.unsupported_families:
            raise OSError(errno.EAFNOSUPPORT, "Address family not supported by protocol")
        sock = FakeSocket(self, family)
        self.created.append(sock)
        return sock


def domain(name: str, port: int = 80) -> DetailedAddress:
    return DetailedAddress(ip=name, port=port, name=name, address_type=AddressTypeCodes.DOMAIN_NAME)


def same(returned: object, fake: FakeSocket) -> bool:
    """Whether connect_any() returned this fake; typed loosely because it is declared to return a real socket."""
    return returned is fake


REFUSED = ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")


class TestConnectAny(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self)
        getaddrinfo = patch("simple_socks5.resolver.socket.getaddrinfo", autospec=True)
        self.getaddrinfo = getaddrinfo.start()
        self.addCleanup(getaddrinfo.stop)
        self.sockets = FakeSockets()
        sockets = patch("simple_socks5.resolver.socket.socket", self.sockets)
        sockets.start()
        self.addCleanup(sockets.stop)

    def resolves_to(self, *infos: AddrInfo) -> None:
        self.getaddrinfo.return_value = list(infos)

    def test_v6_unreachable_then_v4_connects(self) -> None:
        strip_socks5_env(self, SOCKS5_ALLOW_LOOPBACK="true")
        self.resolves_to(v6("::1"), v4("127.0.0.1"))
        self.sockets.outcomes["::1"] = OSError(errno.ENETUNREACH, "Network is unreachable")

        with self.assertLogs("simple_socks5.resolver", level="DEBUG") as logs:
            sock, connected = connect_any(domain("localhost"))

        assert connected == DetailedAddress(
            ip="127.0.0.1", port=80, name="localhost", address_type=AddressTypeCodes.IPv4
        )
        v6_sock, v4_sock = self.sockets.created
        assert same(sock, v4_sock)
        assert v6_sock.closed
        assert not v4_sock.closed
        assert [r.levelno for r in logs.records] == [logging.DEBUG]
        assert "::1" in logs.output[0]

    def test_all_refused_raises_last_error(self) -> None:
        self.resolves_to(v4("192.0.2.1"), v4("192.0.2.2"), v6("2001:db8::1"))
        last = ConnectionRefusedError(errno.ECONNREFUSED, "last")
        self.sockets.outcomes = {"192.0.2.1": REFUSED, "192.0.2.2": REFUSED, "2001:db8::1": last}

        with pytest.raises(ConnectionRefusedError) as caught:
            connect_any(domain("example.com"))

        assert caught.value is last
        assert reply_code_for(caught.value) == ReplyCodes.CONNECTION_REFUSED
        assert len(self.sockets.connects) == 3
        assert all(s.closed for s in self.sockets.created)

    def test_all_time_out_stops_after_four_attempts(self) -> None:
        strip_socks5_env(self, SOCKS5_CONNECT_TIMEOUT="0.05")
        ips = [f"192.0.2.{i}" for i in range(1, 7)]
        self.resolves_to(*(v4(ip) for ip in ips))
        self.sockets.connect_delay = 0.05
        self.sockets.outcomes = dict.fromkeys(ips, TimeoutError("timed out"))

        started = time.monotonic()
        with pytest.raises(TimeoutError) as caught:
            connect_any(domain("blackhole.example"))
        elapsed = time.monotonic() - started

        assert MAX_CONNECT_ATTEMPTS == 4
        assert [s[0] for s in self.sockets.connects] == ips[:MAX_CONNECT_ATTEMPTS]
        assert [s.timeout for s in self.sockets.created] == [0.05] * MAX_CONNECT_ATTEMPTS
        assert elapsed < MAX_CONNECT_ATTEMPTS * 0.05 + 0.5
        assert reply_code_for(caught.value) == ReplyCodes.HOST_UNREACHABLE

    def test_all_denied_raises_policy_denied_without_sockets(self) -> None:
        self.resolves_to(v6("::1"), v4("127.0.0.1"))

        with pytest.raises(PolicyDeniedError) as caught:
            connect_any(domain("localhost"))

        assert reply_code_for(caught.value) == ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET
        assert self.sockets.created == []

    def test_denied_then_refused_replies_refused(self) -> None:
        self.resolves_to(v4("127.0.0.1"), v4("192.0.2.1"))
        self.sockets.outcomes["192.0.2.1"] = REFUSED

        with pytest.raises(ConnectionRefusedError) as caught:
            connect_any(domain("mixed.example"))

        assert reply_code_for(caught.value) == ReplyCodes.CONNECTION_REFUSED
        assert [s[0] for s in self.sockets.connects] == ["192.0.2.1"]

    def test_denied_addresses_do_not_use_up_attempts(self) -> None:
        denied = [v4(f"127.0.0.{i}") for i in range(1, 5)]
        self.resolves_to(*denied, v4("192.0.2.1"), v4("192.0.2.2"))
        self.sockets.outcomes["192.0.2.1"] = REFUSED

        _, connected = connect_any(domain("mixed.example"))

        assert connected.ip == "192.0.2.2"

    def test_socket_creation_failure_does_not_count_as_attempt(self) -> None:
        self.sockets.unsupported_families.add(socket.AF_INET6)
        self.resolves_to(*(v6(f"2001:db8::{i}") for i in range(1, 5)), v4("192.0.2.1"))

        _, connected = connect_any(domain("dual.example"))

        assert connected.ip == "192.0.2.1"
        assert connected.address_type == AddressTypeCodes.IPv4

    def test_only_unsupported_families_raise_their_error(self) -> None:
        self.sockets.unsupported_families.add(socket.AF_INET6)
        self.resolves_to(v6("2001:db8::1"))

        with pytest.raises(OSError, match="not supported"):
            connect_any(domain("v6only.example"))

    def test_denied_and_unsupported_families_raise_policy_denied(self) -> None:
        self.sockets.unsupported_families.add(socket.AF_INET6)
        self.resolves_to(v4("127.0.0.1"), v6("2001:db8::1"))

        with pytest.raises(PolicyDeniedError):
            connect_any(domain("mixed.example"))

    def test_literal_destination_skips_lookup(self) -> None:
        for ip, atyp, family in (
            ("192.0.2.1", AddressTypeCodes.IPv4, socket.AF_INET),
            ("2001:db8::1", AddressTypeCodes.IPv6, socket.AF_INET6),
        ):
            with self.subTest(ip=ip):
                dst = DetailedAddress(ip=ip, port=443, name=ip, address_type=atyp)

                sock, connected = connect_any(dst)

                assert connected == dst
                assert same(sock, self.sockets.created[-1])
                assert self.sockets.created[-1].family == family
                assert self.sockets.connects[-1] == (ip, 443)
        self.getaddrinfo.assert_not_called()

    def test_literal_destination_denied_by_policy(self) -> None:
        dst = DetailedAddress(ip="127.0.0.1", port=80, name="127.0.0.1", address_type=AddressTypeCodes.IPv4)

        with pytest.raises(PolicyDeniedError):
            connect_any(dst)
        assert self.sockets.created == []

    def test_connected_ipv6_keeps_scope_id(self) -> None:
        self.resolves_to(v6("2001:db8::1", scope_id=3))

        _, connected = connect_any(domain("scoped.example"))

        assert self.sockets.connects == [("2001:db8::1", 80, 0, 3)]
        assert connected.address_type == AddressTypeCodes.IPv6

    @patch("simple_socks5.resolver.DNS_LOOKUP_TIMEOUT", 0.05)
    def test_lookup_failure_never_connects(self) -> None:
        lookup = HangingLookup()
        self.addCleanup(lookup.finish)
        failures: dict[str, Callable[[], None]] = {
            "timeout": lambda: setattr(self.getaddrinfo, "side_effect", lookup),
            "nxdomain": lambda: setattr(self.getaddrinfo, "side_effect", socket.gaierror(socket.EAI_NONAME, "nx")),
            "empty": self.resolves_to,
        }
        for name, arrange in failures.items():
            with self.subTest(failure=name):
                self.getaddrinfo.side_effect = None
                arrange()

                with pytest.raises(socket.gaierror) as caught:
                    connect_any(domain("unresolvable.example"))

                assert reply_code_for(caught.value) == ReplyCodes.HOST_UNREACHABLE
                assert self.sockets.created == []

    def test_connect_never_receives_hostname(self) -> None:
        outcomes: dict[str, Callable[[], None]] = {
            "first fails": lambda: self.sockets.outcomes.update({"::1": REFUSED}),
            "all fail": lambda: self.sockets.outcomes.update({"::1": REFUSED, "127.0.0.1": REFUSED}),
            "first connects": lambda: None,
            "nxdomain": lambda: setattr(self.getaddrinfo, "side_effect", socket.gaierror(socket.EAI_NONAME, "nx")),
            "empty": self.resolves_to,
        }
        for allow in ("true", "false"):
            for name, arrange in outcomes.items():
                with self.subTest(allow_loopback=allow, outcome=name):
                    strip_socks5_env(self, SOCKS5_ALLOW_LOOPBACK=allow)
                    self.sockets.outcomes.clear()
                    self.sockets.connects.clear()
                    self.getaddrinfo.side_effect = None
                    self.resolves_to(v6("::1"), v4("127.0.0.1"))
                    arrange()

                    with contextlib.suppress(OSError, PolicyDeniedError):
                        connect_any(domain("localhost"))

                    for sockaddr in self.sockets.connects:
                        ip_address(str(sockaddr[0]))  # raises ValueError for a hostname
