import logging
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

import pytest

from simple_socks5 import resolver
from simple_socks5.constants import ReplyCodes
from simple_socks5.errors import reply_code_for
from simple_socks5.resolver import Candidate, resolve
from simple_socks5.utils import WarningRateLimiter

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
            pytest.raises(RuntimeError),
        ):
            resolve("example.com", 80)

        assert [c.ip for c in resolve("example.com", 80)] == ["10.0.0.1"]
