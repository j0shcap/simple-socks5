import errno
import hmac
import logging
import os
import socket
import struct
import threading
import unittest
from unittest.mock import MagicMock, NonCallableMagicMock, create_autospec, patch

import pytest

from simple_socks5.constants import AddressTypeCodes, MethodCodes, ReplyCodes
from simple_socks5.errors import reply_code_for
from simple_socks5.exceptions import (
    AddressTypeNotSupportedError,
    AuthenticationFailedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
)
from simple_socks5.handlers.base import BaseHandler
from simple_socks5.handlers.tcp import TCPHandler
from simple_socks5.models import Request
from tests.env import strip_socks5_env

# Testing Data
# Initial Requests
REQ_INCORRECT_VERSION = b"\x04\x01"
REQ_CORRECT_VERSION_ONE_METHOD = b"\x05\x01"

CORRECT_VERSION_NO_AUTH_REQUIRED = [b"\x05\x01", b"\x00"]
CORRECT_VERSION_AUTH_REQUIRED = [b"\x05\x01", b"\x02"]
CORRECT_VERSION_AUTH_OR_NO_AUTH = [b"\x05\x02", b"\x00\x02"]

# Initial Responses
RESP_CORRECT_VERSION_NO_AUTH_REQUIRED = b"\x05\x00"
RESP_CORRECT_VERSION_AUTH_REQUIRED = b"\x05\x02"
RESP_CORRECT_VERSION_NO_ACCEPTABLE_METHODS = b"\x05\xff"
RESP_LOGIN_SUCCESS = b"\x01\x00"
RESP_LOGIN_FAILURE = b"\x01\x01"


def connection_mock() -> NonCallableMagicMock:
    connection: NonCallableMagicMock = create_autospec(socket.socket, instance=True)
    return connection


class TestTCPRequestHandlerIPv4(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self)
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.handler = TCPHandler(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    @patch("socket.socket.recv", autospec=True)
    def test_handle_handshake__incorrect_version(self, mock_recv: MagicMock) -> None:
        mock_recv.side_effect = [REQ_INCORRECT_VERSION]
        with pytest.raises(InvalidVersionError):
            self.handler.handle_request()

    @patch("socket.socket.recv", autospec=True)
    @patch("socket.socket.sendall", autospec=True)
    def test_handle_handshake__no_authentication_required(self, mock_sendall: MagicMock, mock_recv: MagicMock) -> None:
        mock_recv.side_effect = CORRECT_VERSION_NO_AUTH_REQUIRED
        self.handler.handle_request()
        mock_sendall.assert_called_with(RESP_CORRECT_VERSION_NO_AUTH_REQUIRED)

    @patch("socket.socket.recv", autospec=True)
    @patch("socket.socket.sendall", autospec=True)
    def test_handle_handshake__correct_version__authentication_required_success(
        self, mock_sendall: MagicMock, mock_recv: MagicMock
    ) -> None:
        username = "myusername"
        password = "mypassword"
        mock_recv.side_effect = [
            *CORRECT_VERSION_AUTH_REQUIRED,
            b"\x01",
            chr(len(username)).encode(),
            username.encode(),
            chr(len(password)).encode(),
            password.encode(),
        ]
        self.handler.handle_request()
        mock_sendall.assert_called_with(RESP_LOGIN_SUCCESS)

    @patch("socket.socket.recv", autospec=True)
    @patch("socket.socket.sendall", autospec=True)
    def test_handle_handshake__correct_version__authentication_required_subnegotiation_failure(
        self, mock_sendall: MagicMock, mock_recv: MagicMock
    ) -> None:
        username = "myusername"
        password = "mypassword"
        mock_recv.side_effect = [
            *CORRECT_VERSION_AUTH_REQUIRED,
            b"\x00",
            chr(len(username)).encode(),
            username.encode(),
            chr(len(password)).encode(),
            password.encode(),
        ]
        self.handler.handle_request()
        mock_sendall.assert_called_with(RESP_LOGIN_FAILURE)

    @patch("socket.socket.recv", autospec=True)
    @patch("socket.socket.sendall", autospec=True)
    def test_handle_handshake__correct_version__authentication_required_incorrect_password(
        self, mock_sendall: MagicMock, mock_recv: MagicMock
    ) -> None:
        username = "myusername"
        password = "eh"
        mock_recv.side_effect = [
            *CORRECT_VERSION_AUTH_REQUIRED,
            b"\x00",
            chr(len(username)).encode(),
            username.encode(),
            chr(len(password)).encode(),
            password.encode(),
        ]
        self.handler.handle_request()
        mock_sendall.assert_called_with(RESP_LOGIN_FAILURE)

    def test_authenticate_with_username_password_method(self) -> None:
        methods = b"\x02"
        result = self.handler._negotiate_authentication_method(methods)
        assert result == MethodCodes.USERNAME_PASSWORD

    def test_authenticate_with_no_authentication_required(self) -> None:
        methods = b"\x00"
        result = self.handler._negotiate_authentication_method(methods)
        assert result == MethodCodes.NO_AUTHENTICATION_REQUIRED

    def test_authenticate_with_invalid_methods(self) -> None:
        methods = b"\xff"
        result = self.handler._negotiate_authentication_method(methods)
        assert result == MethodCodes.NO_ACCEPTABLE_METHODS

    @patch("socket.socket.recv", autospec=True)
    @patch("socket.socket.sendall", autospec=True)
    def test_handle_username_password_auth__valid(self, mock_sendall: MagicMock, mock_recv: MagicMock) -> None:
        mock_recv.side_effect = [
            b"\x01",
            bytes([len("myusername")]),
            b"myusername",
            bytes([len("mypassword")]),
            b"mypassword",
        ]
        result = self.handler._handle_username_password_auth()
        mock_sendall.assert_called_with(RESP_LOGIN_SUCCESS)
        assert result

    @patch("socket.socket.recv", autospec=True)
    @patch("socket.socket.sendall", autospec=True)
    def test_handle_username_password_auth__invalid(self, mock_sendall: MagicMock, mock_recv: MagicMock) -> None:
        mock_recv.side_effect = [
            b"\x01",
            bytes([len("myusername")]),
            b"myusername",
            bytes([len("eh")]),
            b"eh",
        ]
        with pytest.raises(AuthenticationFailedError):
            self.handler._handle_username_password_auth()
        mock_sendall.assert_called_with(RESP_LOGIN_FAILURE)

    @patch("socket.socket.recv", autospec=True)
    @patch(
        "simple_socks5.handlers.base.socket.gethostbyaddr",
        autospec=True,
        side_effect=AssertionError("reverse DNS lookup"),
    )
    def test_parse_request(self, mock_gethostbyaddr: MagicMock, mock_recv: MagicMock) -> None:
        mock_recv.side_effect = [
            struct.pack("!BBBB", 0x05, 0x01, 0x00, 0x01),
            socket.inet_aton("93.184.216.34"),
            struct.pack("!H", 80),
        ]
        result = self.handler.parse_request()
        assert isinstance(result, Request)
        assert result.version == 5
        assert result.command == 1
        assert result.address.ip == "93.184.216.34"
        assert result.address.name == "93.184.216.34"
        assert result.address.port == 80
        assert result.address.address_type == AddressTypeCodes.IPv4
        mock_gethostbyaddr.assert_not_called()

    @patch("socket.socket.recv", autospec=True)
    @patch(
        "simple_socks5.handlers.base.socket.gethostbyaddr",
        autospec=True,
        side_effect=AssertionError("reverse DNS lookup"),
    )
    def test_parse_address_ipv4_never_reverse_resolves(
        self, mock_gethostbyaddr: MagicMock, mock_recv: MagicMock
    ) -> None:
        mock_recv.side_effect = [
            socket.inet_aton("1.2.3.4"),
            struct.pack("!H", 443),
        ]
        result = self.handler._parse_address(AddressTypeCodes.IPv4.value)
        assert result.ip == "1.2.3.4"
        assert result.port == 443
        assert result.name == "1.2.3.4"
        assert result.address_type == AddressTypeCodes.IPv4
        mock_gethostbyaddr.assert_not_called()

    @patch("socket.socket.recv", autospec=True)
    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_parse_address_domain_name_ipv4(self, mock_getaddrinfo: MagicMock, mock_recv: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]
        domain = "example.com"
        mock_recv.side_effect = [
            bytes([len(domain)]),
            domain.encode(),
            struct.pack("!H", 80),
        ]
        result = self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)
        assert result.ip == "93.184.216.34"
        assert result.port == 80
        assert result.name == domain
        assert result.address_type == AddressTypeCodes.IPv4

    @patch("socket.socket.recv", autospec=True)
    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_parse_address_domain_name_ipv6(self, mock_getaddrinfo: MagicMock, mock_recv: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2606:4700::6812:1a78", 0, 0, 0)),
        ]
        domain = "ipv6only.example.com"
        mock_recv.side_effect = [
            bytes([len(domain)]),
            domain.encode(),
            struct.pack("!H", 443),
        ]
        result = self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)
        assert result.ip == "2606:4700::6812:1a78"
        assert result.port == 443
        assert result.name == domain
        assert result.address_type == AddressTypeCodes.IPv6

    @patch("socket.socket.recv", autospec=True)
    @patch(
        "simple_socks5.handlers.base.socket.gethostbyaddr",
        autospec=True,
        side_effect=AssertionError("reverse DNS lookup"),
    )
    def test_parse_address_ipv6_never_reverse_resolves(
        self, mock_gethostbyaddr: MagicMock, mock_recv: MagicMock
    ) -> None:
        ipv6 = "2001:db8::1"
        mock_recv.side_effect = [
            socket.inet_pton(socket.AF_INET6, ipv6),
            struct.pack("!H", 8080),
        ]
        result = self.handler._parse_address(AddressTypeCodes.IPv6.value)
        assert result.ip == ipv6
        assert result.port == 8080
        assert result.name == ipv6
        assert result.address_type == AddressTypeCodes.IPv6
        mock_gethostbyaddr.assert_not_called()

    @patch("socket.socket.recv", autospec=True)
    def test_parse_request_rejects_nonzero_rsv(self, mock_recv: MagicMock) -> None:
        """RFC 1928 requires RSV field to be 0x00."""
        mock_recv.side_effect = [
            struct.pack("!BBBB", 0x05, 0x01, 0x01, 0x01),
        ]
        with pytest.raises(InvalidRequestError):
            self.handler.parse_request()

    def test_parse_address_invalid(self) -> None:
        with pytest.raises(InvalidRequestError):
            self.handler._parse_address(0xFF)

    @patch("simple_socks5.handlers.base.DNS_LOOKUP_TIMEOUT", 0.1)
    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_resolve_hostname_timeout_returns_name(self, mock_getaddrinfo: MagicMock) -> None:
        """Forward DNS should return the name with IPv4 default if the lookup takes too long."""
        done = threading.Event()

        def slow_lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            done.wait(timeout=5)
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

        mock_getaddrinfo.side_effect = slow_lookup
        ip, atyp = self.handler._resolve_hostname("example.com")
        assert ip == "example.com"
        assert atyp == AddressTypeCodes.IPv4.value
        done.set()

    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_resolve_hostname_ipv4(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]
        ip, atyp = self.handler._resolve_hostname("example.com")
        assert ip == "93.184.216.34"
        assert atyp == AddressTypeCodes.IPv4.value

    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_resolve_hostname_ipv6(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2606:4700::6812:1a78", 0, 0, 0)),
        ]
        ip, atyp = self.handler._resolve_hostname("example.com")
        assert ip == "2606:4700::6812:1a78"
        assert atyp == AddressTypeCodes.IPv6.value

    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_resolve_hostname_failure_returns_name(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.side_effect = OSError("no DNS")
        ip, atyp = self.handler._resolve_hostname("example.com")
        assert ip == "example.com"
        assert atyp == AddressTypeCodes.IPv4.value

    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_resolve_hostname_non_str_sockaddr_is_unresolved(self, mock_getaddrinfo: MagicMock) -> None:
        """A Python built without IPv6 support reports AF_INET6 results as (int, bytes) sockaddrs."""
        mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", (10, b"\x00" * 16))]
        ip, atyp = self.handler._resolve_hostname("example.com")
        assert ip == "example.com"
        assert atyp == AddressTypeCodes.IPv4.value

    @patch("simple_socks5.handlers.base.socket.getaddrinfo", autospec=True)
    def test_resolve_hostname_empty_result_returns_name(self, mock_getaddrinfo: MagicMock) -> None:
        """getaddrinfo returning empty list should fall back to name with IPv4."""
        mock_getaddrinfo.return_value = []
        ip, atyp = self.handler._resolve_hostname("example.com")
        assert ip == "example.com"
        assert atyp == AddressTypeCodes.IPv4.value


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestRecvExactDeadline(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        patcher = patch("simple_socks5.handlers.base.time.monotonic", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.connection = connection_mock()

    def test_recv_exact_sets_remaining_timeout(self) -> None:
        def recv(_n: int) -> bytes:
            self.clock.now += 0.25
            return b"x"

        self.connection.recv.side_effect = recv
        handler = BaseHandler(self.connection, deadline=1.0)

        assert handler._recv_exact(3) == b"xxx"
        timeouts = [c.args[0] for c in self.connection.settimeout.call_args_list]
        assert timeouts == [1.0, 0.75, 0.5]

    def test_recv_exact_drip_feed_hits_deadline(self) -> None:
        def recv(_n: int) -> bytes:
            self.clock.now += 0.6
            return b"x"

        self.connection.recv.side_effect = recv
        handler = BaseHandler(self.connection, deadline=1.0)

        with pytest.raises(HandshakeTimeoutError):
            handler._recv_exact(10)
        assert self.connection.recv.call_count == 2

    def test_recv_exact_expired_deadline_skips_recv(self) -> None:
        self.clock.now = 1.0
        handler = BaseHandler(self.connection, deadline=1.0)

        with pytest.raises(HandshakeTimeoutError):
            handler._recv_exact(1)
        self.connection.recv.assert_not_called()

    def test_recv_exact_timeout_becomes_handshake_timeout(self) -> None:
        self.connection.recv.side_effect = TimeoutError("timed out")
        handler = BaseHandler(self.connection, deadline=1.0)

        with pytest.raises(HandshakeTimeoutError):
            handler._recv_exact(1)

    def test_recv_exact_without_deadline_never_sets_timeout(self) -> None:
        self.connection.recv.side_effect = [b"ab"]
        handler = BaseHandler(self.connection)

        assert handler._recv_exact(2) == b"ab"
        self.connection.settimeout.assert_not_called()


class TestParseAddress(unittest.TestCase):
    """Typed errors for bad addresses, and every request byte read before any DNS lookup."""

    def setUp(self) -> None:
        self.events: list[str] = []
        self.connection = connection_mock()
        self.handler = BaseHandler(self.connection)

        def resolve_hostname(_name: str) -> tuple[str, int]:
            self.events.append("lookup")
            return "1.2.3.4", AddressTypeCodes.IPv4.value

        patcher = patch.object(self.handler, "_resolve_hostname", autospec=True, side_effect=resolve_hostname)
        patcher.start()
        self.addCleanup(patcher.stop)

    def feed(self, *chunks: bytes) -> None:
        remaining = list(chunks)

        def recv(_n: int) -> bytes:
            self.events.append("recv")
            return remaining.pop(0)

        self.connection.recv.side_effect = recv

    def test_unknown_atyp_raises_address_type_not_supported(self) -> None:
        with pytest.raises(AddressTypeNotSupportedError) as caught:
            self.handler._parse_address(0x05)
        assert isinstance(caught.value, InvalidRequestError)

    def test_non_utf8_domain_raises_invalid_domain_name(self) -> None:
        self.feed(b"\x02", b"\xff\xfe", struct.pack("!H", 80))
        with pytest.raises(InvalidDomainNameError):
            self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)

    def test_empty_domain_raises_invalid_domain_name(self) -> None:
        self.feed(b"\x00", struct.pack("!H", 80))
        with pytest.raises(InvalidDomainNameError) as caught:
            self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)
        assert reply_code_for(caught.value) is ReplyCodes.HOST_UNREACHABLE
        # The port is read, so the whole request is consumed, and nothing is looked up
        assert self.events == ["recv"] * 2

    def test_port_read_before_lookup(self) -> None:
        self.feed(b"\x07", b"example", struct.pack("!H", 80))
        address = self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)
        assert address.port == 80
        assert self.events == ["recv"] * 3 + ["lookup"]

    def test_ip_literals_need_no_lookup(self) -> None:
        cases = {
            AddressTypeCodes.IPv4: (socket.inet_aton("1.2.3.4"), struct.pack("!H", 80)),
            AddressTypeCodes.IPv6: (socket.inet_pton(socket.AF_INET6, "::1"), struct.pack("!H", 80)),
        }
        for address_type, chunks in cases.items():
            with self.subTest(address_type=address_type.name):
                self.events.clear()
                self.feed(*chunks)
                address = self.handler._parse_address(address_type.value)
                assert address.port == 80
                assert self.events == ["recv"] * len(chunks)


class TestHandshakeTimeout(unittest.TestCase):
    """A handshake timeout propagates as HandshakeTimeoutError, with no STATUS byte; the server logs it."""

    def setUp(self) -> None:
        self.connection = connection_mock()
        self.handler = TCPHandler(self.connection)

    def test_auth_does_not_reset_socket_timeout(self) -> None:
        self.connection.recv.side_effect = [b"\x01", b"\x01", b"u", b"\x01", b"p"]
        with pytest.raises(AuthenticationFailedError):
            self.handler._handle_username_password_auth()
        self.connection.settimeout.assert_not_called()

    def test_auth_timeout_raises_without_status(self) -> None:
        self.connection.recv.side_effect = [b"\x01", HandshakeTimeoutError("expired")]
        with self.assertNoLogs("simple_socks5.handlers"), pytest.raises(HandshakeTimeoutError):
            self.handler._handle_username_password_auth()
        self.connection.sendall.assert_not_called()

    def test_greeting_timeout_raises(self) -> None:
        self.connection.recv.side_effect = HandshakeTimeoutError("expired")
        with self.assertNoLogs("simple_socks5.handlers"), pytest.raises(HandshakeTimeoutError):
            self.handler.handle_request()
        self.connection.sendall.assert_not_called()

    def test_greeting_sendall_timeout_raises_handshake_timeout(self) -> None:
        self.connection.recv.side_effect = [b"\x05\x01", b"\x00"]
        self.connection.sendall.side_effect = TimeoutError("timed out")
        with self.assertNoLogs("simple_socks5.handlers"), pytest.raises(HandshakeTimeoutError):
            self.handler.handle_request()

    def test_auth_sendall_timeout_raises_handshake_timeout(self) -> None:
        self.connection.recv.side_effect = [b"\x01", b"\x01", b"u", b"\x01", b"p"]
        self.connection.sendall.side_effect = TimeoutError("timed out")
        with pytest.raises(HandshakeTimeoutError):
            self.handler._handle_username_password_auth()

    def test_request_timeout_propagates_without_traceback(self) -> None:
        self.connection.recv.side_effect = [struct.pack("!BBBB", 5, 1, 0, 1), HandshakeTimeoutError("expired")]
        with self.assertLogs("simple_socks5.handlers", level="DEBUG") as logs:
            # assertLogs needs at least one record; the handler itself must add none above DEBUG
            logging.getLogger("simple_socks5.handlers").debug("start")
            with pytest.raises(HandshakeTimeoutError):
                self.handler.parse_request()
        assert not [r for r in logs.records if r.exc_info or r.levelno >= 30]


class TestHandshakeDisconnects(unittest.TestCase):
    """A client hanging up mid-handshake is routine: DEBUG, no traceback. Anything else keeps its traceback."""

    def setUp(self) -> None:
        strip_socks5_env(self)
        self.connection = connection_mock()
        self.handler = TCPHandler(self.connection)

    def assert_debug_only(self, records: list[logging.LogRecord]) -> None:
        assert records
        assert not [r for r in records if r.exc_info or r.levelno > logging.DEBUG]

    def test_greeting_disconnects_log_debug_without_traceback(self) -> None:
        for recv in (b"", ConnectionResetError("reset"), [b"\x05\x01", b""]):
            with self.subTest(recv=recv):
                self.connection.recv.side_effect = recv if isinstance(recv, list) else [recv]
                with self.assertLogs("simple_socks5.handlers", level="DEBUG") as logs:
                    assert not self.handler.handle_request()
                self.assert_debug_only(logs.records)

    def test_auth_disconnect_logs_debug_without_traceback(self) -> None:
        self.connection.recv.side_effect = [b"\x01", b"\x05", b""]
        with self.assertLogs("simple_socks5.handlers", level="DEBUG") as logs:
            assert not self.handler._handle_username_password_auth()
        self.assert_debug_only(logs.records)

    def test_no_acceptable_methods_logs_debug(self) -> None:
        strip_socks5_env(self, SOCKS5_AUTH_REQUIRED="true")
        self.connection.recv.side_effect = [b"\x05\x01", b"\x00"]
        with self.assertLogs("simple_socks5.handlers", level="DEBUG") as logs:
            assert not self.handler.handle_request()
        self.connection.sendall.assert_called_once_with(RESP_CORRECT_VERSION_NO_ACCEPTABLE_METHODS)
        self.assert_debug_only(logs.records)

    def test_unexpected_socket_error_logs_traceback(self) -> None:
        self.connection.recv.side_effect = OSError(errno.EBADF, "bad file descriptor")
        with self.assertLogs("simple_socks5.handlers", level="ERROR") as logs:
            assert not self.handler.handle_request()
        assert logs.records[0].exc_info

    def test_request_disconnect_raises_without_logging(self) -> None:
        for recv in ([b""], [struct.pack("!BBBB", 5, 1, 0, 1), b"\x7f"], [ConnectionResetError("reset")]):
            with self.subTest(recv=recv):
                self.connection.recv.side_effect = [*recv, b""]
                with self.assertNoLogs("simple_socks5.handlers"), pytest.raises(ConnectionError):
                    self.handler.parse_request()


def userpass_frame(username: bytes, password: bytes) -> list[bytes]:
    """The RFC 1929 request as the separate reads the handler makes; empty fields are never read."""
    chunks = [b"\x01", bytes([len(username)]), username, bytes([len(password)]), password]
    return [chunk for chunk in chunks if chunk]


class TestUsernamePasswordAuth(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self, SOCKS5_USERNAME="alice", SOCKS5_PASSWORD="s3cret")
        self.connection = connection_mock()
        self.handler = TCPHandler(self.connection)

    def authenticate(self, username: bytes, password: bytes) -> bool:
        self.connection.recv.side_effect = userpass_frame(username, password)
        return self.handler._handle_username_password_auth()

    def assert_rejected(self, username: bytes, password: bytes) -> None:
        # The server logs the failure, rate-limited; the handler only reports it
        with self.assertNoLogs("simple_socks5.handlers"), pytest.raises(AuthenticationFailedError):
            self.authenticate(username, password)
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_FAILURE)
        # The whole frame was read, so closing sends FIN rather than RST
        assert self.connection.recv.call_count == len(userpass_frame(username, password))

    def test_correct_credentials_succeed(self) -> None:
        assert self.authenticate(b"alice", b"s3cret")
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_SUCCESS)

    def test_wrong_username_fails(self) -> None:
        self.assert_rejected(b"mallory", b"s3cret")

    def test_wrong_password_fails(self) -> None:
        self.assert_rejected(b"alice", b"guess")

    def test_both_wrong_fails(self) -> None:
        self.assert_rejected(b"mallory", b"guess")

    def test_empty_username_fails_and_consumes_frame(self) -> None:
        self.assert_rejected(b"", b"s3cret")

    def test_empty_password_fails_and_consumes_frame(self) -> None:
        self.assert_rejected(b"alice", b"")

    def test_empty_credentials_rejected_even_when_configured_empty(self) -> None:
        strip_socks5_env(self, SOCKS5_USERNAME="", SOCKS5_PASSWORD="")
        self.assert_rejected(b"", b"")

    def test_non_utf8_username_fails_without_exception(self) -> None:
        # The audit repro: VER=1, ULEN=2, UNAME=ff fe, PLEN=1, PASSWD="a"
        self.connection.recv.side_effect = [b"\x01", b"\x02", b"\xff\xfe", b"\x01", b"a"]
        with pytest.raises(AuthenticationFailedError):
            self.handler._handle_username_password_auth()
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_FAILURE)

    def test_non_utf8_password_fails_without_exception(self) -> None:
        self.assert_rejected(b"alice", b"\xff\xfe")

    def test_compare_digest_called_for_both_fields_even_on_wrong_username(self) -> None:
        with (
            patch("simple_socks5.handlers.tcp.hmac.compare_digest", wraps=hmac.compare_digest) as spy,
            pytest.raises(AuthenticationFailedError),
        ):
            self.authenticate(b"mallory", b"s3cret")
        assert spy.call_count == 2

    def test_password_change_after_import_honoured(self) -> None:
        with patch.dict(os.environ, {"SOCKS5_PASSWORD": "rotated"}):
            with pytest.raises(AuthenticationFailedError):
                self.authenticate(b"alice", b"s3cret")
            self.connection.reset_mock()
            assert self.authenticate(b"alice", b"rotated")

    def test_success_logs_configured_username_never_password(self) -> None:
        with self.assertLogs("simple_socks5.handlers", level="DEBUG") as logs:
            assert self.authenticate(b"alice", b"s3cret")
        messages = "\n".join(r.getMessage() for r in logs.records)
        assert "alice" in messages
        assert "s3cret" not in messages

    def test_utf8_password_succeeds(self) -> None:
        strip_socks5_env(self, SOCKS5_USERNAME="alice", SOCKS5_PASSWORD="pässwörd")
        assert self.authenticate(b"alice", "pässwörd".encode())
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_SUCCESS)


class TestAuthEnforcement(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.handler = TCPHandler(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    @patch("simple_socks5.handlers.tcp.auth_required", lambda: True)
    def test_auth_required_rejects_no_auth_only_client(self) -> None:
        """When auth_required() is True, a client offering only NO_AUTH should be rejected."""
        methods = b"\x00"
        result = self.handler._negotiate_authentication_method(methods)
        assert result == MethodCodes.NO_ACCEPTABLE_METHODS

    @patch("simple_socks5.handlers.tcp.auth_required", lambda: True)
    def test_auth_required_accepts_username_password(self) -> None:
        """When auth_required() is True, USERNAME_PASSWORD should still be accepted."""
        methods = b"\x00\x02"
        result = self.handler._negotiate_authentication_method(methods)
        assert result == MethodCodes.USERNAME_PASSWORD

    @patch("simple_socks5.handlers.tcp.auth_required", lambda: False)
    def test_default_allows_no_auth(self) -> None:
        """Default behavior (auth_required()=False) should allow NO_AUTH."""
        methods = b"\x00"
        result = self.handler._negotiate_authentication_method(methods)
        assert result == MethodCodes.NO_AUTHENTICATION_REQUIRED


if __name__ == "__main__":
    unittest.main()
