import hmac
import logging
import os
import threading
import unittest
from unittest.mock import MagicMock, patch
import struct
import socket
from src.handlers.base import BaseHandler
from src.handlers.tcp import TCPHandler
from src.exceptions import (
    AddressTypeNotSupportedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
)
from src.constants import AddressTypeCodes, MethodCodes
from src.models import Request

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
RESP_CORRECT_VERSION_NO_ACCEPTABLE_METHODS = b"\x05\xFF"
RESP_LOGIN_SUCCESS = b"\x01\x00"
RESP_LOGIN_FAILURE = b"\x01\x01"


def strip_socks5_env(test: unittest.TestCase, **environ) -> None:
    """Runs the test with no SOCKS5_* variables from the outer environment, plus the given ones."""
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
    patcher = patch.dict(os.environ, {**clean, **environ}, clear=True)
    patcher.start()
    test.addCleanup(patcher.stop)


class TestTCPRequestHandlerIPv4(unittest.TestCase):
    def setUp(self):
        strip_socks5_env(self)
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.handler = TCPHandler(self.connection)

    def tearDown(self):
        self.connection.close()

    @patch("socket.socket.recv")
    def test_handle_handshake__incorrect_version(self, mock_recv):
        mock_recv.side_effect = [REQ_INCORRECT_VERSION]
        with self.assertRaises(InvalidVersionError):
            self.handler.handle_request()

    @patch("socket.socket.recv")
    @patch("socket.socket.sendall")
    def test_handle_handshake__no_authentication_required(
        self, mock_sendall, mock_recv
    ):
        mock_recv.side_effect = CORRECT_VERSION_NO_AUTH_REQUIRED
        self.handler.handle_request()
        mock_sendall.assert_called_with(RESP_CORRECT_VERSION_NO_AUTH_REQUIRED)

    @patch("socket.socket.recv")
    @patch("socket.socket.sendall")
    def test_handle_handshake__correct_version__authentication_required_success(
        self, mock_sendall, mock_recv
    ):
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

    @patch("socket.socket.recv")
    @patch("socket.socket.sendall")
    def test_handle_handshake__correct_version__authentication_required_subnegotiation_failure(
        self, mock_sendall, mock_recv
    ):
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

    @patch("socket.socket.recv")
    @patch("socket.socket.sendall")
    def test_handle_handshake__correct_version__authentication_required_incorrect_password(
        self, mock_sendall, mock_recv
    ):
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

    def test_authenticate_with_username_password_method(self):
        methods = b"\x02"
        result = self.handler._negotiate_authentication_method(methods)
        self.assertEqual(result, MethodCodes.USERNAME_PASSWORD)

    def test_authenticate_with_no_authentication_required(self):
        methods = b"\x00"
        result = self.handler._negotiate_authentication_method(methods)
        self.assertEqual(result, MethodCodes.NO_AUTHENTICATION_REQUIRED)

    def test_authenticate_with_invalid_methods(self):
        methods = b"\xFF"
        result = self.handler._negotiate_authentication_method(methods)
        self.assertEqual(result, MethodCodes.NO_ACCEPTABLE_METHODS)

    @patch("socket.socket.recv")
    @patch("socket.socket.sendall")
    def test_handle_username_password_auth__valid(self, mock_sendall, mock_recv):
        mock_recv.side_effect = [
            b"\x01",
            bytes([len("myusername")]),
            b"myusername",
            bytes([len("mypassword")]),
            b"mypassword",
        ]
        result = self.handler._handle_username_password_auth()
        mock_sendall.assert_called_with(RESP_LOGIN_SUCCESS)
        self.assertTrue(result)

    @patch("socket.socket.recv")
    @patch("socket.socket.sendall")
    def test_handle_username_password_auth__invalid(self, mock_sendall, mock_recv):
        mock_recv.side_effect = [
            b"\x01",
            bytes([len("myusername")]),
            b"myusername",
            bytes([len("eh")]),
            b"eh",
        ]
        result = self.handler._handle_username_password_auth()
        mock_sendall.assert_called_with(RESP_LOGIN_FAILURE)
        self.assertFalse(result)

    @patch("socket.socket.recv")
    @patch("src.handlers.base.socket.gethostbyaddr", side_effect=AssertionError("reverse DNS lookup"))
    def test_parse_request(self, mock_gethostbyaddr, mock_recv):
        mock_recv.side_effect = [
            struct.pack("!BBBB", 0x05, 0x01, 0x00, 0x01),
            socket.inet_aton("93.184.216.34"),
            struct.pack("!H", 80),
        ]
        result = self.handler.parse_request()
        self.assertIsInstance(result, Request)
        self.assertEqual(result.version, 5)
        self.assertEqual(result.command, 1)
        self.assertEqual(result.address.ip, "93.184.216.34")
        self.assertEqual(result.address.name, "93.184.216.34")
        self.assertEqual(result.address.port, 80)
        self.assertEqual(result.address.address_type, AddressTypeCodes.IPv4)
        mock_gethostbyaddr.assert_not_called()

    @patch("socket.socket.recv")
    @patch("src.handlers.base.socket.gethostbyaddr", side_effect=AssertionError("reverse DNS lookup"))
    def test_parse_address_ipv4_never_reverse_resolves(self, mock_gethostbyaddr, mock_recv):
        mock_recv.side_effect = [
            socket.inet_aton("1.2.3.4"),
            struct.pack("!H", 443),
        ]
        result = self.handler._parse_address(AddressTypeCodes.IPv4.value)
        self.assertEqual(result.ip, "1.2.3.4")
        self.assertEqual(result.port, 443)
        self.assertEqual(result.name, "1.2.3.4")
        self.assertEqual(result.address_type, AddressTypeCodes.IPv4)
        mock_gethostbyaddr.assert_not_called()

    @patch("socket.socket.recv")
    @patch("src.handlers.base.socket.getaddrinfo")
    def test_parse_address_domain_name_ipv4(self, mock_getaddrinfo, mock_recv):
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
        self.assertEqual(result.ip, "93.184.216.34")
        self.assertEqual(result.port, 80)
        self.assertEqual(result.name, domain)
        self.assertEqual(result.address_type, AddressTypeCodes.IPv4)

    @patch("socket.socket.recv")
    @patch("src.handlers.base.socket.getaddrinfo")
    def test_parse_address_domain_name_ipv6(self, mock_getaddrinfo, mock_recv):
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
        self.assertEqual(result.ip, "2606:4700::6812:1a78")
        self.assertEqual(result.port, 443)
        self.assertEqual(result.name, domain)
        self.assertEqual(result.address_type, AddressTypeCodes.IPv6)

    @patch("socket.socket.recv")
    @patch("src.handlers.base.socket.gethostbyaddr", side_effect=AssertionError("reverse DNS lookup"))
    def test_parse_address_ipv6_never_reverse_resolves(self, mock_gethostbyaddr, mock_recv):
        ipv6 = "2001:db8::1"
        mock_recv.side_effect = [
            socket.inet_pton(socket.AF_INET6, ipv6),
            struct.pack("!H", 8080),
        ]
        result = self.handler._parse_address(AddressTypeCodes.IPv6.value)
        self.assertEqual(result.ip, ipv6)
        self.assertEqual(result.port, 8080)
        self.assertEqual(result.name, ipv6)
        self.assertEqual(result.address_type, AddressTypeCodes.IPv6)
        mock_gethostbyaddr.assert_not_called()

    @patch("socket.socket.recv")
    def test_parse_request_rejects_nonzero_rsv(self, mock_recv):
        """RFC 1928 requires RSV field to be 0x00."""
        mock_recv.side_effect = [
            struct.pack("!BBBB", 0x05, 0x01, 0x01, 0x01),
        ]
        with self.assertRaises(InvalidRequestError):
            self.handler.parse_request()

    def test_parse_address_invalid(self):
        with self.assertRaises(InvalidRequestError):
            self.handler._parse_address(0xFF)

    @patch("src.handlers.base.DNS_LOOKUP_TIMEOUT", 0.1)
    @patch("src.handlers.base.socket.getaddrinfo")
    def test_resolve_hostname_timeout_returns_name(self, mock_getaddrinfo):
        """Forward DNS should return the name with IPv4 default if the lookup takes too long."""
        done = threading.Event()

        def slow_lookup(*args, **kwargs):
            done.wait(timeout=5)
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

        mock_getaddrinfo.side_effect = slow_lookup
        ip, atyp = self.handler._resolve_hostname("example.com")
        self.assertEqual(ip, "example.com")
        self.assertEqual(atyp, AddressTypeCodes.IPv4.value)
        done.set()

    @patch("src.handlers.base.socket.getaddrinfo")
    def test_resolve_hostname_ipv4(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]
        ip, atyp = self.handler._resolve_hostname("example.com")
        self.assertEqual(ip, "93.184.216.34")
        self.assertEqual(atyp, AddressTypeCodes.IPv4.value)

    @patch("src.handlers.base.socket.getaddrinfo")
    def test_resolve_hostname_ipv6(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2606:4700::6812:1a78", 0, 0, 0)),
        ]
        ip, atyp = self.handler._resolve_hostname("example.com")
        self.assertEqual(ip, "2606:4700::6812:1a78")
        self.assertEqual(atyp, AddressTypeCodes.IPv6.value)

    @patch("src.handlers.base.socket.getaddrinfo")
    def test_resolve_hostname_failure_returns_name(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = OSError("no DNS")
        ip, atyp = self.handler._resolve_hostname("example.com")
        self.assertEqual(ip, "example.com")
        self.assertEqual(atyp, AddressTypeCodes.IPv4.value)

    @patch("src.handlers.base.socket.getaddrinfo")
    def test_resolve_hostname_empty_result_returns_name(self, mock_getaddrinfo):
        """getaddrinfo returning empty list should fall back to name with IPv4."""
        mock_getaddrinfo.return_value = []
        ip, atyp = self.handler._resolve_hostname("example.com")
        self.assertEqual(ip, "example.com")
        self.assertEqual(atyp, AddressTypeCodes.IPv4.value)


class FakeClock:
    def __init__(self, now: float = 0.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestRecvExactDeadline(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        patcher = patch("src.handlers.base.time.monotonic", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.connection = MagicMock()

    def test_recv_exact_sets_remaining_timeout(self):
        def recv(n):
            self.clock.now += 0.25
            return b"x"

        self.connection.recv.side_effect = recv
        handler = BaseHandler(self.connection, deadline=1.0)

        self.assertEqual(handler._recv_exact(3), b"xxx")
        timeouts = [c.args[0] for c in self.connection.settimeout.call_args_list]
        self.assertEqual(timeouts, [1.0, 0.75, 0.5])

    def test_recv_exact_drip_feed_hits_deadline(self):
        def recv(n):
            self.clock.now += 0.6
            return b"x"

        self.connection.recv.side_effect = recv
        handler = BaseHandler(self.connection, deadline=1.0)

        with self.assertRaises(HandshakeTimeoutError):
            handler._recv_exact(10)
        self.assertEqual(self.connection.recv.call_count, 2)

    def test_recv_exact_expired_deadline_skips_recv(self):
        self.clock.now = 1.0
        handler = BaseHandler(self.connection, deadline=1.0)

        with self.assertRaises(HandshakeTimeoutError):
            handler._recv_exact(1)
        self.connection.recv.assert_not_called()

    def test_recv_exact_timeout_becomes_handshake_timeout(self):
        self.connection.recv.side_effect = socket.timeout("timed out")
        handler = BaseHandler(self.connection, deadline=1.0)

        with self.assertRaises(HandshakeTimeoutError):
            handler._recv_exact(1)

    def test_recv_exact_without_deadline_never_sets_timeout(self):
        self.connection.recv.side_effect = [b"ab"]
        handler = BaseHandler(self.connection)

        self.assertEqual(handler._recv_exact(2), b"ab")
        self.connection.settimeout.assert_not_called()


class TestParseAddress(unittest.TestCase):
    """Typed errors for bad addresses, and every request byte read before any DNS lookup."""

    def setUp(self):
        self.events = []
        self.connection = MagicMock()
        self.handler = BaseHandler(self.connection)
        self.handler._resolve_hostname = (
            lambda name: self.events.append("lookup") or ("1.2.3.4", AddressTypeCodes.IPv4.value)
        )

    def feed(self, *chunks: bytes) -> None:
        remaining = list(chunks)

        def recv(n):
            self.events.append("recv")
            return remaining.pop(0)

        self.connection.recv.side_effect = recv

    def test_unknown_atyp_raises_address_type_not_supported(self):
        with self.assertRaises(AddressTypeNotSupportedError) as caught:
            self.handler._parse_address(0x05)
        self.assertIsInstance(caught.exception, InvalidRequestError)

    def test_non_utf8_domain_raises_invalid_domain_name(self):
        self.feed(b"\x02", b"\xff\xfe", struct.pack("!H", 80))
        with self.assertRaises(InvalidDomainNameError):
            self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)

    def test_port_read_before_lookup(self):
        self.feed(b"\x07", b"example", struct.pack("!H", 80))
        address = self.handler._parse_address(AddressTypeCodes.DOMAIN_NAME.value)
        self.assertEqual(address.port, 80)
        self.assertEqual(self.events, ["recv"] * 3 + ["lookup"])

    def test_ip_literals_need_no_lookup(self):
        cases = {
            AddressTypeCodes.IPv4: (socket.inet_aton("1.2.3.4"), struct.pack("!H", 80)),
            AddressTypeCodes.IPv6: (socket.inet_pton(socket.AF_INET6, "::1"), struct.pack("!H", 80)),
        }
        for address_type, chunks in cases.items():
            with self.subTest(address_type=address_type.name):
                self.events.clear()
                self.feed(*chunks)
                address = self.handler._parse_address(address_type.value)
                self.assertEqual(address.port, 80)
                self.assertEqual(self.events, ["recv"] * len(chunks))


class TestHandshakeTimeout(unittest.TestCase):
    """A handshake timeout closes quietly: no STATUS byte, and a warning without a traceback."""

    def setUp(self):
        self.connection = MagicMock()
        self.handler = TCPHandler(self.connection)

    def assert_quiet_warning(self, logs):
        self.assertTrue(any(r.levelname == "WARNING" for r in logs.records))
        self.assertFalse([r for r in logs.records if r.exc_info or r.levelno >= 40])

    def test_auth_does_not_reset_socket_timeout(self):
        self.connection.recv.side_effect = [b"\x01", b"\x01", b"u", b"\x01", b"p"]
        self.handler._handle_username_password_auth()
        self.connection.settimeout.assert_not_called()

    def test_auth_timeout_returns_false_without_status(self):
        self.connection.recv.side_effect = [b"\x01", HandshakeTimeoutError("expired")]
        with self.assertLogs("src.handlers", level="DEBUG") as logs:
            self.assertFalse(self.handler._handle_username_password_auth())
        self.connection.sendall.assert_not_called()
        self.assert_quiet_warning(logs)

    def test_greeting_timeout_logs_warning_without_traceback(self):
        self.connection.recv.side_effect = HandshakeTimeoutError("expired")
        with self.assertLogs("src.handlers", level="DEBUG") as logs:
            self.assertFalse(self.handler.handle_request())
        self.connection.sendall.assert_not_called()
        self.assert_quiet_warning(logs)

    def test_request_timeout_propagates_without_traceback(self):
        self.connection.recv.side_effect = [struct.pack("!BBBB", 5, 1, 0, 1), HandshakeTimeoutError("expired")]
        with self.assertLogs("src.handlers", level="DEBUG") as logs, self.assertRaises(HandshakeTimeoutError):
            # assertLogs needs at least one record; the handler itself must add none above DEBUG
            logging.getLogger("src.handlers").debug("start")
            self.handler.parse_request()
        self.assertFalse([r for r in logs.records if r.exc_info or r.levelno >= 30])


def userpass_frame(username: bytes, password: bytes) -> list[bytes]:
    """The RFC 1929 request as the separate reads the handler makes; empty fields are never read."""
    chunks = [b"\x01", bytes([len(username)]), username, bytes([len(password)]), password]
    return [chunk for chunk in chunks if chunk]


class TestUsernamePasswordAuth(unittest.TestCase):
    CLIENT_IP = "203.0.113.7"

    def setUp(self):
        strip_socks5_env(self, SOCKS5_USERNAME="alice", SOCKS5_PASSWORD="s3cret")
        self.connection = MagicMock()
        self.connection.getpeername.return_value = (self.CLIENT_IP, 5555)
        self.handler = TCPHandler(self.connection)

    def authenticate(self, username: bytes, password: bytes) -> bool:
        self.connection.recv.side_effect = userpass_frame(username, password)
        return self.handler._handle_username_password_auth()

    def assert_rejected(self, username: bytes, password: bytes):
        with self.assertLogs("src.handlers", level="DEBUG") as logs:
            self.assertFalse(self.authenticate(username, password))
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_FAILURE)
        # The whole frame was read, so closing sends FIN rather than RST
        self.assertEqual(self.connection.recv.call_count, len(userpass_frame(username, password)))
        self.assertFalse([r for r in logs.records if r.exc_info])
        return logs

    def test_correct_credentials_succeed(self):
        self.assertTrue(self.authenticate(b"alice", b"s3cret"))
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_SUCCESS)

    def test_wrong_username_fails(self):
        self.assert_rejected(b"mallory", b"s3cret")

    def test_wrong_password_fails(self):
        self.assert_rejected(b"alice", b"guess")

    def test_both_wrong_fails(self):
        self.assert_rejected(b"mallory", b"guess")

    def test_empty_username_fails_and_consumes_frame(self):
        self.assert_rejected(b"", b"s3cret")

    def test_empty_password_fails_and_consumes_frame(self):
        self.assert_rejected(b"alice", b"")

    def test_empty_credentials_rejected_even_when_configured_empty(self):
        strip_socks5_env(self, SOCKS5_USERNAME="", SOCKS5_PASSWORD="")
        self.assert_rejected(b"", b"")

    def test_non_utf8_username_fails_without_exception(self):
        # The audit repro: VER=1, ULEN=2, UNAME=ff fe, PLEN=1, PASSWD="a"
        self.connection.recv.side_effect = [b"\x01", b"\x02", b"\xff\xfe", b"\x01", b"a"]
        self.assertFalse(self.handler._handle_username_password_auth())
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_FAILURE)

    def test_non_utf8_password_fails_without_exception(self):
        self.assert_rejected(b"alice", b"\xff\xfe")

    def test_compare_digest_called_for_both_fields_even_on_wrong_username(self):
        with patch("src.handlers.tcp.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            self.assertFalse(self.authenticate(b"mallory", b"s3cret"))
        self.assertEqual(spy.call_count, 2)

    def test_password_change_after_import_honoured(self):
        with patch.dict(os.environ, {"SOCKS5_PASSWORD": "rotated"}):
            self.assertFalse(self.authenticate(b"alice", b"s3cret"))
            self.connection.reset_mock()
            self.connection.getpeername.return_value = (self.CLIENT_IP, 5555)
            self.assertTrue(self.authenticate(b"alice", b"rotated"))

    def test_failure_log_has_ip_not_username_or_password(self):
        logs = self.assert_rejected(b"mallory", b"guess")
        messages = "\n".join(r.getMessage() for r in logs.records)
        self.assertIn(self.CLIENT_IP, messages)
        for secret in ("mallory", "guess", "s3cret"):
            self.assertNotIn(secret, messages)

    def test_failure_log_survives_disconnected_peer(self):
        self.connection.getpeername.side_effect = OSError("not connected")
        logs = self.assert_rejected(b"mallory", b"guess")
        self.assertIn("unknown", "\n".join(r.getMessage() for r in logs.records))

    def test_success_logs_configured_username_never_password(self):
        with self.assertLogs("src.handlers", level="DEBUG") as logs:
            self.assertTrue(self.authenticate(b"alice", b"s3cret"))
        messages = "\n".join(r.getMessage() for r in logs.records)
        self.assertIn("alice", messages)
        self.assertNotIn("s3cret", messages)

    def test_utf8_password_succeeds(self):
        strip_socks5_env(self, SOCKS5_USERNAME="alice", SOCKS5_PASSWORD="pässwörd")
        self.assertTrue(self.authenticate(b"alice", "pässwörd".encode()))
        self.connection.sendall.assert_called_once_with(RESP_LOGIN_SUCCESS)


class TestAuthEnforcement(unittest.TestCase):
    def setUp(self):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.handler = TCPHandler(self.connection)

    def tearDown(self):
        self.connection.close()

    @patch("src.handlers.tcp.auth_required", return_value=True)
    def test_auth_required_rejects_no_auth_only_client(self, _mock):
        """When auth_required() is True, a client offering only NO_AUTH should be rejected."""
        methods = b"\x00"
        result = self.handler._negotiate_authentication_method(methods)
        self.assertEqual(result, MethodCodes.NO_ACCEPTABLE_METHODS)

    @patch("src.handlers.tcp.auth_required", return_value=True)
    def test_auth_required_accepts_username_password(self, _mock):
        """When auth_required() is True, USERNAME_PASSWORD should still be accepted."""
        methods = b"\x00\x02"
        result = self.handler._negotiate_authentication_method(methods)
        self.assertEqual(result, MethodCodes.USERNAME_PASSWORD)

    @patch("src.handlers.tcp.auth_required", return_value=False)
    def test_default_allows_no_auth(self, _mock):
        """Default behavior (auth_required()=False) should allow NO_AUTH."""
        methods = b"\x00"
        result = self.handler._negotiate_authentication_method(methods)
        self.assertEqual(result, MethodCodes.NO_AUTHENTICATION_REQUIRED)


if __name__ == "__main__":
    unittest.main()
