import errno
import os
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from src.constants import AddressTypeCodes, CommandCodes
from src.exceptions import (
    AddressTypeNotSupportedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
)
from src.models import DetailedAddress, Request
from src.server import TCPProxyServer, ThreadingTCPServer


def make_proxy_handler() -> TCPProxyServer:
    """Create a TCPProxyServer without actually binding a socket."""
    handler = object.__new__(TCPProxyServer)
    handler.connection = MagicMock(spec=socket.socket)
    handler.connection.getpeername.return_value = ("127.0.0.1", 9999)
    handler.request = handler.connection
    handler.server = MagicMock()
    return handler


def connect_request(address_type: AddressTypeCodes = AddressTypeCodes.IPv4) -> Request:
    ip = "::1" if address_type == AddressTypeCodes.IPv6 else "127.0.0.1"
    address = DetailedAddress(name=ip, ip=ip, port=80, address_type=address_type)
    return Request(version=5, command=CommandCodes.CONNECT.value, address=address)


class TestHandleParseRequestErrors(unittest.TestCase):
    """Verify parse_request() exceptions produce SOCKS5 error replies."""

    @patch("src.server.TCPHandler")
    def test_invalid_version_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidVersionError(4)

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        # VER=05, REP=01 (general failure), RSV=00, ATYP=01 (IPv4), zeroed addr+port
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    @patch("src.server.TCPHandler")
    def test_invalid_request_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidRequestError(0xFF)

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    @patch("src.server.TCPHandler")
    def test_connection_error_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = ConnectionError("closed")

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    @patch("src.server.TCPHandler")
    def test_socket_error_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = socket.error("reset")

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")


@patch("src.server.TCPHandler")
class TestHandshakeDeadline(unittest.TestCase):
    def test_handle_passes_deadline(self, mock_tcp_handler_cls):
        mock_tcp_handler_cls.return_value.handle_request.return_value = False
        with patch.dict(os.environ, {"SOCKS5_HANDSHAKE_TIMEOUT": "2.5"}), \
                patch("src.server.time.monotonic", return_value=100.0):
            make_proxy_handler().handle()
        self.assertEqual(mock_tcp_handler_cls.call_args.kwargs["deadline"], 102.5)

    def test_deadline_cleared_before_dispatch(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.return_value = connect_request()
        calls = []
        handler.connection.settimeout.side_effect = lambda t: calls.append(("settimeout", t))
        handler.handle_connect = lambda address: calls.append(("connect", address.port))

        handler.handle()

        self.assertEqual(calls, [("settimeout", None), ("connect", 80)])

    def test_parse_handshake_timeout_sends_nothing(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.side_effect = HandshakeTimeoutError("expired")

        handler.handle()

        handler.connection.sendall.assert_not_called()


@patch("src.server.TCPHandler")
class TestReplyCodes(unittest.TestCase):
    """Each failure sends exactly one reply, with the code reply_code_for() picks."""

    def run_handle(self, mock_tcp_handler_cls, handler, parse_result):
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        if isinstance(parse_result, Exception):
            mock_instance.parse_request.side_effect = parse_result
        else:
            mock_instance.parse_request.return_value = parse_result
        handler.handle()
        handler.connection.sendall.assert_called_once()
        return handler.connection.sendall.call_args[0][0]

    def test_parse_bad_atyp_replies_08(self, mock_tcp_handler_cls):
        reply = self.run_handle(mock_tcp_handler_cls, make_proxy_handler(), AddressTypeNotSupportedError(5))
        self.assertEqual(reply, b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_parse_bad_domain_replies_04(self, mock_tcp_handler_cls):
        reply = self.run_handle(mock_tcp_handler_cls, make_proxy_handler(), InvalidDomainNameError(b"\xff"))
        self.assertEqual(reply, b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_connect_errors_map_reply_codes(self, mock_tcp_handler_cls):
        cases = (
            (OSError(errno.ENETUNREACH, "network unreachable"), 0x03),
            (OSError(errno.EHOSTUNREACH, "host unreachable"), 0x04),
            (TimeoutError("timed out"), 0x04),
            (ConnectionRefusedError(), 0x05),
        )
        for exc, code in cases:
            for address_type in (AddressTypeCodes.IPv4, AddressTypeCodes.IPv6):
                with self.subTest(exc=repr(exc), address_type=address_type.name), \
                        patch("src.server.TCPRelay", side_effect=exc):
                    reply = self.run_handle(mock_tcp_handler_cls, make_proxy_handler(), connect_request(address_type))
                    zero_address = b"\x00" * (16 if address_type == AddressTypeCodes.IPv6 else 4)
                    self.assertEqual(reply, bytes([5, code, 0, address_type.value]) + zero_address + b"\x00\x00")


class TestSendErrorReply(unittest.TestCase):
    """Verify _send_error_reply swallows all OSError subclasses."""

    def _make_handler(self):
        handler = object.__new__(TCPProxyServer)
        handler.connection = MagicMock(spec=socket.socket)
        return handler

    def test_swallows_broken_pipe(self):
        handler = self._make_handler()
        handler.connection.sendall.side_effect = BrokenPipeError
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_swallows_connection_reset(self):
        handler = self._make_handler()
        handler.connection.sendall.side_effect = ConnectionResetError
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_swallows_generic_oserror(self):
        handler = self._make_handler()
        handler.connection.sendall.side_effect = OSError("transport endpoint closed")
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")


class TestConnectionTracking(unittest.TestCase):
    """Verify ThreadingTCPServer tracks in-flight requests so shutdown can drain or close them."""

    def setUp(self):
        self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)
        self.server._connection_semaphore = MagicMock()

    def _process(self, request, during=lambda: None):
        """Accepts request and runs its handler synchronously instead of on a new thread."""
        def start_handler(server, request, client_address):
            server.process_request_thread(request, client_address)

        def handle(server, request, client_address):
            during()

        with patch("socketserver.ThreadingMixIn.process_request", start_handler), \
                patch("socketserver.ThreadingMixIn.process_request_thread", handle):
            self.server.process_request(request, ("127.0.0.1", 9999))

    def test_request_tracked_before_handler_thread_runs(self):
        # A shutdown that drains right after serve_forever() returns must see a request whose handler
        # thread has started but not yet run.
        with patch("socketserver.ThreadingMixIn.process_request"):
            self.server.process_request(MagicMock(spec=socket.socket), ("127.0.0.1", 9999))
        self.assertFalse(self.server.wait_for_connections(0))

    def test_request_untracked_when_handler_thread_fails_to_start(self):
        with patch("socketserver.ThreadingMixIn.process_request", side_effect=RuntimeError("can't start thread")):
            with self.assertRaises(RuntimeError):
                self.server.process_request(MagicMock(spec=socket.socket), ("127.0.0.1", 9999))
        self.assertTrue(self.server.wait_for_connections(0))
        self.server._connection_semaphore.release.assert_called_once()

    def test_request_tracked_during_handling_and_removed_after(self):
        request = MagicMock(spec=socket.socket)
        seen = []
        self._process(request, during=lambda: seen.append(self.server.close_connections()))
        self.assertEqual(seen, [1])
        self.assertEqual(self.server.close_connections(), 0)

    def test_semaphore_still_released(self):
        self._process(MagicMock(spec=socket.socket))
        self.server._connection_semaphore.release.assert_called_once()

    def test_request_removed_when_handling_raises(self):
        request = MagicMock(spec=socket.socket)
        with patch("socketserver.ThreadingMixIn.process_request"):
            self.server.process_request(request, ("127.0.0.1", 9999))
        with patch("socketserver.ThreadingMixIn.process_request_thread", side_effect=RuntimeError("handler failed")):
            with self.assertRaises(RuntimeError):
                self.server.process_request_thread(request, ("127.0.0.1", 9999))
        self.assertTrue(self.server.wait_for_connections(0))
        self.server._connection_semaphore.release.assert_called_once()

    def test_wait_returns_true_when_idle(self):
        self.assertTrue(self.server.wait_for_connections(0))

    def test_wait_returns_false_on_timeout(self):
        started, release = threading.Event(), threading.Event()

        def hold():
            started.set()
            release.wait(5)

        worker = threading.Thread(target=self._process, args=(MagicMock(spec=socket.socket), hold))
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(release.set)
        started.wait(5)

        self.assertFalse(self.server.wait_for_connections(0.01))
        release.set()
        self.assertTrue(self.server.wait_for_connections(5))

    def test_close_connections_shuts_down_each_and_counts(self):
        requests = [MagicMock(spec=socket.socket), MagicMock(spec=socket.socket)]
        counts = []

        def process_both(remaining):
            if remaining:
                self._process(remaining[0], during=lambda: process_both(remaining[1:]))
            else:
                counts.append(self.server.close_connections())

        process_both(requests)
        self.assertEqual(counts, [2])
        for request in requests:
            request.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            request.close.assert_not_called()

    def test_close_connections_skips_already_closed_socket(self):
        closed, live = MagicMock(spec=socket.socket), MagicMock(spec=socket.socket)
        closed.shutdown.side_effect = OSError("Bad file descriptor")
        counts = []
        self._process(closed, during=lambda: self._process(
            live, during=lambda: counts.append(self.server.close_connections())))
        self.assertEqual(counts, [1])
        live.shutdown.assert_called_once_with(socket.SHUT_RDWR)


if __name__ == "__main__":
    unittest.main()
