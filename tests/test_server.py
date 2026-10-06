import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from src.exceptions import InvalidVersionError, InvalidRequestError
from src.server import TCPProxyServer, ThreadingTCPServer


class TestHandleParseRequestErrors(unittest.TestCase):
    """Verify parse_request() exceptions produce SOCKS5 error replies."""

    def _make_handler(self):
        """Create a TCPProxyServer without actually binding a socket."""
        handler = object.__new__(TCPProxyServer)
        handler.connection = MagicMock(spec=socket.socket)
        handler.connection.getpeername.return_value = ("127.0.0.1", 9999)
        handler.request = handler.connection
        handler.server = MagicMock()
        return handler

    @patch("src.server.TCPHandler")
    def test_invalid_version_sends_general_failure(self, mock_tcp_handler_cls):
        handler = self._make_handler()
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
        handler = self._make_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidRequestError(0xFF)

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    @patch("src.server.TCPHandler")
    def test_connection_error_sends_general_failure(self, mock_tcp_handler_cls):
        handler = self._make_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = ConnectionError("closed")

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    @patch("src.server.TCPHandler")
    def test_socket_error_sends_general_failure(self, mock_tcp_handler_cls):
        handler = self._make_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = socket.error("reset")

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        self.assertEqual(reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")


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
        def handle(server, request, client_address):
            during()

        with patch("socketserver.ThreadingMixIn.process_request_thread", handle):
            self.server.process_request_thread(request, ("127.0.0.1", 9999))

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
        def fail():
            raise RuntimeError("handler failed")

        with self.assertRaises(RuntimeError):
            self._process(MagicMock(spec=socket.socket), during=fail)
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
