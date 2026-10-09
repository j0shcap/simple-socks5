import errno
import io
import logging
import os
import socket
import struct
import threading
import unittest
from contextlib import redirect_stderr
from unittest.mock import MagicMock, patch

import pytest

from simple_socks5.constants import AddressTypeCodes, CommandCodes
from simple_socks5.exceptions import (
    AddressTypeNotSupportedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
    PolicyDenied,
)
from simple_socks5.models import BindAddress, DetailedAddress, Request
from simple_socks5.server import TCPProxyServer, ThreadingTCPServer


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

    @patch("simple_socks5.server.TCPHandler")
    def test_invalid_version_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidVersionError(4)

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        # VER=05, REP=01 (general failure), RSV=00, ATYP=01 (IPv4), zeroed addr+port
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("simple_socks5.server.TCPHandler")
    def test_invalid_request_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidRequestError(0xFF)

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("simple_socks5.server.TCPHandler")
    def test_connection_error_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = ConnectionError("closed")

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("simple_socks5.server.TCPHandler")
    def test_socket_error_sends_general_failure(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = OSError("reset")

        handler.handle()

        handler.connection.sendall.assert_called_once()
        reply = handler.connection.sendall.call_args[0][0]
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"


@patch("simple_socks5.server.TCPHandler")
class TestHandshakeDeadline(unittest.TestCase):
    def test_handle_passes_deadline(self, mock_tcp_handler_cls):
        mock_tcp_handler_cls.return_value.handle_request.return_value = False
        with (
            patch.dict(os.environ, {"SOCKS5_HANDSHAKE_TIMEOUT": "2.5"}),
            patch("simple_socks5.server.time.monotonic", return_value=100.0),
        ):
            make_proxy_handler().handle()
        assert mock_tcp_handler_cls.call_args.kwargs["deadline"] == 102.5

    def test_deadline_cleared_before_dispatch(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.return_value = connect_request()
        calls = []
        handler.connection.settimeout.side_effect = lambda t: calls.append(("settimeout", t))
        handler.handle_connect = lambda address: calls.append(("connect", address.port))

        handler.handle()

        assert calls == [("settimeout", None), ("connect", 80)]

    def test_parse_handshake_timeout_sends_nothing(self, mock_tcp_handler_cls):
        handler = make_proxy_handler()
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.side_effect = HandshakeTimeoutError("expired")

        handler.handle()

        handler.connection.sendall.assert_not_called()


@patch("simple_socks5.server.TCPHandler")
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
        assert reply == b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"

    def test_parse_bad_domain_replies_04(self, mock_tcp_handler_cls):
        reply = self.run_handle(mock_tcp_handler_cls, make_proxy_handler(), InvalidDomainNameError(b"\xff"))
        assert reply == b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00"

    def test_connect_errors_map_reply_codes(self, mock_tcp_handler_cls):
        cases = (
            (OSError(errno.ENETUNREACH, "network unreachable"), 0x03),
            (OSError(errno.EHOSTUNREACH, "host unreachable"), 0x04),
            (TimeoutError("timed out"), 0x04),
            (ConnectionRefusedError(), 0x05),
        )
        for exc, code in cases:
            for address_type in (AddressTypeCodes.IPv4, AddressTypeCodes.IPv6):
                with (
                    self.subTest(exc=repr(exc), address_type=address_type.name),
                    patch("simple_socks5.server.TCPRelay", side_effect=exc),
                ):
                    reply = self.run_handle(mock_tcp_handler_cls, make_proxy_handler(), connect_request(address_type))
                    zero_address = b"\x00" * (16 if address_type == AddressTypeCodes.IPv6 else 4)
                    assert reply == bytes([5, code, 0, address_type.value]) + zero_address + b"\x00\x00"


@patch("simple_socks5.server.TCPHandler")
class TestOneReply(unittest.TestCase):
    """Once a reply has been sent, a later failure writes nothing more to the client."""

    SUCCESS_REPLY = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x13\x88"  # 127.0.0.1:5000

    def run_handle(self, mock_tcp_handler_cls, command: CommandCodes, relay_class: str, relay_error: Exception):
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.return_value = Request(5, command.value, connect_request().address)
        handler = make_proxy_handler()
        with patch(relay_class) as relay_cls:
            relay_cls.return_value.get_proxy_address.return_value = BindAddress("127.0.0.1", 5000)
            relay_cls.return_value.listen_and_relay.side_effect = relay_error
            handler.handle()
        return handler

    def test_connect_relay_error_after_success_sends_nothing_more(self, mock_tcp_handler_cls):
        handler = self.run_handle(
            mock_tcp_handler_cls, CommandCodes.CONNECT, "simple_socks5.server.TCPRelay", RuntimeError("boom")
        )
        handler.connection.sendall.assert_called_once_with(self.SUCCESS_REPLY)

    def test_udp_relay_error_after_success_sends_nothing_more(self, mock_tcp_handler_cls):
        handler = self.run_handle(
            mock_tcp_handler_cls,
            CommandCodes.UDP_ASSOCIATE,
            "simple_socks5.server.UDPRelay",
            struct.error("bad datagram"),
        )
        handler.connection.sendall.assert_called_once_with(self.SUCCESS_REPLY)

    def test_success_reply_send_failure_sends_no_failure_reply(self, mock_tcp_handler_cls):
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.return_value = connect_request()
        handler = make_proxy_handler()
        handler.connection.sendall.side_effect = BrokenPipeError
        with patch("simple_socks5.server.TCPRelay") as relay_cls:
            relay_cls.return_value.get_proxy_address.return_value = BindAddress("127.0.0.1", 5000)
            handler.handle()
        handler.connection.sendall.assert_called_once_with(self.SUCCESS_REPLY)
        relay_cls.return_value.listen_and_relay.assert_not_called()

    def test_send_error_reply_twice_sends_once(self, _mock_tcp_handler_cls):
        handler = make_proxy_handler()
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        handler._send_error_reply(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        handler.connection.sendall.assert_called_once_with(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")


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


@patch("simple_socks5.server.TCPHandler")
class TestDisconnectLogging(unittest.TestCase):
    """A client hanging up is DEBUG without a traceback; an unexpected exception is ERROR with one."""

    def run_handle(self, mock_tcp_handler_cls, parse_result=None, handshake_ok=True) -> TCPProxyServer:
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = handshake_ok
        if isinstance(parse_result, Exception):
            mock_instance.parse_request.side_effect = parse_result
        else:
            mock_instance.parse_request.return_value = parse_result
        handler = make_proxy_handler()
        handler.handle()
        return handler

    def assert_debug_only(self, logs):
        assert not [r for r in logs.records if r.exc_info or r.levelno > logging.DEBUG]

    def test_failed_handshake_logs_debug(self, mock_tcp_handler_cls):
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            self.run_handle(mock_tcp_handler_cls, handshake_ok=False)
        self.assert_debug_only(logs)

    def test_parse_disconnect_logs_debug(self, mock_tcp_handler_cls):
        for error in (ConnectionError("Connection closed during recv"), ConnectionResetError("reset")):
            with self.subTest(error=repr(error)), self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
                self.run_handle(mock_tcp_handler_cls, error)
            self.assert_debug_only(logs)

    def test_parse_protocol_error_logs_error_without_traceback(self, mock_tcp_handler_cls):
        with self.assertLogs("simple_socks5.server", level="ERROR") as logs:
            self.run_handle(mock_tcp_handler_cls, InvalidVersionError(4))
        assert not logs.records[0].exc_info

    def test_parse_unexpected_error_logs_traceback_and_replies(self, mock_tcp_handler_cls):
        with self.assertLogs("simple_socks5.server", level="ERROR") as logs:
            handler = self.run_handle(mock_tcp_handler_cls, RuntimeError("bug"))
        assert logs.records[0].exc_info
        handler.connection.sendall.assert_called_once_with(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_connect_unexpected_error_logs_traceback(self, mock_tcp_handler_cls):
        with (
            patch("simple_socks5.server.TCPRelay", side_effect=RuntimeError("bug")),
            self.assertLogs("simple_socks5.server", level="ERROR") as logs,
        ):
            self.run_handle(mock_tcp_handler_cls, connect_request())
        assert logs.records[0].exc_info

    def test_connect_refused_logs_error_without_traceback(self, mock_tcp_handler_cls):
        with (
            patch("simple_socks5.server.TCPRelay", side_effect=ConnectionRefusedError("refused")),
            self.assertLogs("simple_socks5.server", level="ERROR") as logs,
        ):
            self.run_handle(mock_tcp_handler_cls, connect_request())
        assert not logs.records[0].exc_info

    def test_client_gone_before_success_reply_logs_debug(self, mock_tcp_handler_cls):
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.return_value = connect_request()
        handler = make_proxy_handler()
        handler.connection.sendall.side_effect = BrokenPipeError("broken pipe")
        with (
            patch("simple_socks5.server.TCPRelay") as relay_cls,
            self.assertLogs("simple_socks5.server", level="DEBUG") as logs,
        ):
            relay_cls.return_value.get_proxy_address.return_value = BindAddress("127.0.0.1", 5000)
            handler.handle()
        # Only the CONNECTION line, which is logged before the reply
        assert not [r for r in logs.records if r.exc_info or r.levelno > logging.INFO]

    def test_error_reply_to_departed_client_logs_debug(self, _mock_tcp_handler_cls):
        handler = make_proxy_handler()
        handler.connection.sendall.side_effect = BrokenPipeError("broken pipe")
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        self.assert_debug_only(logs)

    def test_error_reply_unexpected_oserror_logs_error(self, _mock_tcp_handler_cls):
        handler = make_proxy_handler()
        handler.connection.sendall.side_effect = OSError(errno.EBADF, "bad file descriptor")
        with self.assertLogs("simple_socks5.server", level="ERROR"):
            handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")


class TestHandleError(unittest.TestCase):
    """Exceptions escaping a handler go through logging (and so respect -L), never straight to stderr."""

    def setUp(self):
        self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)

    def handle_error(self, error: Exception):
        stderr = io.StringIO()
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs, redirect_stderr(stderr):
            try:
                raise error
            except Exception:
                self.server.handle_error(MagicMock(), ("203.0.113.5", 40000))
        assert stderr.getvalue() == ""
        return logs.records

    def test_routine_disconnect_logs_debug(self):
        for error in (ConnectionResetError("reset"), OSError(errno.ENOTCONN, "not connected")):
            with self.subTest(error=repr(error)):
                records = self.handle_error(error)
                assert [(r.levelno, bool(r.exc_info)) for r in records] == [(logging.DEBUG, False)]

    def test_protocol_error_logs_error_without_traceback(self):
        records = self.handle_error(InvalidVersionError(4))
        assert [(r.levelno, bool(r.exc_info)) for r in records] == [(logging.ERROR, False)]

    def test_unexpected_error_logs_traceback(self):
        records = self.handle_error(RuntimeError("bug"))
        assert [(r.levelno, bool(r.exc_info)) for r in records] == [(logging.ERROR, True)]
        assert "203.0.113.5" in records[0].getMessage()


class TestListenBacklog(unittest.TestCase):
    def test_listens_with_somaxconn_backlog(self):
        server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(server.server_close)
        server.socket = MagicMock(spec=socket.socket)
        server.server_activate()
        server.socket.listen.assert_called_once_with(socket.SOMAXCONN)


def _without_socks5_env(**environ):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
    return patch.dict(os.environ, {**clean, **environ}, clear=True)


class TestConnectionLimit(unittest.TestCase):
    def make_server(self, **environ) -> ThreadingTCPServer:
        with _without_socks5_env(**environ):
            server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(server.server_close)
        return server

    def test_default_limit_is_200(self):
        assert self.make_server().max_connections == 200

    def test_limit_read_from_env(self):
        server = self.make_server(SOCKS5_MAX_CONNECTIONS="3")
        assert server.max_connections == 3
        for _ in range(3):
            assert server._connection_semaphore.acquire(blocking=False)
        assert not server._connection_semaphore.acquire(blocking=False)

    def test_instances_have_distinct_semaphores(self):
        first, second = self.make_server(SOCKS5_MAX_CONNECTIONS="1"), self.make_server(SOCKS5_MAX_CONNECTIONS="1")
        assert first._connection_semaphore.acquire(blocking=False)
        assert second._connection_semaphore.acquire(blocking=False)

    def test_invalid_limit_raises_before_binding(self):
        with _without_socks5_env(SOCKS5_MAX_CONNECTIONS="0"), patch("socketserver.socket.socket") as socket_class:
            with pytest.raises(ValueError, match="SOCKS5_MAX_CONNECTIONS"):
                ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer)
        socket_class.assert_not_called()

    def test_rejection_warning_rate_limited(self):
        server = self.make_server(SOCKS5_MAX_CONNECTIONS="1")
        assert server._connection_semaphore.acquire(blocking=False)
        now = [0.0]

        def reject(count):
            for _ in range(count):
                server.process_request(MagicMock(spec=socket.socket), ("127.0.0.1", 9999))

        with (
            patch("simple_socks5.server.time.monotonic", lambda: now[0]),
            patch.object(server, "shutdown_request") as shutdown_request,
            self.assertLogs("simple_socks5.server", level="WARNING") as logs,
        ):
            reject(50)
            assert len(logs.records) == 1
            assert "Connection limit of 1 reached: rejected 1 connection(s)" in logs.records[0].getMessage()

            now[0] = 5.0
            reject(4)
            assert len(logs.records) == 1

            now[0] = 10.0
            reject(1)
            assert len(logs.records) == 2
            assert "rejected 54 connection(s)" in logs.records[1].getMessage()

        assert shutdown_request.call_count == 55


class TestPolicyDenial(unittest.TestCase):
    def setUp(self):
        with _without_socks5_env():
            self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)
        self.dst = DetailedAddress(name="localhost", ip="127.0.0.1", port=80, address_type=AddressTypeCodes.IPv4)

    @patch("simple_socks5.server.TCPHandler")
    def test_policy_denied_sends_rep_02_without_error_log(self, mock_tcp_handler_cls):
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.return_value = Request(5, CommandCodes.CONNECT.value, self.dst)
        handler = make_proxy_handler()
        handler.server = self.server
        with (
            patch("simple_socks5.server.TCPRelay", side_effect=PolicyDenied("127.0.0.1", 80)),
            self.assertLogs("simple_socks5", level="DEBUG") as logs,
        ):
            handler.handle()
        handler.connection.sendall.assert_called_once_with(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        assert "ERROR" not in [r.levelname for r in logs.records]
        assert all(r.exc_info is None for r in logs.records)

    def test_first_policy_denial_warns_with_client_dst_and_env_var(self):
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            self.server.log_policy_denial("192.0.2.7", self.dst)
        assert len(logs.records) == 1
        assert logs.records[0].levelname == "WARNING"
        message = logs.records[0].getMessage()
        assert "192.0.2.7 -> localhost:80 (127.0.0.1)" in message
        assert "SOCKS5_ALLOW_LOOPBACK=true" in message
        assert "more denied" not in message

    def test_policy_warning_rate_limited_with_suppressed_count(self):
        now = [0.0]
        with (
            patch("simple_socks5.server.time.monotonic", lambda: now[0]),
            self.assertLogs("simple_socks5.server", level="DEBUG") as logs,
        ):
            for _ in range(50):
                self.server.log_policy_denial("192.0.2.7", self.dst)
            now[0] = 9.9
            self.server.log_policy_denial("192.0.2.8", self.dst)
            now[0] = 10.0
            self.server.log_policy_denial("192.0.2.9", self.dst)

        levels = [r.levelname for r in logs.records]
        assert levels == ["WARNING"] + ["DEBUG"] * 50 + ["WARNING"]
        assert "192.0.2.9 -> " in logs.records[-1].getMessage()
        assert "(50 more denied since the last warning)" in logs.records[-1].getMessage()


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

        with (
            patch("socketserver.ThreadingMixIn.process_request", start_handler),
            patch("socketserver.ThreadingMixIn.process_request_thread", handle),
        ):
            self.server.process_request(request, ("127.0.0.1", 9999))

    def test_request_tracked_before_handler_thread_runs(self):
        # A shutdown that drains right after serve_forever() returns must see a request whose handler
        # thread has started but not yet run.
        with patch("socketserver.ThreadingMixIn.process_request"):
            self.server.process_request(MagicMock(spec=socket.socket), ("127.0.0.1", 9999))
        assert not self.server.wait_for_connections(0)

    def test_request_untracked_when_handler_thread_fails_to_start(self):
        with patch("socketserver.ThreadingMixIn.process_request", side_effect=RuntimeError("can't start thread")):
            with pytest.raises(RuntimeError):
                self.server.process_request(MagicMock(spec=socket.socket), ("127.0.0.1", 9999))
        assert self.server.wait_for_connections(0)
        self.server._connection_semaphore.release.assert_called_once()

    def test_request_tracked_during_handling_and_removed_after(self):
        request = MagicMock(spec=socket.socket)
        seen = []
        self._process(request, during=lambda: seen.append(self.server.close_connections()))
        assert seen == [1]
        assert self.server.close_connections() == 0

    def test_semaphore_still_released(self):
        self._process(MagicMock(spec=socket.socket))
        self.server._connection_semaphore.release.assert_called_once()

    def test_request_removed_when_handling_raises(self):
        request = MagicMock(spec=socket.socket)
        with patch("socketserver.ThreadingMixIn.process_request"):
            self.server.process_request(request, ("127.0.0.1", 9999))
        with patch("socketserver.ThreadingMixIn.process_request_thread", side_effect=RuntimeError("handler failed")):
            with pytest.raises(RuntimeError):
                self.server.process_request_thread(request, ("127.0.0.1", 9999))
        assert self.server.wait_for_connections(0)
        self.server._connection_semaphore.release.assert_called_once()

    def test_wait_returns_true_when_idle(self):
        assert self.server.wait_for_connections(0)

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

        assert not self.server.wait_for_connections(0.01)
        release.set()
        assert self.server.wait_for_connections(5)

    def test_close_connections_shuts_down_each_and_counts(self):
        requests = [MagicMock(spec=socket.socket), MagicMock(spec=socket.socket)]
        counts = []

        def process_both(remaining):
            if remaining:
                self._process(remaining[0], during=lambda: process_both(remaining[1:]))
            else:
                counts.append(self.server.close_connections())

        process_both(requests)
        assert counts == [2]
        for request in requests:
            request.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            request.close.assert_not_called()

    def test_close_connections_skips_already_closed_socket(self):
        closed, live = MagicMock(spec=socket.socket), MagicMock(spec=socket.socket)
        closed.shutdown.side_effect = OSError("Bad file descriptor")
        counts = []
        self._process(
            closed, during=lambda: self._process(live, during=lambda: counts.append(self.server.close_connections()))
        )
        assert counts == [1]
        live.shutdown.assert_called_once_with(socket.SHUT_RDWR)


if __name__ == "__main__":
    unittest.main()
