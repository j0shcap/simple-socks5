import errno
import io
import logging
import os
import socket
import struct
import threading
import unittest
from collections.abc import Callable
from contextlib import AbstractContextManager, redirect_stderr
from unittest.mock import MagicMock, NonCallableMagicMock, create_autospec, patch

import pytest

from simple_socks5.constants import (
    AUTH_FAILED_WARNING_INTERVAL,
    CONNECTION_LIMIT_WARNING_INTERVAL,
    HANDSHAKE_TIMEOUT_WARNING_INTERVAL,
    POLICY_DENIED_WARNING_INTERVAL,
    AddressTypeCodes,
    CommandCodes,
)
from simple_socks5.exceptions import (
    AddressTypeNotSupportedError,
    AuthenticationFailedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
    PolicyDeniedError,
)
from simple_socks5.models import BindAddress, DetailedAddress, Request
from simple_socks5.server import TCPProxyServer, ThreadingTCPServer
from simple_socks5.utils import WarningRateLimiter


def make_proxy_handler() -> tuple[TCPProxyServer, NonCallableMagicMock]:
    """Creates a TCPProxyServer without actually binding a socket. Returns it and its client connection mock."""
    connection: NonCallableMagicMock = create_autospec(socket.socket, instance=True)
    connection.getpeername.return_value = ("127.0.0.1", 9999)
    handler = object.__new__(TCPProxyServer)
    handler.connection = connection
    handler.request = connection
    handler.client_address = ("127.0.0.1", 9999)
    handler.server = create_autospec(ThreadingTCPServer, instance=True)
    return handler, connection


def connect_request(address_type: AddressTypeCodes = AddressTypeCodes.IPv4) -> Request:
    ip = "::1" if address_type == AddressTypeCodes.IPv6 else "127.0.0.1"
    address = DetailedAddress(name=ip, ip=ip, port=80, address_type=address_type)
    return Request(version=5, command=CommandCodes.CONNECT.value, address=address)


class TestHandleParseRequestErrors(unittest.TestCase):
    """Verify parse_request() exceptions produce SOCKS5 error replies."""

    @patch("simple_socks5.server.TCPHandler", autospec=True)
    def test_invalid_version_sends_general_failure(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidVersionError(4)

        handler.handle()

        connection.sendall.assert_called_once()
        reply = connection.sendall.call_args[0][0]
        # VER=05, REP=01 (general failure), RSV=00, ATYP=01 (IPv4), zeroed addr+port
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("simple_socks5.server.TCPHandler", autospec=True)
    def test_invalid_request_sends_general_failure(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = InvalidRequestError(0xFF)

        handler.handle()

        connection.sendall.assert_called_once()
        reply = connection.sendall.call_args[0][0]
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("simple_socks5.server.TCPHandler", autospec=True)
    def test_connection_error_sends_general_failure(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = ConnectionError("closed")

        handler.handle()

        connection.sendall.assert_called_once()
        reply = connection.sendall.call_args[0][0]
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("simple_socks5.server.TCPHandler", autospec=True)
    def test_socket_error_sends_general_failure(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.side_effect = OSError("reset")

        handler.handle()

        connection.sendall.assert_called_once()
        reply = connection.sendall.call_args[0][0]
        assert reply == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"


@patch("simple_socks5.server.TCPHandler", autospec=True)
class TestHandshakeDeadline(unittest.TestCase):
    def test_handle_passes_deadline(self, mock_tcp_handler_cls: MagicMock) -> None:
        mock_tcp_handler_cls.return_value.handle_request.return_value = False
        with (
            patch.dict(os.environ, {"SOCKS5_HANDSHAKE_TIMEOUT": "2.5"}),
            patch("simple_socks5.server.time.monotonic", autospec=True, return_value=100.0),
        ):
            make_proxy_handler()[0].handle()
        assert mock_tcp_handler_cls.call_args.kwargs["deadline"] == 102.5

    def test_deadline_cleared_before_dispatch(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.return_value = connect_request()
        calls: list[tuple[str, float | None]] = []
        connection.settimeout.side_effect = lambda t: calls.append(("settimeout", t))
        with patch.object(
            handler,
            "handle_connect",
            autospec=True,
            side_effect=lambda address: calls.append(("connect", address.port)),
        ):
            handler.handle()

        assert calls == [("settimeout", None), ("connect", 80)]

    def test_parse_handshake_timeout_sends_nothing(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        handler.server = server = create_autospec(ThreadingTCPServer, instance=True)
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.side_effect = HandshakeTimeoutError("expired")

        handler.handle()

        connection.sendall.assert_not_called()
        server.log_handshake_timeout.assert_called_once_with("127.0.0.1", "waiting for the request")

    def test_greeting_timeout_logged_by_server_and_closed(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        handler.server = server = create_autospec(ThreadingTCPServer, instance=True)
        mock_tcp_handler_cls.return_value.handle_request.side_effect = HandshakeTimeoutError("expired")

        handler.handle()

        connection.sendall.assert_not_called()
        mock_tcp_handler_cls.return_value.parse_request.assert_not_called()
        server.log_handshake_timeout.assert_called_once_with("127.0.0.1", "during the greeting or authentication")
        server.shutdown_request.assert_called_once_with(connection)


@patch("simple_socks5.server.TCPHandler", autospec=True)
class TestReplyCodes(unittest.TestCase):
    """Each failure sends exactly one reply, with the code reply_code_for() picks."""

    def run_handle(self, mock_tcp_handler_cls: MagicMock, parse_result: Request | Exception) -> bytes:
        handler, connection = make_proxy_handler()
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        if isinstance(parse_result, Exception):
            mock_instance.parse_request.side_effect = parse_result
        else:
            mock_instance.parse_request.return_value = parse_result
        handler.handle()
        connection.sendall.assert_called_once()
        reply: bytes = connection.sendall.call_args[0][0]
        return reply

    def test_parse_bad_atyp_replies_08(self, mock_tcp_handler_cls: MagicMock) -> None:
        reply = self.run_handle(mock_tcp_handler_cls, AddressTypeNotSupportedError(5))
        assert reply == b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"

    def test_parse_bad_domain_replies_04(self, mock_tcp_handler_cls: MagicMock) -> None:
        reply = self.run_handle(mock_tcp_handler_cls, InvalidDomainNameError(b"\xff"))
        assert reply == b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00"

    def test_connect_errors_map_reply_codes(self, mock_tcp_handler_cls: MagicMock) -> None:
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
                    patch("simple_socks5.server.TCPRelay", autospec=True, side_effect=exc),
                ):
                    reply = self.run_handle(mock_tcp_handler_cls, connect_request(address_type))
                    zero_address = b"\x00" * (16 if address_type == AddressTypeCodes.IPv6 else 4)
                    assert reply == bytes([5, code, 0, address_type.value]) + zero_address + b"\x00\x00"


@patch("simple_socks5.server.TCPHandler", autospec=True)
class TestOneReply(unittest.TestCase):
    """Once a reply has been sent, a later failure writes nothing more to the client."""

    SUCCESS_REPLY = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x13\x88"  # 127.0.0.1:5000

    def run_handle(
        self, mock_tcp_handler_cls: MagicMock, command: CommandCodes, relay_class: str, relay_error: Exception
    ) -> NonCallableMagicMock:
        """Returns the client connection mock."""
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.return_value = Request(5, command.value, connect_request().address)
        handler, connection = make_proxy_handler()
        with patch(relay_class, autospec=True) as relay_cls:
            relay_cls.return_value.get_proxy_address.return_value = BindAddress("127.0.0.1", 5000)
            relay_cls.return_value.listen_and_relay.side_effect = relay_error
            handler.handle()
        return connection

    def test_connect_relay_error_after_success_sends_nothing_more(self, mock_tcp_handler_cls: MagicMock) -> None:
        connection = self.run_handle(
            mock_tcp_handler_cls, CommandCodes.CONNECT, "simple_socks5.server.TCPRelay", RuntimeError("boom")
        )
        connection.sendall.assert_called_once_with(self.SUCCESS_REPLY)

    def test_udp_relay_error_after_success_sends_nothing_more(self, mock_tcp_handler_cls: MagicMock) -> None:
        connection = self.run_handle(
            mock_tcp_handler_cls,
            CommandCodes.UDP_ASSOCIATE,
            "simple_socks5.server.UDPRelay",
            struct.error("bad datagram"),
        )
        connection.sendall.assert_called_once_with(self.SUCCESS_REPLY)

    def test_success_reply_send_failure_sends_no_failure_reply(self, mock_tcp_handler_cls: MagicMock) -> None:
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.return_value = connect_request()
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = BrokenPipeError
        with patch("simple_socks5.server.TCPRelay", autospec=True) as relay_cls:
            relay_cls.return_value.get_proxy_address.return_value = BindAddress("127.0.0.1", 5000)
            handler.handle()
        connection.sendall.assert_called_once_with(self.SUCCESS_REPLY)
        relay_cls.return_value.listen_and_relay.assert_not_called()


class TestSendErrorReply(unittest.TestCase):
    """_send_error_reply sends at most one reply and swallows every OSError, logging it at the right level."""

    def test_swallows_broken_pipe(self) -> None:
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = BrokenPipeError
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_swallows_connection_reset(self) -> None:
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = ConnectionResetError
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_swallows_generic_oserror(self) -> None:
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = OSError("transport endpoint closed")
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_send_error_reply_twice_sends_once(self) -> None:
        handler, connection = make_proxy_handler()
        handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        handler._send_error_reply(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        connection.sendall.assert_called_once_with(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_error_reply_to_departed_client_logs_debug(self) -> None:
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = BrokenPipeError("broken pipe")
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        assert not [r for r in logs.records if r.exc_info or r.levelno > logging.DEBUG]

    def test_error_reply_unexpected_oserror_logs_error(self) -> None:
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = OSError(errno.EBADF, "bad file descriptor")
        with self.assertLogs("simple_socks5.server", level="ERROR"):
            handler._send_error_reply(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")


@patch("simple_socks5.server.TCPHandler", autospec=True)
class TestDisconnectLogging(unittest.TestCase):
    """A client hanging up is DEBUG without a traceback; an unexpected exception is ERROR with one."""

    def run_handle(
        self,
        mock_tcp_handler_cls: MagicMock,
        parse_result: Request | Exception | None = None,
        handshake_ok: bool = True,
    ) -> NonCallableMagicMock:
        """Returns the client connection mock."""
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = handshake_ok
        if isinstance(parse_result, Exception):
            mock_instance.parse_request.side_effect = parse_result
        else:
            mock_instance.parse_request.return_value = parse_result
        handler, connection = make_proxy_handler()
        handler.handle()
        return connection

    def assert_debug_only(self, records: list[logging.LogRecord]) -> None:
        assert not [r for r in records if r.exc_info or r.levelno > logging.DEBUG]

    def test_failed_handshake_logs_debug(self, mock_tcp_handler_cls: MagicMock) -> None:
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            self.run_handle(mock_tcp_handler_cls, handshake_ok=False)
        self.assert_debug_only(logs.records)

    def test_parse_disconnect_logs_debug(self, mock_tcp_handler_cls: MagicMock) -> None:
        for error in (ConnectionError("Connection closed during recv"), ConnectionResetError("reset")):
            with self.subTest(error=repr(error)), self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
                self.run_handle(mock_tcp_handler_cls, error)
            self.assert_debug_only(logs.records)

    def test_parse_protocol_error_logs_error_without_traceback(self, mock_tcp_handler_cls: MagicMock) -> None:
        with self.assertLogs("simple_socks5.server", level="ERROR") as logs:
            self.run_handle(mock_tcp_handler_cls, InvalidVersionError(4))
        assert not logs.records[0].exc_info

    def test_parse_unexpected_error_logs_traceback_and_replies(self, mock_tcp_handler_cls: MagicMock) -> None:
        with self.assertLogs("simple_socks5.server", level="ERROR") as logs:
            connection = self.run_handle(mock_tcp_handler_cls, RuntimeError("bug"))
        assert logs.records[0].exc_info
        connection.sendall.assert_called_once_with(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_connect_unexpected_error_logs_traceback(self, mock_tcp_handler_cls: MagicMock) -> None:
        with (
            patch("simple_socks5.server.TCPRelay", autospec=True, side_effect=RuntimeError("bug")),
            self.assertLogs("simple_socks5.server", level="ERROR") as logs,
        ):
            self.run_handle(mock_tcp_handler_cls, connect_request())
        assert logs.records[0].exc_info

    def test_connect_refused_logs_error_without_traceback(self, mock_tcp_handler_cls: MagicMock) -> None:
        with (
            patch("simple_socks5.server.TCPRelay", autospec=True, side_effect=ConnectionRefusedError("refused")),
            self.assertLogs("simple_socks5.server", level="ERROR") as logs,
        ):
            self.run_handle(mock_tcp_handler_cls, connect_request())
        assert not logs.records[0].exc_info

    def test_client_gone_before_success_reply_logs_debug(self, mock_tcp_handler_cls: MagicMock) -> None:
        mock_instance = mock_tcp_handler_cls.return_value
        mock_instance.handle_request.return_value = True
        mock_instance.parse_request.return_value = connect_request()
        handler, connection = make_proxy_handler()
        connection.sendall.side_effect = BrokenPipeError("broken pipe")
        with (
            patch("simple_socks5.server.TCPRelay", autospec=True) as relay_cls,
            self.assertLogs("simple_socks5.server", level="DEBUG") as logs,
        ):
            relay_cls.return_value.get_proxy_address.return_value = BindAddress("127.0.0.1", 5000)
            handler.handle()
        # Only the CONNECTION line, which is logged before the reply
        assert not [r for r in logs.records if r.exc_info or r.levelno > logging.INFO]


class TestHandleError(unittest.TestCase):
    """Exceptions escaping a handler go through logging (and so respect -L), never straight to stderr."""

    def setUp(self) -> None:
        self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)

    def handle_error(self, error: Exception) -> list[logging.LogRecord]:
        stderr = io.StringIO()
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs, redirect_stderr(stderr):
            try:
                raise error
            except type(error):
                self.server.handle_error(create_autospec(socket.socket, instance=True), ("203.0.113.5", 40000))
        assert stderr.getvalue() == ""
        return logs.records

    def test_routine_disconnect_logs_debug(self) -> None:
        for error in (ConnectionResetError("reset"), OSError(errno.ENOTCONN, "not connected")):
            with self.subTest(error=repr(error)):
                records = self.handle_error(error)
                assert [(r.levelno, bool(r.exc_info)) for r in records] == [(logging.DEBUG, False)]

    def test_protocol_error_logs_error_without_traceback(self) -> None:
        records = self.handle_error(InvalidVersionError(4))
        assert [(r.levelno, bool(r.exc_info)) for r in records] == [(logging.ERROR, False)]

    def test_handle_error_without_active_exception(self) -> None:
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            self.server.handle_error(create_autospec(socket.socket, instance=True), ("203.0.113.5", 40000))
        assert [(r.levelno, r.getMessage(), r.exc_info) for r in logs.records] == [
            (logging.ERROR, "Unhandled error serving 203.0.113.5", None)
        ]

    def test_unexpected_error_logs_traceback(self) -> None:
        records = self.handle_error(RuntimeError("bug"))
        assert [(r.levelno, bool(r.exc_info)) for r in records] == [(logging.ERROR, True)]
        assert "203.0.113.5" in records[0].getMessage()


class TestListenBacklog(unittest.TestCase):
    def test_listens_with_somaxconn_backlog(self) -> None:
        server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(server.server_close)
        listening: NonCallableMagicMock = create_autospec(socket.socket, instance=True)
        server.socket = listening
        server.server_activate()
        listening.listen.assert_called_once_with(socket.SOMAXCONN)


def _without_socks5_env(**environ: str) -> AbstractContextManager[object]:
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
    return patch.dict(os.environ, {**clean, **environ}, clear=True)


class TestConnectionLimit(unittest.TestCase):
    def make_server(self, **environ: str) -> ThreadingTCPServer:
        with _without_socks5_env(**environ):
            server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(server.server_close)
        return server

    def test_default_limit_is_200(self) -> None:
        assert self.make_server().max_connections == 200

    def test_limit_read_from_env(self) -> None:
        server = self.make_server(SOCKS5_MAX_CONNECTIONS="3")
        assert server.max_connections == 3
        for _ in range(3):
            assert server._connection_semaphore.acquire(blocking=False)
        assert not server._connection_semaphore.acquire(blocking=False)

    def test_instances_have_distinct_semaphores(self) -> None:
        first, second = self.make_server(SOCKS5_MAX_CONNECTIONS="1"), self.make_server(SOCKS5_MAX_CONNECTIONS="1")
        assert first._connection_semaphore.acquire(blocking=False)
        assert second._connection_semaphore.acquire(blocking=False)

    def test_invalid_limit_raises_before_binding(self) -> None:
        with (
            _without_socks5_env(SOCKS5_MAX_CONNECTIONS="0"),
            patch("socketserver.socket.socket", autospec=True) as socket_class,
            pytest.raises(ValueError, match="SOCKS5_MAX_CONNECTIONS"),
        ):
            ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer)
        socket_class.assert_not_called()

    def test_rejection_warning_rate_limited(self) -> None:
        server = self.make_server(SOCKS5_MAX_CONNECTIONS="1")
        assert server._connection_semaphore.acquire(blocking=False)
        now = [0.0]

        def reject(count: int) -> None:
            for _ in range(count):
                server.process_request(create_autospec(socket.socket, instance=True), ("127.0.0.1", 9999))

        server._limit_warnings = WarningRateLimiter(CONNECTION_LIMIT_WARNING_INTERVAL, clock=lambda: now[0])
        with (
            patch.object(server, "shutdown_request", autospec=True) as shutdown_request,
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
    def setUp(self) -> None:
        with _without_socks5_env():
            self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)
        self.dst = DetailedAddress(name="localhost", ip="127.0.0.1", port=80, address_type=AddressTypeCodes.IPv4)

    @patch("simple_socks5.server.TCPHandler", autospec=True)
    def test_policy_denied_sends_rep_02_without_error_log(self, mock_tcp_handler_cls: MagicMock) -> None:
        mock_tcp_handler_cls.return_value.handle_request.return_value = True
        mock_tcp_handler_cls.return_value.parse_request.return_value = Request(5, CommandCodes.CONNECT.value, self.dst)
        handler, connection = make_proxy_handler()
        handler.server = self.server
        with (
            patch("simple_socks5.server.TCPRelay", autospec=True, side_effect=PolicyDeniedError("127.0.0.1", 80)),
            self.assertLogs("simple_socks5", level="DEBUG") as logs,
        ):
            handler.handle()
        connection.sendall.assert_called_once_with(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        assert "ERROR" not in [r.levelname for r in logs.records]
        assert all(r.exc_info is None for r in logs.records)

    def test_first_policy_denial_warns_with_client_dst_and_env_var(self) -> None:
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            self.server.log_policy_denial("192.0.2.7", self.dst)
        assert len(logs.records) == 1
        assert logs.records[0].levelname == "WARNING"
        message = logs.records[0].getMessage()
        assert "192.0.2.7 -> localhost:80 (127.0.0.1)" in message
        assert "SOCKS5_ALLOW_LOOPBACK=true" in message
        assert "more denied" not in message

    def test_policy_warning_rate_limited_with_suppressed_count(self) -> None:
        now = [0.0]
        self.server._policy_warnings = WarningRateLimiter(POLICY_DENIED_WARNING_INTERVAL, clock=lambda: now[0])
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
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


class TestHandshakeTimeoutWarnings(unittest.TestCase):
    def setUp(self) -> None:
        with _without_socks5_env():
            self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)
        self.now = [0.0]
        self.server._timeout_warnings = WarningRateLimiter(
            HANDSHAKE_TIMEOUT_WARNING_INTERVAL, clock=lambda: self.now[0]
        )

    def test_warns_once_per_interval_with_count(self) -> None:
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            for i in range(50):
                stage = "waiting for the request" if i % 2 else "during the greeting or authentication"
                self.server.log_handshake_timeout(f"192.0.2.{i}", stage)
            self.now[0] = 10.0
            self.server.log_handshake_timeout("192.0.2.99", "waiting for the request")

        levels = [r.levelname for r in logs.records]
        assert levels == ["WARNING"] + ["DEBUG"] * 49 + ["WARNING"]
        assert logs.records[0].getMessage() == (
            "1 handshake(s) timed out since the last warning (latest: 192.0.2.0 during the greeting or authentication)"
        )
        assert logs.records[1].getMessage() == "Handshake timed out for 192.0.2.1 waiting for the request"
        assert logs.records[-1].getMessage().startswith("50 handshake(s) timed out since the last warning")


class TestAuthFailureWarnings(unittest.TestCase):
    def setUp(self) -> None:
        with _without_socks5_env():
            self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)
        self.now = [0.0]
        self.server._auth_warnings = WarningRateLimiter(AUTH_FAILED_WARNING_INTERVAL, clock=lambda: self.now[0])

    def test_warns_once_per_interval_with_count(self) -> None:
        with self.assertLogs("simple_socks5.server", level="DEBUG") as logs:
            for _ in range(20):
                self.server.log_auth_failure("203.0.113.7")
            self.now[0] = 10.0
            self.server.log_auth_failure("203.0.113.8")

        assert [r.levelname for r in logs.records] == ["WARNING"] + ["DEBUG"] * 19 + ["WARNING"]
        assert logs.records[0].getMessage() == (
            "Authentication failed for client 203.0.113.7 (1 failure(s) since the last warning)"
        )
        assert logs.records[1].getMessage() == "Authentication failed for client 203.0.113.7"
        assert logs.records[-1].getMessage() == (
            "Authentication failed for client 203.0.113.8 (20 failure(s) since the last warning)"
        )

    @patch("simple_socks5.server.TCPHandler", autospec=True)
    def test_failed_login_logged_by_server_and_closed(self, mock_tcp_handler_cls: MagicMock) -> None:
        handler, connection = make_proxy_handler()
        handler.server = server = create_autospec(ThreadingTCPServer, instance=True)
        mock_tcp_handler_cls.return_value.handle_request.side_effect = AuthenticationFailedError()

        handler.handle()

        server.log_auth_failure.assert_called_once_with("127.0.0.1")
        server.shutdown_request.assert_called_once_with(connection)
        mock_tcp_handler_cls.return_value.parse_request.assert_not_called()


class TestConnectionTracking(unittest.TestCase):
    """Verify ThreadingTCPServer tracks in-flight requests so shutdown can drain or close them."""

    def setUp(self) -> None:
        self.server = ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer, bind_and_activate=False)
        self.addCleanup(self.server.server_close)
        self.semaphore: NonCallableMagicMock = create_autospec(threading.BoundedSemaphore, instance=True)
        self.server._connection_semaphore = self.semaphore

    def _process(self, request: socket.socket, during: Callable[[], object] = lambda: None) -> None:
        """Accepts request and runs its handler synchronously instead of on a new thread."""

        def start_handler(server: ThreadingTCPServer, request: socket.socket, client_address: tuple[str, int]) -> None:
            server.process_request_thread(request, client_address)

        def handle(_server: ThreadingTCPServer, _request: socket.socket, _client_address: tuple[str, int]) -> None:
            during()

        with (
            patch("socketserver.ThreadingMixIn.process_request", start_handler),
            patch("socketserver.ThreadingMixIn.process_request_thread", handle),
        ):
            self.server.process_request(request, ("127.0.0.1", 9999))

    def test_process_request_rejects_non_socket_request(self) -> None:
        datagram_request = (b"data", create_autospec(socket.socket, instance=True))
        with (
            patch("socketserver.ThreadingMixIn.process_request", autospec=True) as start_handler,
            pytest.raises(TypeError, match="expected a connected TCP socket"),
        ):
            self.server.process_request(datagram_request, ("127.0.0.1", 9999))
        start_handler.assert_not_called()
        self.semaphore.acquire.assert_not_called()
        assert self.server.wait_for_connections(0)

    def test_request_tracked_before_handler_thread_runs(self) -> None:
        # A shutdown that drains right after serve_forever() returns must see a request whose handler
        # thread has started but not yet run.
        with patch("socketserver.ThreadingMixIn.process_request", autospec=True):
            self.server.process_request(create_autospec(socket.socket, instance=True), ("127.0.0.1", 9999))
        assert not self.server.wait_for_connections(0)

    def test_request_untracked_when_handler_thread_fails_to_start(self) -> None:
        with (
            patch(
                "socketserver.ThreadingMixIn.process_request",
                autospec=True,
                side_effect=RuntimeError("can't start thread"),
            ),
            pytest.raises(RuntimeError),
        ):
            self.server.process_request(create_autospec(socket.socket, instance=True), ("127.0.0.1", 9999))
        assert self.server.wait_for_connections(0)
        self.semaphore.release.assert_called_once()

    def test_request_tracked_during_handling_and_removed_after(self) -> None:
        request = create_autospec(socket.socket, instance=True)
        seen: list[int] = []
        self._process(request, during=lambda: seen.append(self.server.close_connections()))
        assert seen == [1]
        assert self.server.close_connections() == 0

    def test_semaphore_still_released(self) -> None:
        self._process(create_autospec(socket.socket, instance=True))
        self.semaphore.release.assert_called_once()

    def test_request_removed_when_handling_raises(self) -> None:
        request = create_autospec(socket.socket, instance=True)
        with patch("socketserver.ThreadingMixIn.process_request", autospec=True):
            self.server.process_request(request, ("127.0.0.1", 9999))
        with (
            patch(
                "socketserver.ThreadingMixIn.process_request_thread",
                autospec=True,
                side_effect=RuntimeError("handler failed"),
            ),
            pytest.raises(RuntimeError),
        ):
            self.server.process_request_thread(request, ("127.0.0.1", 9999))
        assert self.server.wait_for_connections(0)
        self.semaphore.release.assert_called_once()

    def test_wait_returns_true_when_idle(self) -> None:
        assert self.server.wait_for_connections(0)

    def test_wait_returns_false_on_timeout(self) -> None:
        started, release = threading.Event(), threading.Event()

        def hold() -> None:
            started.set()
            release.wait(5)

        worker = threading.Thread(target=self._process, args=(create_autospec(socket.socket, instance=True), hold))
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(release.set)
        started.wait(5)

        assert not self.server.wait_for_connections(0.01)
        release.set()
        assert self.server.wait_for_connections(5)

    def test_close_connections_shuts_down_each_and_counts(self) -> None:
        requests = [create_autospec(socket.socket, instance=True), create_autospec(socket.socket, instance=True)]
        counts: list[int] = []

        def process_both(remaining: list[NonCallableMagicMock]) -> None:
            if remaining:
                self._process(remaining[0], during=lambda: process_both(remaining[1:]))
            else:
                counts.append(self.server.close_connections())

        process_both(requests)
        assert counts == [2]
        for request in requests:
            request.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            request.close.assert_not_called()

    def test_close_connections_skips_already_closed_socket(self) -> None:
        closed, live = create_autospec(socket.socket, instance=True), create_autospec(socket.socket, instance=True)
        closed.shutdown.side_effect = OSError("Bad file descriptor")
        counts: list[int] = []
        self._process(
            closed, during=lambda: self._process(live, during=lambda: counts.append(self.server.close_connections()))
        )
        assert counts == [1]
        live.shutdown.assert_called_once_with(socket.SHUT_RDWR)


if __name__ == "__main__":
    unittest.main()
