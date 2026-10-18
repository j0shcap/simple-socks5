import contextlib
import errno
import inspect
import itertools
import logging
import socket
import struct
import threading
import time
import unittest
from collections.abc import Callable, Iterator
from unittest.mock import MagicMock, NonCallableMagicMock, call, create_autospec, patch

import pytest

from simple_socks5.constants import (
    RELAY_BUFFER_SIZE,
    RELAY_IDLE_CHECK_INTERVAL,
    RELAY_INITIAL_BUFFER_SIZE,
    RELAY_WRITE_TIMEOUT,
    AddressTypeCodes,
)
from simple_socks5.exceptions import PolicyDeniedError
from simple_socks5.models import DetailedAddress
from simple_socks5.relays import tcp_relay
from simple_socks5.relays.tcp_relay import TCPRelay, _timeval, _timeval_format

DOMAIN = DetailedAddress(name="example.com", ip="example.com", port=80, address_type=AddressTypeCodes.DOMAIN_NAME)
RESOLVED = DetailedAddress(name="example.com", ip="93.184.216.34", port=80, address_type=AddressTypeCodes.IPv4)
LOGGER = "simple_socks5.relays.tcp_relay"


def _socket() -> NonCallableMagicMock:
    sock: NonCallableMagicMock = create_autospec(socket.socket, instance=True)
    sock.send.side_effect = len
    return sock


def _tcp_pair(stack: contextlib.ExitStack) -> tuple[socket.socket, socket.socket]:
    """A connected pair of loopback TCP sockets, closed when the stack exits."""
    listener = stack.enter_context(socket.create_server(("127.0.0.1", 0)))
    near = stack.enter_context(socket.create_connection(listener.getsockname()))
    far = stack.enter_context(listener.accept()[0])
    return near, far


def _recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while chunk := sock.recv(65536):
        chunks.append(chunk)
    return b"".join(chunks)


class TestTCPRelay(unittest.TestCase):
    @patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True)
    def _create_relay(self, mock_connect_any: MagicMock) -> tuple[TCPRelay, NonCallableMagicMock, NonCallableMagicMock]:
        """A TCPRelay between two socket mocks: the client's and the destination's."""
        proxy = _socket()
        proxy.getsockname.return_value = ("0.0.0.0", 5000)
        mock_connect_any.return_value = (proxy, RESOLVED)
        client = _socket()
        client.getpeername.return_value = ("127.0.0.1", 1234)

        relay = TCPRelay(client, DOMAIN)
        mock_connect_any.assert_called_once_with(DOMAIN)
        return relay, client, proxy

    @contextlib.contextmanager
    def _real_relay(self) -> Iterator[tuple[TCPRelay, socket.socket, socket.socket]]:
        """
        A TCPRelay between real loopback sockets, relaying on its own thread. Yields the relay, the client's end and
        the destination's end; on exit, checks that the relay finished.
        """
        with contextlib.ExitStack() as stack:
            client_app, client_relay = _tcp_pair(stack)
            relay_dst, dst_app = _tcp_pair(stack)
            for sock in (client_app, dst_app):
                sock.settimeout(5)
            with patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True, return_value=(relay_dst, RESOLVED)):
                relay = TCPRelay(client_relay, DOMAIN)
            relaying = threading.Thread(target=relay.listen_and_relay)
            relaying.start()
            self._relaying = relaying
            yield relay, client_app, dst_app
            relaying.join(5)
            assert not relaying.is_alive(), "the relay is still running"
            assert client_relay.fileno() != -1, "the relay closed the client's socket, which the server owns"

    def _wait_for_relay(self, timeout: float) -> None:
        self._relaying.join(timeout)
        assert not self._relaying.is_alive(), f"the relay didn't end within {timeout} s"

    @staticmethod
    def _flood(sock: socket.socket) -> None:
        with contextlib.suppress(OSError):  # reset once the socket's peer closes
            sock.sendall(b"x" * (16 * 1024 * 1024))

    def test_init_connects(self) -> None:
        relay, _client, proxy = self._create_relay()
        assert relay.proxy_connection is proxy
        assert relay.get_proxy_address().port == 5000

    def test_dst_address_is_the_resolved_address(self) -> None:
        relay, _client, _proxy = self._create_relay()
        assert relay.dst_address == RESOLVED
        assert "example.com:80 (93.184.216.34)" in relay.closed_line()

    @patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True)
    def test_init_propagates_connection_failure(self, mock_connect_any: MagicMock) -> None:
        for error in (
            ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
            TimeoutError("timed out"),
            PolicyDeniedError("127.0.0.1", 80),
            socket.gaierror(socket.EAI_NONAME, "nx"),
        ):
            with self.subTest(error=type(error).__name__):
                mock_connect_any.side_effect = error
                with pytest.raises(type(error)):
                    TCPRelay(_socket(), DOMAIN)

    def test_init_disables_nagle_on_both_sockets(self) -> None:
        _relay, client, proxy = self._create_relay()
        for sock in (client, proxy):
            sock.setsockopt.assert_any_call(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True)
    def test_init_closes_proxy_socket_when_setsockopt_fails(self, mock_connect_any: MagicMock) -> None:
        proxy = _socket()
        proxy.setsockopt.side_effect = OSError(errno.EINVAL, "Invalid argument")
        mock_connect_any.return_value = (proxy, RESOLVED)

        with pytest.raises(OSError, match="Invalid argument"):
            TCPRelay(_socket(), DOMAIN)

        proxy.close.assert_called_once()

    def test_init_sets_nodelay_on_real_sockets(self) -> None:
        with contextlib.ExitStack() as stack:
            _, client = _tcp_pair(stack)
            upstream, _ = _tcp_pair(stack)
            with patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True, return_value=(upstream, RESOLVED)):
                relay = TCPRelay(client, DOMAIN)

            for sock in (relay.client_connection, relay.proxy_connection):
                assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0

    def test_half_close_from_client_keeps_downstream_open(self) -> None:
        with self._real_relay() as (_relay, client, dst):
            client.sendall(b"request")
            client.shutdown(socket.SHUT_WR)
            assert _recv_all(dst) == b"request"

            dst.sendall(b"reply after the client's EOF")
            dst.shutdown(socket.SHUT_WR)
            assert _recv_all(client) == b"reply after the client's EOF"

    def test_half_close_from_destination_keeps_upstream_open(self) -> None:
        with self._real_relay() as (_relay, client, dst):
            dst.sendall(b"banner")
            dst.shutdown(socket.SHUT_WR)
            assert _recv_all(client) == b"banner"

            client.sendall(b"request after the destination's EOF")
            client.shutdown(socket.SHUT_WR)
            assert _recv_all(dst) == b"request after the destination's EOF"

    def test_counts_bytes_and_logs_one_closed_line(self) -> None:
        started = iter([100.0])  # then 102.5 for the writes and the CLOSED line
        with (
            patch("simple_socks5.relays.base.time.monotonic", autospec=True, side_effect=lambda: next(started, 102.5)),
            self.assertLogs(LOGGER, level="DEBUG") as logs,
        ):
            relay, client, proxy = self._create_relay()
            client.recv.side_effect = [b"request data", b""]
            proxy.recv.side_effect = [b"response", b""]
            relay.listen_and_relay()

        assert (relay.bytes_up, relay.bytes_down) == (12, 8)
        proxy.send.assert_called_once_with(b"request data")
        client.send.assert_called_once_with(b"response")
        assert [(r.levelname, r.getMessage()) for r in logs.records] == [
            ("INFO", "CLOSED | 127.0.0.1:1234 -> example.com:80 (93.184.216.34) | up=12 B down=8 B | 2.50 s")
        ]

    def test_eof_on_both_sides_half_closes_each_and_closes_only_the_proxy_socket(self) -> None:
        relay, client, proxy = self._create_relay()
        client.recv.return_value = b""
        proxy.recv.return_value = b""

        relay.listen_and_relay()

        assert call(socket.SHUT_WR) in proxy.shutdown.call_args_list
        client.shutdown.assert_called_once_with(socket.SHUT_WR)
        proxy.close.assert_called_once()
        client.close.assert_not_called()

    def test_read_that_fills_the_buffer_grows_only_that_direction(self) -> None:
        relay, client, proxy = self._create_relay()
        client.recv.side_effect = [b"x" * RELAY_INITIAL_BUFFER_SIZE, b"rest", b""]
        proxy.recv.side_effect = [b"response", b""]

        relay.listen_and_relay()

        assert client.recv.call_args_list == [call(RELAY_INITIAL_BUFFER_SIZE)] + [call(RELAY_BUFFER_SIZE)] * 2
        assert proxy.recv.call_args_list == [call(RELAY_INITIAL_BUFFER_SIZE)] * 2

    def test_waits_for_the_next_read_without_holding_the_last_chunk(self) -> None:
        relay, client, proxy = self._create_relay()
        held: list[object] = []

        def recv(_size: int) -> bytes:
            relay_frames = [f.frame for f in inspect.stack() if f.filename == tcp_relay.__file__]
            held.extend(v for frame in relay_frames for v in frame.f_locals.values() if isinstance(v, bytes))
            return b"x" * RELAY_INITIAL_BUFFER_SIZE if client.recv.call_count == 1 else b""

        client.recv.side_effect = recv
        proxy.recv.return_value = b""

        relay.listen_and_relay()

        assert client.recv.call_count == 2
        assert held == [], "the chunk already sent stays allocated while the relay waits"

    def test_write_timeout_warns_once_and_cleans_up(self) -> None:
        with (
            patch("simple_socks5.relays.tcp_relay.RELAY_WRITE_TIMEOUT", 0.3),
            self.assertLogs(LOGGER, level="DEBUG") as logs,
            self._real_relay() as (relay, client, dst),
        ):
            # The destination never reads: once its buffers fill, the relay's write to it times out
            dst.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            relay.proxy_connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            # Until the server closes the client's socket after the relay, this blocks on the full buffers
            flood = threading.Thread(target=self._flood, args=(client,))
            flood.start()
            self._wait_for_relay(2)
        flood.join(5)

        warnings = [r.getMessage() for r in logs.records if r.levelno == logging.WARNING]
        assert warnings == ["Relay write timed out after 0.3 seconds"]
        assert relay.proxy_connection.fileno() == -1

    def test_slow_reader_gets_the_rest_and_the_full_write_timeout_back(self) -> None:
        relay, client, proxy = self._create_relay()
        client.recv.side_effect = [b"request data", b""]
        proxy.recv.return_value = b""
        proxy.send.side_effect = [5, 4, 3]

        relay.listen_and_relay()

        assert [bytes(c.args[0]) for c in proxy.send.call_args_list] == [b"request data", b"st data", b"ata"]
        timeouts = [c.args[2] for c in proxy.setsockopt.call_args_list if c.args[1] == socket.SO_SNDTIMEO]
        assert timeouts[-1] == _timeval(RELAY_WRITE_TIMEOUT)
        assert len(timeouts) >= 3, "each retry is bounded by what is left of the write timeout"
        assert relay.bytes_up == 12

    def test_slow_reader_past_the_deadline_times_out(self) -> None:
        cases: list[tuple[str, Callable[[NonCallableMagicMock], None]]] = [
            ("deadline passed after a partial write", lambda proxy: setattr(proxy.send, "side_effect", [2])),
            (
                "nothing written within the kernel's timeout",
                lambda proxy: setattr(proxy.send, "side_effect", BlockingIOError(errno.EAGAIN, "again")),
            ),
        ]
        for name, slow_reader in cases:
            with self.subTest(name), self.assertLogs(LOGGER, level="DEBUG") as logs:
                relay, client, proxy = self._create_relay()
                client.recv.side_effect = [b"data", b""]
                proxy.recv.return_value = b""
                slow_reader(proxy)
                clock = itertools.count(0.0, RELAY_WRITE_TIMEOUT)
                with patch("simple_socks5.relays.tcp_relay.time.monotonic", side_effect=clock.__next__):
                    relay.listen_and_relay()

                warnings = [r.getMessage() for r in logs.records if r.levelno == logging.WARNING]
                assert warnings == [f"Relay write timed out after {RELAY_WRITE_TIMEOUT} seconds"]
                proxy.close.assert_called_once()
                client.close.assert_not_called()

    def test_error_in_one_pump_wakes_the_other(self) -> None:
        with self.assertLogs(LOGGER, level="DEBUG") as logs, self._real_relay() as (_relay, client, dst):
            client.sendall(b"ping")
            assert dst.recv(4) == b"ping"
            # The destination resets the connection while the client is idle: the client's pump blocks in recv()
            dst.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            dst.close()
            self._wait_for_relay(1)
            assert client.recv(1) == b"", "the client isn't told the relay ended"

        relay_ended = [r for r in logs.records if r.getMessage().startswith("Relay ended")]
        assert [(r.levelno, r.exc_info) for r in relay_ended] == [(logging.DEBUG, None)]
        assert sum(r.getMessage().startswith("CLOSED") for r in logs.records) == 1

    def test_unexpected_error_in_a_pump_still_ends_the_relay(self) -> None:
        move = TCPRelay._move
        failures: list[type[BaseException]] = []

        def failing_move(self: TCPRelay, src: socket.socket, dst: socket.socket, size: int) -> int:
            if src is self.client_connection:
                raise ValueError("a bug")
            return move(self, src, dst, size)

        def excepthook(args: threading.ExceptHookArgs) -> None:
            failures.append(args.exc_type)

        with (
            patch.object(TCPRelay, "_move", autospec=True, side_effect=failing_move),
            patch("threading.excepthook", excepthook),
            self.assertLogs(LOGGER, level="DEBUG") as logs,
            self._real_relay(),
        ):
            self._wait_for_relay(1)

        assert failures == [ValueError]
        assert sum(r.getMessage().startswith("CLOSED") for r in logs.records) == 1

    def test_routine_and_other_socket_errors_log_debug_once_without_traceback(self) -> None:
        for error in (
            BrokenPipeError("broken pipe"),
            ConnectionResetError("reset"),
            OSError(errno.EBADF, "bad file descriptor"),
        ):
            with self.subTest(error=repr(error)), self.assertLogs(LOGGER, level="DEBUG") as logs:
                relay, client, proxy = self._create_relay()
                client.recv.side_effect = error
                proxy.recv.side_effect = ConnectionResetError("induced by the first error")
                relay.listen_and_relay()

                relay_ended = [r for r in logs.records if r.getMessage().startswith("Relay ended")]
                assert [(r.levelno, r.exc_info) for r in relay_ended] == [(logging.DEBUG, None)]
                assert [r for r in logs.records if r.levelno > logging.INFO] == []
                proxy.close.assert_called_once()
                client.close.assert_not_called()

    def test_half_close_shutdown_error_ends_the_relay(self) -> None:
        relay, client, proxy = self._create_relay()
        client.recv.return_value = b""
        proxy.recv.return_value = b""
        proxy.shutdown.side_effect = OSError(errno.ENOTCONN, "not connected")

        with self.assertLogs(LOGGER, level="DEBUG") as logs:
            relay.listen_and_relay()

        assert any(r.getMessage().startswith("Relay ended") for r in logs.records)
        proxy.close.assert_called_once()

    def test_idle_check_ends_the_relay_only_when_a_socket_is_closed(self) -> None:
        idle = BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")
        relay, client, proxy = self._create_relay()
        client.recv.side_effect = [idle, b"still open", b""]
        proxy.recv.side_effect = [idle, b""]

        relay.listen_and_relay()

        proxy.send.assert_called_once_with(b"still open")

        relay, client, proxy = self._create_relay()
        client.recv.side_effect = idle
        proxy.recv.side_effect = idle
        client.fileno.return_value = -1

        relay.listen_and_relay()

        client.shutdown.assert_not_called()
        proxy.close.assert_called_once()

    def test_thread_start_failure_cleans_up(self) -> None:
        relay, client, proxy = self._create_relay()
        with (
            patch("simple_socks5.relays.tcp_relay.threading.Thread.start", side_effect=RuntimeError("can't start")),
            self.assertLogs(LOGGER, level="DEBUG") as logs,
        ):
            relay.listen_and_relay()

        assert [r.getMessage() for r in logs.records if r.levelno == logging.DEBUG] == ["Relay ended: can't start"]
        client.recv.assert_not_called()
        proxy.close.assert_called_once()
        client.close.assert_not_called()

    def test_prepare_sockets_sets_kernel_timeouts_and_keepalive(self) -> None:
        relay, client, proxy = self._create_relay()
        client.recv.return_value = b""
        proxy.recv.return_value = b""
        for sock in (client, proxy):
            sock.setsockopt.reset_mock()  # TCP_NODELAY, set in __init__

        relay.listen_and_relay()

        for sock in (client, proxy):
            # Replaces the connect and handshake timeouts: the kernel bounds each call instead
            assert sock.settimeout.call_args_list[-1] == call(None)
            assert sock.setsockopt.call_args_list == [
                call(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                call(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _timeval(RELAY_WRITE_TIMEOUT)),
                call(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _timeval(RELAY_IDLE_CHECK_INTERVAL)),
            ]

    def test_kernel_timeouts_read_back_from_real_sockets(self) -> None:
        with self._real_relay() as (relay, client, dst):
            client.sendall(b"ping")
            assert dst.recv(4) == b"ping"
            for sock in (relay.client_connection, relay.proxy_connection):
                assert sock.gettimeout() is None
                for option, seconds in ((socket.SO_SNDTIMEO, RELAY_WRITE_TIMEOUT), (socket.SO_RCVTIMEO, 3)):
                    expected = _timeval(seconds)
                    assert sock.getsockopt(socket.SOL_SOCKET, option, len(expected)) == expected
            client.shutdown(socket.SHUT_WR)
            dst.shutdown(socket.SHUT_WR)

    def test_timeval_layout_follows_the_width_of_time_t(self) -> None:
        cases = (
            ("64-bit time_t", None, 16),
            ("32-bit time_t", OverflowError("timestamp out of range for platform time_t"), 8),
        )
        for name, error, size in cases:
            with self.subTest(name), patch("simple_socks5.relays.tcp_relay.time.gmtime", side_effect=error):
                _timeval_format.cache_clear()
                try:
                    assert struct.calcsize(_timeval_format()) == size
                    assert struct.unpack(_timeval_format(), _timeval(1.5)) == (1, 500000)
                finally:
                    _timeval_format.cache_clear()

    def test_timeval_rounds_up_to_a_microsecond(self) -> None:
        assert struct.unpack(_timeval_format(), _timeval(1e-9)) == (0, 1), "a timeval of 0 means no timeout"
        assert struct.unpack(_timeval_format(), _timeval(2.9999999)) == (3, 0)

    def test_wake_up_ends_a_relay_blocked_in_both_directions(self) -> None:
        with self._real_relay() as (relay, _client, _dst):
            time.sleep(0.1)  # both pumps block in recv()
            relay._end(logging.DEBUG, "stopping")
            self._wait_for_relay(1)


if __name__ == "__main__":
    unittest.main()
