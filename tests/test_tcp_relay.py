import errno
import logging
import selectors
import socket
import unittest
from unittest.mock import MagicMock, NonCallableMagicMock, call, create_autospec, patch

import pytest

from simple_socks5.constants import RELAY_BUFFER_SIZE, RELAY_WRITE_TIMEOUT, AddressTypeCodes
from simple_socks5.exceptions import PolicyDeniedError
from simple_socks5.models import DetailedAddress
from simple_socks5.relays.tcp_relay import TCPRelay

DOMAIN = DetailedAddress(name="example.com", ip="example.com", port=80, address_type=AddressTypeCodes.DOMAIN_NAME)


def _event(sock: socket.socket) -> selectors.SelectorKey:
    return selectors.SelectorKey(fileobj=sock, fd=0, events=selectors.EVENT_READ, data=None)


def _socket() -> NonCallableMagicMock:
    sock: NonCallableMagicMock = create_autospec(socket.socket, instance=True)
    return sock


def _selector() -> NonCallableMagicMock:
    selector: NonCallableMagicMock = create_autospec(selectors.BaseSelector, instance=True)
    return selector


RESOLVED = DetailedAddress(name="example.com", ip="93.184.216.34", port=80, address_type=AddressTypeCodes.IPv4)


class TestTCPRelay(unittest.TestCase):
    @patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector", autospec=True)
    @patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True)
    def _create_relay(
        self, mock_connect_any: MagicMock, mock_selector_cls: MagicMock
    ) -> tuple[TCPRelay, NonCallableMagicMock, NonCallableMagicMock, NonCallableMagicMock]:
        """Helper to create a TCPRelay with fully mocked sockets and selector."""
        mock_proxy_sock = _socket()
        mock_proxy_sock.getsockname.return_value = ("0.0.0.0", 5000)
        mock_connect_any.return_value = (mock_proxy_sock, RESOLVED)

        mock_selector: NonCallableMagicMock = create_autospec(selectors.BaseSelector, instance=True)
        mock_selector_cls.return_value = mock_selector

        client_conn = _socket()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)

        relay = TCPRelay(client_conn, DOMAIN)
        mock_connect_any.assert_called_once_with(DOMAIN)
        return relay, client_conn, mock_proxy_sock, mock_selector

    def test_init_creates_selector_and_connects(self) -> None:
        relay, _client, proxy, selector = self._create_relay()
        assert relay.selector is not None
        assert relay.proxy_connection is proxy
        assert relay.get_proxy_address().port == 5000
        # Both sockets should be registered with the selector
        assert selector.register.call_count == 2

    def test_dst_address_is_the_resolved_address(self) -> None:
        relay, _client, _proxy, _selector = self._create_relay()
        assert relay.dst_address == RESOLVED
        assert "example.com:80 (93.184.216.34)" in relay.closed_line()

    @patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True)
    def test_init_closes_selector_on_connection_failure(self, mock_connect_any: MagicMock) -> None:
        for error in (
            ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
            TimeoutError("timed out"),
            PolicyDeniedError("127.0.0.1", 80),
            socket.gaierror(socket.EAI_NONAME, "nx"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch(
                    "simple_socks5.relays.tcp_relay.selectors.DefaultSelector", autospec=selectors.BaseSelector
                ) as mock_sel_cls,
            ):
                mock_connect_any.side_effect = error
                with pytest.raises(type(error)):
                    TCPRelay(_socket(), DOMAIN)
                mock_sel_cls.return_value.close.assert_called_once()

    @patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector", autospec=True)
    @patch("simple_socks5.relays.tcp_relay.connect_any", autospec=True)
    def test_init_closes_proxy_socket_when_register_fails(
        self, mock_connect_any: MagicMock, mock_sel_cls: MagicMock
    ) -> None:
        proxy = _socket()
        mock_connect_any.return_value = (proxy, RESOLVED)
        mock_sel_cls.return_value.register.side_effect = [None, ValueError("Invalid file descriptor: -1")]

        with pytest.raises(ValueError, match="Invalid file descriptor"):
            TCPRelay(_socket(), DOMAIN)

        proxy.close.assert_called_once()
        mock_sel_cls.return_value.close.assert_called_once()

    def test_relay_data_eof_triggers_cleanup(self) -> None:
        relay, client, proxy, selector = self._create_relay()

        selector.select.side_effect = [
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
        ]
        client.recv.return_value = b""
        proxy.recv.return_value = b""

        relay.listen_and_relay()

        proxy.shutdown.assert_any_call(socket.SHUT_WR)
        client.shutdown.assert_called_once_with(socket.SHUT_WR)
        client.close.assert_not_called()
        selector.close.assert_called_once()

    def test_half_close_keeps_relaying_other_direction(self) -> None:
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
        ]
        client.recv.return_value = b""
        proxy.recv.side_effect = [b"response", b""]

        relay.listen_and_relay()

        selector.unregister.assert_any_call(client)
        proxy.shutdown.assert_any_call(socket.SHUT_WR)
        client.sendall.assert_called_once_with(b"response")
        assert selector.select.call_count == 3

    def test_half_close_shutdown_error_cleans_up(self) -> None:
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [[(_event(client), selectors.EVENT_READ)]]
        client.recv.return_value = b""
        proxy.shutdown.side_effect = [OSError("not connected"), None]

        relay.listen_and_relay()

        proxy.close.assert_called_once()
        selector.close.assert_called_once()

    def test_relay_handles_broken_pipe(self) -> None:
        relay, client, _proxy, selector = self._create_relay()

        selector.select.return_value = [(_event(client), selectors.EVENT_READ)]
        client.recv.side_effect = BrokenPipeError("broken pipe")

        relay.listen_and_relay()
        selector.close.assert_called()

    def test_relay_handles_connection_reset(self) -> None:
        relay, client, _proxy, selector = self._create_relay()

        selector.select.return_value = [(_event(client), selectors.EVENT_READ)]
        client.recv.side_effect = ConnectionResetError("reset")

        relay.listen_and_relay()
        selector.close.assert_called()

    def test_routine_disconnect_logs_debug_without_traceback(self) -> None:
        for error in (BrokenPipeError("broken pipe"), ConnectionResetError("reset")):
            with self.subTest(error=repr(error)):
                relay, client, _proxy, selector = self._create_relay()
                selector.select.return_value = [(_event(client), selectors.EVENT_READ)]
                client.recv.side_effect = error
                with self.assertLogs("simple_socks5.relays.tcp_relay", level="DEBUG") as logs:
                    relay.listen_and_relay()
                problems = [r for r in logs.records if r.exc_info or r.levelno > logging.INFO]
                assert problems == []
                assert any(r.levelno == logging.DEBUG for r in logs.records)

    def test_other_socket_error_logs_debug_without_traceback(self) -> None:
        relay, client, _proxy, selector = self._create_relay()
        selector.select.return_value = [(_event(client), selectors.EVENT_READ)]
        client.recv.side_effect = OSError(errno.EBADF, "bad file descriptor")
        with self.assertLogs("simple_socks5.relays.tcp_relay", level="DEBUG") as logs:
            relay.listen_and_relay()
        relay_ended = [r for r in logs.records if r.getMessage().startswith("Relay ended")]
        assert [(r.levelno, r.exc_info) for r in relay_ended] == [(logging.DEBUG, None)]
        selector.close.assert_called_once()

    def test_cleanup_closes_proxy_and_selector_not_client(self) -> None:
        relay, client, proxy, selector = self._create_relay()

        relay._cleanup()

        # Both sockets unregistered from selector
        selector.unregister.assert_any_call(client)
        selector.unregister.assert_any_call(proxy)
        # Proxy socket shutdown and closed
        proxy.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        proxy.close.assert_called_once()
        # Client socket NOT closed — owned by server framework
        client.shutdown.assert_not_called()
        client.close.assert_not_called()
        # Selector closed
        selector.close.assert_called_once()

    def test_cleanup_tolerates_already_unregistered_socket(self) -> None:
        relay, _client, proxy, selector = self._create_relay()
        selector.unregister.side_effect = KeyError("not registered")

        relay._cleanup()

        proxy.close.assert_called_once()
        selector.close.assert_called_once()

    def test_init_leaves_sockets_blocking(self) -> None:
        _relay, client, proxy, _ = self._create_relay()
        client.setblocking.assert_not_called()
        proxy.setblocking.assert_not_called()

    def test_prepare_sockets_sets_timeout_and_keepalive(self) -> None:
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
        ]
        client.recv.return_value = b""
        proxy.recv.return_value = b""

        relay.listen_and_relay()

        client.settimeout.assert_called_once_with(RELAY_WRITE_TIMEOUT)
        # Replaces the connect timeout set before connect()
        assert proxy.settimeout.call_args_list[-1] == call(RELAY_WRITE_TIMEOUT)
        for sock in (client, proxy):
            sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setblocking.assert_not_called()

    def test_relay_write_timeout_cleans_up(self) -> None:
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [[(_event(client), selectors.EVENT_READ)]]
        client.recv.return_value = b"data"
        proxy.sendall.side_effect = TimeoutError("timed out")

        with self.assertLogs("simple_socks5.relays.tcp_relay", level="WARNING") as logs:
            relay.listen_and_relay()

        assert any("timed out" in line for line in logs.output)
        proxy.close.assert_called_once()
        selector.close.assert_called_once()
        client.close.assert_not_called()

    def _relay_one_exchange(self) -> tuple[TCPRelay, NonCallableMagicMock, NonCallableMagicMock]:
        """Client sends 12 bytes, the destination answers with 8, then both sides close. Returns the relay and its
        client and destination socket mocks."""
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
        ]
        client.recv.side_effect = [b"request data", b""]
        proxy.recv.side_effect = [b"response", b""]
        return relay, client, proxy

    def test_reads_up_to_buffer_size_and_writes_with_sendall(self) -> None:
        relay, client, proxy = self._relay_one_exchange()

        relay.listen_and_relay()

        assert client.recv.call_args_list == [call(RELAY_BUFFER_SIZE)] * 2
        proxy.sendall.assert_called_once_with(b"request data")
        client.sendall.assert_called_once_with(b"response")
        proxy.send.assert_not_called()
        client.send.assert_not_called()

    def test_counts_bytes_each_direction(self) -> None:
        relay, _, _ = self._relay_one_exchange()

        relay.listen_and_relay()

        assert (relay.bytes_up, relay.bytes_down) == (12, 8)

    def test_cleanup_logs_one_closed_line(self) -> None:
        with patch("simple_socks5.relays.base.time.monotonic", autospec=True, side_effect=[100.0, 102.5]):
            relay, _, _ = self._relay_one_exchange()
            with self.assertLogs("simple_socks5.relays.tcp_relay", level="DEBUG") as logs:
                relay.listen_and_relay()

        assert [(r.levelname, r.getMessage()) for r in logs.records] == [
            ("INFO", "CLOSED | 127.0.0.1:1234 -> example.com:80 (93.184.216.34) | up=12 B down=8 B | 2.50 s")
        ]

    def test_relay_forwards_data_between_sockets(self) -> None:
        relay, client, proxy, selector = self._create_relay()

        # Client data, then client EOF, then proxy EOF
        selector.select.side_effect = [
            [(_event(client), selectors.EVENT_READ)],
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
        ]
        client.recv.side_effect = [b"request data", b""]
        proxy.recv.return_value = b""

        relay.listen_and_relay()

        proxy.sendall.assert_called_once_with(b"request data")
        proxy.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
