import errno
import logging
import os
import selectors
import socket
import unittest
from unittest.mock import MagicMock, call, patch

import pytest

from simple_socks5.constants import RELAY_BUFFER_SIZE, RELAY_WRITE_TIMEOUT, AddressTypeCodes
from simple_socks5.exceptions import PolicyDeniedError
from simple_socks5.models import DetailedAddress
from simple_socks5.relays.tcp_relay import TCPRelay


def _event(sock):
    key = MagicMock()
    key.fileobj = sock
    return key


class TestTCPRelay(unittest.TestCase):
    @patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector")
    @patch("simple_socks5.relays.tcp_relay.generate_tcp_socket")
    def _create_relay(self, mock_gen_socket, mock_selector_cls):
        """Helper to create a TCPRelay with fully mocked sockets and selector."""
        mock_proxy_sock = MagicMock()
        mock_proxy_sock.getsockname.return_value = ("0.0.0.0", 5000)
        mock_gen_socket.return_value = mock_proxy_sock

        mock_selector = MagicMock()
        mock_selector_cls.return_value = mock_selector

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)

        dst = DetailedAddress(
            name="example.com",
            ip="93.184.216.34",
            port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        relay = TCPRelay(client_conn, dst)
        return relay, client_conn, mock_proxy_sock, mock_selector

    def test_init_creates_selector_and_connects(self):
        relay, client, proxy, selector = self._create_relay()
        assert relay.selector is not None
        proxy.connect.assert_called_once_with(("93.184.216.34", 80))
        assert relay.get_proxy_address().port == 5000
        # Both sockets should be registered with the selector
        assert selector.register.call_count == 2

    def test_connect_timeout_set_before_connect(self):
        with patch.dict(os.environ, {"SOCKS5_CONNECT_TIMEOUT": "0.5"}):
            _, _, proxy, _ = self._create_relay()
        assert proxy.mock_calls[:2] == [call.settimeout(0.5), call.connect(("93.184.216.34", 80))]

    @patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector")
    @patch("simple_socks5.relays.tcp_relay.generate_tcp_socket")
    def test_connect_timeout_closes_socket_and_selector(self, mock_gen_socket, mock_sel_cls):
        mock_gen_socket.return_value.connect.side_effect = TimeoutError("timed out")
        dst = DetailedAddress(name="test", ip="10.255.255.1", port=80, address_type=AddressTypeCodes.IPv4)

        with pytest.raises(TimeoutError):
            TCPRelay(MagicMock(), dst)

        mock_gen_socket.return_value.close.assert_called_once()
        mock_sel_cls.return_value.close.assert_called_once()

    @patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector")
    @patch("simple_socks5.relays.tcp_relay.generate_tcp_socket")
    def test_init_closes_selector_on_connection_failure(self, mock_gen_socket, mock_sel_cls):
        mock_selector = MagicMock()
        mock_sel_cls.return_value = mock_selector
        mock_gen_socket.return_value = MagicMock()
        mock_gen_socket.return_value.connect.side_effect = ConnectionRefusedError

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test",
            ip="1.2.3.4",
            port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        with pytest.raises(ConnectionRefusedError):
            TCPRelay(client_conn, dst)

        mock_selector.close.assert_called_once()

    @patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector")
    @patch("simple_socks5.relays.tcp_relay.generate_tcp_socket")
    def test_init_closes_proxy_socket_when_connect_fails(self, mock_gen_socket, mock_sel_cls):
        mock_proxy_sock = MagicMock()
        mock_proxy_sock.connect.side_effect = ConnectionRefusedError
        mock_gen_socket.return_value = mock_proxy_sock

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test",
            ip="1.2.3.4",
            port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        with pytest.raises(ConnectionRefusedError):
            TCPRelay(client_conn, dst)

        mock_proxy_sock.close.assert_called_once()

    def test_relay_data_eof_triggers_cleanup(self):
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

    def test_half_close_keeps_relaying_other_direction(self):
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

    def test_half_close_shutdown_error_cleans_up(self):
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [[(_event(client), selectors.EVENT_READ)]]
        client.recv.return_value = b""
        proxy.shutdown.side_effect = [OSError("not connected"), None]

        relay.listen_and_relay()

        proxy.close.assert_called_once()
        selector.close.assert_called_once()

    def test_relay_handles_broken_pipe(self):
        relay, client, proxy, selector = self._create_relay()

        mock_key = MagicMock()
        mock_key.fileobj = client
        selector.select.return_value = [(mock_key, selectors.EVENT_READ)]
        client.recv.side_effect = BrokenPipeError("broken pipe")

        relay.listen_and_relay()
        selector.close.assert_called()

    def test_relay_handles_connection_reset(self):
        relay, client, proxy, selector = self._create_relay()

        mock_key = MagicMock()
        mock_key.fileobj = client
        selector.select.return_value = [(mock_key, selectors.EVENT_READ)]
        client.recv.side_effect = ConnectionResetError("reset")

        relay.listen_and_relay()
        selector.close.assert_called()

    def test_routine_disconnect_logs_debug_without_traceback(self):
        for error in (BrokenPipeError("broken pipe"), ConnectionResetError("reset")):
            with self.subTest(error=repr(error)):
                relay, client, proxy, selector = self._create_relay()
                selector.select.return_value = [(_event(client), selectors.EVENT_READ)]
                client.recv.side_effect = error
                with self.assertLogs("simple_socks5.relays.tcp_relay", level="DEBUG") as logs:
                    relay.listen_and_relay()
                problems = [r for r in logs.records if r.exc_info or r.levelno > logging.INFO]
                assert problems == []
                assert any(r.levelno == logging.DEBUG for r in logs.records)

    def test_unexpected_socket_error_logs_traceback(self):
        relay, client, proxy, selector = self._create_relay()
        selector.select.return_value = [(_event(client), selectors.EVENT_READ)]
        client.recv.side_effect = OSError(errno.EBADF, "bad file descriptor")
        with self.assertLogs("simple_socks5.relays.tcp_relay", level="ERROR") as logs:
            relay.listen_and_relay()
        assert logs.records[0].exc_info
        selector.close.assert_called_once()

    def test_cleanup_closes_proxy_and_selector_not_client(self):
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

    def test_cleanup_tolerates_already_unregistered_socket(self):
        relay, client, proxy, selector = self._create_relay()
        selector.unregister.side_effect = KeyError("not registered")

        relay._cleanup()

        proxy.close.assert_called_once()
        selector.close.assert_called_once()

    def test_send_data(self):
        relay, client, proxy, _ = self._create_relay()
        result = relay._send_data(proxy, b"hello")
        assert result is None
        proxy.sendall.assert_called_once_with(b"hello")
        proxy.send.assert_not_called()

    def test_init_leaves_sockets_blocking(self):
        relay, client, proxy, _ = self._create_relay()
        client.setblocking.assert_not_called()
        proxy.setblocking.assert_not_called()

    def test_prepare_sockets_sets_timeout_and_keepalive(self):
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

    def test_relay_write_timeout_cleans_up(self):
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

    def test_recv_data(self):
        relay, client, proxy, _ = self._create_relay()
        client.recv.return_value = b"data"
        result = relay._recv_data(client)
        assert result == b"data"
        client.recv.assert_called_once_with(RELAY_BUFFER_SIZE)

    def test_recv_data_raises_on_error(self):
        relay, client, proxy, _ = self._create_relay()
        client.recv.side_effect = OSError("recv failed")
        with pytest.raises(socket.error):
            relay._recv_data(client)

    def _relay_one_exchange(self):
        """Client sends 12 bytes, the destination answers with 8, then both sides close."""
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
            [(_event(client), selectors.EVENT_READ)],
            [(_event(proxy), selectors.EVENT_READ)],
        ]
        client.recv.side_effect = [b"request data", b""]
        proxy.recv.side_effect = [b"response", b""]
        return relay

    def test_counts_bytes_each_direction(self):
        relay = self._relay_one_exchange()

        relay.listen_and_relay()

        assert (relay.bytes_up, relay.bytes_down) == (12, 8)

    def test_cleanup_logs_one_closed_line(self):
        with patch("simple_socks5.relays.base.time.monotonic", side_effect=[100.0, 102.5]):
            relay = self._relay_one_exchange()
            with self.assertLogs("simple_socks5.relays.tcp_relay", level="DEBUG") as logs:
                relay.listen_and_relay()

        assert [(r.levelname, r.getMessage()) for r in logs.records] == [
            ("INFO", "CLOSED | 127.0.0.1:1234 -> example.com:80 (93.184.216.34) | up=12 B down=8 B | 2.50 s")
        ]

    def test_send_and_recv_errors_reraise_without_logging(self):
        relay, client, proxy, _ = self._create_relay()
        client.recv.side_effect = ConnectionResetError("reset")
        proxy.sendall.side_effect = BrokenPipeError("broken pipe")
        with self.assertNoLogs("simple_socks5.relays.tcp_relay"):
            with pytest.raises(ConnectionResetError):
                relay._recv_data(client)
            with pytest.raises(BrokenPipeError):
                relay._send_data(proxy, b"data")

    def test_relay_forwards_data_between_sockets(self):
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


@patch("simple_socks5.relays.tcp_relay.selectors.DefaultSelector")
@patch("simple_socks5.relays.tcp_relay.generate_tcp_socket")
class TestTCPRelayDestinationPolicy(unittest.TestCase):
    def setUp(self):
        environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        patcher = patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _dst(self, ip: str, address_type=AddressTypeCodes.IPv4) -> DetailedAddress:
        return DetailedAddress(name="test", ip=ip, port=80, address_type=address_type)

    def test_denied_destination_raises_before_socket(self, mock_gen_socket, mock_sel_cls):
        with pytest.raises(PolicyDeniedError):
            TCPRelay(MagicMock(), self._dst("169.254.169.254"))
        mock_gen_socket.assert_not_called()
        mock_sel_cls.return_value.close.assert_called_once()

    def test_unresolved_hostname_raises_gaierror_without_connect(self, mock_gen_socket, mock_sel_cls):
        with pytest.raises(socket.gaierror):
            TCPRelay(MagicMock(), self._dst("slow-dns.example"))
        mock_gen_socket.assert_not_called()

    def test_opt_out_connects_to_loopback(self, mock_gen_socket, mock_sel_cls):
        mock_gen_socket.return_value.getsockname.return_value = ("127.0.0.1", 5000)
        with patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": "true"}):
            TCPRelay(MagicMock(), self._dst("::1", AddressTypeCodes.IPv6))
        mock_gen_socket.return_value.connect.assert_called_once_with(("::1", 80))


if __name__ == "__main__":
    unittest.main()
