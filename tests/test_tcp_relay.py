import socket
import selectors
import unittest
from unittest.mock import MagicMock, patch

from src.constants import RELAY_WRITE_TIMEOUT, AddressTypeCodes
from src.models import DetailedAddress
from src.relays.tcp_relay import TCPRelay


def _event(sock):
    key = MagicMock()
    key.fileobj = sock
    return key


class TestTCPRelay(unittest.TestCase):
    @patch("src.relays.tcp_relay.selectors.DefaultSelector")
    @patch("src.relays.tcp_relay.generate_tcp_socket")
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
            name="example.com", ip="93.184.216.34", port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        relay = TCPRelay(client_conn, dst)
        return relay, client_conn, mock_proxy_sock, mock_selector

    def test_init_creates_selector_and_connects(self):
        relay, client, proxy, selector = self._create_relay()
        self.assertIsNotNone(relay.selector)
        proxy.connect.assert_called_once_with(("93.184.216.34", 80))
        self.assertEqual(relay.get_proxy_address().port, 5000)
        # Both sockets should be registered with the selector
        self.assertEqual(selector.register.call_count, 2)

    @patch("src.relays.tcp_relay.selectors.DefaultSelector")
    @patch("src.relays.tcp_relay.generate_tcp_socket")
    def test_init_closes_selector_on_connection_failure(self, mock_gen_socket, mock_sel_cls):
        mock_selector = MagicMock()
        mock_sel_cls.return_value = mock_selector
        mock_gen_socket.return_value = MagicMock()
        mock_gen_socket.return_value.connect.side_effect = ConnectionRefusedError

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test", ip="1.2.3.4", port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        with self.assertRaises(ConnectionRefusedError):
            TCPRelay(client_conn, dst)

        mock_selector.close.assert_called_once()

    @patch("src.relays.tcp_relay.selectors.DefaultSelector")
    @patch("src.relays.tcp_relay.generate_tcp_socket")
    def test_init_closes_proxy_socket_when_connect_fails(self, mock_gen_socket, mock_sel_cls):
        mock_proxy_sock = MagicMock()
        mock_proxy_sock.connect.side_effect = ConnectionRefusedError
        mock_gen_socket.return_value = mock_proxy_sock

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test", ip="1.2.3.4", port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        with self.assertRaises(ConnectionRefusedError):
            TCPRelay(client_conn, dst)

        mock_proxy_sock.close.assert_called_once()

    def test_relay_data_eof_triggers_cleanup(self):
        relay, client, proxy, selector = self._create_relay()

        mock_key = MagicMock()
        mock_key.fileobj = client

        selector.select.return_value = [(mock_key, selectors.EVENT_READ)]
        client.recv.return_value = b""  # EOF

        relay.listen_and_relay()
        # Cleanup should close selector
        selector.close.assert_called()

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

    def test_send_data(self):
        relay, client, proxy, _ = self._create_relay()
        result = relay._send_data(proxy, b"hello")
        self.assertIsNone(result)
        proxy.sendall.assert_called_once_with(b"hello")
        proxy.send.assert_not_called()

    def test_init_leaves_sockets_blocking(self):
        relay, client, proxy, _ = self._create_relay()
        client.setblocking.assert_not_called()
        proxy.setblocking.assert_not_called()

    def test_prepare_sockets_sets_timeout_and_keepalive(self):
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [[(_event(client), selectors.EVENT_READ)]]
        client.recv.return_value = b""

        relay.listen_and_relay()

        for sock in (client, proxy):
            sock.settimeout.assert_called_once_with(RELAY_WRITE_TIMEOUT)
            sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setblocking.assert_not_called()

    def test_relay_write_timeout_cleans_up(self):
        relay, client, proxy, selector = self._create_relay()
        selector.select.side_effect = [[(_event(client), selectors.EVENT_READ)]]
        client.recv.return_value = b"data"
        proxy.sendall.side_effect = TimeoutError("timed out")

        with self.assertLogs("src.relays.tcp_relay", level="WARNING") as logs:
            relay.listen_and_relay()

        self.assertTrue(any("timed out" in line for line in logs.output))
        proxy.close.assert_called_once()
        selector.close.assert_called_once()
        client.close.assert_not_called()

    def test_recv_data(self):
        relay, client, proxy, _ = self._create_relay()
        client.recv.return_value = b"data"
        result = relay._recv_data(client)
        self.assertEqual(result, b"data")

    def test_recv_data_raises_on_error(self):
        relay, client, proxy, _ = self._create_relay()
        client.recv.side_effect = socket.error("recv failed")
        with self.assertRaises(socket.error):
            relay._recv_data(client)

    def test_relay_forwards_data_between_sockets(self):
        relay, client, proxy, selector = self._create_relay()

        mock_key_client = MagicMock()
        mock_key_client.fileobj = client
        mock_key_eof = MagicMock()
        mock_key_eof.fileobj = client

        # First select: client has data, second select: client EOF
        selector.select.side_effect = [
            [(mock_key_client, selectors.EVENT_READ)],
            [(mock_key_eof, selectors.EVENT_READ)],
        ]
        client.recv.side_effect = [b"request data", b""]

        relay.listen_and_relay()

        proxy.sendall.assert_called_once_with(b"request data")
        proxy.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
