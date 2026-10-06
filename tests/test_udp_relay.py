import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from src.constants import AddressTypeCodes
from src.handlers.udp import UDPHandler
from src.models import DetailedAddress
from src.relays.udp_relay import UDPRelay


def build_udp_datagram(dst_addr: str, dst_port: int, data: bytes, frag: int = 0, atyp: int = 1) -> bytes:
    """Build a SOCKS5 UDP datagram per RFC 1928 section 7."""
    rsv = 0
    header = struct.pack("!HBB", rsv, frag, atyp)
    if atyp == 1:  # IPv4
        addr_bytes = socket.inet_aton(dst_addr)
    elif atyp == 4:  # IPv6
        addr_bytes = socket.inet_pton(socket.AF_INET6, dst_addr)
    else:
        addr_bytes = bytes([len(dst_addr)]) + dst_addr.encode()
    port_bytes = struct.pack("!H", dst_port)
    return header + addr_bytes + port_bytes + data


class TestBuildUDPResponseHeader(unittest.TestCase):
    def test_ipv4_response_header(self):
        header = UDPHandler.build_udp_response_header("10.0.0.1", 53)
        # RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10 bytes
        expected = b"\x00\x00\x00\x01" + socket.inet_aton("10.0.0.1") + struct.pack("!H", 53)
        self.assertEqual(header, expected)

    def test_ipv6_response_header(self):
        addr = "2001:db8::1"
        header = UDPHandler.build_udp_response_header(addr, 443)
        # RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22 bytes
        expected = (
            b"\x00\x00\x00\x04"
            + socket.inet_pton(socket.AF_INET6, addr)
            + struct.pack("!H", 443)
        )
        self.assertEqual(header, expected)

    def test_invalid_address_raises(self):
        with self.assertRaises(ValueError):
            UDPHandler.build_udp_response_header("not-an-ip", 80)


CLIENT_ADDR = ("127.0.0.1", 1234)


@patch("src.relays.udp_relay.generate_udp_socket")
def make_relay(mock_gen_socket) -> UDPRelay:
    """A relay on a mock UDP socket whose client is 127.0.0.1."""
    mock_gen_socket.return_value.getsockname.return_value = ("0.0.0.0", 5000)
    client_conn = MagicMock()
    client_conn.getpeername.return_value = CLIENT_ADDR
    dst = DetailedAddress(name="test", ip="1.2.3.4", port=80, address_type=AddressTypeCodes.IPv4)
    return UDPRelay(client_conn, dst)


def mock_forward_socket(response: bytes = b"response", remote_addr: tuple = ("10.0.0.1", 53)) -> MagicMock:
    forward_socket = MagicMock()
    forward_socket.recvfrom.return_value = (response, remote_addr)
    forward_socket.__enter__.return_value = forward_socket
    return forward_socket


class TestHandleDatagram(unittest.TestCase):
    def setUp(self):
        self.relay = make_relay()

    def test_valid_datagram_forwarded_and_encapsulated(self):
        forward_socket = mock_forward_socket()
        with patch("src.relays.udp_relay.socket.socket", return_value=forward_socket):
            self.assertTrue(self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"hello"), CLIENT_ADDR))

        forward_socket.sendto.assert_called_once_with(b"hello", ("10.0.0.1", 53))
        # RSV(2) + FRAG(1) + ATYP(1)=IPv4 + ADDR(4) + PORT(2) + DATA
        expected = b"\x00\x00\x00\x01" + socket.inet_aton("10.0.0.1") + struct.pack("!H", 53) + b"response"
        self.relay.proxy_connection.sendto.assert_called_once_with(expected, CLIENT_ADDR)

    def test_foreign_source_dropped_returns_false(self):
        """RFC 1928 Section 7: drop datagrams from IPs other than the client."""
        with patch("src.relays.udp_relay.socket.socket") as socket_class:
            self.assertFalse(self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"x"), ("192.168.1.99", 5)))
        socket_class.assert_not_called()

    def test_fragmented_dropped(self):
        with patch("src.relays.udp_relay.socket.socket") as socket_class:
            self.assertTrue(self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"x", frag=1), CLIENT_ADDR))
        socket_class.assert_not_called()

    def test_malformed_dropped_with_debug_log(self):
        for data in (b"\x00\x05", b"\x00\x01" + build_udp_datagram("10.0.0.1", 53, b"x")[2:], b"\x00\x00\x00\x09"):
            with self.subTest(data=data), patch("src.relays.udp_relay.socket.socket") as socket_class, \
                    self.assertLogs("src.relays", level="DEBUG") as logs:
                self.assertTrue(self.relay._handle_datagram(data, CLIENT_ADDR))
            socket_class.assert_not_called()
            self.assertIn("malformed UDP datagram", logs.output[0])

    def test_forward_oserror_dropped(self):
        forward_socket = mock_forward_socket()
        forward_socket.sendto.side_effect = PermissionError(13, "Permission denied")
        with patch("src.relays.udp_relay.socket.socket", return_value=forward_socket):
            self.assertTrue(self.relay._handle_datagram(build_udp_datagram("255.255.255.255", 53, b"x"), CLIENT_ADDR))


class TestUDPRelay(unittest.TestCase):
    @patch("src.relays.udp_relay.generate_udp_socket")
    def test_init_creates_and_binds_socket(self, mock_gen_socket):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("0.0.0.0", 5000)
        mock_gen_socket.return_value = mock_sock

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test", ip="1.2.3.4", port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        relay = UDPRelay(client_conn, dst)
        mock_sock.bind.assert_called_once_with(("", 0))
        self.assertEqual(relay.get_proxy_address().ip, "0.0.0.0")
        self.assertEqual(relay.get_proxy_address().port, 5000)

    @patch("src.relays.udp_relay.generate_udp_socket")
    def test_listen_and_relay_handles_socket_error(self, mock_gen_socket):
        mock_proxy_sock = MagicMock()
        mock_proxy_sock.getsockname.return_value = ("0.0.0.0", 5000)
        mock_gen_socket.return_value = mock_proxy_sock

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test", ip="1.2.3.4", port=80,
            address_type=AddressTypeCodes.IPv4,
        )
        relay = UDPRelay(client_conn, dst)

        # recvfrom raises a socket error
        mock_proxy_sock.recvfrom.side_effect = OSError("network down")

        # Should not raise — error should be handled gracefully
        relay.listen_and_relay()


if __name__ == "__main__":
    unittest.main()
