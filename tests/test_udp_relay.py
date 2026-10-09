import os
import re
import select
import socket
import struct
import threading
import unittest
from unittest.mock import MagicMock, patch

import pytest

from simple_socks5.constants import AddressTypeCodes
from simple_socks5.handlers.udp import UDPHandler
from simple_socks5.models import DetailedAddress
from simple_socks5.relays.udp_relay import UDPRelay


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
        assert header == expected

    def test_ipv6_response_header(self):
        addr = "2001:db8::1"
        header = UDPHandler.build_udp_response_header(addr, 443)
        # RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22 bytes
        expected = b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, addr) + struct.pack("!H", 443)
        assert header == expected

    def test_invalid_address_raises(self):
        with pytest.raises(ValueError):
            UDPHandler.build_udp_response_header("not-an-ip", 80)


CLIENT_ADDR = ("127.0.0.1", 1234)


@patch("simple_socks5.relays.udp_relay.generate_udp_socket")
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
        with patch("simple_socks5.relays.udp_relay.socket.socket", return_value=forward_socket):
            assert self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"hello"), CLIENT_ADDR)

        forward_socket.sendto.assert_called_once_with(b"hello", ("10.0.0.1", 53))
        # RSV(2) + FRAG(1) + ATYP(1)=IPv4 + ADDR(4) + PORT(2) + DATA
        expected = b"\x00\x00\x00\x01" + socket.inet_aton("10.0.0.1") + struct.pack("!H", 53) + b"response"
        self.relay.proxy_connection.sendto.assert_called_once_with(expected, CLIENT_ADDR)

    def test_counts_payload_bytes_each_direction(self):
        with patch("simple_socks5.relays.udp_relay.socket.socket", return_value=mock_forward_socket(b"response")):
            self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"hello"), CLIENT_ADDR)
            self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"hi"), CLIENT_ADDR)

        assert (self.relay.bytes_up, self.relay.bytes_down) == (7, 16)

    def test_dropped_datagram_not_counted(self):
        with patch("simple_socks5.relays.udp_relay.socket.socket"):
            self.relay._handle_datagram(b"\x00\x00", CLIENT_ADDR)
            self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"x"), ("192.168.1.99", 5))

        assert (self.relay.bytes_up, self.relay.bytes_down) == (0, 0)

    def test_foreign_source_dropped_returns_false(self):
        """RFC 1928 Section 7: drop datagrams from IPs other than the client."""
        with patch("simple_socks5.relays.udp_relay.socket.socket") as socket_class:
            assert not self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"x"), ("192.168.1.99", 5))
        socket_class.assert_not_called()

    def test_fragmented_dropped(self):
        with patch("simple_socks5.relays.udp_relay.socket.socket") as socket_class:
            assert self.relay._handle_datagram(build_udp_datagram("10.0.0.1", 53, b"x", frag=1), CLIENT_ADDR)
        socket_class.assert_not_called()

    def test_malformed_dropped_with_debug_log(self):
        for data in (b"\x00\x05", b"\x00\x01" + build_udp_datagram("10.0.0.1", 53, b"x")[2:], b"\x00\x00\x00\x09"):
            with (
                self.subTest(data=data),
                patch("simple_socks5.relays.udp_relay.socket.socket") as socket_class,
                self.assertLogs("simple_socks5.relays", level="DEBUG") as logs,
            ):
                assert self.relay._handle_datagram(data, CLIENT_ADDR)
            socket_class.assert_not_called()
            assert "malformed UDP datagram" in logs.output[0]

    def test_forward_oserror_dropped(self):
        forward_socket = mock_forward_socket()
        forward_socket.sendto.side_effect = PermissionError(13, "Permission denied")
        with patch("simple_socks5.relays.udp_relay.socket.socket", return_value=forward_socket):
            assert self.relay._handle_datagram(build_udp_datagram("255.255.255.255", 53, b"x"), CLIENT_ADDR)


class TestHandleDatagramDestinationPolicy(unittest.TestCase):
    def setUp(self):
        environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        patcher = patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.relay = make_relay()

    def test_datagram_to_loopback_dropped_at_debug_and_association_kept(self):
        for dst, atyp in (("127.0.0.1", 1), ("169.254.169.254", 1), ("::ffff:127.0.0.1", 4)):
            with (
                self.subTest(dst=dst),
                patch("simple_socks5.relays.udp_relay.socket.socket") as socket_class,
                self.assertLogs("simple_socks5.relays", level="DEBUG") as logs,
            ):
                assert self.relay._handle_datagram(build_udp_datagram(dst, 53, b"x", atyp=atyp), CLIENT_ADDR)
            socket_class.assert_not_called()
            assert len(logs.records) == 1
            assert logs.records[0].levelname == "DEBUG"
            assert "blocked by the destination policy" in logs.output[0]

    def test_datagram_to_loopback_forwarded_with_opt_out(self):
        forward_socket = mock_forward_socket()
        with (
            patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": "true"}),
            patch("simple_socks5.relays.udp_relay.socket.socket", return_value=forward_socket),
        ):
            assert self.relay._handle_datagram(build_udp_datagram("127.0.0.1", 53, b"x"), CLIENT_ADDR)
        forward_socket.sendto.assert_called_once_with(b"x", ("127.0.0.1", 53))


class TestUDPRelay(unittest.TestCase):
    @patch("simple_socks5.relays.udp_relay.generate_udp_socket")
    def test_init_creates_and_binds_socket(self, mock_gen_socket):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("0.0.0.0", 5000)
        mock_gen_socket.return_value = mock_sock

        client_conn = MagicMock()
        client_conn.getpeername.return_value = ("127.0.0.1", 1234)
        dst = DetailedAddress(
            name="test",
            ip="1.2.3.4",
            port=80,
            address_type=AddressTypeCodes.IPv4,
        )

        relay = UDPRelay(client_conn, dst)
        mock_sock.bind.assert_called_once_with(("", 0))
        mock_sock.setblocking.assert_called_once_with(False)
        assert relay.get_proxy_address().ip == "0.0.0.0"
        assert relay.get_proxy_address().port == 5000


JOIN_TIMEOUT = 2.0  # seconds


class TestListenAndRelay(unittest.TestCase):
    """The association loop, on a real loopback control connection and UDP socket."""

    def setUp(self):
        with socket.create_server(("127.0.0.1", 0)) as listener:
            self.control = socket.create_connection(listener.getsockname())
            self.addCleanup(self.control.close)
            accepted, _ = listener.accept()
        self.addCleanup(accepted.close)
        dst = DetailedAddress(name="test", ip="0.0.0.0", port=0, address_type=AddressTypeCodes.IPv4)
        self.relay = UDPRelay(accepted, dst)
        self.addCleanup(self.relay.proxy_connection.close)
        self.relay_address = ("127.0.0.1", self.relay.get_proxy_port())

    def start_relay(self) -> threading.Thread:
        thread = threading.Thread(target=self.relay.listen_and_relay)
        thread.start()
        self.addCleanup(thread.join, JOIN_TIMEOUT)
        return thread

    def assert_relay_ends(self, thread: threading.Thread) -> None:
        thread.join(JOIN_TIMEOUT)
        assert not thread.is_alive(), "association did not end"
        assert self.relay.proxy_connection.fileno() == -1

    def send_datagrams(self, *datagrams: bytes) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            for datagram in datagrams:
                udp.sendto(datagram, self.relay_address)

    def test_control_close_ends_association(self):
        thread = self.start_relay()
        self.control.close()
        self.assert_relay_ends(thread)

    def test_end_logs_one_closed_line(self):
        self.relay.bytes_up, self.relay.bytes_down = 12, 8
        with self.assertLogs("simple_socks5.relays.udp_relay", level="INFO") as logs:
            thread = self.start_relay()
            self.control.close()
            self.assert_relay_ends(thread)

        assert len(logs.records) == 1, logs.output
        assert logs.records[0].levelname == "INFO"
        assert re.search(
            r"^CLOSED \| 127\.0\.0\.1:\d+ -> test:0 \(0\.0\.0\.0\) \| up=12 B down=8 B \| \d+\.\d\d s$",
            logs.records[0].getMessage(),
        )

    def test_control_reset_ends_association(self):
        thread = self.start_relay()
        self.control.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.control.close()
        self.assert_relay_ends(thread)

    def test_control_data_ignored_then_close_ends(self):
        thread = self.start_relay()
        self.control.sendall(b"unexpected")
        readable, _, _ = select.select([self.control], [], [], 0.2)
        assert readable == [], "relay wrote to or closed the control connection"
        assert thread.is_alive()
        self.control.close()
        self.assert_relay_ends(thread)

    def test_idle_timeout_ends_association(self):
        with patch("simple_socks5.relays.udp_relay.UDP_RECV_TIMEOUT", 0.2):
            thread = self.start_relay()
            self.assert_relay_ends(thread)

    def test_malformed_then_valid_forwards_valid(self):
        forwarded = threading.Event()
        with patch.object(self.relay, "_forward_packet", side_effect=lambda *_: forwarded.set()) as forward:
            thread = self.start_relay()
            self.send_datagrams(b"\x00\x00", build_udp_datagram("10.0.0.1", 53, b"hello"))
            assert forwarded.wait(JOIN_TIMEOUT)
            self.control.close()
            self.assert_relay_ends(thread)
        forward.assert_called_once()
        assert forward.call_args[0][0].data == b"hello"

    def test_spurious_readiness_keeps_association(self):
        """select() may report a datagram that recvfrom then finds discarded (e.g. a bad UDP checksum)."""
        real_recvfrom = self.relay.proxy_connection.recvfrom
        calls = []

        def recvfrom(size):
            calls.append(size)
            if len(calls) == 1:
                raise BlockingIOError
            return real_recvfrom(size)

        self.relay.proxy_connection = MagicMock(wraps=self.relay.proxy_connection)
        self.relay.proxy_connection.recvfrom.side_effect = recvfrom
        forwarded = threading.Event()
        with patch.object(self.relay, "_forward_packet", side_effect=lambda *_: forwarded.set()):
            thread = self.start_relay()
            self.send_datagrams(build_udp_datagram("10.0.0.1", 53, b"hello"))
            assert forwarded.wait(JOIN_TIMEOUT)
            self.control.close()
            self.assert_relay_ends(thread)

    def test_relay_socket_error_ends_association(self):
        self.relay.proxy_connection = MagicMock(wraps=self.relay.proxy_connection)
        self.relay.proxy_connection.recvfrom.side_effect = OSError("network down")
        thread = self.start_relay()
        self.send_datagrams(b"readable")
        self.assert_relay_ends(thread)


if __name__ == "__main__":
    unittest.main()
