import socket
import threading
import unittest

import pytest

from simple_socks5.constants import AddressTypeCodes, MethodCodes, ReplyCodes
from simple_socks5.models import BaseAddress, DetailedAddress
from simple_socks5.utils import (
    WarningRateLimiter,
    format_connection_closed,
    format_connection_established,
    format_relay,
    generate_connection_method_response,
    generate_failed_reply,
    generate_succeeded_reply,
    generate_tcp_socket,
    map_address_enum_to_socket_family,
    map_address_int_to_enum,
    map_address_to_bytes,
)

IPV4_ZERO_ADDRESS = b"\x00" * 4 + b"\x00\x00"
IPV6_ZERO_ADDRESS = b"\x00" * 16 + b"\x00\x00"


@pytest.mark.parametrize("reply_code", [code for code in ReplyCodes if code is not ReplyCodes.SUCCEEDED])
@pytest.mark.parametrize(
    ("address_type", "expected_tail"),
    [
        (AddressTypeCodes.IPv4, b"\x00\x01" + IPV4_ZERO_ADDRESS),
        (AddressTypeCodes.IPv6, b"\x00\x04" + IPV6_ZERO_ADDRESS),
        # A domain name has no fixed-size zero address, so the reply uses IPv4's
        (AddressTypeCodes.DOMAIN_NAME, b"\x00\x01" + IPV4_ZERO_ADDRESS),
    ],
)
def test_generate_failed_reply(reply_code: ReplyCodes, address_type: AddressTypeCodes, expected_tail: bytes) -> None:
    assert generate_failed_reply(address_type, reply_code) == bytes([0x05, reply_code.value]) + expected_tail


class TestAddressToBytesUtils(unittest.TestCase):
    def test_translate_address_to_bytes__ipv4_1(self) -> None:
        address_type = AddressTypeCodes.IPv4
        ip = "127.127.64.5"
        expected_bytes = map_address_to_bytes(address_type, ip)
        assert expected_bytes == b"\x7f\x7f@\x05"

    def test_translate_address_to_bytes__ipv4_2(self) -> None:
        address_type = AddressTypeCodes.IPv4
        ip = "208.54.62.80"
        expected_bytes = map_address_to_bytes(address_type, ip)
        assert expected_bytes == b"\xd06>P"

    def test_translate_address_to_bytes__ipv4_3(self) -> None:
        address_type = AddressTypeCodes.IPv4
        ip = "17.248.230.65"
        expected_bytes = map_address_to_bytes(address_type, ip)
        assert expected_bytes == b"\x11\xf8\xe6A"

    def test_translate_address_to_bytes__ipv6_full(self) -> None:
        address_type = AddressTypeCodes.IPv6
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        expected_bytes = map_address_to_bytes(address_type, ip)
        assert expected_bytes == b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4"

    def test_translate_address_to_bytes__ipv6_loopback(self) -> None:
        address_type = AddressTypeCodes.IPv6
        ip = "::1"
        expected_bytes = map_address_to_bytes(address_type, ip)
        assert expected_bytes == b"\x00" * 15 + b"\x01"

    def test_translate_address_to_bytes__ipv6_link_local(self) -> None:
        address_type = AddressTypeCodes.IPv6
        ip = "fe80::1"
        expected_bytes = map_address_to_bytes(address_type, ip)
        assert expected_bytes == b"\xfe\x80" + b"\x00" * 13 + b"\x01"

    def test_translate_address_to_bytes__domain_name(self) -> None:
        address_type = AddressTypeCodes.DOMAIN_NAME
        ip = "google.com"
        with pytest.raises(ValueError, match="not suitable for byte translation"):
            map_address_to_bytes(address_type, ip)


class TestConnectionMethodResponseUtils(unittest.TestCase):
    def test_generate_connection_method_response__no_authentication_required(self) -> None:
        method = MethodCodes.NO_AUTHENTICATION_REQUIRED
        expected_response = generate_connection_method_response(method)
        assert expected_response == b"\x05\x00"

    def test_generate_connection_method_response__gssapi(self) -> None:
        method = MethodCodes.GSSAPI
        expected_response = generate_connection_method_response(method)
        assert expected_response == b"\x05\x01"

    def test_generate_connection_method_response__username_password(self) -> None:
        method = MethodCodes.USERNAME_PASSWORD
        expected_response = generate_connection_method_response(method)
        assert expected_response == b"\x05\x02"

    def test_generate_connection_method_response__no_acceptable_methods(self) -> None:
        method = MethodCodes.NO_ACCEPTABLE_METHODS
        expected_response = generate_connection_method_response(method)
        assert expected_response == b"\x05\xff"


class TestMapAddressTypeUtils(unittest.TestCase):
    def test_map_address_int_to_enum__ipv4(self) -> None:
        address_type = AddressTypeCodes.IPv4.value
        expected_enum = map_address_int_to_enum(address_type)
        assert expected_enum == AddressTypeCodes.IPv4

    def test_map_address_int_to_enum__ipv6(self) -> None:
        address_type = AddressTypeCodes.IPv6.value
        expected_enum = map_address_int_to_enum(address_type)
        assert expected_enum == AddressTypeCodes.IPv6

    def test_map_address_int_to_enum__domain_name(self) -> None:
        address_type = AddressTypeCodes.DOMAIN_NAME.value
        expected_enum = map_address_int_to_enum(address_type)
        assert expected_enum == AddressTypeCodes.DOMAIN_NAME

    def test_map_address_type_to_socket_family__ipv4(self) -> None:
        address_type = AddressTypeCodes.IPv4
        expected_family = map_address_enum_to_socket_family(address_type)
        assert expected_family == socket.AF_INET

    def test_map_address_type_to_socket_family__ipv6(self) -> None:
        address_type = AddressTypeCodes.IPv6
        expected_family = map_address_enum_to_socket_family(address_type)
        assert expected_family == socket.AF_INET6

    def test_map_address_type_to_socket_family__domain_name(self) -> None:
        address_type = AddressTypeCodes.DOMAIN_NAME
        with pytest.raises(ValueError, match="Unknown address type"):
            map_address_enum_to_socket_family(address_type)


class TestSuccessUtils(unittest.TestCase):
    def test_generate_succeeded_reply__ipv4_1(self) -> None:
        address_type = AddressTypeCodes.IPv4
        ip = "17.248.230.65"
        port = 443
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        assert expected_reply == b"\x05\x00\x00\x01\x11\xf8\xe6A\x01\xbb"

    def test_generate_succeeded_reply__ipv4_2(self) -> None:
        address_type = AddressTypeCodes.IPv4
        ip = "8.4.2.1"
        port = 10
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        assert expected_reply == b"\x05\x00\x00\x01\x08\x04\x02\x01\x00\n"

    def test_generate_succeeded_reply__ipv4_3(self) -> None:
        address_type = AddressTypeCodes.IPv4
        ip = "127.0.0.1"
        port = 80
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        assert expected_reply == b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00P"

    def test_generate_succeeded_reply__ipv6(self) -> None:
        address_type = AddressTypeCodes.IPv6
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        port = 443
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        # VER=05, REP=00, RSV=00, ATYP=04, then 16-byte IPv6 addr, then port
        expected = b"\x05\x00\x00\x04\x20\x01\x0d\xb8\x85\xa3\x00\x00\x00\x00\x8a\x2e\x03\x70\x73\x34\x01\xbb"
        assert expected_reply == expected


class TestGenerateSocketUtils(unittest.TestCase):
    def test_generate_tcp_socket__ipv4(self) -> None:
        sock = generate_tcp_socket(AddressTypeCodes.IPv4)
        self.addCleanup(sock.close)
        assert isinstance(sock, socket.socket)
        assert sock.family == socket.AF_INET
        assert sock.type == socket.SOCK_STREAM

    def test_generate_tcp_socket__ipv6(self) -> None:
        sock = generate_tcp_socket(AddressTypeCodes.IPv6)
        self.addCleanup(sock.close)
        assert isinstance(sock, socket.socket)
        assert sock.family == socket.AF_INET6
        assert sock.type == socket.SOCK_STREAM

    def test_generate_tcp_socket__domain_name(self) -> None:
        address = DetailedAddress(
            name="Test Localhost",
            ip="google.com",
            port=80,
            address_type=AddressTypeCodes.DOMAIN_NAME,
        )
        with pytest.raises(ValueError, match="Unknown address type"):
            generate_tcp_socket(address.address_type)


class TestConnectionLogLines(unittest.TestCase):
    dst = DetailedAddress(ip="93.184.216.34", port=443, name="example.com", address_type=AddressTypeCodes.IPv4)

    def test_connection_established(self) -> None:
        assert (
            format_connection_established(BaseAddress("172.17.0.1", 51234), self.dst)
            == "CONNECTION | 172.17.0.1:51234 -> example.com:443 (93.184.216.34)"
        )

    def test_connection_established_ipv6_in_brackets(self) -> None:
        dst = DetailedAddress(ip="::1", port=80, name="::1", address_type=AddressTypeCodes.IPv6)
        assert format_connection_established(BaseAddress("::1", 5000), dst) == "CONNECTION | [::1]:5000 -> [::1]:80"

    def test_connection_closed(self) -> None:
        assert (
            format_connection_closed(
                BaseAddress("172.17.0.1", 51234), self.dst, bytes_up=517, bytes_down=10485943, duration=2.314
            )
            == "CLOSED | 172.17.0.1:51234 -> example.com:443 (93.184.216.34) | up=517 B down=10485943 B | 2.31 s"
        )

    def test_format_relay_ipv4_unchanged(self) -> None:
        assert (
            format_relay("UDP", BaseAddress("172.17.0.1", 51234), BaseAddress("8.8.8.8", 53), 42)
            == "RELAY | UDP | 172.17.0.1:51234 -> 8.8.8.8:53 | 42 bytes"
        )

    def test_format_relay_brackets_ipv6(self) -> None:
        assert (
            format_relay("UDP", BaseAddress("::1", 5000), BaseAddress("2001:db8::1", 53), 42)
            == "RELAY | UDP | [::1]:5000 -> [2001:db8::1]:53 | 42 bytes"
        )


class TestWarningRateLimiter(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 100.0
        self.limiter = WarningRateLimiter(10.0, clock=lambda: self.now)

    def test_first_hit_warns_with_count_1(self) -> None:
        assert self.limiter.hit() == 1

    def test_hits_inside_window_return_none(self) -> None:
        self.limiter.hit()
        self.now += 9.9
        assert [self.limiter.hit() for _ in range(3)] == [None] * 3

    def test_first_hit_after_window_returns_accumulated_count(self) -> None:
        self.limiter.hit()
        for _ in range(4):
            self.limiter.hit()
        self.now += 10.0
        assert self.limiter.hit() == 5
        assert self.limiter.hit() is None

    def test_concurrent_hits_are_all_counted(self) -> None:
        results: list[int | None] = []
        lock = threading.Lock()

        def hit_many() -> None:
            for _ in range(100):
                count = self.limiter.hit()
                with lock:
                    results.append(count)

        threads = [threading.Thread(target=hit_many) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.now += 10.0
        assert [c for c in results if c is not None] == [1]
        assert self.limiter.hit() == 800


if __name__ == "__main__":
    unittest.main()
