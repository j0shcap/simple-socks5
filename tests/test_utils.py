import socket
import unittest

from simple_socks5.constants import AddressTypeCodes, MethodCodes
from simple_socks5.models import DetailedAddress
from simple_socks5.utils import (
    format_connection_closed,
    format_connection_established,
    generate_address_type_not_supported_reply,
    generate_command_not_supported_reply,
    generate_connection_method_response,
    generate_connection_not_allowed_by_ruleset_reply,
    generate_connection_refused_reply,
    generate_general_socks_server_failure_reply,
    generate_host_unreachable_reply,
    generate_network_unreachable_reply,
    generate_succeeded_reply,
    generate_tcp_socket,
    generate_ttl_expired_reply,
    map_address_enum_to_socket_family,
    map_address_int_to_enum,
    map_address_to_bytes,
)


class TestErrorUtils(unittest.TestCase):
    def test_generate_general_socks_server_failure_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_general_socks_server_failure_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_general_socks_server_failure_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_general_socks_server_failure_reply(address_type)
        # ATYP=0x04 means 16-byte IPv6 address field + 2-byte port
        expected = b"\x05\x01\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_general_socks_server_failure_reply__domain_name(self):
        result = generate_general_socks_server_failure_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_connection_refused_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_connection_refused_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_connection_refused_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_connection_refused_reply(address_type)
        expected = b"\x05\x05\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_connection_refused_reply__domain_name(self):
        result = generate_connection_refused_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_network_unreachable_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_network_unreachable_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_network_unreachable_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_network_unreachable_reply(address_type)
        expected = b"\x05\x03\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_network_unreachable_reply__domain_name(self):
        result = generate_network_unreachable_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_host_unreachable_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_host_unreachable_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_host_unreachable_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_host_unreachable_reply(address_type)
        expected = b"\x05\x04\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_host_unreachable_reply__domain_name(self):
        result = generate_host_unreachable_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_address_type_not_supported_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_address_type_not_supported_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_address_type_not_supported_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_address_type_not_supported_reply(address_type)
        expected = b"\x05\x08\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_address_type_not_supported_reply__domain_name(self):
        result = generate_address_type_not_supported_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_connection_not_allowed_by_ruleset_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_connection_not_allowed_by_ruleset_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_connection_not_allowed_by_ruleset_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_connection_not_allowed_by_ruleset_reply(address_type)
        expected = b"\x05\x02\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_connection_not_allowed_by_ruleset_reply__domain_name(self):
        result = generate_connection_not_allowed_by_ruleset_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_ttl_expired_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_ttl_expired_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x06\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_ttl_expired_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_ttl_expired_reply(address_type)
        expected = b"\x05\x06\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)

    def test_generate_ttl_expired_reply__domain_name(self):
        result = generate_ttl_expired_reply(AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual(result, b"\x05\x06\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_command_not_supported_reply__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_reply = generate_command_not_supported_reply(address_type)
        self.assertEqual(expected_reply, b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")

    def test_generate_command_not_supported_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_reply = generate_command_not_supported_reply(address_type)
        expected = b"\x05\x07\x00\x04" + b"\x00" * 16 + b"\x00\x00"
        self.assertEqual(expected_reply, expected)


class TestAddressToBytesUtils(unittest.TestCase):
    def test_translate_address_to_bytes__ipv4_1(self):
        address_type = AddressTypeCodes.IPv4
        ip = "127.127.64.5"
        expected_bytes = map_address_to_bytes(address_type, ip)
        self.assertEqual(expected_bytes, b"\x7f\x7f\x40\x05")

    def test_translate_address_to_bytes__ipv4_2(self):
        address_type = AddressTypeCodes.IPv4
        ip = "208.54.62.80"
        expected_bytes = map_address_to_bytes(address_type, ip)
        self.assertEqual(expected_bytes, b"\xd0\x36\x3e\x50")

    def test_translate_address_to_bytes__ipv4_3(self):
        address_type = AddressTypeCodes.IPv4
        ip = "17.248.230.65"
        expected_bytes = map_address_to_bytes(address_type, ip)
        self.assertEqual(expected_bytes, b"\x11\xf8\xe6\x41")

    def test_translate_address_to_bytes__ipv6_full(self):
        address_type = AddressTypeCodes.IPv6
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        expected_bytes = map_address_to_bytes(address_type, ip)
        self.assertEqual(
            expected_bytes,
            b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4",
        )

    def test_translate_address_to_bytes__ipv6_loopback(self):
        address_type = AddressTypeCodes.IPv6
        ip = "::1"
        expected_bytes = map_address_to_bytes(address_type, ip)
        self.assertEqual(
            expected_bytes,
            b"\x00" * 15 + b"\x01",
        )

    def test_translate_address_to_bytes__ipv6_link_local(self):
        address_type = AddressTypeCodes.IPv6
        ip = "fe80::1"
        expected_bytes = map_address_to_bytes(address_type, ip)
        self.assertEqual(
            expected_bytes,
            b"\xfe\x80" + b"\x00" * 13 + b"\x01",
        )

    def test_translate_address_to_bytes__domain_name(self):
        address_type = AddressTypeCodes.DOMAIN_NAME
        ip = "google.com"
        with self.assertRaises(ValueError):
            map_address_to_bytes(address_type, ip)


class TestConnectionMethodResponseUtils(unittest.TestCase):
    def test_generate_connection_method_response__no_authentication_required(self):
        method = MethodCodes.NO_AUTHENTICATION_REQUIRED
        expected_response = generate_connection_method_response(method)
        self.assertEqual(expected_response, b"\x05\x00")

    def test_generate_connection_method_response__gssapi(self):
        method = MethodCodes.GSSAPI
        expected_response = generate_connection_method_response(method)
        self.assertEqual(expected_response, b"\x05\x01")

    def test_generate_connection_method_response__username_password(self):
        method = MethodCodes.USERNAME_PASSWORD
        expected_response = generate_connection_method_response(method)
        self.assertEqual(expected_response, b"\x05\x02")

    def test_generate_connection_method_response__no_acceptable_methods(self):
        method = MethodCodes.NO_ACCEPTABLE_METHODS
        expected_response = generate_connection_method_response(method)
        self.assertEqual(expected_response, b"\x05\xff")


class TestMapAddressTypeUtils(unittest.TestCase):
    def test_map_address_int_to_enum__ipv4(self):
        address_type = AddressTypeCodes.IPv4.value
        expected_enum = map_address_int_to_enum(address_type)
        self.assertEqual(expected_enum, AddressTypeCodes.IPv4)

    def test_map_address_int_to_enum__ipv6(self):
        address_type = AddressTypeCodes.IPv6.value
        expected_enum = map_address_int_to_enum(address_type)
        self.assertEqual(expected_enum, AddressTypeCodes.IPv6)

    def test_map_address_int_to_enum__domain_name(self):
        address_type = AddressTypeCodes.DOMAIN_NAME.value
        expected_enum = map_address_int_to_enum(address_type)
        self.assertEqual(expected_enum, AddressTypeCodes.DOMAIN_NAME)

    def test_map_address_type_to_socket_family__ipv4(self):
        address_type = AddressTypeCodes.IPv4
        expected_family = map_address_enum_to_socket_family(address_type)
        self.assertEqual(expected_family, socket.AF_INET)

    def test_map_address_type_to_socket_family__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        expected_family = map_address_enum_to_socket_family(address_type)
        self.assertEqual(expected_family, socket.AF_INET6)

    def test_map_address_type_to_socket_family__domain_name(self):
        address_type = AddressTypeCodes.DOMAIN_NAME
        with self.assertRaises(ValueError):
            map_address_enum_to_socket_family(address_type)


class TestSuccessUtils(unittest.TestCase):
    def test_generate_succeeded_reply__ipv4_1(self):
        address_type = AddressTypeCodes.IPv4
        ip = "17.248.230.65"
        port = 443
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        self.assertEqual(
            expected_reply,
            b"\x05\x00\x00\x01\x11\xf8\xe6\x41\x01\xbb",
        )

    def test_generate_succeeded_reply__ipv4_2(self):
        address_type = AddressTypeCodes.IPv4
        ip = "8.4.2.1"
        port = 10
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        self.assertEqual(
            expected_reply,
            b"\x05\x00\x00\x01\x08\x04\x02\x01\x00\x0a",
        )

    def test_generate_succeeded_reply__ipv4_3(self):
        address_type = AddressTypeCodes.IPv4
        ip = "127.0.0.1"
        port = 80
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        self.assertEqual(
            expected_reply,
            b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
        )

    def test_generate_succeeded_reply__ipv6(self):
        address_type = AddressTypeCodes.IPv6
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        port = 443
        expected_reply = generate_succeeded_reply(address_type, ip, port)
        # VER=05, REP=00, RSV=00, ATYP=04, then 16-byte IPv6 addr, then port
        expected = b"\x05\x00\x00\x04\x20\x01\x0d\xb8\x85\xa3\x00\x00\x00\x00\x8a\x2e\x03\x70\x73\x34\x01\xbb"
        self.assertEqual(expected_reply, expected)


class TestGenerateSocketUtils(unittest.TestCase):
    def test_generate_tcp_socket__ipv4(self):
        sock = generate_tcp_socket(AddressTypeCodes.IPv4)
        self.addCleanup(sock.close)
        self.assertIsInstance(sock, socket.socket)
        self.assertEqual(sock.family, socket.AF_INET)
        self.assertEqual(sock.type, socket.SOCK_STREAM)

    def test_generate_tcp_socket__ipv6(self):
        sock = generate_tcp_socket(AddressTypeCodes.IPv6)
        self.addCleanup(sock.close)
        self.assertIsInstance(sock, socket.socket)
        self.assertEqual(sock.family, socket.AF_INET6)
        self.assertEqual(sock.type, socket.SOCK_STREAM)

    def test_generate_tcp_socket__domain_name(self):
        address = DetailedAddress(
            name="Test Localhost",
            ip="google.com",
            port=80,
            address_type=AddressTypeCodes.DOMAIN_NAME,
        )
        with self.assertRaises(ValueError):
            generate_tcp_socket(address.address_type)


class TestConnectionLogLines(unittest.TestCase):
    dst = DetailedAddress(ip="93.184.216.34", port=443, name="example.com", address_type=AddressTypeCodes.IPv4)

    def test_connection_established(self):
        self.assertEqual(
            format_connection_established("172.17.0.1", 51234, self.dst),
            "CONNECTION | 172.17.0.1:51234 -> example.com:443 (93.184.216.34)",
        )

    def test_connection_established_ipv6_in_brackets(self):
        dst = DetailedAddress(ip="::1", port=80, name="::1", address_type=AddressTypeCodes.IPv6)
        self.assertEqual(format_connection_established("::1", 5000, dst), "CONNECTION | [::1]:5000 -> [::1]:80")

    def test_connection_closed(self):
        self.assertEqual(
            format_connection_closed("172.17.0.1", 51234, self.dst, bytes_up=517, bytes_down=10485943, duration=2.314),
            "CLOSED | 172.17.0.1:51234 -> example.com:443 (93.184.216.34) | up=517 B down=10485943 B | 2.31 s",
        )


if __name__ == "__main__":
    unittest.main()
