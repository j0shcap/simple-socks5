import unittest

from simple_socks5.constants import AddressTypeCodes
from simple_socks5.models import BaseAddress, DetailedAddress, UDPDatagram


class TestBaseAddressStr(unittest.TestCase):
    def test_ipv4(self) -> None:
        assert str(BaseAddress("0.0.0.0", 1080)) == "0.0.0.0:1080"

    def test_base_address_brackets_ipv6(self) -> None:
        assert str(BaseAddress("::", 1080)) == "[::]:1080"


class TestDetailedAddressStr(unittest.TestCase):
    def test_ip_literal_shown_once(self) -> None:
        address = DetailedAddress(ip="1.1.1.1", port=443, name="1.1.1.1", address_type=AddressTypeCodes.IPv4)
        assert str(address) == "1.1.1.1:443"

    def test_hostname_shown_with_resolved_ip(self) -> None:
        address = DetailedAddress(ip="93.184.216.34", port=443, name="example.com", address_type=AddressTypeCodes.IPv4)
        assert str(address) == "example.com:443 (93.184.216.34)"

    def test_ipv6_literal_in_brackets(self) -> None:
        address = DetailedAddress(ip="2001:db8::1", port=443, name="2001:db8::1", address_type=AddressTypeCodes.IPv6)
        assert str(address) == "[2001:db8::1]:443"


class TestUDPDatagramStr(unittest.TestCase):
    def test_data_shown_as_bytes_literal(self) -> None:
        datagram = UDPDatagram(
            frag=0, address_type=AddressTypeCodes.IPv4, dst_addr="8.8.8.8", dst_port=53, data=b"\x00hi"
        )
        assert str(datagram) == (
            "Fragment: 0, Address Type: AddressTypeCodes.IPv4, Destination Address: 8.8.8.8, "
            "Destination Port: 53, Data: b'\\x00hi'"
        )
