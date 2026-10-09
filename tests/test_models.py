import unittest

from simple_socks5.constants import AddressTypeCodes
from simple_socks5.models import DetailedAddress


class TestDetailedAddressStr(unittest.TestCase):
    def test_ip_literal_shown_once(self):
        address = DetailedAddress(ip="1.1.1.1", port=443, name="1.1.1.1", address_type=AddressTypeCodes.IPv4)
        self.assertEqual(str(address), "1.1.1.1:443")

    def test_hostname_shown_with_resolved_ip(self):
        address = DetailedAddress(
            ip="93.184.216.34", port=443, name="example.com", address_type=AddressTypeCodes.IPv4
        )
        self.assertEqual(str(address), "example.com:443 (93.184.216.34)")

    def test_ipv6_literal_in_brackets(self):
        address = DetailedAddress(ip="2001:db8::1", port=443, name="2001:db8::1", address_type=AddressTypeCodes.IPv6)
        self.assertEqual(str(address), "[2001:db8::1]:443")
