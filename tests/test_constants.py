"""
Ensures that the constants are correct and that hex values are correctly mapped to integers.
"""

import unittest
from src.constants import ReplyCodes, MethodCodes, AddressTypeCodes, CommandCodes, RELAY_BUFFER_SIZE


class TestReplyCodes(unittest.TestCase):
    def test_succeeded(self):
        self.assertEqual(ReplyCodes.SUCCEEDED.value, 0)

    def test_general_socks_server_failure(self):
        self.assertEqual(ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE.value, 1)

    def test_connection_not_allowed_by_ruleset(self):
        self.assertEqual(ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET.value, 2)

    def test_network_unreachable(self):
        self.assertEqual(ReplyCodes.NETWORK_UNREACHABLE.value, 3)

    def test_host_unreachable(self):
        self.assertEqual(ReplyCodes.HOST_UNREACHABLE.value, 4)

    def test_connection_refused(self):
        self.assertEqual(ReplyCodes.CONNECTION_REFUSED.value, 5)

    def test_ttl_expired(self):
        self.assertEqual(ReplyCodes.TTL_EXPIRED.value, 6)

    def test_command_not_supported(self):
        self.assertEqual(ReplyCodes.COMMAND_NOT_SUPPORTED.value, 7)

    def test_address_type_not_supported(self):
        self.assertEqual(ReplyCodes.ADDRESS_TYPE_NOT_SUPPORTED.value, 8)

    def test_unassigned(self):
        self.assertEqual(ReplyCodes.UNASSIGNED.value, 9)


class TestMethodCodes(unittest.TestCase):
    def test_no_authentication_required(self):
        self.assertEqual(MethodCodes.NO_AUTHENTICATION_REQUIRED.value, 0)

    def test_gssapi(self):
        self.assertEqual(MethodCodes.GSSAPI.value, 1)

    def test_username_password(self):
        self.assertEqual(MethodCodes.USERNAME_PASSWORD.value, 2)

    def test_no_acceptable_methods(self):
        self.assertEqual(MethodCodes.NO_ACCEPTABLE_METHODS.value, 255)


class TestAddressTypeCodes(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(AddressTypeCodes.IPv4.value, 1)

    def test_domain_name(self):
        self.assertEqual(AddressTypeCodes.DOMAIN_NAME.value, 3)

    def test_ipv6(self):
        self.assertEqual(AddressTypeCodes.IPv6.value, 4)


class TestCommandCodes(unittest.TestCase):
    def test_connect(self):
        self.assertEqual(CommandCodes.CONNECT.value, 1)

    def test_bind(self):
        self.assertEqual(CommandCodes.BIND.value, 2)

    def test_udp_associate(self):
        self.assertEqual(CommandCodes.UDP_ASSOCIATE.value, 3)


class TestRelayConstants(unittest.TestCase):
    def test_relay_buffer_size(self):
        self.assertEqual(RELAY_BUFFER_SIZE, 65536)


if __name__ == '__main__':
    unittest.main()
