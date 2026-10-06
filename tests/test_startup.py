"""
Tests for the startup advisories that describe the proxy's exposure.
"""
import unittest
from unittest.mock import patch

from src.startup import is_loopback_host

LOOPBACK_HOSTS = ("localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1")
EXPOSED_HOSTS = (
    "0.0.0.0",
    "::",
    "",
    "192.168.1.10",
    "::ffff:10.0.0.1",
    "example.org",
    "localhost.example.com",
    "127.0.0.1.nip.io",
)


class TestIsLoopbackHost(unittest.TestCase):
    def test_loopback_hosts(self):
        for host in LOOPBACK_HOSTS:
            with self.subTest(host=host):
                self.assertTrue(is_loopback_host(host))

    def test_exposed_hosts(self):
        for host in EXPOSED_HOSTS:
            with self.subTest(host=host):
                self.assertFalse(is_loopback_host(host))

    def test_no_dns_lookup(self):
        """Hostnames are classified without resolving them."""
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")), \
                patch("socket.gethostbyname", side_effect=AssertionError("DNS lookup")), \
                patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS lookup")):
            self.assertFalse(is_loopback_host("example.org"))


if __name__ == "__main__":
    unittest.main()
