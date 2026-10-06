"""
Tests for the startup advisories that describe the proxy's exposure.
"""
import itertools
import logging
import re
import unittest
from unittest.mock import patch

from src.startup import (
    AUTH_EXPLICITLY_DISABLED_MESSAGE,
    DEFAULT_CREDENTIALS_MESSAGE,
    OPEN_PROXY_BANNER,
    is_loopback_host,
    startup_advisories,
)

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


# host -> exposed (non-loopback)
TABLE_HOSTS = {
    "localhost": False,
    "127.0.0.1": False,
    "127.1.2.3": False,
    "::1": False,
    "0.0.0.0": True,
    "::": True,
    "192.168.1.10": True,
    "example.org": True,
}


def banner_for(host):
    return [(logging.WARNING, line.format(host=host)) for line in OPEN_PROXY_BANNER]


class TestStartupAdvisories(unittest.TestCase):
    def test_decision_table(self):
        for host, auth, explicit, default_creds in itertools.product(
            TABLE_HOSTS, (True, False), (True, False), (True, False)
        ):
            with self.subTest(host=host, auth=auth, explicit=explicit, default_creds=default_creds):
                expected = []
                if not auth and TABLE_HOSTS[host]:
                    if explicit:
                        expected.append((logging.INFO, AUTH_EXPLICITLY_DISABLED_MESSAGE))
                    else:
                        expected.extend(banner_for(host))
                if default_creds:
                    expected.append((logging.WARNING, DEFAULT_CREDENTIALS_MESSAGE))

                self.assertEqual(startup_advisories(host, auth, explicit, default_creds), expected)

    def test_banner_content(self):
        text = "\n".join(message for _, message in banner_for("0.0.0.0"))
        self.assertIn("0.0.0.0", text)
        self.assertIn("anyone who can reach this port", text.lower())
        for env in ("SOCKS5_USERNAME", "SOCKS5_PASSWORD", "SOCKS5_AUTH_REQUIRED=true", "SOCKS5_AUTH_REQUIRED=false"):
            self.assertIn(env, text)
        self.assertIn("#security", text)
        self.assertIsNone(re.search(r"deprecat|future|will become", text, re.IGNORECASE))

    def test_info_message_text(self):
        self.assertEqual(AUTH_EXPLICITLY_DISABLED_MESSAGE, "Authentication disabled by SOCKS5_AUTH_REQUIRED=false.")

    def test_default_credentials_message_has_no_password(self):
        self.assertNotIn("mypassword", DEFAULT_CREDENTIALS_MESSAGE)

    def test_no_dns_lookup(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")):
            self.assertEqual(len(startup_advisories("example.org", False, False, False)), len(OPEN_PROXY_BANNER))


if __name__ == "__main__":
    unittest.main()
