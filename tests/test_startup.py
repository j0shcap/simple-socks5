"""
Tests for the startup advisories that describe the proxy's exposure.
"""

import itertools
import logging
import os
import re
import unittest
from unittest.mock import patch

from simple_socks5.startup import (
    AUTH_EXPLICITLY_DISABLED_MESSAGE,
    DEFAULT_CREDENTIALS_MESSAGE,
    OPEN_PROXY_BANNER,
    auth_explicitly_disabled,
    collect_startup_advisories,
    is_loopback_host,
    startup_advisories,
    uses_default_credentials,
    validate_environment,
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
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")),
            patch("socket.gethostbyname", side_effect=AssertionError("DNS lookup")),
            patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS lookup")),
        ):
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

    def test_empty_host_named_as_all_interfaces(self):
        text = "\n".join(message for _, message in startup_advisories("", False, False, False))
        self.assertIn("listens on all interfaces.", text)

    def test_info_message_text(self):
        self.assertEqual(AUTH_EXPLICITLY_DISABLED_MESSAGE, "Authentication disabled by SOCKS5_AUTH_REQUIRED=false.")

    def test_default_credentials_message_has_no_password(self):
        self.assertNotIn("mypassword", DEFAULT_CREDENTIALS_MESSAGE)

    def test_no_dns_lookup(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")):
            self.assertEqual(len(startup_advisories("example.org", False, False, False)), len(OPEN_PROXY_BANNER))


class TestAuthExplicitlyDisabled(unittest.TestCase):
    def test_not_explicitly_disabled(self):
        for environ in (
            {},
            {"SOCKS5_AUTH_REQUIRED": ""},
            {"SOCKS5_AUTH_REQUIRED": "true"},
            {"SOCKS5_AUTH_REQUIRED": "0"},
        ):
            with self.subTest(environ=environ):
                self.assertFalse(auth_explicitly_disabled(environ))

    def test_explicitly_disabled(self):
        for value in ("false", "FALSE", "False"):
            with self.subTest(value=value):
                self.assertTrue(auth_explicitly_disabled({"SOCKS5_AUTH_REQUIRED": value}))

    def test_reads_process_environment_by_default(self):
        with patch.dict(os.environ, {"SOCKS5_AUTH_REQUIRED": "false"}):
            self.assertTrue(auth_explicitly_disabled())


class TestUsesDefaultCredentials(unittest.TestCase):
    def test_both_default(self):
        self.assertTrue(uses_default_credentials(b"myusername", b"mypassword"))

    def test_any_custom(self):
        for username, password in ((b"admin", b"mypassword"), (b"myusername", b"s3cret"), (b"admin", b"s3cret")):
            with self.subTest(username=username, password=password):
                self.assertFalse(uses_default_credentials(username, password))


class TestCollectStartupAdvisories(unittest.TestCase):
    def collect(self, host, environ, username="myusername", password="mypassword"):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        credentials = {"SOCKS5_USERNAME": username, "SOCKS5_PASSWORD": password}
        with patch.dict(os.environ, {**clean, **credentials, **environ}, clear=True):
            return collect_startup_advisories(host)

    def test_no_env_on_all_interfaces_warns_banner_and_default_credentials(self):
        self.assertEqual(
            self.collect("0.0.0.0", {}),
            banner_for("0.0.0.0") + [(logging.WARNING, DEFAULT_CREDENTIALS_MESSAGE)],
        )

    def test_loopback_logs_no_banner(self):
        self.assertEqual(self.collect("127.0.0.1", {}), [(logging.WARNING, DEFAULT_CREDENTIALS_MESSAGE)])

    def test_auth_required_with_custom_credentials_logs_nothing(self):
        self.assertEqual(self.collect("0.0.0.0", {"SOCKS5_AUTH_REQUIRED": "true"}, "admin", "s3cret"), [])

    def test_explicitly_disabled_logs_single_info(self):
        self.assertEqual(
            self.collect("0.0.0.0", {"SOCKS5_AUTH_REQUIRED": "false"}, "admin", "s3cret"),
            [(logging.INFO, AUTH_EXPLICITLY_DISABLED_MESSAGE)],
        )


class TestValidateEnvironment(unittest.TestCase):
    def test_validate_environment_ok_with_defaults(self):
        environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
        with patch.dict(os.environ, environ, clear=True):
            validate_environment()

    def test_validate_environment_rejects_invalid_timeout(self):
        for name in ("SOCKS5_HANDSHAKE_TIMEOUT", "SOCKS5_CONNECT_TIMEOUT"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "abc"}):
                with self.assertRaisesRegex(ValueError, name):
                    validate_environment()

    def test_rejects_invalid_max_connections(self):
        for raw in ("0", "abc"):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": raw}):
                with self.assertRaisesRegex(ValueError, "SOCKS5_MAX_CONNECTIONS must be a positive integer"):
                    validate_environment()


if __name__ == "__main__":
    unittest.main()
