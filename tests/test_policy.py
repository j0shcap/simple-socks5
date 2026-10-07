"""
Tests the destination policy: which resolved addresses the proxy refuses to connect or send to.
"""
import os
import socket
import unittest
from unittest.mock import patch

from src.exceptions import PolicyDenied
from src.policy import check_destination, is_destination_allowed

DENIED = (
    "127.0.0.1",
    "127.5.5.5",
    "127.255.255.255",
    "0.0.0.0",
    "0.1.2.3",
    "169.254.169.254",
    "169.254.0.1",
    "::1",
    "::",
    "fe80::1",
    "fe80::1%eth0",
    "febf::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:0.0.0.0",
    "::127.0.0.1",
    "::169.254.169.254",
    "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe",
)

ALLOWED = (
    "10.0.0.1",
    "172.16.5.4",
    "192.168.1.1",
    "100.64.0.1",
    "8.8.8.8",
    "128.0.0.1",
    "169.255.0.1",
    "fc00::1",
    "fd12::1",
    "fec0::1",
    "2001:4860:4860::8888",
    "::ffff:10.0.0.1",
    "::ffff:8.8.8.8",
    "::8.8.8.8",
    "64:ff9b::808:808",
)

# Not IP literals: a hostname whose lookup failed, or a string inet_pton would reject
MALFORMED = ("", "localhost", "0x7f.1", "127.1", "256.0.0.1", "::ffff:999.0.0.1")


def _env(**values: str):
    environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
    environ.update(values)
    return patch.dict(os.environ, environ, clear=True)


class TestDefaultPolicy(unittest.TestCase):
    def setUp(self):
        patcher = _env()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_denied(self):
        for ip in DENIED:
            with self.subTest(ip=ip):
                self.assertFalse(is_destination_allowed(ip))
                with self.assertRaises(PolicyDenied):
                    check_destination(ip, 80)

    def test_allowed(self):
        for ip in ALLOWED:
            with self.subTest(ip=ip):
                self.assertTrue(is_destination_allowed(ip))
                check_destination(ip, 80)

    def test_malformed_not_allowed(self):
        for host in MALFORMED:
            with self.subTest(host=host):
                self.assertFalse(is_destination_allowed(host))
                with self.assertRaises(socket.gaierror) as ctx:
                    check_destination(host, 80)
                self.assertEqual(ctx.exception.errno, socket.EAI_NONAME)

    def test_check_destination_raises_policy_denied_with_host_and_port(self):
        with self.assertRaises(PolicyDenied) as ctx:
            check_destination("::1", 8080)
        self.assertEqual((ctx.exception.host, ctx.exception.port), ("::1", 8080))


class TestAllowLoopbackOptOut(unittest.TestCase):
    def setUp(self):
        patcher = _env(SOCKS5_ALLOW_LOOPBACK="true")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_opt_out_allows_every_denied_entry(self):
        for ip in DENIED:
            with self.subTest(ip=ip):
                self.assertTrue(is_destination_allowed(ip))
                check_destination(ip, 80)

    def test_opt_out_skips_literal_check(self):
        # connect() resolves an unresolved name itself, as before the policy existed
        self.assertIsNone(check_destination("example.invalid", 80))

    def test_opt_out_read_at_call_time(self):
        with patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": "false"}):
            self.assertFalse(is_destination_allowed("127.0.0.1"))
        self.assertTrue(is_destination_allowed("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
