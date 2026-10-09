import logging
import unittest

from simple_socks5.config import ProxyConfiguration


class TestProxyConfiguration(unittest.TestCase):
    def test_is_initialized_returns_false_before_init(self):
        """Before initialize() is called, is_initialized() should return False."""
        # Create a fresh class to avoid pollution from other tests
        class FreshConfig(ProxyConfiguration):
            pass

        self.assertFalse(FreshConfig.is_initialized())

    def test_is_initialized_returns_true_after_init(self):
        """After initialize() is called, is_initialized() should return True."""

        class FreshConfig(ProxyConfiguration):
            pass

        FreshConfig.initialize("localhost", 1080, "debug")
        self.assertTrue(FreshConfig.is_initialized())

    def test_get_logging_level_returns_correct_level(self):

        class FreshConfig(ProxyConfiguration):
            pass

        FreshConfig.initialize("localhost", 1080, "info")
        self.assertEqual(FreshConfig.get_logging_level(), logging.INFO)

    def test_get_logging_level_disabled_returns_notset(self):

        class FreshConfig(ProxyConfiguration):
            pass

        FreshConfig.initialize("localhost", 1080, "disabled")
        self.assertEqual(FreshConfig.get_logging_level(), logging.NOTSET)

    def test_get_host_and_port(self):
        class FreshConfig(ProxyConfiguration):
            pass

        FreshConfig.initialize("0.0.0.0", 9999, "debug")
        self.assertEqual(FreshConfig.get_host(), "0.0.0.0")
        self.assertEqual(FreshConfig.get_port(), 9999)


if __name__ == "__main__":
    unittest.main()
