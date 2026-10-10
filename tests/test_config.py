import logging
import unittest

from simple_socks5.config import LOGGING_LEVELS, LoggingLevelName, ProxyConfiguration
from simple_socks5.models import BaseAddress


class TestProxyConfiguration(unittest.TestCase):
    def test_level_maps_each_name(self) -> None:
        expected: dict[LoggingLevelName, int] = {
            "disabled": logging.NOTSET,
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        assert dict(LOGGING_LEVELS) == expected
        for name, level in expected.items():
            with self.subTest(name=name):
                assert ProxyConfiguration("localhost", 1080, name).level == level

    def test_address(self) -> None:
        assert ProxyConfiguration("0.0.0.0", 9999, "debug").address == BaseAddress("0.0.0.0", 9999)


if __name__ == "__main__":
    unittest.main()
