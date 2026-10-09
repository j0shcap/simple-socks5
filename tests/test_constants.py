"""
Ensures that the constants are correct and that hex values are correctly mapped to integers.
"""

import os
import re
import unittest
from unittest.mock import patch

import pytest

from simple_socks5.constants import (
    RELAY_BUFFER_SIZE,
    AddressTypeCodes,
    CommandCodes,
    MethodCodes,
    ReplyCodes,
    allow_loopback,
    connect_timeout,
    credentials,
    handshake_timeout,
    healthcheck_port,
    log_file,
    max_connections,
)

TIMEOUT_GETTERS = (
    ("SOCKS5_HANDSHAKE_TIMEOUT", handshake_timeout),
    ("SOCKS5_CONNECT_TIMEOUT", connect_timeout),
)


class TestReplyCodes(unittest.TestCase):
    def test_succeeded(self):
        assert ReplyCodes.SUCCEEDED.value == 0

    def test_general_socks_server_failure(self):
        assert ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE.value == 1

    def test_connection_not_allowed_by_ruleset(self):
        assert ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET.value == 2

    def test_network_unreachable(self):
        assert ReplyCodes.NETWORK_UNREACHABLE.value == 3

    def test_host_unreachable(self):
        assert ReplyCodes.HOST_UNREACHABLE.value == 4

    def test_connection_refused(self):
        assert ReplyCodes.CONNECTION_REFUSED.value == 5

    def test_ttl_expired(self):
        assert ReplyCodes.TTL_EXPIRED.value == 6

    def test_command_not_supported(self):
        assert ReplyCodes.COMMAND_NOT_SUPPORTED.value == 7

    def test_address_type_not_supported(self):
        assert ReplyCodes.ADDRESS_TYPE_NOT_SUPPORTED.value == 8

    def test_unassigned(self):
        assert ReplyCodes.UNASSIGNED.value == 9


class TestMethodCodes(unittest.TestCase):
    def test_no_authentication_required(self):
        assert MethodCodes.NO_AUTHENTICATION_REQUIRED.value == 0

    def test_gssapi(self):
        assert MethodCodes.GSSAPI.value == 1

    def test_username_password(self):
        assert MethodCodes.USERNAME_PASSWORD.value == 2

    def test_no_acceptable_methods(self):
        assert MethodCodes.NO_ACCEPTABLE_METHODS.value == 255


class TestAddressTypeCodes(unittest.TestCase):
    def test_ipv4(self):
        assert AddressTypeCodes.IPv4.value == 1

    def test_domain_name(self):
        assert AddressTypeCodes.DOMAIN_NAME.value == 3

    def test_ipv6(self):
        assert AddressTypeCodes.IPv6.value == 4


class TestCommandCodes(unittest.TestCase):
    def test_connect(self):
        assert CommandCodes.CONNECT.value == 1

    def test_bind(self):
        assert CommandCodes.BIND.value == 2

    def test_udp_associate(self):
        assert CommandCodes.UDP_ASSOCIATE.value == 3


class TestRelayConstants(unittest.TestCase):
    def test_relay_buffer_size(self):
        assert RELAY_BUFFER_SIZE == 65536


class TestTimeoutEnv(unittest.TestCase):
    def setUp(self):
        environ = {k: v for k, v in os.environ.items() if k not in dict(TIMEOUT_GETTERS)}
        patcher = patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_timeouts_default_to_10(self):
        for name, getter in TIMEOUT_GETTERS:
            with self.subTest(name=name):
                assert getter() == 10.0

    def test_timeout_parses_float(self):
        for name, getter in TIMEOUT_GETTERS:
            with self.subTest(name=name), patch.dict(os.environ, {name: "2.5"}):
                assert getter() == 2.5

    def test_blank_timeout_uses_default(self):
        for (name, getter), raw in [(g, r) for g in TIMEOUT_GETTERS for r in ("", "  ")]:
            with self.subTest(name=name, raw=raw), patch.dict(os.environ, {name: raw}):
                assert getter() == 10.0

    def test_invalid_timeout_raises_naming_var(self):
        for (name, getter), raw in [(g, r) for g in TIMEOUT_GETTERS for r in ("abc", "0", "-1", "nan", "inf")]:
            with (
                self.subTest(name=name, raw=raw),
                patch.dict(os.environ, {name: raw}),
                pytest.raises(ValueError, match=name),
            ):
                getter()

    def test_timeout_read_at_call_time(self):
        for name, getter in TIMEOUT_GETTERS:
            with self.subTest(name=name):
                with patch.dict(os.environ, {name: "1"}):
                    assert getter() == 1.0
                with patch.dict(os.environ, {name: "3"}):
                    assert getter() == 3.0


def _without_socks5_env():
    environ = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
    return patch.dict(os.environ, environ, clear=True)


class TestMaxConnectionsEnv(unittest.TestCase):
    def setUp(self):
        patcher = _without_socks5_env()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_max_connections_default_is_200(self):
        assert max_connections() == 200

    def test_max_connections_reads_env(self):
        with patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": "5"}):
            assert max_connections() == 5

    def test_max_connections_blank_uses_default(self):
        for raw in ("", "  "):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": raw}):
                assert max_connections() == 200

    def test_max_connections_rejects_invalid(self):
        for raw in ("0", "-3", "abc", "1.5"):
            with (
                self.subTest(raw=raw),
                patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": raw}),
                pytest.raises(
                    ValueError, match=re.escape(f"SOCKS5_MAX_CONNECTIONS must be a positive integer, got '{raw}'")
                ),
            ):
                max_connections()


class TestCredentialsEnv(unittest.TestCase):
    def setUp(self):
        patcher = _without_socks5_env()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_credentials_defaults(self):
        assert credentials() == (b"myusername", b"mypassword")

    def test_credentials_utf8(self):
        with patch.dict(os.environ, {"SOCKS5_USERNAME": "üser", "SOCKS5_PASSWORD": "pässwörd"}):
            assert credentials() == ("üser".encode(), "pässwörd".encode())

    def test_credentials_read_at_call_time(self):
        with patch.dict(os.environ, {"SOCKS5_PASSWORD": "first"}):
            assert credentials()[1] == b"first"
        with patch.dict(os.environ, {"SOCKS5_PASSWORD": "second"}):
            assert credentials()[1] == b"second"

    def test_credentials_empty_env_stays_empty(self):
        with patch.dict(os.environ, {"SOCKS5_USERNAME": "", "SOCKS5_PASSWORD": ""}):
            assert credentials() == (b"", b"")


class TestAllowLoopbackEnv(unittest.TestCase):
    def setUp(self):
        patcher = _without_socks5_env()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_allow_loopback_default_false(self):
        assert not allow_loopback()

    def test_allow_loopback_true_case_insensitive(self):
        for raw in ("true", "TRUE", "True"):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": raw}):
                assert allow_loopback()

    def test_allow_loopback_other_values_false(self):
        for raw in ("1", "yes", "", "false"):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": raw}):
                assert not allow_loopback()


class TestLogFileEnv(unittest.TestCase):
    def setUp(self):
        patcher = _without_socks5_env()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_log_file_unset_is_none(self):
        assert log_file() is None

    def test_log_file_blank_is_none(self):
        for raw in ("", "  "):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_LOG_FILE": raw}):
                assert log_file() is None

    def test_log_file_reads_path(self):
        with patch.dict(os.environ, {"SOCKS5_LOG_FILE": "/var/log/socks5.log"}):
            assert log_file() == "/var/log/socks5.log"


class TestHealthcheckPortEnv(unittest.TestCase):
    def setUp(self):
        patcher = _without_socks5_env()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_healthcheck_port_default_is_1080(self):
        assert healthcheck_port() == 1080

    def test_healthcheck_port_reads_env(self):
        for raw, port in (("1", 1), ("8080", 8080), ("65535", 65535)):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_HEALTHCHECK_PORT": raw}):
                assert healthcheck_port() == port

    def test_healthcheck_port_rejects_invalid(self):
        for raw in ("0", "-1", "65536", "abc", "1.5"):
            with (
                self.subTest(raw=raw),
                patch.dict(os.environ, {"SOCKS5_HEALTHCHECK_PORT": raw}),
                pytest.raises(ValueError, match="SOCKS5_HEALTHCHECK_PORT"),
            ):
                healthcheck_port()


if __name__ == "__main__":
    unittest.main()
