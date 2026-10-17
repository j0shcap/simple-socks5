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
    RELAY_INITIAL_BUFFER_SIZE,
    UDP_BUFFER_SIZE,
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
from tests.env import strip_socks5_env

TIMEOUT_GETTERS = (
    ("SOCKS5_HANDSHAKE_TIMEOUT", handshake_timeout),
    ("SOCKS5_CONNECT_TIMEOUT", connect_timeout),
)


class TestReplyCodes(unittest.TestCase):
    def test_succeeded(self) -> None:
        assert ReplyCodes.SUCCEEDED.value == 0

    def test_general_socks_server_failure(self) -> None:
        assert ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE.value == 1

    def test_connection_not_allowed_by_ruleset(self) -> None:
        assert ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET.value == 2

    def test_network_unreachable(self) -> None:
        assert ReplyCodes.NETWORK_UNREACHABLE.value == 3

    def test_host_unreachable(self) -> None:
        assert ReplyCodes.HOST_UNREACHABLE.value == 4

    def test_connection_refused(self) -> None:
        assert ReplyCodes.CONNECTION_REFUSED.value == 5

    def test_ttl_expired(self) -> None:
        assert ReplyCodes.TTL_EXPIRED.value == 6

    def test_command_not_supported(self) -> None:
        assert ReplyCodes.COMMAND_NOT_SUPPORTED.value == 7

    def test_address_type_not_supported(self) -> None:
        assert ReplyCodes.ADDRESS_TYPE_NOT_SUPPORTED.value == 8

    def test_unassigned(self) -> None:
        assert ReplyCodes.UNASSIGNED.value == 9


class TestMethodCodes(unittest.TestCase):
    def test_no_authentication_required(self) -> None:
        assert MethodCodes.NO_AUTHENTICATION_REQUIRED.value == 0

    def test_gssapi(self) -> None:
        assert MethodCodes.GSSAPI.value == 1

    def test_username_password(self) -> None:
        assert MethodCodes.USERNAME_PASSWORD.value == 2

    def test_no_acceptable_methods(self) -> None:
        assert MethodCodes.NO_ACCEPTABLE_METHODS.value == 255


class TestAddressTypeCodes(unittest.TestCase):
    def test_ipv4(self) -> None:
        assert AddressTypeCodes.IPv4.value == 1

    def test_domain_name(self) -> None:
        assert AddressTypeCodes.DOMAIN_NAME.value == 3

    def test_ipv6(self) -> None:
        assert AddressTypeCodes.IPv6.value == 4


class TestCommandCodes(unittest.TestCase):
    def test_connect(self) -> None:
        assert CommandCodes.CONNECT.value == 1

    def test_bind(self) -> None:
        assert CommandCodes.BIND.value == 2

    def test_udp_associate(self) -> None:
        assert CommandCodes.UDP_ASSOCIATE.value == 3


class TestRelayConstants(unittest.TestCase):
    def test_relay_buffer_size(self) -> None:
        assert RELAY_BUFFER_SIZE == 262144

    def test_relay_initial_buffer_size(self) -> None:
        assert RELAY_INITIAL_BUFFER_SIZE == 65536

    def test_udp_buffer_size(self) -> None:
        assert UDP_BUFFER_SIZE == 65536


class TestTimeoutEnv(unittest.TestCase):
    def setUp(self) -> None:
        environ = {k: v for k, v in os.environ.items() if k not in dict(TIMEOUT_GETTERS)}
        patcher = patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_timeouts_default_to_10(self) -> None:
        for name, getter in TIMEOUT_GETTERS:
            with self.subTest(name=name):
                assert getter() == 10.0

    def test_timeout_parses_float(self) -> None:
        for name, getter in TIMEOUT_GETTERS:
            with self.subTest(name=name), patch.dict(os.environ, {name: "2.5"}):
                assert getter() == 2.5

    def test_blank_timeout_uses_default(self) -> None:
        for (name, getter), raw in [(g, r) for g in TIMEOUT_GETTERS for r in ("", "  ")]:
            with self.subTest(name=name, raw=raw), patch.dict(os.environ, {name: raw}):
                assert getter() == 10.0

    def test_invalid_timeout_raises_naming_var(self) -> None:
        for (name, getter), raw in [(g, r) for g in TIMEOUT_GETTERS for r in ("abc", "0", "-1", "nan", "inf")]:
            with (
                self.subTest(name=name, raw=raw),
                patch.dict(os.environ, {name: raw}),
                pytest.raises(ValueError, match=name),
            ):
                getter()

    def test_timeout_read_at_call_time(self) -> None:
        for name, getter in TIMEOUT_GETTERS:
            with self.subTest(name=name):
                with patch.dict(os.environ, {name: "1"}):
                    assert getter() == 1.0
                with patch.dict(os.environ, {name: "3"}):
                    assert getter() == 3.0


class TestMaxConnectionsEnv(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self)

    def test_max_connections_default_is_200(self) -> None:
        assert max_connections() == 200

    def test_max_connections_reads_env(self) -> None:
        with patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": "5"}):
            assert max_connections() == 5

    def test_max_connections_blank_uses_default(self) -> None:
        for raw in ("", "  "):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_MAX_CONNECTIONS": raw}):
                assert max_connections() == 200

    def test_max_connections_rejects_invalid(self) -> None:
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
    def setUp(self) -> None:
        strip_socks5_env(self)

    def test_credentials_defaults(self) -> None:
        assert credentials() == (b"myusername", b"mypassword")

    def test_credentials_utf8(self) -> None:
        with patch.dict(os.environ, {"SOCKS5_USERNAME": "üser", "SOCKS5_PASSWORD": "pässwörd"}):
            assert credentials() == ("üser".encode(), "pässwörd".encode())

    def test_credentials_read_at_call_time(self) -> None:
        with patch.dict(os.environ, {"SOCKS5_PASSWORD": "first"}):
            assert credentials()[1] == b"first"
        with patch.dict(os.environ, {"SOCKS5_PASSWORD": "second"}):
            assert credentials()[1] == b"second"

    def test_credentials_empty_env_stays_empty(self) -> None:
        with patch.dict(os.environ, {"SOCKS5_USERNAME": "", "SOCKS5_PASSWORD": ""}):
            assert credentials() == (b"", b"")


class TestAllowLoopbackEnv(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self)

    def test_allow_loopback_default_false(self) -> None:
        assert not allow_loopback()

    def test_allow_loopback_true_case_insensitive(self) -> None:
        for raw in ("true", "TRUE", "True"):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": raw}):
                assert allow_loopback()

    def test_allow_loopback_other_values_false(self) -> None:
        for raw in ("1", "yes", "", "false"):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_ALLOW_LOOPBACK": raw}):
                assert not allow_loopback()


class TestLogFileEnv(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self)

    def test_log_file_unset_is_none(self) -> None:
        assert log_file() is None

    def test_log_file_blank_is_none(self) -> None:
        for raw in ("", "  "):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_LOG_FILE": raw}):
                assert log_file() is None

    def test_log_file_reads_path(self) -> None:
        with patch.dict(os.environ, {"SOCKS5_LOG_FILE": "/var/log/socks5.log"}):
            assert log_file() == "/var/log/socks5.log"


class TestHealthcheckPortEnv(unittest.TestCase):
    def setUp(self) -> None:
        strip_socks5_env(self)

    def test_healthcheck_port_default_is_1080(self) -> None:
        assert healthcheck_port() == 1080

    def test_healthcheck_port_reads_env(self) -> None:
        for raw, port in (("1", 1), ("8080", 8080), ("65535", 65535)):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SOCKS5_HEALTHCHECK_PORT": raw}):
                assert healthcheck_port() == port

    def test_healthcheck_port_rejects_invalid(self) -> None:
        for raw in ("0", "-1", "65536", "abc", "1.5"):
            with (
                self.subTest(raw=raw),
                patch.dict(os.environ, {"SOCKS5_HEALTHCHECK_PORT": raw}),
                pytest.raises(ValueError, match="SOCKS5_HEALTHCHECK_PORT"),
            ):
                healthcheck_port()


if __name__ == "__main__":
    unittest.main()
