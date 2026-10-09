"""
Tests the mapping from exceptions to SOCKS5 reply codes (RFC 1928 §6).
"""

import errno
import socket
import unittest

from simple_socks5.constants import ReplyCodes
from simple_socks5.errors import is_routine_disconnect, reply_code_for
from simple_socks5.exceptions import (
    AddressTypeNotSupportedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
    PolicyDenied,
)

CASES = (
    (ConnectionRefusedError(), ReplyCodes.CONNECTION_REFUSED),
    (OSError(errno.ECONNREFUSED, "refused"), ReplyCodes.CONNECTION_REFUSED),
    (OSError(errno.ENETUNREACH, "network unreachable"), ReplyCodes.NETWORK_UNREACHABLE),
    (OSError(errno.EHOSTUNREACH, "host unreachable"), ReplyCodes.HOST_UNREACHABLE),
    (TimeoutError(), ReplyCodes.HOST_UNREACHABLE),
    (socket.timeout("timed out"), ReplyCodes.HOST_UNREACHABLE),
    (socket.gaierror(socket.EAI_NONAME, "not known"), ReplyCodes.HOST_UNREACHABLE),
    # EAI_* codes aren't errno values; a numeric collision must not reach the errno table
    (socket.gaierror(errno.ENETUNREACH, "collides"), ReplyCodes.HOST_UNREACHABLE),
    (PolicyDenied("127.0.0.1", 80), ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET),
    (AddressTypeNotSupportedError(5), ReplyCodes.ADDRESS_TYPE_NOT_SUPPORTED),
    (InvalidDomainNameError(b"\xff"), ReplyCodes.HOST_UNREACHABLE),
    (InvalidRequestError(1), ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE),
    (InvalidVersionError(4), ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE),
    (OSError(errno.EPERM, "not permitted"), ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE),
    (OSError(), ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE),
    (Exception(), ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE),
)


class TestReplyCodeFor(unittest.TestCase):
    def test_reply_code_for(self):
        for exc, expected in CASES:
            with self.subTest(exc=repr(exc)):
                self.assertIs(reply_code_for(exc), expected)

    def test_typed_request_errors_are_invalid_request_errors(self):
        self.assertIsInstance(AddressTypeNotSupportedError(5), InvalidRequestError)
        self.assertIsInstance(InvalidDomainNameError(b"\xff"), InvalidRequestError)


class TestPolicyDenied(unittest.TestCase):
    def test_policy_denied_keeps_host_and_port(self):
        e = PolicyDenied("169.254.169.254", 80)
        self.assertEqual((e.host, e.port), ("169.254.169.254", 80))
        self.assertEqual(str(e), "destination 169.254.169.254:80 is blocked by the destination policy")

    def test_policy_denied_message_brackets_ipv6(self):
        self.assertIn("[::1]:443", str(PolicyDenied("::1", 443)))


ROUTINE_DISCONNECT_CASES = (
    (ConnectionError("Connection closed during recv"), True),
    (ConnectionResetError(), True),
    (BrokenPipeError(), True),
    (ConnectionAbortedError(), True),
    (OSError(errno.ENOTCONN, "not connected"), True),
    (ConnectionRefusedError(), False),
    (HandshakeTimeoutError("expired"), False),
    (TimeoutError(), False),
    (OSError(errno.EBADF, "bad file descriptor"), False),
    (OSError(), False),
    (InvalidVersionError(4), False),
    (PolicyDenied("127.0.0.1", 80), False),
    (RuntimeError("bug"), False),
)


class TestIsRoutineDisconnect(unittest.TestCase):
    def test_is_routine_disconnect(self):
        for exc, expected in ROUTINE_DISCONNECT_CASES:
            with self.subTest(exc=repr(exc)):
                self.assertIs(is_routine_disconnect(exc), expected)


if __name__ == "__main__":
    unittest.main()
