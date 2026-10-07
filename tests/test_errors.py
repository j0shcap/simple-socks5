"""
Tests the mapping from exceptions to SOCKS5 reply codes (RFC 1928 §6).
"""
import errno
import socket
import unittest

from src.constants import ReplyCodes
from src.errors import is_routine_disconnect, reply_code_for
from src.exceptions import (
    AddressTypeNotSupportedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
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
    (RuntimeError("bug"), False),
)


class TestIsRoutineDisconnect(unittest.TestCase):
    def test_is_routine_disconnect(self):
        for exc, expected in ROUTINE_DISCONNECT_CASES:
            with self.subTest(exc=repr(exc)):
                self.assertIs(is_routine_disconnect(exc), expected)


if __name__ == "__main__":
    unittest.main()
