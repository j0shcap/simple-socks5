"""
Classifies exceptions raised while serving a request: their SOCKS5 reply codes (RFC 1928 §6), and whether they
are a routine disconnect.
"""

import errno
import socket

from .constants import ReplyCodes
from .exceptions import AddressTypeNotSupportedError, InvalidDomainNameError, PolicyDenied

# First match wins
_TYPE_RULES: tuple[tuple[type[BaseException], ReplyCodes], ...] = (
    (PolicyDenied, ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET),
    (AddressTypeNotSupportedError, ReplyCodes.ADDRESS_TYPE_NOT_SUPPORTED),
    (InvalidDomainNameError, ReplyCodes.HOST_UNREACHABLE),
    # Before the errno rules: a gaierror's errno is an EAI_* code, which can collide with errno values
    (socket.gaierror, ReplyCodes.HOST_UNREACHABLE),
    (TimeoutError, ReplyCodes.HOST_UNREACHABLE),
    (ConnectionRefusedError, ReplyCodes.CONNECTION_REFUSED),
)

_ERRNO_RULES: dict[int, ReplyCodes] = {
    errno.ENETUNREACH: ReplyCodes.NETWORK_UNREACHABLE,
    errno.EHOSTUNREACH: ReplyCodes.HOST_UNREACHABLE,
}


def reply_code_for(exc: BaseException) -> ReplyCodes:
    for exc_type, code in _TYPE_RULES:
        if isinstance(exc, exc_type):
            return code
    if isinstance(exc, OSError) and exc.errno in _ERRNO_RULES:
        return _ERRNO_RULES[exc.errno]
    return ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE


def is_routine_disconnect(exc: BaseException) -> bool:
    """
    True when a peer hung up (EOF, reset, broken pipe) or the socket is already disconnected. That is normal at any
    point of a connection, so it's logged at DEBUG without a traceback. A refused connect is a destination failure.
    """
    if isinstance(exc, ConnectionRefusedError):
        return False
    return isinstance(exc, ConnectionError) or (isinstance(exc, OSError) and exc.errno == errno.ENOTCONN)
