"""
Maps exceptions raised while serving a request to SOCKS5 reply codes (RFC 1928 §6).
"""
import errno
import socket

from .constants import ReplyCodes
from .exceptions import AddressTypeNotSupportedError, InvalidDomainNameError

# First match wins
_TYPE_RULES: tuple[tuple[type[BaseException], ReplyCodes], ...] = (
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
