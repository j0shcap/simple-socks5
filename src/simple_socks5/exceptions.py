from .models import format_host_port


class InvalidVersionError(Exception):
    """Exception raised when an invalid SOCKS version is encountered."""

    def __init__(self, version: int) -> None:
        super().__init__(f"Version not supported: {version}")


class InvalidRequestError(Exception):
    """Exception raised for invalid requests.

    Attributes:
        request (bytes | int): The invalid request that caused the error.
    """

    def __init__(self, request: bytes | int) -> None:
        super().__init__(f"Invalid request: {request}")


class AddressTypeNotSupportedError(InvalidRequestError):
    """Exception raised when a request uses an unknown address type (ATYP)."""


class InvalidDomainNameError(InvalidRequestError):
    """Exception raised when a requested domain name is empty or not valid UTF-8."""


class MalformedDatagramError(InvalidRequestError):
    """Exception raised for a truncated or invalid RFC 1928 §7 UDP request header.

    The UDP relay drops such datagrams, so this never leads to a SOCKS reply.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"malformed UDP datagram ({reason})")


class HandshakeTimeoutError(TimeoutError):
    """Exception raised when a client doesn't finish the handshake before its deadline."""


class PolicyDenied(Exception):
    """Exception raised when the destination policy blocks a destination address.

    Attributes:
        host (str): The blocked IP address.
        port (int): The requested port.
    """

    def __init__(self, host: str, port: int) -> None:
        super().__init__(f"destination {format_host_port(host, port)} is blocked by the destination policy")
        self.host = host
        self.port = port
