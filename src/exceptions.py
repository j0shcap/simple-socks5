from typing import Union


class InvalidVersionError(Exception):
    """Exception raised when an invalid SOCKS version is encountered."""

    def __init__(self, version: int) -> None:
        super().__init__(f"Version not supported: {version}")


class InvalidRequestError(Exception):
    """Exception raised for invalid requests.

    Attributes:
        request (bytes | int): The invalid request that caused the error.
    """

    def __init__(self, request: Union[bytes, int]) -> None:
        super().__init__(f"Invalid request: {request}")


class AddressTypeNotSupportedError(InvalidRequestError):
    """Exception raised when a request uses an unknown address type (ATYP)."""


class InvalidDomainNameError(InvalidRequestError):
    """Exception raised when a requested domain name is not valid UTF-8."""


class HandshakeTimeoutError(TimeoutError):
    """Exception raised when a client doesn't finish the handshake before its deadline."""
