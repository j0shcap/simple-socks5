import unittest

from simple_socks5.exceptions import (
    AddressTypeNotSupportedError,
    InvalidDomainNameError,
    InvalidRequestError,
    MalformedDatagramError,
)


class TestInvalidRequestMessages(unittest.TestCase):
    def test_int_field(self) -> None:
        assert str(InvalidRequestError(1)) == "Invalid request: 1"
        assert str(AddressTypeNotSupportedError(9)) == "Invalid request: 9"

    def test_bytes_field_shown_as_literal(self) -> None:
        assert str(InvalidDomainNameError(b"\xff")) == "Invalid request: b'\\xff'"
        assert str(InvalidDomainNameError(b"")) == "Invalid request: b''"

    def test_malformed_datagram_reason(self) -> None:
        assert str(MalformedDatagramError("too short: 3 bytes")) == (
            "Invalid request: malformed UDP datagram (too short: 3 bytes)"
        )


if __name__ == "__main__":
    unittest.main()
