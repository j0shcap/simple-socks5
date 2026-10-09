import random
import unittest

from simple_socks5.constants import AddressTypeCodes
from simple_socks5.exceptions import InvalidRequestError, MalformedDatagramError
from simple_socks5.handlers.udp import UDPHandler
from simple_socks5.models import UDPDatagram
from tests.e2e import socks_client as sc

IPV4_HEADER = sc.build_udp_header(sc.ATYP_IPV4, "10.0.0.1", 53)
IPV6_HEADER = sc.build_udp_header(sc.ATYP_IPV6, "2001:db8::1", 53)
DOMAIN_HEADER = sc.build_udp_header(sc.ATYP_DOMAIN, "example.com", 53)


class TestParseUDPDatagram(unittest.TestCase):
    def test_parses_valid_ipv4_at_minimum_length(self):
        datagram = UDPHandler.parse_udp_datagram(sc.build_udp_header(sc.ATYP_IPV4, "10.0.0.1", 53, frag=7))
        self.assertEqual(datagram.frag, 7)
        self.assertEqual(datagram.address_type, AddressTypeCodes.IPv4)
        self.assertEqual((datagram.dst_addr, datagram.dst_port, datagram.data), ("10.0.0.1", 53, b""))

    def test_parses_valid_ipv6_at_minimum_length(self):
        datagram = UDPHandler.parse_udp_datagram(IPV6_HEADER)
        self.assertEqual(datagram.address_type, AddressTypeCodes.IPv6)
        self.assertEqual((datagram.dst_addr, datagram.dst_port, datagram.data), ("2001:db8::1", 53, b""))

    def test_parses_valid_domain_at_minimum_length(self):
        datagram = UDPHandler.parse_udp_datagram(DOMAIN_HEADER)
        self.assertEqual(datagram.address_type, AddressTypeCodes.DOMAIN_NAME)
        self.assertEqual((datagram.dst_addr, datagram.dst_port, datagram.data), ("example.com", 53, b""))

    def test_payload_after_header_is_preserved(self):
        payload = b"\x00\x00\x00\x01 looks like a header"
        self.assertEqual(UDPHandler.parse_udp_datagram(IPV4_HEADER + payload).data, payload)

    def test_rejects_malformed(self):
        cases = {
            **{f"{n} bytes": b"\x00" * n for n in range(4)},
            "RSV=1": b"\x00\x01" + IPV4_HEADER[2:],
            "RSV=0x0100": b"\x01\x00" + IPV4_HEADER[2:],
            **{f"IPv4 truncated to {n} bytes": IPV4_HEADER[:n] for n in range(4, len(IPV4_HEADER))},
            **{f"IPv6 truncated to {n} bytes": IPV6_HEADER[:n] for n in range(4, len(IPV6_HEADER))},
            "domain without length byte": DOMAIN_HEADER[:4],
            "domain name truncated": DOMAIN_HEADER[:8],
            "domain without port": DOMAIN_HEADER[:-2],
            "domain not UTF-8": sc.build_udp_header(sc.ATYP_DOMAIN, b"\x02\xff\xfe", 53),
            **{f"ATYP={atyp}": b"\x00\x00\x00" + bytes([atyp]) + IPV4_HEADER[4:] for atyp in (0, 2, 5, 9, 255)},
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(MalformedDatagramError):
                UDPHandler.parse_udp_datagram(data)

    def test_error_is_invalid_request_error_with_reason(self):
        with self.assertRaises(InvalidRequestError) as ctx:
            UDPHandler.parse_udp_datagram(b"\x00\x00")
        self.assertIsInstance(ctx.exception, MalformedDatagramError)
        self.assertIn("malformed UDP datagram (too short: 2 bytes)", str(ctx.exception))

    def test_fuzz_only_raises_malformed_datagram_error(self):
        rng = random.Random(0x5EC5)
        parsed = rejected = 0
        for i in range(20_000):
            if i % 3 == 0:
                data = rng.randbytes(rng.randint(0, 64))
            else:
                # Valid RSV and a biased ATYP, so most inputs reach the per-address-type branches
                atyp = rng.choice([1, 3, 4, 1, 3, 4, 0, 2, 9, 255, rng.randint(0, 255)])
                data = b"\x00\x00" + bytes([rng.randint(0, 255), atyp]) + rng.randbytes(rng.randint(0, 40))
            try:
                result = UDPHandler.parse_udp_datagram(data)
            except MalformedDatagramError:
                rejected += 1
            except Exception as e:
                self.fail(f"{type(e).__name__} for input {data!r}: {e}")
            else:
                self.assertIsInstance(result, UDPDatagram)
                parsed += 1
        self.assertGreater(parsed, 0)
        self.assertGreater(rejected, 0)


if __name__ == "__main__":
    unittest.main()
