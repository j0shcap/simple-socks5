import socket
import struct

from ..constants import AddressTypeCodes
from ..exceptions import MalformedDatagramError
from ..logger import get_logger
from ..models import UDPDatagram
from ..utils import map_address_int_to_enum
from .base import BaseHandler

logger = get_logger(__name__)


def _require(data: bytes, length: int, reason: str) -> None:
    if len(data) < length:
        raise MalformedDatagramError(f"{reason}: {len(data)} bytes")


class UDPHandler(BaseHandler):
    connection: socket.socket

    def __init__(self, connection: socket.socket):
        """
        Initializes a new instance of the UDPRequestHandler class.

        Args:
            connection (socket.socket): The client socket.
        """
        self.connection = connection

    @staticmethod
    def parse_udp_datagram(data: bytes) -> UDPDatagram:
        """
        Procedure for UDP-based clients per RFC 1928.

        +----+------+------+----------+----------+----------+
        |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        +----+------+------+----------+----------+----------+
        | 2  |  1   |  1   | Variable |    2     | Variable |
        +----+------+------+----------+----------+----------+

        o  RSV - Reserved X'0000'
        o  FRAG - Current fragment number
        o  ATYP - address type of following addresses:
            o  IP V4 address: X'01'
            o  DOMAINNAME: X'03'
            o  IP V6 address: X'04'
        o  DST.ADDR - desired destination address
        o  DST.PORT - desired destination port
        o  DATA - user data

        Raises:
            MalformedDatagramError: The header is truncated, RSV isn't zero, ATYP is unknown or the
                domain name isn't valid UTF-8.
        """
        _require(data, 4, "too short")
        rsv, frag, atyp = struct.unpack("!HBB", data[:4])
        if rsv != 0:
            raise MalformedDatagramError(f"RSV must be 0, got {rsv:#06x}")

        if atyp == AddressTypeCodes.IPv4.value:
            _require(data, 10, "truncated IPv4 address or port")
            dst_addr = socket.inet_ntoa(data[4:8])
            dst_port = struct.unpack("!H", data[8:10])[0]
            user_data = data[10:]
        elif atyp == AddressTypeCodes.DOMAIN_NAME.value:
            _require(data, 5, "missing domain name length")
            domain_end = 5 + data[4]
            _require(data, domain_end + 2, "truncated domain name or port")
            try:
                dst_addr = data[5:domain_end].decode()
            except UnicodeDecodeError:
                raise MalformedDatagramError("domain name is not valid UTF-8") from None
            dst_port = struct.unpack("!H", data[domain_end : domain_end + 2])[0]
            user_data = data[domain_end + 2 :]
        elif atyp == AddressTypeCodes.IPv6.value:
            _require(data, 22, "truncated IPv6 address or port")
            dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            dst_port = struct.unpack("!H", data[20:22])[0]
            user_data = data[22:]
        else:
            raise MalformedDatagramError(f"unsupported address type {atyp}")

        return UDPDatagram(
            frag=frag,
            address_type=map_address_int_to_enum(atyp),
            dst_addr=dst_addr,
            dst_port=dst_port,
            data=user_data,
        )

    @staticmethod
    def build_udp_response_header(addr: str, port: int) -> bytes:
        """Build a SOCKS5 UDP response header for encapsulating remote responses.

        RFC 1928 Section 7 format:
        +----+------+------+----------+----------+
        |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |
        +----+------+------+----------+----------+
        | 2  |  1   |  1   | Variable |    2     |
        +----+------+------+----------+----------+
        """
        try:
            addr_bytes = socket.inet_aton(addr)
            atyp = AddressTypeCodes.IPv4.value
        except OSError:
            try:
                addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
                atyp = AddressTypeCodes.IPv6.value
            except OSError:
                raise ValueError(f"Invalid IP address: {addr}") from None
        return struct.pack("!HBB", 0, 0, atyp) + addr_bytes + struct.pack("!H", port)
