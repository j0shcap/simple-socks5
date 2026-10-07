import struct
import socket
import threading
import time
from typing import Optional

from ..constants import SOCKS_VERSION, AddressTypeCodes, DNS_LOOKUP_TIMEOUT
from ..exceptions import (
    AddressTypeNotSupportedError,
    HandshakeTimeoutError,
    InvalidDomainNameError,
    InvalidRequestError,
    InvalidVersionError,
)
from ..logger import get_logger
from ..models import DetailedAddress, Request
from ..utils import map_address_int_to_enum

logger = get_logger(__name__)


class BaseHandler:
    connection: socket.socket
    deadline: Optional[float] = None

    def __init__(self, connection: socket.socket, deadline: Optional[float] = None):
        """
        Initializes a new instance of the BaseRequestHandler class.

        Args:
            connection (socket.socket): The client socket.
            deadline (Optional[float]): time.monotonic() timestamp by which every read must finish, or None.
        """
        self.connection = connection
        self.deadline = deadline

    def _recv_exact(self, n: int) -> bytes:
        """
        Receive exactly n bytes from the connection, handling partial reads.

        With a deadline, each recv waits only for the time remaining, so a client drip-feeding bytes
        can't extend it. Raises HandshakeTimeoutError once it passes.
        """
        buf = bytearray(n)
        pos = 0
        while pos < n:
            chunk = self._recv_before_deadline(n - pos)
            if not chunk:
                raise ConnectionError("Connection closed during recv")
            buf[pos:pos + len(chunk)] = chunk
            pos += len(chunk)
        return bytes(buf)

    def _recv_before_deadline(self, n: int) -> bytes:
        if self.deadline is None:
            return self.connection.recv(n)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise HandshakeTimeoutError("Handshake deadline expired")
        self.connection.settimeout(remaining)
        try:
            return self.connection.recv(n)
        except TimeoutError as e:
            raise HandshakeTimeoutError("Handshake deadline expired") from e

    def handle_request(self) -> bool:
        """
        Implemented in TCP and UDP request handlers.
        """
        raise NotImplementedError

    def parse_request(self) -> Request:
        """
        Handles requests of the form:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        o  VER - protocol version: X'05'
        o  CMD
            o  CONNECT X'01'
            o  BIND X'02'
            o  UDP ASSOCIATE X'03'
        o  RSV - RESERVED
        o  ATYP - address type of following address
            o  IP V4 address: X'01'
            o  DOMAINNAME: X'03'
            o  IP V6 address: X'04'
        o  DST.ADDR - desired destination address
        o  DST.PORT - desired destination port in network octet order
        """
        try:
            header = self._recv_exact(4)

            version, cmd, rsv, address_type = struct.unpack("!BBBB", header)
            if version != SOCKS_VERSION:
                raise InvalidVersionError(version)
            if rsv != 0x00:
                raise InvalidRequestError(rsv)

            address: DetailedAddress = self._parse_address(address_type)

            return Request(version=version, command=cmd, address=address)

        except HandshakeTimeoutError:
            raise  # Expected for stalled clients; the server logs it without a traceback
        except socket.error as e:
            logger.exception(f"Socket error during request parsing: {e}")
            raise

    def _parse_address(self, address_type: int) -> DetailedAddress:
        # Every request byte, port included, is read before any DNS lookup, so a slow lookup never
        # counts against the handshake deadline.
        try:
            if address_type == AddressTypeCodes.IPv4.value:
                address: str = socket.inet_ntoa(self._recv_exact(4))
                port = self._recv_port()
                domain_name: str = address  # IP literals are never reverse-resolved
            elif address_type == AddressTypeCodes.DOMAIN_NAME.value:
                domain_length = self._recv_exact(1)[0]
                raw_domain_name = self._recv_exact(domain_length)
                port = self._recv_port()
                try:
                    domain_name = raw_domain_name.decode()
                except UnicodeDecodeError as e:
                    raise InvalidDomainNameError(raw_domain_name) from e
                address, address_type = self._resolve_hostname(domain_name)
            elif address_type == AddressTypeCodes.IPv6.value:
                address: str = socket.inet_ntop(
                    socket.AF_INET6, self._recv_exact(16)
                )
                port = self._recv_port()
                domain_name: str = address
            else:
                raise AddressTypeNotSupportedError(address_type)

            return DetailedAddress(
                name=str(domain_name),
                ip=address,
                port=port,
                address_type=map_address_int_to_enum(address_type),
            )

        except HandshakeTimeoutError:
            raise
        except socket.error as e:
            logger.exception(f"Socket error during address and port parsing: {e}")
            raise

    def _recv_port(self) -> int:
        return struct.unpack("!H", self._recv_exact(2))[0]

    def _dns_lookup_with_timeout(self, fn, label: str):
        """Run a DNS function on a daemon thread with timeout. Returns result or None."""
        result = [None]
        error = [None]

        def lookup():
            try:
                result[0] = fn()
            except Exception as e:
                error[0] = e

        t = threading.Thread(target=lookup, daemon=True)
        t.start()
        t.join(timeout=DNS_LOOKUP_TIMEOUT)

        if t.is_alive():
            logger.debug(f"DNS lookup timed out for {label}")
            return None
        if error[0] is not None:
            if not isinstance(error[0], OSError):
                logger.error(f"DNS lookup error for {label}", exc_info=error[0])
            return None
        return result[0]

    def _resolve_hostname(self, name: str) -> tuple[str, int]:
        """Resolve a hostname to (ip, address_type_value) using getaddrinfo for dual-stack support."""
        result = self._dns_lookup_with_timeout(
            lambda: socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM),
            name,
        )
        if not result:
            return name, AddressTypeCodes.IPv4.value

        family, _, _, _, sockaddr = result[0]
        ip = sockaddr[0]
        if family == socket.AF_INET6:
            return ip, AddressTypeCodes.IPv6.value
        return ip, AddressTypeCodes.IPv4.value
