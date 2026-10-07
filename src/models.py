from dataclasses import dataclass
from collections import namedtuple

from .constants import AddressTypeCodes


@dataclass
class BaseAddress:
    ip: str
    port: int

    def __str__(self):
        return f"{self.ip}:{self.port}"


@dataclass
class DetailedAddress(BaseAddress):
    name: str  # Domain name
    address_type: AddressTypeCodes  # IPv4, IPv6, or domain name, see AddressTypeCodes

    def __str__(self):
        host = f"[{self.name}]" if ":" in self.name else self.name
        if self.name == self.ip:
            return f"{host}:{self.port}"
        return f"{host}:{self.port} ({self.ip})"


@dataclass
class Request:
    version: int  # SOCKS version
    command: int  # Command code
    address: DetailedAddress

    def __str__(self):
        return (
            f"Version: {self.version}, Command: {self.command}, Address: {self.address}"
        )


@dataclass
class UDPDatagram:
    """
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
    """

    frag: int
    address_type: AddressTypeCodes
    dst_addr: str
    dst_port: int
    data: bytes

    def __str__(self):
        return (
            f"Fragment: {self.frag}, Address Type: {self.address_type}, "
            f"Destination Address: {self.dst_addr}, Destination Port: {self.dst_port}, "
            f"Data: {self.data}"
        )


BindAddress = namedtuple("BindAddress", ["ip", "port"])
