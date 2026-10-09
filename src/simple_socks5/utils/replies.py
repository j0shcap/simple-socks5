import struct

from ..constants import SOCKS_VERSION, AddressTypeCodes, MethodCodes, ReplyCodes
from .addresses import map_address_to_bytes


def generate_failed_reply(address_type: AddressTypeCodes, error_number: ReplyCodes) -> bytes:
    if address_type == AddressTypeCodes.DOMAIN_NAME:
        address_type = AddressTypeCodes.IPv4
    header = struct.pack("!BBBB", SOCKS_VERSION, error_number.value, 0, address_type.value)
    addr_bytes = b"\x00" * 16 if address_type == AddressTypeCodes.IPv6 else b"\x00" * 4
    port = struct.pack("!H", 0)
    return header + addr_bytes + port


def generate_succeeded_reply(address_type: AddressTypeCodes, ip: str, port: int) -> bytes:
    addr_bytes: bytes = map_address_to_bytes(address_type, ip)
    header = struct.pack("!BBBB", SOCKS_VERSION, ReplyCodes.SUCCEEDED.value, 0, address_type.value)
    port_bytes = struct.pack("!H", port)
    return header + addr_bytes + port_bytes


def generate_connection_method_response(method: MethodCodes) -> bytes:
    return struct.pack("!BB", SOCKS_VERSION, method.value)
