import socket

from ..constants import AddressTypeCodes


def map_address_to_bytes(address_type: AddressTypeCodes, ip: str) -> bytes:
    if address_type == AddressTypeCodes.IPv4:
        return socket.inet_aton(ip)
    elif address_type == AddressTypeCodes.IPv6:
        return socket.inet_pton(socket.AF_INET6, ip)
    else:
        raise ValueError("Address type not suitable for byte translation")


def map_address_int_to_enum(address_type: int) -> AddressTypeCodes:
    if address_type == AddressTypeCodes.IPv4.value:
        return AddressTypeCodes.IPv4
    elif address_type == AddressTypeCodes.DOMAIN_NAME.value:
        return AddressTypeCodes.DOMAIN_NAME
    elif address_type == AddressTypeCodes.IPv6.value:
        return AddressTypeCodes.IPv6
    else:
        raise ValueError("Unknown address type")


def map_address_family_to_enum(address_family: int) -> AddressTypeCodes:
    if address_family == socket.AF_INET:
        return AddressTypeCodes.IPv4
    elif address_family == socket.AF_INET6:
        return AddressTypeCodes.IPv6
    else:
        raise ValueError("Unknown address family")


def map_address_enum_to_socket_family(address_type: AddressTypeCodes) -> int:
    if address_type == AddressTypeCodes.IPv4:
        return socket.AF_INET
    elif address_type == AddressTypeCodes.IPv6:
        return socket.AF_INET6
    else:
        raise ValueError("Unknown address type")


def map_address_int_to_socket_family(address_type: int) -> int:
    if address_type == AddressTypeCodes.IPv4.value:
        return socket.AF_INET
    elif address_type == AddressTypeCodes.IPv6.value:
        return socket.AF_INET6
    else:
        raise ValueError("Unknown address type")
