import socket

from .addresses import map_address_enum_to_socket_family
from ..constants import AddressTypeCodes


def generate_tcp_socket(address_type: AddressTypeCodes) -> socket.socket:
    return socket.socket(
        map_address_enum_to_socket_family(address_type), socket.SOCK_STREAM
    )


def generate_udp_socket(address_type: AddressTypeCodes) -> socket.socket:
    return socket.socket(
        map_address_enum_to_socket_family(address_type), socket.SOCK_DGRAM
    )
