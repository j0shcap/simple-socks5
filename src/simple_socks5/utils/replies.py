import struct

from .addresses import map_address_to_bytes
from ..constants import SOCKS_VERSION, ReplyCodes, AddressTypeCodes, MethodCodes


def generate_general_socks_server_failure_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.GENERAL_SOCKS_SERVER_FAILURE)


def generate_connection_refused_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.CONNECTION_REFUSED)


def generate_network_unreachable_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.NETWORK_UNREACHABLE)


def generate_host_unreachable_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.HOST_UNREACHABLE)


def generate_address_type_not_supported_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.ADDRESS_TYPE_NOT_SUPPORTED)


def generate_connection_not_allowed_by_ruleset_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(
        address_type, ReplyCodes.CONNECTION_NOT_ALLOWED_BY_RULESET
    )


def generate_ttl_expired_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.TTL_EXPIRED)


def generate_command_not_supported_reply(
    address_type: AddressTypeCodes = AddressTypeCodes.IPv4,
) -> bytes:
    return generate_failed_reply(address_type, ReplyCodes.COMMAND_NOT_SUPPORTED)


def generate_unassigned_reply() -> bytes:
    return generate_failed_reply(AddressTypeCodes.IPv4, ReplyCodes.UNASSIGNED)


def generate_failed_reply(
    address_type: AddressTypeCodes, error_number: ReplyCodes
) -> bytes:
    if address_type == AddressTypeCodes.DOMAIN_NAME:
        address_type = AddressTypeCodes.IPv4
    header = struct.pack(
        "!BBBB", SOCKS_VERSION, error_number.value, 0, address_type.value
    )
    if address_type == AddressTypeCodes.IPv6:
        addr_bytes = b"\x00" * 16
    else:
        addr_bytes = b"\x00" * 4
    port = struct.pack("!H", 0)
    return header + addr_bytes + port


def generate_succeeded_reply(
    address_type: AddressTypeCodes, ip: str, port: int
) -> bytes:
    addr_bytes: bytes = map_address_to_bytes(address_type, ip)
    header = struct.pack(
        "!BBBB", SOCKS_VERSION, ReplyCodes.SUCCEEDED.value, 0, address_type.value
    )
    port_bytes = struct.pack("!H", port)
    return header + addr_bytes + port_bytes


def generate_connection_method_response(method: MethodCodes) -> bytes:
    return struct.pack("!BB", SOCKS_VERSION, method.value)
