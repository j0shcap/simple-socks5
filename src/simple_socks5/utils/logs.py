"""
Standardized log messages.
"""

import string

from ..models import DetailedAddress, format_host_port

base_relay_template = string.Template("RELAY | $protocol | $src_ip:$src_port -> $dst_ip:$dst_port | $data_size bytes")


def format_connection_established(client_ip: str, client_port: int, dst: DetailedAddress) -> str:
    return f"CONNECTION | {format_host_port(client_ip, client_port)} -> {dst}"


def format_connection_closed(
    client_ip: str, client_port: int, dst: DetailedAddress, bytes_up: int, bytes_down: int, duration: float
) -> str:
    """bytes_up went from the client to the destination, bytes_down the other way; duration is in seconds."""
    return (
        f"CLOSED | {format_host_port(client_ip, client_port)} -> {dst} "
        f"| up={bytes_up} B down={bytes_down} B | {duration:.2f} s"
    )
