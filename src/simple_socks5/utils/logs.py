"""
Standardized log messages.
"""

from ..models import BaseAddress, DetailedAddress, format_host_port


def format_connection_established(client: BaseAddress, dst: DetailedAddress) -> str:
    return f"CONNECTION | {format_host_port(client.ip, client.port)} -> {dst}"


def format_connection_closed(
    client: BaseAddress, dst: DetailedAddress, bytes_up: int, bytes_down: int, duration: float
) -> str:
    """bytes_up went from the client to the destination, bytes_down the other way; duration is in seconds."""
    return (
        f"CLOSED | {format_host_port(client.ip, client.port)} -> {dst} "
        f"| up={bytes_up} B down={bytes_down} B | {duration:.2f} s"
    )


def format_relay(protocol: str, src: BaseAddress, dst: BaseAddress, data_size: int) -> str:
    return f"RELAY | {protocol} | {src} -> {dst} | {data_size} bytes"
