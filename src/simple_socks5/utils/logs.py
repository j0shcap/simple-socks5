"""
Standardized log messages, and a rate limiter for warnings a client can trigger in bulk.
"""

import threading
import time
from collections.abc import Callable

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


class WarningRateLimiter:
    """
    Lets one warning through per interval and counts the events held back in between. Thread-safe.
    """

    def __init__(self, interval: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._interval = interval
        self._clock = clock
        self._lock = threading.Lock()
        self._count = 0
        self._next_warning = 0.0

    def hit(self) -> int | None:
        """
        Records one event. Returns the number of events since the last warning, this one included, when a warning
        is due now, and None otherwise.
        """
        with self._lock:
            self._count += 1
            now = self._clock()
            if now < self._next_warning:
                return None
            count = self._count
            self._count = 0
            self._next_warning = now + self._interval
            return count
