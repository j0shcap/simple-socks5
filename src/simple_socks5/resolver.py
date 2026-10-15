"""
Resolves a destination hostname to every address it has, with a bounded lookup.

getaddrinfo() has no timeout of its own, so each lookup runs on a daemon thread that is waited on for
DNS_LOOKUP_TIMEOUT seconds. A lookup that takes longer is abandoned, but its thread runs until getaddrinfo() returns,
so at most MAX_PENDING_DNS_LOOKUPS lookups may be running at once; beyond that, a lookup fails straight away.
"""

import socket
import threading
from collections.abc import Callable
from typing import NamedTuple, TypeVar

from .constants import DNS_LOOKUP_TIMEOUT, DNS_SATURATED_WARNING_INTERVAL, MAX_PENDING_DNS_LOOKUPS
from .logger import get_logger
from .models import SocketAddress
from .utils import WarningRateLimiter

logger = get_logger(__name__)

T = TypeVar("T")

_lookup_slots = threading.BoundedSemaphore(MAX_PENDING_DNS_LOOKUPS)
_saturated_warnings = WarningRateLimiter(DNS_SATURATED_WARNING_INTERVAL)


class Candidate(NamedTuple):
    """One address a destination resolved to, as getaddrinfo() returned it."""

    family: socket.AddressFamily
    sockaddr: SocketAddress  # Kept whole, so an IPv6 scope id reaches connect()

    @property
    def ip(self) -> str:
        return self.sockaddr[0]


def resolve(host: str, port: int) -> list[Candidate]:
    """
    Returns every address host resolves to, without duplicates, in the order getaddrinfo() returned them.

    Raises:
        socket.gaierror: the lookup failed, timed out, couldn't start, or returned no usable address.
    """
    results = _bounded_lookup(lambda: socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM), host)
    candidates: dict[Candidate, None] = {}
    for family, _, _, _, sockaddr in results:
        # Only a Python built without IPv6 support returns (int, bytes) sockaddrs, which can't be connected to
        if isinstance(sockaddr[0], str):
            candidates[Candidate(family, sockaddr)] = None
    if not candidates:
        raise socket.gaierror(socket.EAI_NONAME, f"{host!r} resolved to no usable address")
    return list(candidates)


def _bounded_lookup(fn: Callable[[], T], label: str) -> T:
    """
    Runs fn on a daemon thread and returns its result, waiting at most DNS_LOOKUP_TIMEOUT seconds.

    Raises:
        socket.gaierror: fn timed out, too many lookups are pending, or fn raised something other than an OSError.
        OSError: whatever fn raised.
    """
    slots = _lookup_slots  # The thread releases this semaphore even if the module's is replaced meanwhile
    if not slots.acquire(blocking=False):
        refused = _saturated_warnings.hit()
        if refused is not None:
            logger.warning(
                "DNS lookups are not finishing: %s lookup(s) refused since the last warning, %s still pending",
                refused,
                MAX_PENDING_DNS_LOOKUPS,
            )
        raise socket.gaierror(socket.EAI_AGAIN, f"too many pending DNS lookups to look up {label!r}")

    results: list[T] = []
    errors: list[Exception] = []

    def lookup() -> None:
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - handed back to the caller, which logs it
            errors.append(e)
        finally:
            slots.release()

    thread = threading.Thread(target=lookup, name=f"dns-lookup {label}", daemon=True)
    try:
        thread.start()
    except Exception:
        slots.release()
        raise
    thread.join(timeout=DNS_LOOKUP_TIMEOUT)

    if thread.is_alive():
        logger.debug("DNS lookup timed out for %s", label)
        raise socket.gaierror(socket.EAI_AGAIN, f"DNS lookup for {label!r} timed out")
    if errors:
        error = errors[0]
        if isinstance(error, OSError):
            raise error
        if isinstance(error, UnicodeError):
            # The idna codec rejects an empty or over-long label: a bad name, not a fault
            raise socket.gaierror(socket.EAI_NONAME, f"invalid hostname {label!r}: {error}") from error
        logger.error("DNS lookup error for %s", label, exc_info=error)
        raise socket.gaierror(socket.EAI_FAIL, f"DNS lookup for {label!r} failed") from error
    return results[0]
