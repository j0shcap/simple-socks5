"""
Connects to a CONNECT destination, trying each address a hostname resolves to in turn.

Addresses are tried one after another in the order getaddrinfo() returns them (RFC 6724), like
socket.create_connection(), with no reordering or racing (RFC 8305 Happy Eyeballs). Each is checked against the
destination policy first, and at most MAX_CONNECT_ATTEMPTS are tried, so a hostname gets a reply within
MAX_CONNECT_ATTEMPTS * SOCKS5_CONNECT_TIMEOUT seconds however many dead addresses it has.

getaddrinfo() has no timeout of its own, so each lookup runs on a daemon thread that is waited on for
DNS_LOOKUP_TIMEOUT seconds. A lookup that takes longer is abandoned, but its thread runs until getaddrinfo() returns,
so at most MAX_PENDING_DNS_LOOKUPS lookups may be running at once; beyond that, a lookup fails straight away.
"""

import dataclasses
import socket
import threading
from collections.abc import Callable
from typing import NamedTuple, TypeVar

from .constants import (
    DNS_LOOKUP_TIMEOUT,
    DNS_SATURATED_WARNING_INTERVAL,
    MAX_CONNECT_ATTEMPTS,
    MAX_PENDING_DNS_LOOKUPS,
    AddressTypeCodes,
    connect_timeout,
)
from .exceptions import PolicyDeniedError
from .logger import get_logger
from .models import DetailedAddress, SocketAddress
from .policy import check_destination
from .utils import WarningRateLimiter, map_address_enum_to_socket_family, map_address_family_to_enum

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


def connect_any(dst: DetailedAddress) -> tuple[socket.socket, DetailedAddress]:
    """
    Connects to dst. Returns the connected socket and dst with ip and address_type set to the address it reached;
    name stays as the client sent it.

    Addresses the policy denies, and addresses whose socket can't be created (no IPv6 in the kernel), are skipped
    and don't count towards MAX_CONNECT_ATTEMPTS.

    Raises:
        socket.gaierror: dst is a hostname that didn't resolve.
        PolicyDeniedError: the policy denied every address.
        OSError: the error of the last address tried.
    """
    timeout = connect_timeout()
    attempts = 0
    last_error: OSError | None = None
    try:
        for candidate in _candidates(dst):
            if attempts == MAX_CONNECT_ATTEMPTS:
                break
            try:
                check_destination(candidate.ip, dst.port)
            except PolicyDeniedError:
                logger.debug("Skipped %s for %s: denied by the destination policy", candidate.ip, dst)
                continue
            try:
                sock = socket.socket(candidate.family, socket.SOCK_STREAM)
            except OSError as e:
                logger.debug("Skipped %s for %s: %s", candidate.ip, dst, e)
                last_error = e
                continue
            attempts += 1
            try:
                _connect(sock, candidate.sockaddr, timeout)
            except OSError as e:
                logger.debug("Connect to %s via %s failed: %s", dst, candidate.ip, e)
                last_error = e
                continue
            family = map_address_family_to_enum(candidate.family)
            return sock, dataclasses.replace(dst, ip=candidate.ip, address_type=family)
        if last_error is None:
            raise PolicyDeniedError(dst.name, dst.port)
        raise last_error
    finally:
        # last_error's traceback references this frame and, through it, the handler's: the cycle would keep the
        # client's socket open until the next garbage collection
        del last_error


def _candidates(dst: DetailedAddress) -> list[Candidate]:
    if dst.address_type == AddressTypeCodes.DOMAIN_NAME:
        return resolve(dst.name, dst.port)
    family = socket.AddressFamily(map_address_enum_to_socket_family(dst.address_type))
    return [Candidate(family, (dst.ip, dst.port))]


def _connect(sock: socket.socket, sockaddr: SocketAddress, timeout: float) -> None:
    """Connects sock to sockaddr within timeout seconds, closing it if that fails."""
    try:
        # Replaced by the relay's write timeout in TCPRelay._prepare_sockets()
        sock.settimeout(timeout)
        sock.connect(sockaddr)
    except BaseException:
        sock.close()
        raise


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
    if not errors:
        return results[0]
    error = errors.pop()
    try:
        if isinstance(error, OSError):
            raise error
        if isinstance(error, UnicodeError):
            # The idna codec rejects an empty or over-long label: a bad name, not a fault
            raise socket.gaierror(socket.EAI_NONAME, f"invalid hostname {label!r}: {error}") from error
        logger.error("DNS lookup error for %s", label, exc_info=error)
        raise socket.gaierror(socket.EAI_FAIL, f"DNS lookup for {label!r} failed") from error
    finally:
        del error  # As in connect_any(): the raised traceback references this frame
