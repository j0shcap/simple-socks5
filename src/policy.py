"""
Decides which resolved destination addresses the proxy may connect or send to.

Only IP addresses are checked: a hostname can resolve differently by the time it's used, so callers check the
address they are about to connect to.
"""
import socket
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Optional, Union

from .constants import allow_loopback
from .exceptions import PolicyDenied

# Loopback, unspecified and link-local (incl. cloud metadata 169.254.169.254). SOCKS5_ALLOW_LOOPBACK lifts them all.
_DENIED_NETWORKS = (
    ip_network("127.0.0.0/8"),
    ip_network("0.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("::/128"),
    ip_network("fe80::/10"),
)
# IPv6 forms that carry an IPv4 address in their last 32 bits: IPv4-compatible and NAT64 well-known prefix
_V4_COMPATIBLE = ip_network("::/96")
_NAT64 = ip_network("64:ff9b::/96")


def _embedded_ipv4(addr: IPv6Address) -> Optional[IPv4Address]:
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr in _V4_COMPATIBLE or addr in _NAT64:
        return IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def _is_denied(addr: Union[IPv4Address, IPv6Address]) -> bool:
    candidates = [addr]
    if isinstance(addr, IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            candidates.append(embedded)
    return any(candidate in network for candidate in candidates for network in _DENIED_NETWORKS)


def is_destination_allowed(ip: str) -> bool:
    """
    Whether ip may be proxied to. Anything that isn't an IP address is not allowed, unless SOCKS5_ALLOW_LOOPBACK
    turns the policy off.
    """
    try:
        check_destination(ip, 0)
    except (socket.gaierror, PolicyDenied):
        return False
    return True


def check_destination(host: str, port: int) -> None:
    """
    Raises unless the proxy may connect or send to host, which must be an IP address.

    Raises:
        socket.gaierror: host isn't an IP address, so its lookup failed. Passing it on would let connect() or
            sendto() resolve it again, unchecked.
        PolicyDenied: host is in a denied range.
    """
    if allow_loopback():
        return
    try:
        addr = ip_address(host)
    except ValueError:
        raise socket.gaierror(socket.EAI_NONAME, f"could not resolve {host!r}") from None
    if _is_denied(addr):
        raise PolicyDenied(host, port)
