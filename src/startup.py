"""
Startup advisories describing the proxy's exposure (open proxy, default credentials).
"""
import ipaddress


def is_loopback_host(host: str) -> bool:
    """True for 'localhost', 127.0.0.0/8 and ::1 (including IPv4-mapped loopback). Never resolves DNS."""
    if host.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return (mapped or address).is_loopback
