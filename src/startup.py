"""
Startup advisories describing the proxy's exposure (open proxy, default credentials).
"""
import ipaddress
import logging
import os
from typing import Mapping

from . import constants

# Mirrors the credential fallbacks in constants.py; tests guard against drift.
DEFAULT_USERNAME: str = "myusername"
DEFAULT_PASSWORD: str = "mypassword"

Advisory = tuple[int, str]  # (logging level, message)

OPEN_PROXY_BANNER: tuple[str, ...] = (
    "=" * 72,
    "OPEN PROXY: authentication is not required and the server listens on {host}.",
    "Anyone who can reach this port can use this proxy, and your IP address, for their traffic.",
    "To require authentication set SOCKS5_USERNAME, SOCKS5_PASSWORD and SOCKS5_AUTH_REQUIRED=true.",
    "If this is intentional (trusted network only), set SOCKS5_AUTH_REQUIRED=false to acknowledge it.",
    "See https://github.com/j0shcap/simple-socks5#security",
    "=" * 72,
)
AUTH_EXPLICITLY_DISABLED_MESSAGE = "Authentication disabled by SOCKS5_AUTH_REQUIRED=false."
DEFAULT_CREDENTIALS_MESSAGE = (
    "The built-in default credentials are in use and are publicly known. "
    "Set SOCKS5_USERNAME and SOCKS5_PASSWORD to private values."
)


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


def auth_explicitly_disabled(environ: Mapping[str, str] = os.environ) -> bool:
    """True only when SOCKS5_AUTH_REQUIRED is present and set to 'false', not merely defaulted."""
    return environ.get("SOCKS5_AUTH_REQUIRED", "").lower() == "false"


def uses_default_credentials(username: str, password: str) -> bool:
    return username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD


def startup_advisories(
    host: str, auth_required: bool, auth_explicitly_disabled: bool, default_credentials: bool
) -> list[Advisory]:
    advisories: list[Advisory] = []
    if not auth_required and not is_loopback_host(host):
        if auth_explicitly_disabled:
            advisories.append((logging.INFO, AUTH_EXPLICITLY_DISABLED_MESSAGE))
        else:
            advisories.extend((logging.WARNING, line.format(host=host)) for line in OPEN_PROXY_BANNER)
    if default_credentials:
        advisories.append((logging.WARNING, DEFAULT_CREDENTIALS_MESSAGE))
    return advisories


def collect_startup_advisories(host: str) -> list[Advisory]:
    """Gathers the live configuration (environment and credentials) and returns its advisories."""
    return startup_advisories(
        host,
        constants.auth_required(),
        auth_explicitly_disabled(),
        uses_default_credentials(constants.USERNAME, constants.PASSWORD),
    )
