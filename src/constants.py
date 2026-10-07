import math
import os
from enum import Enum
from typing import Optional

SOCKS_VERSION: int = 5

DEFAULT_USERNAME: str = "myusername"
DEFAULT_PASSWORD: str = "mypassword"


def credentials() -> tuple[bytes, bytes]:
    """The configured RFC 1929 username and password as UTF-8 bytes, read at call time."""
    return _utf8_env("SOCKS5_USERNAME", DEFAULT_USERNAME), _utf8_env("SOCKS5_PASSWORD", DEFAULT_PASSWORD)


def _utf8_env(name: str, default: str) -> bytes:
    # surrogateescape turns a non-UTF-8 POSIX value back into its original bytes instead of raising
    return os.environ.get(name, default).encode("utf-8", "surrogateescape")


def auth_required() -> bool:
    return os.environ.get("SOCKS5_AUTH_REQUIRED", "false").lower() == "true"


DEFAULT_HANDSHAKE_TIMEOUT: float = 10.0  # seconds a client has to finish greeting, auth and request
DEFAULT_CONNECT_TIMEOUT: float = 10.0  # seconds to connect to the destination


def _positive_seconds_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive number of seconds, got {raw!r}")
    return value


def handshake_timeout() -> float:
    return _positive_seconds_env("SOCKS5_HANDSHAKE_TIMEOUT", DEFAULT_HANDSHAKE_TIMEOUT)


def connect_timeout() -> float:
    return _positive_seconds_env("SOCKS5_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT)


DEFAULT_MAX_CONNECTIONS: int = 200
CONNECTION_LIMIT_WARNING_INTERVAL: float = 10.0  # seconds between "connection limit reached" warnings


def _positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}")
    return value


def max_connections() -> int:
    return _positive_int_env("SOCKS5_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS)


def log_file() -> Optional[str]:
    """The path errors are also written to, or None to log to the console only."""
    return os.environ.get("SOCKS5_LOG_FILE", "").strip() or None


DEFAULT_HEALTHCHECK_PORT: int = 1080


def healthcheck_port() -> int:
    """The port the container healthcheck probes; the server itself never reads it."""
    port = _positive_int_env("SOCKS5_HEALTHCHECK_PORT", DEFAULT_HEALTHCHECK_PORT)
    if port > 65535:
        raise ValueError(f"SOCKS5_HEALTHCHECK_PORT must be a port number up to 65535, got {port}")
    return port


# Buffer and timeout constants
RELAY_BUFFER_SIZE: int = 65536
TCP_SELECTOR_TIMEOUT: int = 3  # seconds
# Bounds a whole sendall() call, so a reader slower than RELAY_BUFFER_SIZE per this many seconds is dropped
RELAY_WRITE_TIMEOUT: float = 300.0  # seconds
LOG_FILE_MAX_BYTES: int = 1048576  # 1 MB
LOG_FILE_BACKUP_COUNT: int = 5
DNS_LOOKUP_TIMEOUT: float = 2.0  # seconds
UDP_RECV_TIMEOUT: int = 120  # seconds
UDP_FORWARD_TIMEOUT: int = 10  # seconds
SHUTDOWN_GRACE_PERIOD: float = 5.0  # seconds in-flight connections get after SIGTERM/SIGINT
SHUTDOWN_FORCE_CLOSE_TIMEOUT: float = 0.5  # seconds before the grace deadline to force-close stragglers

# See https://www.ietf.org/rfc/rfc1928.txt for more information about the below codes


class MethodCodes(Enum):
    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE_METHODS = 0xFF


class ReplyCodes(Enum):
    SUCCEEDED = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08
    UNASSIGNED = 0x09


class AddressTypeCodes(Enum):
    IPv4 = 0x01
    DOMAIN_NAME = 0x03
    IPv6 = 0x04


class CommandCodes(Enum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03
