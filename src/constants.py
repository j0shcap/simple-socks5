import os
from enum import Enum

SOCKS_VERSION: int = 5

USERNAME: str = os.environ.get("SOCKS5_USERNAME", "myusername")
PASSWORD: str = os.environ.get("SOCKS5_PASSWORD", "mypassword")


def auth_required() -> bool:
    return os.environ.get("SOCKS5_AUTH_REQUIRED", "false").lower() == "true"


# Buffer and timeout constants
RELAY_BUFFER_SIZE: int = 65536
TCP_SELECTOR_TIMEOUT: int = 3  # seconds
# Bounds a whole sendall() call, so a reader slower than RELAY_BUFFER_SIZE per this many seconds is dropped
RELAY_WRITE_TIMEOUT: float = 300.0  # seconds
AUTH_TIMEOUT: float = 45.0  # seconds
LOG_FILE_MAX_BYTES: int = 1048576  # 1 MB
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
