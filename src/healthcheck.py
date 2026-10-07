"""
Container healthcheck: `python -m src.healthcheck` exits 0 when a SOCKS5 server answers on 127.0.0.1, else 1.

It sends a greeting offering only "no authentication" and accepts any SOCKS5 method reply, X'FF' included, so it
passes whether or not SOCKS5_AUTH_REQUIRED is set. The server logs such a probe at DEBUG only.
"""
import socket
import sys

from .constants import SOCKS_VERSION, MethodCodes, healthcheck_port

HOST = "127.0.0.1"
TIMEOUT = 3.0  # seconds, for the connect and for each send and receive
GREETING = bytes([SOCKS_VERSION, 1, MethodCodes.NO_AUTHENTICATION_REQUIRED.value])


def probe(host: str, port: int, timeout: float = TIMEOUT) -> bool:
    """
    True if the server at host:port answers the greeting with a 2-byte SOCKS5 method reply. Raises OSError if it
    can't be reached or doesn't answer in time.
    """
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(GREETING)
        reply = b""
        while len(reply) < 2:
            chunk = sock.recv(2 - len(reply))
            if not chunk:
                break
            reply += chunk
    return len(reply) == 2 and reply[0] == SOCKS_VERSION


def main() -> int:
    try:
        if probe(HOST, healthcheck_port()):
            return 0
        reason = "no SOCKS5 reply"
    except (OSError, ValueError) as e:
        reason = str(e)
    print(f"unhealthy: {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
