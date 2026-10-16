"""
The origin servers the benchmarks reach, directly or through the proxy.

Run in their own process (python -m benchmarks.origins), so they don't compete with the load generators for a GIL.
Prints {"tcp": port, "udp": port} once listening, and exits when stdin closes.

Every TCP connection starts with a 9-byte command: an op byte and a big-endian 64-bit argument n.

    D n  sends n bytes, then closes (bulk download, or a small response)
    U n  reads n bytes, then sends one byte (bulk upload)
    W n  until EOF: reads n bytes, then answers with n bytes in two writes (16 bytes, then the rest WRITE_GAP later)
    H    holds the connection open until EOF

The UDP server echoes every datagram back to its sender.
"""

import contextlib
import json
import socket
import socketserver
import struct
import sys
import threading
import time
from typing import Final

COMMAND: Final = struct.Struct("!cQ")
CHUNK: Final = 1 << 20
HEADER: Final = 16  # the first of W's two writes
# Between W's two writes, so the proxy relays them as two segments, as it would for an application writing a header
# and then a body. That is where Nagle's algorithm on the proxy's sockets can hold the second one back.
WRITE_GAP: Final = 0.0005
SEND_CHUNK: Final = 1 << 16  # 1 MiB sends fail with ENOBUFS on macOS loopback at a few hundred connections
_ZEROS: Final = memoryview(bytes(CHUNK))


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray(n)
    view = memoryview(buf)
    pos = 0
    while pos < n:
        got = sock.recv_into(view[pos:])
        if not got:
            raise ConnectionError(f"connection closed after {pos} of {n} bytes")
        pos += got
    return bytes(buf)


def send_zeros(sock: socket.socket, n: int) -> None:
    while n > 0:
        chunk = min(n, SEND_CHUNK)
        sock.sendall(_ZEROS[:chunk])
        n -= chunk


def drain(sock: socket.socket, n: int, buf: bytearray) -> int:
    """Reads n bytes, or until EOF, into buf without keeping them. Returns the number read."""
    total = 0
    while total < n:
        got = sock.recv_into(buf, min(len(buf), n - total))
        if not got:
            break
        total += got
    return total


class _OriginHandler(socketserver.BaseRequestHandler):
    request: socket.socket

    def handle(self) -> None:
        sock = self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        op, n = COMMAND.unpack(recv_exact(sock, COMMAND.size))
        if op == b"D":
            send_zeros(sock, n)
        elif op == b"U":
            drain(sock, n, bytearray(CHUNK))
            sock.sendall(b"\x00")
        elif op == b"W":
            self._round_trips(sock, n)
        elif op == b"H":
            sock.recv(1)

    @staticmethod
    def _round_trips(sock: socket.socket, n: int) -> None:
        body = bytes(n - HEADER)
        with contextlib.suppress(ConnectionError):
            while True:
                recv_exact(sock, n)
                sock.sendall(bytes(HEADER))
                time.sleep(WRITE_GAP)
                sock.sendall(body)

    def finish(self) -> None:
        with contextlib.suppress(OSError):
            self.request.shutdown(socket.SHUT_RDWR)


class _TCPOrigin(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 4096
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        # Dual-stack, so a hostname that resolves to ::1 before 127.0.0.1 doesn't pay for a refused connect
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def handle_error(self, request: object, client_address: object) -> None:
        pass  # Clients the benchmarks abandon on purpose would print tracebacks


class _TCPOriginV4(_TCPOrigin):
    address_family = socket.AF_INET


def start_tcp_origin() -> socketserver.ThreadingTCPServer:
    try:
        server: socketserver.ThreadingTCPServer = _TCPOrigin(("::", 0), _OriginHandler)
    except OSError:  # no IPv6 in this kernel or container
        server = _TCPOriginV4(("0.0.0.0", 0), _OriginHandler)  # noqa: S104 - reached as 127.0.0.1 only
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def start_udp_echo() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def echo() -> None:
        while True:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)

    threading.Thread(target=echo, daemon=True).start()
    return sock


def main() -> None:
    tcp = start_tcp_origin()
    udp = start_udp_echo()
    print(json.dumps({"tcp": tcp.server_address[1], "udp": udp.getsockname()[1]}), flush=True)
    sys.stdin.read()


if __name__ == "__main__":
    main()
