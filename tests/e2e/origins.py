"""
Loopback peers for end-to-end tests, plus the one lifecycle helper shared with the proxy.

serve_in_thread(server)     context manager: serve_forever in a thread; shutdown, close and join on exit
deterministic_payload(n)    n seeded, non-periodic bytes (the HTTP origin serves exactly these)
OriginTCPServer[V6]         threading TCP server whose server_close() joins its handler threads
RecordingOriginTCPServer    OriginTCPServer with .results, a queue.Queue its handlers report into
EchoHandler                 echoes bytes until EOF
HalfCloseHandler            reads until EOF, then replies b"GOT <n> BYTES"
TrickleHandler              sends TRICKLE_CHUNK every TRICKLE_INTERVAL seconds until the peer goes away
ReplyThenReadHandler        sends b"BANNER", shuts down its sending side, reads until EOF, then reports
                            the sha256 hex digest of what it read (needs RecordingOriginTCPServer)
StreamUntilClosedHandler    sends bytes until a send fails, then reports time.monotonic() (needs
                            RecordingOriginTCPServer)
ResetMidTransferHandler     sends 1 MiB, resets the connection (RST), then reports time.monotonic()
                            (needs RecordingOriginTCPServer)
PayloadHTTPHandler          GET /bytes/<n> -> 200 with deterministic_payload(n); anything else -> 404
UDPEchoHandler              (for socketserver.UDPServer) echoes each datagram to its sender
Origin(host, port)          where a started origin listens; .address is the (host, port) tuple
"""

import hashlib
import queue
import random
import socket
import socketserver
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler

HANDLER_TIMEOUT = 5
TRICKLE_CHUNK = b"x" * 1024
TRICKLE_INTERVAL = 0.1  # seconds
STREAM_CHUNK_SIZE = 65536
RESET_AFTER_BYTES = 1024 * 1024


@contextmanager
def serve_in_thread(server: socketserver.BaseServer, poll_interval: float = 0.01):
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": poll_interval},
        name=f"serve:{type(server).__name__}",
        daemon=True,
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(HANDLER_TIMEOUT)


def deterministic_payload(n: int) -> bytes:
    return random.Random(n).randbytes(n)  # noqa: S311 - seeded for reproducible test data, not security


@dataclass(frozen=True)
class Origin:
    host: str
    port: int

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port


class OriginTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True


class OriginTCPServerV6(OriginTCPServer):
    address_family = socket.AF_INET6


class RecordingOriginTCPServer(OriginTCPServer):
    def __init__(self, *args, **kwargs):
        self.results: queue.Queue = queue.Queue()
        super().__init__(*args, **kwargs)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HANDLER_TIMEOUT)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class HalfCloseHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HANDLER_TIMEOUT)
        received = 0
        while data := self.request.recv(65536):
            received += len(data)
        self.request.sendall(b"GOT %d BYTES" % received)


class TrickleHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HANDLER_TIMEOUT)
        try:
            while True:
                self.request.sendall(TRICKLE_CHUNK)
                time.sleep(TRICKLE_INTERVAL)
        except OSError:
            pass  # The peer closed the connection


class ReplyThenReadHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HANDLER_TIMEOUT)
        self.request.sendall(b"BANNER")
        self.request.shutdown(socket.SHUT_WR)
        digest = hashlib.sha256()
        while data := self.request.recv(65536):
            digest.update(data)
        self.server.results.put(digest.hexdigest())


class StreamUntilClosedHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HANDLER_TIMEOUT)
        chunk = deterministic_payload(STREAM_CHUNK_SIZE)
        try:
            while True:
                self.request.sendall(chunk)
        except OSError:
            self.server.results.put(time.monotonic())


class ResetMidTransferHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HANDLER_TIMEOUT)
        self.request.sendall(deterministic_payload(RESET_AFTER_BYTES))
        # Linger 0 makes close() send RST; closing here, not in shutdown_request(), avoids a FIN first
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.request.close()
        self.server.results.put(time.monotonic())


class PayloadHTTPHandler(BaseHTTPRequestHandler):
    timeout = HANDLER_TIMEOUT

    def do_GET(self):
        prefix = "/bytes/"
        if not (self.path.startswith(prefix) and self.path[len(prefix) :].isdigit()):
            self.send_error(404)
            return
        body = deterministic_payload(int(self.path[len(prefix) :]))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class UDPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)
