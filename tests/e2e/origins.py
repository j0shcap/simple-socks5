"""
Loopback peers for end-to-end tests, plus the one lifecycle helper shared with the proxy.

serve_in_thread(server)     context manager: serve_forever in a thread; shutdown, close and join on exit
deterministic_payload(n)    n seeded, non-periodic bytes (the HTTP origin serves exactly these)
OriginTCPServer[V6]         threading TCP server whose server_close() joins its handler threads
EchoHandler                 echoes bytes until EOF
HalfCloseHandler            reads until EOF, then replies b"GOT <n> BYTES"
PayloadHTTPHandler          GET /bytes/<n> -> 200 with deterministic_payload(n); anything else -> 404
UDPEchoHandler              (for socketserver.UDPServer) echoes each datagram to its sender
Origin(host, port)          where a started origin listens; .address is the (host, port) tuple
"""

import random
import socket
import socketserver
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler

HANDLER_TIMEOUT = 5


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
    return random.Random(n).randbytes(n)


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


class PayloadHTTPHandler(BaseHTTPRequestHandler):
    timeout = HANDLER_TIMEOUT

    def do_GET(self):
        prefix = "/bytes/"
        if not (self.path.startswith(prefix) and self.path[len(prefix):].isdigit()):
            self.send_error(404)
            return
        body = deterministic_payload(int(self.path[len(prefix):]))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class UDPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)
