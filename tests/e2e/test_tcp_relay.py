import hashlib
import socket
import time

from tests.e2e import socks_client as sc
from tests.e2e.origins import deterministic_payload

SLOW_READER_SIZE = 20 * 1024 * 1024
SLOW_READER_RATE = 10 * 1024 * 1024  # bytes/s; far below loopback, well inside the origin's 5 s sendall
SLOW_READER_RCVBUF = 4096
SLOW_READER_CHUNK = 16384


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slow_tunnel(proxy_addr: tuple[str, int], dst_port: int) -> socket.socket:
    sock = socket.socket()
    try:
        # A small receive window set before connect makes the proxy's sends to us fill up quickly
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SLOW_READER_RCVBUF)
        sock.settimeout(sc.TIMEOUT)
        sock.connect(proxy_addr)
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", dst_port)
        assert sc.read_reply(sock).rep == sc.REP_SUCCEEDED
        return sock
    except BaseException:
        sock.close()
        raise


def _paced_recv_until_eof(sock: socket.socket, rate: int) -> bytes:
    chunks = []
    received = 0
    start = time.monotonic()
    while chunk := sock.recv(SLOW_READER_CHUNK):
        chunks.append(chunk)
        received += len(chunk)
        ahead = received / rate - (time.monotonic() - start)
        if ahead > 0:
            time.sleep(ahead)
    return b"".join(chunks)


def _http_body(response: bytes) -> bytes:
    head, _, body = response.partition(b"\r\n\r\n")
    assert head.split(b"\r\n")[0].split(b" ")[1] == b"200"
    return body


def test_slow_reader_receives_full_payload(proxy, http_origin):
    with _slow_tunnel(proxy.address, http_origin.port) as tunnel:
        tunnel.sendall(b"GET /bytes/%d HTTP/1.0\r\n\r\n" % SLOW_READER_SIZE)
        body = _http_body(_paced_recv_until_eof(tunnel, SLOW_READER_RATE))

    assert len(body) == SLOW_READER_SIZE
    assert _sha256(body) == _sha256(deterministic_payload(SLOW_READER_SIZE))


def test_large_single_send(proxy, http_origin):
    size = 1024 * 1024
    with sc.open_tunnel(proxy.address, "127.0.0.1", http_origin.port) as tunnel:
        tunnel.sendall(b"GET /bytes/%d HTTP/1.0\r\n\r\n" % size)
        body = _http_body(sc.recv_until_eof(tunnel))

    assert _sha256(body) == _sha256(deterministic_payload(size))
