import hashlib
import socket
import threading
import time

from tests.e2e import socks_client as sc
from tests.e2e.origins import deterministic_payload

SLOW_READER_SIZE = 20 * 1024 * 1024
SLOW_READER_RATE = 10 * 1024 * 1024  # bytes/s; far below loopback, well inside the origin's 5 s sendall
SLOW_READER_RCVBUF = 4096
SLOW_READER_CHUNK = 16384
BULK_SIZE = 10 * 1024 * 1024
UPLOAD_SIZE = 1024 * 1024
DISCONNECT_AFTER_BYTES = 256 * 1024


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


def test_half_close_from_client(proxy, half_close_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", half_close_origin.port) as tunnel:
        tunnel.sendall(b"hello world")
        tunnel.shutdown(socket.SHUT_WR)
        assert sc.recv_until_eof(tunnel) == b"GOT 11 BYTES"


def test_half_close_from_origin(proxy, reply_then_read_origin):
    upload = deterministic_payload(UPLOAD_SIZE)
    with sc.open_tunnel(proxy.address, "127.0.0.1", reply_then_read_origin.port) as tunnel:
        assert sc.recv_until_eof(tunnel) == b"BANNER"
        tunnel.sendall(upload)
        tunnel.shutdown(socket.SHUT_WR)
        assert reply_then_read_origin.results.get(timeout=sc.TIMEOUT) == _sha256(upload)


def test_bidirectional_bulk(proxy, echo_origin):
    upload = deterministic_payload(BULK_SIZE)
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:

        def write():
            tunnel.sendall(upload)
            tunnel.shutdown(socket.SHUT_WR)

        writer = threading.Thread(target=write, name="bulk-writer")
        writer.start()
        try:
            echoed = sc.recv_until_eof(tunnel)
        finally:
            writer.join(sc.TIMEOUT)

    assert not writer.is_alive()
    assert len(echoed) == BULK_SIZE
    assert _sha256(echoed) == _sha256(upload)


def test_immediate_close_echo_returns_empty(proxy, echo_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        tunnel.shutdown(socket.SHUT_WR)
        assert sc.recv_until_eof(tunnel) == b""


def test_immediate_close_half_close_origin_reports_zero(proxy, half_close_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", half_close_origin.port) as tunnel:
        tunnel.shutdown(socket.SHUT_WR)
        assert sc.recv_until_eof(tunnel) == b"GOT 0 BYTES"


def test_tunnel_closed_immediately_leaks_nothing(proxy, echo_origin):
    # The autouse leak guard fails the test if the relay thread or a socket is left behind
    sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port).close()


def test_client_disconnect_closes_origin(proxy, streaming_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", streaming_origin.port) as tunnel:
        sc.recv_exact(tunnel, DISCONNECT_AFTER_BYTES)
        disconnected_at = time.monotonic()

    assert streaming_origin.results.get(timeout=sc.TIMEOUT) - disconnected_at < 2.0


def test_origin_reset_closes_client_promptly(proxy, reset_origin):
    with sc.open_tunnel(proxy.address, "127.0.0.1", reset_origin.port) as tunnel:
        try:
            sc.recv_until_eof(tunnel)
        except ConnectionResetError:
            pass
        closed_at = time.monotonic()

    assert closed_at - reset_origin.results.get(timeout=sc.TIMEOUT) < 1.0
