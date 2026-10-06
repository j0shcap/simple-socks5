"""
Raw SOCKS5 client for end-to-end tests (RFC 1928 + RFC 1929), stdlib only.

Deliberately independent of ``src``: the constants are re-declared from the RFCs so a
wrong constant in the code under test cannot hide behind a shared import.

Public API (stable; later slices build on it):

Constants
    CMD_CONNECT, CMD_BIND, CMD_UDP_ASSOCIATE
    ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6
    METHOD_NO_AUTH, METHOD_GSSAPI, METHOD_USERPASS, METHOD_NO_ACCEPTABLE
    REP_* (RFC 1928 section 6), AUTH_SUCCESS, AUTH_FAILURE

Types
    Reply(ver, rep, rsv, atyp, bnd_addr, bnd_port)
    UDPHeader(rsv, frag, atyp, addr, port, data)
    Socks5Error(message, reply=None)          raised only by open_tunnel

Raw builders (``bytes`` arguments are emitted verbatim, so malformed input is possible)
    encode_address(atyp, addr) -> bytes       str: packed IP / length-prefixed domain
    build_greeting(methods, *, ver=5) -> bytes
    build_userpass(username, password, *, ver=1) -> bytes
    build_request(cmd, atyp, addr, port, *, ver=5, rsv=0) -> bytes
    build_udp_header(atyp, addr, port, *, frag=0) -> bytes
    parse_udp_header(datagram) -> UDPHeader

Socket I/O
    recv_exact(sock, n) -> bytes              EOFError on a short read
    recv_until_eof(sock) -> bytes
    assert_closed(sock)                       next recv is EOF (or a reset)
    greet(sock, methods) -> int               selected METHOD
    authenticate(sock, username, password, *, ver=1) -> int   STATUS
    send_request(sock, cmd, atyp, addr, port, **kwargs)
    read_reply(sock) -> Reply                 reads exactly one reply, never over-reads

Convenience
    open_tunnel(proxy_addr, dst_addr, dst_port, *, atyp=None, credentials=None) -> socket
        Greets (USERPASS if credentials else NO_AUTH), authenticates, sends CONNECT and
        returns the tunnelled socket. ATYP is inferred from dst_addr when None. Raises
        Socks5Error on any refusal and closes the socket on every failure.

Every socket created here has a TIMEOUT-second timeout, so a hang fails instead of stalling.
"""

import socket
import struct
from typing import Iterable, NamedTuple

TIMEOUT = 5.0
SOCKS_VERSION = 5

# RFC 1928 section 4
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# RFC 1928 section 3
METHOD_NO_AUTH = 0x00
METHOD_GSSAPI = 0x01
METHOD_USERPASS = 0x02
METHOD_NO_ACCEPTABLE = 0xFF

# RFC 1928 section 6
REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

# RFC 1929 section 2
AUTH_VERSION = 0x01
AUTH_SUCCESS = 0x00
AUTH_FAILURE = 0x01

Address = str | bytes


class Reply(NamedTuple):
    ver: int
    rep: int
    rsv: int
    atyp: int
    bnd_addr: str
    bnd_port: int


class UDPHeader(NamedTuple):
    rsv: int
    frag: int
    atyp: int
    addr: str
    port: int
    data: bytes


class Socks5Error(Exception):
    def __init__(self, message: str, reply: Reply | None = None):
        super().__init__(message)
        self.reply = reply


def encode_address(atyp: int, addr: Address) -> bytes:
    if isinstance(addr, bytes):
        return addr
    if atyp == ATYP_IPV4:
        return socket.inet_pton(socket.AF_INET, addr)
    if atyp == ATYP_IPV6:
        return socket.inet_pton(socket.AF_INET6, addr)
    encoded = addr.encode()
    return bytes([len(encoded)]) + encoded


def build_greeting(methods: Iterable[int], *, ver: int = SOCKS_VERSION) -> bytes:
    methods = bytes(methods)
    return bytes([ver, len(methods)]) + methods


def build_userpass(username: Address, password: Address, *, ver: int = AUTH_VERSION) -> bytes:
    username = username.encode() if isinstance(username, str) else username
    password = password.encode() if isinstance(password, str) else password
    return bytes([ver, len(username)]) + username + bytes([len(password)]) + password


def build_request(
    cmd: int, atyp: int, addr: Address, port: int, *, ver: int = SOCKS_VERSION, rsv: int = 0
) -> bytes:
    return bytes([ver, cmd, rsv, atyp]) + encode_address(atyp, addr) + struct.pack("!H", port)


def build_udp_header(atyp: int, addr: Address, port: int, *, frag: int = 0) -> bytes:
    return b"\x00\x00" + bytes([frag, atyp]) + encode_address(atyp, addr) + struct.pack("!H", port)


def _decode_address(atyp: int, raw: bytes) -> str:
    if atyp == ATYP_IPV4:
        return socket.inet_ntop(socket.AF_INET, raw)
    if atyp == ATYP_IPV6:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return raw.decode()


def parse_udp_header(datagram: bytes) -> UDPHeader:
    rsv, frag, atyp = struct.unpack("!HBB", datagram[:4])
    if atyp == ATYP_DOMAIN:
        start, end = 5, 5 + datagram[4]
    else:
        start, end = 4, 4 + (4 if atyp == ATYP_IPV4 else 16)
    (port,) = struct.unpack("!H", datagram[end:end + 2])
    return UDPHeader(rsv, frag, atyp, _decode_address(atyp, datagram[start:end]), port, datagram[end + 2:])


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError(f"expected {n} bytes, got {len(data)} before EOF")
        data += chunk
    return data


def recv_until_eof(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def assert_closed(sock: socket.socket) -> None:
    try:
        data = sock.recv(1)
    except ConnectionResetError:
        return
    assert data == b"", f"expected EOF, got {data!r}"


def greet(sock: socket.socket, methods: Iterable[int]) -> int:
    sock.sendall(build_greeting(methods))
    ver, method = recv_exact(sock, 2)
    assert ver == SOCKS_VERSION, f"unexpected VER {ver}"
    return method


def authenticate(sock: socket.socket, username: Address, password: Address, *, ver: int = AUTH_VERSION) -> int:
    sock.sendall(build_userpass(username, password, ver=ver))
    _, status = recv_exact(sock, 2)
    return status


def send_request(sock: socket.socket, cmd: int, atyp: int, addr: Address, port: int, **kwargs) -> None:
    sock.sendall(build_request(cmd, atyp, addr, port, **kwargs))


def read_reply(sock: socket.socket) -> Reply:
    ver, rep, rsv, atyp = recv_exact(sock, 4)
    if atyp == ATYP_IPV4:
        raw = recv_exact(sock, 4)
    elif atyp == ATYP_IPV6:
        raw = recv_exact(sock, 16)
    else:
        raw = recv_exact(sock, recv_exact(sock, 1)[0])
    (port,) = struct.unpack("!H", recv_exact(sock, 2))
    return Reply(ver, rep, rsv, atyp, _decode_address(atyp, raw), port)


def infer_atyp(addr: str) -> int:
    for family, atyp in ((socket.AF_INET, ATYP_IPV4), (socket.AF_INET6, ATYP_IPV6)):
        try:
            socket.inet_pton(family, addr)
            return atyp
        except OSError:
            pass
    return ATYP_DOMAIN


def open_tunnel(
    proxy_addr: tuple[str, int],
    dst_addr: str,
    dst_port: int,
    *,
    atyp: int | None = None,
    credentials: tuple[Address, Address] | None = None,
) -> socket.socket:
    sock = socket.create_connection(proxy_addr, timeout=TIMEOUT)
    try:
        wanted = METHOD_USERPASS if credentials else METHOD_NO_AUTH
        method = greet(sock, [wanted])
        if method != wanted:
            raise Socks5Error(f"proxy selected method {method:#04x}, wanted {wanted:#04x}")
        if credentials and authenticate(sock, *credentials) != AUTH_SUCCESS:
            raise Socks5Error("authentication failed")
        send_request(sock, CMD_CONNECT, atyp or infer_atyp(dst_addr), dst_addr, dst_port)
        reply = read_reply(sock)
        if reply.rep != REP_SUCCEEDED:
            raise Socks5Error(f"CONNECT failed with REP {reply.rep:#04x}", reply)
        return sock
    except BaseException:
        sock.close()
        raise
