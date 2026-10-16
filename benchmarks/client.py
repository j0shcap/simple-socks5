"""
A minimal SOCKS5 client, the operations the scenarios time, and the load-generating workers that run them.

Workers run in separate processes, each with several threads, so the client side isn't limited to one GIL.
Timestamps are time.perf_counter(), which is system-wide on Linux and macOS, so workers' times can be compared.
"""

import contextlib
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from .origins import CHUNK, COMMAND, HEADER, WRITE_GAP, drain, recv_exact, send_zeros

CONNECT_TIMEOUT: Final = 30.0


@dataclass(frozen=True)
class Route:
    """How a client reaches the origin: directly, or through a proxy with optional credentials."""

    origin: tuple[str, int]
    proxy: tuple[str, int] | None = None
    credentials: tuple[bytes, bytes] | None = None
    hostname: str | None = None  # sent as a DOMAINNAME instead of the origin's IP


def open_stream(route: Route, marks: list[float] | None = None, *, connect: bool = True) -> socket.socket:
    """
    Connects to the origin, through the proxy if the route has one. With marks, appends the time the TCP connection
    was established, then (through a proxy) the times the method reply and the CONNECT reply arrived. Without
    connect, stops after the proxy's greeting and authentication.
    """
    sock = socket.create_connection(route.proxy or route.origin, timeout=CONNECT_TIMEOUT)
    try:
        # As curl and browsers do, so each write leaves at once
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if marks is not None:
            marks.append(time.perf_counter())
        if route.proxy is not None:
            _greet(sock, route)
            if marks is not None:
                marks.append(time.perf_counter())
            if connect:
                sock.sendall(b"\x05\x01\x00" + _address(route))
                _read_reply(sock)
                if marks is not None:
                    marks.append(time.perf_counter())
    except BaseException:
        sock.close()
        raise
    return sock


def _greet(sock: socket.socket, route: Route) -> None:
    method = 2 if route.credentials else 0
    sock.sendall(bytes((5, 1, method)))
    if recv_exact(sock, 2) != bytes((5, method)):
        raise ConnectionError("the proxy refused the authentication method")
    if route.credentials:
        user, password = route.credentials
        sock.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
        if recv_exact(sock, 2) != b"\x01\x00":
            raise ConnectionError("the proxy rejected the credentials")


def _address(route: Route) -> bytes:
    host, port = route.origin
    if route.hostname is not None:
        name = route.hostname.encode()
        return bytes((3, len(name))) + name + port.to_bytes(2, "big")
    return b"\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")


def _read_reply(sock: socket.socket) -> tuple[str, int]:
    """Reads a SOCKS5 reply and returns its BND.ADDR and BND.PORT."""
    _, rep, _, atyp = recv_exact(sock, 4)
    if rep != 0:
        raise ConnectionError(f"the proxy replied {rep:#04x}")
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        host = recv_exact(sock, recv_exact(sock, 1)[0]).decode()
    return host, int.from_bytes(recv_exact(sock, 2), "big")


def download(route: Route, size: int) -> int:
    with open_stream(route) as sock:
        sock.sendall(COMMAND.pack(b"D", size))
        got = drain(sock, size + 1, bytearray(CHUNK))
    if got != size:
        raise ConnectionError(f"downloaded {got} of {size} bytes")
    return size


def upload(route: Route, size: int) -> int:
    with open_stream(route) as sock:
        sock.sendall(COMMAND.pack(b"U", size))
        send_zeros(sock, size)
        recv_exact(sock, 1)
    return size


def first_byte_marks(route: Route, size: int) -> list[float]:
    """
    Downloads size bytes and returns the times: start, connected, (method reply, CONNECT reply,) first byte, done.
    """
    marks = [time.perf_counter()]
    with open_stream(route, marks) as sock:
        sock.sendall(COMMAND.pack(b"D", size))
        buf = bytearray(CHUNK)
        got = sock.recv_into(buf)
        marks.append(time.perf_counter())
        got += drain(sock, size, buf)
    marks.append(time.perf_counter())
    if got != size:
        raise ConnectionError(f"downloaded {got} of {size} bytes")
    return marks


def round_trips(route: Route, size: int, count: int) -> list[float]:
    """
    Over one connection, sends count messages of size bytes, each in two writes WRITE_GAP apart, and waits for each
    answer, which also comes in two writes. Returns each round trip's latency.
    """
    header, body = bytes(HEADER), bytes(size - HEADER)
    latencies = []
    with open_stream(route) as sock:
        sock.sendall(COMMAND.pack(b"W", size))
        for _ in range(count):
            start = time.perf_counter()
            sock.sendall(header)
            time.sleep(WRITE_GAP)
            sock.sendall(body)
            recv_exact(sock, size)
            latencies.append(time.perf_counter() - start)
    return latencies


def udp_round_trips(route: Route, udp_port: int, size: int, count: int) -> list[float]:
    """
    Sends count datagrams of size bytes to the UDP echo origin, through a UDP association if the route has a proxy,
    each after the previous answer. Returns each round trip's latency.
    """
    payload = bytes(size)
    latencies = []
    with contextlib.ExitStack() as stack:
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(CONNECT_TIMEOUT)
        if route.proxy is None:
            to = ("127.0.0.1", udp_port)
            datagram = payload
            header = 0
        else:
            control = stack.enter_context(open_stream(route, connect=False))
            # The client tells the proxy the address it sends from, as RFC 1928 §7 asks
            sent_from = udp.getsockname()
            control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton(sent_from[0]) + sent_from[1].to_bytes(2, "big"))
            bound_host, bound_port = _read_reply(control)
            to = (route.proxy[0] if bound_host in {"0.0.0.0", "::"} else bound_host, bound_port)  # noqa: S104
            datagram = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, "big") + payload
            header = 10
        for _ in range(count):
            start = time.perf_counter()
            udp.sendto(datagram, to)
            answer = udp.recv(65535)
            latencies.append(time.perf_counter() - start)
            if len(answer) != header + size:
                raise ConnectionError(f"UDP answer of {len(answer)} bytes, expected {header + size}")
    return latencies


@dataclass(frozen=True)
class Job:
    """One worker process's share of a load: threads that each run op count times."""

    op: str
    route: Route
    size: int
    count: int
    threads: int
    start_at: float  # perf_counter() time all workers start at
    udp_port: int = 0


@dataclass
class JobResult:
    latencies: list[float] = field(default_factory=list)
    marks: list[list[float]] = field(default_factory=list)
    nbytes: int = 0
    started: float = 0.0
    ended: float = 0.0
    errors: list[str] = field(default_factory=list)


def _operation(job: Job) -> Callable[[JobResult], None]:
    def once(result: JobResult, fn: Callable[[], int]) -> None:
        start = time.perf_counter()
        result.nbytes += fn()
        result.latencies.append(time.perf_counter() - start)

    if job.op == "download":
        return lambda result: once(result, lambda: download(job.route, job.size))
    if job.op == "upload":
        return lambda result: once(result, lambda: upload(job.route, job.size))
    if job.op == "first_byte":
        return lambda result: result.marks.append(first_byte_marks(job.route, job.size))
    if job.op == "round_trips":
        return lambda result: result.latencies.extend(round_trips(job.route, job.size, job.count))
    if job.op == "udp":
        return lambda result: result.latencies.extend(udp_round_trips(job.route, job.udp_port, job.size, job.count))
    raise ValueError(f"unknown operation {job.op!r}")


def _repeats(job: Job) -> int:
    # round_trips and udp make count round trips over one connection or association
    return 1 if job.op in {"round_trips", "udp"} else job.count


def _attempt(operation: Callable[[JobResult], None], result: JobResult) -> None:
    try:
        operation(result)
    except OSError as e:
        result.errors.append(f"{type(e).__name__}: {e}")


def run_job(job: Job) -> JobResult:
    """Runs in a worker process: starts job.threads threads at job.start_at and returns their combined results."""
    operation = _operation(job)
    results = [JobResult() for _ in range(job.threads)]

    def thread_main(result: JobResult) -> None:
        time.sleep(max(0.0, job.start_at - time.perf_counter()))
        result.started = time.perf_counter()
        for _ in range(_repeats(job)):
            _attempt(operation, result)
        result.ended = time.perf_counter()

    threads = [threading.Thread(target=thread_main, args=(result,)) for result in results]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    combined = JobResult(started=min(r.started for r in results), ended=max(r.ended for r in results))
    for result in results:
        combined.latencies += result.latencies
        combined.marks += result.marks
        combined.nbytes += result.nbytes
        combined.errors += result.errors
    return combined


def warm_up() -> None:
    """Submitted once to each worker process, so process start-up isn't timed."""
