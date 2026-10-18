import contextlib
import functools
import logging
import math
import socket
import struct
import threading
import time

from ..constants import RELAY_BUFFER_SIZE, RELAY_IDLE_CHECK_INTERVAL, RELAY_INITIAL_BUFFER_SIZE, RELAY_WRITE_TIMEOUT
from ..logger import get_logger
from ..models import DetailedAddress
from ..resolver import connect_any
from .base import BaseRelay

logger = get_logger(__name__)


class _WriteTimeoutError(TimeoutError):
    """A peer read nothing, or too little, for RELAY_WRITE_TIMEOUT."""


class TCPRelay(BaseRelay):
    """
    Class responsible for relaying data between a client socket and a remote socket via TCP.

    Each direction has its own thread that blocks in recv() and then in send(): the handler thread relays
    destination -> client, and a thread the relay starts relays client -> destination.
    """

    def __init__(self, client_connection: socket.socket, dst_address: DetailedAddress) -> None:
        """
        Initializes a new instance of the TCPRelay class.

        Args:
            client_connection (socket.socket): The client socket.
            dst_address (DetailedAddress): The address to connect to. self.dst_address becomes the address reached.
        """
        super().__init__(client_connection, dst_address)
        # Taken by the first direction to fail, which alone logs why the relay ended
        self._ended = threading.Lock()
        sock: socket.socket | None = None
        try:
            sock, self.dst_address = connect_any(dst_address)
            self._disable_nagle(sock)
        except Exception:
            if sock is not None:
                sock.close()
            raise
        self.proxy_connection = sock

    def listen_and_relay(self) -> None:
        """
        Relays data between the client socket and the remote socket.

        EOF from one side is passed on as a half-close; relaying continues in the other direction
        until it reaches EOF too. Each direction reads larger chunks once a read fills the initial size.
        """
        try:
            self._prepare_sockets()
            upstream = threading.Thread(
                target=self._pump_upstream,
                name=f"{threading.current_thread().name}-up",
                daemon=True,
            )
            upstream.start()
        except (OSError, RuntimeError) as e:
            # RuntimeError: can't start new thread, so the process is out of threads or memory
            self._end(logging.WARNING if isinstance(e, RuntimeError) else logging.DEBUG, "Relay ended: %s", e)
            self._cleanup()
            return
        try:
            self._pump(self.proxy_connection, self.client_connection)
        finally:
            upstream.join()
            self._cleanup()

    def _pump_upstream(self) -> None:
        """
        _pump from the client on the thread the relay starts. Logs a bug there as the server's handle_error does for
        the handler thread: threading.excepthook would print it to stderr, ignoring -L.
        """
        try:
            self._pump(self.client_connection, self.proxy_connection)
        except Exception:
            logger.exception("Unhandled error serving %s", self.client_address.ip)

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        """
        Relays src to dst until src sends EOF, which is passed on to dst as a half-close. A failure ends both
        directions.
        """
        size = RELAY_INITIAL_BUFFER_SIZE
        upstream = src is self.client_connection
        try:
            while True:
                try:
                    n = self._move(src, dst, size)
                except BlockingIOError:  # nothing to read for RELAY_IDLE_CHECK_INTERVAL
                    if self.client_connection.fileno() == -1 or self.proxy_connection.fileno() == -1:
                        return
                    continue
                if not n:
                    dst.shutdown(socket.SHUT_WR)
                    return
                if n == size:
                    size = RELAY_BUFFER_SIZE
                if upstream:
                    self.bytes_up += n
                else:
                    self.bytes_down += n
        except _WriteTimeoutError:
            self._end(logging.WARNING, "Relay write timed out after %s seconds", RELAY_WRITE_TIMEOUT)
        except OSError as e:
            self._end(logging.DEBUG, "Relay ended: %s", e)
        except BaseException:
            self._wake()  # otherwise the other direction waits for its peer
            raise

    def _move(self, src: socket.socket, dst: socket.socket, size: int) -> int:
        """
        Reads up to size bytes from src and writes them all to dst. Returns how many, 0 at EOF. The chunk is released
        on return, so it isn't held while the next read waits.
        """
        data = src.recv(size)
        if data:
            self._send_all(dst, data)
        return len(data)

    def _send_all(self, sock: socket.socket, data: bytes | memoryview) -> None:
        """
        Writes all of data within RELAY_WRITE_TIMEOUT. The kernel's SO_SNDTIMEO bounds each send(), so a reader that
        takes only part of it gets what is left of the timeout for the rest. Blocks while the reader is slow: that is
        the backpressure.
        """
        started = time.monotonic()
        try:
            sent = sock.send(data)
            if sent == len(data):
                return
            rest = memoryview(data)[sent:]
            try:
                while rest:
                    remaining = started + RELAY_WRITE_TIMEOUT - time.monotonic()
                    if remaining <= 0:
                        raise _WriteTimeoutError
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _timeval(remaining))
                    rest = rest[sock.send(rest) :]
            finally:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _timeval(RELAY_WRITE_TIMEOUT))
        except BlockingIOError as e:  # SO_SNDTIMEO passed without the reader taking anything
            raise _WriteTimeoutError from e

    def _end(self, level: int, msg: str, *args: object) -> None:
        """
        Logs why the relay ended and wakes the other direction, unless another failure already did.
        """
        if self._ended.acquire(blocking=False):
            logger.log(level, msg, *args)
            self._wake()

    def _wake(self) -> None:
        """
        Shuts both sockets down, which returns from a recv() or send() blocked on either.
        """
        for sock in (self.client_connection, self.proxy_connection):
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)

    def _disable_nagle(self, upstream: socket.socket) -> None:
        """
        Sends small writes at once. Otherwise the second part of a message written in two waits until the first is
        acknowledged, which the peer delays (about 40 ms on Linux). Set before the CONNECT reply, so that isn't held
        either.
        """
        for sock in (self.client_connection, upstream):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _prepare_sockets(self) -> None:
        """
        Makes both sockets blocking with kernel timeouts, and enables keepalive to detect dead peers. A Python
        socket timeout would poll() before every recv() and send().
        """
        for sock in (self.client_connection, self.proxy_connection):
            sock.settimeout(None)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _timeval(RELAY_WRITE_TIMEOUT))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _timeval(RELAY_IDLE_CHECK_INTERVAL))

    def _cleanup(self) -> None:
        logger.info(self.closed_line())
        # Only close proxy_connection — client_connection is owned by the server
        with contextlib.suppress(OSError):
            self.proxy_connection.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.proxy_connection.close()


@functools.cache
def _timeval_format() -> str:
    """
    The struct format of a struct timeval: two 32-bit fields where time_t is 32 bits, else 16 bytes, which also fits
    macOS's long and padded int. The width of time_t also decides which SO_SNDTIMEO the socket module has: 32-bit
    platforms built with a 64-bit time_t, such as Debian's armhf, have the one that takes 16 bytes.
    """
    try:
        time.gmtime(2**31)
    except (OverflowError, OSError):
        return "@ii"
    return "@qq"


def _timeval(seconds: float) -> bytes:
    """
    seconds as the struct timeval that SO_SNDTIMEO and SO_RCVTIMEO take, rounded up to a microsecond: a timeval of 0
    means no timeout.
    """
    return struct.pack(_timeval_format(), *divmod(math.ceil(seconds * 1_000_000), 1_000_000))
