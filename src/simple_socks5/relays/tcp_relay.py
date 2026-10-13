import contextlib
import selectors
import socket

from ..constants import RELAY_BUFFER_SIZE, RELAY_WRITE_TIMEOUT, TCP_SELECTOR_TIMEOUT, connect_timeout
from ..logger import get_logger
from ..models import DetailedAddress
from ..policy import check_destination
from ..utils import generate_tcp_socket
from .base import BaseRelay

logger = get_logger(__name__)


class TCPRelay(BaseRelay):
    """
    Class responsible for relaying data between a client socket and a remote socket via TCP.
    """

    def __init__(self, client_connection: socket.socket, dst_address: DetailedAddress) -> None:
        """
        Initializes a new instance of the TCPRelay class.

        Args:
            client_connection (socket.socket): The client socket.
            dst_address (DetailedAddress): The address to connect to.
        """
        super().__init__(client_connection, dst_address)
        self.selector: selectors.BaseSelector = selectors.DefaultSelector()
        sock: socket.socket | None = None
        try:
            check_destination(dst_address.ip, dst_address.port)
            sock = generate_tcp_socket(dst_address.address_type)
            # Replaced by the relay's write timeout in _prepare_sockets()
            sock.settimeout(connect_timeout())
            sock.connect((dst_address.ip, dst_address.port))
            self.selector.register(client_connection, selectors.EVENT_READ)
            self.selector.register(sock, selectors.EVENT_READ)
        except Exception:
            if sock is not None:
                sock.close()
            self.selector.close()
            raise
        self.proxy_connection = sock

    def listen_and_relay(self) -> None:
        """
        Relays data between the client socket and the remote socket.

        EOF from one side is passed on as a half-close; relaying continues in the other direction
        until it reaches EOF too.
        """
        open_readers = {self.client_connection, self.proxy_connection}
        try:
            self._prepare_sockets()
            while open_readers:
                events = self.selector.select(timeout=TCP_SELECTOR_TIMEOUT)
                if not events:
                    if self.client_connection.fileno() == -1 or self.proxy_connection.fileno() == -1:
                        break
                    continue

                for key, _ in events:
                    sock, other_sock = self._direction(key.fileobj)

                    data = sock.recv(RELAY_BUFFER_SIZE)
                    if not data:
                        self._half_close(sock, other_sock)
                        open_readers.discard(sock)
                        continue

                    # Blocks while the receiver is slow: that is the backpressure
                    other_sock.sendall(data)
                    if sock is self.client_connection:
                        self.bytes_up += len(data)
                    else:
                        self.bytes_down += len(data)

        except TimeoutError:
            logger.warning("Relay write timed out after %s seconds", RELAY_WRITE_TIMEOUT)
        except OSError as e:
            logger.debug("Relay ended: %s", e)
        finally:
            self._cleanup()

    def _direction(self, ready: object) -> tuple[socket.socket, socket.socket]:
        """
        Returns the socket the selector reported readable and the socket its data goes to. The selector types its
        file objects as any file, so the socket is found by identity.
        """
        if ready is self.client_connection:
            return self.client_connection, self.proxy_connection
        return self.proxy_connection, self.client_connection

    def _prepare_sockets(self) -> None:
        """
        Makes both sockets blocking with a bounded write time, and enables keepalive to detect dead peers.
        """
        for sock in (self.client_connection, self.proxy_connection):
            sock.settimeout(RELAY_WRITE_TIMEOUT)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def _half_close(self, eof_sock: socket.socket, other_sock: socket.socket) -> None:
        """
        Stops reading from the side that sent EOF and passes the EOF on to the other side.
        """
        self.selector.unregister(eof_sock)
        other_sock.shutdown(socket.SHUT_WR)

    def _cleanup(self) -> None:
        logger.info(self.closed_line())
        # Unregister both sockets from the selector
        for sock in [self.client_connection, self.proxy_connection]:
            with contextlib.suppress(OSError, ValueError, KeyError):
                self.selector.unregister(sock)
        # Only close proxy_connection — client_connection is owned by the server
        with contextlib.suppress(OSError):
            self.proxy_connection.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.proxy_connection.close()
        with contextlib.suppress(OSError):
            self.selector.close()
