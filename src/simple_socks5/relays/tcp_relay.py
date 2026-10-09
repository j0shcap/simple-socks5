import selectors
import socket

from ..constants import RELAY_BUFFER_SIZE, RELAY_WRITE_TIMEOUT, TCP_SELECTOR_TIMEOUT, connect_timeout
from ..errors import is_routine_disconnect
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

    def __init__(self, client_connection: socket.socket, dst_address: DetailedAddress):
        """
        Initializes a new instance of the TCPRelay class.

        Args:
            connection (socket.socket): The client socket.
            dst_address (DetailedAddress): The address to connect to.
        """
        super().__init__(client_connection, dst_address)
        self.selector = selectors.DefaultSelector()
        try:
            self.generate_proxy_connection()
        except Exception:
            # proxy_connection is unset if generate_tcp_socket itself raised
            proxy_connection = getattr(self, "proxy_connection", None)
            if proxy_connection is not None:
                proxy_connection.close()
            self.selector.close()
            raise

    def generate_proxy_connection(self) -> None:
        """
        Generates a new proxy connection.
        """
        check_destination(self.dst_address.ip, self.dst_address.port)
        # Generate proxy connection
        self.proxy_connection = generate_tcp_socket(self.dst_address.address_type)
        # Replaced by the relay's write timeout in _prepare_sockets()
        self.proxy_connection.settimeout(connect_timeout())
        self.proxy_connection.connect((self.dst_address.ip, self.dst_address.port))
        self.set_proxy_address()
        # Register sockets with selector
        self.selector.register(self.client_connection, selectors.EVENT_READ)
        self.selector.register(self.proxy_connection, selectors.EVENT_READ)

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
                    sock = key.fileobj
                    other_sock = self.proxy_connection if sock is self.client_connection else self.client_connection

                    # Handle incoming data
                    data: bytes = self._recv_data(sock)
                    if not data:
                        self._half_close(sock, other_sock)
                        open_readers.discard(sock)
                        continue

                    # Blocks while the receiver is slow: that is the backpressure
                    self._send_data(other_sock, data)
                    if sock is self.client_connection:
                        self.bytes_up += len(data)
                    else:
                        self.bytes_down += len(data)

        except TimeoutError:
            logger.warning("Relay write timed out after %s seconds", RELAY_WRITE_TIMEOUT)
        except OSError as e:
            if is_routine_disconnect(e):
                logger.debug("Relay ended: %s", e)
            else:
                logger.exception("Socket error during relay")
        finally:
            self._cleanup()

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

    def _send_data(self, sock: socket.socket, data: bytes) -> None:
        sock.sendall(data)

    def _recv_data(self, sock: socket.socket) -> bytes:
        return sock.recv(RELAY_BUFFER_SIZE)

    def _cleanup(self) -> None:
        logger.info(self.closed_line())
        # Unregister both sockets from the selector
        for sock in [self.client_connection, self.proxy_connection]:
            try:
                self.selector.unregister(sock)
            except (OSError, ValueError, KeyError):
                pass
        # Only close proxy_connection — client_connection is owned by the server
        try:
            self.proxy_connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.proxy_connection.close()
        except OSError:
            pass
        try:
            self.selector.close()
        except OSError:
            pass
