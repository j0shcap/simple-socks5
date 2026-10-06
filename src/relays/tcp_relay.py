import socket
import selectors

from .base import BaseRelay
from ..constants import RELAY_BUFFER_SIZE, RELAY_WRITE_TIMEOUT, TCP_SELECTOR_TIMEOUT
from ..models import DetailedAddress
from ..logger import get_logger
from ..utils import (
    generate_tcp_socket,
    detailed_relay_template,
    connection_closed_template,
)

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
        # Generate proxy connection
        self.proxy_connection = generate_tcp_socket(self.dst_address.address_type)
        self.proxy_connection.connect((self.dst_address.ip, self.dst_address.port))
        self.set_proxy_address()
        # Register sockets with selector
        self.selector.register(self.client_connection, selectors.EVENT_READ)
        self.selector.register(self.proxy_connection, selectors.EVENT_READ)

    def listen_and_relay(self) -> None:
        """
        Relays data between the client socket and the remote socket.
        """

        try:
            self._prepare_sockets()
            while True:
                events = self.selector.select(timeout=TCP_SELECTOR_TIMEOUT)
                if not events:
                    if self.client_connection.fileno() == -1 or self.proxy_connection.fileno() == -1:
                        break
                    continue

                for key, _ in events:
                    sock = key.fileobj
                    other_sock = (
                        self.proxy_connection
                        if sock is self.client_connection
                        else self.client_connection
                    )

                    # Metadata for logging
                    other_info: DetailedAddress = (
                        self.get_dst_address()
                        if sock is self.client_connection
                        else self.get_client_address()
                    )
                    sock_info: DetailedAddress = (
                        self.get_client_address()
                        if sock is self.client_connection
                        else self.get_dst_address()
                    )

                    # Handle incoming data
                    data: bytes = self._recv_data(sock)
                    if not data:
                        return

                    # Blocks while the receiver is slow: that is the backpressure
                    self._send_data(other_sock, data)
                    self._log_relay(sock_info, other_info, len(data))

        except BrokenPipeError:
            logger.exception("Broken Pipe")
        except ConnectionResetError:
            logger.exception("Connection Reset")
        except TimeoutError:
            logger.warning(f"Relay write timed out after {RELAY_WRITE_TIMEOUT} seconds")
        except OSError:
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

    def _log_relay(
        self, src_addr: DetailedAddress, dst_addr: DetailedAddress, data_len: int
    ) -> None:
        """
        Logs the relay of data between the client and the destination.

        Args:
            src_addr (DetailedAddress): The source socket information.
            dst_addr (DetailedAddress): The destination socket information.
            data_len (int): The length of the data sent.
        """
        logger.debug(
            detailed_relay_template.substitute(
                protocol="TCP",
                src_domain_name=src_addr.name,
                src_ip=src_addr.ip,
                src_port=src_addr.port,
                dst_domain_name=dst_addr.name,
                dst_ip=dst_addr.ip,
                dst_port=dst_addr.port,
                data_size=data_len,
            )
        )

    def _log_connection_closed(self) -> None:
        """
        Logs a connection closed event.
        """
        client_address: DetailedAddress = self.get_client_address()
        dst_address: DetailedAddress = self.get_dst_address()

        logger.info(
            connection_closed_template.substitute(
                src_domain_name=client_address.name,
                src_ip=client_address.ip,
                src_port=client_address.port,
                dst_domain_name=dst_address.name,
                dst_ip=dst_address.ip,
                dst_port=dst_address.port,
            )
        )

    def _send_data(self, sock: socket.socket, data: bytes) -> None:
        try:
            sock.sendall(data)
        except socket.error as e:
            logger.error(f"Error sending data: {e}")
            raise

    def _recv_data(self, sock: socket.socket) -> bytes:
        try:
            return sock.recv(RELAY_BUFFER_SIZE)
        except socket.error as e:
            logger.error(f"Error receiving data: {e}")
            raise

    def _cleanup(self) -> None:
        self._log_connection_closed()
        # Unregister both sockets from the selector
        for sock in [self.client_connection, self.proxy_connection]:
            try:
                self.selector.unregister(sock)
            except (OSError, ValueError):
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
