import contextlib
import selectors
import socket
import time

from ..constants import RELAY_BUFFER_SIZE, UDP_FORWARD_TIMEOUT, UDP_RECV_TIMEOUT
from ..exceptions import MalformedDatagramError, PolicyDeniedError
from ..handlers import UDPHandler
from ..logger import get_logger
from ..models import BaseAddress, DetailedAddress
from ..policy import check_destination
from ..utils import (
    base_relay_template,
    generate_udp_socket,
    map_address_enum_to_socket_family,
)
from .base import BaseRelay

logger = get_logger(__name__)


class UDPRelay(BaseRelay):
    """
    Class responsible for relaying data between a client socket and a remote socket via UDP.
    """

    def __init__(self, client_connection: socket.socket, dst_address: DetailedAddress):
        super().__init__(client_connection, dst_address)
        self.expected_client_ip = client_connection.getpeername()[0]
        self.generate_proxy_connection()

    def generate_proxy_connection(self) -> None:
        sock = generate_udp_socket(self.dst_address.address_type)
        try:
            sock.bind(("", 0))  # Bind to any available port
            # select() can report a datagram that is then discarded (e.g. a bad checksum), so a read must not block
            sock.setblocking(False)
        except Exception:
            sock.close()
            raise
        self.proxy_connection = sock
        self.set_proxy_address()

    def listen_and_relay(self):
        """
        Relays client datagrams until the control connection closes or no client datagram arrives for
        UDP_RECV_TIMEOUT seconds (RFC 1928 §7: the association ends with its TCP connection).
        """
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.client_connection, selectors.EVENT_READ)
            selector.register(self.proxy_connection, selectors.EVENT_READ)
            idle_deadline = time.monotonic() + UDP_RECV_TIMEOUT
            while True:
                remaining = idle_deadline - time.monotonic()
                if remaining <= 0:
                    logger.debug("UDP relay timed out waiting for data")
                    return
                ready = {key.fileobj for key, _ in selector.select(timeout=remaining)}

                # Checked first, so nothing more is relayed once the control connection has closed
                if self.client_connection in ready and not self._control_connection_open():
                    logger.debug("UDP association ended: control connection closed")
                    return

                if self.proxy_connection in ready:
                    try:
                        data, addr = self.proxy_connection.recvfrom(RELAY_BUFFER_SIZE)
                    except BlockingIOError:
                        continue
                    if self._handle_datagram(data, addr):
                        idle_deadline = time.monotonic() + UDP_RECV_TIMEOUT

        except OSError as e:
            logger.error("UDP relay socket error: %s", e)
        finally:
            logger.info(self.closed_line())
            selector.close()
            with contextlib.suppress(OSError):
                self.proxy_connection.close()

    def _control_connection_open(self) -> bool:
        """
        Reads from the readable control connection. Returns False on EOF or error.

        Nothing is expected on it after the reply, so any data is discarded.
        """
        try:
            data = self.client_connection.recv(RELAY_BUFFER_SIZE)
        except OSError as e:
            logger.debug("UDP control connection error: %s", e)
            return False
        if data:
            logger.debug("(UDP) Ignored %s bytes on the control connection", len(data))
        return bool(data)

    def _handle_datagram(self, data: bytes, addr: tuple) -> bool:
        """
        Forwards one datagram received on the relay socket, or drops it.

        Returns whether it came from the client, which is what keeps the association alive.
        """
        if addr[0] != self.expected_client_ip:
            logger.debug("(UDP) Dropped datagram from unauthorized source: %s", addr[0])
            return False

        try:
            datagram = UDPHandler.parse_udp_datagram(data)
        except MalformedDatagramError as e:
            logger.debug("(UDP) Dropped datagram from %s: %s", addr, e)
            return True

        if datagram.frag != 0:
            logger.debug(
                "(UDP) Dropped fragmented datagram: %s -> %s:%s, Size: %s bytes",
                addr,
                datagram.dst_addr,
                datagram.dst_port,
                len(datagram.data),
            )
            return True

        try:
            self._forward_packet(datagram, addr)
        except PolicyDeniedError as e:
            logger.debug("(UDP) Dropped datagram from %s: %s", addr, e)
        except (ValueError, KeyError, OSError) as e:
            logger.debug("(UDP) Dropped unsupported datagram from %s: %s", addr, e)
        return True

    def _forward_packet(self, datagram, client_addr: tuple) -> None:
        check_destination(datagram.dst_addr, datagram.dst_port)
        with socket.socket(
            map_address_enum_to_socket_family(datagram.address_type),
            socket.SOCK_DGRAM,
        ) as forward_socket:
            forward_socket.settimeout(UDP_FORWARD_TIMEOUT)
            forward_socket.sendto(datagram.data, (datagram.dst_addr, datagram.dst_port))
            self.bytes_up += len(datagram.data)
            self._log_relay(
                BaseAddress(client_addr[0], client_addr[1]),
                BaseAddress(datagram.dst_addr, datagram.dst_port),
                len(datagram.data),
            )

            try:
                response, remote_addr = forward_socket.recvfrom(RELAY_BUFFER_SIZE)
                header = UDPHandler.build_udp_response_header(remote_addr[0], remote_addr[1])
                encapsulated = header + response
                self.proxy_connection.sendto(encapsulated, client_addr)
                self.bytes_down += len(response)
                self._log_relay(
                    BaseAddress(datagram.dst_addr, datagram.dst_port),
                    BaseAddress(client_addr[0], client_addr[1]),
                    len(encapsulated),
                )
            except TimeoutError:
                logger.debug(
                    "UDP forward timeout waiting for response from %s:%s", datagram.dst_addr, datagram.dst_port
                )

    def _log_relay(self, src_addr: BaseAddress, dst_addr: BaseAddress, data_len: int):
        logger.debug(
            base_relay_template.substitute(
                protocol="UDP",
                src_ip=src_addr.ip,
                src_port=src_addr.port,
                dst_ip=dst_addr.ip,
                dst_port=dst_addr.port,
                data_size=data_len,
            )
        )
