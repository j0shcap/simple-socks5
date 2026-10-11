import time
from abc import ABC, abstractmethod
from socket import socket

from ..models import BindAddress, DetailedAddress, SocketAddress
from ..utils.addresses import map_address_family_to_enum
from ..utils.logs import format_connection_closed


class BaseRelay(ABC):
    # Created by each subclass once its destination is allowed
    proxy_connection: socket

    def __init__(self, connection: socket, dst_address: DetailedAddress) -> None:
        self.client_connection = connection
        self.dst_address = dst_address
        self.client_address = self._read_client_address()
        self._started = time.monotonic()
        self.bytes_up = 0  # client -> destination
        self.bytes_down = 0  # destination -> client

    @abstractmethod
    def listen_and_relay(self) -> None:
        """
        Relays until either side is done, then releases the proxy socket.
        """

    def closed_line(self) -> str:
        """
        Returns the CLOSED summary logged once when the relay ends.
        """
        return format_connection_closed(
            self.client_address,
            self.dst_address,
            self.bytes_up,
            self.bytes_down,
            time.monotonic() - self._started,
        )

    def _read_client_address(self) -> DetailedAddress:
        peer: SocketAddress = self.client_connection.getpeername()
        try:
            addr_type = map_address_family_to_enum(self.client_connection.family)
        except ValueError:
            addr_type = self.dst_address.address_type
        return DetailedAddress(
            ip=peer[0],
            port=peer[1],
            name="Client",
            address_type=addr_type,
        )

    def get_proxy_address(self) -> BindAddress:
        """
        Returns the address of the proxy socket, which the client is told in BND.ADDR and BND.PORT.
        """
        addr: SocketAddress = self.proxy_connection.getsockname()
        return BindAddress(ip=addr[0], port=addr[1])
