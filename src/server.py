import socket
import threading
from socketserver import StreamRequestHandler, ThreadingMixIn, TCPServer

from .constants import CommandCodes
from .handlers import TCPHandler
from .relays import TCPRelay, UDPRelay
from .utils import (
    generate_general_socks_server_failure_reply,
    generate_command_not_supported_reply,
    generate_connection_refused_reply,
    generate_host_unreachable_reply,
    generate_succeeded_reply,
    connection_established_template,
)
from .logger import get_logger
from .models import Request, DetailedAddress

logger = get_logger(__name__)


MAX_CONNECTIONS = 200


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    """
    A threading version of a TCP server with a connection limit.

    https://docs.python.org/3/library/socketserver.html#socketserver.ThreadingMixIn
    """

    daemon_threads = True
    _connection_semaphore = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if self._connection_semaphore.acquire(blocking=False):
            try:
                super().process_request(request, client_address)
            except Exception:
                self._connection_semaphore.release()
                raise
        else:
            logger.warning("Connection limit reached, rejecting connection")
            self.shutdown_request(request)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Daemon request threads aren't tracked by ThreadingMixIn, so track their sockets for shutdown.
        self._active_requests: set[socket.socket] = set()
        self._active_cond = threading.Condition()

    def process_request_thread(self, request, client_address):
        with self._active_cond:
            self._active_requests.add(request)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_cond:
                self._active_requests.discard(request)
                self._active_cond.notify_all()
            self._connection_semaphore.release()

    def wait_for_connections(self, timeout: float) -> bool:
        """
        Waits up to timeout seconds for every in-flight request to finish. Returns True if none remain.
        """
        with self._active_cond:
            return self._active_cond.wait_for(lambda: not self._active_requests, timeout)

    def close_connections(self) -> int:
        """
        Shuts down every in-flight request socket so its handler thread wakes up, sees EOF and closes it.
        Returns the number of sockets shut down.
        """
        with self._active_cond:
            requests = list(self._active_requests)
        closed = 0
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                continue  # The handler closed it in the meantime
            closed += 1
        return closed


class TCPProxyServer(StreamRequestHandler):
    """
    For each connection, a new instance of this class is created.

    https://docs.python.org/3/library/socketserver.html#socketserver.StreamRequestHandler
    """

    client_address: DetailedAddress
    connection: socket.socket
    server: ThreadingTCPServer

    def handle(self):
        """
        This function must do all the work required to service a request.

        Available:
            connection: The new socket.socket object to be used to communicate with the client.
            client_address: Client address returned by BaseServer.get_request().
            server: BaseServer object used for handling the request.
        """
        request_handler = TCPHandler(self.connection)

        if not request_handler.handle_request():
            logger.error("Handshake failed")
            self.server.shutdown_request(self.request)
            return

        try:
            dst_request: Request = request_handler.parse_request()
        except Exception:
            logger.error("Failed to parse SOCKS5 request")
            self._send_error_reply(generate_general_socks_server_failure_reply())
            return

        peer = self.connection.getpeername()
        self.client_address: DetailedAddress = DetailedAddress(
            ip=peer[0],
            port=peer[1],
            name="Client",
            address_type=dst_request.address.address_type,
        )
        self._log_connection(dst_request.address)

        atyp = dst_request.address.address_type
        try:
            if dst_request.command == CommandCodes.CONNECT.value:
                self.handle_connect(dst_request.address)

            elif dst_request.command == CommandCodes.BIND.value:
                self.handle_bind(dst_request.address)

            elif dst_request.command == CommandCodes.UDP_ASSOCIATE.value:
                self.handle_udp_associate(dst_request.address)

            else:
                self._send_error_reply(generate_command_not_supported_reply(atyp))

        except ConnectionRefusedError:
            logger.error(f"Connection refused: {dst_request.address}")
            self._send_error_reply(generate_connection_refused_reply(atyp))
        except socket.gaierror:
            logger.error(f"Host unreachable: {dst_request.address}")
            self._send_error_reply(generate_host_unreachable_reply(atyp))
        except Exception as e:
            logger.error(f"Exception: {e}")
            self._send_error_reply(generate_general_socks_server_failure_reply(atyp))

    def handle_connect(self, dst_address: DetailedAddress) -> None:
        """
        Handles CONNECT command.
        """
        # Allocate port for TCP relay
        tcp_relay = TCPRelay(self.connection, dst_address)

        # Send reply with bind address and port
        success_reply = generate_succeeded_reply(
            dst_address.address_type, *tcp_relay.get_proxy_address()
        )
        self.connection.sendall(success_reply)

        # Start TCP relay
        tcp_relay.listen_and_relay()

    def handle_udp_associate(self, dst_address: DetailedAddress) -> None:
        """
        Handles UDP ASSOCIATE command.
        """
        # Allocate port for UDP relay
        udp_relay = UDPRelay(self.connection, dst_address)

        # Send reply with allocated port and server IP
        success_reply = generate_succeeded_reply(
            dst_address.address_type, *udp_relay.get_proxy_address()
        )
        self.connection.sendall(success_reply)

        # Start UDP relay
        udp_relay.listen_and_relay()

    def handle_bind(self, address: DetailedAddress) -> None:
        """
        Handles BIND command.
        """
        logger.error("BIND command not supported")
        self._send_error_reply(generate_command_not_supported_reply(address.address_type))

    def _send_error_reply(self, reply: bytes) -> None:
        """
        Sends an error reply to the client, swallowing OSError on send failure.
        """
        try:
            self.connection.sendall(reply)
        except OSError as e:
            logger.error(f"Error sending reply: {e}")

    def finish(self):
        """
        Called after handle() to perform any clean-up actions required.

        Ensures proper closure of each socket.
        """
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass  # Handle already closed socket
        finally:
            self.connection.close()

    def _log_connection(self, dst_address: DetailedAddress) -> None:
        """
        Logs connection.
        """
        logger.info(
            connection_established_template.substitute(
                src_domain_name=self.client_address.name,
                src_ip=self.client_address.ip,
                src_port=self.client_address.port,
                dst_domain_name=dst_address.name,
                dst_ip=dst_address.ip,
                dst_port=dst_address.port,
            )
        )
