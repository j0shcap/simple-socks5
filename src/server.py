import socket
import threading
import time
from socketserver import StreamRequestHandler, ThreadingMixIn, TCPServer

from .constants import (
    CONNECTION_LIMIT_WARNING_INTERVAL,
    AddressTypeCodes,
    CommandCodes,
    handshake_timeout,
    max_connections,
)
from .errors import reply_code_for
from .exceptions import HandshakeTimeoutError
from .handlers import TCPHandler
from .relays import TCPRelay, UDPRelay
from .utils import (
    generate_command_not_supported_reply,
    generate_failed_reply,
    generate_succeeded_reply,
    connection_established_template,
)
from .logger import get_logger
from .models import BindAddress, Request, DetailedAddress

logger = get_logger(__name__)


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    """
    A threading version of a TCP server with a connection limit.

    https://docs.python.org/3/library/socketserver.html#socketserver.ThreadingMixIn
    """

    daemon_threads = True
    # socketserver's default backlog of 5 overflows when many clients connect at once, and Linux then
    # retransmits the dropped handshakes after 1 s, 3 s, ..., delaying both their accept and their rejection
    request_queue_size = socket.SOMAXCONN

    def process_request(self, request, client_address):
        if self._connection_semaphore.acquire(blocking=False):
            # Tracked on the serving thread, not the handler thread, so a drain that starts once serve_forever()
            # returns can't miss a request whose handler thread hasn't run yet.
            self._track_request(request)
            try:
                super().process_request(request, client_address)
            except Exception:
                self._untrack_request(request)
                self._connection_semaphore.release()
                raise
        else:
            self._reject_request(request)

    def __init__(self, *args, **kwargs):
        # Read before binding, so an invalid value can't leave a listening socket behind
        self.max_connections = max_connections()
        self._connection_semaphore = threading.BoundedSemaphore(self.max_connections)
        # Only touched by process_request(), which socketserver calls from the serving thread alone
        self._rejected_since_warning = 0
        self._next_limit_warning = 0.0
        super().__init__(*args, **kwargs)
        # Daemon request threads aren't tracked by ThreadingMixIn, so track their sockets for shutdown.
        self._active_requests: set[socket.socket] = set()
        self._active_cond = threading.Condition()

    def _reject_request(self, request) -> None:
        """
        Closes a connection over the limit, warning at most once per CONNECTION_LIMIT_WARNING_INTERVAL.
        """
        self._rejected_since_warning += 1
        now = time.monotonic()
        if now >= self._next_limit_warning:
            logger.warning(
                f"Connection limit of {self.max_connections} reached: rejected "
                f"{self._rejected_since_warning} connection(s) since the last warning"
            )
            self._rejected_since_warning = 0
            self._next_limit_warning = now + CONNECTION_LIMIT_WARNING_INTERVAL
        self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._untrack_request(request)
            self._connection_semaphore.release()

    def _track_request(self, request: socket.socket) -> None:
        with self._active_cond:
            self._active_requests.add(request)

    def _untrack_request(self, request: socket.socket) -> None:
        with self._active_cond:
            self._active_requests.discard(request)
            self._active_cond.notify_all()

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
    # Set as soon as a reply is attempted: the client must never receive a second one
    _reply_sent: bool = False

    def handle(self):
        """
        This function must do all the work required to service a request.

        Available:
            connection: The new socket.socket object to be used to communicate with the client.
            client_address: Client address returned by BaseServer.get_request().
            server: BaseServer object used for handling the request.
        """
        # Greeting, authentication and request must all arrive before this deadline
        deadline = time.monotonic() + handshake_timeout()
        request_handler = TCPHandler(self.connection, deadline=deadline)

        if not request_handler.handle_request():
            logger.error("Handshake failed")
            self.server.shutdown_request(self.request)
            return

        try:
            dst_request: Request = request_handler.parse_request()
        except HandshakeTimeoutError:
            # The client never finished its request, so it gets no reply
            logger.warning("Handshake timed out waiting for the request")
            return
        except Exception as e:
            logger.error(f"Failed to parse SOCKS5 request: {e}")
            self._send_error_reply(generate_failed_reply(AddressTypeCodes.IPv4, reply_code_for(e)))
            return

        self.connection.settimeout(None)  # Clears the handshake deadline

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

        except Exception as e:
            if self._reply_sent:
                logger.error(f"Error after replying to the {dst_request.address} request: {e}")
                return
            reply_code = reply_code_for(e)
            logger.error(f"{reply_code.name} for {dst_request.address}: {e}")
            self._send_error_reply(generate_failed_reply(atyp, reply_code))

    def handle_connect(self, dst_address: DetailedAddress) -> None:
        """
        Handles CONNECT command.
        """
        # Allocate port for TCP relay
        tcp_relay = TCPRelay(self.connection, dst_address)

        # Send reply with bind address and port
        self._send_success_reply(dst_address.address_type, tcp_relay.get_proxy_address())

        # Start TCP relay
        tcp_relay.listen_and_relay()

    def handle_udp_associate(self, dst_address: DetailedAddress) -> None:
        """
        Handles UDP ASSOCIATE command.
        """
        # Allocate port for UDP relay
        udp_relay = UDPRelay(self.connection, dst_address)

        # Send reply with allocated port and server IP
        self._send_success_reply(dst_address.address_type, udp_relay.get_proxy_address())

        # Start UDP relay
        udp_relay.listen_and_relay()

    def handle_bind(self, address: DetailedAddress) -> None:
        """
        Handles BIND command.
        """
        logger.error("BIND command not supported")
        self._send_error_reply(generate_command_not_supported_reply(address.address_type))

    def _send_success_reply(self, address_type: AddressTypeCodes, bind_address: BindAddress) -> None:
        """
        Sends the success reply to the client. A failed send propagates.
        """
        # Set before sending, so a partially written reply is never followed by a failure reply
        self._reply_sent = True
        self.connection.sendall(generate_succeeded_reply(address_type, *bind_address))

    def _send_error_reply(self, reply: bytes) -> None:
        """
        Sends an error reply to the client unless a reply was already sent, swallowing OSError on send failure.
        """
        if self._reply_sent:
            logger.debug("Suppressed a second SOCKS reply")
            return
        self._reply_sent = True
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
