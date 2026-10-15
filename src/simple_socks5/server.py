import dataclasses
import logging
import socket
import sys
import threading
import time
from socketserver import BaseRequestHandler, StreamRequestHandler, TCPServer, ThreadingMixIn
from typing import Final, TypeAlias

from .constants import (
    AUTH_FAILED_WARNING_INTERVAL,
    CONNECTION_LIMIT_WARNING_INTERVAL,
    HANDSHAKE_TIMEOUT_WARNING_INTERVAL,
    POLICY_DENIED_WARNING_INTERVAL,
    AddressTypeCodes,
    CommandCodes,
    ReplyCodes,
    handshake_timeout,
    max_connections,
)
from .errors import is_routine_disconnect, reply_code_for
from .exceptions import (
    AuthenticationFailedError,
    HandshakeTimeoutError,
    InvalidRequestError,
    InvalidVersionError,
    PolicyDeniedError,
)
from .handlers import TCPHandler
from .logger import get_logger
from .models import BindAddress, DetailedAddress, Request, SocketAddress
from .relays import TCPRelay, UDPRelay
from .resolver import resolve
from .utils import (
    WarningRateLimiter,
    format_connection_established,
    generate_failed_reply,
    generate_succeeded_reply,
    map_address_family_to_enum,
)

logger = get_logger(__name__)

# Failures with a known cause: logged without a traceback. Anything else is a bug and gets one.
_EXPECTED_ERRORS: Final = (OSError, InvalidRequestError, InvalidVersionError)

# What socketserver passes as a request: a connected socket for a TCP server, (data, socket) for a UDP one
SocketServerRequest: TypeAlias = socket.socket | tuple[bytes, socket.socket]


def _log_failure(level: int, msg: str, *args: object, exc: BaseException) -> None:
    """
    Logs an expected failure at level without a traceback, and anything else as an ERROR with one.
    """
    if isinstance(exc, _EXPECTED_ERRORS):
        logger.log(level, msg, *args)
    else:
        logger.error(msg, *args, exc_info=exc)


def _udp_family_address(dst: DetailedAddress) -> DetailedAddress:
    """
    Returns dst with the address type the UDP relay socket is created for. A hostname gets its first address's
    family, or IPv4 if it doesn't resolve.
    """
    if dst.address_type != AddressTypeCodes.DOMAIN_NAME:
        return dst
    try:
        first = resolve(dst.name, dst.port)[0]
    except OSError:
        return dataclasses.replace(dst, address_type=AddressTypeCodes.IPv4)
    return dataclasses.replace(dst, ip=first.ip, address_type=map_address_family_to_enum(first.family))


def _tcp_socket(request: SocketServerRequest) -> socket.socket:
    if isinstance(request, socket.socket):
        return request
    raise TypeError(f"expected a connected TCP socket, got {type(request).__name__}")


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    """
    A threading version of a TCP server with a connection limit.

    https://docs.python.org/3/library/socketserver.html#socketserver.ThreadingMixIn
    """

    daemon_threads = True
    # socketserver's default backlog of 5 overflows when many clients connect at once, and Linux then
    # retransmits the dropped handshakes after 1 s, 3 s, ..., delaying both their accept and their rejection
    request_queue_size = socket.SOMAXCONN

    def process_request(self, request: SocketServerRequest, client_address: SocketAddress) -> None:
        sock = _tcp_socket(request)
        if self._connection_semaphore.acquire(blocking=False):
            # Tracked on the serving thread, not the handler thread, so a drain that starts once serve_forever()
            # returns can't miss a request whose handler thread hasn't run yet.
            self._track_request(sock)
            try:
                super().process_request(sock, client_address)
            except Exception:
                self._untrack_request(sock)
                self._connection_semaphore.release()
                raise
        else:
            self._reject_request(sock)

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseRequestHandler],
        bind_and_activate: bool = True,
    ) -> None:
        # Read before binding, so an invalid value can't leave a listening socket behind
        self.max_connections = max_connections()
        self._connection_semaphore = threading.BoundedSemaphore(self.max_connections)
        self._limit_warnings = WarningRateLimiter(CONNECTION_LIMIT_WARNING_INTERVAL)
        self._policy_warnings = WarningRateLimiter(POLICY_DENIED_WARNING_INTERVAL)
        self._timeout_warnings = WarningRateLimiter(HANDSHAKE_TIMEOUT_WARNING_INTERVAL)
        self._auth_warnings = WarningRateLimiter(AUTH_FAILED_WARNING_INTERVAL)
        super().__init__(server_address, handler_class, bind_and_activate)
        # Daemon request threads aren't tracked by ThreadingMixIn, so track their sockets for shutdown.
        self._active_requests: set[socket.socket] = set()
        self._active_cond = threading.Condition()

    def _reject_request(self, request: socket.socket) -> None:
        """
        Closes a connection over the limit, warning at most once per CONNECTION_LIMIT_WARNING_INTERVAL.
        """
        rejected = self._limit_warnings.hit()
        if rejected is not None:
            logger.warning(
                "Connection limit of %s reached: rejected %s connection(s) since the last warning",
                self.max_connections,
                rejected,
            )
        self.shutdown_request(request)

    def log_policy_denial(self, client_ip: str, dst: DetailedAddress) -> None:
        """
        Logs a destination the policy denied, as a WARNING at most once per POLICY_DENIED_WARNING_INTERVAL and
        otherwise at DEBUG, so a scanning client can't flood the log.
        """
        denied = self._policy_warnings.hit()
        if denied is None:
            logger.debug("Denied %s -> %s", client_ip, dst)
            return
        message = (
            f"Denied {client_ip} -> {dst}: loopback, link-local and unspecified destinations are blocked; "
            "set SOCKS5_ALLOW_LOOPBACK=true to allow them"
        )
        if denied > 1:
            message += f" ({denied - 1} more denied since the last warning)"
        logger.warning(message)

    def log_handshake_timeout(self, client_ip: str, stage: str) -> None:
        """
        Logs a client that didn't finish its handshake in time, as a WARNING at most once per
        HANDSHAKE_TIMEOUT_WARNING_INTERVAL and otherwise at DEBUG, so idle connections can't flood the log.
        """
        timed_out = self._timeout_warnings.hit()
        if timed_out is None:
            logger.debug("Handshake timed out for %s %s", client_ip, stage)
            return
        logger.warning("%s handshake(s) timed out since the last warning (latest: %s %s)", timed_out, client_ip, stage)

    def log_auth_failure(self, client_ip: str) -> None:
        """
        Logs a client that sent the wrong username or password, as a WARNING at most once per
        AUTH_FAILED_WARNING_INTERVAL and otherwise at DEBUG, so a brute-force attempt can't flood the log.
        """
        failures = self._auth_warnings.hit()
        if failures is None:
            logger.debug("Authentication failed for client %s", client_ip)
            return
        logger.warning(
            "Authentication failed for client %s (%s failure(s) since the last warning)", client_ip, failures
        )

    def handle_error(self, request: SocketServerRequest, client_address: SocketAddress) -> None:  # noqa: ARG002 - keeps socketserver.BaseServer's signature
        """
        Logs an exception that escaped a handler. socketserver's default prints the traceback to stderr, ignoring -L.
        """
        e = sys.exc_info()[1]  # None only if called outside an except block, which socketserver never does
        if e is not None and is_routine_disconnect(e):
            logger.debug("Client %s disconnected: %s", client_address[0], e)
        elif isinstance(e, _EXPECTED_ERRORS):
            logger.debug("Error serving %s: %s", client_address[0], e)
        else:
            logger.error("Unhandled error serving %s", client_address[0], exc_info=e)

    def process_request_thread(self, request: SocketServerRequest, client_address: SocketAddress) -> None:
        sock = _tcp_socket(request)
        try:
            super().process_request_thread(sock, client_address)
        finally:
            self._untrack_request(sock)
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

    connection: socket.socket
    server: ThreadingTCPServer
    # Set as soon as a reply is attempted: the client must never receive a second one
    _reply_sent: bool = False

    def handle(self) -> None:
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

        try:
            handshake_ok = request_handler.handle_request()
        except HandshakeTimeoutError:
            self.server.log_handshake_timeout(self.client_address[0], "during the greeting or authentication")
            handshake_ok = False
        except AuthenticationFailedError:
            self.server.log_auth_failure(self.client_address[0])
            handshake_ok = False
        if not handshake_ok:
            logger.debug("Handshake failed")
            self.server.shutdown_request(self.request)
            return

        dst_request = self._read_request(request_handler)
        if dst_request is None:
            return

        self.connection.settimeout(None)  # Clears the handshake deadline

        peer: SocketAddress = self.connection.getpeername()
        # Not client_address: socketserver's (host, port) tuple stays as it is
        self.client = DetailedAddress(
            ip=peer[0],
            port=peer[1],
            name="Client",
            address_type=dst_request.address.address_type,
        )
        if dst_request.command != CommandCodes.CONNECT.value:
            # A CONNECT is logged once it has connected, with the address it reached
            self._log_connection(dst_request.address)
        self._dispatch(dst_request)

    def _read_request(self, request_handler: TCPHandler) -> Request | None:
        """
        Returns the client's request, or None once the failure is logged and, unless the client stalled, replied to.
        """
        try:
            return request_handler.parse_request()
        except HandshakeTimeoutError:
            # The client never finished its request, so it gets no reply
            self.server.log_handshake_timeout(self.client_address[0], "waiting for the request")
        except Exception as e:  # noqa: BLE001 - _log_failure gives anything unexpected a traceback
            if is_routine_disconnect(e):
                logger.debug("Client disconnected before finishing its request: %s", e)
            else:
                _log_failure(logging.DEBUG, "Failed to parse SOCKS5 request: %s", e, exc=e)
            self._send_error_reply(generate_failed_reply(AddressTypeCodes.IPv4, reply_code_for(e)))
        return None

    def _dispatch(self, dst_request: Request) -> None:
        """
        Runs the requested command. A failure gets an error reply, unless a reply was already sent.
        """
        atyp = dst_request.address.address_type
        try:
            if dst_request.command == CommandCodes.CONNECT.value:
                self.handle_connect(dst_request.address)

            elif dst_request.command == CommandCodes.BIND.value:
                self.handle_bind(dst_request.address)

            elif dst_request.command == CommandCodes.UDP_ASSOCIATE.value:
                self.handle_udp_associate(dst_request.address)

            else:
                logger.debug("Unsupported command 0x%02x", dst_request.command)
                self._send_error_reply(generate_failed_reply(atyp, ReplyCodes.COMMAND_NOT_SUPPORTED))

        except Exception as e:  # noqa: BLE001 - _log_failure gives anything unexpected a traceback
            if self._reply_sent:
                if is_routine_disconnect(e):
                    logger.debug("Client disconnected after the reply to the %s request: %s", dst_request.address, e)
                else:
                    _log_failure(
                        logging.DEBUG, "Error after replying to the %s request: %s", dst_request.address, e, exc=e
                    )
                return
            reply_code = reply_code_for(e)
            if isinstance(e, PolicyDeniedError):
                self.server.log_policy_denial(self.client.ip, dst_request.address)
            else:
                _log_failure(logging.INFO, "%s for %s: %s", reply_code.name, dst_request.address, e, exc=e)
            self._send_error_reply(generate_failed_reply(atyp, reply_code))

    def handle_connect(self, dst_address: DetailedAddress) -> None:
        """
        Handles CONNECT command.
        """
        # Connects to the first of dst_address's addresses that accepts
        tcp_relay = TCPRelay(self.connection, dst_address)
        self._log_connection(tcp_relay.dst_address)

        # Send reply with bind address and port
        self._send_success_reply(tcp_relay.dst_address.address_type, tcp_relay.get_proxy_address())

        # Start TCP relay
        tcp_relay.listen_and_relay()

    def handle_udp_associate(self, dst_address: DetailedAddress) -> None:
        """
        Handles UDP ASSOCIATE command.
        """
        # Allocate port for UDP relay
        relay_address = _udp_family_address(dst_address)
        udp_relay = UDPRelay(self.connection, relay_address)

        # Send reply with allocated port and server IP
        self._send_success_reply(relay_address.address_type, udp_relay.get_proxy_address())

        # Start UDP relay
        udp_relay.listen_and_relay()

    def handle_bind(self, address: DetailedAddress) -> None:
        """
        Handles BIND command.
        """
        logger.debug("BIND command not supported")
        self._send_error_reply(generate_failed_reply(address.address_type, ReplyCodes.COMMAND_NOT_SUPPORTED))

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
            if is_routine_disconnect(e):
                logger.debug("Client disconnected before the reply: %s", e)
            else:
                logger.debug("Error sending reply: %s", e)

    def finish(self) -> None:
        """
        Called after handle() to perform any clean-up actions required.

        Ensures proper closure of each socket.
        """
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # Handle already closed socket
        finally:
            self.connection.close()

    def _log_connection(self, dst_address: DetailedAddress) -> None:
        logger.info(format_connection_established(self.client, dst_address))
