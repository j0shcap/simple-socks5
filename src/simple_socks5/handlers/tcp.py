import hmac
import socket
import struct

from ..constants import SOCKS_VERSION, MethodCodes, auth_required, credentials
from ..errors import is_routine_disconnect
from ..exceptions import InvalidVersionError
from ..logger import get_logger
from ..utils import generate_connection_method_response
from .base import BaseHandler

logger = get_logger(__name__)


class TCPHandler(BaseHandler):
    connection: socket.socket

    def handle_request(self) -> bool:
        """
        Procedure for TCP-based clients per RFC 1928.

        Handles authentication negotation.

        Client request:
            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     | 1 to 255 |
            +----+----------+----------+
        Server response:
            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+

        Methods:
            o  X'00' NO AUTHENTICATION REQUIRED
            o  X'01' GSSAPI
            o  X'02' USERNAME/PASSWORD
            o  X'03' to X'7F' IANA ASSIGNED
            o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
            o  X'FF' NO ACCEPTABLE METHODS

        Returns:
            bool: True if the handshake was successful, False otherwise.
        """
        try:
            # Parses client VER, NMETHODS, METHODS
            header = self._recv_exact(2)

            version, nmethods = struct.unpack("!BB", header)

            if version != SOCKS_VERSION:
                raise InvalidVersionError(version)

            methods = self._recv_exact(nmethods)

            # Handles negotiation for authentication method
            negotiated_authentication: MethodCodes = self._negotiate_authentication_method(methods)

            # Handles server response
            self.connection.sendall(generate_connection_method_response(negotiated_authentication))

        except TimeoutError:
            logger.warning("Handshake timed out")
            return False
        except OSError as e:
            _log_socket_error("handshake", e)
            return False

        # Handles authentication; each method catches its own socket errors
        if negotiated_authentication == MethodCodes.NO_AUTHENTICATION_REQUIRED:
            return True
        if negotiated_authentication == MethodCodes.USERNAME_PASSWORD:
            return self._handle_username_password_auth()
        if negotiated_authentication == MethodCodes.GSSAPI:
            # Not implemented yet
            return self._handle_gssapi_auth()
        # The client is told with X'FF'. DEBUG, because a healthcheck probe offering only X'00' lands here.
        logger.debug("No acceptable authentication methods")
        return False

    def _negotiate_authentication_method(self, methods: bytes) -> MethodCodes:
        """
        Finds the a mutually supported authentication method.
        USERNAME/PASSWORD is the preferred method.

        Args:
            methods (bytes): The methods sent by the client.

        Returns:
            MethodCodes: The negotiated authentication method.
        """
        client_methods = set(methods)

        supported_methods = {MethodCodes.USERNAME_PASSWORD.value}
        if not auth_required():
            supported_methods.add(MethodCodes.NO_AUTHENTICATION_REQUIRED.value)

        mutual_method = client_methods.intersection(supported_methods)

        if MethodCodes.USERNAME_PASSWORD.value in mutual_method:
            return MethodCodes.USERNAME_PASSWORD
        # TODO: Implement GSS-API authentication
        if MethodCodes.NO_AUTHENTICATION_REQUIRED.value in mutual_method:
            return MethodCodes.NO_AUTHENTICATION_REQUIRED
        # No acceptable methods
        return MethodCodes.NO_ACCEPTABLE_METHODS

    def _handle_username_password_auth(self) -> bool:
        """
        Handles USERNAME/PASSWORD authentication method.

        Client request:
            +----+------+----------+------+----------+
            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            +----+------+----------+------+----------+
            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            +----+------+----------+------+----------+
        Server response:
            +----+--------+
            |VER | STATUS |
            +----+--------+
            | 1  |   1    |
            +----+--------+

        Fields
            o VER - subnegotiation protocol version (1 byte): X'01'
            o ULEN - username length (1 byte)
            o UNAME - username
            o PLEN - password length (1 byte)
            o PASSWD - password
            o STATUS - status code (1 byte): X'00' for success, X'01' for failure
                - Connection must be closed if status is not X'00'

        UNAME and PASSWD are compared as raw octets against the UTF-8 encoded configured credentials.
        """
        try:
            # Receive and verify the version
            version = self._recv_exact(1)
            if version != b"\x01":
                logger.error("Incorrect subnegotiation version: %s", version)
                self.connection.sendall(b"\x01\x01")
                return False

            # The whole frame is read even when a length is 0: closing with unread bytes would send an RST
            username = self._recv_exact(self._recv_exact(1)[0])
            password = self._recv_exact(self._recv_exact(1)[0])

            expected = credentials()
            authenticated = self._credentials_match(username, password, expected)
            if authenticated:
                logger.info("Authenticated user: %s", expected[0].decode("utf-8", "backslashreplace"))
                self.connection.sendall(b"\x01\x00")  # version 1, status 0 (success)
            else:
                logger.warning("Authentication failed for client %s", self._peer_ip())
                self.connection.sendall(b"\x01\x01")  # version 1, status 1 (failure)
        except TimeoutError:
            logger.warning("Handshake timed out during authentication")
            return False
        except OSError as e:
            _log_socket_error("username/password authentication", e)
            return False
        return authenticated

    @staticmethod
    def _credentials_match(username: bytes, password: bytes, expected: tuple[bytes, bytes]) -> bool:
        """
        Compares in constant time and never short-circuits, so the timing reveals neither which field
        was wrong nor how much of it matched. RFC 1929 fields are 1 to 255 octets, so empty never matches.
        """
        expected_username, expected_password = expected
        username_ok = hmac.compare_digest(username, expected_username)
        password_ok = hmac.compare_digest(password, expected_password)
        return bool(username) & bool(password) & username_ok & password_ok

    def _peer_ip(self) -> str:
        try:
            return self.connection.getpeername()[0]
        except OSError:
            return "unknown"  # The client has already disconnected

    def _handle_gssapi_auth(self) -> bool:
        """
        GSS-API method implementation per RFC 1961.
        """
        logger.warning("GSS-API authentication method not implemented")
        return False


def _log_socket_error(stage: str, e: OSError) -> None:
    if is_routine_disconnect(e):
        logger.debug("Client disconnected during %s: %s", stage, e)
    else:
        logger.error("Socket error during %s: %s", stage, e, exc_info=e)
