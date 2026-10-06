from tests.e2e import socks_client as sc
from tests.e2e.conftest import E2E_PASSWORD, E2E_USERNAME


def test_no_acceptable_methods(proxy):
    with proxy.connect() as sock:
        sock.sendall(sc.build_greeting([sc.METHOD_GSSAPI]))

        assert sc.recv_exact(sock, 2) == b"\x05\xff"
        sc.assert_closed(sock)


def test_auth_required_rejects_no_auth(auth_proxy):
    with auth_proxy.connect() as sock:
        sock.sendall(sc.build_greeting([sc.METHOD_NO_AUTH]))

        assert sc.recv_exact(sock, 2) == b"\x05\xff"
        sc.assert_closed(sock)


def test_auth_preferred_when_offered(auth_proxy):
    with auth_proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH, sc.METHOD_USERPASS]) == sc.METHOD_USERPASS


def test_auth_success_then_connect(auth_proxy, echo_origin):
    credentials = (E2E_USERNAME, E2E_PASSWORD)
    with sc.open_tunnel(auth_proxy.address, "127.0.0.1", echo_origin.port, credentials=credentials) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"


def test_auth_wrong_password(auth_proxy):
    with auth_proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS

        assert sc.authenticate(sock, E2E_USERNAME, "wrong") == sc.AUTH_FAILURE
        sc.assert_closed(sock)


def test_auth_wrong_subnegotiation_version(auth_proxy):
    with auth_proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS
        # Only VER: the server rejects after one byte, and unread bytes would turn its close into an RST.
        sock.sendall(b"\x05")

        assert sc.recv_exact(sock, 2) == b"\x01\x01"
        sc.assert_closed(sock)
