import logging

import pytest

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


LONG_USERNAME = "u" * 255
LONG_PASSWORD = "p" * 255

# (case, submitted username, submitted password); the proxy is configured with E2E_USERNAME / E2E_PASSWORD
REJECTED = [
    ("wrong user", b"nope", E2E_PASSWORD.encode()),
    ("wrong password", E2E_USERNAME.encode(), b"nope"),
    ("both wrong", b"nope", b"nope"),
    ("empty user", b"", E2E_PASSWORD.encode()),
    ("empty password", E2E_USERNAME.encode(), b""),
    ("non-UTF-8 user", b"\xff\xfe", E2E_PASSWORD.encode()),
    ("non-UTF-8 password", E2E_USERNAME.encode(), b"\xff\xfe"),
]


def _assert_tunnel_works(sock, echo_origin):
    sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", echo_origin.port)
    assert sc.read_reply(sock).rep == sc.REP_SUCCEEDED
    sock.sendall(b"ping")
    assert sc.recv_exact(sock, 4) == b"ping"


def _log_text(caplog) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


@pytest.mark.parametrize("auth_required", [True, False], ids=["auth-required", "auth-optional"])
@pytest.mark.parametrize("case, username, password", REJECTED, ids=[case for case, _, _ in REJECTED])
def test_auth_rejected(make_proxy, caplog, capsys, auth_required, case, username, password):
    caplog.set_level(logging.DEBUG)
    proxy = make_proxy(auth_required=auth_required)
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS

        assert sc.authenticate(sock, username, password) == sc.AUTH_FAILURE
        sc.assert_closed(sock)

    # socketserver prints an unhandled handler error before it closes the connection, so it is in by now
    assert "Traceback" not in capsys.readouterr().err
    assert not [record for record in caplog.records if record.exc_info]
    logs = _log_text(caplog)
    assert any(r.levelname == "WARNING" and "127.0.0.1" in r.getMessage() for r in caplog.records)
    for secret in {username, password, E2E_PASSWORD.encode()} - {b""}:
        assert secret.decode("utf-8", "backslashreplace") not in logs
        assert repr(secret) not in logs


@pytest.mark.parametrize("auth_required", [True, False], ids=["auth-required", "auth-optional"])
def test_auth_correct_credentials(make_proxy, caplog, echo_origin, auth_required):
    caplog.set_level(logging.DEBUG)
    proxy = make_proxy(auth_required=auth_required)
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS

        assert sc.authenticate(sock, E2E_USERNAME, E2E_PASSWORD) == sc.AUTH_SUCCESS
        _assert_tunnel_works(sock, echo_origin)
    assert E2E_PASSWORD not in _log_text(caplog)


@pytest.mark.parametrize("auth_required", [True, False], ids=["auth-required", "auth-optional"])
def test_auth_255_byte_credentials(make_proxy, monkeypatch, echo_origin, auth_required):
    proxy = make_proxy(auth_required=auth_required)
    monkeypatch.setenv("SOCKS5_USERNAME", LONG_USERNAME)
    monkeypatch.setenv("SOCKS5_PASSWORD", LONG_PASSWORD)
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS

        assert sc.authenticate(sock, LONG_USERNAME, LONG_PASSWORD) == sc.AUTH_SUCCESS
        _assert_tunnel_works(sock, echo_origin)


def test_utf8_password_authenticates(auth_proxy, monkeypatch, echo_origin):
    monkeypatch.setenv("SOCKS5_PASSWORD", "pässwörd")
    credentials = (E2E_USERNAME, "pässwörd".encode())
    with sc.open_tunnel(auth_proxy.address, "127.0.0.1", echo_origin.port, credentials=credentials) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"


def test_password_change_after_start_honoured(auth_proxy, monkeypatch, echo_origin):
    monkeypatch.setenv("SOCKS5_PASSWORD", "rotated")
    with auth_proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS
        assert sc.authenticate(sock, E2E_USERNAME, E2E_PASSWORD) == sc.AUTH_FAILURE
        sc.assert_closed(sock)

    credentials = (E2E_USERNAME, "rotated")
    with sc.open_tunnel(auth_proxy.address, "127.0.0.1", echo_origin.port, credentials=credentials) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"
