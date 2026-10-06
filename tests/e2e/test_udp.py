import socket

from tests.e2e import socks_client as sc


def test_udp_associate_echo(monkeypatch, proxy, udp_echo_origin):
    # F8 workaround; remove in slice 8. The relay otherwise outlives the control connection by 120 s.
    monkeypatch.setattr("src.relays.udp_relay.UDP_RECV_TIMEOUT", 0.5)

    with proxy.connect() as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(sc.TIMEOUT)
        udp.bind(("127.0.0.1", 0))
        assert sc.greet(control, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(control, sc.CMD_UDP_ASSOCIATE, sc.ATYP_IPV4, "127.0.0.1", 0)
        reply = sc.read_reply(control)
        assert reply.rep == sc.REP_SUCCEEDED

        # BND.ADDR is the unspecified address today, so send to the proxy's host.
        relay_address = (proxy.address[0], reply.bnd_port)
        udp.sendto(sc.build_udp_header(sc.ATYP_IPV4, "127.0.0.1", udp_echo_origin.port) + b"ping", relay_address)
        response, _ = udp.recvfrom(65536)

    assert sc.parse_udp_header(response) == sc.UDPHeader(
        rsv=0, frag=0, atyp=sc.ATYP_IPV4, addr="127.0.0.1", port=udp_echo_origin.port, data=b"ping"
    )
