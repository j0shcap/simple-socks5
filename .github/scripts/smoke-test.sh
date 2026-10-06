#!/usr/bin/env bash
# Usage: smoke-test.sh IMAGE [CMD...]
# Runs IMAGE (optionally with CMD), waits for the SOCKS5 server and fetches a file through it, then checks
# that `docker stop` exits 0 in under 6s, both with a relayed connection open and with none.
set -euo pipefail

if (( $# < 1 )); then
    echo "Usage: $0 IMAGE [CMD...]" >&2
    exit 2
fi
image=$1
shift

http_port=18080
tmp=$(mktemp -d)
container=
http_pid=
socks_port=

cleanup() {
    local status=$?
    if [[ -n $container ]]; then
        if (( status != 0 )); then
            echo "--- container logs ---" >&2
            docker logs "$container" >&2
        fi
        docker rm -f "$container" >/dev/null
    fi
    if [[ -n $http_pid ]]; then
        kill "$http_pid"
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

wait_for() {
    local description=$1
    shift
    for _ in $(seq 60); do
        if "$@"; then
            return 0
        fi
        sleep 0.5
    done
    echo "Timed out after 30s waiting for $description" >&2
    exit 1
}

http_ready() {
    curl -fs -o /dev/null "http://127.0.0.1:$http_port/ok.txt"
}

# A bare TCP connect isn't enough: Docker's port proxy accepts on the published port even when
# nothing listens inside the container, so require a real SOCKS5 method-selection reply.
socks_ready() {
    if [[ $(docker inspect -f '{{.State.Running}}' "$container") != true ]]; then
        echo "Container exited before accepting SOCKS5 connections" >&2
        exit 1
    fi
    local socks_address
    socks_address=$(docker port "$container" 1080/tcp)
    socks_port=${socks_address##*:}
    python3 - "$socks_port" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1) as sock:
        sock.sendall(b"\x05\x01\x00")
        sys.exit(sock.recv(2) != b"\x05\x00")
except OSError:
    sys.exit(1)
PY
}

start_container() {
    container=$(docker run -d -p 127.0.0.1::1080 --add-host host.docker.internal:host-gateway "$image" "$@")
    wait_for "the SOCKS5 server" socks_ready
}

assert_graceful_stop() {
    local label=$1 start elapsed exit_code
    start=$(python3 -c 'import time; print(time.time())')
    docker stop -t 10 "$container" >/dev/null
    elapsed=$(python3 -c 'import sys, time; print(f"{time.time() - float(sys.argv[1]):.2f}")' "$start")
    exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$container")
    echo "docker stop ($label): exit code $exit_code after ${elapsed}s"
    if [[ $exit_code != 0 ]] || ! python3 -c 'import sys; sys.exit(float(sys.argv[1]) >= 6)' "$elapsed"; then
        echo "Expected docker stop ($label) to exit 0 in under 6s" >&2
        exit 1
    fi
}

# Opens a SOCKS5 CONNECT to the HTTP server and holds it without sending a request, then reports whether
# the proxy closed it (EOF) or not (TIMEOUT).
hold_connection() {
    python3 - "$socks_port" "$http_port" "$tmp/held" <<'PY'
import socket
import sys


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk, "connection closed during the SOCKS5 handshake"
        data += chunk
    return data


socks_port, http_port, result_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
host = b"host.docker.internal"
with socket.create_connection(("127.0.0.1", socks_port), timeout=15) as sock:
    sock.sendall(b"\x05\x01\x00")
    assert recv_exact(sock, 2) == b"\x05\x00"
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + http_port.to_bytes(2, "big"))
    version, reply, _, address_type = recv_exact(sock, 4)
    assert (version, reply) == (5, 0), f"CONNECT failed with reply {reply}"
    address_length = {1: 4, 4: 16}.get(address_type) or recv_exact(sock, 1)[0]
    recv_exact(sock, address_length + 2)  # Bound address and port
    print("READY", flush=True)
    try:
        result = "EOF" if sock.recv(1024) == b"" else "DATA"
    except socket.timeout:
        result = "TIMEOUT"
    except ConnectionResetError:
        result = "RESET"
with open(result_path, "w") as f:
    f.write(result)
PY
}

held_ready() {
    grep -q READY "$tmp/holder.out"
}

nonce=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
printf '%s' "$nonce" > "$tmp/ok.txt"
python3 -m http.server "$http_port" --bind 0.0.0.0 --directory "$tmp" &
http_pid=$!
disown "$http_pid"
wait_for "the HTTP server on port $http_port" http_ready

# The target is the Docker bridge gateway (a private address), not loopback, so the test still
# holds once the proxy refuses loopback destinations.
start_container "$@"

body=$(curl -fsS --max-time 10 --socks5-hostname "127.0.0.1:$socks_port" \
    "http://host.docker.internal:$http_port/ok.txt")
if [[ $body != "$nonce" ]]; then
    echo "Expected '$nonce' through the proxy, got '$body'" >&2
    exit 1
fi

hold_connection > "$tmp/holder.out" &
holder_pid=$!
wait_for "the held connection" held_ready
assert_graceful_stop "active connection"
wait "$holder_pid"
if [[ $(cat "$tmp/held") != EOF ]]; then
    echo "Expected the held connection to be closed (EOF), got '$(cat "$tmp/held")'" >&2
    exit 1
fi

docker rm "$container" >/dev/null
container=
start_container "$@"
assert_graceful_stop "idle"

echo "SMOKE TEST PASSED"
