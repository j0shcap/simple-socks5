#!/usr/bin/env bash
# Usage: smoke-test.sh IMAGE [CMD...]
# Runs IMAGE (optionally with CMD), waits for the SOCKS5 server and fetches a file through it.
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

nonce=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
printf '%s' "$nonce" > "$tmp/ok.txt"
python3 -m http.server "$http_port" --bind 0.0.0.0 --directory "$tmp" &
http_pid=$!
disown "$http_pid"
wait_for "the HTTP server on port $http_port" http_ready

# The target is the Docker bridge gateway (a private address), not loopback, so the test still
# holds once the proxy refuses loopback destinations.
container=$(docker run -d -p 127.0.0.1::1080 --add-host host.docker.internal:host-gateway "$image" "$@")
wait_for "the SOCKS5 server" socks_ready

body=$(curl -fsS --max-time 10 --socks5-hostname "127.0.0.1:$socks_port" \
    "http://host.docker.internal:$http_port/ok.txt")
if [[ $body != "$nonce" ]]; then
    echo "Expected '$nonce' through the proxy, got '$body'" >&2
    exit 1
fi
echo "SMOKE TEST PASSED"
