# Simple SOCKS5 Proxy Server

[![CI](https://github.com/j0shcap/simple-socks5/actions/workflows/ci.yml/badge.svg)](https://github.com/j0shcap/simple-socks5/actions/workflows/ci.yml)

A SOCKS Protocol Version 5 proxy server written in Python. Implements [RFC 1928](https://www.ietf.org/rfc/rfc1928.txt) (SOCKS5) and [RFC 1929](https://www.ietf.org/rfc/rfc1929.txt) (username/password authentication).

## Features

- **TCP & UDP**: Supports CONNECT and UDP ASSOCIATE commands
- **Authentication**: Optional username/password authentication (RFC 1929)
- **IPv4 & IPv6**: Full support for both address families
- **Concurrent**: Thread-per-connection
- **Docker**: Multi-architecture images on [Docker Hub](https://hub.docker.com/r/jcaponigro20/simple-socks5)

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Quick Start

Run with authentication, published only on localhost:

```bash
export SOCKS5_USERNAME=proxyuser
export SOCKS5_PASSWORD="$(openssl rand -hex 16)"   # or choose your own
echo "Password: $SOCKS5_PASSWORD"

docker run -p 127.0.0.1:1080:1080 \
  -e SOCKS5_USERNAME -e SOCKS5_PASSWORD -e SOCKS5_AUTH_REQUIRED=true \
  jcaponigro20/simple-socks5

# In another shell with the same variables exported:
curl -x "socks5h://$SOCKS5_USERNAME:$SOCKS5_PASSWORD@127.0.0.1:1080" https://example.com
```

Without Docker (binds to `localhost` by default):

```bash
SOCKS5_AUTH_REQUIRED=true python3 app.py -P 1080
```

### No authentication (trusted networks only)

Anyone who can reach the port can use the proxy. Only do this on a network you trust:

```bash
docker run -p 127.0.0.1:1080:1080 -e SOCKS5_AUTH_REQUIRED=false jcaponigro20/simple-socks5
```

Setting `SOCKS5_AUTH_REQUIRED=false` explicitly acknowledges the choice: the open-proxy warning banner is replaced by a single INFO line. The default-credentials warning still appears unless you set your own `SOCKS5_USERNAME`/`SOCKS5_PASSWORD`. See [Security](#security).

## Usage

```bash
python3 app.py [--host HOST | -H HOST] [--port PORT | -P PORT] [--logging-level LEVEL | -L LEVEL]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-H`, `--host` | `localhost` | Bind address. `0.0.0.0` or `::` expose the proxy to the network; see [Security](#security). |
| `-P`, `--port` | `1080` | Bind port. |
| `-L`, `--logging-level` | `$LOGGING_LEVEL`, else `debug` | `disabled`, `debug`, `info`, `warning`, `error`, `critical`. Startup warnings are hidden at `error`, `critical` and `disabled`. |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SOCKS5_USERNAME` | `myusername` | Username for RFC 1929 authentication. |
| `SOCKS5_PASSWORD` | `mypassword` | Password for RFC 1929 authentication. |
| `SOCKS5_AUTH_REQUIRED` | `false` | Set to `true` to require authentication. |
| `LOGGING_LEVEL` | `debug` | Logging level used when `-L` isn't given. Same choices as `-L`. |

## Docker

The examples below forward `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` from your shell (export them as in [Quick Start](#quick-start)).

```bash
# Default (logging enabled)
docker run -p 127.0.0.1:1080:1080 -e SOCKS5_AUTH_REQUIRED=true \
  -e SOCKS5_USERNAME -e SOCKS5_PASSWORD jcaponigro20/simple-socks5

# Logging disabled (also suppresses the startup warnings)
docker run -p 127.0.0.1:1080:1080 -e SOCKS5_AUTH_REQUIRED=true \
  -e SOCKS5_USERNAME -e SOCKS5_PASSWORD jcaponigro20/simple-socks5:logging-disabled

# Custom build
docker build --build-arg LOGGING_LEVEL=info -t my-socks5 .
```

The container always listens on `0.0.0.0` inside Docker; the `-p` flag decides which host interfaces the port is published on.

## Authentication

Authentication is optional and off by default. To require it, set credentials and `SOCKS5_AUTH_REQUIRED=true`:

```bash
export SOCKS5_USERNAME=admin
export SOCKS5_PASSWORD="$(openssl rand -hex 16)"
export SOCKS5_AUTH_REQUIRED=true
python3 app.py -H 0.0.0.0 -P 1080
```

The default credentials (`myusername`/`mypassword`) are public; always set your own.

## Testing

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pytest pytest-cov flake8
pytest --cov=src --cov-fail-under=85
flake8 src/ tests/
```

## RFC Compliance

### Implemented

- SOCKS5 handshake and connection negotiation
- CONNECT command (TCP proxying)
- UDP ASSOCIATE command (UDP relaying)
- Username/password authentication (RFC 1929)
- IPv4, IPv6, and domain name address types
- All standard reply codes (success, server failure, connection refused, host unreachable, etc.)

### Not Implemented

- BIND command (recognized but returns "command not supported")
- UDP fragmentation (fragmented datagrams are dropped)
- GSSAPI authentication (RFC 1961)

## Security

### Open-proxy risk

Authentication is optional and off by default. With authentication off and the server listening on a non-loopback address, anyone who can reach the port can relay traffic through the proxy, and that traffic appears to come from your IP address. The Docker image listens on `0.0.0.0`, so a plain `docker run -p 1080:1080 jcaponigro20/simple-socks5` on a public host is an open proxy.

To require authentication, set all three variables (see [Quick Start](#quick-start)):

```bash
docker run -p 127.0.0.1:1080:1080 \
  -e SOCKS5_USERNAME -e SOCKS5_PASSWORD -e SOCKS5_AUTH_REQUIRED=true \
  jcaponigro20/simple-socks5
```

### Startup warnings

At startup the server logs:

- a **WARNING banner** when authentication is off and the bind address is not loopback (`localhost`, `127.0.0.0/8`, `::1`). Inside Docker the bind address is always `0.0.0.0`, so the banner appears even when the port is published only on `127.0.0.1`.
- a single **INFO** line instead of the banner when `SOCKS5_AUTH_REQUIRED=false` is set explicitly, to acknowledge a deliberate no-auth setup.
- a separate **WARNING** when the default credentials `myusername`/`mypassword` are in use, whether or not authentication is required. The password is never logged.

The warnings are shown at `-L debug`, `info` and `warning`. They are hidden at `error` and `critical`, and nothing is printed at `-L disabled` or with the `:logging-disabled` image.

### Publish only on trusted interfaces

Bind or publish the port only where you need it, e.g. `-p 127.0.0.1:1080:1080` or a specific LAN address (`-p 192.168.1.10:1080:1080`). Ports published by Docker bypass host firewalls such as ufw. Never expose the proxy to the internet without authentication.

### Cleartext

Data is transmitted in cleartext, including authentication credentials. Use additional encryption (e.g., SSH tunnel, VPN) in environments where interception is a risk.

### Pinning the previous release

To keep the exact pre-2.1 behaviour, pin `jcaponigro20/simple-socks5:2.0.0` (or `jcaponigro20/simple-socks5:2.0.0-logging-disabled`).
