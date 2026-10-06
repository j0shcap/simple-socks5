# Simple SOCKS5 Proxy Server

[![CI](https://github.com/j0shcap/simple-socks5/actions/workflows/ci.yml/badge.svg)](https://github.com/j0shcap/simple-socks5/actions/workflows/ci.yml)

A SOCKS Protocol Version 5 proxy server written in Python. Implements [RFC 1928](https://www.ietf.org/rfc/rfc1928.txt) (SOCKS5) and [RFC 1929](https://www.ietf.org/rfc/rfc1929.txt) (username/password authentication).

## Features

- **TCP & UDP**: Supports CONNECT and UDP ASSOCIATE commands
- **Authentication**: Optional username/password authentication (RFC 1929)
- **IPv4 & IPv6**: Full support for both address families
- **Concurrent**: Thread-per-connection with configurable connection limits
- **Docker**: Multi-architecture images on [Docker Hub](https://hub.docker.com/r/jcaponigro20/simple-socks5)

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Quick Start

```bash
# Run directly
python3 app.py -H 0.0.0.0 -P 1080 -L debug

# Or with Docker
docker run -p 1080:1080 jcaponigro20/simple-socks5
```

## Usage

```bash
python3 app.py [--host HOST | -H HOST] [--port PORT | -P PORT] [--logging-level LEVEL | -L LEVEL]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-H`, `--host` | `localhost` | Bind address. Use `0.0.0.0` for all interfaces. |
| `-P`, `--port` | `9999` | Bind port. |
| `-L`, `--logging-level` | `debug` | `disabled`, `debug`, `info`, `warning`, `error`, `critical` |

## Docker

```bash
# Default (logging enabled)
docker run -p 1080:1080 jcaponigro20/simple-socks5

# Logging disabled
docker run -p 1080:1080 jcaponigro20/simple-socks5:logging-disabled

# Custom build
docker build --build-arg LOGGING_LEVEL=info -t my-socks5 .
```

## Authentication

Set credentials via environment variables (defaults: `myusername`/`mypassword`):

```bash
export SOCKS5_USERNAME=admin
export SOCKS5_PASSWORD=secret
python3 app.py -H 0.0.0.0 -P 1080
```

## Testing

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pytest pytest-cov flake8
pytest --cov=src --cov-fail-under=60
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

## Security Considerations

Data is transmitted in cleartext, including authentication credentials. Use additional encryption (e.g., SSH tunnel, VPN) in environments where interception is a risk.
