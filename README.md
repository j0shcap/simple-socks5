# Simple SOCKS5 Proxy Server

[![CI](https://github.com/j0shcap/simple-socks5/actions/workflows/ci.yml/badge.svg)](https://github.com/j0shcap/simple-socks5/actions/workflows/ci.yml)

A SOCKS Protocol Version 5 proxy server written in Python. Implements [RFC 1928](https://www.ietf.org/rfc/rfc1928.txt) (SOCKS5) and [RFC 1929](https://www.ietf.org/rfc/rfc1929.txt) (username/password authentication).

## Features

- **TCP & UDP**: Supports CONNECT and UDP ASSOCIATE commands
- **Authentication**: Optional username/password authentication (RFC 1929)
- **IPv4 & IPv6**: Full support for both address families
- **Concurrent**: Thread-per-connection with a configurable connection limit
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

### Upgrading to 2.1

2.1 changes some defaults: the image logs at `info`, proxying to loopback and link-local addresses is refused unless `SOCKS5_ALLOW_LOOPBACK=true`, nothing is written to `/app/errors.log` unless `SOCKS5_LOG_FILE` is set, and `latest` moves only on releases. Each change has an opt-out; see [Upgrading from 2.0](CHANGELOG.md#upgrading-from-20-behaviour-changes). To keep the 2.0 behaviour, pin `jcaponigro20/simple-socks5:2.0.0`.

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
| `SOCKS5_PASSWORD` | `mypassword` | Password for RFC 1929 authentication. An empty username or password never authenticates. |
| `SOCKS5_AUTH_REQUIRED` | `false` | Set to `true` to require authentication. |
| `SOCKS5_HANDSHAKE_TIMEOUT` | `10` | Seconds a client has to finish the greeting, authentication and request. A client that is still sending when it runs out is disconnected without a reply. |
| `SOCKS5_CONNECT_TIMEOUT` | `10` | Seconds to connect to the destination. A timeout replies `0x04` (host unreachable). |
| `SOCKS5_ALLOW_LOOPBACK` | `false` | Set to `true` to allow destinations on loopback, link-local and unspecified addresses. See [Destination policy](#destination-policy). |
| `SOCKS5_MAX_CONNECTIONS` | `200` | Maximum concurrent client connections. Further connections are closed without a reply; a WARNING with the number rejected is logged at most every 10 seconds. |
| `LOGGING_LEVEL` | `debug` (Docker image: `info`) | Logging level used when `-L` isn't given. Same choices as `-L`. |
| `SOCKS5_LOG_FILE` | unset | Also write ERROR and CRITICAL lines to this file, rotated at 1 MB with 5 backups. Unset means console only. See [Logging](#logging). |
| `SOCKS5_HEALTHCHECK_PORT` | `1080` | Port the Docker healthcheck probes. Only the healthcheck reads it; set it when you change `--port`. |

Timeouts accept any positive number of seconds, such as `2.5`. `SOCKS5_MAX_CONNECTIONS` must be a positive integer. An invalid value stops the proxy at startup with an error.

### Logging

Logs go to stderr. Each connection logs one line when it opens and one when it closes:

```
CONNECTION | 172.17.0.1:51234 -> example.com:443 (93.184.216.34)
CLOSED | 172.17.0.1:51234 -> example.com:443 (93.184.216.34) | up=517 B down=10485943 B | 2.31 s
```

`up` counts bytes from the client to the destination, `down` the other way. The destination is the hostname the client sent, with the address it resolved to, or just the IP the client sent: the proxy never does reverse-DNS lookups. A UDP association logs the same two lines: it closes with its TCP control connection, and `up` and `down` count the datagram payloads relayed. Individual UDP datagrams are logged at `debug`.

A client that disconnects mid-handshake is logged at `debug` only; unexpected errors are logged at ERROR with a traceback. Colours are used only when stderr is a terminal. Nothing is written to disk unless `SOCKS5_LOG_FILE` is set.

## Docker

The examples below forward `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` from your shell (export them as in [Quick Start](#quick-start)).

```bash
# Default (logs at info; add -e LOGGING_LEVEL=debug for handshake details and UDP datagrams)
docker run -p 127.0.0.1:1080:1080 -e SOCKS5_AUTH_REQUIRED=true \
  -e SOCKS5_USERNAME -e SOCKS5_PASSWORD jcaponigro20/simple-socks5

# Logging disabled (also suppresses the startup warnings)
docker run -p 127.0.0.1:1080:1080 -e SOCKS5_AUTH_REQUIRED=true \
  -e SOCKS5_USERNAME -e SOCKS5_PASSWORD jcaponigro20/simple-socks5:logging-disabled

# Custom build with a different default logging level
docker build --build-arg LOGGING_LEVEL=debug -t my-socks5 .
```

The container always listens on `0.0.0.0` inside Docker; the `-p` flag decides which host interfaces the port is published on.

Docker's default bridge network has no IPv6. A client that resolves names itself (`curl --socks5`, `socks5://` URLs) may send the proxy an IPv6 address, which then fails with reply `0x03` (network unreachable). Let the proxy resolve names instead (`curl --socks5-hostname`, `socks5h://`, "Proxy DNS when using SOCKS v5" in Firefox), or [enable IPv6](https://docs.docker.com/engine/daemon/ipv6/) on the container's network.

### Version tags and pinning

```bash
docker pull jcaponigro20/simple-socks5:2.1.0   # exact release, recommended for production
docker pull jcaponigro20/simple-socks5:2.1     # 2.1.x patch releases
docker pull jcaponigro20/simple-socks5:2       # 2.x minor and patch releases
```

| Tag | Follows |
|-----|---------|
| `X.Y.Z` (e.g. `2.1.0`) | One release; never moves. |
| `X.Y`, `X` | The newest release in that line. |
| `latest` | The newest stable release. |
| `main` | The `main` branch; unreleased, for testing only. |
| `X.Y.Z-logging-disabled`, `logging-disabled` | The same, with logging disabled. |
| `2.0.0`, `2.0.0-logging-disabled` | The pre-2.1 behaviour. |

The image's `HEALTHCHECK` runs `python -m src.healthcheck` every 30 seconds. It sends a SOCKS5 greeting to `127.0.0.1` on `SOCKS5_HEALTHCHECK_PORT` (default `1080`) and passes on any SOCKS5 reply, so it works with and without authentication, and the proxy logs it at `debug` only. If you override the command with a different `--port`, set `SOCKS5_HEALTHCHECK_PORT` to match. If you bind a specific non-loopback address instead of `0.0.0.0` or `::`, the healthcheck can't reach it.

`docker stop` (SIGTERM) shuts the proxy down gracefully: it stops accepting connections, gives open connections up to 5 seconds to finish, then closes them and exits with code 0. Ctrl-C (SIGINT) does the same. Docker kills the container if it hasn't exited by the stop timeout, so keep that above 5 seconds: Docker Engine's default is 10, but some Docker Desktop versions use less. Run with `--stop-timeout 10` or stop with `docker stop -t 10` to be sure.

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

### Destination policy

By default the proxy refuses to connect or send to:

- loopback: `127.0.0.0/8` and `::1`;
- unspecified: `0.0.0.0/8` and `::`;
- link-local: `169.254.0.0/16` and `fe80::/10`, which includes the cloud instance metadata service at `169.254.169.254`;
- the IPv4-mapped (`::ffff:127.0.0.1`), IPv4-compatible (`::127.0.0.1`) and NAT64 (`64:ff9b::7f00:1`) forms of these.

The check is made on the resolved IP address just before connecting, so `localhost` and names that resolve or rebind to these addresses are refused too. A refused CONNECT gets reply `0x02` (connection not allowed by ruleset), and a WARNING naming the client, the destination and `SOCKS5_ALLOW_LOOPBACK` is logged at most every 10 seconds. A refused UDP datagram is dropped and logged at DEBUG; the association stays open. Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and public addresses are allowed, so the proxy and other services stay reachable on the host's or container's own non-loopback addresses. A request with an empty domain name gets `0x04` (host unreachable).

With the Docker image on its default bridge network nothing changes for you: the container's loopback is the container itself, and services on the host are reached through a private address such as `host.docker.internal`. If you run the proxy directly on a host, or with `--network host`, and proxy to services on `localhost`, set `SOCKS5_ALLOW_LOOPBACK=true`. It lifts the whole policy above.

### Cleartext

Data is transmitted in cleartext, including authentication credentials. Use additional encryption (e.g., SSH tunnel, VPN) in environments where interception is a risk.
