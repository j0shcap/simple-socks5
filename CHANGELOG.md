# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a minor version may
contain breaking changes, and each one is listed under **Breaking changes**.

## [Unreleased]

### Added
- Versioned Docker image tags: a `vX.Y.Z` release publishes `X.Y.Z`, `X.Y` and `X` (and
  `X.Y.Z-logging-disabled`), so a deployment can pin a version. A pre-release such as
  `v2.1.0-rc.1` publishes only its exact version.
- Startup warning when the proxy runs without authentication on a non-loopback host: anyone
  who can reach the port can use it. Set `SOCKS5_AUTH_REQUIRED=false` to acknowledge an
  intentional no-auth setup; this logs one INFO line instead. Visible at `-L debug`, `info`
  and `warning`.
- Startup warning when the built-in default credentials are in use. The password is never
  logged.
- README `Security` section: open-proxy risk, requiring authentication, publishing only on
  trusted interfaces, cleartext credentials, and pinning `:2.0.0` for the pre-2.1 behaviour.
- `SOCKS5_HANDSHAKE_TIMEOUT` and `SOCKS5_CONNECT_TIMEOUT` (seconds, default `10`). An invalid
  value exits at startup with an error.
- `SOCKS5_MAX_CONNECTIONS` (default `200`): the maximum number of concurrent client
  connections. It must be a positive integer; an invalid value exits at startup with an error.

### Changed
- `latest` and `logging-disabled` now move only on stable releases; pushes to `main` publish
  `:main` only. An image is published only after the tests and a container smoke test pass.
- README Quick Start leads with an authenticated example published on `127.0.0.1`; the
  no-auth example is labelled for trusted networks only.
- Docker image base is now `python:3.13-slim`, pinned by digest (Python 3.10 reaches end of life
  in October 2026). The image also sets `PYTHONUNBUFFERED=1` and `PYTHONDONTWRITEBYTECODE=1`.
- **Behaviour change:** the Docker image now logs at `info` by default instead of `debug`, so it
  no longer logs every relayed chunk. Set `-e LOGGING_LEVEL=debug` to restore the old output.
  This also applies when you override the container command without `-L`.
- The Docker image runs `python` directly as PID 1 (exec-form `CMD`), so it receives
  `docker stop`'s SIGTERM.
- `app.py` reads the `LOGGING_LEVEL` environment variable when `-L/--logging-level` isn't
  given. Precedence is `-L`, then `LOGGING_LEVEL`, then `debug`; an invalid value exits with
  an error.
- TCP relay buffer raised from 4 KiB to 64 KiB, about 7× the throughput. The UDP relay's
  receive buffer, which shares the setting, grows to match.
- The "connection limit reached" warning is logged at most once every 10 seconds, with the
  number of connections rejected since the previous one, instead of once per rejection.

### Fixed
- SIGTERM and SIGINT now shut the server down gracefully: it stops accepting connections, gives
  in-flight connections up to 5 seconds to finish, closes the rest and exits with code 0. This
  includes connections accepted just before the signal. An open UDP association can take the
  full 5 seconds. `docker stop` previously waited 10 seconds and killed the container (exit
  code 137).
- README: the default port is `1080`, not `9999`; removed the claim of configurable
  connection limits; the authentication example now sets `SOCKS5_AUTH_REQUIRED=true`.
- The outbound socket leaked when a CONNECT target refused the connection; it is now closed
  before the refusal reply is sent.
- Downloads were truncated when the client read slower than the origin sent: a full send
  buffer dropped the connection. The relay now waits for the slow side (up to 5 minutes per
  write), so the transfer completes.
- TCP half-close: a client or server that closes its sending side still receives the reply.
  Before, the first end-of-stream from either side closed the whole connection.
- Handshake slowloris: a client that connected and then sent nothing (or one byte at a time)
  held a connection slot forever, so 200 idle connections locked out every client. The
  greeting, authentication and request must now arrive within `SOCKS5_HANDSHAKE_TIMEOUT`
  seconds in total; a client that is still sending is disconnected without a reply. The
  separate 45-second authentication timeout is gone.
- Connection bursts: the listen backlog was 5, so on Linux clients connecting during a burst
  waited 1 to 3 seconds for TCP retransmits before the proxy accepted them. It is now the
  system maximum (`SOMAXCONN`).
- Outbound connect timeout: CONNECT to an unreachable host waited for the OS default (75 s on
  macOS, about 2 minutes on Linux) and replied `0x01`. It now gives up after
  `SOCKS5_CONNECT_TIMEOUT` seconds and replies `0x04` (host unreachable).
- Accurate SOCKS reply codes (RFC 1928): network unreachable replies `0x03`, host unreachable
  and connect timeouts `0x04`, an unknown address type `0x08`, and a domain name that isn't
  valid UTF-8 `0x04`. These all replied `0x01` before.
- A malformed UDP datagram (too short, a non-zero reserved field, an unknown address type or a
  truncated address) ended the UDP association and sent a stray failure reply on its control
  connection; a single spoofed datagram was enough. It is now dropped and the association keeps
  working. A datagram to a destination that can't be sent to (such as port 0) is dropped too.
- A request now gets exactly one SOCKS reply. An error after the success reply (for example
  during a CONNECT tunnel) used to send a second, failure reply, injecting 10 bytes into the
  stream; it is now only logged.

### Security
- Usernames and passwords are compared in constant time, and both are always checked, so
  response timing no longer reveals which one was wrong.
- Stricter RFC 1929 parsing: credentials that aren't valid UTF-8 now get a failure reply
  instead of an uncaught error and a traceback on stderr, and an empty username or password
  is always rejected. **Behaviour change:** an empty `SOCKS5_USERNAME` or `SOCKS5_PASSWORD`
  can no longer be used to log in.
- A failed login logs the client's IP address instead of the username it submitted.
- `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` are read for each login rather than once at import.
