# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). A minor release may change a default
to make the proxy safer; each such change is marked **Behaviour change** and is listed under
"Upgrading" for that release, with how to restore the old behaviour where that is possible.

## [Unreleased]

### Changed
- The code is now the `simple_socks5` package under `src/`, and `pip install .` installs it.
  `python3 app.py` keeps working from a clone and in the image.
- **Behaviour change:** the image healthcheck runs `python -m simple_socks5.healthcheck`. If
  you copied `python -m src.healthcheck` into a compose file or Kubernetes probe, update it.
- **Behaviour change:** logger names in `SOCKS5_LOG_FILE` lines change from `[src.…]` to
  `[simple_socks5.…]`, which matters if you parse that file. Console lines are unchanged.

## [2.1.0] - 2026-10-06

### Upgrading from 2.0 (behaviour changes)

Authentication stays optional and off by default; 2.1 only warns when the proxy is open. These
defaults changed:

1. **Image tags.** `latest` and `logging-disabled` now move only on releases, and pushes to
   `main` publish `:main`. Pin `:2`, `:2.1` or `:2.1.0` to choose how far you follow.
2. **Log level.** The Docker image logs at `info` instead of `debug`, and connection log lines
   have a new format. Set `-e LOGGING_LEVEL=debug` to restore the old level.
3. **Loopback and link-local destinations.** Proxying to loopback, link-local (including the
   cloud metadata service at `169.254.169.254`) and unspecified addresses is refused with reply
   `0x02`. Set `-e SOCKS5_ALLOW_LOOPBACK=true` to restore it. Containers on Docker's default
   bridge network are unaffected.
4. **Error log file.** The image no longer writes `/app/errors.log`. Set
   `-e SOCKS5_LOG_FILE=/app/errors.log` to restore it.
5. **Empty credentials.** An empty `SOCKS5_USERNAME` or `SOCKS5_PASSWORD` can no longer be used
   to log in. There is no opt-out.
6. **Keep 2.0 entirely.** Pin `jcaponigro20/simple-socks5:2.0.0` (or
   `:2.0.0-logging-disabled`).

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
- `SOCKS5_LOG_FILE`: when set, ERROR and CRITICAL lines are also written to this file,
  rotated at 1 MB with 5 backups.
- `SOCKS5_HEALTHCHECK_PORT` (default `1080`): the port the Docker healthcheck probes. Set it
  when you run the image with a different `--port`.
- `SOCKS5_ALLOW_LOOPBACK` (default `false`): set to `true` to allow destinations on loopback,
  link-local and unspecified addresses, which are now refused by default.

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
- No reverse-DNS (PTR) lookups: CONNECT to an IP address no longer waits up to 2 seconds for
  one, and visited addresses no longer leak to the resolver. Logs show the hostname the client
  sent or the IP address.
- Connection log lines have a new format, which matters if you parse them. Each connection
  logs `CONNECTION | client -> destination` when it opens and one summary line when it
  closes, `CLOSED | client -> destination | up=N B down=N B | N.NN s`, instead of a debug line
  per relayed chunk.
- A client disconnecting mid-handshake or mid-relay is logged at `debug` without a traceback.
  So is a client that offers no acceptable authentication method, which was a warning.
- Log colours are used only when the output is a terminal.
- **Behaviour change:** errors are no longer written to `errors.log` in the working directory
  (`/app/errors.log` in the Docker image). Set `SOCKS5_LOG_FILE` to keep a log file.
- The Docker `HEALTHCHECK` runs `python -m src.healthcheck`, which speaks SOCKS5 instead of
  opening and closing a bare TCP connection.

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
- A UDP association now logs a `CLOSED` line when it ends, like a TCP connection, with the
  datagram payload bytes relayed each way.
- A UDP association now ends as soon as its TCP control connection closes, as RFC 1928
  requires. Before, its relay port kept relaying datagrams for up to 2 minutes after the client
  disconnected. The 2-minute idle timeout stays, but only datagrams from the client reset it.
- The Docker healthcheck no longer logs an error with a traceback every 30 seconds (about 2,880
  a day); the proxy now logs nothing above `debug` for it.
- Error log rotation: each module had its own handler writing to the same `errors.log`, so
  rotation renamed the file under the others and could lose or interleave lines.
- An exception that escaped a connection handler was printed to stderr by `socketserver`,
  even with `-L disabled`. It now goes through logging, so `-L` applies: ERROR with its
  traceback, or `debug` for a client that disconnected.
- An empty domain name is rejected with `0x04` (host unreachable). It used to connect to the
  proxy host itself.

### Security
- Usernames and passwords are compared in constant time, and both are always checked, so
  response timing no longer reveals which one was wrong.
- Stricter RFC 1929 parsing: credentials that aren't valid UTF-8 now get a failure reply
  instead of an uncaught error and a traceback on stderr, and an empty username or password
  is always rejected. **Behaviour change:** an empty `SOCKS5_USERNAME` or `SOCKS5_PASSWORD`
  can no longer be used to log in.
- A failed login logs the client's IP address instead of the username it submitted.
- `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` are read for each login rather than once at import.
- **Behaviour change:** proxying to loopback (`127.0.0.0/8`, `::1`), link-local
  (`169.254.0.0/16`, including the cloud metadata service at `169.254.169.254`, and
  `fe80::/10`) and unspecified (`0.0.0.0/8`, `::`) addresses is refused by default, including
  their IPv4-mapped, IPv4-compatible and NAT64 forms. The resolved IP is checked, so
  `localhost` is refused too. A refused CONNECT gets `0x02` and a WARNING, logged at most every
  10 seconds; a refused UDP datagram is dropped. Private ranges stay allowed. Docker users on
  the default bridge network are unaffected; if you proxy to `localhost` on the host or with
  `--network host`, set `SOCKS5_ALLOW_LOOPBACK=true` to restore the old behaviour.

## [2.0.0] - 2026-02-26

### Removed
- **Breaking:** Python 3.7, 3.8 and 3.9 are no longer supported; the minimum is Python 3.10.

### Added
- `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` environment variables for the credentials.
- A limit of 200 concurrent connections.
- Timeouts on DNS lookups.
- Docker `HEALTHCHECK`, a single Dockerfile with a `LOGGING_LEVEL` build argument, and
  `.dockerignore`.
- `pyproject.toml`, flake8 and a coverage threshold in CI. Python 3.13 in the CI matrix.

### Fixed
- IPv6: replies crashed with `struct.error`, and socket address unpacking failed.
- UDP relay: it blocked indefinitely and leaked sockets, and crashed on domain-name datagrams.
- TCP relay: partial reads, a selector leak when setup failed, lost tracebacks, and a client
  socket closed twice.
- Error replies always used the IPv4 address type.
- The socket timeout wasn't restored after authentication.
- Server shutdown order, duplicate log handlers, a thread-unsafe logger cache and DNS thread
  leaks.
- The reserved (RSV) field is validated, as RFC 1928 requires.

## [1.0.0] - 2024-09-28

### Added
- First release: a SOCKS5 server (RFC 1928) with CONNECT and UDP ASSOCIATE, username/password
  authentication (RFC 1929), and IPv4, IPv6 and domain-name addresses.
- Host, port and logging level set on the command line.
- Docker image running as a non-root user, with a variant that has logging disabled.

[Unreleased]: https://github.com/j0shcap/simple-socks5/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/j0shcap/simple-socks5/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/j0shcap/simple-socks5/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/j0shcap/simple-socks5/releases/tag/v1.0.0
