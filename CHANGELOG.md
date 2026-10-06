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

### Changed
- `latest` and `logging-disabled` now move only on stable releases; pushes to `main` publish
  `:main` only. An image is published only after the tests and a container smoke test pass.
- README Quick Start leads with an authenticated example published on `127.0.0.1`; the
  no-auth example is labelled for trusted networks only.
- `app.py` reads the `LOGGING_LEVEL` environment variable when `-L/--logging-level` isn't
  given. Precedence is `-L`, then `LOGGING_LEVEL`, then `debug`; an invalid value exits with
  an error.

### Fixed
- SIGTERM and SIGINT now shut the server down gracefully: it stops accepting connections, gives
  in-flight connections up to 5 seconds to finish, closes the rest and exits with code 0.
- README: the default port is `1080`, not `9999`; removed the claim of configurable
  connection limits; the authentication example now sets `SOCKS5_AUTH_REQUIRED=true`.
- The outbound socket leaked when a CONNECT target refused the connection; it is now closed
  before the refusal reply is sent.
