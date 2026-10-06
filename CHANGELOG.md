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

### Changed
- `latest` and `logging-disabled` now move only on stable releases; pushes to `main` publish
  `:main` only. An image is published only after the tests and a container smoke test pass.
