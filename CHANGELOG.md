# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-beta.2] - 2026-09-19

### Changed

- Updated the WireGuard adapter to discover tunnels through official callable
  capabilities instead of depending on the legacy global configuration shape.
- Preserved backward compatibility with the official WireGuard 0.2.1 contract
  while adding the WireGuard 0.2.13_4 contract used by pfSense CE 2.9.0.
- Rebuilt the experimental package for pfSense CE 2.9.0 on FreeBSD 16
  `amd64`.

### Tested

- Passed all 81 automated tests, including pinned legacy and current
  WireGuard contract coverage.
- Verified upgrade/reinstallation on pfSense CE 2.9.0 with existing
  Client Export settings preserved.
- Completed peer provisioning, runtime synchronization, cleanup, and UI smoke
  testing with the official WireGuard 0.2.13_4 package.

## [0.1.0-beta.1] - 2026-09-08

### Added

- FreeBSD/pfSense port skeleton, native VPN menu entry, and package privilege.
- Per-tunnel non-secret settings, IPv4 allocation, configuration rendering,
  official WireGuard adapter, locked provisioning, confirmation, and rollback.
- Native pfSense generation page with one-time QR, copy, and `.conf` download.
- Editable first-run suggestions for client pool, endpoint, port, DNS, local
  routes, routing profile, and persistent keepalive. Existing saved settings
  always take precedence over suggestions.

### Changed

- Kept generation unavailable until settings are saved and a client name is
  present.
- Added unique form identifiers, an accessible client-name label, and explicit
  feedback when a public endpoint cannot be detected safely.

### Security

- Kept client private keys ephemeral and out of pfSense configuration, files,
  sessions, URLs, logs, and diagnostics.
- Added locked allocation, fail-closed compatibility checks, secret redaction,
  anti-caching response headers, and peer rollback on provisioning failure.

### Tested

- PHP 8.2-8.5 test matrix and pinned WireGuard 0.2.1/current contract tests.
- Package lifecycle and UI acceptance tested on pfSense CE 2.7.2 amd64 with
  the official WireGuard 0.2.1 package.

[Unreleased]: https://github.com/sirius0/pfsense-pkg-wireguard-client-export/compare/v0.1.0-beta.2...HEAD
[0.1.0-beta.2]: https://github.com/sirius0/pfsense-pkg-wireguard-client-export/releases/tag/v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/sirius0/pfsense-pkg-wireguard-client-export/releases/tag/v0.1.0-beta.1
