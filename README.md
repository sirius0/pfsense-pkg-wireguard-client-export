# pfSense-pkg-WireGuard-ClientExport

`pfSense-pkg-WireGuard-ClientExport` is a minimal companion package for the
official pfSense WireGuard package. It creates a road-warrior peer and delivers
its client configuration as a QR code or `.conf` file in one guided workflow.

The project does not fork, replace, or patch the official WireGuard package.
WireGuard remains the source of truth for tunnels and peers.

## Design goals

- Use the native pfSense user interface and privilege model.
- Create peers through supported pfSense/WireGuard functions.
- Keep client private keys ephemeral: never save, log, e-mail, or re-export
  them.
- Allocate client IPv4 addresses safely from an explicit per-tunnel pool.
- Offer clear split-tunnel, full-tunnel, and custom routing profiles.
- Provision atomically at the application level, with rollback on failure.
- Remain small enough to audit and maintain.

## Non-goals for version 1

Version 1 will not provide:

- tunnel management or a replacement WireGuard control plane;
- storage or later recovery of client private keys;
- client re-export;
- e-mail delivery;
- preshared keys;
- IPv6 client allocation;
- automatic firewall or NAT changes;
- a daemon, cron task, telemetry, or any external service;
- high availability replication beyond behavior already provided by pfSense
  and the official WireGuard package.

## Intended workflow

1. An administrator configures an official WireGuard tunnel.
2. In Client Export settings, the administrator assigns that tunnel an IPv4
   client pool, public endpoint, DNS values, and split-tunnel destinations.
3. The administrator chooses the tunnel, names the client, selects a routing
   profile, and generates it.
4. The package locks allocation for that tunnel, validates current state,
   generates a keypair, creates the official peer, and synchronizes WireGuard.
5. The result page shows a QR code and offers copy/download actions exactly
   once. These actions operate from the configuration already present in the
   page; they do not fetch it again from the firewall.
6. The peer is subsequently managed from the official WireGuard **Peers** page.

If the one-time configuration is lost, the administrator must remove the peer
and create a replacement.

## Security model

The generated client private key exists only in process and browser memory for
the initial response. It is never written to pfSense configuration, a session,
a temporary file, a log, or a URL. The result response must use anti-caching
headers, and secrets must be redacted from all exceptions and diagnostics.

The package stores only non-secret per-tunnel preferences and the normal peer
data required by the official WireGuard package.

## Compatibility policy

- **Primary target:** pfSense CE 2.9.0.
- **Secondary target:** pfSense CE 2.8.1.
- **Legacy contract check:** pfSense CE 2.7.2 with WireGuard 0.2.1, on a
  best-effort basis only.

pfSense CE 2.7.2 is not a publicly supported target. The adapter fails closed
when the installed WireGuard package does not expose a tested contract. See
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

## Project documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data flow, and
  transaction boundaries.
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — supported versions and
  compatibility gates.

## Installation

Release `v0.1.0-beta.1` has been tested on pfSense CE 2.7.2 amd64 with the
official `pfSense-pkg-WireGuard` 0.2.1 package. Install and configure that
WireGuard package before installing Client Export. The GitHub tag follows
Semantic Versioning (`v0.1.0-beta.1`), while the equivalent FreeBSD package
version is `0.1.0.b1`.

Before installing or upgrading, export a pfSense configuration backup from
**Diagnostics > Backup & Restore**. When upgrading, also keep a copy of the
currently installed package file for rollback.

Open a pfSense shell as an administrator, then download the release package and
its checksum file:

```sh
cd /tmp
PACKAGE=pfSense-pkg-WireGuard-ClientExport-0.1.0.b1.pkg
RELEASE_URL=https://github.com/sirius0/pfsense-pkg-wireguard-client-export/releases/download/v0.1.0-beta.1
fetch -o "$PACKAGE" "$RELEASE_URL/$PACKAGE"
fetch -o SHA256SUMS "$RELEASE_URL/SHA256SUMS"
```

Verify the package with FreeBSD's `sha256` utility. The command exits with a
non-zero status if the downloaded file does not match the published checksum:

```sh
EXPECTED_SHA256="$(awk -v file="$PACKAGE" '$2 == file { print $1; exit }' SHA256SUMS)"
test -n "$EXPECTED_SHA256" && sha256 -c "$EXPECTED_SHA256" "$PACKAGE"
```

Only after the checksum succeeds, install or upgrade the package:

```sh
pkg add -f "./$PACKAGE"
```

The package is then available under **VPN > WireGuard Client Export**.

### Rollback

For this first public beta, rollback means removing only the Client Export
companion package:

```sh
pkg delete pfSense-pkg-WireGuard-ClientExport
```

If configuration recovery is also necessary, restore the backup from
**Diagnostics > Backup & Restore**. Installing or removing Client Export does
not delete tunnels or peers owned by the official WireGuard package.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
