# Architecture

## 1. Context

`pfSense-pkg-WireGuard-ClientExport` is a presentation and orchestration layer
beside the official pfSense WireGuard package. It does not own WireGuard
tunnels, peers, interfaces, or runtime synchronization.

```text
Administrator browser
        |
        | authenticated HTTPS + CSRF token
        v
Native pfSense page
        |
        v
Validation -> Provisioner -> WireGuard adapter -> Official WireGuard package
                    |                    |                    |
                    |                    |                    +-> runtime sync
                    |                    +-> official peer configuration
                    +-> per-tunnel allocation lock
```

Only the final HTML response crosses back to the browser with the client
private key. No secret crosses into persistent package settings.

## 2. Component boundaries

### Bootstrap and compatibility

The bootstrap component loads pfSense facilities and locates the official
WireGuard package. It selects a recognized compatibility adapter based on
tested capabilities, not only a version string. Missing or ambiguous contracts
cause a fail-closed readiness error.

Tunnel configuration rows are not the source of truth for an assigned
interface's address. When the selected WireGuard tunnel is assigned, readiness
obtains its current live IPv4 address and subnet from that pfSense interface;
missing, ambiguous, or IPv6-only live state fails closed without a row
fallback. When the tunnel is unassigned, readiness uses its valid current IPv4
address/subnet from the official WireGuard tunnel row instead. Being
unassigned is not itself a readiness failure.

### Configuration service

The configuration service reads and writes package-owned, non-secret settings
through supported pfSense configuration facilities. It validates the complete
per-tunnel settings object before persisting it.

It never stores generated peer credentials. Tunnel references use a stable
official identifier rather than a list position.

### Validation service

Validation is pure wherever practical. It validates and normalizes names,
IPv4 CIDRs, endpoint hosts and ports, DNS addresses, keepalive values, and
routing selections. It returns structured errors suitable for native pfSense
forms.

Untrusted POST values do not become shell fragments, filesystem paths, HTML,
or authoritative tunnel properties.

### IP allocator

The allocator accepts an immutable snapshot of the pool, reservations,
authoritative tunnel IPv4 address/subnet, and official peers. It returns a
candidate `/32` or an explicit exhaustion/conflict result.

The allocator itself has no configuration or runtime side effects. The
provisioner supplies a current snapshot while holding the tunnel lock. For an
assigned tunnel, that snapshot contains the interface's live IPv4
address/subnet and cached row fields are never substituted. For an unassigned
tunnel, the snapshot contains the current official tunnel-row IPv4/subnet.

### Client configuration builder

The builder is a pure component that accepts already validated values and
returns canonical WireGuard text. It controls ordering, whitespace, optional
fields, and the distinction between:

- server-side peer Allowed IP: allocated client `/32`;
- client-side peer Allowed IPs: selected routing destinations.

It has no logging and no persistence access.

### WireGuard adapter

The adapter is the only package component allowed to call official WireGuard
mutation and synchronization functions. Its interface is deliberately small:

```text
readiness()
listTunnels()
getTunnel(id)
resolveTunnelIPv4(id) -> assignmentSource/address/subnet
listPeers(tunnelId)
createPeer(tunnelId, peerData) -> peerIdentity
deletePeer(peerIdentity)
applyTunnel(tunnelId)
confirmPeer(peerIdentity, expectedData)
```

Exact PHP names and data shapes are adapter implementation details verified by
contract fixtures/tests for each supported official-package line.

The adapter MUST NOT edit `/conf/config.xml` directly. It may use supported
pfSense configuration functions as required by the official WireGuard API,
with all such coupling contained and tested here.

### Provisioner

The provisioner owns the use-case transaction and is the only component that
combines key generation, allocation, official peer mutation, runtime apply,
and rollback.

It receives validated intent from the UI and returns either:

- a success value containing the client configuration and public metadata; or
- a sanitized failure with rollback status.

It never returns the private key to logs, exceptions, or persistent metadata.

### Native UI

The UI performs authentication/authorization and CSRF verification before
calling application services. It escapes every output in the appropriate HTML
context and uses pfSense controls and notifications.

On success, vendored browser-side QR code logic consumes the already-rendered
configuration. Copy and download operations use that same in-page value, so no
second HTTP request or server-side secret store is necessary. Their event
handlers are established independently and before QR rendering. QR failure is
reported without disabling either action.

The one-time payload is limited to 2048 UTF-8 bytes. At most 32 normalized
routes and four DNS servers can contribute to it. The QR container contains no
secret-bearing `title`, `aria-*`, `data-*`, or other attribute; only the
intended in-page configuration value and QR modules carry the credential.

## 3. Persistent data model

The companion owns one configuration subtree containing a schema version and
settings indexed by stable tunnel ID. Conceptually:

```text
wireguard-client-export
  schema_version
  tunnels[]
    tunnel_id
    enabled
    client_pool_ipv4
    endpoint_host
    endpoint_port
    dns_ipv4[]
    persistent_keepalive
    local_routes_ipv4[]
    reservations_ipv4[]
```

The implemented structure must follow pfSense package conventions. This model
is conceptual and does not authorize direct XML access.

Forbidden persistent fields include client private keys, preshared keys,
generated configuration text, QR data, and retrievable one-time tokens.

## 4. Provisioning sequence

```text
UI              Provisioner       Allocator       WG adapter
 | POST + CSRF       |                |                |
 |------------------>|                |                |
 |                   | acquire local per-tunnel lock   |
 |                   | resolve IPv4 + read tunnel/peers|
 |                   |<--------------------------------|
 |                   | allocate------>|                |
 |                   |<------IPv4 /32 |                |
 |                   | generate keypair in memory      |
 |                   | create peer-------------------->|
 |                   |<----------------peer identity---|
 |                   | apply + confirm---------------->|
 |                   |<-----------------------success--|
 |                   | release lock                     |
 |<--one-time config-|                                  |
```

If create, apply, or confirmation fails after mutation, the provisioner calls
`deletePeer`, applies the tunnel again, and confirms restoration before
returning failure.

## 5. Transaction and concurrency model

The transaction is application-level because pfSense configuration and
runtime WireGuard state do not form a database transaction.

- Lock scope is one stable tunnel identifier.
- Lock names are derived only from a safe digest of that identifier.
- Acquisition is exclusive, bounded, and released in a `finally` path.
- Current configuration is loaded after acquisition.
- The lock remains held through confirmation or rollback.
- Rollback targets the exact identity returned by `createPeer`; it does not
  infer a peer from name or array index.
- A rollback failure is a high-severity operational condition, not success.

Separate tunnels may provision concurrently. Two requests for the same tunnel
serialize, preventing duplicate allocations.

## 6. Key lifecycle

Key generation uses the WireGuard tooling or a reviewed cryptographic facility
available on the supported pfSense version. Commands, if required, are invoked
without a shell and with checked exit status.

```text
generate -> derive public key -> build peer/config -> response -> discard
```

The private key remains in local variables only as long as needed. PHP does not
guarantee deterministic memory erasure, so the design minimizes copies and
lifetime but does not claim secure zeroization. No object containing the key is
serializable into configuration, sessions, exception context, or diagnostics.

## 7. Failure classes

- **Readiness failure:** no mutation; administrator receives remediation.
- **Address-source resolution failure:** no key generation or mutation. An
  assigned tunnel never falls back to its row; an unassigned tunnel may use a
  valid current official row address/subnet.
- **Validation or pool failure:** no key generation and no mutation.
- **Payload-limit failure:** no peer mutation; request-local key data is
  discarded.
- **Key-generation failure:** no mutation; sanitized error.
- **Peer-create failure:** adapter confirms whether mutation occurred and rolls
  back if necessary.
- **Apply/confirmation failure:** remove peer, re-apply, confirm restoration.
- **Rollback failure:** explicit critical error instructing the administrator
  to inspect official peer/runtime state.
- **Response interruption:** the peer may exist although the user did not
  receive its private key. The UI warns that the orphan peer must be removed;
  no insecure recovery path is introduced.
- **QR-rendering failure:** peer creation remains successful; the page shows a
  safe warning and preserves copy/download delivery of the same payload.

## 8. Packaging boundaries

The package installs files only in its own web, include, metadata, menu, and
privilege paths. The package manifest must declare every installed file and its
dependency on official WireGuard.

Installation and deinstallation scripts must be idempotent. Deinstallation
must not remove official peers/tunnels, official package files, or shared
runtime state. No install hook may automatically modify firewall or NAT rules.

## 9. Extension policy

Future IPv6, preshared-key, re-export, e-mail, automation, or API features are
not latent version 1 switches. Each requires a new specification and threat
review. Compatibility logic remains isolated in adapters rather than spreading
official-package assumptions across the UI and domain code.
