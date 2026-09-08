# Compatibility policy

## Supported targets

| pfSense | Architecture | WireGuard package | Policy |
|---|---|---|---|
| CE 2.9.0 | `amd64` | Version available for that release | Primary target |
| CE 2.8.1 | `amd64` | Version available for that release | Secondary target |
| CE 2.7.2 | `amd64` | 0.2.1 contract fixture/check | Experimental preview only; unsupported |

Exact official WireGuard package revisions for primary and secondary targets
must be recorded and tested before the first stable release. A
pfSense/WireGuard pair not listed in release notes is unsupported even if
installation succeeds.

Automated PHP compatibility runs on PHP 8.2, 8.3, 8.4, and 8.5. This matrix is
a language/runtime gate, not a substitute for testing the exact PHP and
FreeBSD build shipped by each supported pfSense release.

`amd64` is the initial hardware architecture. Other architectures require an
explicit build and firewall validation before support is claimed.

## Experimental preview releases

A GitHub release explicitly marked **Pre-release** may publish an experimental
package for one exact pfSense/WireGuard pair before the stable support matrix is
complete. Its release notes and package architecture must identify that pair,
must not claim production or stable support, and must state which primary and
secondary targets remain unvalidated.

The exact preview artifact must pass source tests, PHP/XML/shell checks, package
content and secret audits, checksum verification, installation, authenticated
UI smoke testing, peer provisioning and confirmed cleanup on the stated test
firewall. The source tag and packaged version must map unambiguously to each
other. A preview built outside a full Ports tree may not be submitted as an
official FreeBSD/pfSense port or promoted to stable.

This preview exception does not waive any stable-release gate below. It exists
only to distribute a reproducible, narrowly scoped test artifact for early
evaluation and rollback.

## Meaning of support

A supported pair must pass:

- static PHP and XML checks;
- domain and adapter contract tests;
- package build and content audit;
- clean install and upgrade from the previous companion release;
- native UI/privilege/CSRF tests;
- correct IPv4 source selection: live pfSense interface state for assigned
  tunnels and current official tunnel-row state for unassigned tunnels;
- successful peer creation and runtime synchronization;
- QR, copy, and `.conf` import verification;
- forced failure with confirmed rollback;
- concurrent allocation testing;
- uninstall verification that official tunnels/peers remain untouched.

Passing local Docker tests alone does not establish pfSense support. Final
validation requires the target pfSense/FreeBSD environment with the real
official WireGuard package and kernel/runtime integration.

## Legacy pfSense CE 2.7.2

CE 2.7.2 is retained only because the initial development firewall uses it.
The project may maintain a fixture and contract test for WireGuard 0.2.1 and
may perform a one-off smoke test on that non-production firewall.

This does not make CE 2.7.2 a publicly supported target. An experimental
pre-release may name it as its sole validated evaluation environment, but must
not encourage remaining on an obsolete firewall version. Issues reproducible
only on CE 2.7.2 may be closed or require upgrade unless a safe, isolated fix
has no cost to supported versions.

## Compatibility adapter policy

The package integrates with official WireGuard code only through a narrow
adapter. Startup/readiness must verify required files, callable functions, and
expected data contracts.

Contract fixtures are pinned to immutable upstream revisions. The legacy
fixture pins official WireGuard 0.2.1; the supported-current fixture pins the
exact official package revision/commit tested for the release. A moving branch
or unrecorded latest-version lookup is not a compatibility contract.

The package must fail closed before mutation when:

- the official WireGuard package is missing or disabled;
- required functions are missing;
- the configuration shape is unknown;
- an assigned tunnel cannot be mapped to one live pfSense interface with an
  unambiguous current IPv4 address and subnet;
- an unassigned tunnel has no valid, unambiguous current IPv4 address/subnet in
  its official WireGuard tunnel row;
- a detected version/contract combination has not passed tests;
- runtime synchronization capability cannot be confirmed.

Version strings may help select a tested adapter, but feature/capability checks
are mandatory. Silent fallback to direct `config.xml` edits is forbidden.
Address/subnet values retained in WireGuard tunnel rows are not accepted as a
fallback for unavailable live assigned-interface state. They are the
authoritative source for an unassigned tunnel, which remains supported.

## Upgrade policy

An official pfSense or WireGuard package upgrade is a compatibility event.
Before declaring compatibility:

1. capture/update upstream contract fixtures;
2. review relevant upstream changes;
3. run the complete automated suite;
4. install on the target pfSense build;
5. execute create/apply/rollback/uninstall smoke tests;
6. record the exact versions in release notes.

The stable-release packaging gate must also run `portlint -CN`,
`make check-plist`, a clean package build, and the package content/security
audit inside a compatible FreeBSD ports environment. Linux CI source-to-plist
checks do not replace these commands.

If an already-supported upstream update breaks the contract, the safe behavior
is to disable generation with an actionable message. Existing official peers
must remain manageable through the official WireGuard UI.

## Local development environments

Linux/macOS containers or hosts are suitable for pure validation, allocator,
configuration builder, UI asset, secret scanning, and packaging-fixture tests.
They cannot validate FreeBSD ABI, pfSense configuration integration, native
privileges/CSRF, WireGuard kernel state, or real package lifecycle hooks.
