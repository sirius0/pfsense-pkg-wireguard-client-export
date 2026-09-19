# Compatibility policy

## Supported targets

| pfSense | FreeBSD | Architecture | WireGuard package | Release | Policy |
|---|---|---|---|---|---|
| CE 2.9.0 | 16 | `amd64` | 0.2.13_4 | `v0.1.0-beta.2` / `0.1.0.b2` | Validated current experimental preview |
| CE 2.8.1 | Not validated | `amd64` | Not validated | None | Unvalidated; do not install either preview |
| CE 2.7.2 | 14 | `amd64` | 0.2.1 | `v0.1.0-beta.1` / `0.1.0.b1` | Validated legacy experimental preview |

Each preview is valid only for the exact pfSense, FreeBSD architecture/ABI,
and official WireGuard package combination listed above. A different
pfSense/WireGuard pair is unsupported even if package installation succeeds.
Neither preview establishes stable or production support.

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

CE 2.7.2 is retained as the exact legacy environment validated for
`v0.1.0-beta.1`. The project maintains its pinned WireGuard 0.2.1 fixture and
contract test so changes to the shared adapter do not silently break that
preview.

This does not make CE 2.7.2 a stable or current target and does not encourage
remaining on an obsolete firewall version. Issues reproducible only on CE
2.7.2 may be closed or require upgrade unless a safe, isolated fix has no cost
to the current preview.

## Compatibility adapter policy

The package integrates with official WireGuard code only through a narrow
adapter. Startup/readiness must verify required files, callable functions, and
expected data contracts.

Contract fixtures are pinned to immutable upstream revisions. The legacy
fixture pins official WireGuard 0.2.1. When the exact package build revision is
public, the current fixture pins that revision. Otherwise it pins an immutable
public revision whose eight WireGuard include files are verified byte-for-byte
against the installed package, and the release records that provenance gap.
For `0.2.13_4`, commit `cec6cafe9d63e77aeacfa270cdefb69717f8d3ce`
provides the byte-identical public include files, while its public port
Makefile reports revision `_3`. A moving branch or unrecorded latest-version
lookup is not a compatibility contract.

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

The adapter selects behavior through official callable capabilities and
normalizes their output into one internal model. It does not branch on pfSense
or WireGuard version strings when the same tested capability is available.
Version strings may help identify a tested contract, but feature/capability
checks are mandatory. Silent fallback to direct `config.xml` edits is
forbidden. Address/subnet values retained in WireGuard tunnel rows are not
accepted as a fallback for unavailable live assigned-interface state. They
are the authoritative source for an unassigned tunnel, which remains
supported.

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
