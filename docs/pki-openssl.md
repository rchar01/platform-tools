# OpenSSL PKI Helpers

The `platform-pki-*` commands manage a small internal OpenSSL PKI for platform TLS certificates.

Generated CA keys, service keys, CSRs, issued certificates, CA database files, exports, and backups live outside Git under:

```text
~/.config/platform-infrastructure/pki/
```

## Responsibility Split

| Area | Responsibility |
| --- | --- |
| `platform-tools` | Reusable PKI helper scripts, templates, and documentation. |
| `platform-private` | Private environment-specific references and operator config; no raw private keys. |
| `~/.config/platform-infrastructure/pki/` | Real CA state, service keys, issued certificates, CSRs, exports, and backups. |
| `platform-config` | Ansible deployment of certs/keys, CA trust, permissions, and service reloads. |
| Monitoring | Live endpoint expiry checks and alerts. |

## Architecture

The helpers use this model:

```text
offline root CA
  signs
intermediate CA
  signs
service certificates
```

Service certificates are not signed directly by the root CA.

Defaults:

| Setting | Default |
| --- | --- |
| Key algorithm | ECDSA |
| Curve | `secp384r1` / P-384 |
| Digest | `sha384` |
| Root lifetime | 3650 days |
| Intermediate lifetime | 1825 days |
| Service lifetime | 397 days |

## Requirements

See `../README.md` for the canonical repository requirements. This section lists PKI-specific requirements and behavior.

Required:

- `bash`
- `openssl`
- util-linux `flock` and Linux procfs at `/proc` for stable operation-lock identity checks
- `tar` with `--no-wildcards` support for safe backup directory exclusions
- GNU `date` for certificate expiry calculations
- GNU `mv` with `--no-copy` and `--update=none-fail`; inventory publication prefers `--exchange` when supported and otherwise uses a guarded rename fallback under cooperative same-UID locks
- standard Unix tools such as `awk`, `cmp`, `cp`, `find`, `grep`, `mkdir`, `mktemp`, `sed`, and `stat`

Backup encryption requires `age`.

If `age` is unavailable, `platform-pki-backup` refuses to create an unencrypted archive unless `--allow-plain-backup` is passed explicitly.

## Install

```bash
make install
```

The install target copies command wrappers into `INSTALL_DIR` and shared PKI library/templates into `SHARE_DIR`.

Use custom paths when needed:

```bash
make install \
  INSTALL_DIR="$PWD/.tools/bin" \
  SHARE_DIR="$PWD/.tools/share/platform-tools"
```

If commands cannot find shared assets, set:

```bash
export PLATFORM_TOOLS_SHARE_DIR="$PWD/.tools/share/platform-tools"
```

## Initialize PKI State

```bash
platform-pki-init
```

This initializes the following working-tree layout. CA material, service
directories, OpenSSL database sidecars, exports, and backups appear as the
corresponding commands populate it:

```text
~/.config/platform-infrastructure/pki/
├── inventory/
│   └── services.yml.example
├── authorities/
│   ├── roots/
│   │   └── g1/
│   └── intermediates/
│       └── g1-i1/
├── state/
│   ├── active-issuer
│   ├── bootstrap-root
│   ├── generation-reservations/
│   └── rollover/
├── locks/
├── services/
│   └── <service>/
│       ├── certs/
│       ├── chain/
│       ├── csr/
│       ├── private/
│       ├── openssl.cnf
│       └── issuer
├── export/
│   └── ansible/
└── backups/
```

OpenSSL creates `index.txt.old`, `index.txt.attr.old`, and `serial.old`
database sidecars during CA mutations. It also stores issued-certificate copies
under `newcerts/`. These are active CA state, not obsolete files, and must stay
with the corresponding CA database. Renewal archives are similarly active
history under `services/<service>/archive/`.

PKI directories are owner-only mode `700`. Private keys, CSRs, inventory,
private configuration, CA database files, and database sidecars must be mode
`600` or stricter. Certificates, chains, and issued-certificate copies under
`newcerts/` may be mode `644`, but must never be group- or world-writable.
Tool-managed renewal archives under `services/<service>/archive/` remain active
PKI history. Do not keep other retired keys or passphrase files in an active
PKI tree. Quarantine unmanaged material awaiting review in a separate
owner-only directory outside `pki/` so PKI backups and helpers do not treat it
as current state.

Use a temporary namespace for testing:

```bash
platform-pki-init --namespace /tmp/platform-pki-test
```

The initializer creates only `inventory/services.yml.example`; it does not
create active inventory. Existing examples are preserved by default. Use
`--force` to refresh the example. Active inventory, CA keys, certificates, and
database state are never overwritten by the initializer. Historical local
copies of `pki.env` or `openssl-*.cnf.tpl` remain untouched until explicit
legacy migration quarantines them with migration provenance.

Namespace and PKI paths must be absolute, must not be the filesystem root, and
must not traverse symbolic links. Existing PKI state containing symbolic links
or hard-linked files is rejected before permissions or files are changed.
The PKI directory may be inside the namespace, as it is by default, but it must
not equal or contain the namespace.
Missing path components are created atomically and existing components must be
owned by the current user or root without unsafe writable permissions.
Existing private directories and key files are also checked before
initialization continues; private keys must already be mode `600` or stricter.

The path checks protect against replacement by other local users. Processes
running as the same user, and privileged root processes, are inside the trusted
boundary because portable Bash cannot perform all mutations relative to locked
directory descriptors.

## Create CA Material

Create the root CA:

```bash
platform-pki-root-create \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL"
```

The root key is encrypted by default. `--days` defaults to
`PLATFORM_PKI_ROOT_DAYS`, or 3650 when that environment variable is unset.
Root key, certificate, configuration, and database state are staged as a new
immutable generation. A clean namespace allocates `authorities/roots/g1`.
Publication records a consumed generation reservation and
`state/bootstrap-root`; it does not select an active issuer. A failed or
interrupted allocation remains permanently `abandoned`, so a retry allocates
the next root ID instead of reusing key identity under the old ID.
Another root is refused while that bootstrap root exists. `--force` cannot
replace a completed bootstrap root, an active issuer, or state with descendants;
future generation changes use `platform-pki-ca-rollover`.

For isolated test namespaces only, use:

```bash
platform-pki-root-create \
  --namespace /tmp/platform-pki-test \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL" \
  --allow-unencrypted-root-key
```

Create the intermediate CA:

```bash
platform-pki-intermediate-create \
  --name "Platform Example Intermediate CA" \
  --org "Platform Example" \
  --country "PL"
```

The first clean bootstrap allocates immutable intermediate generation `g1-i1`.
Its key is encrypted by default. `--days` defaults to
`PLATFORM_PKI_INTERMEDIATE_DAYS`, or 1825 when that environment variable is
unset. Intermediate state and the root database update are staged privately.
After the allocated intermediate verifies against the exact bootstrap root, the command publishes
`state/active-issuer` and removes `state/bootstrap-root`. Existing active state
cannot be replaced with `--force`; use the rollover workflow for future
generations. Failed or interrupted intermediate IDs remain abandoned, and a
retry allocates the next intermediate ID under the same bootstrap root. The
identity-bound staging subtree that temporarily contains the copied root key is
durably removed before commit. An interruption during that terminal cleanup can
only resume cleanup; earlier intermediate bootstrap states remain rollback-only.

Services issued or renewed afterward record the selected pair in mode-600
`services/<service>/issuer`. Renewal archives the previous issuer record with
the previous service material. Verification resolves the recorded pair, not the
issuer that happens to be active for new issuance.

All operations use persistent files under `locks/` with `flock`. Acquisition is
`lifecycle`, `root`, `intermediate`, `inventory`, then `export` as required, and
release is reverse. Lock files are current-user-owned, singly linked, mode 600,
and descriptor identity is checked through `/proc/self/fd` before locking.
After locks are held, normal commands reject an uncommitted migration or
rollover journal before reading operational snapshots. Rollover `status` is the
read-only exception and reports recovery-required state with status 2.

`SIGKILL`, host failure, or storage failure cannot run transaction cleanup.
After an unclean stop, treat journals, recovery markers, private staging
directories, and partially published state as incident evidence. Persistent
lock files are normal and must not be deleted; `flock` ownership, not file
existence, indicates an active operation. First stop or account for every PKI
process, inspect process state and artifact timestamps, and make a protected
filesystem-level copy of the complete PKI tree without invoking a normal PKI
command that rejects unresolved recovery state.
Compare configuration, key, certificate, CSR, chain, root `index.txt`, serial,
database sidecars, and `newcerts/` entries with the staging data and a known-good
backup. Validate matching keys and certificates and verify the certificate
chain. If publication is partial or consistency cannot be established, restore
the complete affected transaction state from a known-good protected backup.
Only after proving that no operation is active and the published state is
consistent or restored should an operator resolve the journal and securely
remove reviewed staging material. Re-run `platform-pki-ca-rollover status` and
the relevant verification commands before resuming CA mutations.

For isolated test namespaces only, use
`--allow-unencrypted-intermediate-key`.

For non-interactive automation, provide passphrases through restricted files instead of typing them at OpenSSL prompts:

```bash
# Example assumes these files are populated by a secret manager with mode 600.
# /run/secrets/platform-pki-root-pass
# /run/secrets/platform-pki-intermediate-pass

platform-pki-root-create \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL" \
  --root-pass-file /run/secrets/platform-pki-root-pass

platform-pki-intermediate-create \
  --name "Platform Example Intermediate CA" \
  --org "Platform Example" \
  --country "PL" \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

Passphrase files must exist, be readable by the current user, and must not be group- or world-accessible. OpenSSL uses the first line of each passphrase file; that first line must be at least 16 characters and contain non-whitespace characters. Keep passphrase files outside Git and prefer temporary secret-manager mounts such as `/run/secrets` over long-lived files. Omit pass-file options to let OpenSSL prompt interactively.

## Service Inventory

Service certificates are issued from:

```text
~/.config/platform-infrastructure/pki/inventory/services.yml
```

Install the canonical private-Git source after initialization:

```bash
platform-pki-inventory-install
platform-pki-inventory-install --private-repo /absolute/path/to/platform-private
```

The default private repository is exactly `../platform-private`, resolved from
the physical current directory. The command reads
`<private-repo>/pki/services.yml`, validates one safely staged copy, and
atomically publishes those exact bytes as mode `600`. It rejects linked,
foreign-owned, or writable source and destination files, unsafe path ancestry,
source paths inside the PKI tree, malformed inventory, and concurrent lock
contention. Identical protected content is a no-op; identical content with a
safe non-writable mode is atomically normalized to mode `600`.

The inventory parser supports this strict YAML subset:

```yaml
services:
  platform-example:
    common_name: app.example.internal
    dns:
      - app.example.internal
      - app
    ips:
      - 192.0.2.10
    days: 397
```

The supported format is a restricted YAML subset, not general YAML. There must
be exactly one `services:` mapping and at least one uniquely named service.
Every service has exactly one `common_name`, optional unique `dns` and `ips`
block lists, and optional decimal `days` from 1 through 365000. SANs are mandatory: a
service must define at least one value under `dns:` or `ips:`. Indentation is
exactly two spaces for services, four for fields, and six before list dashes.
Blank lines, whole-line comments, and one leading `---` are allowed. Duplicate
names, fields, or SANs; tabs; inline comments; unknown fields including
`deploy`; anchors, aliases, tags, flow values, multiline values, extra
documents, and trailing top-level content are rejected.

Inventory values are written into OpenSSL configuration files during issuance and renewal. `common_name` and `dns` entries must be DNS names using only letters, digits, dots, and hyphens; wildcard names are not supported. `ips` entries must be IPv4 addresses. Inventory values must not contain OpenSSL configuration expansion syntax such as `$ENV::SECRET_NAME`.

Issuance, renewal, verification, certificate printing, expiry listing, and
Ansible export acquire the current root, intermediate, and inventory operation
locks in that order. Each command privately copies and validates active
inventory once, then uses only its canonical parsed snapshot for the rest of
the invocation. Locks are released inventory first, then intermediate and root.

## Issue And Verify A Service Certificate

```bash
platform-pki-service-issue \
  platform-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki-service-verify platform-example
```

Use `--min-days` to set the required remaining validity. Verification checks
chain trust, the private-key match, certificate purpose, inventory SANs, and
remaining lifetime.

Generated files:

```text
~/.config/platform-infrastructure/pki/services/platform-example/private/tls.key
~/.config/platform-infrastructure/pki/services/platform-example/csr/tls.csr
~/.config/platform-infrastructure/pki/services/platform-example/certs/tls.crt
~/.config/platform-infrastructure/pki/services/platform-example/chain/ca-chain.crt
~/.config/platform-infrastructure/pki/services/platform-example/chain/fullchain.crt
~/.config/platform-infrastructure/pki/services/platform-example/openssl.cnf
```

`platform-pki-service-issue` refuses to overwrite an existing service certificate. Use `platform-pki-service-renew` after the first issuance.
Issuance validates inventory, CA state, paths, ownership, modes, links, file
types, and the next CA serial destination before mutation. It then holds the
root and intermediate operation locks in fixed order while staging signing,
publishing the service artifacts and intermediate database update, and running
`platform-pki-service-verify`. Signing, publication, verification, and handled
signal failures restore identity-matched prior state. Existing private keys are
reused by default; `--rotate-key` archives the old key only when the complete
transaction commits.

The intermediate OpenSSL configuration used for issuance must retain the
managed signing contract. Include directives, global directives, external or
escaping CA paths, unsupported `CA_default` directives, and alternate CA or
policy selection are rejected before signing. Database, serial, issued-certificate,
private-key, certificate, and optional CRL or random-state paths must remain
under the intermediate CA directory and are redirected to private staging.
Every publication destination is identity-checked against its locked preflight
snapshot immediately before replacement or no-clobber publication.

## Renew A Service Certificate

Renewal archives the previous certificate material under:

```text
~/.config/platform-infrastructure/pki/services/<service>/archive/<timestamp>/
```

By default, renewal reuses the existing service private key:

```bash
platform-pki-service-renew \
  platform-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

Rotate the service private key explicitly when needed:

```bash
platform-pki-service-renew platform-example --rotate-key
```

Renewal requires existing service private-key state and validates inventory,
CA state, path ancestry, file ownership, modes, links, and the closed OpenSSL
signing contract before mutation. It holds root and intermediate operation
locks in that order while signing against staged CA state, archiving previous
service files, publishing replacements, and verifying the result. Signing,
publication, verification, and handled signal failures restore the CA database,
service key, certificate files, and archive state. If a published destination
is replaced by foreign state during recovery, that state and the locked staging
directory are preserved for manual recovery rather than overwritten.

The renew command does not deploy anything to remote hosts. Deployment belongs in `platform-config`.

## Print Certificate Details

```bash
platform-pki-print-cert platform-example
```

The command prints subject, issuer, serial, validity dates, SANs, key usage, extended key usage, and SHA-256 fingerprint.

Use `platform-pki-print-cert --help` for the generated command reference and
`platform-pki-print-cert --version` for the installed platform-tools version.

## Export For Ansible

Export all generated inventory services by default:

```bash
platform-pki-export-ansible --force
```

Export only selected services by passing names:

```bash
platform-pki-export-ansible platform-example --force
```

Output layout:

```text
~/.config/platform-infrastructure/pki/export/ansible/
├── ca/
│   └── root-ca.crt
└── services/
    └── platform-example/
        ├── tls.crt
        ├── tls.key
        ├── ca-chain.crt
        └── fullchain.crt
```

The export directory contains service private keys and must stay outside Git.
Custom `--export-dir` values must be absolute paths. Existing export path components must be owned by the current user or root, must not be unsafe writable directories, and must not contain symlink components. The immediate export parent must already exist, be owned by the current user, and must not be group- or world-writable. The helper creates a fresh private export tree and publishes temporary files with exact-target, no-clobber hard links.

An export inside the PKI tree must stay under its `export/` directory. Forced
replacement of an existing custom export requires the marker written by this
version of the helper; the default `export/ansible` path remains compatible
with exports created by earlier versions.

Use `platform-pki-export-ansible --help` for generated option details and
`platform-pki-export-ansible --version` for the installed version.

## Back Up PKI State

Backups include the full PKI working directory, including CA private keys, service private keys, issued certificates, CSRs, CA database files, inventory, and exports. When the backup output directory is inside the PKI directory, it is excluded from the archive to avoid recursive backups.

The backup command acquires the full lifecycle, root, intermediate, inventory,
and export lock matrix and accepts only a complete legacy or generation-aware
layout. It refuses unresolved recovery state. Each successful archive also
publishes a mode-600 `<archive>.receipt` that binds the archive identity and
SHA-256 digest to its layout and public-state manifest digest. Keep that receipt
with the protected archive; one-time legacy migration requires it.

Use `age` recipient encryption for non-interactive backups:

```bash
platform-pki-backup --age-recipient "$AGE_RECIPIENT"
```

If no `--age-recipient` is provided, `age` passphrase mode is used and prompts interactively:

```bash
platform-pki-backup
```

Output path:

```text
~/.config/platform-infrastructure/pki/backups/platform-pki-YYYYMMDD-HHMMSS.tar.gz.age
```

The default `~/.config/platform-infrastructure/pki/backups/` output directory is not included in generated backup archives.

Plain unencrypted archives require an explicit override:

```bash
platform-pki-backup --allow-plain-backup
```

Use `platform-pki-backup --help` for generated option details and
`platform-pki-backup --version` for the installed platform-tools version.

Plain backup output uses `.tar.gz` and still contains secrets. Keep it outside Git and move it to encrypted storage as soon as practical.

## Migrate Legacy CA State

First install the canonical inventory and create a new independent protected
backup. Then inspect status and migrate with that backup's receipt:

```bash
platform-pki-inventory-install
platform-pki-backup --age-recipient "$AGE_RECIPIENT"
platform-pki-ca-rollover status
platform-pki-ca-rollover migrate \
  --backup-receipt /secure/path/platform-pki-....tar.gz.age.receipt
```

`status` exits 0 for ready generation-aware state, 1 for legacy state, and 2
for recovery-required, incomplete, or ambiguous state. It is the only rollover
operation allowed to inspect an unresolved journal.

Resume or roll back an interrupted migration only through its exact journaled
transaction ID:

```bash
platform-pki-ca-rollover recover \
  --transaction migrate-20260730-120000-1234 \
  --action rollback \
  --yes
```

Recovery validates the journal, backup receipt, transaction directory,
identity-and-digest-bound service snapshot, and authority identities before
mutation. A migration command failure never starts a second in-process rollback:
it preserves an unresolved journal and marker, blocks normal commands, and
requires explicit `recover`. Missing or replaced evidence is preserved and rejected. Recovery
records and fsyncs pending and completed state around every mutation, so another
`recover` invocation can continue after a recovery-process crash. Fresh root
and first-intermediate bootstrap operations use the same durable journal
discipline and automatically roll back handled failures; `--force` never
recursively deletes unproven authority state.

Interactive migration requires typing the exact root and intermediate public
SHA-256 fingerprints. Non-interactive migration additionally requires `--yes`,
`--expected-root-sha256`, and `--expected-intermediate-sha256`. Use
`--private-repo` when the canonical private repository is not
`../platform-private` relative to the current directory.

Migration verifies the backup receipt and archive identity, public certificate
chain, current public-state digest, and semantic equality between installed
inventory and `<private-repo>/pki/services.yml`. It records a recovery journal,
reserves `g1` and `g1-i1`, and moves legacy CA directories on the same
filesystem. It regenerates managed OpenSSL paths, publishes service issuer
records, quarantines legacy scaffolding with provenance, and publishes
`state/active-issuer` last. It durably publishes the identity-bound migration
provenance directory before marking the transaction journal committed. Existing
keys are not copied, hashed, parsed, or regenerated. Provenance includes a
deterministically ordered relative-path manifest with object identities and
non-secret file digests; potentially private quarantine contents are marked
secret and are not hashed. A completed valid migration
is an idempotent no-op.

The migration journal binds original and published identities for managed
configurations, reservations, the backup-session record, service issuer
records, quarantined entries, and the active manifest. Recovery accepts only
the exact journaled legacy or generation location for each authority and fails
closed if both paths exist. Bootstrap rollback likewise restores only exact
transaction-owned CA database, sidecar, serial, and `newcerts/` state. A fully
verified bootstrap rollback publishes an `abandoned` reservation and never
deletes or reuses that generation ID; retries allocate the next available ID.

Backup receipts are valid for legacy migration for 24 hours, carry a unique
session, and bind both public state and metadata-only private state, including
keys and files under passphrase or quarantine paths. Migration does not read or
hash private-key or passphrase content.

Certificate issuance checks actual ASN.1 validity against the issuer.
`--issuer-safety-days` defaults to one day for first-intermediate creation,
service issuance, and renewal.

Inventory installation prefers atomic exchange. A guarded ordinary atomic-rename
fallback is supported when the filesystem or rootless container runtime does
not support `RENAME_EXCHANGE`. The fallback performs a final identity recheck
under cooperative same-UID lifecycle/root/intermediate/inventory locks. This excludes
cooperating commands but does not protect against a malicious same-UID process,
which remains inside the documented trust boundary.

Phase 5 implements only `migrate`, `recover`, and `status`. Candidate
preparation, activation, retirement, and completion remain deferred.

## List Expiry

```bash
platform-pki-list-expiry --warn-days 90 --critical-days 30
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All certificates are OK. |
| `1` | Warning threshold reached, or a parser/configuration error occurred. |
| `2` | At least one certificate is within the critical threshold. |
| `3` | A generated certificate is missing. |

The shared generated CLI contract uses status 1 for parser and configuration
errors. Inspect stderr to distinguish those errors from a warning report.
Missing status 3 takes precedence when other certificates are warning or
critical.

## Safety Rules

Do not commit anything generated under `~/.config/platform-infrastructure/pki/`.

Do not commit CA passphrases or passphrase files. If automation needs passphrase files, keep them outside Git, use mode `600` or stricter, use a first-line passphrase of at least 16 characters with non-whitespace content, and prefer short-lived secret-manager mounts.

Do not issue service certificates without SANs.

Do not use the root CA to sign service certificates directly.

Deployment to hosts belongs in `platform-config`, not in these helper scripts.

## Future Migration To ACME Or step-ca

These OpenSSL helpers are an initial private PKI, bootstrap path, break-glass fallback, and appliance support path.

A future `step-ca` or ACME workflow can replace manual service certificate issuance for services that support automated enrollment. The surrounding pieces remain useful:

- CA trust installation through `platform-config`.
- Certificate deployment for non-ACME appliances.
- Expiry checks and monitoring alerts.
- Documentation of certificate ownership and file locations.
- OpenSSL-based fallback for recovery or isolated environments.
