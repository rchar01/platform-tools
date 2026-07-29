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
- `tar` with `--no-wildcards` support for safe backup directory exclusions
- GNU `date` for certificate expiry calculations
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
│   └── services.yml
├── pki.env
├── openssl-root.cnf.tpl
├── openssl-intermediate.cnf.tpl
├── openssl-service.cnf.tpl
├── root-ca/
│   ├── certs/
│   ├── crl/
│   ├── newcerts/
│   ├── private/
│   ├── index.txt
│   ├── index.txt.attr
│   ├── serial
│   └── crlnumber
├── intermediate-ca/
│   ├── certs/
│   ├── crl/
│   ├── csr/
│   ├── newcerts/
│   ├── private/
│   ├── index.txt
│   ├── index.txt.attr
│   ├── serial
│   └── crlnumber
├── services/
│   └── <service>/
│       ├── certs/
│       ├── chain/
│       ├── csr/
│       ├── private/
│       └── openssl.cnf
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

Existing templates and examples are preserved by default. Use `--force` to
refresh only those files; CA keys, certificates, and database state are never
overwritten by the initializer.

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
Root key, certificate, and configuration generation is staged in a private
directory before publication. Existing key or certificate files are refused
unless `--force` is used. Failed generation, partial publication, and handled
interruptions restore all original root configuration, key, and certificate
files before removing transaction state. The expanded PKI path must not contain
OpenSSL variable expansion syntax, newlines, or control characters. Before any
mutation, the PKI and root directory chain, CA database files, and root output
destinations are checked for expected types, links, ownership, and safe modes.
Root and database destinations must be regular, singly linked files in
owner-controlled, non-writable directories; symbolic and hard links are
rejected. The CA database and unrelated PKI files are not replaced by
`--force`.

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

The intermediate key is encrypted by default. `--days` defaults to
`PLATFORM_PKI_INTERMEDIATE_DAYS`, or 1825 when that environment variable is
unset. Intermediate configuration, key, CSR, certificate, chain, and the root
CA database update are staged privately before publication. Existing
intermediate key or certificate files are refused unless `--force` is used.
Failed generation, signing, partial publication, and handled interruptions
restore all original intermediate files and root CA database files. The root
database is advanced only when the complete transaction is published.
Missing intermediate CA database files are restored in staging and published
with the same transaction: an empty `index.txt`, `index.txt.attr` containing
`unique_subject = no`, and `serial` and `crlnumber` containing `1000`. Restored
files use mode `600`; valid existing database files are preserved unchanged.
Rollback tracks only destinations successfully published by the active
transaction and verifies their device/inode identity before removal. A file
that appears at a failed no-clobber destination, or replaces a published file,
is preserved rather than deleted; unresolved identity changes retain staging
and locks for operator recovery.

CA mutations use cooperative operation locks inside the CA directories. The
fixed acquisition order is root CA lock first, then intermediate CA lock, with
release in reverse order. `platform-pki-root-create` holds the root lock for its
entire generation and publication transaction. `platform-pki-intermediate-create`
holds both locks for its entire signing and publication transaction, so a
cooperating consumer cannot observe forced sequential publication. Commands
that issue or renew service certificates must take the intermediate lock when
they are migrated to this transaction contract. A command that needs both
locks must never acquire them in the opposite order.

The PKI path, identity values, CA directories, database files, prerequisites,
and output destinations are validated before mutation. Symbolic links, hard
links, foreign-owned files, unsafe writable directories, and unexpected file
types are rejected. `--force` replaces intermediate material and records a new
root signing event; it does not replace the root key, root certificate, or
unrelated PKI state.

`SIGKILL`, host failure, or storage failure cannot run the transaction cleanup
handler. After an unclean stop, treat operation-lock directories, command-lock
directories, private `.platform-pki-root-create.*` or
`.platform-pki-intermediate-create.*` staging directories, and partially
published sequential state as incident evidence. Do not blindly delete any of
them. First stop or account for every PKI process, inspect process state and
artifact timestamps, and make a protected backup of the complete PKI tree.
Compare configuration, key, certificate, CSR, chain, root `index.txt`, serial,
database sidecars, and `newcerts/` entries with the staging data and a known-good
backup. Validate matching keys and certificates and verify the certificate
chain. If publication is partial or consistency cannot be established, restore
the complete affected transaction state from a known-good protected backup.
Only after proving that no operation is active and the published state is
consistent or restored should an operator remove confirmed-stale lock
directories and securely remove reviewed staging material. Re-run the relevant
verification commands before resuming CA mutations.

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

SANs are mandatory. A service must define at least one value under `dns:` or `ips:`.

Inventory values are written into OpenSSL configuration files during issuance and renewal. `common_name` and `dns` entries must be DNS names using only letters, digits, dots, and hyphens; wildcard names are not supported. `ips` entries must be IPv4 addresses. Inventory values must not contain OpenSSL configuration expansion syntax such as `$ENV::SECRET_NAME`.

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
