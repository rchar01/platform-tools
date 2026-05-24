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
- `tar`
- GNU `date` for certificate expiry calculations
- standard Unix tools such as `awk`, `cmp`, `cp`, `find`, `grep`, `mkdir`, `mktemp`, and `sed`

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

This creates:

```text
~/.config/platform-infrastructure/pki/
├── inventory/services.yml
├── pki.env
├── root-ca/
├── intermediate-ca/
├── services/
├── export/ansible/
└── backups/
```

Use a temporary namespace for testing:

```bash
platform-pki-init --namespace /tmp/platform-pki-test
```

## Create CA Material

Create the root CA:

```bash
platform-pki-root-create \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL"
```

The root key is encrypted by default. For isolated test namespaces only, use:

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

The intermediate key is encrypted by default. For isolated test namespaces only, use `--allow-unencrypted-intermediate-key`.

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

## Issue And Verify A Service Certificate

```bash
platform-pki-service-issue platform-example
platform-pki-service-verify platform-example
```

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

## Renew A Service Certificate

Renewal archives the previous certificate material under:

```text
~/.config/platform-infrastructure/pki/services/<service>/archive/<timestamp>/
```

By default, renewal reuses the existing service private key:

```bash
platform-pki-service-renew platform-example
```

Rotate the service private key explicitly when needed:

```bash
platform-pki-service-renew platform-example --rotate-key
```

The renew command does not deploy anything to remote hosts. Deployment belongs in `platform-config`.

## Print Certificate Details

```bash
platform-pki-print-cert platform-example
```

The command prints subject, issuer, serial, validity dates, SANs, key usage, extended key usage, and SHA-256 fingerprint.

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

## Back Up PKI State

Backups include the full PKI working directory, including CA private keys, service private keys, issued certificates, CSRs, CA database files, inventory, exports, and existing backups.

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

Plain unencrypted archives require an explicit override:

```bash
platform-pki-backup --allow-plain-backup
```

Plain backup output uses `.tar.gz` and still contains secrets. Keep it outside Git and move it to encrypted storage as soon as practical.

## List Expiry

```bash
platform-pki-list-expiry --warn-days 90 --critical-days 30
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All certificates are OK. |
| `1` | At least one certificate is within the warning threshold. |
| `2` | At least one certificate is within the critical threshold. |
| `3` | Script/config error or missing generated certificate. |

## Safety Rules

Do not commit anything generated under `~/.config/platform-infrastructure/pki/`.

Do not store CA passphrases in files.

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
