# Changelog

All notable changes to `platform-tools` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a pinned Podman development environment with Bashly, test, lint, and generated-artifact verification tooling.
- Added repository version `1.4.0-dev` and generated `--version` support to `platform-config-init`.
- Added `platform-proxmox-vm-snapshot` with exact VM or dual-tag environment selection, structured Proxmox preflight, dry-run support, destructive confirmation, target-drift protection, and partial-operation summaries. Mutating environment workflows remain gated on reconciled `platform-infra` tags and a manually verified dry-run target set.
- Added a reusable live-acceptance runbook for selector, snapshot, rollback, negative-path, evidence, and cleanup checks on disposable VMs.

### Changed

- Migrated `platform-config-init` argument parsing and help generation to Bashly while preserving namespace creation, permissions, existing-file handling, and legacy-path warnings.
- Migrated `platform-vm-env-collect` CLI and environment validation to Bashly while preserving report format version `1.1.0`, collection, redaction, and archive behavior.
- Migrated `platform-pki-print-cert` parsing and help generation to Bashly while preserving external PKI library discovery and certificate detail output.
- Migrated `platform-pki-list-expiry` parsing, help, and threshold validation to Bashly, and fixed missing-certificate status 3 being overwritten by a later critical status.
- Migrated `platform-pki-service-verify` parsing, help, and minimum-lifetime validation to Bashly while preserving all certificate verification checks.
- Migrated `platform-pki-init` parsing and help generation to Bashly, added pre-mutation path and template validation, removed broad recursive permission mutation, and made forced template replacement atomic.
- Migrated `platform-pki-backup` parsing and help generation to Bashly while preserving encrypted defaults, repeatable recipients, output modes, and recursive-backup exclusions; output is now published atomically without overwriting concurrent backups.
- Migrated `platform-pki-export-ansible` parsing and help generation to Bashly while preserving service selection and private-key modes; forced replacement now rejects source-overlapping or unmarked custom directories and file publication is no-clobber.
- Migrated `platform-pki-root-create` parsing and help generation to Bashly while preserving encrypted-key and lifetime defaults; PKI paths, CA database files, and output destinations are validated before mutation, and staged root replacement restores all originals after generation, publication, or handled-interruption failures.
- Migrated `platform-pki-intermediate-create` parsing and help generation to Bashly while preserving encrypted-key and lifetime defaults; intermediate material, missing intermediate database defaults, and root CA database updates are staged and restored together after generation, signing, publication, or handled-interruption failures. Root and intermediate CA operation locks use fixed ordering to exclude concurrent root replacement and cooperating intermediate consumers across complete transactions, and rollback removes only identity-matched files published by its transaction.
- Migrated `platform-ssh-init` parsing and help generation to Bashly while preserving interspersed config-file input, strict non-evaluating config loading, CLI precedence, key creation and reuse, public-key output, SSH config writing, and access testing. Invalid action prerequisites, directive-injection values, unsafe key or SSH-config paths, and duplicate aliases are now rejected before key generation; reconstructed public keys use cleanup-safe no-clobber publication.

## [1.3.0] - 2026-07-10

### Added

- Added `platform-bastion-policy` for validating and rendering Kubernetes bastion access-policy documents.

### Changed

- Refined the README landing page with a branded header, clearer install notes, and license information.

### Security

- Hardened `platform-vm-env-collect` to write reports and archives under a private random `/tmp` directory with owner-only permissions.
- Hardened `platform-bastion-policy` to create output files with owner-only permissions and refuse existing output paths.
- Hardened `platform-bastion-policy` Linux user and group validation to reject newline-suffixed identity names.
- Hardened PKI passphrase-file validation to reject empty, whitespace-only, or shorter-than-16-character first lines.
- Excluded in-tree PKI backup output directories from `platform-pki-backup` archives to prevent recursive backup growth.
- Hardened `platform-pki-export-ansible` to reject unsafe export paths, untrusted path ancestors, and destination symlinks.
- Hardened PKI service inventory validation to reject OpenSSL configuration expansion syntax in certificate names and SANs; `ips` inventory entries are now explicitly IPv4-only.

## [1.2.0] - 2026-05-25

### Added

- Added non-interactive passphrase file support for encrypted PKI root, intermediate, service issuance, and service renewal operations.
- Added PKI documentation and README guidance for passphrase-file automation.
- Added `AGENTS.md` with repository-specific workflow, verification, security, and release guidance for future agent sessions.

### Changed

- Hardened PKI passphrase file validation to require readable files with no group or world permissions.

### Fixed

- Rejected conflicting PKI options that combine passphrase files with unencrypted CA key creation.
- Updated the existing-service certificate message to point directly at `platform-pki-service-renew`.

## [1.1.0] - 2026-05-24

### Added

- Added initial OpenSSL PKI helpers: `platform-pki-init`, `platform-pki-root-create`, `platform-pki-intermediate-create`, `platform-pki-service-issue`, `platform-pki-service-verify`, and `platform-pki-list-expiry`.
- Added PKI renewal, certificate detail printing, and Ansible export helpers: `platform-pki-service-renew`, `platform-pki-print-cert`, and `platform-pki-export-ansible`.
- Added `platform-pki-backup` for encrypted `age` backups, with explicit opt-in for plain `.tar.gz` backups.
- Added PKI templates and shared helper library under `templates/pki/` and `lib/`.
- Added `docs/pki-openssl.md` for PKI helper usage and safety rules.
- Added README requirements for core, PKI, SSH, Proxmox, and optional verification tools.

### Changed

- Changed the local secret convention to include `pki/` as a top-level namespace for PKI CA state, issued certificates, exports, and backups.
- Changed `platform-config-init` to create `pki/` alongside `infra/` and `config/`.
- Changed `make install` to install shared PKI assets into `SHARE_DIR`.
- Renamed `vm-env-collect` to `platform-vm-env-collect` for CLI naming consistency.

### Compatibility

- `vm-env-collect` was removed. Use `platform-vm-env-collect` instead.

## [1.0.0] - 2026-05-23

### Added

- Added `platform-ssh-init` for purpose-specific SSH keypair creation, optional SSH config output, direct CLI input, config-file input, public-key printing, and access testing.
- Added `vm-env-collect` for collecting Rocky Linux VM rebuild facts into local archives while redacting obvious sensitive values by default.
- Added `platform-config-init` for creating the shared outside-Git local secret namespace at `~/.config/platform-infrastructure/`.
- Added `platform-proxmox-token-init` for bootstrapping the Proxmox API user/token used by OpenTofu workflows, including SSH execution and optional local token-file writing.
- Added `platform-proxmox-vm-cleanup` for safely stopping and destroying exactly one known Proxmox VM by VMID.
- Added documentation for SSH identity workflows, VM environment collection, Proxmox token bootstrap, VM cleanup, secret namespace ownership, and OpenTofu-to-Ansible handoff boundaries.
- Added brand assets under `assets/brand/`.

### Changed

- Changed the local secret convention to a major-namespace layout: `infra/` for infrastructure bootstrap secrets and `config/` for service/Ansible secrets.
- Changed the documented Proxmox token path to `~/.config/platform-infrastructure/infra/proxmox.token`.
- Changed the default Proxmox token ID to `platform`.
- Changed `platform-config-init` to avoid creating concrete project/service secret skeletons; downstream projects now own their own subdirectories and files.
- Removed shipped SSH config examples; real operator config files belong in private repositories such as `platform-private`.

### Security

- Hardened SSH config parsing so `platform-ssh-init` treats config files as strict `NAME=value` data rather than shell scripts.
- Corrected SSH private key modes to `600` and public key modes to `644` when reusing existing keys.
- Hardened Proxmox token parsing so raw `pveum` token output is not printed when parsing fails.
- Made raw process environment capture in `vm-env-collect` opt-in with `COLLECT_ENV=1`.
- Added validation for sensitive collector flags so only `0` or `1` are accepted.

### Compatibility

- `platform-config-init` preserves legacy top-level config files such as `proxmox-token`, `proxmox.env`, `codeberg.env`, `ansible.env`, and `backup.env`, but no longer creates or migrates them automatically.
