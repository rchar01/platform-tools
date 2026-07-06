# Changelog

All notable changes to `platform-tools` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refined the README landing page with a branded header, clearer install notes, and license information.

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
