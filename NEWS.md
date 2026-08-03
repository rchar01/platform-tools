# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

- All maintained behavior and integration tests now use pytest orchestration while preserving real Bash commands, external tools, PTYs, inherited descriptors, archive operations, and SSH subprocess boundaries. The canonical container check runs the full aggregate once.
- Added `platform-pki-inventory-install` for strict, atomic mode-600 installation from `../platform-private/pki/services.yml`, with `--private-repo` override and guarded source/destination handling.
- PKI inventory now has one strict whole-file schema and one-snapshot consumption across issuance, renewal, verification, expiry listing, certificate printing, and Ansible export.
- `platform-pki-init` now writes only `services.yml.example`, preserves active inventory even with `--force`, and no longer installs unused PKI environment or OpenSSL template files.
- Fresh PKI state now begins with immutable `g1` root and `g1-i1` intermediate generations, protected active/bootstrap manifests, recorded service issuers, and persistent lifecycle-first operation locks. Failed bootstrap IDs remain abandoned and retries allocate monotonically increasing IDs.
- Added `platform-pki-ca-rollover migrate|prepare|recover|status` for verified, receipt-backed migration and immutable root or intermediate candidate preparation. Preparation preserves the active issuer; later activation and lifecycle operations remain deferred.
- PKI backups now reject incomplete or recovery-required state and publish a mode-600 receipt binding each archive to its identity, digest, layout, and public state.
- Migration and fresh bootstrap transactions now use fsynced identity-complete journals; `platform-pki-ca-rollover recover` resumes or rolls back every mutation and remains resumable if recovery itself is interrupted.
- Recovery now requires exact journaled identities for CA database files and their staged sources, configurations, reservations, issuer records, quarantine entries, backup sessions, active manifests, service snapshots, and digest-bound complete-tree manifests that omit private-content hashes. Phase 6A pre-journals sensitive child destinations, uses full nanosecond staged-source identities and immutable write-ahead transaction manifests, and binds final journal/marker unlink through terminal receipts. Rollover certificates require exact critical CA profiles and verified root self-signatures. Migration failures require explicit recovery, sensitive root-key staging is removed before intermediate commit, and verified bootstrap rollback permanently abandons rather than reuses its generation ID.
- Intermediate and service certificate publication now enforces actual ASN.1 validity against the issuer with a one-day default safety margin.
- Inventory publication prefers `RENAME_EXCHANGE` and supports a guarded rename fallback under cooperative same-UID locks, including rootless Podman filesystems.
- The development toolbox now uses a reproducible Debian 13 snapshot on `amd64` and `arm64`, with a locked Bashly bundle, pytest, and checksum-verified ShellCheck and shfmt binaries.

## v1.4.0 - 2026-07-27

- Generated help for all 16 Bashly-backed commands now uses restrained colors on interactive terminals while remaining plain for pipes, redirects, and `NO_COLOR=1`.
- Completed the Bashly migration for all 16 maintained shell commands and added one shared CLI contract for help, version, parser errors, and subcommand help.
- Aligned `platform-bastion-policy` help, version, parser-error status, and output streams with the shared command contract.
- `platform-bastion-policy` now rejects abbreviated long options consistently with the Bashly-backed commands.
- Added disposable installed-command smoke coverage for every maintained tool and installed PKI shared assets without runtime Ruby, Bashly, or checkout source paths.
- Added a pinned Podman development environment and Bashly generation workflow.
- Migrated `platform-pki-print-cert` to the shared Bashly CLI contract.
- Migrated `platform-pki-list-expiry` and made missing-certificate status 3 independent of inventory order.
- Migrated `platform-pki-service-verify` to generated parsing and validation.
- Migrated `platform-pki-init` with guarded paths and atomic template replacement.
- Migrated `platform-pki-backup` with generated repeatable recipient parsing.
- Migrated `platform-pki-export-ansible` with generated service selection.
- Migrated `platform-pki-root-create` with staged, guarded root CA replacement.
- Migrated `platform-pki-intermediate-create` with staged intermediate material, missing database initialization, root CA database updates, and ordered CA operation locks.
- Migrated `platform-pki-service-issue` with transactional service and intermediate CA publication, ordered operation locks, and rollback-safe verification.
- Migrated `platform-pki-service-renew` with transactional archival, service and intermediate CA replacement, ordered operation locks, and rollback-safe verification.
- Migrated `platform-proxmox-token-init` to generated parsing while preserving local and self-streamed SSH bootstrap behavior, conditional remote `jq`, and one-time token handling; absent token-file destinations use atomic no-clobber publication, while validated existing non-empty destinations require `--force`.
- Migrated `platform-proxmox-vm-cleanup` to generated parsing with strict SSH destinations, exact status parsing, repeated VM identity/config/status drift checks, capability-probed `qm` arguments, fixed-command SSH transport with bearer data on protected FD 3 instead of argv, bounded owner-only authorization persisted on the Proxmox host, and identity-checked cleanup of aged interrupted authorization artifacts; interactive cleanup refuses non-TTY or unavailable confirmation input unless `--yes` is supplied.
- Migrated `platform-proxmox-vm-snapshot` to generated create, list, rollback, and delete subcommands while preserving fake-backed local and self-streamed SSH safety checks; private expected-state manifests are atomically consumed and descriptor-validated through Linux procfs before use, and snapshot mutations refuse non-TTY confirmation unless `--yes` is supplied.
- Migrated and hardened `platform-ssh-init` with generated parsing, strict config loading, safe key and SSH-config path checks, no-clobber public-key reconstruction, key reuse, SSH config output, and controlled access testing.
- `platform-config-init` now provides generated, consistent help and repository version output through `--help` and `--version`.
- `platform-vm-env-collect` now uses the same generated help, version, and environment validation conventions.
- Added `platform-proxmox-vm-snapshot` for safe, short-lived Proxmox VE 9 development snapshot creation, listing, rollback, and deletion through local execution or SSH.
- Added a disposable-VM live-acceptance runbook for the snapshot helper.

## v1.3.0 - 2026-07-10

- Hardened `platform-vm-env-collect` to write reports and archives under a private random `/tmp` directory with owner-only permissions.
- Hardened `platform-bastion-policy` to create output files with owner-only permissions and refuse existing output paths.
- Hardened `platform-bastion-policy` Linux user and group validation to reject newline-suffixed identity names.
- Hardened PKI passphrase-file validation to reject empty, whitespace-only, or shorter-than-16-character first lines.
- Excluded in-tree PKI backup output directories from `platform-pki-backup` archives to prevent recursive backup growth.
- Hardened `platform-pki-export-ansible` to reject unsafe export paths, untrusted path ancestors, and destination symlinks.
- Hardened PKI service inventory validation to reject OpenSSL configuration expansion syntax in certificate names and SANs; `ips` inventory entries are now explicitly IPv4-only.
- Added `platform-bastion-policy` for validating and rendering Kubernetes bastion access-policy documents.
- Refined the README landing page with a branded header, clearer install notes, and license information.

## v1.2.0 - 2026-05-25

- Added non-interactive passphrase file support for encrypted root, intermediate, service issuance, and service renewal PKI operations.
- Added `AGENTS.md` with repository-specific workflow, verification, security, and release guidance for future agent sessions.
- Hardened PKI passphrase file handling by requiring readable owner-only files and rejecting conflicting unencrypted-key options.
- Documented passphrase-file automation examples and updated PKI secret handling guidance.

## v1.1.0 - 2026-05-24

- Reserved `~/.config/platform-infrastructure/pki/` as a top-level outside-Git namespace for PKI helper state.
- `platform-config-init` now creates `pki/` alongside `infra/` and `config/`.
- Added OpenSSL PKI helpers for initializing PKI state, creating root/intermediate CAs, issuing service certificates, verifying certificates, and listing expiry.
- Added PKI renewal, certificate detail printing, and Ansible export helpers.
- Added PKI backup support with encrypted `age` output by default and explicit plain-backup override.
- Added README requirements for core tools, PKI helpers, SSH/Proxmox helpers, and optional verification tools.
- Renamed `vm-env-collect` to `platform-vm-env-collect` for CLI naming consistency. This is a breaking command-name change.

## v1.0.0 - 2026-05-23

Initial public release of `platform-tools`.

Highlights:

- Shared operator helpers are now centralized in one repository: SSH identity setup, Rocky VM fact collection, local secret namespace initialization, Proxmox API token bootstrap, and safe single-VM cleanup.
- Local secrets now use the outside-Git namespace `~/.config/platform-infrastructure/` with major directories `infra/` and `config/`.
- The documented Proxmox token path is `~/.config/platform-infrastructure/infra/proxmox.token`.
- SSH config parsing, token output handling, file modes, and VM collector defaults were hardened for safer operator use.
- Downstream ownership of concrete config paths is documented in `docs/handoffs/config-namespace-handoff.md`.
