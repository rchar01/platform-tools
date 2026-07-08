# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

- Hardened `platform-vm-env-collect` to write reports and archives under a private random `/tmp` directory with owner-only permissions.
- Hardened `platform-bastion-policy` to create output files with owner-only permissions and refuse existing output paths.
- Hardened PKI passphrase-file validation to reject empty, whitespace-only, or shorter-than-16-character first lines.
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
