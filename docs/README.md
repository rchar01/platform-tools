# Documentation Index

Use this page as a navigation index for `platform-tools` docs.

Canonical repository: <https://codeberg.org/rch/platform-tools>

All shared platform helper tools are installed from `platform-tools`. Related platform repositories follow the Codeberg `rch/platform-*` namespace pattern.

## Start Here

- [`../README.md`](../README.md): Tool overview, install command, and high-level usage.
- [`../Makefile`](../Makefile): Supported local entry points. Run `make help` to see them.
- [`development.md`](./development.md): Separate Podman development and test images, Bashly generation, shell linting, and generated-file verification.

## Docs In This Tree

- [`ssh-identity-helper.md`](./ssh-identity-helper.md): How to use `platform-ssh-init` with CLI flags or config files, downstream repository patterns, private config storage, and CI/CD expectations.
- [`platform-vm-env-collect.md`](./platform-vm-env-collect.md): How to use `platform-vm-env-collect`, inspect generated archives, and avoid committing collected VM data.
- [`platform-config-init.md`](./platform-config-init.md): How to create the outside-Git local secret namespace under `~/.config/platform-infrastructure/`.
- [`bastion-policy.md`](./bastion-policy.md): How to validate and render Kubernetes bastion access-policy documents.
- [`pki-openssl.md`](./pki-openssl.md): How to use the OpenSSL PKI helpers and keep generated PKI state outside Git.
- [`pki-gitlab-package-exchange.md`](./pki-gitlab-package-exchange.md): Proposed production GitLab 18.11.3 Generic Package exchange for public host-local PKI workflow artifacts.
- [`pki-host-local-csr-development-runbook.md`](./pki-host-local-csr-development-runbook.md): Development-only direct SSH/SFTP registry migration design and manual handoff; not executable or crash-safe.
- [`proxmox-token-init.md`](./proxmox-token-init.md): How to bootstrap the Proxmox API user/token with `platform-proxmox-token-init`.
- [`proxmox-vm-cleanup.md`](./proxmox-vm-cleanup.md): How to safely stop and destroy exactly one Proxmox VM by VMID.
- [`proxmox-vm-snapshot.md`](./proxmox-vm-snapshot.md): How to manage short-lived Proxmox VE 9 development snapshots safely.
- [`proxmox-vm-snapshot-acceptance.md`](./proxmox-vm-snapshot-acceptance.md): How to run live acceptance against the isolated disposable VM environment.
- [`handoffs/config-namespace-handoff.md`](./handoffs/config-namespace-handoff.md): Downstream ownership notes for the local secret namespace.
- [`handoffs/pki-host-local-csr-handoff.md`](./handoffs/pki-host-local-csr-handoff.md): Implemented host-local signer contract and future downstream activation contract.
- [`handoffs/tofu-ansible-handoff.md`](./handoffs/tofu-ansible-handoff.md): Example handoff that separates OpenTofu infrastructure work from Ansible guest configuration.

## Common Tasks

- Install shared platform tools: use [`../README.md`](../README.md).
- Generate a purpose-specific SSH keypair: use [`ssh-identity-helper.md`](./ssh-identity-helper.md).
- Create a cloud-init public key for `platform-infra`: use [`ssh-identity-helper.md`](./ssh-identity-helper.md).
- Decide where real SSH configs live: use [`ssh-identity-helper.md`](./ssh-identity-helper.md).
- Collect VM rebuild facts: use [`platform-vm-env-collect.md`](./platform-vm-env-collect.md).
- Create the outside-Git local secret namespace: use [`platform-config-init.md`](./platform-config-init.md).
- Create internal TLS certificates: use [`pki-openssl.md`](./pki-openssl.md).
- Publish or resolve an exact certificate-only CSR export: use [`pki-openssl.md`](./pki-openssl.md#immutable-certificate-only-export).
- Plan production CI exchange through GitLab Generic Packages: use [`pki-gitlab-package-exchange.md`](./pki-gitlab-package-exchange.md).
- Review the direct development-host registry migration design/manual handoff: use [`pki-host-local-csr-development-runbook.md`](./pki-host-local-csr-development-runbook.md).
- Inspect or migrate legacy PKI CA state: use [`pki-openssl.md`](./pki-openssl.md#migrate-legacy-ca-state).
- Validate or render bastion access policy: use [`bastion-policy.md`](./bastion-policy.md).
- Bootstrap the Proxmox API token identity: use [`proxmox-token-init.md`](./proxmox-token-init.md).
- Clean up one known Proxmox VM: use [`proxmox-vm-cleanup.md`](./proxmox-vm-cleanup.md).
- Manage one development VM snapshot: use [`proxmox-vm-snapshot.md`](./proxmox-vm-snapshot.md).
- Validate snapshot behavior on disposable VMs: use [`proxmox-vm-snapshot-acceptance.md`](./proxmox-vm-snapshot-acceptance.md).

## Key Repo Paths

- [`../bin/platform-ssh-init`](../bin/platform-ssh-init): Shared SSH identity helper.
- [`../bin/platform-vm-env-collect`](../bin/platform-vm-env-collect): VM environment collector.
- [`../bin/platform-config-init`](../bin/platform-config-init): Local outside-Git config initializer.
- [`../bin/platform-proxmox-token-init`](../bin/platform-proxmox-token-init): Proxmox API token bootstrap helper.
- [`../bin/platform-proxmox-vm-cleanup`](../bin/platform-proxmox-vm-cleanup): Safe single-VM Proxmox cleanup helper.
- [`../bin/platform-proxmox-vm-snapshot`](../bin/platform-proxmox-vm-snapshot): Safe Proxmox VE 9 development snapshot helper.
- [`../bin/platform-pki`](../bin/platform-pki): Unified Python PKI migration interface with shared runtime, filesystem, fork-safe ordered advisory-lock, and bounded Linux durable-publication primitives; init and the read-oriented pilot handlers are operational.
- [`../bin/platform-pki-init`](../bin/platform-pki-init): PKI working directory initializer.
- [`../bin/platform-pki-csr-trust-install`](../bin/platform-pki-csr-trust-install): Strict public-trust installer for authenticated host-local CSR signing.
- [`../bin/platform-pki-csr-recover`](../bin/platform-pki-csr-recover): Deterministic recovery for interrupted host-local CSR signing.
- [`../bin/platform-pki-certificate-export`](../bin/platform-pki-certificate-export): Exact immutable certificate-only CSR export publisher and resolver.
- [`../bin/platform-pki-csr-candidate`](../bin/platform-pki-csr-candidate): Authenticated candidate verification, finalization, abandonment, and recovery state.
- [`../bin/platform-pki-root-create`](../bin/platform-pki-root-create): Root CA creation helper.
- [`../bin/platform-pki-intermediate-create`](../bin/platform-pki-intermediate-create): Intermediate CA creation helper.
- [`../bin/platform-pki-service-issue`](../bin/platform-pki-service-issue): Service certificate issuance helper.
- [`../bin/platform-pki-service-renew`](../bin/platform-pki-service-renew): Service certificate renewal helper.
- [`../bin/platform-pki-service-verify`](../bin/platform-pki-service-verify): Service certificate verification helper.
- [`../bin/platform-pki-list-expiry`](../bin/platform-pki-list-expiry): Certificate expiry listing helper.
- [`../bin/platform-pki-print-cert`](../bin/platform-pki-print-cert): Certificate detail printing helper.
- [`../bin/platform-pki-export-ansible`](../bin/platform-pki-export-ansible): Ansible export helper for generated PKI files.
- [`../bin/platform-pki-backup`](../bin/platform-pki-backup): PKI state backup helper.
- [`../bin/platform-pki-custody-report`](../bin/platform-pki-custody-report): Read-only PKI encryption, custody, and backup-policy report helper.
- [`../bin/platform-pki-ca-passphrase-verify`](../bin/platform-pki-ca-passphrase-verify): Read-only active CA passphrase and certificate-match verification helper.
- [`../bin/platform-pki-ca-rollover`](../bin/platform-pki-ca-rollover): Generation state inspection, legacy migration, and rollover candidate preparation helper.
- [`../bin/platform-bastion-policy`](../bin/platform-bastion-policy): Bastion access-policy validation and rendering helper.
- [`../assets/brand/`](../assets/brand/): Project brand assets for release metadata and forge profiles.
- [`handoffs/`](./handoffs/): Handoff notes for downstream coding agents and platform repositories.
