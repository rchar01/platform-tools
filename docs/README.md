# Documentation Index

Use this page as a navigation index for `platform-tools` docs.

Canonical repository: <https://codeberg.org/rch/platform-tools>

All shared platform helper tools are installed from `platform-tools`. Related platform repositories follow the Codeberg `rch/platform-*` namespace pattern.

## Start Here

- [`../README.md`](../README.md): Tool overview, install command, and high-level usage.
- [`../Makefile`](../Makefile): Supported local entry points. Run `make help` to see them.
- [`development.md`](./development.md): Separate Podman development and test images, Bashly generation, shell linting, and generated-file verification.

PKI documentation uses the unified `platform-pki <command>` form. The current
production package installs only `platform-pki`; see the exact v2.3.0 alias
cleanup list in the [upgrade section](../README.md#upgrade-from-v230).

## Docs In This Tree

- [`ssh-identity-helper.md`](./ssh-identity-helper.md): How to use `platform-ssh-init` with CLI flags or config files, downstream repository patterns, private config storage, and CI/CD expectations.
- [`platform-vm-env-collect.md`](./platform-vm-env-collect.md): How to use `platform-vm-env-collect`, inspect generated archives, and avoid committing collected VM data.
- [`platform-runtime-evidence.md`](./platform-runtime-evidence.md): How to collect and review secret-free PKI runtime and installation evidence without reading PKI state.
- [`platform-config-init.md`](./platform-config-init.md): How to create the outside-Git local security-sensitive namespace under `~/.config/platform-infrastructure/`.
- [`bastion-policy.md`](./bastion-policy.md): How to validate and render Kubernetes bastion access-policy documents.
- [`pki-openssl.md`](./pki-openssl.md): How to use the OpenSSL PKI helpers and keep generated PKI state outside Git.
- [`pki-offline-workspace.md`](./pki-offline-workspace.md): How to initialize an owner-only removable-media custody and staging workspace without creating signer state.
- [`pki-direct-exchange.md`](./pki-direct-exchange.md): How to move exact public PKI packages through the pinned restricted target SSH endpoint.
- [`pki-gitlab-package-exchange.md`](./pki-gitlab-package-exchange.md): Implemented GitLab 18.11.3 Generic Package exchange and its remaining production gates.
- [`pki-host-local-csr-development-runbook.md`](./pki-host-local-csr-development-runbook.md): Pointer to the implemented cross-repository host-local registry PKI workflow and its signer-side references.
- [`proxmox-token-init.md`](./proxmox-token-init.md): How to bootstrap the Proxmox API user/token with `platform-proxmox-token-init`.
- [`proxmox-vm-cleanup.md`](./proxmox-vm-cleanup.md): How to safely stop and destroy exactly one Proxmox VM by VMID.
- [`proxmox-vm-snapshot.md`](./proxmox-vm-snapshot.md): How to manage short-lived Proxmox VE 9 development snapshots safely.
- [`proxmox-vm-snapshot-acceptance.md`](./proxmox-vm-snapshot-acceptance.md): How to run live acceptance against the isolated disposable VM environment.
- [`handoffs/config-namespace-handoff.md`](./handoffs/config-namespace-handoff.md): Downstream ownership notes for the local security-sensitive namespace.
- [`handoffs/pki-host-local-csr-handoff.md`](./handoffs/pki-host-local-csr-handoff.md): Implemented host-local signer and downstream lifecycle contract.
- [`handoffs/tofu-ansible-handoff.md`](./handoffs/tofu-ansible-handoff.md): Example handoff that separates OpenTofu infrastructure work from Ansible guest configuration.

## Common Tasks

- Install shared platform tools: use [`../README.md`](../README.md).
- Generate a purpose-specific SSH keypair: use [`ssh-identity-helper.md`](./ssh-identity-helper.md).
- Create a cloud-init public key for `platform-infra`: use [`ssh-identity-helper.md`](./ssh-identity-helper.md).
- Decide where real SSH configs live: use [`ssh-identity-helper.md`](./ssh-identity-helper.md).
- Collect VM rebuild facts: use [`platform-vm-env-collect.md`](./platform-vm-env-collect.md).
- Collect PKI runtime and installation evidence: use [`platform-runtime-evidence.md`](./platform-runtime-evidence.md).
- Create the outside-Git local security-sensitive namespace: use [`platform-config-init.md`](./platform-config-init.md).
- Create internal TLS certificates: use [`pki-openssl.md`](./pki-openssl.md).
- Approve and sign an exact removable-media CSR directory: use [`pki-openssl.md`](./pki-openssl.md#offline-csr-approval-and-signing).
- Initialize removable-media custody and staging directories: use [`pki-offline-workspace.md`](./pki-offline-workspace.md).
- Publish or resolve an exact certificate-only CSR export: use [`pki-openssl.md`](./pki-openssl.md#immutable-certificate-only-export).
- Move exact packages through a restricted target endpoint: use [`pki-direct-exchange.md`](./pki-direct-exchange.md).
- Publish or download exact packages through GitLab: use [`pki-gitlab-package-exchange.md`](./pki-gitlab-package-exchange.md).
- Run the complete host-local registry PKI lifecycle: start with [`pki-host-local-csr-development-runbook.md`](./pki-host-local-csr-development-runbook.md).
- Inspect or migrate legacy PKI CA state: use [`pki-openssl.md`](./pki-openssl.md#migrate-legacy-ca-state).
- Validate or render bastion access policy: use [`bastion-policy.md`](./bastion-policy.md).
- Bootstrap the Proxmox API token identity: use [`proxmox-token-init.md`](./proxmox-token-init.md).
- Clean up one known Proxmox VM: use [`proxmox-vm-cleanup.md`](./proxmox-vm-cleanup.md).
- Manage one development VM snapshot: use [`proxmox-vm-snapshot.md`](./proxmox-vm-snapshot.md).
- Validate snapshot behavior on disposable VMs: use [`proxmox-vm-snapshot-acceptance.md`](./proxmox-vm-snapshot-acceptance.md).

## Key Repo Paths

- [`../bin/platform-ssh-init`](../bin/platform-ssh-init): Shared SSH identity helper.
- [`../bin/platform-vm-env-collect`](../bin/platform-vm-env-collect): VM environment collector.
- [`../bin/platform-runtime-evidence`](../bin/platform-runtime-evidence): Secret-free PKI runtime and installation evidence collector.
- [`../bin/platform-config-init`](../bin/platform-config-init): Local outside-Git config initializer.
- [`../bin/platform-proxmox-token-init`](../bin/platform-proxmox-token-init): Proxmox API token bootstrap helper.
- [`../bin/platform-proxmox-vm-cleanup`](../bin/platform-proxmox-vm-cleanup): Safe single-VM Proxmox cleanup helper.
- [`../bin/platform-proxmox-vm-snapshot`](../bin/platform-proxmox-vm-snapshot): Safe Proxmox VE 9 development snapshot helper.
- [`../bin/platform-pki`](../bin/platform-pki): Unified Python PKI interface with shared runtime, filesystem, fork-safe ordered advisory-lock, and bounded Linux durable-publication primitives for every maintained PKI route.

- [`../bin/platform-bastion-policy`](../bin/platform-bastion-policy): Bastion access-policy validation and rendering helper.
- [`../assets/brand/`](../assets/brand/): Project brand assets for release metadata and forge profiles.
- [`handoffs/`](./handoffs/): Handoff notes for downstream coding agents and platform repositories.
