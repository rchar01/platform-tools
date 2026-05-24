# Documentation Index

Use this page as a navigation index for `platform-tools` docs.

Canonical repository: <https://codeberg.org/rch/platform-tools>

All shared platform helper tools are installed from `platform-tools`. Related platform repositories follow the Codeberg `rch/platform-*` namespace pattern.

## Start Here

- `../README.md`: Tool overview, install command, and high-level usage.
- `../Makefile`: Supported local entry points. Run `make help` to see them.

## Docs In This Tree

- `ssh-identity-helper.md`: How to use `platform-ssh-init` with CLI flags or config files, downstream repository patterns, private config storage, and CI/CD expectations.
- `vm-env-collector.md`: How to use `vm-env-collect`, inspect generated archives, and avoid committing collected VM data.
- `platform-config-init.md`: How to create the outside-Git local secret namespace under `~/.config/platform-infrastructure/`.
- `pki-openssl.md`: How to use the OpenSSL PKI helpers and keep generated PKI state outside Git.
- `pki-implementation-plan.md`: Checklist plan for the OpenSSL PKI helper feature.
- `proxmox-token-init.md`: How to bootstrap the Proxmox API user/token with `platform-proxmox-token-init`.
- `proxmox-vm-cleanup.md`: How to safely stop and destroy exactly one Proxmox VM by VMID.
- `handoffs/config-namespace-handoff.md`: Downstream ownership notes for the local secret namespace.
- `handoffs/tofu-ansible-handoff.md`: Example handoff that separates OpenTofu infrastructure work from Ansible guest configuration.

## Common Tasks

- Install shared platform tools: use `../README.md`.
- Generate a purpose-specific SSH keypair: use `ssh-identity-helper.md`.
- Create a cloud-init public key for `platform-infra`: use `ssh-identity-helper.md`.
- Decide where real SSH configs live: use `ssh-identity-helper.md`.
- Collect Rocky VM rebuild facts: use `vm-env-collector.md`.
- Create the outside-Git local secret namespace: use `platform-config-init.md`.
- Create internal TLS certificates: use `pki-openssl.md`.
- Track PKI helper implementation: use `pki-implementation-plan.md`.
- Bootstrap the Proxmox API token identity: use `proxmox-token-init.md`.
- Clean up one known Proxmox VM: use `proxmox-vm-cleanup.md`.

## Key Repo Paths

- `../bin/platform-ssh-init`: Shared SSH identity helper.
- `../bin/vm-env-collect`: Rocky VM environment collector.
- `../bin/platform-config-init`: Local outside-Git config initializer.
- `../bin/platform-proxmox-token-init`: Proxmox API token bootstrap helper.
- `../bin/platform-proxmox-vm-cleanup`: Safe single-VM Proxmox cleanup helper.
- `../bin/platform-pki-init`: PKI working directory initializer.
- `../bin/platform-pki-root-create`: Root CA creation helper.
- `../bin/platform-pki-intermediate-create`: Intermediate CA creation helper.
- `../bin/platform-pki-service-issue`: Service certificate issuance helper.
- `../bin/platform-pki-service-verify`: Service certificate verification helper.
- `../bin/platform-pki-list-expiry`: Certificate expiry listing helper.
- `pki-implementation-plan.md`: PKI helper implementation checklist.
- `../assets/brand/`: Project brand assets for release metadata and forge profiles.
- `handoffs/`: Handoff notes for downstream coding agents and platform repositories.
