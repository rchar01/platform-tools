# Config Namespace Handoff

## Scope

`platform-tools` owns only the shared outside-Git secret namespace root:

```text
~/.config/platform-infrastructure/
├── README.md
├── infra/
├── config/
└── pki/
```

Concrete secret subdirectories and files are owned by the consuming project or helper. Private but non-secret operator config belongs in private Git, for example `platform-private`.

## Current Contract

- `platform-config-init` creates `README.md`, `infra/`, `config/`, and `pki/` only.
- `platform-config-init` does not create service skeletons or empty secret placeholders.
- Legacy top-level files are preserved and warned about, not migrated or deleted.
- Proxmox tokens should use `~/.config/platform-infrastructure/infra/proxmox.token`.
- Ansible/service secrets should live under `~/.config/platform-infrastructure/config/`.
- PKI CA state, issued certificates, service private keys, exports, and backups should live under `~/.config/platform-infrastructure/pki/`.

## Downstream Handoff

`platform-infra` should continue to consume the Proxmox token from:

```text
~/.config/platform-infrastructure/infra/proxmox.token
```

`platform-config` should own concrete service paths below:

```text
~/.config/platform-infrastructure/config/
```

PKI helpers should own concrete PKI paths below:

```text
~/.config/platform-infrastructure/pki/
```

Examples of project-owned paths:

```text
~/.config/platform-infrastructure/config/k8s-bastion/<env>/admin.kubeconfig
~/.config/platform-infrastructure/config/rke2/<env>/cluster-token
~/.config/platform-infrastructure/config/monitoring/<env>/grafana-admin-password
~/.config/platform-infrastructure/pki/inventory/services.yml
~/.config/platform-infrastructure/pki/export/ansible/
```

If a downstream repository needs preflight or scaffolding for those concrete paths, add that logic to the downstream repository or a purpose-specific helper, not to `platform-config-init`.

## Migration Notes

Older `platform-tools` versions created top-level files such as:

```text
~/.config/platform-infrastructure/proxmox-token
~/.config/platform-infrastructure/proxmox.env
~/.config/platform-infrastructure/codeberg.env
~/.config/platform-infrastructure/ansible.env
~/.config/platform-infrastructure/backup.env
```

Do not delete or rewrite these automatically. Operators should migrate any real values manually after confirming the consuming repository no longer references the legacy path.
