# Platform Config Init

`platform-config-init` creates the shared local secret namespace outside Git.

The default location is:

```text
~/.config/platform-infrastructure/
```

Use this directory for local secret material needed by `platform-*` repositories, such as Proxmox API tokens, Kubernetes admin kubeconfigs, PKI CA material, service TLS private keys, runner tokens, and service passwords.

Only secret material that should stay outside every Git repository belongs here. Private but non-secret configuration still belongs in the relevant private repository, for example `platform-private`.

The initializer creates only the major namespaces. Concrete subdirectories and files are owned by the consuming project or helper.

## Install

Clone the canonical `platform-tools` repository and install maintained tools into `~/.local/bin`:

```bash
git clone https://codeberg.org/rch/platform-tools
cd platform-tools
make install
```

## Usage

Create the default secret namespace:

```bash
platform-config-init
```

Run directly from a checkout before install:

```bash
./bin/platform-config-init
```

Use a custom directory for testing or non-default setups:

```bash
platform-config-init --config-dir /tmp/platform-infrastructure-test
```

## Created Layout

```text
~/.config/platform-infrastructure/
├── README.md
├── infra/
├── config/
└── pki/
```

Directories are created with mode `700`. `README.md` is created with mode `600`.

Existing `README.md` is not overwritten and is chmodded to `600`. Existing namespace directories are chmodded to `700`.

## Namespace Ownership

| Path | Owner |
| --- | --- |
| `~/.config/platform-infrastructure/` | Shared outside-Git local secret root created by `platform-tools`. |
| `infra/` | Infrastructure bootstrap secrets, especially Proxmox/OpenTofu token material used by `platform-infra` and `platform-proxmox-token-init`. |
| `config/` | Ansible and service secrets consumed by `platform-config`. |
| `pki/` | CA state, issued certificates, service private keys, exports, and backups managed by PKI helpers. |
| `config/<project-or-service>/...` | The consuming project or service that knows the concrete secret file semantics. |

Examples of project-owned paths include:

```text
~/.config/platform-infrastructure/infra/proxmox.token
~/.config/platform-infrastructure/config/k8s-bastion/<env>/admin.kubeconfig
~/.config/platform-infrastructure/config/rke2/<env>/cluster-token
~/.config/platform-infrastructure/config/monitoring/<env>/grafana-admin-password
~/.config/platform-infrastructure/pki/inventory/services.yml
~/.config/platform-infrastructure/pki/export/ansible/
```

`platform-config-init` intentionally does not create those concrete files. Empty placeholder secrets can accidentally satisfy file-exists checks while still being invalid.

## Proxmox/OpenTofu Example

Use `platform-proxmox-token-init` to create or write the Proxmox token file:

```bash
platform-proxmox-token-init \
  --ssh root@<proxmox-ip> \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path / \
  --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token
```

File content should be one raw line only:

```text
tofu@pve!platform=YOUR_REAL_TOKEN_SECRET
```

Then run OpenTofu from the downstream repository using a variable that points to the token file:

```bash
tofu plan -var-file=../../../platform-private/infra/production.tfvars
```

Downstream OpenTofu should read the token from the file, for example:

```hcl
variable "proxmox_api_token_file" {
  type      = string
  sensitive = true
}

locals {
  proxmox_api_token = chomp(file(var.proxmox_api_token_file))
}
```

Use an absolute path in private tfvars if the downstream tool does not expand `~` reliably:

```hcl
proxmox_api_token_file = "/home/YOUR_USER/.config/platform-infrastructure/infra/proxmox.token"
```

## Platform Config Example

`platform-config` can read service secret inputs from the local secret namespace while reading private non-secret inputs from `platform-private`:

```bash
export PLATFORM_INFRASTRUCTURE_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/config"
export PLATFORM_INFRASTRUCTURE_PKI_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/pki"
```

Example secret file paths:

```text
$PLATFORM_INFRASTRUCTURE_CONFIG_DIR/k8s-bastion/dev/admin.kubeconfig
$PLATFORM_INFRASTRUCTURE_CONFIG_DIR/rke2/dev/cluster-token
$PLATFORM_INFRASTRUCTURE_CONFIG_DIR/monitoring/dev/grafana-admin-password
```

Keep real inventories, host vars, access policies, and other private non-secret config in private Git unless they contain secret material.

## Legacy Paths

Older versions of this helper created top-level placeholder files such as:

```text
~/.config/platform-infrastructure/proxmox-token
~/.config/platform-infrastructure/proxmox.env
~/.config/platform-infrastructure/codeberg.env
~/.config/platform-infrastructure/ansible.env
~/.config/platform-infrastructure/backup.env
```

The current helper leaves those files untouched and prints a warning if they exist. It does not migrate or delete secrets automatically.

## Safety Rules

Do not commit real values from `~/.config/platform-infrastructure/` into any repository.

Do not copy these local token files, kubeconfigs, private keys, service passwords, or private TLS keys into `platform-tools`, `platform-infra`, `platform-config`, or other `platform-*` repositories.

Keep real variable values in this outside-Git config directory or in a private secret store.

## Downstream Repository Pattern

Downstream repositories should document which local paths they read and should create their own subdirectories when needed. They should not duplicate shared bootstrap logic from `platform-tools`.

This keeps shared tooling in `https://codeberg.org/rch/platform-tools` and local secret values outside Git.
