<div align="center">
  <img src="assets/brand/platform-tools-forge-avatar-transparent-512.png" width="256" alt="platform-tools logo">

  <h1>platform-tools</h1>

  <p>Shared Bash helper scripts for platform infrastructure, PKI, Proxmox, SSH, and local operator workflows.</p>
</div>

---

`platform-tools` provides reusable command-line helpers used across the platform project repositories.

Canonical repository: <https://codeberg.org/rch/platform-tools>

All shared platform helper tools live in this repository. The platform repositories are split by responsibility so provisioning, configuration, deployment, runtime tooling, private operator config, template building, and shared helpers can evolve independently.

## Platform Repositories

| Repository | Purpose |
| --- | --- |
| `platform-config` | Configures operating systems and services with Ansible. |
| `platform-deployments` | Owns Helm chart source plus deployment values and overlays. |
| `platform-infra` | Provisions Proxmox VMs with OpenTofu and exposes handoff outputs. |
| `platform-k8s-bastion` | Provides runtime commands and libraries for Kubernetes bastion hosts. |
| `platform-private` | Stores private environment-specific operator config; secrets still stay outside Git. |
| `platform-template-builder` | Builds reusable Proxmox VM templates from upstream Linux cloud images. |
| `platform-tools` | Provides shared helper scripts used by the platform project repositories. |

## Tools

| Tool | Purpose |
| --- | --- |
| `platform-ssh-init` | Create purpose-specific SSH identities and optional SSH config blocks. |
| `platform-vm-env-collect` | Collect VM environment facts for rebuild planning. |
| `platform-config-init` | Create the local outside-Git secret namespace under `~/.config/platform-infrastructure/`. |
| `platform-proxmox-token-init` | Bootstrap the Proxmox API user/token expected by platform OpenTofu runs. |
| `platform-proxmox-vm-cleanup` | Stop and destroy exactly one Proxmox VM by VMID with confirmation and optional SSH execution. |
| `platform-pki-init` | Create the outside-Git PKI working directory under `~/.config/platform-infrastructure/pki/`. |
| `platform-pki-root-create` | Create the root CA key and certificate. |
| `platform-pki-intermediate-create` | Create the intermediate CA and CA chain. |
| `platform-pki-service-issue` | Issue a service certificate from PKI inventory. |
| `platform-pki-service-renew` | Renew a service certificate, reusing the private key by default. |
| `platform-pki-service-verify` | Verify a generated service certificate. |
| `platform-pki-list-expiry` | List service certificate expiry status. |
| `platform-pki-print-cert` | Print readable certificate details for a service. |
| `platform-pki-export-ansible` | Export generated PKI files for `platform-config` Ansible consumption. |
| `platform-pki-backup` | Create encrypted or explicitly plain backups of PKI state. |

## Install

Clone the canonical tools repository and install maintained CLI helpers into `~/.local/bin`:

```bash
git clone https://codeberg.org/rch/platform-tools
cd platform-tools
make install
```

Use another install directory when needed. PKI helpers also install shared library and template assets under `SHARE_DIR`:

```bash
make install \
  INSTALL_DIR="$PWD/.tools/bin" \
  SHARE_DIR="$PWD/.tools/share/platform-tools"
```

Ensure the install directory is on `PATH` when using tools by command name.

## Requirements

Core local requirements:

- `bash`
- `make`
- standard Unix tools such as `awk`, `cmp`, `cp`, `date`, `find`, `grep`, `mkdir`, `mktemp`, `sed`, `stat`, and `tar`

PKI helpers require:

- `openssl`
- GNU `date` for certificate expiry calculations
- `age` for encrypted `platform-pki-backup` output; plain `.tar.gz` backup requires explicit `--allow-plain-backup`

SSH and Proxmox helpers require:

- `ssh` for remote execution modes
- `pveum` on the Proxmox host for `platform-proxmox-token-init`
- `qm` on the Proxmox host for `platform-proxmox-vm-cleanup`
- `jq` on the Proxmox host when `platform-proxmox-token-init --write-token-file` is used over SSH

Optional verification tools:

- `shellcheck` for `make shellcheck`
- `gitleaks` for local secret scanning

## Verify

Run syntax checks for maintained scripts:

```bash
make verify
```

Run ShellCheck when it is available:

```bash
make shellcheck
```

## Quick Usage

Create a purpose-specific SSH key directly:

```bash
platform-ssh-init \
  --key-path ~/.ssh/platform-example_ed25519 \
  --comment "platform example" \
  --print-public-key
```

Or use a config file from private operator config:

```bash
platform-ssh-init ../platform-private/infra/ssh/production-cloud-init.env --print-public-key
```

Collect facts from a VM:

```bash
sudo platform-vm-env-collect
```

Create the outside-Git local secret namespace with `infra/`, `config/`, and `pki/`:

```bash
platform-config-init
```

Bootstrap the Proxmox API token identity over SSH:

```bash
platform-proxmox-token-init \
  --ssh root@<proxmox-ip> \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path / \
  --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token
```

Check Proxmox token bootstrap prerequisites first:

```bash
platform-proxmox-token-init --ssh root@<proxmox-ip> --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token --check
```

Clean up one Proxmox VM by VMID after verifying the printed target:

```bash
platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --vmid 9900
```

Initialize PKI state and issue a test service certificate from inventory:

```bash
platform-pki-init
platform-pki-root-create --name "Platform Example Root CA" --org "Platform Example" --country "PL"
platform-pki-intermediate-create --name "Platform Example Intermediate CA" --org "Platform Example" --country "PL"
platform-pki-service-issue platform-example
platform-pki-service-verify platform-example
platform-pki-list-expiry
```

For non-interactive PKI automation with encrypted CA keys, pass restricted passphrase files such as `--root-pass-file /run/secrets/platform-pki-root-pass` and `--intermediate-pass-file /run/secrets/platform-pki-intermediate-pass`. See `docs/pki-openssl.md` for the full flow and safety rules.

Add a name guard and non-interactive confirmation for automation:

```bash
platform-proxmox-vm-cleanup \
  --ssh root@<proxmox-ip> \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 9900 \
  --name platform-template-smoke-9900 \
  --yes
```

If running directly from a checkout before install:

```bash
sudo ./bin/platform-vm-env-collect
./bin/platform-config-init
./bin/platform-proxmox-token-init --ssh root@<proxmox-ip>
./bin/platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --identity-file ~/.ssh/platform-template-builder_ed25519 --vmid 9900
./bin/platform-pki-init
```

## Documentation

| Document | Purpose |
| --- | --- |
| `docs/ssh-identity-helper.md` | SSH helper usage with CLI flags or config files, private config layout, and CI/CD expectations. |
| `docs/platform-vm-env-collect.md` | VM environment collector usage, output structure, and safety notes. |
| `docs/platform-config-init.md` | Local outside-Git secret namespace initialization for platform secrets. |
| `docs/pki-openssl.md` | OpenSSL PKI helper usage, state layout, and safety model. |
| `docs/proxmox-token-init.md` | Proxmox API user/token bootstrap helper and manual `pveum` reference. |
| `docs/proxmox-vm-cleanup.md` | Safe single-VM Proxmox cleanup helper usage and safety model. |
| `docs/handoffs/config-namespace-handoff.md` | Downstream ownership notes for the local secret namespace. |
| `docs/handoffs/tofu-ansible-handoff.md` | Example OpenTofu/Ansible handoff from a collected VM report. |
| `assets/brand/` | Project brand assets for release metadata and forge profiles. |

## Security

Keep real secrets outside Git. Do not commit VM collection output, generated archives, SSH keys, private `.env` files, token files, PKI CA material, service private keys, issued real certificates, PKI exports, PKI backups, or copied private configuration.

Use `~/.config/platform-infrastructure/` for local secret material. Private but non-secret operator configuration belongs in private Git, such as `platform-private`.

Collected VM reports and PKI exports can contain sensitive environment details even when they do not contain obvious passwords. Review generated files before sharing them.

PKI passphrase files are plaintext secrets. Keep them outside Git, restrict them to mode `600` or stricter, and prefer temporary secret-manager mounts over long-lived files.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
