<div align="center">
  <img src="assets/brand/platform-tools-forge-avatar-transparent-512.png" width="256" alt="platform-tools logo">

  <h1>platform-tools</h1>

  <p>Shared helper tools for platform infrastructure, PKI, Proxmox, SSH, bastion policy, and local operator workflows.</p>
</div>

---

`platform-tools` provides reusable command-line helpers used across the platform project repositories.

Canonical repository: <https://codeberg.org/rch/platform-tools>

All shared platform helper tools live in this repository. The platform repositories are split by responsibility so provisioning, configuration, deployment, runtime tooling, private operator config, template building, and shared helpers can evolve independently.

## Platform Repositories

| Repository | Purpose |
| --- | --- |
| [`platform-config`](https://codeberg.org/rch/platform-config) | Configures operating systems and services with Ansible. |
| [`platform-deployments`](https://codeberg.org/rch/platform-deployments) | Owns Helm chart source plus deployment values and overlays. |
| [`platform-infra`](https://codeberg.org/rch/platform-infra) | Provisions Proxmox VMs with OpenTofu and exposes handoff outputs. |
| [`platform-k8s-bastion`](https://codeberg.org/rch/platform-k8s-bastion) | Provides runtime commands and libraries for Kubernetes bastion hosts. |
| `platform-private` | Stores private environment-specific operator config; secrets still stay outside Git. |
| [`platform-template-builder`](https://codeberg.org/rch/platform-template-builder) | Builds reusable Proxmox VM templates from upstream Linux cloud images. |
| [`platform-tools`](https://codeberg.org/rch/platform-tools) | Provides shared helper tools used by the platform project repositories. |

## Tools

| Tool | Purpose |
| --- | --- |
| `platform-ssh-init` | Create purpose-specific SSH identities and optional SSH config blocks. |
| `platform-vm-env-collect` | Collect VM environment facts for rebuild planning. |
| `platform-config-init` | Create the local outside-Git secret namespace under `~/.config/platform-infrastructure/`. |
| `platform-proxmox-token-init` | Bootstrap the Proxmox API user/token expected by platform OpenTofu runs. |
| `platform-proxmox-vm-cleanup` | Stop and destroy exactly one Proxmox VM by VMID with confirmation and optional SSH execution. |
| `platform-proxmox-vm-snapshot` | Create, list, roll back, and delete short-lived Proxmox VE 9 development snapshots. |
| `platform-pki-init` | Create the outside-Git PKI working directory under `~/.config/platform-infrastructure/pki/`. |
| `platform-pki-inventory-install` | Validate and install private-Git service inventory into protected PKI state. |
| `platform-pki-root-create` | Create the root CA key and certificate. |
| `platform-pki-intermediate-create` | Create the intermediate CA and CA chain. |
| `platform-pki-service-issue` | Issue a service certificate from PKI inventory. |
| `platform-pki-service-renew` | Renew a service certificate, reusing the private key by default. |
| `platform-pki-service-verify` | Verify a generated service certificate. |
| `platform-pki-list-expiry` | List service certificate expiry status. |
| `platform-pki-print-cert` | Print readable certificate details for a service. |
| `platform-pki-export-ansible` | Export generated PKI files for `platform-config` Ansible consumption. |
| `platform-pki-backup` | Create encrypted or explicitly plain backups of PKI state. |
| `platform-pki-ca-rollover` | Inspect generation state; migrate legacy state; prepare or recover rollover candidates. |
| `platform-bastion-policy` | Validate and render Kubernetes bastion access-policy documents. |

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
- standard Unix tools such as `awk`, `cmp`, `cp`, `date`, `find`, `grep`, `mkdir`, `mktemp`, `od`, `sed`, `sha256sum`, `stat`, `tar`, and `tr`

PKI helpers require:

- `openssl`
- util-linux `flock` and Linux procfs at `/proc` for stable operation-lock identity checks
- GNU `date` for certificate expiry calculations
- GNU `mv` with `--no-copy` and `--update=none-fail`; inventory publication prefers exchange and supports a guarded rename fallback under cooperative same-UID locks
- `tar` with `--no-wildcards` support for safe PKI backup exclusions
- `age` for encrypted `platform-pki-backup` output; plain `.tar.gz` backup requires explicit `--allow-plain-backup`

SSH and Proxmox helpers require:

- `ssh` for remote execution modes
- `pveum` on the Proxmox host for `platform-proxmox-token-init`
- `qm` on the Proxmox host for `platform-proxmox-vm-cleanup`
- `pvesh`, `jq`, and Linux procfs at `/proc` on a single-node Proxmox VE 9 host for `platform-proxmox-vm-snapshot`, plus `qm` for mutations; local `jq` is also required with `--ssh`
- `jq` on the Proxmox host when `platform-proxmox-token-init --write-token-file` is used over SSH

Bastion policy helpers require:

- `python3`
- `PyYAML`

Optional verification tools:

- `shellcheck` for `make shellcheck`
- `gitleaks` for local secret scanning

## Development Container

The canonical development environment is a Debian 13 rootless Podman container
for `amd64` and `arm64`, with the repository mounted at `/workspace`. It includes
the pinned Bashly generator, pytest, and the tools needed by the maintained
checks without mounting host SSH keys, private configuration, or PKI state.

Open an interactive development shell:

```bash
make shell
```

Run all maintained checks in a one-shot container:

```bash
make container-check
```

This is the canonical final acceptance command and runs the complete pytest
aggregate once. Do not run `make test` immediately before it unless a separate
host-environment comparison is intentional.

Run only the generic pytest harness contract tests:

```bash
make test-python-infrastructure
```

Run the authoritative PKI rollover pytest scenarios:

```bash
make test-pki-ca-rollover
```

The authoritative target uses four workers by default. Run the serial diagnostic
target directly when comparing ordering or timing. The pinned development image
includes pytest-xdist; host-only runs must provide it separately:

```bash
make test-python-pki-rollover
```

Set `PKI_PYTEST_WORKERS` from 1 through 4 to override the authoritative target's
bounded default or benchmark the parallel target directly:

```bash
make test-pki-ca-rollover PKI_PYTEST_WORKERS=2
make test-python-pki-rollover-parallel
make test-python-pki-rollover-parallel PKI_PYTEST_WORKERS=4
```

Run the authoritative Python rollover parser group without creating PKI seed
state:

```bash
make test-pki-ca-rollover-parser
```

Generate Bashly-backed executables and verify that committed output is current:

```bash
make generate
make verify-generated
```

Edit Bashly source under `bashly/<tool>/`, not the corresponding generated file
under `bin/`. See [`docs/development.md`](docs/development.md) for the full
workflow.

All maintained shell commands use the same generated CLI contract: leading
`--help`/`-h` and `--version`/`-v` write to stdout and exit 0, while parser
errors write to stderr and exit 1. `platform-bastion-policy` follows the same
public contract through Python argparse. Commands with subcommands provide
command-specific help as `COMMAND --help` or `COMMAND -h`.
Generated shell-command help uses a restrained color palette on interactive
terminals. Colors are disabled automatically for pipes and redirects; set
`NO_COLOR=1` to disable them explicitly. Command result, warning, and error
logs remain uncolored.

Set `PLATFORM_TOOLS_DEV_IMAGE` to override the local image name. The wrapper
targets require Podman, Bash, and Make on the host.

## Verify

Run syntax checks for maintained scripts:

```bash
make verify
```

Run ShellCheck when it is available:

```bash
make shellcheck
```

Run maintained behavior tests:

```bash
make test
```

All maintained test orchestration uses pytest. The tests still execute the real
generated Bash commands, external tools, PTYs, inherited file descriptors,
self-streamed SSH, and executable fakes as subprocesses. Coverage includes the
cross-command CLI contract and a disposable installation smoke test for every
command, including installed PKI shared-asset lookup without Ruby, Bashly, or
checkout source paths at runtime.

Run only the isolated SSH identity helper tests:

```bash
make test-platform-ssh-init
```

Run only the fake-backed Proxmox token bootstrap tests, which never contact a
real Proxmox host:

```bash
make test-proxmox-token-init
```

Run only the fake-backed Proxmox VM cleanup tests, which never contact a real
Proxmox host or mutate a VM:

```bash
make test-proxmox-vm-cleanup
```

Run only the fake-backed Proxmox VM snapshot tests, which never contact a real
Proxmox host or mutate a live VM:

```bash
make test-proxmox-vm-snapshot
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

Token-file output is staged beside the destination with mode `600`. Absent
destinations use atomic no-clobber publication. Validated existing non-empty
files are preserved unless `--force` is explicitly supplied; see the token
helper documentation for the existing-file trust boundary.

Clean up one Proxmox VM by VMID after verifying the printed target:

```bash
platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --vmid 9900
```

Without `--yes`, cleanup requires an interactive TTY and confirmation containing
exactly the selected VMID. Redirected input and unavailable input are refused.
After confirmation, the helper re-inspects the VMID, exact name, and status and
aborts on drift before and after resolving the supported destroy command. A
running VM is checked again after stop. Remote destruction consumes a
five-minute, owner-only authorization record persisted on the Proxmox host;
the fixed remote command receives VM and token data over standard input rather
than login-shell syntax, and the generated remote child reads the nonce from a
protected file descriptor rather than argv, closing that descriptor before any
authorization or Proxmox child command. Aged interrupted publication and
consume artifacts are reaped only after strict owner, mode, link-count,
device/inode, and non-symlink checks. `--ssh` accepts
only a DNS-name/IPv4 `host` or `user@host` destination; option-like, whitespace,
shell-metacharacter, and bracketed IPv6 values are rejected.

Create a short-lived development snapshot for one exact VM:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade
```

Snapshot create, rollback, and delete require an interactive TTY unless
`--yes` is supplied. Generated subcommand parsing exposes only options that
apply to the selected operation; private self-streaming protocol flags remain
hidden from public help.

Initialize PKI state and issue a test service certificate from inventory:

```bash
platform-pki-init
platform-pki-inventory-install
platform-pki-root-create --name "Platform Example Root CA" --org "Platform Example" --country "PL"
platform-pki-intermediate-create --name "Platform Example Intermediate CA" --org "Platform Example" --country "PL"
platform-pki-service-issue platform-example
platform-pki-service-verify platform-example
platform-pki-list-expiry
```

PKI initialization paths must be absolute, non-root, and symlink-free.
`platform-pki-init` creates `inventory/services.yml.example`, not active
inventory. `platform-pki-inventory-install` installs
`../platform-private/pki/services.yml` by default; use `--private-repo` for a
different private repository. `platform-pki-init --force` refreshes only the
example and does not replace active inventory, CA keys, certificates, or
database state. Existing PKI directories must
be owned by the current user and must not be group- or world-writable.

Fresh CA state begins with immutable root `g1` and intermediate `g1-i1`
generations, with the active pair selected by a protected manifest. Generation
reservations are monotonic: failed or interrupted bootstrap IDs remain
permanently abandoned, and retries allocate the next root or intermediate ID.
Existing singleton CA state is changed only through explicit, receipt-backed
`platform-pki-ca-rollover migrate`. Inventory installation, protected backup,
and rollover status/migration prepare missing private control directories for
that workflow. Other PKI commands reject legacy state with migration guidance
after acquiring persistent locks. On generation-aware state, receipt-backed
`platform-pki-ca-rollover prepare --type intermediate|root` creates immutable
candidate generations without changing the active issuer. Root preparation
also requires the reviewed `pki/trust-consumers.yml` checklist from the private
repository. `status --format text|json` reports public active and candidate
metadata after validating complete digest-bound candidate/state trees and every
service issuer manifest. Preparation pre-creates and journals sensitive child
outputs, records full nanosecond identities for staged CA database sources, and
uses immutable write-ahead transaction manifests. It verifies strict critical
CA certificate profiles and retains recovery-required state until
crash-resumable terminal cleanup completes. Terminal receipts bind the exact
journal and marker identities before either control file is removed. Superseded
and final transaction-tree manifests are identity-unlinked in journaled order;
missing prior unlinks resume safely, while replacement objects fail closed.
Recovery-required JSON uses schema 2 and reports the validated terminal outcome
and exact `resume` or `rollback` action; every retained preparation journal
blocks normal PKI commands even after its mutation outcome is committed.
Activation, acknowledgement, rollback, retirement, and completion
remain unavailable pending immutable export and evidence support.

For non-interactive PKI automation with encrypted CA keys, pass restricted passphrase files such as `--root-pass-file /run/secrets/platform-pki-root-pass` and `--intermediate-pass-file /run/secrets/platform-pki-intermediate-pass`. See `docs/pki-openssl.md` for the full flow, migration procedure, and safety rules.

Service issuance refuses an existing certificate, reuses an existing private
key unless `--rotate-key` is requested, and transactionally publishes service
artifacts with the intermediate CA database only after successful signing and
verification.

Service renewal requires an existing private key, reuses it unless
`--rotate-key` is requested, and archives previous service material while
transactionally replacing the certificate and intermediate CA database. Both
operations hold ordered root, intermediate, and inventory locks through
verification and consume one validated inventory snapshot.

`platform-pki-root-create` generates its key and certificate in private staging
before publishing a new immutable generation. It refuses an existing bootstrap
or active issuer; `--force` cannot replace unproven generation state. Handled
failures and explicit recovery remove only transaction-owned authority state
and preserve the reserved ID as abandoned. Root keys remain encrypted by
default, and unencrypted root keys require the explicit
`--allow-unencrypted-root-key` opt-in.

`platform-pki-intermediate-create` likewise stages its key, CSR, certificate,
chain, and root CA database update. It refuses an existing active issuer;
`--force` cannot replace unproven generation state. Failed signing, publication,
or recovery restores the exact root database state and permanently abandons the
allocated intermediate ID. Intermediate keys
remain encrypted by default, and unencrypted keys require the explicit
`--allow-unencrypted-intermediate-key` opt-in. CA mutation locks use a fixed
root-before-intermediate acquisition order and cover complete generation,
signing, and publication transactions.

Validate and render a Kubernetes bastion access policy:

```bash
POLICY_OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-policy.XXXXXX")"

platform-bastion-policy validate \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml

platform-bastion-policy render-host \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml \
  --output "$POLICY_OUT_DIR/access-policy.yaml"

platform-bastion-policy render-csr-configmap \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml \
  --name bastion-csr-policy \
  --namespace bastion-system \
  --output "$POLICY_OUT_DIR/bastion-csr-policy.configmap.yaml"
```

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
./bin/platform-proxmox-vm-snapshot list --ssh root@192.0.2.10 --identity-file ~/.ssh/platform-template-builder_ed25519 --vmid 101
./bin/platform-pki-init
./bin/platform-bastion-policy validate --input examples/bastion-policy/access-policy.example.yaml
```

## Documentation

| Document | Purpose |
| --- | --- |
| `docs/ssh-identity-helper.md` | SSH helper usage with CLI flags or config files, private config layout, and CI/CD expectations. |
| `docs/platform-vm-env-collect.md` | VM environment collector usage, output structure, and safety notes. |
| `docs/platform-config-init.md` | Local outside-Git secret namespace initialization for platform secrets. |
| `docs/bastion-policy.md` | Kubernetes bastion access-policy validation and rendering flow. |
| `docs/pki-openssl.md` | OpenSSL PKI helper usage, state layout, and safety model. |
| `docs/proxmox-token-init.md` | Proxmox API user/token bootstrap helper and manual `pveum` reference. |
| `docs/proxmox-vm-cleanup.md` | Safe single-VM Proxmox cleanup helper usage and safety model. |
| `docs/proxmox-vm-snapshot.md` | Proxmox VE 9 development snapshot workflows, safety model, and environment-tag gate. |
| `docs/handoffs/config-namespace-handoff.md` | Downstream ownership notes for the local secret namespace. |
| `docs/handoffs/tofu-ansible-handoff.md` | Example OpenTofu/Ansible handoff from a collected VM report. |
| `assets/brand/` | Project brand assets for release metadata and forge profiles. |

## Security

Keep real secrets outside Git. Do not commit VM collection output, generated archives, SSH keys, private `.env` files, token files, PKI CA material, service private keys, issued real certificates, PKI exports, PKI backups, or copied private configuration.

Use `~/.config/platform-infrastructure/` for local secret material. Private but non-secret operator configuration belongs in private Git, such as `platform-private`.

Collected VM reports and PKI exports can contain sensitive environment details even when they do not contain obvious passwords. Review generated files before sharing them.

PKI passphrase files are plaintext secrets. Keep them outside Git, restrict them to mode `600` or stricter, use a first-line passphrase of at least 16 characters with non-whitespace content, and prefer temporary secret-manager mounts over long-lived files.

PKI Ansible exports contain service private keys. Custom export directories must be absolute paths with current-user-owned parents that are not group- or world-writable and do not contain symlink components.

Real bastion access policies can reveal users, groups, cluster endpoints, and access intent. Keep real policies in `platform-private`; only fake examples belong in this repository.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
