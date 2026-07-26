# Proxmox VM Snapshots

`platform-proxmox-vm-snapshot` creates, lists, rolls back, and deletes
short-lived development snapshots on a single-node Proxmox VE 9 installation.

Snapshots are rollback points on the VM's storage. They disappear with the VM
or failed storage and do not replace `vzdump`, Proxmox Backup Server, or another
durable backup system. Multi-VM operations run serially and are not atomic.

## Requirements

The Proxmox host must provide:

- Proxmox VE 9 in a single-node installation
- `bash`, `pvesh`, and `jq` for all operations
- `qm` additionally for create, rollback, and delete
- an operator identity allowed to run the required local Proxmox commands,
  normally `root`

An operator workstation using `--ssh` also needs `bash`, `ssh`, and `jq`. The
helper streams itself and a private operation-state manifest over SSH, so the
tool does not need to be installed on the Proxmox host. Use `--identity-file`
when the key is not already selected by `ssh-agent` or SSH configuration.

## Connection Model

The snapshot helper connects to the Proxmox host, not to guest VMs:

| Connection | Identity | Purpose |
| --- | --- | --- |
| Operator workstation to Proxmox | `--ssh root@<proxmox-host>` and the Proxmox SSH key selected by `--identity-file` | Run `pvesh` and `qm` on Proxmox. |
| Direct execution on Proxmox | Current local Proxmox user; no SSH key | Run `pvesh` and `qm` locally. |
| Proxmox to QEMU guest agent | Virtual guest-agent channel; no SSH key | For snapshots without saved RAM, Proxmox may freeze and thaw guest filesystems when the agent is enabled, running, and permits filesystem freeze. |
| Operator workstation to a guest VM | Guest cloud-init or configuration-management key | Separate guest administration; not used by this helper. |

`~/.ssh/platform-template-builder_ed25519` is the public example convention for
a purpose-specific Proxmox host key. It is not a required filename; users may
select any suitable Proxmox SSH identity. The `platform-infra` guest-key
convention, `~/.ssh/platform-infra-<environment>-<vm-key>-cloud-init_ed25519`,
is unrelated to snapshot transport. See [SSH Identity Helper](./ssh-identity-helper.md)
for key generation and private configuration examples.

The examples below use the RFC 5737 documentation address `192.0.2.10`. Replace
it with the Proxmox host address or SSH alias. Keep all private keys outside Git
with owner-only permissions.

When running directly on the Proxmox host, omit `--ssh` and `--identity-file`:

```bash
platform-proxmox-vm-snapshot list --vmid 101
```

## Common Use Cases

- Create a rollback point before an application, package, or operating-system
  upgrade.
- Snapshot a complete tagged development environment before a coordinated
  configuration change, understanding that VM operations are serial rather
  than atomic.
- Use `--include-memory` for a short-lived runtime debugging checkpoint when
  the additional storage and QEMU compatibility constraints are acceptable.
- Roll back a failed change, verify the restored system, and delete the
  temporary snapshot after the rollback window closes.

## Single-VM Workflow

Create a disk and configuration snapshot without saved memory state:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade \
  --description "Before the application upgrade"
```

When `--description` is omitted, the helper records a short generated
description containing the selected VMID or environment. It never records the
full command line.

Select by one exact, unique VM name instead:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vm-name example-dev-app-01 \
  --snapshot-name before-upgrade
```

List snapshots:

```bash
platform-proxmox-vm-snapshot list \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101
```

Preview a rollback without mutation:

```bash
platform-proxmox-vm-snapshot rollback \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade \
  --dry-run
```

Perform the rollback:

```bash
platform-proxmox-vm-snapshot rollback \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade
```

Rollback leaves the VM stopped by default. Add `--start-after-rollback` only
when the VM should start after successful restoration:

```bash
platform-proxmox-vm-snapshot rollback \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade \
  --start-after-rollback
```

Delete a validated checkpoint:

```bash
platform-proxmox-vm-snapshot delete \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade
```

Snapshot deletion can merge storage data and produce significant I/O. The
helper never passes Proxmox's forced metadata-only deletion option.

## Environment Selection

Environment membership requires both exact Proxmox tags:

```text
managed-by-tofu;<environment>
```

Tag order does not matter, but matching is complete and case-sensitive. VM
names are never used to infer environment membership. Templates are excluded.

The companion `platform-infra` environment-tag migration and reconciliation is
a release prerequisite for mutating environment workflows. Until that evidence
is recorded, use environment selection only for listing and dry-run inspection:

```bash
platform-proxmox-vm-snapshot list \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --environment dev

platform-proxmox-vm-snapshot create \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --environment dev \
  --snapshot-name before-change \
  --dry-run
```

The isolated `snapshot-test` root has separate automatic-tag, exact-target,
dry-run, and authorized live-acceptance evidence. That acceptance-only exception
does not enable mutations for broader `dev`, `homelab`, or other environments;
each still requires reconciled tags and review of its complete dry-run target
set.

The helper cannot detect an intended environment VM whose environment tag is
missing. Always compare the complete printed VMID set with Proxmox before an
environment mutation is approved for operational use.

## Snapshot Names

Snapshot names follow the Proxmox VE 9 schema enforced by the helper:

- 2-40 characters
- start with an ASCII letter
- contain only ASCII letters, digits, underscores, or hyphens
- must not be `current` or `pending`, case-insensitively

Input is rejected rather than silently changed.

## Memory State

Creation defaults to disk and configuration state only. Add `--include-memory`
to pass `--vmstate 1` to Proxmox:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-runtime-change \
  --include-memory
```

Saved memory consumes additional storage and can depend on the recorded QEMU
machine and CPU versions. The helper does not issue guest freeze or thaw
commands itself. For snapshots without saved RAM, Proxmox VE 9 may use QEMU
guest-agent freeze/thaw when the agent is enabled, running, and permits
filesystem freeze. Do not assume that saved-memory snapshots use the same
freeze path. Neither behavior coordinates applications or guarantees
application-consistent state, so a live snapshot may still be only
crash-consistent.

## Safety Model

Before mutation, the helper:

- obtains structured data through local `pvesh --output-format json`
- rejects multi-node installations, templates, malformed data, and VM locks
- resolves exact VM identities and complete environment tags
- verifies snapshot absence for create or exact presence for rollback/delete
- prints status, attached disk configuration, and snapshots
- binds confirmation to the exact node, VMID, name, sanitized config, status,
  and snapshot state that was displayed
- repeats checks after confirmation and before every serial VM mutation

Create uses a yes/no prompt. Rollback and deletion require typing the VMID and
snapshot name, or the environment and snapshot name. `--yes` skips only the
prompt; it does not skip preflight, drift checks, postconditions, or summaries.

If a later VM fails, the helper stops, returns nonzero, and reports each VM as
`succeeded`, `failed`, or `not attempted`. It does not automatically compensate
for earlier successful operations because another rollback or deletion could
compound the failure.

## Options

```text
Usage: platform-proxmox-vm-snapshot <create|list|rollback|delete> [options]

Target selector; exactly one required:
  --vmid <vmid>                 Select one numeric VMID.
  --vm-name <exact-name>        Select one exact, uniquely named VM.
  --environment <tag>           Select non-template VMs tagged
                                managed-by-tofu and <tag>.

Snapshot options:
  --snapshot-name <name>        Required for create, rollback, and delete.
  --description <text>          Create-only snapshot description.
  --include-memory              Create-only saved VM memory state.
  --start-after-rollback        Rollback-only explicit VM start.

Connection and safety:
  --ssh <user@host>             Run Proxmox work on a host over SSH.
  --identity-file <path>        SSH private key for --ssh.
  --dry-run                     Resolve, inspect, and print without mutation.
  --yes                         Skip mutation confirmation, not preflight.
  -h, --help                    Show help.
```
