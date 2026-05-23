# Proxmox VM Cleanup

`platform-proxmox-vm-cleanup` stops and destroys exactly one Proxmox VM by VMID.

This is an operator helper for known temporary or failed VMs. It is intentionally narrow: it does not clean by name, tag, pattern, range, or VM state.

## Requirements

Run the helper on a Proxmox host or use `--ssh` from an operator workstation. The remote SSH user must be able to run `qm status`, `qm config`, `qm stop`, and `qm destroy`.

The local workstation needs `ssh` when `--ssh` is used. The helper streams itself over SSH, so no remote install is required. Use `--identity-file` when the Proxmox SSH key is not already selected by `ssh-agent` or `~/.ssh/config`.

## Usage

Inspect and clean one VM over SSH:

```bash
platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --vmid 9900
```

The helper prints `qm config <vmid>` and then asks you to type the VMID before destroying anything.

Use a name guard when automation knows the expected VM name:

```bash
platform-proxmox-vm-cleanup \
  --ssh root@<proxmox-ip> \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 9900 \
  --name platform-template-smoke-9900
```

Skip the prompt only after the VMID and optional name guard are already verified by the calling workflow:

```bash
platform-proxmox-vm-cleanup \
  --ssh root@<proxmox-ip> \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 9900 \
  --name platform-template-smoke-9900 \
  --yes
```

Run directly on a Proxmox host:

```bash
platform-proxmox-vm-cleanup --vmid 9900
```

## Safety Model

The helper:

- requires one numeric `--vmid`
- checks that the VMID exists before prompting
- prints the full Proxmox VM config before destruction
- optionally verifies the exact VM name with `--name`
- requires typing the VMID unless `--yes` is set
- force-stops a running VM before destroy so broken guests do not block cleanup
- destroys with `qm destroy --purge`
- adds `--destroy-unreferenced-disks 1` when the Proxmox version supports it

The helper does not:

- destroy by VM name alone
- destroy by tag, pattern, state, or VMID range
- discover temporary VMs automatically
- skip confirmation by default
- recover disks or VM config after destruction

## Common Workflows

Template smoke tests and failed platform VM clones often leave a known VMID behind for debugging. After confirming the VMID is safe to destroy, use this tool instead of hand-writing `qm stop` and `qm destroy` commands.

For repository-specific cleanup targets, prefer calling this shared helper from that repository rather than copying Proxmox destroy logic into multiple places.

## Options

```text
Usage: platform-proxmox-vm-cleanup --vmid <vmid> [options]

Options:
  --vmid <vmid>          Required numeric Proxmox VMID to destroy.
  --ssh <user@host>      SSH target for the Proxmox host.
  --identity-file <path> SSH private key for --ssh.
  --name <vm-name>       Optional safety guard; abort unless qm config name
                         matches this exact value.
  --yes                  Skip the interactive VMID confirmation prompt.
  -h, --help             Show this help.
```
