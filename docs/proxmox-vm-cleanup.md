# Proxmox VM Cleanup

`platform-proxmox-vm-cleanup` stops and destroys exactly one Proxmox VM by VMID.

This is an operator helper for known temporary or failed VMs. It is intentionally narrow: it does not clean by name, tag, pattern, range, or VM state.

## Requirements

Run the helper on a Proxmox host or use `--ssh` from an operator workstation. The remote SSH user must be able to run `qm status`, `qm config`, `qm stop`, and `qm destroy`.

The local workstation needs `ssh` when `--ssh` is used. The helper streams
itself over SSH, so no remote install is required. The Proxmox host also needs
`sha256sum`, `od`, and `tr` for inspected-config identity and authorization
nonces. SSH destinations use `host`
or `user@host` syntax with DNS-name or IPv4 characters only. Leading options,
whitespace, control characters, shell metacharacters, and bracketed IPv6
destinations are rejected. Use `--identity-file` when the Proxmox SSH key is
not already selected by `ssh-agent` or `~/.ssh/config`.

## Usage

Inspect and clean one VM over SSH:

```bash
platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --vmid 9900
```

The helper prints `qm config <vmid>` and then asks you to type the VMID before
destroying anything. The prompt requires an interactive TTY; redirected input,
EOF, and any response other than the exact VMID are refused. Use `--yes` for a
deliberately non-interactive workflow.

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
- refuses non-TTY or unavailable confirmation input unless `--yes` is set
- re-inspects the exact VMID, name, and running/stopped status after confirmation
- aborts if the VM identity or status changed after the displayed inspection
- verifies the complete supported `qm destroy` arguments before stopping a VM
- rechecks status, name, and the exact `qm config` SHA-256 after capability probing
- rechecks stopped status, name, and config again after stopping a running VM
- force-stops a running VM before destroy so broken guests do not block cleanup
- destroys with `qm destroy --purge`
- adds `--destroy-unreferenced-disks 1` when the Proxmox version supports it

Inspection creates a five-minute authorization record on the Proxmox host. The
authorization directory is current-user-owned with exact mode `700`; each
record has exact mode `600`, one link, a 256-bit nonce, creation time, VMID,
name, status, and SHA-256 of the observed `qm config`. The local coordinator
receives only the nonce. Destruction atomically moves and identity-checks the
server-side record before validating its age and content, so missing, copied,
hardlinked, replaced, concurrently consumed, expired, or replayed state is
refused. Abandoned valid records are removed after expiration during later
authorization operations; refused interactive workflows revoke current state.

Interrupted publication or consumption can leave `.tmp.*` or `.consumed.*`
files. Later authorization operations reap them only after five minutes and
only inside the validated mode-`700` authorization directory. Reaping requires
regular non-symlink files with the current owner, exact mode `600`, expected
link count, matching filesystem device, stable device/inode identity, complete
authorization content, and a nonce matching the artifact name. An nlink-2
publication pair is removed only when the staged and published names are the
same aged inode. Current artifacts, unverified hardlinks, symlinks, malformed
lookalikes, and metadata-incompatible foreign files are left untouched.

SSH transport sends mode and validated argument data over standard input to a
fixed `exec bash -c` receiver. The remote login shell parses no VM name, VMID,
or authorization token as command syntax. The nonce is framed on standard
input, written under the receiver's private temporary directory with mode
`600`, and opened for the generated child only as file descriptor 3. It is not
placed in SSH arguments, generated-child arguments, or process titles. Public
output and diagnostics suppress the nonce. The generated child requires one
newline-terminated token line followed by clean EOF; a second complete line or
any trailing partial bytes is rejected. It closes FD 3 on every framing outcome
and, after valid framing, before authorization
`stat`/`mv`, `qm`, or any other subprocess is started; read and framing errors
also close the descriptor before reporting failure.

The config SHA-256 is an observational drift guard, not a Proxmox object
version or an atomic compare-and-destroy primitive. The helper checks it before
and immediately after capability probing and after a stop, but Proxmox can
still change state after the final check and before `qm destroy` begins.

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
Usage: platform-proxmox-vm-cleanup [OPTIONS]

Options:
  --vmid VMID             Required numeric Proxmox VMID to destroy
  --ssh DESTINATION       SSH target for the Proxmox host
  --identity-file PATH    SSH private key for --ssh
  --name VM-NAME          Abort unless the qm config name exactly matches this value
  --yes                   Skip the interactive VMID confirmation prompt
  --help, -h              Show this help
  --version, -v           Show version number
```
