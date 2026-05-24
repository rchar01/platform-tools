# Platform VM Environment Collector

`platform-vm-env-collect` collects important settings from an existing VM so a similar VM can be recreated later in a target Proxmox platform environment.

It is intended for VMs such as:

- Kubernetes nodes
- Bastion hosts
- GitLab Runner VMs
- Zot registry VMs
- General Rocky Linux service VMs

The script creates a timestamped `.tar.gz` archive containing system, network, storage, package, service, container, Kubernetes, GitLab Runner, and Zot configuration details.

## Install

Clone the canonical `platform-tools` repository and install maintained tools into `~/.local/bin`:

```bash
git clone https://codeberg.org/rch/platform-tools
cd platform-tools
make install
```

Downstream repositories in the `https://codeberg.org/rch/platform-*` family should reference this tool from `platform-tools` instead of carrying their own copy.

## Usage

Copy the script to the VM you want to inspect, or install it first.

Installed usage:

```bash
sudo platform-vm-env-collect
```

Checkout usage:

```bash
sudo ./bin/platform-vm-env-collect
```

The output is created under:

```text
/tmp/platform-vm-env-collect/
```

Example output:

```text
/tmp/platform-vm-env-collect/platform-vm-env-collect-myhost-20260513-184500.tar.gz
/tmp/platform-vm-env-collect/platform-vm-env-collect-myhost-20260513-184500.tar.gz.sha256
```

## Local Report Directory

Use `reports/platform-vm-env-collect/` inside this repository as the local analysis/import location for collector archives and extracted reports.

The collector still writes to `/tmp/platform-vm-env-collect/` by default because it usually runs on a remote/source VM. After copying an archive back to this repository, extract it under `reports/platform-vm-env-collect/`:

```bash
mkdir -p reports/platform-vm-env-collect
tar -C reports/platform-vm-env-collect -xzf /tmp/platform-vm-env-collect/platform-vm-env-collect-myhost-20260513-184500.tar.gz
```

Only `reports/.gitkeep` is committed. Report contents under `reports/` are ignored by Git.

## Why Run With sudo?

Run the script with `sudo` for a complete inventory.

Without `sudo`, many important files and commands may be unavailable, including Kubernetes configs, GitLab Runner config, firewall settings, LVM details, systemd unit files, and journal logs.

Recommended:

```bash
sudo platform-vm-env-collect
```

## Sensitive Data

By default, the script tries to avoid or redact obvious secrets such as passwords, tokens, API keys, private keys, kube secrets, and registry credentials.

The raw process environment is not collected by default because it often contains credentials. The archive contains a note at `meta/collector-env.txt` instead.

Do not use this unless you intentionally want environment variables included and have confirmed the shell environment does not contain secrets:

```bash
sudo COLLECT_ENV=1 platform-vm-env-collect
```

Do not use this unless you intentionally want a more sensitive archive:

```bash
sudo INCLUDE_SENSITIVE=1 platform-vm-env-collect
```

Even with the default safe mode, review the archive before copying it outside the source environment.

## Suggested Workflow

Run the script once on each important source VM:

```bash
sudo platform-vm-env-collect
```

Then rename the archive by role:

```bash
mv /tmp/platform-vm-env-collect/platform-vm-env-collect-*.tar.gz company-k8s-worker-01.tar.gz
```

Example set:

```text
company-k8s-control-plane-01.tar.gz
company-k8s-worker-01.tar.gz
company-bastion-01.tar.gz
company-gitlab-runner-01.tar.gz
company-zot-registry-01.tar.gz
```

## What To Inspect First

After extracting an archive, start with:

```text
SUMMARY.md
system/hostnamectl.txt
storage/lsblk.txt
storage/fstab.txt
network/nmcli-connections.txt
packages/rpm-qa-simple.txt
services/systemctl-enabled.txt
services/systemctl-running.txt
security/firewalld-all-zones.txt
containers/
kubernetes/
gitlab-runner/
zot/
configs/
```

These files are usually enough to rebuild a near-identical platform VM.

## What Not To Copy Directly

Do not blindly copy machine identity or production credentials into the target environment.

Avoid copying:

```text
/etc/machine-id
SSH host keys
SSH private keys
Kubernetes certificates
Kubernetes secrets
GitLab Runner registration tokens
registry credentials
production kubeconfigs
database dumps
container registry data
```

For a target-environment recreation, copy the structure and settings, not the real identities or secrets.

## Goal

The goal is not to clone the source VM byte-for-byte.

The goal is to recreate the same operational shape:

```text
same OS family
same packages
same services
same ports
same storage layout
same container runtime
same Kubernetes tooling
same GitLab Runner/Zot configuration style
same firewall and network behavior
```

Use the collected archive as a rebuild checklist for Proxmox, OpenTofu, Ansible, and manual validation.

## Repository Policy

Do not commit extracted collection directories or generated archives to this repository.

Place local analysis copies under:

```text
reports/platform-vm-env-collect/
```

The `.gitignore` intentionally ignores common collector outputs:

```text
reports/*
!reports/.gitkeep
platform-vm-env-collect-*/
*-vm-collect-*/
platform-vm-env-collect/
*.tar.gz
*.tar.gz.sha256
```
