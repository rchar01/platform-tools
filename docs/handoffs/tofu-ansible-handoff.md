# OpenTofu and Ansible Handoff

Example source report: `platform-vm-env-collect-example-bastion-01-YYYYMMDD-HHMMSS/SUMMARY.md`

VM boundary:

```text
platform-infra = VM exists with the right virtual hardware and initial access.
platform-config = VM is configured after boot.
```

## Source VM Facts

| Item | Value |
| --- | --- |
| Hostname | `example-bastion-01.example.test` |
| OS | Rocky Linux 10.0 |
| Architecture | `x86_64` |
| CPU | 4 vCPU |
| RAM | 8 GiB target, report shows 7.5 GiB usable |
| Primary disk | 60 GiB |
| Secondary disk | 80 GiB |
| NICs | 3 |
| IPs | `192.0.2.26/27`, `198.51.100.186/27`, `203.0.113.154/27` |
| Default gateway | `203.0.113.158` via third NIC |
| DNS search | `example.test` |
| DNS server | `192.0.2.53` |
| SSH | port `22`, key auth only, password auth disabled |
| Container runtime | none detected |
| Kubernetes runtime | none detected |
| QEMU guest agent | not detected on source, source was VMware |

## Target Implementation Differences

This implementation targets a Proxmox platform environment, not a byte-for-byte rebuild of the source VMware VM.

Keep these differences explicit in the OpenTofu and Ansible code:

| Area | Source VM | Target Implementation |
| --- | --- | --- |
| Hypervisor | VMware | Proxmox |
| Physical NICs available | source had multiple VMware-backed NICs | Proxmox host has one physical NIC |
| VM NICs | 3 guest NICs: `ens192`, `ens224`, `ens256` | 1 guest NIC attached to the main Proxmox bridge, usually `vmbr0` |
| IP addressing | source environment IPs | one target IP, gateway, and DNS |
| Static routes | several source-specific routes | do not recreate unless equivalent target networks exist |
| Physical storage | source disks were VMware virtual disks | Proxmox may have one physical disk/datastore |
| VM disks | 60 GiB OS disk, 80 GiB `/var` disk | 25 GiB OS virtual disk, 15 GiB `/var` virtual disk |
| Storage purpose | preserve source layout shape | preserve partition/mount layout with smaller sizes |

Having one physical disk on the Proxmox host does not prevent creating two virtual disks for the VM. Both virtual disks can live on the same Proxmox datastore. This preserves the guest OS shape while accepting that there is no physical disk redundancy.

Recommended target disk model:

| VM Disk | Size | Guest Purpose |
| --- | ---: | --- |
| disk 0 | 25 GiB | `/boot/efi`, `/boot`, `/`, `/usr`, `/tmp`, `/home`, `/opt`, `swap` |
| disk 1 | 15 GiB | dedicated `/var` disk |

Recommended target network model:

| VM NIC | Proxmox Bridge | Purpose |
| --- | --- | --- |
| nic 0 | `vmbr0` or configured main bridge | all guest traffic |

Do not attempt to recreate the source VMware NIC names. Interface names inside the new guest may differ depending on the template and Proxmox device model.

## Configure With OpenTofu

OpenTofu should only create the Proxmox VM and provide initial access.

| Area | Configure in OpenTofu |
| --- | --- |
| Provider | Proxmox provider endpoint, credentials, TLS behavior |
| VM identity | VM name, VM ID, hostname |
| Placement | Proxmox node, datastore, resource pool if used |
| Template | Clone from existing Rocky Linux 10 cloud-init template |
| CPU | 4 vCPU |
| Memory | 8192 MiB |
| Disks | target: 25 GiB OS disk, 15 GiB `/var` disk |
| Network | target: 1 virtual NIC mapped to the main Proxmox bridge |
| Network intent | one target IP, gateway, DNS, and search domain |
| Cloud-init user | One initial admin user only |
| SSH access | Inject SSH public key for the initial admin user |
| Tags | e.g. `rocky`, `bastion`, `example`, `managed-by-tofu` |
| Description | Mention source report and intended role |
| Guest agent flag | Enable QEMU guest agent support in Proxmox |
| Outputs | VM ID, VM name, hostname, IPs, SSH user, SSH host |

Suggested OpenTofu VM values:

| Setting | Value |
| --- | --- |
| `vm_name` | `example-bastion-01` |
| `hostname` | `example-bastion-01.example.test` or target equivalent |
| `cpu_cores` | `4` |
| `memory_mb` | `8192` |
| `os_disk_size` | `25G` |
| `var_disk_size` | `15G` |
| `agent_enabled` | `true` |

Source network mapping for reference only:

| Source NIC | Source IP | Purpose Guess | OpenTofu Action |
| --- | --- | --- | --- |
| `ens192` | `192.0.2.26/27` | SSH/listening address | do not recreate as separate NIC in the target environment |
| `ens224` | `198.51.100.186/27` | secondary network | do not recreate as separate NIC in the target environment |
| `ens256` | `203.0.113.154/27` | default route network | do not recreate as separate NIC in the target environment |

Target OpenTofu should create only one NIC:

| Target NIC | Bridge | Addressing |
| --- | --- | --- |
| `net0` | `vmbr0` or configured main bridge | one static target IP or DHCP intent |

OpenTofu should output enough data for Ansible inventory generation:

```text
vm_id
vm_name
hostname
ssh_user
primary_ip
all_ips
ansible_host
```

## Do Not Configure With OpenTofu

Do not put these in OpenTofu or cloud-init:

| Area | Reason |
| --- | --- |
| OS packages | Post-boot configuration belongs to Ansible |
| `fstab` | Guest OS storage configuration belongs to Ansible |
| LVM layout | Guest OS storage configuration belongs to Ansible |
| Users beyond initial admin | Post-boot identity config belongs to Ansible |
| SSH daemon hardening | Post-boot OS config belongs to Ansible |
| Firewalld rules | Guest firewall belongs to Ansible |
| Systemd services | Post-boot service management belongs to Ansible |
| Docker or Podman | Not detected and out of infra scope |
| Kubernetes tools | Not detected and out of infra scope |
| Certificates | Service/security config belongs outside OpenTofu |
| Template creation | Explicitly out of scope |
| Cloud image download/import | Explicitly out of scope |

## Configure With Ansible

Ansible should configure the VM after first boot.

| Area | Configure in Ansible |
| --- | --- |
| OS baseline | Rocky 10 package updates and required baseline packages |
| QEMU guest agent | Install and enable `qemu-guest-agent` if template lacks it |
| Time sync | Ensure `chronyd` is installed, enabled, and running |
| SSH daemon | Recreate intended hardening settings |
| Users/groups | Create non-cloud-init users only if intentionally needed |
| Sudo | Configure sudo policy for selected admin group |
| NetworkManager | Configure persistent connections if cloud-init is not enough |
| Static routes | Configure routes from the report if needed in target network |
| DNS | Configure resolver/search domain if not handled by cloud-init |
| Storage | Partition/format/mount the 15 GiB secondary virtual disk for `/var` |
| LVM | Recreate the source mount layout with smaller target sizes |
| Filesystems | Create XFS filesystems where needed |
| Services | Enable required baseline services |
| SELinux | Keep targeted/enforcing unless a role requires otherwise |
| Firewalld | Configure guest firewall rules if required |
| Audit/sysstat/rsyslog | Enable if matching the source baseline is desired |

Target storage layout to implement with Ansible:

| Mount | Target Size | Source Equivalent |
| --- | ---: | --- |
| `/boot/efi` | 600 MiB | same as source |
| `/boot` | 1 GiB | same as source |
| `/` | 5 GiB | same as source |
| `/usr` | 3 GiB | same as source |
| `/tmp` | 2 GiB | same as source |
| `/home` | 2 GiB | same as source |
| `/opt` | 2 GiB | same as source |
| `/var` | 15 GiB | smaller than source disk, larger than source LV |
| `swap` | 1 GiB | same as source |

The source has an 80 GiB second disk but only a 1 GiB `/var` LV. The target intentionally keeps `/var` on a second virtual disk but reduces the disk size to 15 GiB.

## Ansible Cautions

Do not blindly recreate production identities or secrets.

Do not copy these from the source VM:

```text
/etc/machine-id
SSH host keys
SSH private keys
Kubernetes certificates
Kubernetes secrets
GitLab Runner tokens
Registry credentials
Production kubeconfigs
```

The report may show source-environment user accounts. Treat those as source-environment identities, not automatic target users.

## Report-Based Decisions Needed

| Decision | Needed By |
| --- | --- |
| Proxmox node name | OpenTofu |
| Proxmox datastore name | OpenTofu |
| Rocky 10 template VM name or ID | OpenTofu |
| VM ID to assign | OpenTofu |
| Main bridge name, probably `vmbr0` | OpenTofu |
| Target IP, gateway, DNS, and search domain | OpenTofu and Ansible |
| Initial cloud-init username | OpenTofu |
| SSH public key path/value | OpenTofu |
| Exact target disk device names after boot | Ansible |
| Whether to recreate source user accounts | Ansible |
| Whether bastion needs Kubernetes client tooling | Ansible |
