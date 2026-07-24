# Proxmox VE 9 Fixture Contract

These fixtures contain synthetic names and storage references only. They model
the minimum JSON fields used by `platform-proxmox-vm-snapshot` and must not be
replaced with unreviewed output from a real environment.

The field shapes and endpoint paths were derived from the Proxmox VE 9.2.3
manuals and these official PVE 9 source revisions:

- `pve-common` `389a003d691b94c2dd6cd09d4acb276faa445c91`
- `qemu-server` `601c77f89cf57551ae6159570415ec261f6ee8a5`
- `pve-manager` `e122fb2bde72575f24121dd00c3f35239446bfac`

Modeled endpoints:

```text
GET /nodes
GET /nodes/<node>/qemu
GET /nodes/<node>/qemu/<vmid>/config?current=1
GET /nodes/<node>/qemu/<vmid>/status/current
GET /nodes/<node>/qemu/<vmid>/snapshot
```

Before real-host acceptance, record the exact `pveversion -v` output, confirm
the endpoint schemas, and compare sanitized stopped, running, template, locked,
and snapshot responses. Remove VM names, addresses, storage IDs, descriptions,
and any other environment-specific data before adding new fixtures.
