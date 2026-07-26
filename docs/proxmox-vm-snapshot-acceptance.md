# Proxmox VM Snapshot Live Acceptance

## Purpose

This runbook validates `platform-proxmox-vm-snapshot` against two disposable
VMs on a single-node Proxmox VE 9 installation. It complements fake-backed
tests; it does not replace them or authorize testing against service VMs.

`platform-tools` owns CLI behavior and this acceptance procedure.
`platform-infra` owns the disposable VM lifecycle:

<https://codeberg.org/rch/platform-infra/src/branch/main/docs/proxmox-snapshot-test-environment.md>

Keep exact VMIDs, names, addresses, SSH paths, checksums, and command output in
private operator evidence. Public records must remain sanitized.

## Scope

Live acceptance covers:

- VMID, exact-name, and environment selectors
- local Proxmox and SSH transport paths
- dry-run and confirmation behavior
- disk-only and saved-memory snapshot creation
- list, rollback, and normal deletion
- stopped and explicit-start rollback behavior
- observable disk and memory restoration
- duplicate snapshot-name collision and incomplete-checkpoint preflight failures
- snapshot-name schema and reserved-name handling
- serial two-VM environment behavior

Do not inject live locks, target drift, storage failures, or partial operations.
Those unsafe paths remain fake-backed tests.

Snapshots are temporary rollback points, not durable backups. Multi-VM
operations are serial rather than atomic; partial success is possible.

## Preconditions

Before any live operation:

1. Use the exact `platform-tools` checkout under test and record its revision.
2. Confirm its worktree state is understood and run:

   ```bash
   make test-proxmox-vm-snapshot
   ```

3. Confirm `platform-infra` provisioned exactly two disposable VMs in its
   independent `snapshot-test` state.
4. Confirm each VM has exactly `disposable`, `managed-by-tofu`, `rocky`, and
   `snapshot-test` tags.
5. Confirm no unrelated VM has the `snapshot-test` tag.
6. Confirm both VMs are running, unlocked, reachable through their dedicated
   guest keys, and have healthy guest agents.
7. Confirm each VM has the reviewed boot disk and one disposable additional
   disk.
8. Confirm neither VM hosts a platform service.
9. Confirm both snapshot lists contain only Proxmox's synthetic `current`
   entry.
10. Record the exact target set and obtain approval for the planned live test
    bundle.

Stop on any unexpected target, disk, lock, state, or snapshot.

## Connection Paths

Exercise both supported execution modes:

- invoke the CLI from the operator workstation with `--ssh` and, when needed,
  `--identity-file`
- stream or invoke the same checkout directly on the Proxmox host without
  installing a different copy

The SSH identity connects to Proxmox, not to guest VMs. Guest cloud-init keys
are used only for observable rollback checks inside the disposable guests.

## Target Gate

Immediately before every environment create, rollback, or delete dry-run and
mutation:

1. Query both expected VMs directly through structured Proxmox output.
2. Confirm exact VMID/name bindings, exact four-tag sets, non-template state,
   and absent locks.
3. Run the matching environment list or dry-run operation.
4. Compare the complete resolved target set with the two reviewed VMs.
5. Abort if either target is missing or any additional target appears.
6. Record approval for that operation and exact target set.

Do not infer intended membership from names. Environment selection requires
both `managed-by-tofu` and `snapshot-test` tags.

## Disposable Guest Fixture

The fixture is intentionally temporary and must target only the reviewed
additional disk on each disposable VM.

Before formatting anything, require all of these guards:

- the stable by-id path resolves to the reviewed additional-disk interface
- the target is a whole block device, not a partition
- its byte size exactly matches the reviewed disposable disk
- it is unmounted
- it has no existing filesystem signature
- exact VM identity and tags still pass the target gate

Create a filesystem, mount it temporarily, and write distinct baseline markers
to the boot disk and additional disk. Correct filesystem security labeling when
required by the guest template, then directly verify guest-agent filesystem
freeze and thaw before relying on disk snapshot observations.

Do not add guest fixture setup to `platform-infra`, cloud-init, a persistent
configuration role, or `fstab`. The VMs are destroyed after acceptance.

## Selector And Read-Only Checks

Verify that list operations resolve the intended targets through:

- one VMID
- one exact, unique VM name
- the `snapshot-test` environment
- the environment with `--dry-run`
- SSH transport
- direct execution on Proxmox

Record direct structured Proxmox output as the source of truth.

## Single-VM Create And Delete

On one disposable VM:

1. Dry-run exact-name snapshot creation.
2. Create through interactive confirmation without an explicit description.
3. Verify the generated description references the selected VMID and saved
   memory is absent.
4. List the snapshot through the CLI and direct Proxmox output.
5. Delete it through the strong VMID-plus-snapshot confirmation.
6. Verify direct absence.

This proves exact-name selection, default description behavior, interactive
create confirmation, and strong single-VM deletion confirmation before later
use of `--yes`.

## Environment Disk Snapshot

For the exact two-VM environment:

1. Re-run the target gate.
2. Dry-run creation with an explicit description.
3. Create through interactive confirmation.
4. Verify exactly one matching disk-only snapshot on each VM.
5. Attempt duplicate creation with `--yes`; require a nonzero preflight failure
   and no mutation.
6. Confirm all baseline markers remain unchanged after the rejected duplicate.

Then change the boot- and additional-disk markers on both guests and verify an
incorrect strong rollback confirmation fails without mutation.

## Rollback Behavior

First test the default stopped-state contract:

1. Re-run the target gate and rollback dry-run.
2. Roll back through the exact environment-plus-snapshot confirmation.
3. Verify both VMs are stopped.
4. Start both deliberately.
5. Remount the temporary additional filesystems.
6. Verify all baseline disk markers were restored.

Change the markers again, then repeat rollback with
`--start-after-rollback`. Verify both VMs reach `running` and all baseline
markers are restored.

## Saved-Memory Behavior

On one VM:

1. Write a baseline marker in `/dev/shm`.
2. Dry-run and create a snapshot with `--include-memory`.
3. Verify direct Proxmox output reports saved memory state.
4. Replace the RAM marker.
5. Dry-run and roll back with `--start-after-rollback`.
6. Verify the VM is running and the baseline RAM marker returned.
7. Dry-run and delete the saved-memory snapshot normally.

Saved-memory behavior depends on the recorded QEMU machine and CPU state. The
observed result applies to the tested host and is not a durable-backup claim.

## Incomplete Checkpoint Failure

Create a disk-only snapshot on only one disposable VM, then run environment
rollback and deletion against that snapshot. Both commands must fail during
remote preflight before any mutation because the second VM lacks the snapshot.

After each failure, verify:

- the isolated snapshot still exists exactly once
- the other VM remains snapshot-free
- both VMs retain their prior power state
- all guest markers remain unchanged

Delete the isolated snapshot normally after the negative check.

## Schema And Timing Checks

Use installed Proxmox schemas or authoritative version-matched source to verify
the snapshot-name character set, length, and reserved names without issuing an
invalid live mutation.

Also invoke the checkout under test with a valid selector, `--dry-run`, and an
unreachable `.invalid` SSH target for representative invalid names: too short,
too long, an invalid character, `current`, and case-varied `pending`. Require
the expected local validation error and no SSH or Proxmox output. Any attempted
connection fails the check. These probes establish that CLI validation occurs
before remote execution; the maintained fake-backed suite covers the complete
boundary matrix.

For explicit-start rollback, record the complete CLI duration as host-specific
observational evidence without imposing a universal limit. Separately confirm
that, after the synchronous Proxmox rollback command returns, the tool's
post-command power-state poll reaches `running` within its 30-second bound.
Query structured VM status immediately afterward.

## Final Snapshot Cleanup

Delete every remaining test snapshot through the normal CLI path. Never use
forced metadata-only deletion.

Before handing back to `platform-infra`, verify:

- each VM has only the synthetic `current` snapshot entry
- both VMs are unlocked and in the expected power state
- the exact environment target set remains unchanged
- temporary snapshot storage artifacts are absent
- OpenTofu reports no drift

Record detailed evidence privately and publish only a sanitized summary.
Destruction of the disposable VMs requires a separately generated, reviewed,
and approved OpenTofu destroy plan.

## Acceptance Result

Live acceptance completed successfully on a single-node Proxmox VE 9 host in
July 2026. It covered all operations and negative checks in this runbook,
including observable disk and memory restoration, fail-closed incomplete
environment handling, normal snapshot deletion, and VM teardown through the
owning OpenTofu root.

That result does not authorize environment mutations in `dev`, `homelab`, or
another platform environment. Each environment requires reconciled tags,
complete target-set review, and separate operational approval.
