# Plan: Proxmox Development Snapshot Tool

## Goal

Add a safe, on-demand operator command for creating, listing, rolling back, and deleting Proxmox VM snapshots during development. The command should let a developer checkpoint either one exact VM or every correctly tagged `platform-infra` VM in one environment before a major configuration change, then restore or remove that checkpoint without assembling `qm` commands manually.

The intended workflow is short-lived development rollback, not scheduled snapshots, backup retention, or disaster recovery.

## Why This Belongs in `platform-tools`

Snapshots are transient operator actions rather than desired VM state. Modeling timestamped or manually named snapshots in OpenTofu would make retries, retention, asynchronous completion, and out-of-band changes difficult to reconcile. The companion-repository review recorded for this plan identified `bpg/proxmox` `0.106.0`, which has no VM snapshot resource or data source; reverify the pinned provider version before implementation.

`platform-tools` already owns reusable Proxmox operator helpers. In particular, `platform-proxmox-vm-cleanup` establishes the relevant conventions:

- A maintained Bash command under `bin/`.
- Direct execution on a Proxmox host or self-streaming execution through SSH.
- VMID checks and an optional exact-name guard before mutation.
- A separate inspection phase before destructive remote execution.
- Interactive confirmation unless the operator explicitly bypasses it.
- User-facing documentation under `docs/`.

`platform-infra` should continue to own VM creation, shape, IDs, and tags. It should not own snapshot operations.

## User Outcomes

A developer can:

- Create one checkpoint across all managed VMs in `dev` before a major `platform-config` change.
- Create a checkpoint for one VM selected by exact name or VMID.
- List snapshots for the selected VM or environment.
- Roll one VM or a selected environment back to a named checkpoint.
- Delete a named checkpoint after validating the change.
- Preview every selection and action with `--dry-run`.
- See an explicit per-VM success or failure summary after a multi-VM operation.

## Scope

- Add `bin/platform-proxmox-vm-snapshot`.
- Implement `create`, `list`, `rollback`, and `delete` subcommands.
- Support local Proxmox execution and `--ssh <user@host>` using the existing self-streaming pattern.
- Select one VM by numeric VMID or exact unique VM name.
- Select one environment by exact Proxmox tags.
- Target Proxmox VE 9 for the first version.
- Use structured local Proxmox API reads through `pvesh --output-format json` and native `qm` commands for mutations.
- Process environment VMs serially in deterministic VMID order.
- Add focused behavior tests with fake `pvesh`, `qm`, and `ssh` commands; tests must never contact Proxmox.
- Add installation, verification, help, and user documentation integration.
- Document the required `platform-infra` environment-tag contract.

## Non-Goals

- Scheduled or automatic snapshot cycles.
- Treating snapshots as backups.
- Proxmox Backup Server or `vzdump` policy management.
- Snapshot retention schedules or time-based pruning.
- Application-consistent database or distributed-system checkpoints.
- Atomic multi-VM snapshots or rollbacks; Proxmox performs one VM operation at a time.
- Snapshotting every running VM in the cluster without an environment selector.
- Partial, regular-expression, or glob VM-name matching.
- Discovering environments from VM-name prefixes.
- Supporting multiple Proxmox nodes in the first version. `platform-infra` currently targets one configured node and has multi-node behavior deferred.
- Proxmox REST API authentication in the first version.
- Supporting Proxmox VE 8 or older versions in the first release.
- Bypassing Proxmox locks or force-deleting snapshot metadata.
- Managing snapshots through OpenTofu provisioners or side effects.

## Current Context

- `platform-tools/bin/platform-proxmox-vm-cleanup` is the implementation precedent for SSH streaming, target inspection, exact-name guards, and confirmation.
- `platform-tools/Makefile` explicitly lists maintained and installed shell commands in `SHELL_TOOLS`.
- `platform-tools/AGENTS.md` requires `make verify`, behavior tests, and ShellCheck when available.
- The first supported baseline is Proxmox VE 9. Exact development-host package versions and command behavior remain a real-host acceptance and release requirement; fake-backed implementation may proceed from pinned official PVE 9 schemas.
- Current Proxmox VE 9 documentation exposes structured VM and snapshot data through `pvesh`; `qm list` and `qm listsnapshot` are human-oriented and are not suitable safety interfaces for exact matching.
- The implementation host needs `pvesh` and `jq`, plus `qm` for mutations. An operator workstation using `--ssh` also needs `jq` to validate and relay the remote preflight operation-state manifest.
- The recorded companion-repository assumptions are that `platform-infra` exposes `vm_ids`, attaches `managed-by-tofu`, and currently lacks automatic environment tags for every private VM definition. Reverify these facts in the companion repository before environment release acceptance.
- The recorded companion-repository storage default is raw disks on `local-lvm`; reverify it before documentation is finalized. Snapshot capability depends on the storage backend, not only the disk format, and Proxmox remains authoritative.
- Proxmox VM snapshots are deleted with the VM and normally share the VM storage failure domain. They are rollback points, not durable backups.

## Design Decisions

### Command Shape

Use one command with subcommands:

```text
platform-proxmox-vm-snapshot create [options]
platform-proxmox-vm-snapshot list [options]
platform-proxmox-vm-snapshot rollback [options]
platform-proxmox-vm-snapshot delete [options]
```

Keep snapshot terminology explicit. Do not overload the existing cleanup command.

### Connection Model

Match the existing Proxmox helpers:

- Run directly on a Proxmox host when `--ssh` is absent.
- With `--ssh`, locate the current script and stream it to `bash -s` on the remote Proxmox host.
- Support `--identity-file` with `IdentitiesOnly=yes`.
- Require `bash`, `pvesh`, `qm`, and `jq` remotely.
- Require local `ssh` and `jq` when `--ssh` is used.
- Do not require installation of `platform-tools` on the Proxmox host.
- Do not read or transmit the OpenTofu API token.

### Structured Read Model

Use `pvesh --output-format json` for read-only discovery and preflight. Confirm the exact Proxmox VE 9 endpoint syntax on the development host before implementation, then use the version-matched node, QEMU inventory, current configuration, current status, and snapshot endpoints.

- Discover the configured node and abort unless the setup satisfies the first-version single-node contract.
- Use the node's QEMU inventory only to obtain candidate VMs and stable identifiers.
- Query each selected VM's current configuration, status, and snapshots through structured endpoints before relying on tags, template state, lock state, disks, or snapshot identity.
- Parse JSON with `jq` using `--arg` for operator-controlled values. Never construct a `jq` expression by interpolating a VM name, tag, snapshot name, or description.
- Fail closed on command failure, invalid JSON, missing required fields, unexpected duplicate VMIDs, or data that does not satisfy the documented PVE 9 schema assumptions.
- Keep mutations on the native `qm snapshot`, `qm rollback`, and `qm delsnapshot` commands. `pvesh` is a local structured read interface, not a second authentication path.

### Target Selection

Require exactly one selector:

```text
--vmid <numeric-vmid>
--vm-name <exact-name>
--environment <environment-tag>
```

Selection requirements:

- `--vmid` must identify exactly one existing QEMU VM.
- `--vm-name` must match exactly one QEMU VM. Abort on zero or multiple matches and print candidate VMIDs where useful.
- `--environment dev` must select only VMs carrying both exact tags `managed-by-tofu` and `dev`.
- Reject an empty value and the closed initial reserved set `managed-by-tofu`, `all`, and `*` as environment names. Keep required ownership tags in one implementation constant and dynamically reject every value in that constant if ownership tags are added later. The environment tag must remain distinct from every required ownership tag, so the two-tag requirement can never collapse into one tag.
- Match tags as complete tokens, not substrings. Confirm the PVE 9 tag representation in Phase 1 and parse it into exact tokens before comparison.
- Exclude templates from environment selection and report that exclusion. Reject direct `--vmid` or `--vm-name` selection when it resolves to a template.
- Abort when environment selection is empty.
- Sort selected VMs numerically by VMID before display or mutation.
- Do not provide an unrestricted `--all-running` selector.

Environment membership must not be inferred from names such as `example-dev-*`.

### Snapshot Identity

Require `--snapshot-name <name>` for `create`, `rollback`, and `delete`.

- Apply version-independent validation before remote execution: reject empty values, control characters, `current`, and case-insensitive `pending`.
- Do not silently sanitize operator input into another name.
- Use the same snapshot name for every VM in an environment checkpoint.
- Accept an optional `--description <text>` for `create`.
- When the operator omits a description, use `Created by platform-proxmox-vm-snapshot for environment <environment>` for environment selection and `Created by platform-proxmox-vm-snapshot for VMID <vmid>` for single-VM selection. Do not put secrets or full command lines in it.

The implementation must confirm the installed Proxmox VE 9 snapshot-name schema or observed rejection behavior before encoding any stricter character or length validation. Treat `current` and `pending` as project-reserved even if the installed schema reports only one of them. Do not invent undocumented limits or silently sanitize input.

### Create Behavior

Use:

```text
qm snapshot <vmid> <snapshot-name> [--description <text>] [--vmstate 1]
```

Requirements:

- Default to disk/configuration snapshots without saved memory state.
- Add `--include-memory` as an explicit opt-in that maps to `--vmstate 1`.
- Warn that memory snapshots consume additional storage and can carry QEMU machine-version constraints.
- Before creating anything, verify that no selected VM already has the snapshot name.
- Print every selected VM, status, relevant lock state, and disk configuration before confirmation.
- Refuse selected VMs with any nonempty Proxmox lock unless Phase 1 establishes and documents a safe exception. Never call `qm unlock`.
- Require a create confirmation after preflight. Prompt `Create snapshot <name> for <count> VM(s)? [y/N]`; `--yes` may skip this prompt. Creation consumes storage even though it is less destructive than rollback or deletion.
- Allow snapshots of running VMs, subject to Proxmox/storage support.
- Do not manually freeze guest filesystems in the first version. Rely on Proxmox behavior and document that a live snapshot may only be crash-consistent.
- If Proxmox rejects unsupported disk storage or another runtime condition, report the exact VM and command failure without claiming a complete environment checkpoint.

### List Behavior

- Query the structured snapshot endpoint through `pvesh` for each selected VM.
- List requires a target selector but not `--snapshot-name`.
- Clearly separate output by VMID and VM name.
- Listing is non-mutating and does not require confirmation.
- Compare decoded JSON snapshot-name fields for exact equality. Prefix or substring matches must never satisfy collision, rollback, or deletion preflight.
- Handle the synthetic `current` entry explicitly and fail closed on missing or malformed snapshot identity fields.
- Accept `list --dry-run` as equivalent to `list`; both are read-only and never prompt.

### Rollback Behavior

Rollback is destructive and must be deliberately harder than creation.

- Before changing any VM, verify that the named snapshot exists on every selected VM.
- Abort the entire environment rollback during preflight if any selected VM lacks the snapshot.
- Refuse any nonempty Proxmox lock unless Phase 1 records a safe exception.
- Print target VM configuration, current status, and snapshot details.
- Require interactive confirmation unless `--yes` is supplied.
- For one VM, require typing the VMID and snapshot name.
- For an environment, require typing the environment and snapshot name.
- Do not use `--yes` in documentation examples for ordinary interactive use.
- Confirm the exact target-host behavior in Phase 1. Proxmox VE 9 documentation indicates that rollback stops a running VM and supports `qm rollback <vmid> <snapshot-name> --start 1` for an explicit post-rollback start.
- Default to invoking rollback without `--start`, leaving the VM stopped after rollback.
- Map `--start-after-rollback` to `qm rollback ... --start 1`; do not add a separate `qm start` path unless observed target-host behavior requires and documents it.
- After a requested restart, poll structured current status for a bounded interval established in Phase 1 and require the final Proxmox state to be `running`. Treat command failure, timeout, malformed status, or another final state as failure. This verifies QEMU power state, not guest or application readiness.
- Process VMs serially and report partial completion if a later rollback fails. Do not describe multi-VM rollback as atomic.

### Delete Behavior

- Before deleting anything, verify that the named snapshot exists on every selected VM.
- Abort environment deletion during preflight if any selected VM lacks it.
- Print every target and require confirmation unless `--yes` is supplied.
- For one VM, require typing the VMID and snapshot name.
- For an environment, require typing the environment and snapshot name.
- Delete serially with `qm delsnapshot <vmid> <snapshot-name>`.
- Never use forced metadata-only deletion in the normal path.
- Warn that deleting or merging snapshots can create significant storage I/O and may affect running VMs.

### Dry Run and Failure Handling

Add `--dry-run` to all subcommands.

- Resolve and fully print targets.
- Perform non-mutating preflight checks.
- Print the exact logical action without executing snapshot, rollback, delete, stop, or start commands.
- Never prompt during dry-run.

For actual multi-VM mutations:

- Run serially.
- Record each VM as `succeeded`, `failed`, or `not attempted`.
- Stop starting new mutations after the first failure by default.
- Print a final summary and return nonzero if any target failed or was not attempted.
- Treat rollback as failed when the requested `--start-after-rollback` outcome is not achieved, even if snapshot restoration completed; print that distinction in the per-VM detail.
- Do not automatically undo successful earlier operations; compensating rollback or deletion could compound the failure.

### Confirmation and Target Drift

Apply the same revalidation contract to local and SSH mutations:

1. Resolve, inspect, and canonically sort all targets.
2. Complete every non-mutating operation-wide preflight check.
3. Prompt when confirmation is required; `--yes` skips only this prompt.
4. Resolve and inspect the targets again for every mutation, including `--yes`.
5. Compare the exact canonical target identities and repeat mutation-specific safety checks before the first mutation.

Canonical target identity must include Proxmox node, numeric VMID, and exact VM name. A different discovery order is not drift after canonical sorting. Abort before mutation when a VM is added, removed, renamed, moved to another node, or replaced under a reused VMID with a different name. Node/VMID/name equality cannot prove that a VM was not recreated with the same identity and configuration; retain this as a documented residual risk.

Before each later VM in a serial operation, re-resolve the selector and compare the not-yet-attempted expected target identities and sanitized config, status, lock, disk, and snapshot state after excluding already attempted VMIDs. Stop on drift and classify remaining targets as `not attempted`. This filtering is necessary because a successful rollback may itself restore an earlier name or tag set on an already attempted VM.

Follow the cleanup helper's two-phase remote model:

1. Stream the command remotely in inspection/preflight mode.
2. Prompt on the local operator terminal when confirmation is required.
3. Capture a canonical JSON operation-state manifest on the workstation while showing the same sanitized state to the operator.
4. Stream the command and expected manifest as a framed stdin payload, store them in a private remote temporary directory, execute the action, and remove the temporary files on exit.

Pass the normalized selector and snapshot name as safely quoted arguments, validate the manifest with local and remote `jq`, and repeat all safety checks in the action phase. Internal flags are transport details, not an authorization boundary; direct invocation must still require explicit `--yes`, a restricted manifest file, and exact state comparison before mutation. This contract is mandatory for create, rollback, and delete.

## Expected CLI Contract

The exact help layout may follow existing style, but the public options should be equivalent to:

```text
Usage: platform-proxmox-vm-snapshot <create|list|rollback|delete> [options]

Target selector; exactly one required:
  --vmid <vmid>                 Select one numeric VMID.
  --vm-name <exact-name>        Select one exact, uniquely named VM.
  --environment <tag>           Select VMs tagged managed-by-tofu and <tag>.

Snapshot options:
  --snapshot-name <name>        Required except for list.
  --description <text>          Create-only snapshot description.
  --include-memory              Create-only saved VM memory state.
  --start-after-rollback        Rollback-only explicit VM start.

Connection and safety:
  --ssh <user@host>             Run Proxmox work on a host over SSH.
  --identity-file <path>        SSH identity for --ssh.
  --dry-run                     Resolve, inspect, and print without mutation.
  --yes                         Skip mutation confirmation.
  -h, --help                    Show help.
```

Reject nonsensical combinations, including:

- `--description` without `create`.
- `--include-memory` without `create`.
- `--start-after-rollback` without `rollback`.
- `--yes` for non-mutating `list`.
- `--identity-file` without `--ssh`.
- `--yes` together with `--dry-run`.
- Multiple target selectors.
- Repeated singleton options or incomplete internal target manifests.
- Internal remote-execution flags combined with `--ssh`, `--dry-run`, or another internal mode.

## Example Workflows

The mutating environment examples in this plan describe the intended post-reconciliation workflow. Do not publish them as supported user guidance until the `platform-infra` environment-tag release gate is satisfied.

Create an environment checkpoint:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@pve \
  --environment dev \
  --snapshot-name before-vault-reconfiguration \
  --description "Before major Vault configuration changes"
```

Create a single-VM checkpoint:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@pve \
  --vm-name example-dev-vault-01 \
  --snapshot-name before-upgrade
```

Inspect an environment:

```bash
platform-proxmox-vm-snapshot list \
  --ssh root@pve \
  --environment dev
```

Preview an environment rollback:

```bash
platform-proxmox-vm-snapshot rollback \
  --ssh root@pve \
  --environment dev \
  --snapshot-name before-vault-reconfiguration \
  --dry-run
```

Perform the rollback and explicitly restart rolled-back VMs:

```bash
platform-proxmox-vm-snapshot rollback \
  --ssh root@pve \
  --environment dev \
  --snapshot-name before-vault-reconfiguration \
  --start-after-rollback
```

Delete a validated checkpoint:

```bash
platform-proxmox-vm-snapshot delete \
  --ssh root@pve \
  --environment dev \
  --snapshot-name before-vault-reconfiguration
```

## Cross-Repository Integration

Environment selection needs a guaranteed environment tag. A separately owned companion change in `platform-infra` must make each root automatically apply both ownership and environment tags, conceptually:

```hcl
locals {
  environment  = "dev"
  default_tags = ["managed-by-tofu", local.environment]
}
```

The `platform-infra` owner must apply the equivalent change to every environment root and reconcile existing VMs before environment mutations are considered ready for use. Verify the companion repository's actual tag-merging behavior as part of that work rather than relying on this plan to establish it.

This is a release prerequisite for an enabled mutating `--environment` path. Do not release the complete tool with environment mutations enabled until the companion change is applied, existing VMs are reconciled, and a dry-run target set is manually compared with Proxmox. Before that gate is satisfied, environment selection and mutation logic may be exercised with fake fixtures, and real selection may be exercised with `--dry-run`, but only single-VM mutation is operationally supported. The tool must always document that tags define membership, print the complete selected set before mutation, and never claim it can detect an environment VM whose environment tag is missing.

Do not make `platform-tools` parse `platform-infra` tfvars or OpenTofu state in the first version. Tag-based selection keeps the helper reusable and avoids coupling it to checkout layout, local state availability, or private configuration paths.

## Implementation Tasks

### Phase 1: Confirm Proxmox VE 9 Behavior

- [ ] Record `pveversion -v`, including the installed `qemu-server`, `pve-common`, and `pve-manager` versions used for development.
- [ ] Inspect `qm help snapshot`, `qm help rollback`, and `qm help delsnapshot` on that host.
- [ ] Confirm that rollback stops a running VM and that `qm rollback ... --start 1` provides the intended explicit restart behavior.
- [ ] Observe rollback command completion and status-transition timing so restart verification has a justified polling interval and timeout rather than an invented value.
- [ ] Confirm the installed snapshot-name schema or observed rejection behavior, including the treatment of `current` and `pending`.
- [ ] Confirm the exact `pvesh --output-format json` commands for node discovery, QEMU inventory, current configuration, current status, and snapshot listing.
- [ ] Confirm the structured representation of VMID, node, name, tags, templates, locks, disks, status, snapshot name, and the synthetic `current` entry.
- [x] Capture minimal source-derived PVE 9 fixtures with synthetic names and storage references and no private infrastructure data.
- [x] Add `tests/proxmox-vm-snapshot/fixtures/README.md` recording the source revisions, endpoint contract, retained fields, and redaction rules.
- [ ] Record the observed package versions, command syntax, and adjusted assumptions in this plan's Progress Log and Decision Log.

Validation gate:

- [ ] Every JSON field and mutation option used by the implementation is backed by observed PVE 9 output or matching authoritative documentation.
- [ ] No production parser depends on `qm list` or `qm listsnapshot` presentation output.

### Phase 2: Add the Behavior Test Harness

- [x] Add focused shell tests under `tests/proxmox-vm-snapshot/` following the repository's temporary-directory and `PATH`-injection conventions.
- [x] Add fake `pvesh`, `qm`, and `ssh` commands that read test-owned state and never contact Proxmox.
- [x] Make fake command logs preserve argument boundaries so descriptions and hostile inputs can be tested without flattening arguments into one string.
- [x] Add synthetic JSON fixtures for single-node inventory, tags, templates, locks, disks, status, snapshots, malformed JSON, and target drift.
- [x] Add CLI validation tests for missing values, repeated singleton options, invalid option combinations, selectors, internal modes, and connection options.
- [ ] Test that exactly one valid node is accepted and zero-node, multi-node, duplicate-node, and malformed node discovery fail before VM selection or mutation.
- [x] Test VMID selection, exact unique-name selection, rejection of partial and duplicate names, and numeric VMID ordering.
- [x] Test that environment selection requires exact ownership and environment tags, rejects `managed-by-tofu`, `all`, and `*`, excludes templates, and does not accept differently cased tags.
- [ ] Test direct template rejection, every nonempty lock rejection, malformed JSON, missing required fields, and unexpected duplicate identities.
- [x] Test exact snapshot identity, prefix collisions, project-reserved names, and the synthetic `current` entry.
- [x] Test create collision preflight, default and explicit descriptions as single arguments, default no-memory behavior, and `--include-memory` mapping only to `--vmstate 1`.
- [x] Test rollback and delete abort before mutation when any target lacks the snapshot, require strong confirmation, and never pass a forced-delete option.
- [x] Test rollback leaves the VM stopped by default and adds `--start 1` only for `--start-after-rollback`.
- [x] Test requested restart success, rollback postcondition failure, and bounded status timeout behavior.
- [x] Test dry-run never invokes mutating fake `qm` operations and never prompts.
- [x] Test first-failure handling, rollback postcondition detail, final summaries, and nonzero partial-operation exits.
- [x] Make fake `pvesh` enforce structured endpoint arguments and fake `qm` accept only `snapshot`, `rollback`, and `delsnapshot` mutations.
- [x] Add a dedicated `test-proxmox-vm-snapshot` Make target and include it in `make test`.

Validation gate:

- [ ] Initial focused tests fail because the command does not yet exist or behavior is not implemented, rather than because the harness contacts real infrastructure.
- [ ] Test fixtures contain no private infrastructure data.

### Phase 3: Implement Local Read and Mutation Behavior

- [x] Add `bin/platform-proxmox-vm-snapshot` using `#!/usr/bin/env bash` and `set -euo pipefail`.
- [x] Reuse existing conventions for logging, path expansion, command checks, and array-based command invocation without creating a new shared Proxmox library.
- [x] Implement strict subcommand and option validation, including `--identity-file` requiring `--ssh`.
- [x] Require structured-read tools and `qm` for mutations and enforce the first-version single-node contract.
- [x] Implement exact VMID, exact unique name, and dual-tag environment selection from structured data.
- [x] Implement deterministic operation-state records, template handling, lock rejection, status/config/disk inspection, and numeric VMID sorting.
- [x] Implement grouped list output and exact snapshot identity checks from decoded JSON fields.
- [x] Implement create preflight, confirmation, default descriptions, optional memory state, and serial execution.
- [x] Implement delete preflight, strong confirmation, serial execution, and the no-force invariant.
- [x] Implement rollback preflight, strong confirmation, `--start-after-rollback`, current-parent verification, and serial execution.
- [x] Implement bounded structured power-state polling after rollback.
- [x] Implement dry-run behavior for all subcommands; treat `list --dry-run` as ordinary read-only listing.
- [x] Bind confirmation to canonical config, status, snapshot, and target state and repeat comparison even when `--yes` skips confirmation.
- [x] Before each later mutation, compare every not-yet-attempted target's expected operation state without claiming atomicity.
- [x] Implement explicit `succeeded`, `failed`, and `not attempted` result states, stop after the first failure, always print the final summary, and return nonzero for partial completion.
- [x] Capture mutation failures explicitly so `set -e` cannot terminate before the final summary.

Validation gate:

- [ ] `bash -n bin/platform-proxmox-vm-snapshot` passes.
- [ ] Focused local fake-backed tests cover normal, invalid, boundary, dry-run, confirmation, drift, and partial-failure paths.
- [ ] Manual review confirms no `eval`, unquoted operator input, interpolated `jq` programs, lock bypass, or forced snapshot deletion.

### Phase 4: Implement SSH Streaming and Drift Protection

- [x] Reuse self-path resolution, `--identity-file`, `IdentitiesOnly=yes`, and Bash `%q` remote-command quoting from `platform-proxmox-vm-cleanup`.
- [x] Check local `ssh` and `jq` plus remote structured-read and mutation prerequisites.
- [x] Implement remote preflight with human inspection output separated from a canonical JSON operation-state manifest.
- [x] Validate the manifest locally and transport it through framed stdin into a private remote temporary file rather than process arguments.
- [x] Require internal action mode to receive a restricted manifest file plus explicit `--yes`, rerun every safety check, and compare canonical operation state before mutation.
- [x] Test local and remote target and operation-state drift before mutation and between serial VM mutations.
- [x] Test that a different discovery order is accepted after canonical sorting.
- [x] Test script streaming, identity-file handling, hostile descriptions, oversized manifests, SSH target validation, and internal-mode rejection without making a network connection.

Validation gate:

- [ ] Tests demonstrate that local and remote mutations cannot begin after target drift or incomplete preflight.
- [ ] Tests demonstrate that every operator-controlled value remains one argument across the SSH boundary.

### Phase 5: Integrate, Document, and Satisfy the Environment Gate

- [x] Add `platform-proxmox-vm-snapshot` to `SHELL_TOOLS` in `Makefile` so `make install`, `make verify`, and `make shellcheck` include it.
- [x] Add the command to the tool table, requirements, and single-VM usage examples in `README.md`.
- [x] Add `docs/proxmox-vm-snapshot.md` covering workflows, PVE 9 and `pvesh`/`jq` prerequisites, safety behavior, storage considerations, crash consistency, and snapshot-versus-backup limits.
- [x] Add the new document to the documentation table in `README.md` and the index in `docs/README.md`.
- [x] Update `AGENTS.md` with lasting PVE 9 prerequisites, fake-backed test guidance, and safe real-host smoke-test constraints.
- [x] Update the current `Unreleased` sections in `NEWS.md` and `CHANGELOG.md`.
- [x] Document the separately owned `platform-infra` environment-tag change and reconciliation procedure without modifying the sibling repository implicitly.
- [ ] Obtain evidence that ownership and environment tags are automatic and reconciled on existing development VMs.
- [ ] Compare an environment `--dry-run` target set with Proxmox manually before publishing mutating environment examples as supported.
- [ ] Block release of the complete tool with environment mutations enabled until the companion tag and manual dry-run evidence is recorded in the Progress Log.

Validation gate:

- [ ] Every public option and default in command help matches README and topic documentation.
- [ ] Documentation never presents snapshots as backups or multi-VM checkpoints as atomic.
- [ ] The release remains blocked while mutating environment workflows are enabled but companion tag and dry-run evidence is unrecorded.

### Phase 6: Verify and Review

- [x] Run `make test-proxmox-vm-snapshot` and record the observed result in the Progress Log.
- [x] Run `make verify` and record the observed result in the Progress Log.
- [x] Run `make test` and record the observed result in the Progress Log.
- [x] Run `make shellcheck` and record the result in the Progress Log.
- [x] Run ShellCheck explicitly over new test and fake-command scripts.
- [x] Run focused `--help`, invalid-option, and fake-backed dry-run smoke commands.
- [x] Run `git diff --check`.
- [x] Inspect the final diff for unrelated changes, unsafe command interpolation, substring identity matching, mutation before complete preflight, skipped summaries, documentation drift, and accidental private infrastructure data.
- [x] Ask review agents to focus on structured-data validation, target-selection safety, remote argument quoting, destructive confirmation, partial-failure behavior, and documentation drift.

Optional real-system acceptance, requiring explicit operator authorization:

- [ ] On a disposable development VM, create a snapshot without memory state.
- [ ] List and verify the snapshot through the tool and Proxmox.
- [ ] Make a harmless observable guest change.
- [ ] Roll back without automatic restart and verify the expected stopped state and restored change.
- [ ] Repeat with `--start-after-rollback` if operationally needed and verify the final running state.
- [ ] Delete the snapshot and verify it no longer appears.
- [ ] Exercise environment selection only with `--dry-run` until the environment release gate is satisfied.

## Acceptance Criteria

- The installed command supports create, list, rollback, and delete on Proxmox VE 9 through local execution or SSH streaming.
- Read-only discovery and preflight use validated `pvesh` JSON; mutations use native `qm` commands.
- The command aborts on multi-node setups in the first version.
- One VM can be selected only by exact VMID or exact unique name.
- One environment can be selected only by complete `managed-by-tofu` and environment tags.
- Reserved selector values cannot be used to collapse the two-tag environment requirement.
- The complete selected VM set is visible before every mutation.
- Local and remote mutations, including `--yes`, require exact node/VMID/name equality between inspection and action and abort on drift.
- Serial mutations revalidate the remaining target set and next target identity before each later VM.
- Environment operations use the same snapshot name across selected VMs and execute serially.
- Create refuses name collisions before the first mutation.
- Rollback and delete refuse incomplete environment checkpoints before the first mutation.
- Rollback and delete require strong interactive confirmation unless `--yes` is explicit.
- Dry-run performs no mutations.
- Partial failures return nonzero and identify succeeded, failed, and unattempted VMs.
- `--start-after-rollback` succeeds only when bounded structured status polling observes the final Proxmox state `running`.
- The command never bypasses Proxmox locks and never force-deletes snapshot metadata.
- Tests exercise structured-data validation, selection, preflight, quoting, confirmation, dry-run, drift, and failure paths without contacting Proxmox.
- Documentation explicitly states that snapshots are temporary development rollback points, disappear with destroyed VMs, and do not replace backups.
- The complete tool is not released with environment mutations enabled until automatic tag reconciliation and manual dry-run verification are recorded.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Incorrect environment selection affects unrelated VMs. | Require both ownership and exact environment tags, exclude templates, show all targets, and confirm destructive actions. |
| Ownership tag is passed as the environment and broadens selection. | Reject ownership and reserved selector values as environment names and test the negative cases. |
| Missing environment tags produce an incomplete checkpoint. | Make automatic tag reconciliation a release prerequisite for mutating environment workflows; state that tags are the authoritative membership boundary. |
| Name selection resolves the wrong VM. | Exact matching only; abort on duplicate names; print VMID and config. |
| VM inventory changes during local or remote confirmation. | Repeat preflight and verify the exact canonical node/VMID/name identities before mutation. |
| A VM is recreated with the same node, VMID, and name. | Repeat all current safety checks and document that the first-version identity cannot prove VM generation; require complete target review before mutation. |
| Human-oriented Proxmox output changes and creates a false match. | Use `pvesh --output-format json`, validate required fields with `jq`, and fail closed on malformed or unexpected data. |
| A multi-node cluster broadens discovery beyond the intended host. | Detect the node topology and abort unless it satisfies the first-version single-node contract. |
| One VM fails after earlier VMs succeeded. | Serial execution, stop after first failure, nonzero exit, and explicit per-VM summary; never claim atomicity. |
| Snapshot storage is unsupported or full. | Show disk configuration, rely on Proxmox capability checks, preserve exact errors, and recommend checking storage health/free space. |
| Live snapshot is not application-consistent. | Document crash-consistency limits; do not promise database or distributed consistency. |
| Memory snapshots consume substantial space. | Default off and require `--include-memory`. |
| Rollback unexpectedly changes VM power state. | Target PVE 9, verify installed behavior, omit `--start` by default, map explicit restart to rollback's supported `--start 1` option, and verify requested restart with bounded structured status polling. |
| Snapshot deletion causes storage I/O or VM latency. | Warn before deletion and process one VM at a time. |
| Operator treats snapshots as backups. | Repeat the distinction in help and docs; point to `vzdump`/PBS for durable recovery. |
| Shell injection through names, descriptions, or SSH arguments. | Validate identifiers, preserve descriptions as quoted arguments, use arrays and `%q`, avoid `eval`, and test hostile inputs. |

## Assumptions

- The initial target is a single-node Proxmox development environment.
- The operator has local or SSH access capable of running the required `pvesh` and `qm` commands.
- `jq` is available in the execution environment and on the workstation when `--ssh` is used.
- Proxmox VE 9 is the only supported major version for the first release.
- Proxmox provides the authoritative storage capability and lock checks.
- Environment snapshots are acceptable as sequential per-VM checkpoints for development.
- Developers understand that rollback may leave cross-VM services in a logically inconsistent state.
- A separate backup solution protects any data that must survive VM or datastore loss.

## Open Questions

These are implementation-time checks, not blockers to starting Phase 1:

- [ ] What exact Proxmox VE 9 package versions and structured endpoint fields are present on the development host?
- [ ] Does the installed PVE 9 snapshot-name schema reject any values beyond the project-reserved `current` and `pending` names?
- [ ] Does target-host rollback behavior match the documented stop and `--start 1` semantics without a separate `qm start` call?
- [ ] What polling interval and timeout are justified by observed PVE 9 rollback/start behavior on the development host?
- [ ] Should a later version add an explicit `--allow-partial` mode? It is intentionally excluded from the first version.
- [ ] Should a later REST API mode use a separate least-privilege token with `VM.Audit`, `VM.Snapshot`, and optionally `VM.Snapshot.Rollback`?
- [ ] Should a later version support multi-node selection by making node identity a public selector?

## Authoritative References

- Proxmox VE 9 `qm(1)` command reference: <https://pve.proxmox.com/pve-docs/qm.1.html>
- Proxmox VE API Viewer: <https://pve.proxmox.com/pve-docs/api-viewer/>
- Proxmox `pvesh(1)` command reference: <https://pve.proxmox.com/pve-docs/pvesh.1.html>
- Proxmox VM documentation: <https://pve.proxmox.com/pve-docs/chapter-qm.html>
- Proxmox storage documentation: <https://pve.proxmox.com/pve-docs/chapter-pvesm.html>
- Proxmox QEMU guest-agent guidance: <https://pve.proxmox.com/wiki/Qemu-guest-agent>
- Proxmox backup documentation for the snapshot-versus-backup distinction: <https://pve.proxmox.com/pve-docs/vzdump.1.html>
- `bpg/proxmox` `v0.106.0` resource registrations: <https://github.com/bpg/terraform-provider-proxmox/blob/v0.106.0/proxmoxtf/provider/resources.go>

## Progress Log

| Date | Update | Evidence |
| --- | --- | --- |
| 2026-07-24 | Proposal created from recorded `platform-infra` assumptions, Proxmox snapshot research, provider `0.106.0`, and existing `platform-tools` helper conventions. | `docs/plans/proxmox-development-snapshots.md`; `bin/platform-proxmox-vm-cleanup`; `README.md`; `Makefile`; companion-repository facts require revalidation in Phase 1 |
| 2026-07-24 | Revised the design to target Proxmox VE 9, use structured `pvesh` JSON reads with `jq`, apply local and remote drift checks, and gate environment mutations on tag reconciliation. | User decisions; current Proxmox VE 9 documentation; `bin/platform-proxmox-vm-cleanup`; `bin/platform-proxmox-token-init`; `Makefile`; repository test conventions |
| 2026-07-25 | Implemented the command, structured fake fixtures, stateful fake `pvesh`/`qm`/`ssh`, local and remote confirmation-state binding, serial revalidation, postconditions, documentation, and Make integration. | `bin/platform-proxmox-vm-snapshot`; `tests/proxmox-vm-snapshot/`; `Makefile`; `docs/proxmox-vm-snapshot.md`; `README.md`; review agents reported no remaining material code findings |
| 2026-07-25 | Completed repository verification. Real-host acceptance and environment tag reconciliation remain open release gates. | `make verify`, `make test`, `make shellcheck`, explicit ShellCheck for new test scripts, `git diff --check`, and focused help/dry-run checks passed; no authorized PVE 9 host was available |

## Decision Log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-07-24 | Place the implementation in `platform-tools`. | On-demand snapshots are reusable operator actions, not declarative VM lifecycle state. |
| 2026-07-24 | Use SSH streaming and Proxmox host CLIs for the first version. | This matches existing Proxmox helpers and avoids introducing a second authentication path. |
| 2026-07-24 | Support a whole environment or one exact VM. | Development changes may affect the complete environment or one service VM. |
| 2026-07-24 | Select environments by ownership and environment tags. | Tags are safer and less coupled than parsing private tfvars, names, or OpenTofu state. |
| 2026-07-24 | Keep snapshots on demand with no automatic retention cycle. | The goal is deliberate development checkpoints around major configuration changes. |
| 2026-07-24 | Support Proxmox VE 9 only in the first release. | A defined major-version baseline makes command and schema assumptions reviewable and testable. |
| 2026-07-24 | Use `pvesh` JSON for reads and `qm` for mutations. | Structured reads avoid safety decisions based on human-oriented `qm list` and `qm listsnapshot` output while retaining native mutation commands. |
| 2026-07-24 | Require local and remote target-drift checks. | VM inventory can change during either local or SSH confirmation; both paths need the same node/VMID/name equality contract. |
| 2026-07-24 | Gate environment mutation readiness on tag reconciliation. | The tool cannot detect an intended environment VM whose required environment tag is missing. |
| 2026-07-25 | Bind confirmation to sanitized operation state. | Node/VMID/name alone cannot detect config, status, lock, disk, or snapshot drift after the operator reviews preflight output. |
| 2026-07-25 | Transport remote state through framed stdin. | Operation manifests can exceed per-argument limits and should not expose VM metadata in remote process arguments. |
