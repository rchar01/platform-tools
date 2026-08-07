# Plan: Migrate Platform PKI to Python

## Status

Phase 0 in progress. Python command implementation has not started.

## Goal

Replace the PKI Bash implementations with one maintainable Python package while
preserving the existing command interfaces, persisted state, security
boundaries, and crash-recovery behavior. Add a unified `platform-pki` CLI as an
additional interface.

## Scope

- Migrate all 18 existing `platform-pki-*` commands to shared Python code.
- Preserve every existing executable name as a supported compatibility entry
  point.
- Add a unified `platform-pki` command that dispatches to the same handlers.
- Preserve existing OpenSSL, OpenSSH, `age`, `tar`, GNU `mv`, and locking
  subprocess boundaries where they remain necessary.
- Preserve existing inventory, policy, record, journal, manifest, state-tree,
  output, and exit-status contracts.
- Introduce Python-native models for records and transaction states without
  changing their persisted encodings during the initial migration.
- Retire PKI Bashly sources and shared PKI shell libraries only after all PKI
  commands have migrated and passed compatibility gates.

## Non-Goals

- Do not rewrite cryptographic operations with a Python cryptography library.
- Do not remove or rename existing `platform-pki-*` commands.
- Do not convert persisted `key=value` records or journals to JSON during this
  migration.
- Do not migrate the six non-PKI Bashly tools as part of this work.
- Do not adopt PEX, pipx, a virtual environment, or OS packages before the
  repository-native installation model is proven.
- Do not weaken subprocess-backed integration, race, signal, descriptor, or
  crash-recovery tests in favor of in-process mocks.

## Approved Decisions

- Preserve all existing `platform-pki-*` executable names.
- Add `platform-pki` as a new unified alias rather than a replacement.
- Python must recover supported interrupted transactions written by the final
  Bash implementation.
- Recovery compatibility is forward-only: the previous Bash release is not
  required to recover transactions started by Python.
- Downgrade to a Bash release is permitted only after Python verifies that no
  journal, recovery marker, migration, rollover, or recovery-required state is
  unresolved.
- Build the maintained Python source into a deterministic standard-library
  zipapp for checkout and installed execution.
- Require Python 3.12 or newer.
- Use shallow unified command names that directly mirror the existing
  `platform-pki-*` executable suffixes.
- Migrate commands incrementally, with rollover and other recovery-critical
  state machines last.

## Compatibility Contract

The initial Python implementation must preserve:

- Existing command names, options, duplicate-option handling, empty-option
  handling, help output, version output, TTY colors, `NO_COLOR`, diagnostics,
  exit statuses, and no-state parser behavior.
- Inventory grammar and canonical inventory bytes.
- Ordered record fields, exact values, schema numbers, and final newline rules.
- Journal paths, field order, phases, checkpoints, and recovery boundaries.
- PKI directory layout, file types, modes, owners, link-count rules, and
  symlink rejection.
- Lock paths, acquisition order, nonblocking behavior, ownership, and reverse
  release order.
- Descriptor-based secret transport and the absence of passphrases from argv,
  environment variables, diagnostics, exceptions, and persisted state.
- Source and destination identity checks, atomic exchange/no-clobber behavior,
  file and directory durability, and final pre-publication rechecks.
- Existing fault-injection checkpoint names and shell-style signal statuses.

## Target Architecture

Begin with a small package and split modules only when implementation reveals a
real reusable boundary:

```text
src/platform_pki/
├── __init__.py
├── __main__.py
├── cli.py
├── compat.py
├── errors.py
├── paths.py
├── records.py
├── inventory.py
├── filesystem.py
├── locks.py
├── subprocesses.py
├── openssl.py
├── ssh_signatures.py
├── commands/
└── transactions/
```

The unified command and compatibility executables must dispatch to the same
handler functions. Compatibility launchers must not contain separate command
logic.

The frozen unified command mapping is:

```text
platform-pki init
platform-pki inventory-install
platform-pki csr-trust-install
platform-pki csr-recover
platform-pki certificate-export
platform-pki csr-candidate
platform-pki root-create
platform-pki intermediate-create
platform-pki service-issue
platform-pki service-renew
platform-pki service-verify
platform-pki list-expiry
platform-pki print-cert
platform-pki export-ansible
platform-pki backup
platform-pki custody-report
platform-pki ca-passphrase-verify
platform-pki ca-rollover
```

Existing nested subcommands and options follow the shallow command unchanged.
For example, `platform-pki certificate-export publish` and
`platform-pki ca-rollover prepare` dispatch to the same handlers as their
existing compatibility commands.

## Phase 0: Freeze Contracts

Goal: Make current behavior and compatibility requirements executable before
changing implementations.

Tasks:

- [x] Inventory every PKI command form and source-defined option, including
  runtime-only option relationships and duplicate rejection fields.
- [ ] Inventory remaining output, status, parser edge-case, runtime dependency,
  and installed-asset contracts.
- [x] Execute shared help precedence, equals-form, abbreviation, stream/status,
  and no-state parser edges across all 24 retained leaf routes.
- [x] Define and review the complete unified `platform-pki` command hierarchy.
- [x] Establish Python 3.12 as the minimum supported runtime; target-host
  availability remains a release-readiness check.
- [x] Inventory every persisted record, policy, manifest, pointer, journal,
  checkpoint, and schema.
- [ ] Freeze exact ordered fields, schema values, and final-newline rules for
  persisted records written from literal or dynamically assembled shell text.
- [x] Define the forward-only upgrade and clean-state downgrade procedure.
- [x] Define metadata-aware state-tree comparison that excludes raw inode values
  while preserving identity relationships and mutation behavior.
- [x] Add a differential harness capable of running Bash and Python commands on
  private copies of the same initialized state.
- [x] Define Bash-oracle retention: keep each migrated command's final Bash
  source in-tree through Phase 8 and record its exact pre-cutover commit.
- [ ] Record and preserve each command's final Bash implementation as it is cut
  over.

Validation gate:

- [x] Existing source-backed contract tests cover every retained parser route,
  option field, runtime relationship, and duplicate rejection list.
- [x] Every persisted schema family and recovery checkpoint is represented in
  the migration inventory.
- [ ] Every persisted record's exact field order, schema value, and final
  newline is source-backed by an executable contract test.
- [ ] The downgrade procedure fails closed when any unresolved state exists.

### Bash Oracle Retention

- Immediately before each compatibility command switches to Python, record the
  exact commit containing its final Bash implementation.
- Keep that command's Bashly source and required shared shell libraries in-tree
  and unchanged through the migration acceptance releases.
- Generate the oracle executable separately from the Python-backed compatibility
  executable and supply both paths to the differential harness; do not add a
  runtime implementation switch to production commands.
- Remove Bash sources only in Phase 8 after final differential acceptance. Keep
  the recorded commits and release tags indefinitely so the evidence remains
  reproducible from a Git checkout.
- After cleanup, ordinary tests exercise Python only. Re-running historical
  Bash/Python differential cases requires a checkout of the recorded oracle
  commit and is a release or compatibility investigation workflow, not an
  installed-runtime dependency.

## Phase 1: Build the Python Foundation

Goal: Introduce shared Python infrastructure without switching existing PKI
commands.

Tasks:

- [ ] Add a standard-library-only `platform_pki` package.
- [ ] Implement parser compatibility, leading help/version precedence, TTY help
  color, `NO_COLOR`, diagnostics, and status mapping.
- [ ] Implement exact-argv subprocess execution with `shell=False`, bounded
  output, minimal environments, process-group cleanup, and protected inherited
  descriptors.
- [ ] Implement strict ordered-record parsing and serialization.
- [ ] Implement inventory parsing without broadening the accepted input
  language or changing canonical bytes.
- [ ] Implement common errors that redact secret-bearing argv, descriptors, and
  child diagnostics.
- [ ] Add the read-only `platform-pki doctor` command.
- [ ] Make `doctor` report runtime prerequisites, path safety, unresolved state,
  and clean-downgrade eligibility.
- [ ] Build a deterministic zipapp from `src/platform_pki/` as
  `bin/platform-pki`.
- [ ] Run the zipapp with isolated Python startup so `PYTHONPATH`, user site
  packages, and checkout imports cannot affect execution.
- [ ] Prove direct unified-command execution and compatibility-name dispatch
  outside the checkout.

Validation gate:

- [ ] `platform-pki --help`, `--version`, parser failures, and `doctor` create no
  PKI state.
- [ ] Installed execution ignores `PYTHONPATH`, user site packages, checkout
  imports, shell startup hooks, and unsupported source overrides.
- [ ] No existing `platform-pki-*` command has changed implementation.

## Phase 2: Implement Filesystem and Locking Primitives

Goal: Prove the security and durability layer before migrating state-mutating
commands.

Tasks:

- [ ] Implement descriptor-oriented opening with `O_NOFOLLOW`, `fstat`, and
  descriptor-relative APIs where supported.
- [ ] Implement exact file and directory identity models.
- [ ] Implement trusted-ancestor, owner, mode, file-type, symlink, and link-count
  validation.
- [ ] Implement lifecycle and operation locks as ordered context managers.
- [ ] Implement atomic writes, guarded no-clobber publication, file `fsync`, and
  directory `fsync`.
- [ ] Prototype atomic exchange and no-copy publication; retain reviewed GNU
  `mv` calls where Python lacks an equivalent proven primitive.
- [ ] Preserve deterministic fault and pause barriers for race tests.

Validation gate:

- [ ] Real symlink, hard-link, source replacement, destination replacement,
  concurrent publication, permission, and durability tests pass.
- [ ] Lock acquisition and reverse release match the Bash implementation.
- [ ] Unit tests supplement rather than replace subprocess-backed tests.

## Phase 3: Migrate Read-Oriented Commands

Goal: Validate package, parser, installation, locking, and OpenSSL integration
with lower-risk commands.

Migration order:

1. `platform-pki-print-cert`
2. `platform-pki-list-expiry`
3. `platform-pki-service-verify`

Tasks for each command:

- [ ] Implement one Python handler used by both command interfaces.
- [ ] Run Bash and Python against equivalent isolated state.
- [ ] Compare status, stdout, stderr, and all state reads or mutations.
- [ ] Pass the existing focused test target without weakening assertions.
- [ ] Switch the existing executable only after differential parity is proven.
- [ ] Add and document the corresponding unified CLI route.

Validation gate:

- [ ] Command-contract and installed-tool tests pass for both interfaces.
- [ ] The first Python-backed compatibility commands are independently
  releasable.

## Phase 4: Migrate Bounded Publication Commands

Goal: Exercise validated filesystem publication without introducing CA signing
transactions.

Migration order:

1. `platform-pki-init`
2. `platform-pki-inventory-install`
3. `platform-pki-export-ansible`

Tasks:

- [ ] Preserve template lookup and custom `INSTALL_DIR`/`SHARE_DIR` behavior.
- [ ] Preserve lifecycle, authority, inventory, and export locking boundaries.
- [ ] Preserve source identities, destination identities, and atomic
  publication behavior.
- [ ] Run existing unsafe-path, race, no-op, and installed-layout tests.

Validation gate:

- [ ] Bash/Python state-tree comparisons are equivalent for success, no-op,
  invalid input, interrupted publication, and competing destination cases.

## Phase 5: Migrate Security Utilities

Goal: Move secret-sensitive and archive-oriented commands after subprocess and
descriptor handling is proven.

Migration order:

1. `platform-pki-custody-report`
2. `platform-pki-ca-passphrase-verify`
3. `platform-pki-backup`

Tasks:

- [ ] Preserve byte-bounded identity-checked inspection and secret-free output.
- [ ] Preserve minimal inherited-descriptor passphrase transport.
- [ ] Preserve suppressed OpenSSL diagnostics and certificate/key matching.
- [ ] Preserve archive exclusions, `age` behavior, plain-backup opt-in, receipts,
  and backup state manifests.

Validation gate:

- [ ] Passphrases never appear in argv, environment variables, output,
  exceptions, process listings, or persisted state.
- [ ] Backup archives and receipts remain compatible with existing consumers.

## Phase 6: Migrate CA and CSR Transactions

Goal: Move related transaction protocols together after their shared primitives
are proven.

Migration groups:

```text
platform-pki-root-create
platform-pki-intermediate-create

platform-pki-service-issue
platform-pki-service-renew
platform-pki-csr-recover

platform-pki-csr-trust-install
platform-pki-certificate-export
platform-pki-csr-candidate
```

Tasks:

- [ ] Model transaction phases and legal transitions with enums and typed state.
- [ ] Preserve exact existing journal serialization and state paths.
- [ ] Preserve pre-commit rollback and post-commit resume behavior.
- [ ] Preserve CA database backup, mutation, restoration, and identity checks.
- [ ] Preserve replay consumption, immutable candidates, retained response trust,
  exports, outcomes, active pointers, and historical authentication.
- [ ] Preserve lifecycle-through-operation locking and final source/state
  rechecks.
- [ ] Migrate each public command as a whole; do not dispatch custody modes to
  different implementation languages.

Required recovery matrix:

| Transaction writer | Recovery implementation | Required |
| --- | --- | --- |
| Bash | Python | Yes |
| Python | Python | Yes |
| Python | Bash | No |
| Bash | Bash | Existing evidence |

Validation gate:

- [ ] Every Bash crash checkpoint can be recovered by Python.
- [ ] Every Python crash checkpoint can be recovered by Python.
- [ ] Python refuses clean downgrade while any unresolved state exists.
- [ ] Successful, invalid, no-op, replay, signal, race, and recovery state trees
  match the frozen compatibility contract.

## Phase 7: Migrate Rollover Last

Goal: Reimplement the most complex durable state machines only after all shared
primitives have production evidence.

Migration order:

1. `platform-pki-ca-rollover status`
2. Rollover migration parsing and validation
3. Rollover migration and recovery
4. Rollover preparation
5. Rollover preparation recovery

Tasks:

- [ ] Model preparation, migration, bootstrap, publication, and terminal cleanup
  as explicit state machines.
- [ ] Preserve schema, transaction fields, generation reservations, backup
  receipts, trust snapshots, manifests, fault checkpoints, and recovery actions.
- [ ] Reuse the established filesystem, lock, record, subprocess, and
  transaction primitives rather than creating rollover-specific duplicates.
- [ ] Run Bash-to-Python and Python-to-Python crash recovery at every checkpoint.
- [ ] Preserve the authoritative bounded-parallel rollover test suite.

Validation gate:

- [ ] Parser, preparation, migration, fault, lifecycle, recovery, and advanced
  rollover suites pass without skipped or weakened scenarios.
- [ ] Rollover is independently releasable before Bash cleanup begins.

## Phase 8: Retire PKI Bash Implementations

Goal: Remove obsolete PKI Bash code after all compatibility entry points use
Python.

Tasks:

- [ ] Remove migrated PKI commands from `SHELL_TOOLS` and `BASHLY_TOOLS`.
- [ ] Add all Python-backed command names to the maintained Python inventory.
- [ ] Remove PKI Bashly workspaces only after the corresponding Python release
  has passed final acceptance.
- [ ] Remove `lib/platform-pki-common.sh`, `lib/platform-pki-csr-sign.sh`, and
  `lib/platform-pki-csr-candidate.sh` only after no installed or checkout
  consumer remains.
- [ ] Preserve the final Bash tag and migration compatibility evidence.
- [ ] Update generation, verification, installation, docs, `NEWS.md`, and
  `CHANGELOG.md`.
- [ ] Leave non-PKI Bashly commands unchanged.

Validation gate:

- [ ] Command inventory, installed tools, focused PKI suites, generated-file
  verification for remaining Bash tools, ShellCheck, and final container
  acceptance pass.

## Packaging and Installation

The selected application artifact is a deterministic standard-library zipapp.
Maintained source and generated output use this repository layout:

```text
src/platform_pki/
bin/platform-pki
$INSTALL_DIR/platform-pki
$INSTALL_DIR/platform-pki-*
```

Requirements:

- Build the archive with stable member order, timestamps, modes, and content.
- Include the application package and `__main__.py`, but not a Python runtime or
  third-party dependencies.
- Embed the repository `VERSION` and verify it against every public launcher.
- Use isolated Python startup and reject accidental imports from outside the
  archive.
- Validate the complete zipapp before publishing compatibility launchers.
- Dispatch compatibility commands and the unified CLI to the same handlers.
- Preserve custom `INSTALL_DIR`, `SHARE_DIR`, `PLATFORM_TOOLS_SHARE_DIR`, and
  existing shared-template lookup behavior.
- Prove direct execution, copied installation, compatibility-name invocation,
  signals, inherited descriptors, and subprocess behavior.
- Defer wheels, PEX, virtual environments, and OS packages until a concrete
  dependency or deployment requirement justifies them.

## Release Strategy

Use independently deployable releases rather than one large cutover:

| Release tranche | Scope |
| --- | --- |
| Foundation | Python package, unified CLI, and `doctor`; no command replacement |
| Pilot | Print, expiry, and service verification commands |
| Publication | Init, inventory installation, and Ansible export |
| Utilities | Custody report, passphrase verification, and backup |
| Transactions | Authority, service, CSR, export, and candidate workflows |
| Rollover | Status, migration, preparation, and recovery |
| Cleanup | Retire PKI Bash sources and libraries |

Each release must document:

- Commands now implemented in Python.
- The supported Python runtime.
- Bash-journal recovery coverage.
- Downgrade restrictions.
- Focused and final verification performed.
- Remaining Bash implementations.

An implementation-language change does not require a major version when all
public and persisted contracts remain compatible. Command removal, incompatible
parser behavior, state-layout changes, journal incompatibility, or broken
recovery requires a major-version decision.

## Validation Strategy

Every command cutover must include:

- [ ] `make verify`
- [ ] `make test-command-contract`
- [ ] `make test-installed-tools`
- [ ] The command's focused Make target.
- [ ] Bash/Python differential success and failure scenarios.
- [ ] State-tree comparison including paths, types, modes, links, digests,
  canonical bytes, and expected identity relationships.

Transaction cutovers must additionally include:

- [ ] Bash interrupted state recovered by Python.
- [ ] Python interrupted state recovered by Python.
- [ ] Source and destination replacement races.
- [ ] Signals before and after the commit boundary.
- [ ] No-op, replay, retry, rollback, and resume behavior.
- [ ] Installed-layout execution with isolated imports and runtime paths.

Use focused checks during development. Run `make container-check` once as the
final acceptance gate for each releasable tranche rather than repeatedly during
implementation.

## Risks

- Python does not directly provide every required GNU `mv` exchange and
  no-copy/no-clobber primitive.
- A naive `pathlib` rewrite could weaken descriptor and TOCTOU protections.
- Python exceptions or subprocess wrappers could expose secret-bearing
  arguments or diagnostics.
- Mixed Bash/Python releases could create shared-package or journal-version skew.
- Parser compatibility requires more than default `argparse` behavior.
- The current strict inventory language is not equivalent to general YAML
  loading.
- Forward-only recovery requires an enforced clean-state downgrade gate and
  operator documentation.
- The minimum Python version and target-host availability are not yet known.

## Open Questions

- [ ] Which supported target hosts need Python 3.12 provisioned before the first
  Python-backed release?
- [ ] How long should the final Bash implementation remain in the repository as
  a differential oracle after each command migrates?
- [ ] Which Python-written persisted states, if any, may deliberately retain
  byte-for-byte compatibility with Bash despite the forward-only downgrade
  policy?

## Progress Log

| Date | Update | Evidence |
| --- | --- | --- |
| 2026-08-07 | Migration plan created; implementation not started. | User requested a durable plan after architecture review. |
| 2026-08-07 | Deterministic zipapp selected as the Python application artifact. | User approved the standard-library zipapp approach. |
| 2026-08-07 | Phase 0 started with runtime and CLI decisions frozen. | User selected Python 3.12 and shallow unified command names. |
| 2026-08-07 | Public, persisted, recovery, differential, and downgrade baseline drafted. | `docs/plans/platform-pki-python-contract-inventory.md`; initial migration contract/harness tests passed. Exhaustive option and checkpoint coverage remains open. |
| 2026-08-07 | Phase 0 harness foundation hardened and integrated. | `make test-python-infrastructure`: 95 passed; focused CSR copy/issuance checks: 2 passed; final patch review found no concrete issue. |
| 2026-08-07 | Exhaustive Phase 0 parser-route and recovery-checkpoint inventories completed. | `tests/pki/test_migration_contract.py` source-normalizes 24 Bashly leaves, runtime option guards, literal and finite fault domains, and maintained pytest domains; focused infrastructure run: 18 passed. Differential execution and Bash-oracle retention remain open. |
| 2026-08-07 | Differential execution foundation and Bash-oracle retention policy completed. | `run_differential_case` executes real commands on isolated private copies and compares normalized process observations, semantic trees, and identity-sensitive transitions; focused harness run: 16 passed. Per-command oracle commits are recorded at cutover. |
| 2026-08-07 | Shared parser-edge behavior was frozen across all retained PKI leaves. | `tests/test_command_contract.py` drives help, equals-form, abbreviation, action-order, stream/status, and no-state probes through the 24-route source-backed inventory. |

## Decision Log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-08-07 | Preserve existing command names and add a unified alias. | Maintain automation compatibility while providing a coherent new interface. |
| 2026-08-07 | Require forward-only cross-version recovery. | Python must recover Bash state; rollback is allowed only after Python establishes clean state. |
| 2026-08-07 | Migrate incrementally and move rollover last. | Reduce simultaneous parser, filesystem, transaction, and recovery risk. |
| 2026-08-07 | Build and install a deterministic standard-library zipapp. | Keep maintained source modular while avoiding Python package/import skew and unnecessary PEX dependencies. |
| 2026-08-07 | Require Python 3.12 or newer. | Use a modern standard-library baseline while retaining a clear target-host provisioning contract. |
| 2026-08-07 | Use shallow unified command names. | Mirror existing executable suffixes and minimize parser and documentation divergence. |
| 2026-08-07 | Retain the final Bash source through migration acceptance and record each command's pre-cutover commit. | Keep differential evidence reproducible without shipping a production runtime language switch or duplicate oracle installation. |
