# Plan: Migrate Platform PKI to Python

## Status

Phase 0 contract expansion remains in progress. Phases 1 through 3 are
implemented, and Phase 4 is complete with `platform-pki-init`,
`platform-pki-inventory-install`, and `platform-pki-export-ansible`
Python-backed.

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
- After the first operational command cuts over, installing an older Bash
  release is unsupported even when no transaction appears unresolved.
- Build the maintained Python source into a deterministic standard-library
  zipapp for checkout and installed execution.
- Require Python 3.14 or newer.
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
- [x] Freeze the first migration tranche's output/status semantics,
  migration-sensitive runtime boundaries, and common installed asset.
- [x] Define and review the complete unified `platform-pki` command hierarchy.
- [x] Establish Python 3.14 as the minimum supported runtime; target-host
  availability remains a release-readiness check.
- [x] Inventory every persisted record, policy, manifest, pointer, journal,
  checkpoint, and schema.
- [x] Freeze exact ordered fields, schema values, and final-newline rules for
  persisted records written from literal or dynamically assembled shell text.
- [x] Define the forward-only package and recovery policy; Python-to-Bash
  downgrade is unsupported.
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
- [x] Every persisted record's exact field order, schema value, and final
  newline is source-backed by an executable contract test.
- [x] The contract explicitly excludes Python-to-Bash package rollback and does
  not imply it from byte-compatible persisted records.

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

Recorded cutovers:

| Command | Final Bash commit | Retained executable |
| --- | --- | --- |
| `platform-pki-print-cert` | `4cd6b2294760571ffed632295de441c34a4c0eb1` | `tests/pki/oracles/platform-pki-print-cert/platform-pki-print-cert` |
| `platform-pki-list-expiry` | `b421370123db006148d0439af3e35efd47bcda2f` | `tests/pki/oracles/platform-pki-list-expiry/platform-pki-list-expiry` |
| `platform-pki-service-verify` | `b421370123db006148d0439af3e35efd47bcda2f` | `tests/pki/oracles/platform-pki-service-verify/platform-pki-service-verify` |
| `platform-pki-init` | `ee03cddc626338ea7d066dd71519204bddb46db3` | `tests/pki/oracles/platform-pki-init/platform-pki-init` |
| `platform-pki-inventory-install` | `8c2e8e7ae46e9aedbda70a9035682aa9f1445dd1` | `tests/pki/oracles/platform-pki-inventory-install/platform-pki-inventory-install` |
| `platform-pki-export-ansible` | `00c7cd55fa51ffc3e5911f0f3bcba1b76e7c5f6b` | `tests/pki/oracles/platform-pki-export-ansible/platform-pki-export-ansible` |

## Phase 1: Build the Python Foundation

Goal: Introduce shared Python infrastructure without switching existing PKI
commands.

Tasks:

- [x] Add a standard-library-only `platform_pki` package.
- [x] Implement parser compatibility, leading help/version precedence, TTY help
  color, `NO_COLOR`, diagnostics, and status mapping.
- [x] Implement exact-argv subprocess execution with `shell=False`, bounded
  output, minimal environments, process-group cleanup, and protected inherited
  descriptors.
- [x] Implement strict ordered-record parsing and serialization.
- [x] Implement inventory parsing without broadening the accepted input
  language or changing canonical bytes.
- [x] Implement common errors that redact secret-bearing argv, descriptors, and
  child diagnostics.
- [x] Build a deterministic zipapp from `src/platform_pki/` as
  `bin/platform-pki`.
- [x] Run the zipapp with isolated Python startup so `PYTHONPATH`, user site
  packages, and checkout imports cannot affect execution.
- [x] Prove direct unified-command execution and compatibility-name dispatch
  outside the checkout.

Validation gate:

- [x] `platform-pki --help`, `--version`, and parser failures create no PKI
  state.
- [x] Installed execution ignores `PYTHONPATH`, user site packages, checkout
  imports, shell startup hooks, and unsupported source overrides.
- [x] No existing `platform-pki-*` command has changed implementation.

## Phase 2: Implement Filesystem and Locking Primitives

Goal: Prove the security and durability layer before migrating state-mutating
commands.

Tasks:

- [x] Implement descriptor-oriented opening with `O_NOFOLLOW`, `fstat`, and
  descriptor-relative APIs where supported.
- [x] Implement exact file and directory identity models.
- [x] Implement trusted-ancestor, owner, mode, file-type, symlink, and link-count
  validation.
- [x] Implement lifecycle and operation locks as ordered context managers.
- [x] Implement absent-destination atomic writes, exact no-clobber publication,
  file `fsync`, directory `fsync`, and identity-bound cleanup.
- [x] Prototype atomic exchange and inode-preserving publication with Linux
  `renameat2`; retain reviewed GNU `mv` calls as the Bash differential oracle.
- [x] Implement and prove guarded replacement of an exact existing file or
  directory with forward-only exchange, durability, exact regular cleanup, and
  complete retained-directory readiness evidence.
- [x] Preserve deterministic fault and pause barriers for race tests.
- [x] Remove the proposed clean-downgrade `doctor` route after package rollback
  was excluded from the supported migration model.

Validation gate:

- [x] Under cooperative locks and exclusive stage ownership, real symlink,
  hard-link, source/destination race, concurrent publication, permission, and
  durability tests pass across the primitive publication layer. Syscall-bound
  same-UID races produce explicit ambiguity without deleting unexpected state.
- [x] Equivalent validation passes for the bounded absent-destination and exact
  exchange checkpoint, including simultaneous publishers, content/metadata
  mutation, readiness, parent binding, process death, and durability failures.
- [x] Lock acquisition and reverse release match the Bash implementation.
- [x] Unit tests supplement rather than replace subprocess-backed tests.

## Phase 3: Migrate Read-Oriented Commands

Goal: Validate package, parser, installation, locking, and OpenSSL integration
with lower-risk commands.

Migration order:

1. `platform-pki-print-cert`
2. `platform-pki-list-expiry`
3. `platform-pki-service-verify`

Tasks for each command:

- [x] Implement one Python handler used by both command interfaces.
- [x] Run Bash and Python against equivalent isolated state.
- [x] Compare status, stdout, stderr, and all state reads or mutations.
- [x] Pass the existing focused test target without weakening assertions.
- [x] Switch the existing executable only after differential parity is proven.
- [x] Add and document the corresponding unified CLI route.

Validation gate:

- [x] Command-contract and installed-tool tests pass for both interfaces.
- [x] The first Python-backed compatibility commands are independently
  releasable.

## Phase 4: Migrate Bounded Publication Commands

Goal: Exercise validated filesystem publication without introducing CA signing
transactions.

Migration order:

1. `platform-pki-init`
2. `platform-pki-inventory-install`
3. `platform-pki-export-ansible`

Tasks:

- [x] Migrate `platform-pki-init` with one handler shared by compatibility and
  unified routes, retained Bash provenance, and fresh/no-op/force/failure
  differential coverage.
- [x] Preserve init template lookup and custom `INSTALL_DIR`/`SHARE_DIR`
  behavior.
- [x] Preserve installed-layout behavior for the remaining Phase 4 command.
- [x] Preserve lifecycle, authority, inventory, and export locking boundaries.
- [x] Preserve source identities, destination identities, and atomic
  publication behavior.
- [x] Run existing unsafe-path, race, no-op, and installed-layout tests for
  inventory installation.
- [x] Migrate `platform-pki-export-ansible` with one shared handler, retained
  Bash provenance and compatible success/failure differentials, complete
  same-parent staging, exact no-clobber or forward-only exchange publication,
  and Python-specific interruption, race, durability, and no-follow displaced
  tree cleanup coverage.

Validation gate:

- [x] Bash/Python process and final state-tree comparisons are equivalent for
  compatible success, selection, warnings, invalid input, and generation
  gating. Python-specific tests cover intentionally safer interruption and
  competing-publication behavior where transition parity is neither possible
  nor desired.

## Phase 5: Migrate Security Utilities

Goal: Move secret-sensitive and archive-oriented commands after subprocess and
descriptor handling is proven.

Migration order:

1. `platform-pki-custody-report`
2. `platform-pki-ca-passphrase-verify`
3. `platform-pki-backup`

Tasks:

- [x] Preserve byte-bounded identity-checked custody inspection and secret-free
  output, including receipt compatibility and metadata-only recursive scans.
- [ ] Preserve minimal inherited-descriptor passphrase transport.
- [ ] Preserve suppressed OpenSSL diagnostics and certificate/key matching.
- [ ] Preserve archive exclusions, `age` behavior, plain-backup opt-in, receipts,
  and backup state manifests.

Validation gate:

- [ ] Passphrases never appear in argv, environment variables, output,
  exceptions, process listings, or persisted state.
- [ ] Backup archives and receipts remain compatible with existing consumers.
- [x] Custody report output, status, layout, receipt acceptance, and storage
  evidence match the frozen Bash oracle; Python-only tests cover strengthened
  no-follow read and traversal races.

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
- [ ] Python rejects unresolved or unsupported transaction state before each
  affected operation reads or mutates operational snapshots.
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
| Foundation | Python package and unified CLI; no command replacement |
| Safety | Filesystem, locking, and publication primitives; no command replacement |
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

These are later command-specific operational integration gates. Phase 2
primitive completion does not satisfy them or provide a generic recovery
protocol.

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
- Forward-only package migration requires release documentation to state that
  older Bash implementations must not be used with Python-written transaction
  state and are not guaranteed to interpret it.
- Target-host Python 3.14 availability remains a release-readiness check.

## Open Questions

- [ ] Which supported target hosts need Python 3.14 provisioned before the first
  Python-backed release?
- [ ] How long should the final Bash implementation remain in the repository as
  a differential oracle after each command migrates?

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
| 2026-08-07 | Pilot output, status, dependency, and installed-asset contracts were added. | Source- and test-backed inventories cover `print-cert`, `list-expiry`, and `service-verify`; exhaustive expansion to the remaining routes stays open. |
| 2026-08-07 | Minimum runtime raised to Python 3.14. | The pinned test image provides Python 3.14.7, avoiding an unverified older-runtime claim. |
| 2026-08-07 | Deterministic unified zipapp foundation added without command cutover. | Fixed-metadata standard-library archive, isolated `-I -S` startup, 18 copied compatibility names, 24 unified help routes, installed-layout execution, and no-state parser behavior are covered in the pinned Python 3.14 test image. |
| 2026-08-07 | Phase 1 shared parser and runtime primitives implemented. | Source-backed 24-route parsing, strict records, C-locale inventory differentials, bounded process-group execution, protected inherited descriptors, and secret-safe diagnostics pass 429 focused tests. Final `make container-check`: 2,285 passed; operational handlers remain unavailable. |
| 2026-08-07 | Phase 2 path, filesystem, and deterministic fault primitives implemented. | Lexical path policy, full-component descriptor bindings, exact identity and policy models, checked bounded reads, trusted ancestors, file and directory synchronization, and pinned pause controls pass 91 focused real-filesystem/process tests; locking and publication remain open. |
| 2026-08-07 | Phase 2 ordered advisory-lock checkpoint implemented and independently hardened. | `acquire_pki_locks` provides descriptor-bound lifecycle-through-export prefix profiles, exact lock policy, no-state behavior, fork-safe descriptor/registry handling, validated anonymous `O_TMPFILE` no-clobber creation, thread-safe duplicate rejection, finite race hooks, primary-exception preservation, and reverse cleanup. The focused pinned-container suite passed 42 tests and the integrated foundation suite passed 562 tests across real Python/Python, Python/util-linux, fork, exec, descriptor-reuse, process-death, and replacement boundaries; general publication primitives remained open. |
| 2026-08-07 | Bounded Phase 2 durable-publication checkpoint implemented and review-hardened. | Owned exact-byte stages, source-file synchronization/content observations, parent-bound immutable tree readiness, exact unlink, Linux no-clobber file/directory rename, file/directory exchange, absent-only atomic writes, operation-lifetime pins, and recursive tree synchronization have finite race hooks and retain ambiguous post-mutation state. The pinned focused suite passed 87 tests and the integrated foundation suite passed 649 tests; guarded existing-destination replacement remained open. |
| 2026-08-07 | Guarded existing-destination replacement completed the next Phase 2 publication checkpoint and was narrowed after review. | Exact file/directory replacement uses forward-only `RENAME_EXCHANGE`, synchronized content/tree observations, six finite replacement checkpoints, exact regular-file cleanup, complete retained-directory readiness evidence, static ambiguity classes, and a documented cooperative same-UID boundary. The pinned focused suite passed 160 tests, 20 dedicated concurrent cases passed, the integrated foundation suite passed 722 tests, and infrastructure passed 139 tests. |
| 2026-08-07 | A proposed `doctor` contract was investigated before implementation. | Source inventory and review exposed incomplete positive-eligibility grammars and the lack of an exclusive assessment-to-package-replacement handoff. No route or runtime code was added. |
| 2026-08-08 | Python-to-Bash package rollback and the proposed `doctor` route were removed from scope. | The user selected a forward-only operating model; Python still recovers final Bash transactions, while using older Bash releases with Python-written state is unsupported. |
| 2026-08-08 | `platform-pki-print-cert` became the first Python-backed operational compatibility command. | The frozen Bash oracle is recorded at `4cd6b2294760571ffed632295de441c34a4c0eb1`; focused Bash/Python output and state comparison passed, and command-contract, installed-tool, and legacy-gating verification passed 702 tests. |
| 2026-08-08 | `platform-pki-init` started Phase 4 bounded-publication command migration. | The frozen Bash oracle is recorded at `ee03cddc626338ea7d066dd71519204bddb46db3`; the compatibility and unified routes share one Python handler and retain the existing template and path contract. |
| 2026-08-08 | `platform-pki-inventory-install` migrated to one Python publication handler. | The frozen Bash oracle is recorded at `8c2e8e7ae46e9aedbda70a9035682aa9f1445dd1`; Bash/Python differentials cover installation, no-op, normalization, invalid input, physical-CWD resolution, legacy and recovery gates, replacement, fallback, overlap, and lock contention, while Python-specific tests exercise descriptor-bound races and retained ambiguity. |
| 2026-08-08 | `platform-pki-export-ansible` completed Phase 4 bounded-publication migration and independent cleanup review. | The frozen Bash oracle is recorded at `00c7cd55fa51ffc3e5911f0f3bcba1b76e7c5f6b`; compatible output/final-state differentials cover success, custom marker authorization, reversed explicit selection order, warnings, path boundaries, host-local rejection, issuer diagnostics, and generation gating. Python-specific subprocess tests prove the exact export manifest, whole-tree atomicity, descriptor-pinned marker authorization, late pre-publication preservation, exact readiness-bound stage cleanup or reported private retention, competing-publisher no-clobber behavior, forward-only replacement, pre/post-commit crashes, mutation-boundary exact-name cleanup, retained displaced-tree evidence, and no-follow hostile-symlink cleanup. Final `make container-check` passed 2,703 tests in the pinned containers. |
| 2026-08-09 | `platform-pki-custody-report` completed Phase 5 utility migration. | The final Bash commit is `a2336a1518d41bf5dd2c5f2897a0c1c84128b5f4`; the frozen mode-755 oracle has SHA-256 `f17aa588e5d6d200f16c3ae416da15a18c839f29ae97963704d5f11b27f822e4`, and the retained common library has SHA-256 `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`. Compatibility and unified routes share one Python handler with descriptor-relative scans and bounded reads/helpers. Final `make container-check` passed 2,768 tests in the pinned containers. |
| 2026-08-09 | `platform-pki-ca-passphrase-verify` completed Phase 5 secret-descriptor migration. | The final Bash commit is `95c0b277af77375d00f23585282dcf3aed83b119`; its frozen mode-755 oracle has SHA-256 `cdf4cb3f018e8b6c723310933691d2c433992fc74321e3d1e60bff2a99e88be1`. Compatibility and unified routes share one Python handler with fresh minimal passphrase descriptors, retained input identities, final locked rechecks and output, locale-compatible secret validation, bounded in-memory public-key comparison, and no temporary verification state. The focused suite passed 78 tests, independent final review found no concrete defect, and final `make container-check` passed 2,818 tests in the pinned containers. |

## Decision Log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-08-07 | Preserve existing command names and add a unified alias. | Maintain automation compatibility while providing a coherent new interface. |
| 2026-08-07 | Require forward-only cross-version recovery. | Python must recover Bash state; older Bash implementations are not required to recover Python state. |
| 2026-08-07 | Migrate incrementally and move rollover last. | Reduce simultaneous parser, filesystem, transaction, and recovery risk. |
| 2026-08-07 | Build and install a deterministic standard-library zipapp. | Keep maintained source modular while avoiding Python package/import skew and unnecessary PEX dependencies. |
| 2026-08-07 | Require Python 3.12 or newer. | Use a modern standard-library baseline while retaining a clear target-host provisioning contract. |
| 2026-08-07 | Use shallow unified command names. | Mirror existing executable suffixes and minimize parser and documentation divergence. |
| 2026-08-07 | Retain the final Bash source through migration acceptance and record each command's pre-cutover commit. | Keep differential evidence reproducible without shipping a production runtime language switch or duplicate oracle installation. |
| 2026-08-07 | Raise the minimum from Python 3.12 to 3.14. | Align the application contract with the pinned Python 3.14.7 test environment instead of maintaining an unverified older-runtime claim. |
| 2026-08-07 | Design and review the `doctor` contract before exposing a public route. | The review exposed missing positive-eligibility and package-handoff contracts before runtime code was added; this decision was superseded on 2026-08-08. |
| 2026-08-08 | Make package migration forward-only and do not add `doctor`. | Supported rollback would require exhaustive historical-state validation and a guarded package-replacement workflow; neither is needed when using older Bash releases with Python-written state is outside the supported model. |
