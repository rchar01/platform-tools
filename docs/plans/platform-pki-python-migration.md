# Plan: Migrate Platform PKI to Python

## Status

All runtime migration and next-major implementation phases are complete.
Production packaging generates and installs one canonical PKI zipapp,
`platform-pki`; all 18 v2 compatibility executables and invocation-name dispatch
are removed. Exact managed recovery is public through
`platform-pki service-recover`. Phase 8 retired production PKI Bashly workspaces
and shell libraries while preserving immutable final-Bash evidence and
historical mappings under `tests/pki/oracles/`. A copied or renamed archive
still behaves as `platform-pki`. The v3 release gate remains pending on external
downstream inventory, canary validation, and Python 3.14 target-host prerequisites;
`VERSION` remains `2.3.0` until those blockers close. Migration remains
forward-only: installing an older Bash release after Python has written state is
unsupported.

## Goal

Replace the PKI Bash implementations with one maintainable Python package while
preserving persisted state, security boundaries, and crash-recovery behavior.
Preserve existing command interfaces during incremental migration, then make
the unified `platform-pki` CLI the only installed PKI executable in the next
major release.

## Scope

- Migrate all 18 existing `platform-pki-*` commands to shared Python code.
- Preserve every existing executable name as a compatibility entry point only
  during the completed incremental migration.
- Add a unified `platform-pki` command that dispatches to the same handlers.
- Remove the `platform-pki-*` compatibility executables at the approved
  next-major implementation boundary.
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
- Do not remove existing `platform-pki-*` commands before all unified routes
  have migrated and the next-major implementation boundary is prepared. This
  condition is complete.
- Do not convert persisted `key=value` records or journals to JSON during this
  migration.
- Do not migrate the seven non-PKI Bashly tools as part of this work.
- Do not adopt PEX, pipx, a virtual environment, or OS packages before the
  repository-native installation model is proven.
- Do not weaken subprocess-backed integration, race, signal, descriptor, or
  crash-recovery tests in favor of in-process mocks.

## Approved Decisions

- Preserve all existing `platform-pki-*` executable names during incremental
  migration.
- Make `platform-pki` the sole installed PKI application at the next-major
  implementation boundary after every route has migrated and passed acceptance.
  This decision is implemented; external release readiness remains pending.
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
- Managed service issue/renew use a new forward-only Python schema-1 journal and
  recover only through `platform-pki service-recover --transaction`.
  Host-local issue/migrate/renew continue to use the CSR signing journal and
  public `csr-recover`.

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

During migration, each cut-over compatibility route and its unified interface
dispatched to the same handler. That temporary launcher boundary is now retired;
production dispatch is unified-only.

The frozen unified command mapping is:

```text
platform-pki init
platform-pki inventory-install
platform-pki csr-trust-install
platform-pki csr-recover
platform-pki offline-csr
platform-pki certificate-export
platform-pki csr-candidate
platform-pki root-create
platform-pki intermediate-create
platform-pki service-issue
platform-pki service-renew
platform-pki service-recover
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
The current `offline-csr` leaves are `approve` and `sign`. For example,
`platform-pki certificate-export publish` and `platform-pki ca-rollover prepare`
dispatch to the same handlers as their historical compatibility commands.

## Phase 0: Freeze Contracts

Goal: Make current behavior and compatibility requirements executable before
changing implementations.

Tasks:

- [x] Inventory every PKI command form and source-defined option, including
  runtime-only option relationships and duplicate rejection fields.
- [ ] Extend the machine-readable output, status, and runtime-dependency
  inventory from the seven covered routes to the 20 explicitly deferred parser
  leaves. The current init template and historical oracle assets are separately
  inventoried; this documentation expansion is not a runtime-migration blocker.
- [x] Execute shared help precedence, equals-form, abbreviation, stream/status,
  and no-state parser edges across all 27 current unified leaf routes while
  preserving the historical 24-leaf v2 compatibility parser evidence.
- [x] Freeze seven routes' output/status semantics and migration-sensitive
  runtime boundaries, and separately inventory the current init template and
  historical shell-library oracle evidence.
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
- [x] Record and preserve each command's final Bash implementation as it is cut
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
| `platform-pki-root-create` | `ba9dd57214cae18f82c83dfb54b6ddce13882280` | `tests/pki/oracles/platform-pki-ca-rollover/platform-pki-root-create` |
| `platform-pki-csr-trust-install` | `678daa6de2ea24ada1fd36199013347f79f303bf` | `tests/pki/oracles/platform-pki-csr-trust-install/platform-pki-csr-trust-install` |
| `platform-pki-certificate-export` | `24db7d54ca5c113fe763d4007c5dfef507dc23a6` | `tests/pki/oracles/platform-pki-certificate-export/platform-pki-certificate-export` |
| `platform-pki-csr-candidate` | `24db7d54ca5c113fe763d4007c5dfef507dc23a6` | `tests/pki/oracles/platform-pki-csr-candidate/platform-pki-csr-candidate` |
| `platform-pki-ca-rollover` | `ba9dd57214cae18f82c83dfb54b6ddce13882280` | `tests/pki/oracles/platform-pki-ca-rollover/platform-pki-ca-rollover` |

The CA recovery foundation also freezes the final Bash recovery and authority
writer assets from `ba9dd57214cae18f82c83dfb54b6ddce13882280` under
`tests/pki/oracles/platform-pki-ca-rollover/`. These are retained authority and
rollover writer oracles and recovery evidence; all public rollover routes and
both authority-creation routes are Python-backed.

Recorded SHA-256 provenance for that oracle set is
`7e9430e6d17969d5d1779e8073b9757e08157625e16b91969991e611953b806b`
for `platform-pki-ca-rollover`,
`44f12eae381eedfb6414b6135ebc2bd8ff5fa2a99731adbc80c4a3201b107a3b`
for `platform-pki-root-create`,
`efd59fff7a0913f048f1799ce6d91caa751e477fc1c29884f868a95b37fbcdf7`
for `platform-pki-intermediate-create`, and
`dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`
for the private `lib/platform-pki-common.sh` copy. Executables retain mode 755;
the library remains non-executable at mode 644.

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
- [x] Preserve minimal inherited-descriptor passphrase transport.
- [x] Preserve suppressed OpenSSL diagnostics and certificate/key matching.
- [x] Preserve archive exclusions, `age` behavior, plain-backup opt-in, receipts,
  and backup state manifests.

Validation gate:

- [x] Passphrases never appear in argv, environment variables, output,
  exceptions, process listings, or persisted state.
- [x] Backup archives and receipts remain compatible with existing consumers.
- [x] Custody report output, status, layout, receipt acceptance, and storage
  evidence match the frozen Bash oracle; Python-only tests cover strengthened
  no-follow read and traversal races.

## Phase 6: Migrate CA and CSR Transactions

Goal: Move related transaction protocols together after their shared primitives
are proven.

The approved sequencing exception completed unified rollover recovery before
the authority writers and other rollover leaves. The complete compatibility and
unified rollover command now use Python; frozen Bash assets remain for
differential recovery and writer evidence.
The compatibility and unified root and intermediate creation routes now share
their respective Python schema-3 transaction writers.

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

- [x] Model transaction phases and legal transitions with enums and typed state.
- [x] Preserve exact existing journal serialization and state paths.
- [x] Preserve pre-commit rollback and post-commit resume behavior.
- [x] Preserve CA database backup, mutation, restoration, and identity checks.
- [x] Preserve replay consumption, immutable candidates, retained response trust,
  exports, outcomes, active pointers, and historical authentication.
- [x] Add non-public structural and semantic CSR signing/finalization journal
  models without changing public dispatch or recovery mutation.
- [x] Add non-public candidate-finalization recovery with complete live evidence
  validation, monotonic resume-only publication, and isolated subprocess tests;
  public `csr-recover` remained Bash until the later whole-command cutover.
- [x] Add non-public signing recovery for every final-Bash phase with permanent
  replay consumption, exact reverse-order pre-commit rollback, no-resign
  post-commit publication, inherited response-key descriptors, restart
  checkpoints, hostile-state tests, and independent Bash/Python differentials.
- [x] Cut compatibility and unified `csr-recover` dispatch over together with
  exact confirmation, journal-kind-specific locking, and an under-lock
  no-protocol-switch recheck.
- [x] Preserve lifecycle-through-operation locking and final source/state
  rechecks.
- [x] Add exact typed codecs for the retained host-local request, approval,
  response, candidate, replay, and terminal records without changing their
  writers or public recovery.
- [x] Add a non-public managed issue/renew schema-1 transaction model with exact
  paths, ordered pre/post/stage/backup evidence, reverse pre-commit rollback,
  cleanup-only post-commit recovery, archive/key variants, and terminal cleanup.
- [x] Migrate each public command as a whole; do not dispatch custody modes to
  different implementation languages.

Required recovery matrix:

| Transaction writer | Recovery implementation | Required |
| --- | --- | --- |
| Bash | Python | Yes |
| Python | Python | Yes |
| Python | Bash | No |
| Bash | Bash | Existing evidence |

Validation gate:

- [x] Every supported final-Bash persisted crash checkpoint can be recovered by
  Python.
- [x] Every Python crash checkpoint can be recovered by Python.
- [x] Python rejects unresolved or unsupported transaction state before each
  affected operation reads or mutates operational snapshots.
- [x] Successful, invalid, no-op, replay, signal, race, and recovery state trees
  match the frozen compatibility contract.

CSR-recover checkpoint:

- [x] The final Bash commit is
  `0843c1c11b952aab39f5c95b5eced82989656eb3`.
- [x] The frozen mode-755 executable SHA-256 is
  `181528862958bf5a0810b3cae5c773b5f3d395c68226f2e2d17f019ad0757271`.
- [x] Frozen mode-644 common, signing, and candidate library SHA-256 values are
  `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`,
  `8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001`,
  and `ca1fb976f09730fbbc840ce97cb0c6db3ae76e5d679fdc777a1a96d80df5b43f`.
- [x] All retained signing and finalization differentials execute that frozen
  oracle with its frozen libraries. Live Bash remains authoritative for signing
  writer checkpoints; `src/platform_pki/csr_candidate.py` owns finalization
  writer checkpoints and the frozen candidate library is compatibility evidence.
- [x] Compatibility and unified routes share one Python handler and preserve
  parser, help, confirmation, diagnostics, output, and status contracts.
- [x] Signing holds lifecycle through inventory; finalization holds lifecycle
  through export. Selection is rechecked under lock and never switches after
  confirmation.

Managed service foundation checkpoint:

- [x] `src/platform_pki/csr_protocol.py` owns canonical schema-1 codecs for the
  retained host-local request, approval, response, candidate, replay-request,
  replay-nonce, and terminal records; source extraction keeps every shell
  declaration and literal writer aligned.
- [x] `src/platform_pki/service_transaction.py` owns a fixed 485-field managed
  journal with 29 directory/file destination mutations, generic
  pre/stage/backup/publication/rollback identity and digest chains,
  per-archive-file displaced-source bindings, seven conditional transaction
  inputs, typed persisted identities, exact destination/replacement policy,
  complete phase/evidence matrices, and no live state access.
- [x] The writer-derived mutation audit covers every retained service, CA, key,
  archive, rollback, and cleanup destination. The forward-only private stage
  binds exact inventory and issuer inputs and does not persist the retained
  Bash writer's `/tmp` inventory scratch paths.
- [x] The managed lock profile is lifecycle, root, intermediate, inventory.
  Publication follows the retained service/CA order. Rollback reverses ordinary
  files, then archive containers, restores existing archive-root metadata at
  the exact boundary, and finally reverses created service containers.
- [x] The durable commit record changes recovery from rollback to cleanup-only;
  no post-commit state can encode rollback.
- [x] Staging, private backup, publication, rollback, and cleanup progress use
  exact evidence prefixes. Failed pre-commit cleanup requires a retained
  canonical full-prefix rollback-completion record before detailed rollback
  evidence can be cleared; its digest also binds archive-root restoration state
  and identity.
- [x] Every successful committed and cleanup state retains complete staging,
  private-backup, and publication prefixes.
- [x] Retained host-local request and approval codecs independently enforce
  their timing bounds; cross-record validation enforces creation order and the
  conditional sole-operator delay without claiming live signer trust,
  signature, artifact-digest, or current-time validation.
- [x] CSR response/candidate, managed service, retained transaction, and CSR
  signing recovery paths enforce the retained canonical OpenSSL serial form.
- [x] Preserve Bash ownership until each whole service command is ready for
  cutover; service issue and renew are now Python-backed.
- [x] Expose managed recovery only as unified `service-recover`; do not add a
  compatibility executable.
- [x] Non-public operational recovery now provides descriptor-bound exact-
  transaction journal selection, full live preflight, reverse rollback,
  cleanup-only post-commit recovery, canonical retained outcomes, and restart
  checkpoints under the lifecycle-through-inventory lock profile.
- [x] Rollback and cleanup mutation boundaries require exact journal identities
  and use exact publication primitives. Same-name replacements are preserved;
  absence or retained bytes without authenticated resulting identity fail
  closed with the unresolved journal retained.
- [x] Add a non-public managed writer engine with atomic self-sized journal
  creation and rewrites, exact stage/backup/publication prefixes, deferred
  handled signals only across mutation-to-evidence assignments,
  transaction-wide authenticated publication preflight, authenticated
  replace/no-clobber publication, identity-journaled empty private directory
  stages, durable verification/commit transitions, and a committed journal
  accepted by shared cleanup-only recovery. Directory creation uses atomic
  no-clobber rename, and recovery reconciles only the exact staged or published
  inode rather than adopting a same-mode destination. Publication evidence
  carries the authenticated directory or full file identity through a final
  destination recheck at the journal replacement boundary; neither writer nor
  recovery serializes a fresh path observation. Commit returns that journal;
  the writer does not invoke or hand off to recovery.
- [x] Add non-public managed issue planning and orchestration with exact
  inventory/issuer/source snapshots, descriptor-only passphrase transport,
  real OpenSSL P-384 key/CSR/certificate generation, staged CA database state,
  writer-owned publication and verification, shared reverse rollback before
  commit, and cleanup-only recovery after commit. Crash, handled signal/failure,
  source-race, verification-failure, key create/reuse/rotation, days-precedence,
  invalid-state, and Bash/Python semantic differential cases exercise the real
  subprocess path. Unauthenticated post-mutation stage/backup windows remain
  fail-closed with retained evidence by design.
- [x] Close managed-issue bootstrap and verification gaps with a durable
  pre-tree reservation, immutable transaction-named bootstrap history, exact
  recovery retry across issue and recovery crashes, authoritative terminal
  rollover parsing, active-issuer source rechecks, pre-mutation OpenSSL value
  validation, and exact published certificate-profile enforcement.
- [x] Add exact public confirmation and unified-only dispatch after managed
  transaction writing, forward publication, verification, and operational
  recovery are complete.
- [x] Freeze the final Bash service-issue executable and loaded libraries from
  `6a7f162240c9970cf9a17091d9b37c8dea071ad8`; keep managed and host-local
  Bash/Python writer differentials pinned to that oracle.
- [x] Add managed renewal planning/orchestration and host-local
  renewal writing on the accepted service and 114-field CSR transaction
  foundations. Managed renewal binds sparse displaced archive sources and exact
  rollback/cleanup state; host-local renewal authenticates recursive finalized
  schema-2 predecessor history and treats a retained candidate as resolved only
  after its exact immutable terminal outcome, transaction, replay, trust,
  deployment, export, and predecessor evidence authenticate under current
  inventory and the exact installed schema-2 five-file trust root before replay
  reservation. Admission scans bounded sorted service/request coordinates
  globally, so any pending candidate or orphan, malformed, unsafe, ambiguous,
  or conflicting outcome blocks replay independent of predecessor. Every
  terminal must resolve to a non-`none` request in the current authenticated
  chain; abandoned issue or migration outcomes do not satisfy renewal
  admission. Retained request and approval signatures verify against that root,
  while retained response and deployer trust copies must byte-match it.
- [x] Add whole-command Bash/Python managed and host-local renewal
  differentials against the frozen final-Bash command.
- [x] Freeze final Bash service-renew assets from
  `c5a66cd846fe84bf7917da84613762b1f2db09ce` and repin the differentials
  immediately before public parser/dispatch cutover. The executable is mode 755
  with SHA-256
  `5956ab87ff665da4dd2d4820b9676771ad1e809de6aeedf28d0acb29a2634562`;
  the loaded mode-644 common, CSR-sign, and CSR-candidate libraries have
  SHA-256 `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`,
  `8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001`,
  and `ca1fb976f09730fbbc840ce97cb0c6db3ae76e5d679fdc777a1a96d80df5b43f`.
- [x] Dispatch compatibility and unified service-renew through one Python
  handler, retain managed recovery only under unified `service-recover`, and
  retain host-local recovery under `csr-recover`.

Root-create checkpoint:

- [x] Compatibility and unified routes share one Python schema-3 writer.
- [x] Writer-order journals, reservation/bootstrap records, OpenSSL artifacts,
  modes, output, status, and all five handled-failure state trees match the
  frozen Bash oracle.
- [x] Unified Python recovery accepts every public crash checkpoint written by
  both final Bash and Python, and direct final-Bash recovery accepts the
  Python-written compatible records used by the retained compatibility route.
- [x] Installed direct/unified operation, signals, retry generation allocation,
  deterministic generation, focused suites, and canonical container acceptance
  pass. The intermediate authority writer remains the next Phase 6 tranche.

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

- [x] Model preparation, migration, bootstrap, publication, and terminal cleanup
  as explicit state machines.
- [x] Preserve schema, transaction fields, generation reservations, backup
  receipts, trust snapshots, manifests, fault checkpoints, and recovery actions.
- [x] Reuse the established filesystem, lock, record, subprocess, and
  transaction primitives rather than creating rollover-specific duplicates.
- [x] Run Bash-to-Python and Python-to-Python crash recovery at every checkpoint.
- [x] Preserve the authoritative bounded-parallel rollover test suite.

Validation gate:

- [x] Parser, preparation, migration, fault, lifecycle, recovery, and advanced
  rollover suites pass without skipped or weakened scenarios.
- [x] Rollover is independently releasable before Bash cleanup begins; final
  pre-cleanup `make container-check` acceptance passed.

## Phase 8: Retire PKI Bash Implementations

Goal: Remove obsolete PKI Bash implementation and runtime-library ownership
after all unified routes use Python and pass final acceptance, then complete the
approved next-major unified-only production boundary.

Tasks:

- [x] Remove migrated PKI commands from `SHELL_TOOLS` and `BASHLY_TOOLS`.
- [x] Add all Python-backed command names to the maintained Python inventory.
- [x] Remove all `platform-pki-*` compatibility launchers from the installed
  tool inventory and retain only `platform-pki` at the next-major implementation
  boundary.
- [x] Remove compatibility-name dispatch and update user-facing examples,
  installed-tool tests, release notes, and upgrade guidance to unified routes.
- [x] Remove PKI Bashly workspaces only after the corresponding Python release
  has passed final acceptance.
- [x] Remove `lib/platform-pki-common.sh`, `lib/platform-pki-csr-sign.sh`, and
  `lib/platform-pki-csr-candidate.sh` only after no installed or checkout
  consumer remains.
- [x] Preserve the final Bash commits and migration compatibility evidence under
  `tests/pki/oracles/`.
- [x] Update generation, verification, installation, docs, `NEWS.md`, and
  `CHANGELOG.md`.
- [x] Leave non-PKI Bashly commands unchanged.

Validation gate:

- [x] Command inventory, installed tools, focused PKI suites, generated-file
  verification for remaining Bash tools, ShellCheck, and final container
  acceptance pass.
- [x] Targeted next-major implementation evidence covers one generated/installed
  PKI zipapp, absent alias artifacts, canonical renamed-copy behavior, and
  pre-mutation install refusal for exact stale aliases.
- [ ] Release gate: external downstream command inventory is reconciled, the
  canary is accepted, and every PKI target host provides Python 3.14 or newer.

## Packaging and Installation

The selected application artifact is a deterministic standard-library zipapp.
Maintained source and generated output use this repository layout:

```text
src/platform_pki/
bin/platform-pki
$INSTALL_DIR/platform-pki
```

During the completed incremental migration the repository also built and
installed `bin/platform-pki-*` compatibility launchers. They are absent from the
current next-major implementation layout above.

Requirements:

- Build the archive with stable member order, timestamps, modes, and content.
- Include the application package and `__main__.py`, but not a Python runtime or
  third-party dependencies.
- Embed the repository `VERSION` and verify it against `platform-pki`.
- Use isolated Python startup and reject accidental imports from outside the
  archive.
- Validate the complete zipapp before installation.
- Keep copied or renamed archives canonical; invocation names must not select a
  legacy route.
- Preserve custom `INSTALL_DIR`, `SHARE_DIR`, `PLATFORM_TOOLS_SHARE_DIR`, and
  existing shared-template lookup behavior.
- Prove direct execution, copied or renamed canonical behavior, signals,
  inherited descriptors, and subprocess behavior.
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
| Next-major implementation | Remove compatibility launchers and install only `platform-pki` |

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

- `make verify`
- `make test-command-contract`
- `make test-installed-tools`
- The command's focused Make target.
- Bash/Python differential success and failure scenarios.
- State-tree comparison including paths, types, modes, links, digests,
  canonical bytes, and expected identity relationships.

Transaction cutovers must additionally include:

These are later command-specific operational integration gates. Phase 2
primitive completion does not satisfy them or provide a generic recovery
protocol.

- Bash interrupted state recovered by Python.
- Python interrupted state recovered by Python.
- Source and destination replacement races.
- Signals before and after the commit boundary.
- No-op, replay, retry, rollback, and resume behavior.
- Installed-layout execution with isolated imports and runtime paths.

Use focused checks during development. Run `make container-check` once as the
final acceptance gate for each releasable tranche rather than repeatedly during
implementation. Every completed cutover met these recurring criteria, and the
Phase 8 progress entry records the final aggregate acceptance run.

## Risks

- Python does not directly provide every required GNU `mv` exchange and
  no-copy/no-clobber primitive.
- A naive `pathlib` rewrite could weaken descriptor and TOCTOU protections.
- Python exceptions or subprocess wrappers could expose secret-bearing
  arguments or diagnostics.
- Downgrading to mixed Bash/Python releases could create shared-package or
  journal-version skew.
- Parser compatibility requires more than default `argparse` behavior.
- The current strict inventory language is not equivalent to general YAML
  loading.
- Forward-only package migration requires release documentation to state that
  older Bash implementations must not be used with Python-written transaction
  state and are not guaranteed to interpret it.
- Every deployment target that executes a PKI command must provide Python 3.14
  or newer before the v3 release. Target provisioning is owned by the deployment
  environment rather than this tool repository and remains a release blocker.

## Open Questions

- [x] Require deployment owners to provision Python 3.14 or newer on every host
  that executes a PKI command before installing v2.3.0.
- [x] Retain recorded final-Bash commits, release tags, source extracts, and
  executable oracles indefinitely as historical compatibility evidence.
- [ ] Reconcile every external downstream command inventory to unified routes.
- [ ] Complete the release canary against the unified-only package.
- [ ] Prove Python 3.14 or newer on every target host that executes a PKI
  command.

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
| 2026-08-07 | Shared parser-edge behavior was frozen across all then-current PKI leaves. | `tests/test_command_contract.py` drove help, equals-form, abbreviation, action-order, stream/status, and no-state probes through the then-current compatibility-backed inventory; the current parser inventory has 27 leaves including unified-only `service-recover` and `offline-csr approve|sign`. |
| 2026-08-07 | Pilot output, status, dependency, and installed-asset contracts were added. | The original source- and test-backed tranche covered `print-cert`, `list-expiry`, and `service-verify`; the current inventory covers seven routes and explicitly defers 20. |
| 2026-08-07 | Minimum runtime raised to Python 3.14. | The pinned test image provides Python 3.14.7, avoiding an unverified older-runtime claim. |
| 2026-08-07 | Deterministic unified zipapp foundation added without command cutover. | Fixed-metadata standard-library archive, isolated `-I -S` startup, 18 copied compatibility names, then-current unified help coverage, installed-layout execution, and no-state parser behavior were covered in the pinned Python 3.14 test image. |
| 2026-08-07 | Phase 1 shared parser and runtime primitives implemented. | Source-backed parsing for the then-current compatibility-backed inventory, strict records, C-locale inventory differentials, bounded process-group execution, protected inherited descriptors, and secret-safe diagnostics passed 429 focused tests. Final `make container-check`: 2,285 passed; operational handlers remained unavailable. |
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
| 2026-08-09 | `platform-pki-backup` completed Phase 5 archive migration. | The final Bash commit is `3d5e3b4ecd4c137f97748b4066c7e4c508e99655`; its frozen mode-755 oracle has SHA-256 `beac1204e2014e41be39254389ebc18a9db4b5a7b699197bf25187d5a8b6deea`, and the retained common library has SHA-256 `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`. Compatibility and unified routes share one Python handler with external GNU `tar`, inherited-terminal `age -p`, exact in-tree exclusions, canonical schema-2 receipts, full lock coverage, durable no-clobber publication, final source/archive/receipt rechecks, and explicit retained or uncertain publication evidence. The focused suite passed 31 tests, the complete 224-test rollover suite accepted Python receipts, independent final review found no concrete defect, and final `make container-check` passed 2,834 tests in the pinned containers. |
| 2026-08-09 | First behavior-neutral CA recovery foundation checkpoint added. | Final Bash rollover/root/intermediate/common assets from `ba9dd57214cae18f82c83dfb54b6ddce13882280` are frozen with provenance tests; Python adds strict persisted GNU-stat codecs, exact schema-2/3 structural record parsing, bounded private journal loading, and generic schema-5 structure parsing. Operation-specific phase, path, identity, and transition semantics remain pending; public recover dispatch and all recovery mutation behavior remain unchanged. Schema 5 remains semantically pending because the writer has 206 declared keys plus 13 cumulatively introduced successful-copy identity keys rather than one fixed 208-field shape. The integrated foundation passed 785 tests, the authoritative rollover parser passed 61 tests, deterministic generation and static verification passed, and independent final review found no concrete defect. |
| 2026-08-09 | Typed CA recovery evidence and manifested-tree validation added without changing dispatch. | Python now types all four final-Bash recovery journal families, including cumulative schema-5 copy evidence and receipt-bound terminal marker records. Descriptor-relative manifested-tree validation binds self-excluded manifests, exact metadata, public digests, secret literals, complete membership, xdev traversal, and cleanup readiness. Differential test setup can now create identity-bound interrupted states independently after each private copy. Public recovery mutation remains Bash until the state machines and differential gates are complete. The pinned foundation passed 811 tests, Python infrastructure passed 149, the authoritative parser passed 61, static and deterministic-generation checks passed, and final independent review found no concrete defect. |
| 2026-08-09 | Non-public CA recovery state-machine implementation started. | Python can recover representative final-Bash schema-2 migration, schema-3 root and intermediate bootstrap, and schema-5 preparation states through an isolated subprocess driver, including receipt-bound terminal cleanup. Final-Bash cleanup subset semantics were preserved for already-consumed manifested members. Public dispatch remains unavailable because every writer/recovery checkpoint, race, signal, invalid-state, and differential state-tree gate has not yet been exercised. Final `make container-check` passed generated-Bash verification, ShellCheck, static checks, and all 2,919 maintained tests, including the four focused Python recovery scenarios. |
| 2026-08-09 | Non-public CA recovery review findings fixed. | Staged replacement now accepts only journal-authorized destination states and preserves ambiguous post-mutation errors; control writes translate filesystem failures; legacy transaction evidence requires exact owner and mode policy; and schema-5 root DB resume/rollback publication windows authenticate relocated inode state, persist the observed full identity, and remain crash-resumable. Focused Python recovery passed 11 tests, manifested cleanup passed 18, the foundation passed 814, and the bounded rollover suite passed 235. Public dispatch remains unavailable. |
| 2026-08-10 | Unified CA recovery dispatch migrated to Python. | `platform-pki ca-rollover recover` now runs the complete Python schema-2, schema-3, and schema-5 recovery state machines while direct `platform-pki-ca-rollover` invocations and rollover sibling leaves remain on final Bash. Seven state-tree differentials cover bootstrap rollback/cleanup, legacy resume/rollback, root-preparation publication resume/rollback, and terminal marker-only cleanup. The root-DB differentials explicitly record the one strengthened contract: Python authenticates and resumes publication or restoration completed immediately before a pending journal rewrite, while final Bash fails closed. The opt-in authoritative rollover suite passed all 243 tests in the pinned Python 3.14.7 container. Final `make container-check` passed generated-artifact verification, ShellCheck, static checks, all 2,940 maintained tests, and the archive smoke. |
| 2026-08-10 | Root authority creation migrated to Python. | `platform-pki-root-create` and `platform-pki root-create` share one schema-3 transaction writer with descriptor-bound passphrase input, fixed writer-order evidence, deferred handled signals across mutation-to-evidence assignments, complete private staging, no-clobber publication, identity-bound rollback, and ASCII canonical recovery paths. Frozen-Bash/Python differentials cover success and every handled-failure checkpoint; unified Python recovery covers every final-Bash and Python writer crash checkpoint. The complete opt-in recovery suite passed 252 tests. Final `make container-check` passed generated Bash and Python verification, ShellCheck, static checks, 2,949 maintained tests, and the 10-test archive smoke. |
| 2026-08-10 | Intermediate authority creation migrated to Python. | `platform-pki-intermediate-create` and `platform-pki intermediate-create` share one schema-3 writer with separate passphrase descriptors, exact one-open root-database staging and rollback snapshots, staged bootstrap-root verification, ordered crash-evidenced publication, and cleanup-only resume. Frozen-Bash/Python differentials cover success, handled rollback, root-database crash, and sensitive-stage cleanup states; the focused intermediate suite passed 83 tests and unified Python recovery passed 252 tests. Final `make container-check` passed generated Bash and Python verification, ShellCheck, static checks, all 2,974 maintained tests, and the 10-test archive smoke. |
| 2026-08-10 | First behavior-neutral Python CSR recovery foundation tranche added. | `src/platform_pki/csr_recovery.py` freezes and types the 114-field signing and 82-field finalization journals, exact DB and source paths, identities, scalar and digest forms, phase coherence, durable signing-checkpoint evidence and publication-rewrite windows, and the top-level source-evidence bindings present in the finalization journal. Final Bash commit `418d1fe` is the current provenance baseline. This is non-public structural foundation only: public dispatch, live validation, mutation, and output remain unchanged. The future operational route must fail closed if its post-confirmation, under-lock journal-kind recheck differs from the kind the operator confirmed. The maintained foundation target passed 1,458 tests; final `make container-check` passed generated-artifact verification, ShellCheck, static checks, all 3,618 maintained tests, and the 10-test archive smoke. |
| 2026-08-10 | Non-public Python candidate-finalization recovery implemented. | `src/platform_pki/csr_recover.py` loads the typed 82-field final-Bash journal through bounded private descriptor access, holds the lifecycle-through-export lock profile, authenticates every source and publication state before mutation, and resumes only durable outcome, active-pointer, superseded-pointer, and journal transitions. The isolated subprocess suite covers all final-Bash phases in create and exchange modes, every Python recovery checkpoint, mutation-before-journal windows, replacement/digest/ambiguity failures, strict journal policy, and six independently created Bash/Python terminal-state differentials. Public `csr-recover` remains Bash. The pinned candidate target passed 77 tests, the pinned foundation passed 1,464 tests, and static plus deterministic Python generation verification passed. |
| 2026-08-10 | Non-public Python CSR signing recovery implemented. | `src/platform_pki/csr_recover.py` consumes exact replay evidence, restores all seven uncommitted CA database entries in reverse order, terminalizes failed requests without identity reuse, and resumes committed candidate-before-response publication without CA re-signing. Response signatures use pinned no-options Ed25519 trust and inherited key descriptors. The isolated suite covers all 18 final-Bash phases, restart checkpoints, fresh rollback and publication authorization races, complete branch preflight, descriptor and output secrecy, and field-aware Bash/Python terminal-state differentials. Public `csr-recover` remains Bash-owned. The pinned signing target passed 233 tests, the foundation passed 1,464 tests, and the candidate/finalization target passed 77 tests. Final `make container-check` passed generated Bash and Python verification, ShellCheck, static checks, all 3,824 maintained tests, and the 10-test archive smoke. |
| 2026-08-10 | CSR recovery compatibility and unified dispatch migrated to Python. | Final Bash executable and libraries from `0843c1c11b952aab39f5c95b5eced82989656eb3` are frozen with exact hash and mode provenance. One public handler selects without parsing, confirms exactly, acquires only the selected inventory or export lock profile, and fails closed if journal presence changes under lock. Frozen-oracle differentials retain final-Bash writer evidence; public subprocess tests cover compatibility/unified dispatch, help/color, diagnostics, confirmation, ambiguous state, lock selection, and no-switch races. Focused signing passed 243 tests, candidate/finalization passed 77, foundation passed 1,465, command contract passed 478, and installed tools passed 175. Final `make container-check` passed generated Bash and Python verification, ShellCheck, static checks, all 3,834 maintained tests, the 252-test rollover suite, and the 10-test archive smoke. |
| 2026-08-11 | Behavior-neutral managed service transaction foundation added and writer-derived authenticity findings resolved. | Typed host-local record codecs remain source-backed by retained CSR libraries and enforce retained cross-record timing plus canonical request/response digest bindings without claiming live trust or signature validation. The fixed 485-field schema-1 managed journal models all 29 retained operational destinations; complete pre/stage/private-backup/publication/rollback identity-object-digest chains; exact preparation and mutation progress prefixes; seven inventory/issuer/signing inputs under an exact private hierarchy; displaced archive-source bindings; deterministic issuer bytes; self-sized journal state; canonical retained transaction, rollback-completion, and terminal record sizes; optional-member presence; archive-container restoration; and phase evidence without dispatch or mutation. A durable full-prefix rollback witness now precedes detailed rollback-evidence clearing. Independent substitutions and restart matrices exercise every generic authenticity relationship and progress counter across issue reuse/create/rotate, renewal sparse/full archives, key rotation, publication, completed rollback, and cleanup. Pinned Python 3.14.7 verification passed the 209-test focused model, 1,674-test foundation, 40 issue tests, 8 renewal tests, 478 command-contract tests, 175 installed-tool tests, and 154 infrastructure tests. Static, deterministic Python generation, and containerized generated-Bash checks also passed. The preceding full `make container-check` passed generated Bash and Python verification, ShellCheck, all 3,899 then-maintained tests including the separately run 252-test rollover suite, and the 10-test archive smoke; this behavior-neutral follow-up did not repeat full acceptance. |
| 2026-08-11 | Independent managed-service boundary findings fixed. | Standalone request and approval codecs now enforce their retained maximum intervals; affected managed-service and CSR issued-serial paths reject removable leading `00` pairs; successful committed states retain complete staging, private-backup, and publication prefixes; and rollback separates ordinary files, archive containers, exact-boundary archive-root metadata restoration, and service containers. The adjacent audit also bound archive-root restoration state and identity into the durable rollback-completion digest so pre-restoration evidence cannot be reused. Exact boundary and negative regressions increased the focused model to 235 tests and the complete foundation to 1,705. Final `make container-check` passed deterministic Bash and Python generation, ShellCheck, static checks, all 4,072 maintained tests including the 252-test rollover suite, and the 10-test archive smoke. Public service issue/renew and recovery dispatch remain unchanged. |
| 2026-08-11 | Non-public managed-service operational recovery implemented and mutation boundaries hardened. | `src/platform_pki/service_recover.py` authenticates one exact Python service transaction under lifecycle-through-inventory locking, reconciles authorized publication windows, performs reverse-only pre-commit rollback with exact archive-root restoration and durable rollback completion, and performs cleanup-only post-commit recovery through canonical terminal publication and exact journal removal. Every absent/existing file rollback and directory/private-tree/marker/journal cleanup mutation now reaches an exact identity-bound publication primitive; private member identities and digests are revalidated after readiness capture. Same-name replacements are rejected and preserved. Cleanup absence or retained rollback/terminal bytes without journal-authenticated resulting identity fail closed with the journal retained. The isolated 116-test subprocess suite covers all incomplete stage and backup prefixes, every publication mutation window, all declared checkpoint applicability across issue/renew and pre/post-commit scenarios, crash/signal/failure windows, file/directory mutation-boundary replacements, root/container replacement, lock scope, and secret-safe diagnostics. Final `make container-check` passed deterministic Bash and Python generation, ShellCheck, static checks, all 4,188 maintained tests including the 252-test rollover suite, and the 10-test archive smoke. Public issue/renew behavior and `service-recover` parser/dispatch remain unchanged; no Bash recovery differential is claimed because retained Bash has no durable managed-service transaction journal. |
| 2026-08-11 | Final managed-service retained-evidence handoff hardened. | The schema-1 retained terminal now has 10 fixed fields and binds the exact retained transaction identity/digest plus the applicable failed-precommit rollback-completion identity/digest; successful terminals explicitly exclude rollback completion. Recovery reauthenticates canonical journal-bound transaction, terminal, and rollback evidence immediately before exact journal unlink, while journal-absent retries use one pinned retained-transaction directory and recheck every claimed identity, digest, mode, canonical record, and cleanup absence. Exact-replacement and unsafe-mode regressions increased the focused recovery suite to 125 tests, the focused model to 241, and the foundation to 1,711. Final `make container-check` passed deterministic Bash and Python generation, ShellCheck, static checks, all 4,203 maintained tests including the 252-test rollover suite, and the 10-test archive smoke. Public issue/renew behavior and `service-recover` parser/dispatch remain unchanged. |
| 2026-08-11 | Final managed-service cleanup-absence authorization completed. | One model-owned applicability set now covers exact `stage` and `backup` names for every terminal issue/renew outcome and the retained service/archive-bound marker only for successful renewal. Final unlink rechecks the complete applicable set after retained-evidence authentication; journal-absent retries derive the same paths without current/latest inference. File, directory, or symlink reappearance fails closed and remains untouched. Operation/outcome positives, non-applicable marker cases, journal-absent negatives, and nine final-unlink pause races increased the focused recovery suite to 152 tests, the focused model to 245, and the foundation to 1,715. Rollover differential normalization was also corrected for unlinked root-reservation inode reuse and the full Python intermediate temporary-name alphabet exposed by acceptance. Final `make container-check` passed deterministic Bash and Python generation, ShellCheck, static checks, all 4,234 maintained tests including the 252-test rollover suite, and the 10-test archive smoke. Public issue/renew behavior and `service-recover` parser/dispatch remain unchanged. |
| 2026-08-11 | Non-public managed service issue orchestration implemented and independently hardened. | `src/platform_pki/service_issue.py` plans one exact schema-1 issue transaction, snapshots inventory/issuer/CA state, passes encrypted-key secrets through inherited descriptors, runs real OpenSSL against detached staged state, publishes only through `ManagedServiceWriter`, verifies the live certificate, and hands pre-commit rollback or post-commit cleanup to shared recovery. Follow-up review added a durable pre-tree bootstrap reservation, immutable transaction-named bootstrap history, exact issue/recovery crash retry, authoritative terminal rollover parsing, active-issuer replacement rejection, pre-mutation OpenSSL value/path validation, and exact certificate subject/issuer/serial/key/signature/extension/SAN/identifier/validity checks. Public service issue remains final-Bash-owned, managed renew remains unimplemented, and no public recovery route was added. Pinned verification passed the expanded 41-test orchestration suite in 189.20 seconds, 164-test recovery suite, 40-test retained issue oracle, 41-test writer suite, 246-test service model, 478-test command contract, and 175-test installed-tools suite, including exact 485-field create/reuse/rotate journals and hostile profile outputs. Static and deterministic generated-artifact checks also passed. Full `make container-check` was intentionally not run for this non-public tranche. |
| 2026-08-11 | Non-public Python host-local CSR issue/migration writing implemented and final review findings resolved. | `issue_host_local_csr` in `src/platform_pki/service_issue.py` authenticates canonical request and approval records against installed no-options Ed25519 trust, pins and repeatedly rechecks the exact trust tree plus authenticated inventory, authority, and protocol sources, rejects duplicate or non-exact SAN profiles, enforces issued `notBefore` skew and exact inventory-authoritative lifetime, transports the intermediate passphrase through an inherited descriptor, writes every durable phase through the frozen 114-field parser, publishes all seven CA database entries in order, and delegates committed response signing plus candidate-before-response publication to the existing Python recovery engine. The final pre-publication authorization window now rechecks the exact journal identity, both active authority directory identities, root certificate, intermediate key/certificate/closed configuration/CRL number, every snapshotted CA database input, active-issuer record, inventory, and complete trust tree; replacement failures retain the uncommitted journal without CA mutation so exact source restoration can be followed by recovery. Exception and signal handling reloads the durable journal: pre-commit cleanup permanently consumes replay and restores CA state, while a committed journal is retained for forward-only recovery without rollback or CA re-signing. Complete semantic state-tree differential coverage matches final Bash after normalizing only copied roots and certificate time/signature dynamics. The 68-test focused suite passed in 38.98 seconds and covers issue, migration preservation, trust/source races, malformed trust, exact CSR/certificate profiles, replay retries, all 22 post-journal writer crash checkpoints, commit-rewrite failure/signal gaps, response-key replacement, and response-signing invocation count. Copied CSR fixtures now authenticate the source-bound committed terminal `g1-i1` intermediate-bootstrap journal through authoritative CA recovery semantics before removing only its byte-identical copied path; the six targeted positive/malformed/pending/unknown-operation/wrong-operation/wrong-transaction fixture checks passed in 3.29 seconds. Public service issue remains final-Bash-owned; no CLI, compatibility, or Make command-ownership cutover occurred. Full `make container-check` was intentionally not run for this non-public tranche. |
| 2026-08-11 | Host-local response-signature mutation ownership and test interception boundaries hardened. | Python recovery now writes a durable `response-signing` checkpoint before invoking `ssh-keygen`; only that owned post-sign/pre-evidence window may authenticate and adopt an exact safe signature after rechecking complete committed sources, while final-Bash-compatible `ca-committed` recovery removes and recreates a safe unowned signature. Malformed, unsafe-mode, hard-linked, or replaced signatures fail closed. OpenSSL interception regressions resolve the real executable before prepending an executable fake and assert invocation markers before profile or commit-gap outcomes. Pinned verification passed the expanded 73-test writer suite in 48.07 seconds, the 680-test CSR recovery foundation, two isolated descriptor/replacement signing tests, and six authenticated fixture-copy tests. Public issue dispatch and final-Bash compatibility remain unchanged; full acceptance was intentionally not run for this focused follow-up. |
| 2026-08-11 | Service issue and managed recovery public cutover implemented. | `platform-pki-service-issue` and unified `service-issue` now share the Python managed/host-local handler; unified-only `service-recover` confirms and recovers one exact managed transaction. The final Bash executable from `6a7f162240c9970cf9a17091d9b37c8dea071ad8` is frozen at mode 755 and SHA-256 `c06bb8baba8d7a75f0a3a88f814b86740aab03f78eef2e8fcd05140534206fa5`, with loaded common and CSR-sign libraries pinned at SHA-256 `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f` and `8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001`. Service renew remains Bash-owned. |
| 2026-08-11 | Service renewal public cutover implemented. | `platform-pki-service-renew` and unified `service-renew` now share one Python managed/host-local whole-command handler; managed interruption recovery remains unified-only through `service-recover`, while host-local recovery remains under `csr-recover`. Final Bash commit `c5a66cd846fe84bf7917da84613762b1f2db09ce` is frozen with mode/hash provenance and both managed and host-local differentials. Final focused verification passed 12 public renewal tests in 63.83 seconds, four managed writer/differential tests in 75.60 seconds, 47 host-local tests with four workers in 159.42 seconds, 167 managed recovery tests, 473 command-contract tests, 1,750 foundation tests, 175 installed-tool tests, and 48 migration-contract tests. Deterministic Bash/Python generation, static checks, and ShellCheck passed; full `make container-check` was intentionally not run for this focused cutover. |
| 2026-08-12 | CSR trust installation public cutover implemented and final publication authorization hardened. | `platform-pki-csr-trust-install` and unified `csr-trust-install` now share one Python handler; final Bash commit `678daa6de2ea24ada1fd36199013347f79f303bf` is frozen with executable and loaded-library provenance. Frozen-oracle differentials cover fresh install, exact no-op, atomic update, and retained-root terminal history across all four signer rotations. Python-specific tests cover source, installed-state, inventory, retained-history, staging, lock, interruption, and immediate pre-publication authorization races. The bounded four-worker trust suite passed all 75 tests in 61.17 seconds; deterministic Python generation and static checks passed. Final `make container-check` remains reserved for migration acceptance. |
| 2026-08-12 | Certificate export public cutover implemented and targeted acceptance completed. | Final Bash commit `24db7d54ca5c113fe763d4007c5dfef507dc23a6` is frozen at mode 755 and SHA-256 `21c73b92d8568a74e8b75f554831060309c4f998d4230d28b019d72c3e1f85fa`; loaded common and CSR-sign libraries are frozen at SHA-256 `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f` and `8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001`. Compatibility and unified `certificate-export publish|resolve` share one Python handler. Frozen-oracle differentials cover publication plus path, JSON, and wrong-pin resolution; final authenticated-source replacement races fail cleanly before publication or output. The expanded export suite passed 17 tests in 45.47 seconds; the Bash-owned candidate consumer passed 77 tests with four workers in 190.22 seconds; inventory, migration, parser, and foundation contracts passed 389 tests in 53.66 seconds; shared publication passed 175 tests; command contract passed 465 tests; and installed tools passed 175 tests. Deterministic Python generation, static verification, and whitespace checks passed. Final `make container-check` remains reserved for final migration acceptance. |
| 2026-08-12 | CSR candidate public cutover implemented and handled-signal ownership hardened. | Final Bash commit `24db7d54ca5c113fe763d4007c5dfef507dc23a6` is frozen with executable SHA-256 `03566a3917505e1999e52e2ece0f7a29313cd8869c4f968802e6525c8a3b5c95` and exact common, CSR-sign, and candidate-library provenance. Compatibility and unified `csr-candidate verify|finalize|abandon` share one Python handler. Frozen-oracle help and state-tree differentials cover all three actions. Handled SIGHUP, SIGINT, and SIGTERM are deferred across pre-journal stage ownership and durable journal handoff; exact partial-stage cleanup cannot adopt foreign replacements, and post-journal interruption retains resume-only recovery. The committed compatibility candidate and finalization recovery target passed 104 tests; ownership, parser, foundation, inventory, migration, and Make contracts passed 424 tests; command contracts passed 461 tests; installed tools passed 175 tests; deterministic Python generation, static checks, retained Bash generation, ShellCheck, and whitespace checks passed. Final `make container-check` remains reserved for final migration acceptance. |
| 2026-08-12 | CA rollover public cutover implemented and focused acceptance completed. | Final Bash commit `ba9dd57214cae18f82c83dfb54b6ddce13882280` remains frozen with executable SHA-256 `7e9430e6d17969d5d1779e8073b9757e08157625e16b91969991e611953b806b` and common-library SHA-256 `dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`. Compatibility and unified `ca-rollover migrate|status|prepare|recover` share Python handlers. Core migration, status, and preparation scenarios execute the generated compatibility launcher; private drivers remain limited to implementation-level race injection and frozen-oracle differentials. The complete four-worker rollover suite passed 544 tests, and focused trust-install, certificate-export, and candidate suites passed 75, 17, and 104 tests. Deterministic Python generation and the 250-test foundation passed. Final `make container-check` remains pending. |
| 2026-08-13 | Phase 8 production Bash retirement completed. | PKI Bashly workspaces and installed shell libraries were removed after pre-cleanup acceptance. Current-release compatibility names remain deterministic Python zipapps. Required final-Bash source evidence was relocated byte-for-byte under `tests/pki/oracles/final-bash-source/` with a complete SHA-256 manifest; command-specific executable oracles remain unchanged. Final `make container-check` passed remaining Bash generation, ShellCheck, static checks, all 4,849 maintained tests including 544 rollover cases, and the 10-test archive smoke. |
| 2026-08-13 | Next-major unified-only implementation completed; release gate remains open. | Current worktree source and targeted test changes remove all 18 alias artifacts and compatibility-name dispatch, generate/install only `platform-pki`, keep renamed copies canonical, and make installation reject exact stale alias paths before mutation without deleting them. Final bounded parser/help verification passed 40 tests; unified-only install inventory and exact legacy-alias preflight verification passed 3 tests; deterministic zipapp verification, Python compilation, whitespace validation, and frozen-oracle checks passed. Documentation and Unreleased notes carry exact manual cleanup guidance. External downstream inventory, canary validation, and Python 3.14 target-host readiness remain blockers; `VERSION` is still `2.3.0`. |
| 2026-08-17 | Unified-only candidate hardening completed without closing the release gate. | Current route documentation now records all 27 unified leaves and 20 deferred output/status contracts. Exact legacy-alias install preflight covers regular files, directories, dangling symlinks, and live symlinks; runtime-evidence races cover one immutable artifact-state snapshot, descriptor-bound executable status, replacement during and after hashing, sealed-snapshot invocation, and one immutable alias snapshot for both detail fields and aggregate status; offline signing rejects approved-source or installed-trust changes after confirmation before journal/replay mutation. Persisted rollover recovery and migration action bytes retain their exact historical alias spellings despite unified-only runtime dispatch. The focused install, offline, and persisted-action additions passed 4, 2, and 2 cases, and the complete 26-test runtime-evidence target passed. Pinned deterministic Bash generation, ShellCheck, Python zipapp verification, Python compilation, and whitespace checks passed. Full `make container-check` and the external downstream, canary, and target-host Python gates remain pending; `VERSION` remains `2.3.0`. |

## Decision Log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-08-07 | Preserve existing command names and add a unified alias. | Maintain automation compatibility while providing a coherent new interface. |
| 2026-08-07 | Require forward-only cross-version recovery. | Python must recover Bash state; older Bash implementations are not required to recover Python state. |
| 2026-08-07 | Migrate incrementally and move rollover last. | Reduce simultaneous parser, filesystem, transaction, and recovery risk. |
| 2026-08-07 | Build and install a deterministic standard-library zipapp. | Keep maintained source modular while avoiding Python package/import skew and unnecessary PEX dependencies. |
| 2026-08-07 | Require Python 3.12 or newer. | Use a modern standard-library baseline while retaining a clear target-host provisioning contract. |
| 2026-08-07 | Use shallow unified command names. | Mirror existing executable suffixes and minimize parser and documentation divergence. |
| 2026-08-11 | Recover managed issue/renew through a future unified-only `service-recover` route. | Managed Python transactions need a new forward-only journal; host-local operations retain the existing CSR journal and public recovery ownership. |
| 2026-08-07 | Retain the final Bash source through migration acceptance and record each command's pre-cutover commit. | Keep differential evidence reproducible without shipping a production runtime language switch or duplicate oracle installation. |
| 2026-08-07 | Raise the minimum from Python 3.12 to 3.14. | Align the application contract with the pinned Python 3.14.7 test environment instead of maintaining an unverified older-runtime claim. |
| 2026-08-07 | Design and review the `doctor` contract before exposing a public route. | The review exposed missing positive-eligibility and package-handoff contracts before runtime code was added; this decision was superseded on 2026-08-08. |
| 2026-08-08 | Make package migration forward-only and do not add `doctor`. | Supported rollback would require exhaustive historical-state validation and a guarded package-replacement workflow; neither is needed when using older Bash releases with Python-written state is outside the supported model. |
| 2026-08-09 | Pull the complete recover leaf ahead of Phase 6 authority writers. | A temporary leaf-level Bash/Python mix is approved and follows the Phase 7 leaf migration strategy; no public dispatch changes until the complete recovery leaf passes Bash-to-Python recovery acceptance. |
| 2026-08-10 | Cut over only the unified rollover recovery route. | This exposes the accepted Python recovery state machines without changing the final-Bash compatibility executable or the migration, status, preparation, and authority-writer paths that still produce the recovered state. |
| 2026-08-10 | Require a post-confirmation CSR journal-kind recheck before Python recovery mutation. | Recovery must not switch between signing and candidate-finalization protocols after the operator confirms one kind; a changed selection under the required locks fails closed. The public Python route now enforces this decision. |
| 2026-08-10 | Remove `platform-pki-*` compatibility executables in the next major release. | Compatibility names remain available while routes migrate, but the completed migration will install only `platform-pki`; frozen Bash oracles remain test evidence rather than public launchers. This supersedes the 2026-08-07 decision to preserve compatibility names indefinitely. |
| 2026-08-13 | Complete the unified-only implementation before opening the v3 release gate. | Alias removal, canonical copied-name behavior, and fail-closed manual-cleanup installation are implemented, but release remains blocked on external downstream inventory, canary acceptance, and target-host Python prerequisites. |
