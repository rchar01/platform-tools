# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

- Added `platform-pki offline-csr approve|sign` for exact-directory offline
  host-local CSR review. Approval authenticates and no-clobber-publishes the
  canonical five files without changing CA or replay state; signing adds an
  authenticated precommit confirmation and delegates to the existing signer
  and `csr-recover` state machine. Protected approval and response Ed25519 keys
  prompt through the inherited terminal without exposing passphrases in
  arguments, environment, or machine-readable output.
- Added `platform-runtime-evidence`, a state-free collector for reviewed host or
  image identity, Python 3.14 readiness, installed `platform-pki` metadata and
  digest, all 18 exact retired aliases, external tool versions, and selected
  Linux filesystem capabilities. It does not read PKI state or execute the
  selected artifact unless `--invoke-version` is supplied, and it reports
  evidence rather than certifying role-specific readiness.
- **Breaking:** PKI packaging is unified-only. Production generation and
  installation now publish only `platform-pki`; all 18 v2 `platform-pki-*`
  compatibility aliases have been removed. Update commands and automation to
  `platform-pki <command>`. A copied or renamed archive still identifies and
  behaves as `platform-pki`; its filename does not restore alias dispatch.
- Before upgrading from v2.3.0, inspect and manually remove or relocate every
  exact legacy alias path listed in the
  [upgrade guide](README.md#upgrade-from-v230). Do not use wildcard deletion.
  Installation checks those exact paths before any mutation, fails closed if
  any path or dangling symlink remains, lists the blockers, and never deletes or
  replaces them.
- This remains post-v2.3.0 release development. `VERSION` stays at `2.3.0`
  until the next-major release gate is complete.

## v2.3.0 - 2026-08-13

- All maintained PKI routes and current-release `platform-pki-*` compatibility
  commands are now Python zipapps. PKI Bashly workspaces and installed shell
  libraries have been retired, so `make install` now publishes only PKI
  templates under the shared-data directory. Immutable final-Bash executables,
  libraries, and required source fragments remain test-only evidence under
  `tests/pki/oracles/`. Compatibility command names remain supported until the
  approved next major release. New operator commands, documentation, and
  automation should use the unified `platform-pki <command>` interface. PKI
  execution requires Python 3.14 or newer on each target host.
- `platform-pki-service-issue` and `platform-pki service-issue` now share one
  Python handler for managed issuance and authenticated host-local issue or
  migration. Managed schema-1 transactions can now be recovered through the
  unified-only `platform-pki service-recover --transaction` route with exact
  confirmation; host-local transactions continue to use `csr-recover`.
  Host-local issue and migration preserve the final Bash fault-injection and
  validation diagnostics, and exact-identity cleanup now retains both a
  displaced temporary input tree and any foreign same-name replacement.
- `platform-pki-service-renew` and `platform-pki service-renew` now share the
  same Python whole-command handler for managed and authenticated host-local
  renewal. Managed interruption recovery remains unified-only through
  `service-recover`; host-local interruption recovery remains with
  `csr-recover`. The final Bash command and its loaded libraries are retained
  only as frozen compatibility-test evidence.
- `platform-pki-csr-trust-install` and unified
  `platform-pki csr-trust-install` now share one Python handler. Trust rotation
  continues to authenticate historical responses and deployments with their
  immutable retained signer roots, while preserving exact no-op behavior,
  current-inventory bindings, four-lock coverage, and atomic whole-directory
  publication.
- `platform-pki-certificate-export` and unified
  `platform-pki certificate-export publish|resolve` now share one Python
  handler. Publication remains certificate-only, immutable, and bound to one
  authenticated pending CSR response; resolution still requires the exact
  service, request ID, and manifest digest and performs no finalization.
- `platform-pki-csr-candidate` and unified
  `platform-pki csr-candidate verify|finalize|abandon` now share one Python
  handler. Decisions still authenticate exact schema-2 deployment evidence,
  preserve immutable terminal history, and delegate journaled finalization to
  resume-only CSR recovery without performing or claiming live deployment.
- `platform-pki-ca-rollover` and unified `platform-pki ca-rollover` now share
  Python handlers for `migrate`, `status`, `prepare`, and `recover`. The
  migration and preparation writers preserve their schema-2 and schema-5
  journals, generation reservations, immutable manifests, fault boundaries,
  and recovery actions; the final Bash command remains only as a frozen
  compatibility oracle.
- Added the deterministic, standard-library-only `platform-pki` Python 3.14
  zipapp as the unified migration interface. The foundation build provides the
  frozen 25-route parser, strict ordered-record and inventory models, bounded
  exact-argv process execution, descriptor-bound filesystem and path safety
  primitives, descriptor-bound lifecycle-through-export advisory lock context
  managers, bounded Linux no-clobber publication, exact exchange, and guarded
  existing-destination replacement, owned exact-byte staging, identity-bound
  cleanup, source-file synchronization, parent-bound immutable directory
  readiness, descriptor-relative tree durability, deterministic transaction
  test hooks, secret-safe errors, and fail-closed unavailable-handler behavior.
  The Python locks interoperate with
  util-linux `flock`, close inherited descriptors safely across fork, and link
  validated anonymous files at absent destinations without replacement.
  Existing-destination replacement requires explicit exact identities, uses
  forward-only `RENAME_EXCHANGE`, exact-unlinks only displaced regular files,
  and retains complete displaced directories with readiness evidence for later
  caller-journaled cleanup. `platform-pki-init` now shares one Python handler
  with `platform-pki init` while preserving its path and tree validation,
  template publication, installed shared-asset lookup, output, and status.
  `platform-pki-inventory-install` now likewise shares one descriptor-bound
  Python publication handler with `platform-pki inventory-install`, preserving
  source and destination identity checks, lifecycle-through-inventory locking,
  mode normalization, atomic no-clobber/exchange behavior, and retained
  ambiguous recovery artifacts.
  `platform-pki-print-cert`, `platform-pki-list-expiry`, and
  `platform-pki-service-verify` likewise share their Python operational handlers
  with the corresponding unified routes while preserving locking, OpenSSL child
  behavior and legacy-state rejection without an installed shell library.
  `platform-pki-export-ansible` and `platform-pki export-ansible` now build a
  complete mode-700 same-parent tree, copy source bytes through no-follow
  identity-checked descriptors, synchronize and revalidate the complete tree,
  and publish it atomically. Forced replacement exchanges only the validated
  destination identity, never rolls back a published replacement, and retains
  the exact displaced directory with recovery evidence when safe cleanup cannot
  be completed. Custom marker authorization remains descriptor-pinned through
  exchange, cleanup rechecks each exact entry immediately before mutation, and
  prepublication stages without complete cleanup readiness are retained and
  reported rather than traversed destructively. `platform-pki-custody-report`
  and `platform-pki custody-report` now share one Python handler with exact text
  and schema-1 JSON output, first-line-only 257-byte key and age inspection,
  compatible unordered schema-2 receipt parsing, descriptor-relative xdev
  metadata enumeration without temporary path lists, bounded suppressed storage
  helpers, and lifecycle-through-export locking. Receipt digests remain recorded
  evidence and are not recalculated. `platform-pki-ca-passphrase-verify` and
  `platform-pki ca-passphrase-verify` also share one Python handler. It retains
  all requested passphrase, active-key, certificate, and manifest descriptors
  through final locked rechecks, passes each secret to OpenSSL through a fresh
  minimal inherited descriptor, suppresses OpenSSL diagnostics, and compares
  public keys in bounded memory without temporary verification state.
  `platform-pki-backup` and `platform-pki backup` now share one Python handler
  while preserving GNU `tar` exclusions, ordered literal `age` recipients,
  inherited passphrase prompting, explicit plain-backup opt-in, full lock
  coverage, and canonical schema-2 receipts. Archive and receipt publication is
  durable and no-clobber; a published archive is retained and reported if its
  receipt cannot be published. `platform-pki-root-create` and
  `platform-pki root-create` now share a Python schema-3 transaction writer with
  passphrase-descriptor OpenSSL input, exact writer-order journals, signal-safe
  rollback evidence, no-clobber authority publication, and Python recovery for
  every final-Bash and Python writer crash checkpoint. Recovery-journal paths
  must be ASCII. `platform-pki-intermediate-create` and
  `platform-pki intermediate-create` now likewise share a Python schema-3
  writer. It passes both passphrases through minimal inherited descriptors,
  binds the bootstrap root and database snapshot through exact source
  identities, publishes the intermediate and root-database updates with
  crash-resumable evidence, and supports rollback or terminal sensitive-stage
  cleanup through unified Python recovery. The unified
  `platform-pki ca-rollover recover` route uses Python
  recovery state machines for legacy migration, root and intermediate bootstrap,
  rollover preparation, and receipt-bound terminal cleanup. It preserves
  final-Bash journal, output, and recovery-action contracts
  for previously accepted states and additionally resumes authenticated root-DB
  publication windows that Bash leaves recovery-required.
- `platform-pki-csr-recover` and `platform-pki csr-recover` now share one Python
  recovery handler. It preserves final-Bash signing and candidate-finalization
  journals, exact confirmation and output contracts, pre-commit rollback,
  permanent replay consumption, and post-commit resume-only publication. The
  selected journal kind is rechecked under its exact lock profile after
  confirmation and recovery fails closed rather than switching protocols.
- Bashly generation and shell linting now use a dedicated development image,
  while Python 3.14 tests run in a separate pinned image with pytest 9.1.1 and
  pytest-xdist 3.8.0. The canonical container check still runs the complete test
  aggregate exactly once.
- CSR protocol test modules now copy one immutable per-session PKI seed instead
  of regenerating complete root and intermediate authorities for every test.

## v2.2.0 - 2026-08-07

- `platform-pki-csr-trust-install` now explicitly owns the complete lifecycle,
  root, intermediate, and inventory lock boundary and fails closed before an
  actual schema-2 trust change unless every retained signer candidate has an
  authenticated finalized or abandoned outcome. Exact no-ops and authenticated
  terminal history remain allowed; external pending requests still require a
  separate lifecycle gate.

## v2.1.0 - 2026-08-06

- The maintained test aggregate now runs non-rollover modules with two bounded
  Make jobs before running the four-worker PKI rollover suite alone. Container
  runs forward `TEST_MAKE_JOBS` and `PKI_PYTEST_WORKERS`, each bounded from 1
  through 4, for reproducible resource tuning and serial diagnostics.
- Documented the proposed production GitLab 18.11.3 Generic Package exchange and
  the development-only direct SSH/SFTP registry migration design/manual handoff
  for host-local CSR artifacts. These documents add no network transport,
  target activation, crash-safe automation, or live authorization to
  `platform-tools`.
- Added `platform-pki-csr-trust-install` for strict, atomic installation of the
  reviewed public Ed25519 trust and timing policy reserved for authenticated
  host-local CSR exchange. Installing trust performs no signing itself.
- Added authenticated host-local issue, managed-to-host-local migration, and
  renewal from P-384 CSRs. The signer verifies canonical request and approval
  signatures, enforces replay and inventory-authoritative profiles, updates CA
  state transactionally, and publishes certificate-only pending candidates and
  signed responses. `platform-pki-csr-recover` deterministically rolls back
  exact pre-commit publication or resumes post-commit response publication.
- Added `platform-pki-certificate-export` to publish one explicit authenticated
  pending CSR response as an immutable certificate-only artifact and resolve it
  only by exact service, request ID, and manifest digest. Exports remain
  unfinalized; there is no current/latest inference, deployment, or activation.
- Added `platform-pki-csr-candidate` for exact candidate verification and
  schema-2 authenticated finalize/abandon decisions with immutable outcomes,
  fully authenticated historical active evidence, rollback holds, and
  source-complete resume-only recovery. Certificate export and decisions require
  exact current inventory targets and canonical nonces. It performs no live
  operation; abandonment is not revocation.
- Added `platform-pki-ca-passphrase-verify` for lock-safe, secret-free
  point-in-time validation that an active encrypted CA key can be opened by a
  supplied passphrase and matches its active certificate.
- Extended strict host-local inventory with required target, validation-boundary
  digest, and rollback-hold fields. Managed entries reject those fields.
- Added `platform-pki-custody-report` with deterministic text and JSON reports
  for managed CA, leaf-key, export, backup, inventory, and legacy custody. The
  command detects structural findings without decrypting or parsing private
  keys and keeps unverifiable operational controls explicitly `unknown`.
- Schema-2 CSR trust rotation remains operationally prohibited while any
  request or candidate is pending. This release does not implement the required
  empty-pending-state rotation gate.

## v2.0.0 - 2026-08-04

- This release changes PKI initialization incompatibly. `platform-pki-init`
  creates only `inventory/services.yml.example`; install reviewed active
  inventory from the private repository with `platform-pki-inventory-install`.
- Existing 1.x singleton CA layouts must take a protected backup and run the
  explicit receipt-backed migration before normal CA or service operations.
  Migration preserves existing keys, certificates, and active issuer identity.
- All maintained behavior and integration tests now use pytest orchestration while preserving real Bash commands, external tools, PTYs, inherited descriptors, archive operations, and SSH subprocess boundaries. The canonical container check runs the full aggregate once.
- Added `platform-pki-inventory-install` for strict, atomic mode-600 installation from `../platform-private/pki/services.yml`, with `--private-repo` override and guarded source/destination handling.
- PKI inventory now has one strict whole-file schema and one-snapshot consumption across issuance, renewal, verification, expiry listing, certificate printing, and Ansible export.
- `platform-pki-init` now writes only `services.yml.example`, preserves active inventory even with `--force`, and no longer installs unused PKI environment or OpenSSL template files.
- Fresh PKI state now begins with immutable `g1` root and `g1-i1` intermediate generations, protected active/bootstrap manifests, recorded service issuers, and persistent lifecycle-first operation locks. Failed bootstrap IDs remain abandoned and retries allocate monotonically increasing IDs.
- Legacy PKI layouts now prepare missing private control directories before locking and receive explicit migration guidance from normal CA and service commands. Receipt-backed migration also safely prepares missing private generation destination parents absent from older initializers. Inventory installation, protected backup, and rollover status/migration remain available to complete the migration workflow.
- Added `platform-pki-ca-rollover migrate|prepare|recover|status` for verified, receipt-backed migration and immutable root or intermediate candidate preparation. Preparation preserves the active issuer; later activation and lifecycle operations remain deferred.
- PKI backups now reject incomplete or recovery-required state and publish a mode-600 receipt binding each archive to its identity, digest, layout, and public state.
- Migration and fresh bootstrap transactions now use fsynced identity-complete journals; `platform-pki-ca-rollover recover` resumes or rolls back every mutation and remains resumable if recovery itself is interrupted.
- Recovery now requires exact journaled identities for CA database files and their staged sources, configurations, reservations, issuer records, quarantine entries, backup sessions, active manifests, service snapshots, and digest-bound complete-tree manifests that omit private-content hashes. Phase 6A pre-journals sensitive child destinations, uses full nanosecond staged-source identities and immutable write-ahead transaction manifests, and binds final journal/marker unlink through terminal receipts. Rollover certificates require exact critical CA profiles and verified root self-signatures. Migration failures require explicit recovery, sensitive root-key staging is removed before intermediate commit, and verified bootstrap rollback permanently abandons rather than reuses its generation ID.
- Rollover preparation and recovery now remove superseded and final transaction-tree manifests by exact journaled identity, preventing stale control-state accumulation while preserving replacement objects on mismatch.
- Intermediate and service certificate publication now enforces actual ASN.1 validity against the issuer with a one-day default safety margin.
- Inventory publication prefers `RENAME_EXCHANGE` and supports a guarded rename fallback under cooperative same-UID locks, including rootless Podman filesystems.
- The development toolbox now uses a reproducible Debian 13 snapshot on `amd64` and `arm64`, with a locked Bashly bundle, pytest, and checksum-verified ShellCheck and shfmt binaries.
- Rollover activation, acknowledgement, lifecycle rollback, retirement, and
  completion remain unavailable in this release. Candidate preparation does not
  change the active issuer.

## v1.4.0 - 2026-07-27

- Generated help for all 16 Bashly-backed commands now uses restrained colors on interactive terminals while remaining plain for pipes, redirects, and `NO_COLOR=1`.
- Completed the Bashly migration for all 16 maintained shell commands and added one shared CLI contract for help, version, parser errors, and subcommand help.
- Aligned `platform-bastion-policy` help, version, parser-error status, and output streams with the shared command contract.
- `platform-bastion-policy` now rejects abbreviated long options consistently with the Bashly-backed commands.
- Added disposable installed-command smoke coverage for every maintained tool and installed PKI shared assets without runtime Ruby, Bashly, or checkout source paths.
- Added a pinned Podman development environment and Bashly generation workflow.
- Migrated `platform-pki-print-cert` to the shared Bashly CLI contract.
- Migrated `platform-pki-list-expiry` and made missing-certificate status 3 independent of inventory order.
- Migrated `platform-pki-service-verify` to generated parsing and validation.
- Migrated `platform-pki-init` with guarded paths and atomic template replacement.
- Migrated `platform-pki-backup` with generated repeatable recipient parsing.
- Migrated `platform-pki-export-ansible` with generated service selection.
- Migrated `platform-pki-root-create` with staged, guarded root CA replacement.
- Migrated `platform-pki-intermediate-create` with staged intermediate material, missing database initialization, root CA database updates, and ordered CA operation locks.
- Migrated `platform-pki-service-issue` with transactional service and intermediate CA publication, ordered operation locks, and rollback-safe verification.
- Migrated `platform-pki-service-renew` with transactional archival, service and intermediate CA replacement, ordered operation locks, and rollback-safe verification.
- Migrated `platform-proxmox-token-init` to generated parsing while preserving local and self-streamed SSH bootstrap behavior, conditional remote `jq`, and one-time token handling; absent token-file destinations use atomic no-clobber publication, while validated existing non-empty destinations require `--force`.
- Migrated `platform-proxmox-vm-cleanup` to generated parsing with strict SSH destinations, exact status parsing, repeated VM identity/config/status drift checks, capability-probed `qm` arguments, fixed-command SSH transport with bearer data on protected FD 3 instead of argv, bounded owner-only authorization persisted on the Proxmox host, and identity-checked cleanup of aged interrupted authorization artifacts; interactive cleanup refuses non-TTY or unavailable confirmation input unless `--yes` is supplied.
- Migrated `platform-proxmox-vm-snapshot` to generated create, list, rollback, and delete subcommands while preserving fake-backed local and self-streamed SSH safety checks; private expected-state manifests are atomically consumed and descriptor-validated through Linux procfs before use, and snapshot mutations refuse non-TTY confirmation unless `--yes` is supplied.
- Migrated and hardened `platform-ssh-init` with generated parsing, strict config loading, safe key and SSH-config path checks, no-clobber public-key reconstruction, key reuse, SSH config output, and controlled access testing.
- `platform-config-init` now provides generated, consistent help and repository version output through `--help` and `--version`.
- `platform-vm-env-collect` now uses the same generated help, version, and environment validation conventions.
- Added `platform-proxmox-vm-snapshot` for safe, short-lived Proxmox VE 9 development snapshot creation, listing, rollback, and deletion through local execution or SSH.
- Added a disposable-VM live-acceptance runbook for the snapshot helper.

## v1.3.0 - 2026-07-10

- Hardened `platform-vm-env-collect` to write reports and archives under a private random `/tmp` directory with owner-only permissions.
- Hardened `platform-bastion-policy` to create output files with owner-only permissions and refuse existing output paths.
- Hardened `platform-bastion-policy` Linux user and group validation to reject newline-suffixed identity names.
- Hardened PKI passphrase-file validation to reject empty, whitespace-only, or shorter-than-16-character first lines.
- Excluded in-tree PKI backup output directories from `platform-pki-backup` archives to prevent recursive backup growth.
- Hardened `platform-pki-export-ansible` to reject unsafe export paths, untrusted path ancestors, and destination symlinks.
- Hardened PKI service inventory validation to reject OpenSSL configuration expansion syntax in certificate names and SANs; `ips` inventory entries are now explicitly IPv4-only.
- Added `platform-bastion-policy` for validating and rendering Kubernetes bastion access-policy documents.
- Refined the README landing page with a branded header, clearer install notes, and license information.

## v1.2.0 - 2026-05-25

- Added non-interactive passphrase file support for encrypted root, intermediate, service issuance, and service renewal PKI operations.
- Added `AGENTS.md` with repository-specific workflow, verification, security, and release guidance for future agent sessions.
- Hardened PKI passphrase file handling by requiring readable owner-only files and rejecting conflicting unencrypted-key options.
- Documented passphrase-file automation examples and updated PKI secret handling guidance.

## v1.1.0 - 2026-05-24

- Reserved `~/.config/platform-infrastructure/pki/` as a top-level outside-Git namespace for PKI helper state.
- `platform-config-init` now creates `pki/` alongside `infra/` and `config/`.
- Added OpenSSL PKI helpers for initializing PKI state, creating root/intermediate CAs, issuing service certificates, verifying certificates, and listing expiry.
- Added PKI renewal, certificate detail printing, and Ansible export helpers.
- Added PKI backup support with encrypted `age` output by default and explicit plain-backup override.
- Added README requirements for core tools, PKI helpers, SSH/Proxmox helpers, and optional verification tools.
- Renamed `vm-env-collect` to `platform-vm-env-collect` for CLI naming consistency. This is a breaking command-name change.

## v1.0.0 - 2026-05-23

Initial public release of `platform-tools`.

Highlights:

- Shared operator helpers are now centralized in one repository: SSH identity setup, Rocky VM fact collection, local secret namespace initialization, Proxmox API token bootstrap, and safe single-VM cleanup.
- Local secrets now use the outside-Git namespace `~/.config/platform-infrastructure/` with major directories `infra/` and `config/`.
- The documented Proxmox token path is `~/.config/platform-infrastructure/infra/proxmox.token`.
- SSH config parsing, token output handling, file modes, and VM collector defaults were hardened for safer operator use.
- Downstream ownership of concrete config paths is documented in `docs/handoffs/config-namespace-handoff.md`.
