# Platform PKI Python Migration Contract Inventory

## Status

Phase 0 baseline. This inventory records the compatibility surface that the
Python migration must preserve. Maintained Bash source and existing tests remain
the authoritative oracle until each command is cut over.

## Runtime and Interfaces

- Minimum Python version: 3.12.
- Application artifact: deterministic standard-library zipapp.
- Existing `platform-pki-*` executable names remain supported.
- The new `platform-pki` CLI uses shallow command names.
- Existing nested subcommands and options remain unchanged beneath each shallow
  command.
- Python must recover supported interrupted transactions written by Bash.
- Downgrade to Bash requires an implementation-independent clean-state check.

## Command Mapping

| Compatibility executable | Unified route | Nested commands |
| --- | --- | --- |
| `platform-pki-init` | `platform-pki init` | none |
| `platform-pki-inventory-install` | `platform-pki inventory-install` | none |
| `platform-pki-csr-trust-install` | `platform-pki csr-trust-install` | none |
| `platform-pki-csr-recover` | `platform-pki csr-recover` | none |
| `platform-pki-certificate-export` | `platform-pki certificate-export` | `publish`, `resolve` |
| `platform-pki-csr-candidate` | `platform-pki csr-candidate` | `verify`, `finalize`, `abandon` |
| `platform-pki-root-create` | `platform-pki root-create` | none |
| `platform-pki-intermediate-create` | `platform-pki intermediate-create` | none |
| `platform-pki-service-issue` | `platform-pki service-issue` | none |
| `platform-pki-service-renew` | `platform-pki service-renew` | none |
| `platform-pki-service-verify` | `platform-pki service-verify` | none |
| `platform-pki-list-expiry` | `platform-pki list-expiry` | none |
| `platform-pki-print-cert` | `platform-pki print-cert` | none |
| `platform-pki-export-ansible` | `platform-pki export-ansible` | none |
| `platform-pki-backup` | `platform-pki backup` | none |
| `platform-pki-custody-report` | `platform-pki custody-report` | none |
| `platform-pki-ca-passphrase-verify` | `platform-pki ca-passphrase-verify` | none |
| `platform-pki-ca-rollover` | `platform-pki ca-rollover` | `migrate`, `status`, `prepare`, `recover` |

## Shared Parser Contract

- Root help uses `--help` and `-h`.
- Root version uses `--version` and `-v`.
- Leading root help or version takes precedence over later invalid arguments.
- Help and version return status 0, write stdout, and leave stderr empty.
- Version output is exactly `<invoked-name> <VERSION>\n`.
- Parser errors return status 1, leave stdout empty, and write stderr.
- Long-option abbreviations are rejected.
- Nonempty `--option=value` is accepted where the option accepts a value.
- Empty equals-form values are rejected.
- Help, version, and parser failures create no state.
- Generated help is colored only on a TTY.
- Any nonempty `NO_COLOR` suppresses help color.
- Application log messages remain uncolored.
- Duplicate-option behavior is command- and option-specific; Python must follow
  the existing explicit rejection lists rather than applying one global rule.
- Every retained leaf route accepts leading long and short help without state,
  rejects non-leading help after a previously parsed option, rejects empty
  equals values and long option abbreviations before help, rejects an unknown
  option before help, and gives leading help precedence over a later unknown
  option.

Authoritative evidence:

- `tests/test_command_contract.py`
- `tests/pki/test_ca_rollover_parser.py`
- `bashly/platform-pki-*/src/bashly.yml`
- `lib/platform-pki-common.sh`

`tests/pki/test_migration_contract.py` separately normalizes the committed
`PKI_PARSER_ROUTES` inventory against all Bashly sources.
`tests/test_command_contract.py` then drives parser-edge probes through all 24
retained routes, combining existing root-command checks with nested-leaf checks.
The clean environment fixture rejects state creation under `HOME`,
`XDG_CONFIG_HOME`, and `XDG_DATA_HOME`; probes supplying an explicit namespace
also require that path to remain absent.

## Shared Path and Validation Contract

- Namespace defaults to
  `${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure`.
- PKI directory defaults to `<namespace>/pki`.
- `~` and `~/...` expand using `HOME`.
- Service names match `[A-Za-z0-9][A-Za-z0-9_.-]*`.
- Day values contain decimal digits and have an allowed range of 1 through
  365000; leading zeroes remain accepted.
- Installed shared assets preserve checkout-relative,
  `PLATFORM_TOOLS_SHARE_DIR`, XDG data, and `/usr/local/share/platform-tools`
  lookup where currently supported.
- `PLATFORM_TOOLS_LIB_DIR` and `PLATFORM_TOOLS_TEMPLATE_DIR` remain migration
  compatibility inputs until their consumers are retired.

## Command Surface

| Command | Required command-specific inputs | Defaults and result contract | Focused tests |
| --- | --- | --- | --- |
| `init` | none | `--force` refreshes only the example inventory | `test_init.py` |
| `inventory-install` | none | private repo `../platform-private` | `test_inventory_install.py`, inventory contract modules |
| `csr-trust-install` | none | private repo `../platform-private` | `test_csr_trust_install.py` |
| `csr-recover` | recovery-dependent transaction/key inputs | `--yes`; dispatches signing or finalization recovery | CSR signing and candidate modules |
| `certificate-export publish` | service, request ID | immutable six-file artifact publication | `test_certificate_export.py` |
| `certificate-export resolve` | service, request ID, manifest digest | format `path`; exact digest-pinned resolution | `test_certificate_export.py` |
| `csr-candidate verify` | service, request ID | format `text` | `test_csr_candidate.py` |
| `csr-candidate finalize` | service, request ID, artifact digest, evidence and signature | optional `--yes` | `test_csr_candidate.py` |
| `csr-candidate abandon` | service, request ID, artifact digest, evidence and signature | optional `--yes` | `test_csr_candidate.py` |
| `root-create` | name, organization, country | 3650 days; encrypted key unless explicitly allowed | `test_root_create.py` and shared pass/legacy tests |
| `intermediate-create` | name, organization, country | 1825 days; one-day issuer margin | `test_intermediate_create.py` and shared pass/legacy tests |
| `service-issue` | service | inventory days, environment days, then 397 | `test_service_issue.py`, `test_csr_signing.py` |
| `service-renew` | service | inventory days, environment days, then 397 | `test_service_renew.py`, `test_csr_signing.py` |
| `service-verify` | service | minimum 30 days | `test_service_verify.py` |
| `list-expiry` | none | warning 90, critical 30; statuses 0/1/2/3 | `test_list_expiry.py` |
| `print-cert` | service | certificate text on stdout | `test_print_cert.py` |
| `export-ansible` | optional service list | all managed services; export under PKI tree | `test_export_ansible_safe_paths.py` |
| `backup` | none | encrypted by default; plain requires explicit opt-in | backup modules |
| `custody-report` | none | format `text`; statuses 0/1/2 | `test_custody_report.py` |
| `ca-passphrase-verify` | at least one passphrase file | descriptor-only point-in-time check | `test_ca_passphrase_verify.py` |
| `ca-rollover migrate` | backup receipt | private repo `../platform-private` | rollover migration and parser modules |
| `ca-rollover status` | none | format `text` | rollover status and parser modules |
| `ca-rollover prepare` | type, backup receipt, intermediate name, organization, country | root/intermediate defaults 3650/1825 | rollover prepare, fault, lifecycle, recovery modules |
| `ca-rollover recover` | transaction and resume/rollback action | optional `--yes` | rollover recovery modules |

`tests/pki/migration_contract.py` now freezes all 24 leaf routes, including
ordered positionals and long flags, required names, defaults, enum values,
conflicts, repeatable entries, and Bashly validators. Infrastructure tests load
all 18 definitions with PyYAML so aliases are resolved and compare the complete
normalized source shape with the committed inventory. Separate source-backed
inventories record runtime-only conditional requirements, conflicts, explicit
empty-value rejection, confirmations, and exact duplicate-option rejection
fields.

## Pilot Output, Status, Dependency, and Asset Contracts

The first migration tranche has machine-readable contracts for
`print-cert`, `list-expiry`, and `service-verify`:

- `print-cert` owns the leading `Service:` line and ordering of its OpenSSL
  invocations; the remaining detail lines are OpenSSL-owned output. Missing
  optional extensions do not fail the command and may leave OpenSSL-owned
  diagnostics on stderr.
- `list-expiry` owns a fixed-width ordered table and semantic statuses 0 for
  OK, 1 for warning, 2 for critical, and 3 for any missing certificate. Missing
  status dominates independently of inventory order.
- `service-verify` emits one exact success line only after all checks pass.
  Application validation failures return 1 with empty stdout and end with a
  newline-terminated application error, but may first preserve OpenSSL-owned
  diagnostics. The direct trust check emits only OpenSSL-owned stderr.
- All three require OpenSSL and nonblocking `flock` behavior during operational
  execution. The pilot inventory additionally records GNU `date -d` for expiry
  conversion and `cmp`/`grep` behavior for managed certificate verification.
- All three load `lib/platform-pki-common.sh` only after parser dispatch. The
  installed asset is a regular mode-644 file resolved through
  `PLATFORM_TOOLS_LIB_DIR`, checkout-relative `../lib`, then
  `PLATFORM_TOOLS_SHARE_DIR` or the XDG/default user share.

Infrastructure tests prove that every pilot contract references a retained
route, authoritative source fragment, and maintained focused test function.
The runtime dependencies listed here are migration-sensitive external
boundaries, not yet an exhaustive inventory of every core utility used by the
shared shell implementation.

## External Runtime Boundaries

The initial Python implementation retains explicit argv-only subprocess calls
for:

- OpenSSL certificate, key, CSR, and CA database operations.
- OpenSSH `ssh-keygen` trust-key validation and signatures.
- `age` backup encryption.
- `tar` archive creation and exclusions.
- GNU `mv` operations whose exchange/no-copy/no-clobber semantics do not have a
  proven Python equivalent.
- util-linux `flock` unless an `fcntl.flock` implementation proves identical
  lock-file and contention behavior.

The implementation also retains Linux procfs requirements where descriptor
identity or escaped-process supervision depends on `/proc`.

## Lock Contract

Lock paths are persistent files under `<pki-dir>/locks/`:

```text
lifecycle
root
intermediate
inventory
export
```

Acquisition order is always:

```text
lifecycle -> root -> intermediate -> inventory -> export
```

Release order is the reverse. Lock files are non-symlink regular files, mode
600, current-user-owned, singly linked, identity-checked through an opened
descriptor, and acquired nonblocking.

| Command or path | Effective locks |
| --- | --- |
| `init` | none |
| `root-create` | lifecycle, root |
| `intermediate-create`, `ca-passphrase-verify` | lifecycle, root, intermediate |
| inventory, trust, issue, renew, verify, expiry, print, signing recovery | lifecycle, root, intermediate, inventory |
| exports, candidate actions, finalization recovery, backup, custody, rollover | lifecycle, root, intermediate, inventory, export |

## Persisted Layout

The generation layout contains:

```text
inventory/
authorities/roots/<generation>/
authorities/intermediates/<generation>/
state/active-issuer
state/bootstrap-root
state/generation-reservations/
state/csr/
state/rollover/
state/rollovers/
locks/
services/<service>/
export/ansible/
export/certificates/v1/artifacts/
backups/
```

OpenSSL CA database files and sidecars, including `.old` files and
`newcerts/<serial>.pem`, are active persisted state. They must not be normalized
or regenerated during migration.

## Record and Journal Inventory

| Record family | Schema | Ordering | Authoritative definition |
| --- | --- | --- | --- |
| Active/service issuer pair | implicit | `root`, `intermediate` | `pki_load_active_issuer_snapshot`, `pki_load_service_issuer_snapshot` |
| Generation reservation | current shell format | exact record bytes | generation reservation helpers in `platform-pki-common.sh` |
| Backup receipt | 2 | 14 fixed fields | `platform-pki-backup/src/root_command.sh` |
| Root bootstrap journal | 3 | fixed | `platform-pki-root-create/src/root_command.sh` |
| Intermediate bootstrap journal | 3 | fixed prefix, database-key groups, `committed` | `platform-pki-intermediate-create/src/root_command.sh` |
| CSR request | 1 | `PKI_CSR_REQUEST_FIELDS` | `platform-pki-csr-sign.sh` |
| CSR approval | 1 | `PKI_CSR_APPROVAL_FIELDS` | `platform-pki-csr-sign.sh` |
| CSR signing journal | 1 | `PKI_CSR_JOURNAL_FIELDS` | `platform-pki-csr-sign.sh` |
| CSR response | 1 | `PKI_CANDIDATE_RESPONSE_FIELDS` | `platform-pki-csr-candidate.sh` |
| CSR candidate | 1 | `PKI_CANDIDATE_RECORD_FIELDS` | `platform-pki-csr-candidate.sh` |
| Export manifest | 1 | `PKI_CERTIFICATE_EXPORT_ARTIFACT_FIELDS` | certificate-export initializer |
| Deployment evidence | 1 | `PKI_CANDIDATE_DEPLOYMENT_FIELDS` | `platform-pki-csr-candidate.sh` |
| Active candidate pointer | 1 | `PKI_CANDIDATE_ACTIVE_FIELDS` | `platform-pki-csr-candidate.sh` |
| Candidate outcome | 1 | `PKI_CANDIDATE_DECISION_FIELDS` | `platform-pki-csr-candidate.sh` |
| Candidate finalization journal | 1 | `PKI_CANDIDATE_JOURNAL_FIELDS` | `platform-pki-csr-candidate.sh` |
| Legacy migration journal | 2 | initial writer order; recovery may use sorted order | rollover migrate/recover sources |
| Rollover preparation journal | 5 | C-locale key order | rollover prepare/recover sources |
| Rollover prepared-state manifest | 1 | canonical key order | rollover prepare source |

Array-defined CSR, candidate, and certificate-export records have exact ordered
field tuples in `tests/pki/migration_contract.py`; infrastructure tests compare
those tuples with the authoritative shell declarations and verify the duplicate
export/candidate declarations remain equal. Exact executable extraction of the
remaining literal and dynamically assembled writers, including schema values
and final-newline behavior, remains a Phase 0 item.

For initial migration, the following remain byte-identical:

- Inventory canonical output.
- Signed request, approval, response, deployment, and decision records.
- Trust policy and allowed-signers files.
- Candidate, export, pointer, receipt, reservation, and journal records.
- Recovery markers, terminal receipts, and tree/provenance manifests.
- OpenSSL configuration, databases, certificates, CSRs, chains, and signatures.
- Replay records, retained response trust, exports, outcomes, and migration
  ledgers.

## Recovery Contracts

### Root bootstrap

- Journal schema 3, operation `root-bootstrap`.
- Recovery is identity-bound rollback until terminal completion.
- Generation reservations are consumed or abandoned and never reused.

### Intermediate bootstrap

- Journal schema 3, operation `intermediate-bootstrap`.
- Recovery restores the exact root CA database and publication state.
- Only explicitly terminal sensitive-stage cleanup is resumable.

### CSR signing

- Journal schema 1, operation `csr-sign`.
- Pre-commit recovery restores exact CA state without reusing the request.
- Post-commit recovery never rolls back or re-signs and resumes exact response
  publication.
- Bash-written journals must be recoverable by Python.

### Candidate finalization

- Recovery is resume-only and source-complete.
- Tested crash checkpoints are `journal-written`, `outcome-published`, and
  `active-published`.
- Every journal-bound source identity and digest is revalidated.

### Legacy migration

- Journal schema 2, operation `legacy-migrate`.
- Resume and rollback validate every affected state category before mutation.
- Python must accept both the initial writer order and the final Bash recovery
  representation.

### Rollover preparation

- Journal schema 5, operation `rollover-prepare`.
- Journals use C-locale lexicographic key ordering.
- Sequence-numbered immutable tree manifests protect destructive cleanup.
- Terminal cleanup binds committed journal state, recovery marker, terminal
  receipt, staging manifests, and identity-checked unlink.

The migration contract also freezes every literal writer and recovery fault
hook for these transaction families, finite key/kind/label/quarantine domains,
fault environment variables, commit-boundary category, and allowed recovery
actions. Service-specific migration issuer-ledger checkpoint templates are
source-backed but intentionally marked runtime-derived because inventory service
names do not form a global finite domain. Source-only generic recovery points
are retained even when the focused pytest suites exercise only a subset.

## Differential Comparison Contract

Each Bash/Python comparison uses two private metadata-preserving copies of one
clean seed and separate HOME, XDG, and temporary directories.

The copier must rebase only validated OpenSSL `dir = ...` assignments under
managed root/intermediate configurations. It must not blanket-replace paths in
signed records, manifests, policies, or journals.

Compare:

- Exact status.
- Exact stdout and stderr after narrowly declared path, transaction, timestamp,
  and random-artifact normalization.
- Relative path set, file type, mode, owner class, group class, link count,
  size, and content semantics.
- Created, deleted, retained, and replaced object transitions.
- Hard-link relationships represented by stable relative-path groups.
- Canonical record order, field count, values, and final newline.

Do not compare raw device, inode, mtime, or ctime values across copied trees.
Use raw identities only inside one workspace to prove alias relationships and
replacement behavior.

Post-crash recovery must run on the exact crashed filesystem. Never copy an
interrupted tree before recovery because journals contain object identities.

`tests/pki/migration_harness.py` provides the common differential executor. It
builds sibling private copies, supplies separate `HOME`, XDG, and temporary
directories, runs both entry points as real subprocesses, and compares
normalized status/output, semantic before/after trees, and within-copy identity
transitions. Output normalization is opt-in and command-specific; the harness
does not broadly rewrite paths, timestamps, transaction IDs, or random values.

Required recovery matrix:

| Writer | Recovery | Requirement |
| --- | --- | --- |
| Bash | Bash | control |
| Bash | Python | required compatibility |
| Python | Python | required |
| Python | Bash | deliberately unsupported |

## Clean-Downgrade Contract

`platform-pki doctor --require-clean-downgrade` is a read-only point-in-time
assessment, not a durable authorization receipt.

The gate must:

- Create no state.
- Fail closed on contention, unsafe paths, malformed state, or unknown schemas.
- Acquire every required pre-existing lock in standard order and release in
  reverse order.
- Reject unresolved CSR signing or finalization journals.
- Reject rollover recovery markers and nonterminal rollover journals.
- Reject active prepared rollover state for the initial policy.
- Reject legacy, mixed, incomplete, or ambiguous authority layouts.
- Reject unexplained transaction or staging objects.
- Allow validated terminal history, consumed/abandoned reservations, and
  supported committed bootstrap or migration evidence.

Downgrade operations must quiesce PKI automation so no lifecycle operation can
start between the assessment and package replacement.

## Verification Index

Every command cutover runs:

```text
make verify
make test-command-contract
make test-installed-tools
the command's focused Make target
the command's Bash/Python differential cases
```

Transaction cutovers additionally run all declared Bash-to-Python and
Python-to-Python crash checkpoints. Rollover differential recovery remains out
of the ordinary non-rollover Make pool.

## Open Items

- Determine which target hosts require Python 3.12 provisioning.
- Define the exact installation representation for compatibility aliases to the
  zipapp.
- Record each command's exact final-Bash commit immediately before cutover and
  add its command-specific differential cases.
- Freeze exact ordered fields, schema values, and final-newline behavior for the
  remaining literal and dynamically assembled persisted-record writers.
- Extend output/status, runtime-boundary, and installed-asset contracts from the
  three pilot commands to the remaining PKI routes.
