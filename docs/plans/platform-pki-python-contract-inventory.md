# Platform PKI Python Migration Contract Inventory

## Status

Completed runtime-migration contract. This inventory records the compatibility
surface preserved by the Python implementation. All maintained PKI routes and
current-release compatibility executable names are Python-backed. Exact managed
transaction recovery is exposed only through unified `service-recover`.
Retained Bash executables, libraries, and source fragments under
`tests/pki/oracles/` are immutable test evidence rather than runtime ownership.

## Runtime and Interfaces

- Minimum Python version: 3.14.
- Application artifact: deterministic standard-library zipapp.
- Existing `platform-pki-*` executable names remain supported during
  incremental migration. The approved next major release removes these
  compatibility launchers and installs only `platform-pki` after every unified
  route passes final acceptance.
- The new `platform-pki` CLI uses shallow command names.
- Existing nested subcommands and options remain unchanged beneath each shallow
  command.
- Python must recover supported interrupted transactions written by Bash.
- Package migration is forward-only after the first operational command cuts
  over; installing an older Bash implementation is unsupported.

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
| none | `platform-pki service-recover` | none |
| `platform-pki-service-verify` | `platform-pki service-verify` | none |
| `platform-pki-list-expiry` | `platform-pki list-expiry` | none |
| `platform-pki-print-cert` | `platform-pki print-cert` | none |
| `platform-pki-export-ansible` | `platform-pki export-ansible` | none |
| `platform-pki-backup` | `platform-pki backup` | none |
| `platform-pki-custody-report` | `platform-pki custody-report` | none |
| `platform-pki-ca-passphrase-verify` | `platform-pki ca-passphrase-verify` | none |
| `platform-pki-ca-rollover` | `platform-pki ca-rollover` | `migrate`, `status`, `prepare`, `recover` |

Managed service transaction recovery is exposed only as
`platform-pki service-recover --transaction`. It has no compatibility
executable. Host-local issue, migrate, and renew continue to recover through the
existing public `platform-pki csr-recover` route.

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
- Help is colored only on a TTY.
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
- `tests/pki/oracles/final-bash-source/bashly/platform-pki-*/src/bashly.yml`
- `tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh`

`tests/pki/test_migration_contract.py` separately normalizes the committed
`PKI_PARSER_ROUTES` inventory against the immutable final-Bash source evidence.
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
- Installed templates preserve checkout-relative,
  `PLATFORM_TOOLS_SHARE_DIR`, XDG data, and `/usr/local/share/platform-tools`
  lookup where currently supported.
- `PLATFORM_TOOLS_TEMPLATE_DIR` remains the explicit template override.
  `PLATFORM_TOOLS_LIB_DIR` is accepted only by frozen Bash test oracles, not by
  production Python commands.

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
| `service-recover` | transaction | exact confirmation or `--yes` | `test_service_recover.py` |
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

The compatibility and unified `service-issue` routes share one Python handler.
Its `issue_host_local_csr` path writes authenticated host-local `issue` and
`migrate` transactions using the same 114-field journal consumed by public
Python CSR recovery. It pins and repeatedly rechecks the exact installed trust
tree and authenticated sources, enforces exact inventory lifetime and SAN
profiles, reauthenticates the journal plus every active authority directory and
source immediately before CA publication, and derives rollback-versus-forward
recovery from the reloaded durable commit record. Its focused coverage is
`test_csr_issue_writer.py`; no managed service key or certificate publication is
part of this interface.

The retained init oracle is
`tests/pki/oracles/platform-pki-init/platform-pki-init` from commit
`ee03cddc626338ea7d066dd71519204bddb46db3`. Its SHA-256 is
`bebb970bea2fbd46ed807854e14680416f9cef6e0e2b63557a7675ecc1e28e9e`;
the required common library and `services.yml.example` oracle dependencies are
pinned by `tests/pki/test_init.py`.

The retained inventory-install oracle is
`tests/pki/oracles/platform-pki-inventory-install/platform-pki-inventory-install`
from commit `8c2e8e7ae46e9aedbda70a9035682aa9f1445dd1`. Its SHA-256 is
`9084754ca9a6906abdbd3b1f6cbe7230f17a55074dfd327a0403d8d7a9a77031`;
the required common-library SHA-256 is
`dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`.
`tests/pki/test_inventory_install.py` checks this provenance and compares the
oracle with both Python interfaces and descriptor-bound publication races.

The retained export-ansible oracle is
`tests/pki/oracles/platform-pki-export-ansible/platform-pki-export-ansible`
from commit `00c7cd55fa51ffc3e5911f0f3bcba1b76e7c5f6b`. Its SHA-256 is
`08ea4436e688569ed3a0794b2946ced76a8e69cca335b06cf3fcc4a5577c2599`;
the required common-library SHA-256 is
`dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f`.
Compatible Bash/Python differentials compare process observations and final
state. Python-only subprocess acceptance tests record the bounded safety
divergence: complete exports are atomically published rather than rebuilt in
place, failures before publication preserve the old identity tree and either
remove an exactly readiness-bound stage or report retained private evidence,
and failures after exchange retain the new export plus displaced directory
evidence without rollback. Custom replacement authorization keeps the accepted
marker descriptor, identity, and exact bytes pinned through the final exchange
boundary; displaced-tree cleanup rechecks every snapshotted name immediately
before its destructive mutation.

`tests/pki/migration_contract.py` freezes all 24 compatibility leaf routes, including
ordered positionals and long flags, required names, defaults, enum values,
conflicts, repeatable entries, and Bashly validators. Infrastructure tests load
all 18 final-Bash definitions from test-only evidence with PyYAML so aliases are
resolved and compare the complete normalized source shape with the committed inventory. Separate source-backed
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
- The frozen Bash versions loaded `lib/platform-pki-common.sh` only after parser
  dispatch. The Python handlers preserve the operational behavior without
  installing or loading that shell library; the exact historical library is
  retained under `tests/pki/oracles/final-bash-source/lib/`.

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
state/service/
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
| Root bootstrap journal | 3 | fixed | `src/platform_pki/root_create.py` and the frozen final-Bash oracle |
| Intermediate bootstrap journal | 3 | fixed prefix, database-key groups, `committed` | `src/platform_pki/intermediate_create.py` |
| CSR request | 1 | `PKI_CSR_REQUEST_FIELDS` | `platform-pki-csr-sign.sh` |
| CSR approval | 1 | `PKI_CSR_APPROVAL_FIELDS` | `platform-pki-csr-sign.sh` |
| CSR signing journal | 1 | 114 fixed writer-order fields | `src/platform_pki/csr_recovery.py`, checked against `PKI_CSR_JOURNAL_FIELDS` |
| CSR response | 1 | `CSR_RESPONSE_FIELDS` | `src/platform_pki/csr_protocol.py`, checked against the frozen candidate library |
| CSR candidate | 1 | `CSR_CANDIDATE_FIELDS` | `src/platform_pki/csr_protocol.py`, checked against the frozen candidate library |
| CSR replay request | 1 | 9 fixed fields | literal writer in `platform-pki-csr-sign.sh` |
| CSR replay nonce | 1 | 5 fixed fields | literal writer in `platform-pki-csr-sign.sh` |
| CSR signing terminal | 1 | 7 fixed fields | literal writer in `platform-pki-csr-sign.sh` |
| Export manifest | 1 | `CSR_ARTIFACT_FIELDS` | `src/platform_pki/certificate_export.py`, checked against the frozen certificate-export initializer |
| Deployment evidence | 1 | `CSR_DEPLOYMENT_FIELDS` | `src/platform_pki/csr_history.py`, checked against the frozen candidate library |
| Active candidate pointer | 1 | `CSR_ACTIVE_FIELDS` | `src/platform_pki/csr_history.py`, checked against the frozen candidate library |
| Candidate outcome | 1 | `CSR_DECISION_FIELDS` | `src/platform_pki/csr_history.py`, checked against the frozen candidate library |
| Candidate finalization journal | 1 | 82 fixed writer-order fields | `src/platform_pki/csr_recovery.py`, written by `src/platform_pki/csr_candidate.py` and recovered by `src/platform_pki/csr_recover.py`, checked against the frozen candidate library |
| Managed service transaction journal | 1 | 485 fixed writer-order fields | non-public `src/platform_pki/service_transaction.py` and operational `src/platform_pki/service_recover.py` |
| Managed service retained transaction | 1 | 13 fixed writer-order fields | non-public `src/platform_pki/service_transaction.py` |
| Managed service retained terminal | 1 | 10 fixed writer-order fields | non-public `src/platform_pki/service_transaction.py` |
| Managed service retained rollback completion | 1 | 9 fixed writer-order fields | non-public `src/platform_pki/service_transaction.py` |
| Legacy migration journal | 2 | initial writer order; recovery may use sorted order | rollover migrate/recover sources |
| Rollover preparation journal | 5 | C-locale key order | rollover prepare/recover sources |
| Rollover prepared-state manifest | 1 | canonical key order | rollover prepare source |

Python-owned CSR, candidate, and certificate-export records use the exact ordered
field tuples from `src/platform_pki/csr_protocol.py`,
`src/platform_pki/csr_history.py`, and `src/platform_pki/csr_recovery.py`.
Infrastructure tests compare those tuples with the frozen final candidate
library. Source-backed tests extract the literal and dynamically assembled
final-Bash writers and verify their schema values, field order, and exact final
newline behavior against the runtime models.

CA recovery field tuples are now authoritative in
`src/platform_pki/ca_rollover_recovery.py` and are re-exported by
`tests/pki/migration_contract.py`; source-extraction tests keep the runtime
models aligned with the frozen Bash writers. The typed recovery layer validates
schema-2/3 field sets and accepted ordering plus operation-specific paths,
generations, actions, committed state, persisted identities, and terminal
relationships. Schema 2 has 56-field writer and
sorted recovery forms plus a 58-field sorted checkpoint form. Schema 3 has the
exact 20-field root and 56-field intermediate writer/sorted forms. Schema 5 is
not one fixed 208-field record: the associative array starts with 206 declared
keys and successful `prepare_copy_file` calls can cumulatively add 13 identity
keys, for source-valid sorted variants up to 219 keys; the requested 208-key
shape is one intermediate successful-copy checkpoint, not the complete family.
Schema-5 typing now validates the complete declared field set, cumulative
runtime-copy shapes, manifest triples, exact path relationships, typed identity
sentinels, transaction-manifest rotation, and terminal marker/receipt bindings.
The Python recovery handler now binds those records to live filesystem state and
performs identity-checked recovery mutations for legacy migration, root and
intermediate bootstrap, rollover preparation, and receipt-bound terminal
cleanup. It accepts all supported final-Bash states and also resumes an
authenticated root-DB publication or restoration completed immediately before
its pending journal rewrite; final Bash rejects that narrow post-mutation
window. The final Bash executable remains the retained differential oracle;
direct and unified rollover invocations use the Python handlers. The
Python root writer preserves the fixed schema-3 writer order and exact
reservation/bootstrap encodings. It requires ASCII PKI paths so every persisted
path remains representable by the canonical recovery-record codec, and defers
handled signals only across mutation-to-evidence assignments. Final-Bash and
Python writer interruptions at every public root checkpoint are accepted by
unified Python recovery.

CSR recovery field tuples are now authoritative in
`src/platform_pki/csr_recovery.py` and are re-exported by the migration
contract inventory. Source extraction from the retained shell declarations
remains the independent oracle. The model parses the exact 114-field signing
journal and 82-field finalization journal, decodes every persisted identity
according to its writer, and validates scalar, digest, path, database, source,
and publication-phase relationships. Commit `5026f65` is the final-Bash/model
provenance baseline for the operational finalization tranche.

The public `src/platform_pki/csr_recover.py` layer binds both models to live
state for compatibility and unified dispatch. Finalization recovery performs bounded
mode-600 single-link no-follow journal access, holds lifecycle through export
locks, validates all 17 source files and retained transaction, trust, outcome,
and active evidence before mutation, and resumes only journal-authorized
publication and cleanup.

Signing recovery holds lifecycle through inventory locks, permanently adopts or
creates exact replay records, restores the seven CA database entries in reverse
order before commit, freshly reauthorizes rollback immediately before mutation
and evidence, and never rolls back or re-signs after commit. Complete branch
preflight rejects hostile key, terminal, source, and publication state before
branch mutation. Committed recovery authenticates the retained response trust
and signing sources, signs through an inherited response-key descriptor only
when needed, stages candidate and response trees before ordered no-clobber
publication, and freshly rechecks committed database and source state in each
publication authorization window. A durable `response-signing` checkpoint
owns the Python post-sign/pre-evidence mutation window: recovery adopts a
signature from that checkpoint only after authenticating its content, trust,
mode, identity, and complete committed sources. The compatible
`ca-committed` checkpoint never adopts an unowned signature and instead
removes and recreates one only when its file state is safe. Public
`csr-recover` selects the existing
journal without parsing it, obtains exact operator confirmation, acquires only
that protocol's lock profile, and rechecks the same selection under lock before
parsing or mutation. Ambiguous, missing, or changed selection fails closed
without switching protocols.

The signing model names its authority path `journal_intermediate_dir` because
it is derived from the journal, not discovered as the live active authority. A
caller may supply `active_intermediate_dir` to require an exact context match;
the model itself does not claim that an unbound journal path is active. The
pure signing model also enforces the exact durable checkpoint evidence matrix
for replay records, transaction and trust snapshots, signing artifacts,
sensitive-key removal, response signing, and artifact publication. It accepts
the prior persisted checkpoint across mutation-before-checkpoint windows and
the stage/destination identity rewrites that final Bash durably records before
advancing the checkpoint; it makes no claim about corresponding live objects.
The finalization model validates every source digest's canonical form and
derives every source path, but only the candidate, artifact, response, and
response signature fields have corresponding top-level evidence that can be
cross-checked for equality.

The pure host-local CSR protocol codecs validate canonical record structure,
record-only request/approval bindings, and canonical OpenSSL serials in response
and candidate records. Request and approval parsing and serialization each
independently enforce validity intervals of at most 604,800 and 86,400 seconds,
respectively; cross-record binding additionally requires approval creation no
earlier than request creation. A caller that has independently resolved the two
trusted signer keys can supply their equality to enforce the retained 86,400-
second sole-operator delay. The binding validators hash the canonical
newline-terminated request and response record bytes and require the approval's
`request_sha256` and candidate's `response_sha256` to match, respectively. The
codecs do not perform signature verification, resolve allowed signers, hash
external signature or artifact bytes, or apply current-time freshness; callers
must authenticate those live inputs, so the codecs do not claim complete
authenticated protocol validation.

The managed service transaction and non-public recovery foundation is
Python-only. It defines one
mode-600, current-user-owned, singly linked unresolved journal at
`state/service/recovery-journal` and one mode-700 retained transaction under
`state/service/transactions/service-<32-lower-hex-id>/`. The transaction binds
an immutable mode-600 transaction record by exact path, identity, and digest;
private `stage/`, `stage/inputs/`, and `backup/` trees are identity-bound and
removed exactly, while the retained transaction, rollback-completion when
applicable, and terminal evidence remain after journal cleanup. Canonical
retained-record file identities bind their exact serialized byte lengths as
well as their mode, owner, type, link count, and separately recorded digest.

The journal embeds its own stable file object state and exact canonical byte
length, not a timestamped full identity that writing the journal would
invalidate. The non-public live loader compares this state with the opened
journal descriptor before acting; atomic rewrites create and authenticate the
next self-sized object before publication.

The schema has a fixed 54-field transaction prefix, four fields for each of
seven directory mutations, 15 fields for each of 22 file mutations, three
displaced-source fields for each of eight possible archive files, and seven
source/stage fields for each of seven possible transaction inputs, for 485
fields total. Every enabled file mutation records its exact destination;
pre-identity and, when existing, pre-state digest; staged path, full identity,
object state, and digest; private backup path, full identity, object state, and
digest when replacement displaces an existing file; and publication and
rollback full identities with paired digests when those transitions have
completed. Directory mutations separately bind their destination and exact
pre, post, and rollback identities. Disabled mutations and inputs must be
entirely `none`. Typed GNU-stat identities enforce the journal owner, mode-700
private directories, mode-600 retained control files, regular files, and
single-link evidence without reading live state.

Each staged full identity equals its recorded object state. Each private backup
has a distinct filesystem object identity from the displaced file, preserves
its owner, mode, size, and modification time, equals its own recorded object
state, and has the same digest as the pre-state. Preauthorized-absent and
no-clobber destinations cannot claim pre-state digests or backup evidence. A
completed publication equals the staged object state and digest. A completed
rollback either restores exact absence or, for an existing destination, equals
the backup object state and the pre-state/backup digest while preserving the
displaced metadata.

Every enabled displaced-state archive file additionally records its canonical
service source path, exact source identity, and source digest. That source
identity and digest equal the corresponding service mutation's displaced
pre-state, and the source digest equals the generic staged digest. The staged
copy must use a distinct object identity while preserving source owner, mode,
size, and modification time. The renewal marker has no displaced source and
instead binds the canonical empty-file staged digest. An existing archive root
binds its full original identity and metadata to a private mode-600 empty
timestamp reference; if archive-directory publication changed that container,
failed pre-commit recovery must record an exact same-directory and
restored-modification-time identity after reverse publication rollback and
before cleanup-only state.

The transaction privately stages up to seven writer-derived inputs: the exact
inventory bytes, root certificate, intermediate key, intermediate certificate,
processed intermediate configuration, CRL number, and, only for key reuse, the
current service key. Source and staged identities are distinct and every pair
has exact digests. Exact copies preserve source bytes and applicable metadata;
the inventory and reused key are normalized to mode 600, and the processed CA
configuration is mode 600. The current CA index, index attributes, and serial
are already bound as mutable pre-state rather than duplicated as input fields.
The journal and retained transaction accept only uppercase, even-length
OpenSSL serials with no removable leading `00` pair, and bind the same serial to
the exact `newcerts/<serial>.pem` destination. Retained CSR signing recovery
applies the same canonicality rule to its journal-derived new-certificate path.
The deterministic service issuer file additionally binds exact
`root=<generation>\nintermediate=<generation>\n` bytes to the claimed issuer
IDs. Operational code must still regenerate and validate the processed
configuration and cryptographically validate CSR, certificate, chain, and full
chain bytes; this pure parser does not claim those live checks.

The writer-derived mutation audit is complete for the retained managed paths:

| Retained writer action | Future transaction evidence |
| --- | --- |
| Create or remove the service root, private, CSR, certificate, and chain directories | Five ordered directory mutations with exact absence/existing, post, and reverse-rollback identities |
| Replace or no-clobber-publish six service files and seven CA database files | The fixed 13-file service/CA prefix with complete pre/stage/backup/post/rollback chains |
| Create or replace the managed service key | Conditional `service_key` mutation bound to the current key identity and digest |
| Create/remove archive root and timestamp directory; publish/remove marker and up to seven archived files | Two directory mutations, eight file mutations, displaced-source bindings, and exact archive-root timestamp restoration |
| Copy inventory, authority, and reused-key inputs into private staging | Seven conditional transaction-input groups under the exact mode-700 `stage/inputs/` container |
| Create private backups and restore or remove destinations | One backup chain per existing destination and exact reverse-only rollback evidence |
| Remove the renewal marker, stage tree, and backup tree; publish the terminal and remove the unresolved journal | Exact ordered cleanup pending/done matrix; retained transaction and terminal remain |

The retained Bash `/tmp` inventory directory, its derived DNS/IP/canonical
scratch files, and its intermediate OpenSSL work directories are not persisted
operational destinations and are never recovery evidence. The forward-only
Python contract instead retains one authenticated raw inventory input under its
private transaction tree and uses the fixed private stage hierarchy above.
Shared lock/control files and passphrase inputs are likewise outside the
transaction mutation inventory: locks are persistent shared infrastructure,
while passphrases are descriptor-bound read-only inputs that must never be
persisted.

The planned managed order is the retained 13-file service/CA prefix, optional
key publication, then any absent archive root, archive directory, marker, and
ordered archive members. Issue permits key reuse, creation, or rotation and
archives only the displaced key when rotating. Renewal permits reuse or
rotation, always has an archive marker, and records exactly the ordered subset
whose certificate, CSR, chain, full chain, configuration, and issuer sources
were present, plus the displaced key only for rotation. Each archive source
identity equals the corresponding service mutation pre-state. The model also
derives the retained issue/renew replace-versus-no-clobber policy for every
destination. Rollback restores ordinary published files in reverse order,
followed by archive containers and then created service containers in reverse
order. When an existing archive root requires timestamp restoration, recovery
does so immediately after rolling back `archive_dir` and before any created
service container.

`staging`, `backing-up`, `planned`, `publishing`, and `verifying` phases are
rollback-authorized and uncommitted. Staging and backup counts admit only their
exact completed evidence prefixes, and backup or publication progress cannot
precede complete earlier preparation. Each publication has durable
`publication-pending` authorization before mutation and `publication-done`
full-identity and digest evidence afterward. Before the commit record, recovery
may only restore the exact reverse prefix with paired rollback identity/digest
evidence for restored files and absence evidence for newly created
destinations. Every successful committed, cleanup, and terminal state retains
the complete staging, private-backup, and publication prefixes. After full
rollback and required archive-container restoration, recovery publishes a
canonical retained `rollback-complete` record that binds the transaction, full
reverse sequence, count, exact restoration inputs, and archive-root restoration
state and identity. Only its identity and canonical digest authorize clearing
the detailed rollback evidence and entering failed cleanup.
`committed`, `cleaning-up`, and `terminal` are cleanup-only: they cannot encode
rollback, and renewal marker removal, stage cleanup, backup cleanup, terminal
publication, and unresolved-journal cleanup have an exact pending/done matrix.
The pure transaction model performs no live reads, publication, signing,
rollback, cleanup, or dispatch. The separate non-public recovery engine performs
bounded live preflight, reverse-only rollback, rollback-completion and terminal
publication, cleanup, and exact journal removal. Immediately before removal it
reauthenticates the journal-bound retained transaction, terminal, and applicable
rollback completion. The terminal preserves the exact transaction identity and
digest and, for failed pre-commit recovery, the exact rollback-completion
identity and digest so journal-absent retries authenticate the same evidence;
successful terminals explicitly exclude rollback-completion evidence. It does
Final unlink authorization also rechecks the complete model-owned cleanup
absence set after retained-evidence authentication: exact transaction `stage`
and `backup` names for every outcome, and the exact archive marker derived from
the retained service/archive binding only for successful renewal. Journal-absent
retries derive and enforce the same applicable set without current/latest or
live deployment inference. Reappearance of any object type fails closed and is
left untouched. It does not sign, perform
forward service publication, or provide parser/CLI dispatch.

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
- Python recovery terminalizes uncommitted requests after exact
  reverse-order CA rollback and resumes committed response publication without
  invoking CA signing again. The isolated subprocess suite covers every
  final-Bash phase, Python recovery checkpoints, rollback and publication pause
  races, hostile branch state, inherited response-key descriptors, and
  field-aware Bash/Python terminal-state differentials.
- Compatibility and unified routes dispatch the same Python handler.

### Candidate finalization

- Recovery is resume-only and source-complete.
- Python writer ownership covers the pre-journal `outcome-staged` and
  `active-staged` checkpoints. The retained `journal-written`,
  `outcome-published`, and `active-published` phases preserve final-Bash
  compatibility, while the recovery suite directly parameterizes the complete
  `CSR_FINALIZATION_RECOVERY_CHECKPOINTS` domain.
- Every journal-bound source identity and digest is revalidated.
- Python recovery performs live validation, durable publication,
  and identity-bound cleanup for candidate finalization. Final-Bash and
  Python recovery states are differentially tested for all three phases in both
  active create and exchange modes.
- Public dispatch rechecks the selected journal kind after operator confirmation
  and while holding the required locks. If signing/finalization journal presence
  differs from the confirmed kind, recovery fails closed without switching
   protocols or mutating state.

### Managed service issue and renew

- Journal schema 1, operations `service-issue` and `service-renew`.
- The unresolved journal is `state/service/recovery-journal`; retained private
  evidence is under `state/service/transactions/`.
- The recovery interface is unified-only
  `platform-pki service-recover --transaction` and requires exact confirmation
  or `--yes`.
- Recovery holds lifecycle, root, intermediate, and inventory locks.
- Uncommitted recovery rolls back only the exact published prefix in reverse.
- The durable commit boundary permanently changes recovery to cleanup-only.
- Operational recovery authenticates the exact journal, retained
  transaction, authority and inventory inputs, destination prefix, private
  stage/backup prefixes, archive sources, and retained outcomes before mutation.
- Self-sized journal rewrites authenticate resumable publication, rollback, and
  archive-root relocation windows. Destructive cleanup or retained-record
  publication observed without journal-authenticated resulting identity fails
  closed and retains the journal rather than adopting same-name bytes or
  absence.
- Isolated subprocess tests cover every incomplete stage and backup prefix,
  every publication mutation window, issue/renew key and archive variants,
  pre/post-commit interruption, all declared recovery checkpoint applicability,
  mutation-boundary hostile replacement, secret-safe diagnostics, and the
  complete lifecycle-through-inventory lock profile.
- Writer infrastructure atomically publishes self-sized parser-valid
  journals, records exact stage/backup/publication prefixes, defers handled
  signals only across journal or object mutation-to-evidence assignments,
  applies transaction-wide authenticated preflight and authenticated pre-state
  replace/no-clobber policy, publishes created directories from exact empty
  private stages whose identities are journaled before atomic rename, and
  returns a committed journal accepted by shared cleanup-only recovery. Shared
  recovery reconciles the exact staged or published inode and never adopts an
  unbound same-mode destination. Writer and recovery carry that authenticated
  directory identity, or the authenticated full file identity, through a final
  destination recheck at the journal replacement boundary and serialize only
  the carried identity. The writer does not invoke or hand off to recovery.
- Managed issue/renew orchestration snapshots one authenticated inventory
  and active issuer, validates managed custody and generation paths, plans the
  complete issue transaction, copies fixed private signing inputs, invokes real
  OpenSSL with passphrases available only through inherited descriptors, stages
  generated output and exact CA database state, publishes through the writer,
  verifies the live certificate, and crosses the durable cleanup-only commit
  boundary before handing the exact transaction to shared recovery. Handled
  pre-commit failures roll back through that same recovery implementation.
  Hard crashes after an unrecorded stage or backup mutation deliberately retain
  the journal because recovery cannot authenticate the resulting object.
- Before creating the transaction tree, issue publishes one canonical mode-600
  bootstrap reservation under `state/service/`. Bootstrap-only recovery removes
  only its exact constrained partial tree and atomically moves the reservation
  to immutable `bootstrap-history/<transaction>` evidence; journal handoff uses
  the same history transition. Recovery retries authenticate that exact record.
- Operational rollover history is accepted only through the authoritative CA
  recovery semantic parser in an exact terminal bootstrap or migration state.
  Issue rechecks the active-issuer identity before signing, publication, and
  verification, and verifies the published certificate's exact subject,
  issuer, serial, P-384 key, SHA-384 signature, extension set and criticality,
  SAN set, key identifiers, and planned validity duration.
- Managed and host-local renew dispatch publicly through the shared Python
  whole-command handler. Whole-command differentials remain pinned to the
  frozen final-Bash executable and loaded libraries; managed recovery is
  unified-only and host-local recovery remains under `csr-recover`.
- Host-local renewal treats outcome-path presence as untrusted: only a strict
  finalized outcome in the authenticated current chain or an exact abandoned
  outcome whose resulting predecessor belongs to that chain can suppress a
  pending-candidate conflict. Before replay reservation it enumerates the exact
  namespace-wide retained candidate and outcome coordinates in bounded sorted
  service/request order, resolves every service through current inventory, and
  rejects every pending candidate regardless of predecessor plus orphan,
  malformed, unsafe, ambiguous, or active-history-conflicting outcomes. Every
  terminal must resolve to a non-`none` request in the current authenticated
  chain, so abandoned issue and migration outcomes cannot satisfy renewal
  admission. All terminal sources survive a final identity and content recheck
  before journal creation and every CA publication boundary.
- Historical signer trust has one explicit external root: the exact installed
  schema-2 five-file tree under `inventory/csr-trust`. Historical request and
  approval signatures verify directly against its requester and approver files;
  retained response and deployer signer files must byte-match their installed
  counterparts before response or deployment signature verification. The
  installed policy pins the approval and response principals, and the complete
  trust tree participates in the returned final source recheck.
- Host-local service operations do not use this journal or recovery route.

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

## Forward-Only Package Migration

Cross-version recovery and package rollback are deliberately asymmetric:

- Python must recover every supported interrupted transaction written by the
  final Bash implementation.
- Each supported Python release must recover transactions written by itself and
  by the preceding supported Python release.
- Installing or running an older Bash implementation after cutover is
  unsupported; it is not guaranteed to recover or interpret Python-written
  transaction state.
- In particular, retained Bash service issue/renew and `csr-recover` do not
  recognize the managed schema-1 service journal. A package downgrade after a
  managed Python writer starts a transaction is unsupported.
- After the first operational compatibility command cuts over to Python,
  replacing the installed release with an older Bash implementation is outside
  the supported operating model, even when no journal appears unresolved.

The migration therefore has no clean-downgrade eligibility state, downgrade
receipt, package-replacement handoff, or planned `platform-pki doctor` route.
Exact byte compatibility remains required where this inventory says so for
incremental cutover, mixed-command operation within one release, Bash-to-Python
recovery, and differential testing. It does not imply Python-to-Bash package
rollback support.

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

- Remove the Python compatibility zipapps at the approved next major-release
  boundary; the current release installs one deterministic zipapp under every
  supported compatibility name.
- Extend output/status, runtime-boundary, and installed-asset contracts from the
  three pilot commands to the remaining PKI routes. This is a machine-readable
  post-release documentation expansion, not a v2.3.0 release blocker; focused
  runtime tests already cover every route.
