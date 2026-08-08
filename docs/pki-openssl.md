# OpenSSL PKI Helpers

The `platform-pki-*` commands manage a small internal OpenSSL PKI for platform TLS certificates.

Generated CA keys, service keys, CSRs, issued certificates, CA database files, exports, and backups live outside Git under:

```text
~/.config/platform-infrastructure/pki/
```

## Responsibility Split

| Area | Responsibility |
| --- | --- |
| `platform-tools` | Reusable PKI helper scripts, templates, and documentation. |
| `platform-private` | Private environment-specific references and operator config; no raw private keys. |
| `~/.config/platform-infrastructure/pki/` | Real CA state, service keys, issued certificates, CSRs, exports, and backups. |
| `platform-config` | Ansible deployment of certs/keys, CA trust, permissions, and service reloads. |
| Monitoring | Live endpoint expiry checks and alerts. |

## Architecture

The helpers use this model:

```text
offline root CA
  signs
intermediate CA
  signs
service certificates
```

Service certificates are not signed directly by the root CA.

Defaults:

| Setting | Default |
| --- | --- |
| Key algorithm | ECDSA |
| Curve | `secp384r1` / P-384 |
| Digest | `sha384` |
| Root lifetime | 3650 days |
| Intermediate lifetime | 1825 days |
| Service lifetime | 397 days |

## Requirements

See `../README.md` for the canonical repository requirements. This section lists PKI-specific requirements and behavior.

Required:

- `bash`
- `openssl`
- util-linux `flock` and Linux procfs at `/proc` for stable operation-lock identity checks
- `tar` with `--no-wildcards` support for safe backup directory exclusions
- GNU `date` for certificate expiry calculations
- GNU `mv` with `--no-copy` and `--update=none-fail`; inventory publication prefers `--exchange` when supported and otherwise uses a guarded rename fallback under cooperative same-UID locks
- standard Unix tools such as `awk`, `cmp`, `cp`, `find`, `grep`, `mkdir`, `mktemp`, `sed`, and `stat`

Backup encryption requires `age`.

If `age` is unavailable, `platform-pki-backup` refuses to create an unencrypted archive unless `--allow-plain-backup` is passed explicitly.

## Install

```bash
make install
```

The install target copies command wrappers into `INSTALL_DIR` and shared PKI library/templates into `SHARE_DIR`.

Use custom paths when needed:

```bash
make install \
  INSTALL_DIR="$PWD/.tools/bin" \
  SHARE_DIR="$PWD/.tools/share/platform-tools"
```

If commands cannot find shared assets, set:

```bash
export PLATFORM_TOOLS_SHARE_DIR="$PWD/.tools/share/platform-tools"
```

## Initialize PKI State

```bash
platform-pki-init
```

This initializes the following working-tree layout. CA material, service
directories, OpenSSL database sidecars, exports, and backups appear as the
corresponding commands populate it:

```text
~/.config/platform-infrastructure/pki/
├── inventory/
│   └── services.yml.example
├── authorities/
│   ├── roots/
│   │   └── g1/
│   └── intermediates/
│       └── g1-i1/
├── state/
│   ├── active-issuer
│   ├── bootstrap-root
│   ├── csr/
│   │   ├── candidates/
│   │   ├── replay/
│   │   ├── responses/
│   │   ├── transactions/
│   │   └── recovery-journal
│   ├── generation-reservations/
│   └── rollover/
├── locks/
├── services/
│   └── <service>/
│       ├── certs/
│       ├── chain/
│       ├── csr/
│       ├── private/
│       ├── openssl.cnf
│       └── issuer
├── export/
│   ├── ansible/
│   └── certificates/v1/artifacts/<service>/<request-id>/
└── backups/
```

OpenSSL creates `index.txt.old`, `index.txt.attr.old`, and `serial.old`
database sidecars during CA mutations. It also stores issued-certificate copies
under `newcerts/`. These are active CA state, not obsolete files, and must stay
with the corresponding CA database. Renewal archives are similarly active
history under `services/<service>/archive/`.

PKI directories are owner-only mode `700`. Private keys, CSRs, inventory,
private configuration, CA database files, and database sidecars must be mode
`600` or stricter. Certificates, chains, and issued-certificate copies under
`newcerts/` may be mode `644`, but must never be group- or world-writable.
Tool-managed renewal archives under `services/<service>/archive/` remain active
PKI history. Do not keep other retired keys or passphrase files in an active
PKI tree. Quarantine unmanaged material awaiting review in a separate
owner-only directory outside `pki/` so PKI backups and helpers do not treat it
as current state.

Use a temporary namespace for testing:

```bash
platform-pki-init --namespace /tmp/platform-pki-test
```

The initializer creates only `inventory/services.yml.example`; it does not
create active inventory. Existing examples are preserved by default. Use
`--force` to refresh the example. Active inventory, CA keys, certificates, and
database state are never overwritten by the initializer. Historical local
copies of `pki.env` or `openssl-*.cnf.tpl` remain untouched until explicit
legacy migration quarantines them with migration provenance.

Namespace and PKI paths must be absolute, must not be the filesystem root, and
must not traverse symbolic links. Existing PKI state containing symbolic links
or hard-linked files is rejected before permissions or files are changed.
The PKI directory may be inside the namespace, as it is by default, but it must
not equal or contain the namespace.
Missing path components are created atomically and existing components must be
owned by the current user or root without unsafe writable permissions.
Existing private directories and key files are also checked before
initialization continues; private keys must already be mode `600` or stricter.

The path checks protect against replacement by other local users. Processes
running as the same user, and privileged root processes, are inside the trusted
boundary because portable Bash cannot perform all mutations relative to locked
directory descriptors.

## Create CA Material

Create the root CA:

```bash
platform-pki-root-create \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL"
```

The root key is encrypted by default. `--days` defaults to
`PLATFORM_PKI_ROOT_DAYS`, or 3650 when that environment variable is unset.
Root key, certificate, configuration, and database state are staged as a new
immutable generation. A clean namespace allocates `authorities/roots/g1`.
Publication records a consumed generation reservation and
`state/bootstrap-root`; it does not select an active issuer. A failed or
interrupted allocation remains permanently `abandoned`, so a retry allocates
the next root ID instead of reusing key identity under the old ID.
Another root is refused while that bootstrap root exists. `--force` cannot
replace a completed bootstrap root, an active issuer, or state with descendants;
future generation changes use `platform-pki-ca-rollover`.

For isolated test namespaces only, use:

```bash
platform-pki-root-create \
  --namespace /tmp/platform-pki-test \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL" \
  --allow-unencrypted-root-key
```

Create the intermediate CA:

```bash
platform-pki-intermediate-create \
  --name "Platform Example Intermediate CA" \
  --org "Platform Example" \
  --country "PL"
```

The first clean bootstrap allocates immutable intermediate generation `g1-i1`.
Its key is encrypted by default. `--days` defaults to
`PLATFORM_PKI_INTERMEDIATE_DAYS`, or 1825 when that environment variable is
unset. Intermediate state and the root database update are staged privately.
After the allocated intermediate verifies against the exact bootstrap root, the command publishes
`state/active-issuer` and removes `state/bootstrap-root`. Existing active state
cannot be replaced with `--force`; use the rollover workflow for future
generations. Failed or interrupted intermediate IDs remain abandoned, and a
retry allocates the next intermediate ID under the same bootstrap root. The
identity-bound staging subtree that temporarily contains the copied root key is
durably removed before commit. An interruption during that terminal cleanup can
only resume cleanup; earlier intermediate bootstrap states remain rollback-only.

Services issued or renewed afterward record the selected pair in mode-600
`services/<service>/issuer`. Renewal archives the previous issuer record with
the previous service material. Verification resolves the recorded pair, not the
issuer that happens to be active for new issuance.

All operations use persistent files under `locks/` with `flock`. Acquisition is
`lifecycle`, `root`, `intermediate`, `inventory`, then `export` as required, and
release is reverse. Lock files are current-user-owned, singly linked, mode 600,
and descriptor identity is checked through `/proc/self/fd` before locking.
After locks are held, normal commands reject an uncommitted migration or any
retained rollover-preparation journal before reading operational snapshots.
This preserves the Phase 5 behavior that permits committed migration journals.
Rollover `status` is the read-only exception and reports recovery-required state
with status 2. Recovery-required JSON uses schema 2 and includes the validated
`terminal_outcome` plus the exact `required_action` (`resume` or `rollback`),
including during marker-only terminal cleanup.

`SIGKILL`, host failure, or storage failure cannot run transaction cleanup.
After an unclean stop, treat journals, recovery markers, private staging
directories, and partially published state as incident evidence. Persistent
lock files are normal and must not be deleted; `flock` ownership, not file
existence, indicates an active operation. First stop or account for every PKI
process, inspect process state and artifact timestamps, and make a protected
filesystem-level copy of the complete PKI tree without invoking a normal PKI
command that rejects unresolved recovery state.
Compare configuration, key, certificate, CSR, chain, root `index.txt`, serial,
database sidecars, and `newcerts/` entries with the staging data and a known-good
backup. Validate matching keys and certificates and verify the certificate
chain. If publication is partial or consistency cannot be established, restore
the complete affected transaction state from a known-good protected backup.
Only after proving that no operation is active and the published state is
consistent or restored should an operator resolve the journal and securely
remove reviewed staging material. Re-run `platform-pki-ca-rollover status` and
the relevant verification commands before resuming CA mutations.

For isolated test namespaces only, use
`--allow-unencrypted-intermediate-key`.

For non-interactive automation, provide passphrases through restricted files instead of typing them at OpenSSL prompts:

```bash
# Example assumes these files are populated by a secret manager with mode 600.
# /run/secrets/platform-pki-root-pass
# /run/secrets/platform-pki-intermediate-pass

platform-pki-root-create \
  --name "Platform Example Root CA" \
  --org "Platform Example" \
  --country "PL" \
  --root-pass-file /run/secrets/platform-pki-root-pass

platform-pki-intermediate-create \
  --name "Platform Example Intermediate CA" \
  --org "Platform Example" \
  --country "PL" \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

Passphrase files must exist, be readable by the current user, and must not be group- or world-accessible. OpenSSL uses the first line of each passphrase file; that first line must be at least 16 characters and contain non-whitespace characters. Keep passphrase files outside Git and prefer temporary secret-manager mounts such as `/run/secrets` over long-lived files. Omit pass-file options to let OpenSSL prompt interactively.

The 16-character rule is a parser minimum, not a production-strength creation
policy. For production custody:

1. Generate distinct root and intermediate credentials inside an approved
   cryptographic secret manager or on the isolated signer from at least 32
   random bytes. Do not type a generated value into a command argument, shell
   history, Git file, ticket, chat, or automation log.
2. Keep the durable credentials outside the PKI tree and separate from CA-key
   and backup media. Maintain two independently accessible recovery paths whose
   loss does not depend on a service protected by this PKI.
3. Inject only an operation-scoped, current-user-owned mode-`600` first-line
   file such as `/run/secrets/platform-pki-root-pass`; remove or unmount it
   after the operation. An ephemeral `/run` file is not a recovery copy.
4. Record only non-secret ceremony evidence: credential identifier, purpose,
   creation and review times, custodians, recovery locations, and successful
   validation result. Never record the value or a reusable verifier.
5. Replace a credential after suspected disclosure, custody loss, unauthorized
   access, or an approved cryptographic-policy change. Validate replacement and
   recovery paths before retiring the old credential.

Backup encryption uses a separate credential or, preferably, independent
`age` recipients. Never store an `age` identity or backup passphrase beside the
archive it decrypts, and do not reuse either CA passphrase for backups.

Verify candidate CA passphrase files against the active generation:

```bash
platform-pki-ca-passphrase-verify \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

At least one pass-file option is required. The command acquires the standard
lifecycle, root, and intermediate locks, rejects unresolved journals and legacy
layouts, and gates both rollover and authenticated-CSR recovery before reading
the active issuer or inspecting a passphrase or CA key. It verifies each
encrypted key and proves its public key matches the active certificate. It emits `root=valid` and/or `intermediate=valid` only after
all requested checks succeed. Failures suppress raw OpenSSL diagnostics, and
passphrases are passed through inherited descriptors rather than argv or the
environment. The command writes no persistent receipt; a successful run is
point-in-time evidence and does not prove offline custody or future recovery.
Temporary verification cleanup is bound to the directory identity created by
the command; an unexpected replacement is retained and makes cleanup fail.

## Service Inventory

Service certificates are issued from:

```text
~/.config/platform-infrastructure/pki/inventory/services.yml
```

Install the canonical private-Git source after initialization:

```bash
platform-pki-inventory-install
platform-pki-inventory-install --private-repo /absolute/path/to/platform-private
```

The default private repository is exactly `../platform-private`, resolved from
the physical current directory. The command reads
`<private-repo>/pki/services.yml`, validates one safely staged copy, and
atomically publishes those exact bytes as mode `600`. It rejects linked,
foreign-owned, or writable source and destination files, unsafe path ancestry,
source paths inside the PKI tree, malformed inventory, and concurrent lock
contention. Identical protected content is a no-op; identical content with a
safe non-writable mode is atomically normalized to mode `600`.

The inventory parser supports this strict YAML subset:

```yaml
services:
  platform-example:
    key_custody: host-local
    target: host-01
    validation_boundary_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    rollback_hold_seconds: 86400
    common_name: app.example.internal
    dns:
      - app.example.internal
      - app
    ips:
      - 192.0.2.10
    days: 397
```

The supported format is a restricted YAML subset, not general YAML. There must
be exactly one `services:` mapping and at least one uniquely named service.
Every service has exactly one `common_name`, optional unique `dns` and `ips`
block lists, optional decimal `days` from 1 through 365000, and optional
`key_custody: host-local`. Host-local entries require canonical `target`,
`validation_boundary_sha256`, and positive `rollback_hold_seconds` scalars;
managed entries reject those fields. Absence of `key_custody` preserves the
managed controller-key workflow. Authenticated issue, migration, renewal, and
exact candidate decisions are available for host-local entries. Explicit
host-local Ansible export remains fail closed. SANs are mandatory: a service must
define at least one value under `dns:` or `ips:`. Indentation is
exactly two spaces for services, four for fields, and six before list dashes.
Blank lines, whole-line comments, and one leading `---` are allowed. Duplicate
names, fields, or SANs; tabs; inline comments; unknown fields including
`deploy`; anchors, aliases, tags, flow values, multiline values, extra
documents, and trailing top-level content are rejected.

Inventory values are written into OpenSSL configuration files during issuance and renewal. `common_name` and `dns` entries must be DNS names using only letters, digits, dots, and hyphens; wildcard names are not supported. `ips` entries must be IPv4 addresses. Inventory values must not contain OpenSSL configuration expansion syntax such as `$ENV::SECRET_NAME`.

## Host-Local CSR Trust

Install the reviewed public trust snapshot for authenticated CSR signing after
PKI initialization:

```bash
platform-pki-csr-trust-install
platform-pki-csr-trust-install --private-repo /absolute/path/to/platform-private
```

The source is `<private-repo>/pki/csr-trust`; the protected destination is
`<pki-dir>/inventory/csr-trust`. The source directory must contain exactly:

```text
policy
requesters.allowed_signers
approvers.allowed_signers
responses.allowed_signers
```

`policy` is bounded ASCII text with exactly these ten ordered records and one
trailing newline:

```text
schema=1
request_namespace=platform-pki-csr-request-v1
approval_namespace=platform-pki-csr-approval-v1
response_namespace=platform-pki-csr-response-v1
request_max_age_seconds=604800
sole_operator_min_delay_seconds=86400
approval_max_age_seconds=86400
clock_skew_seconds=300
approver_principal=offline-approver
response_principal=offline-response
```

Schema 1 is accepted for signing and certificate export only. Candidate
finalization and abandonment require an exact five-file schema-2 trust tree
that additionally contains `deployers.allowed_signers` and this ordered policy:

```text
schema=2
request_namespace=platform-pki-csr-request-v1
approval_namespace=platform-pki-csr-approval-v1
response_namespace=platform-pki-csr-response-v1
deployment_namespace=platform-pki-csr-deployment-v1
request_max_age_seconds=604800
sole_operator_min_delay_seconds=86400
approval_max_age_seconds=86400
deployment_max_age_seconds=86400
clock_skew_seconds=300
approver_principal=offline-approver
response_principal=offline-response
```

`deployers.allowed_signers` contains one or more unique no-options Ed25519
principals. Deployment signatures use namespace
`platform-pki-csr-deployment-v1`; deployment principal, target, request
principal, and inventory target agree exactly.

The principal values shown are examples chosen by the private repository. Each
must match `[a-z0-9][a-z0-9.-]*`. The approver and response principal records
pin the corresponding allowed-signer files.

Every allowed-signer line has exactly this no-options OpenSSH form:

```text
principal ssh-ed25519 BASE64_PUBLIC_KEY
```

`requesters.allowed_signers` contains one or more unique principals.
`approvers.allowed_signers` and `responses.allowed_signers` each contain exactly
the one principal pinned by `policy`. Blank records, key options, comments,
duplicate principals, extra fields, non-Ed25519 keys, and keys rejected by
`ssh-keygen` fail validation.

All schema-selected source files must be current-user-owned, singly linked, readable
regular files that are not group- or world-writable, are at most 65536 bytes,
and contain bounded ASCII text with one trailing newline. The command rejects
unsafe or linked path components, a private repository inside the PKI tree,
source changes during staging, unresolved PKI journals, and an unsafe existing
destination. It holds the lifecycle, root, intermediate, and inventory locks;
pins any existing destination identity through comparison and exchange;
publishes the complete mode-`700` directory with mode-`600` files atomically;
and makes identical protected content a no-op. An exchange, durability, or
cleanup failure leaves either the prior complete tree or the complete staged
tree, never a per-file mixture. If identities become ambiguous after exchange,
the command fails and retains the displaced tree for review rather than
deleting or restoring potentially independent state. No private key is
installed. Temporary files used to validate public keys are removed only while
their exact created identity remains current; replacements are retained and
make installation fail.

Any actual trust-tree change involving schema 2 runs a lifecycle-locked,
fail-closed scan of retained signer candidate and outcome state. Initial schema-2
installation succeeds when no candidate is pending, and identical protected
content remains a no-op. A candidate is terminal only when its complete retained
sources and immutable finalized or abandoned outcome authenticate under the
response trust snapshotted by its signing transaction and the deployer trust
retained with its decision. Retained candidate directories and superseded
history do not by themselves make terminal history pending, but every terminal
outcome must still authenticate against current inventory and any required
preserved managed migration state. Missing outcomes, malformed or unsafe trees,
duplicate request IDs, orphan outcomes, conflicting evidence, inventory drift,
source races, and recovery-required state block replacement. This gate covers
candidates persisted by the signer; request
transport and target/controller automation must separately prevent rotation
while an external request has not yet reached signer candidate state.

This trust snapshot freezes OpenSSH `ssh-keygen -Y` detached Ed25519 signature
namespaces and timing limits. Installing it performs no signing. Authenticated
host-local issue, migration, and renewal consume schema 1 or schema 2. Candidate
decisions require schema 2. Explicit host-local Ansible export remains fail
closed.

## Authenticated Host-Local CSR Signing

Host-local signing requires all protocol inputs in one invocation. Issue and
migration use `platform-pki-service-issue`; renewal uses
`platform-pki-service-renew` and additionally requires the exact current
certificate:

```bash
platform-pki-service-issue external \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass \
  --csr-file ./tls.csr \
  --request-file ./request \
  --request-signature ./request.sig \
  --approval-file ./approval \
  --approval-signature ./approval.sig \
  --response-key /secure/offline-response

platform-pki-service-renew external \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass \
  --csr-file ./tls.csr \
  --request-file ./request \
  --request-signature ./request.sig \
  --approval-file ./approval \
  --approval-signature ./approval.sig \
  --response-key /secure/offline-response \
  --current-cert-file ./current-tls.crt
```

These inputs are current-user-owned, singly linked, non-writable-by-others
regular files. Records are printable ASCII, ordered exactly as documented, and
reject missing, duplicate, unknown, reordered, or trailing fields. Request IDs
are 32 lowercase hexadecimal characters and nonces are 64. The request
signature uses namespace `platform-pki-csr-request-v1`; the approval signature
uses `platform-pki-csr-approval-v1`. In schema 1, `target` is the canonical
target inventory identity and `requester_principal` must equal it exactly. The
signer verifies the request with the installed allowed-signers key for that
exact principal; another trusted requester cannot claim the target.

The request schema is:

```text
schema=1
request_id=<32-lowercase-hex>
nonce=<64-lowercase-hex>
created_epoch=<canonical-decimal-epoch>
expires_epoch=<canonical-decimal-epoch>
operation=<issue|migrate|renew>
service=<inventory-service>
target=<target-principal>
requester_principal=<trusted-requester-principal>
inventory_sha256=<sha256>
csr_sha256=<sha256>
csr_spki_sha256=<sha256>
current_cert_sha256=<sha256|none>
profile=server-p384-sha384-v1
response_principal=<policy-response-principal>
```

The approval schema is:

```text
schema=1
request_id=<request-id>
nonce=<request-nonce>
created_epoch=<canonical-decimal-epoch>
expires_epoch=<canonical-decimal-epoch>
approver_principal=<policy-approver-principal>
request_sha256=<request-manifest-sha256>
csr_sha256=<request-csr-sha256>
inventory_sha256=<request-inventory-sha256>
operation=<request-operation>
service=<request-service>
target=<request-target>
profile=server-p384-sha384-v1
```

Requests may be valid for at most 604800 seconds and approvals for at most
86400 seconds, with 300 seconds of clock skew. Approval cannot predate the
request. If requester and approver resolve to the same Ed25519 public key,
approval must be at least 86400 seconds after request creation.

Inventory is authoritative for subject, SANs, validity, and profile. The signer
accepts only a self-signed EC P-384 CSR whose subject is exactly the inventory
common name and whose only requested extension is the exact inventory SAN set.
It rejects unsupported attributes and extensions. Issue requires no existing
managed key or certificate and `current_cert_sha256=none`. Migration requires
the digest of the preserved managed certificate. Renewal requires the supplied
current certificate digest and verifies that certificate against the active
issuer. `--days` and `--rotate-key` are unavailable in the host-local path.

Before CA mutation, the signer permanently reserves both request ID and nonce
under `state/csr/replay/`. It signs against staged CA state, validates the
issued chain, profile, SANs, serial, validity, and CSR public-key match, and
publishes each CA database file transactionally. It never receives a host leaf
private key. Migration leaves existing managed service and export state intact.

The signed response record uses namespace
`platform-pki-csr-response-v1` and this exact schema:

```text
schema=1
request_id=<request-id>
nonce=<request-nonce>
operation=<issue|migrate|renew>
service=<inventory-service>
target=<target-principal>
request_sha256=<sha256>
approval_sha256=<sha256>
inventory_sha256=<sha256>
csr_sha256=<sha256>
csr_spki_sha256=<sha256>
certificate_sha256=<sha256>
certificate_spki_sha256=<sha256>
chain_sha256=<sha256>
issuer_root=<root-generation>
issuer_intermediate=<intermediate-generation>
serial=<uppercase-even-length-hex>
not_before_epoch=<canonical-decimal-epoch>
not_after_epoch=<canonical-decimal-epoch>
candidate_state=pending
response_principal=<policy-response-principal>
created_epoch=<canonical-decimal-epoch>
```

Certificate-only artifacts are published at
`state/csr/candidates/<service>/<request-id>/` and
`state/csr/responses/<service>/<request-id>/`. Each contains `tls.crt`,
`ca-chain.crt`, `fullchain.crt`, `response`, and `response.sig`; the candidate
also contains its exact pending-state record. These directories contain no
leaf key. Records and candidates are not automatically deleted or selected for
deployment.

If signing is interrupted, every normal PKI command rejects
`state/csr/recovery-journal`. Recover the exact transaction shown in the
journal:

```bash
platform-pki-csr-recover \
  --transaction csr-0123456789abcdef0123456789abcdef \
  --response-key /secure/offline-response
```

Pre-commit recovery restores exact original CA database state, removes only
identity-matched staging, writes terminal evidence, and keeps the request and
nonce consumed. Post-commit recovery never restores CA state, re-signs the CSR,
or allocates another serial; it validates exact journal paths and identities
and resumes the original signed response and candidate publication. Omit
`--response-key` only when the journaled response signature already exists.
Without `--yes`, recovery requires a TTY and the exact transaction confirmation.
The signer rejects a pre-existing transaction path before creating its journal,
removes a staged CA key only when its exact identity was recorded, and binds
temporary input cleanup to the directory identity it created. Unexpected
temporary-directory replacements are retained and cause cleanup to fail.
Replay records must remain current-user-owned, singly linked, non-symlink
mode-`600` files at their exact journaled identities. Artifact-stage ownership
is journaled before the first copy, and an existing stage must match that exact
identity before any write. Published candidate and response identities remain
authoritative after their checkpoints; content-based reconciliation is limited
to the interrupted atomic-rename window immediately before each checkpoint and
requires the destination to retain the exact journaled stage identity.

Issuance, renewal, verification, certificate printing, expiry listing, and
Ansible export acquire the current root, intermediate, and inventory operation
locks in that order. Each command privately copies and validates active
inventory once, then uses only its canonical parsed snapshot for the rest of
the invocation. Locks are released inventory first, then intermediate and root.

## Immutable Certificate-Only Export

Publish one explicit authenticated pending CSR response by exact service and
request ID:

```bash
platform-pki-certificate-export publish platform-example \
  --request-id 0123456789abcdef0123456789abcdef
```

The command acquires lifecycle, root, intermediate, inventory, and export locks
in that order and rejects unresolved or non-generation state before reading the
candidate. It validates the exact candidate and response trees, signed response
fields, certificate/SPKI/serial/validity, exact current inventory target and
service profile,
historical issuer generation chain, and full chain. Signature verification uses
an identity-checked, descriptor-copied snapshot of the exact
`responses.allowed_signers` file retained by the original
`state/csr/transactions/csr-<request-id>/` signing transaction, not whichever
response trust happens to be installed currently.

The immutable output is:

```text
export/certificates/v1/artifacts/<service>/<request-id>/
├── artifact
├── tls.crt
├── ca-chain.crt
├── fullchain.crt
├── response
└── response.sig
```

The directory is current-user-owned mode `700`; every exact file is singly
linked, current-user-owned mode `600`. It contains no key and permits no extra
entry. Publication stages under the final service parent, writes `artifact`
last, fsyncs the complete tree, and uses a same-filesystem no-clobber rename.
Repeating an exact publication is idempotent; an unsafe or conflicting existing
path is left untouched and fails. There is no force mode.

The canonical `artifact` fields are ordered exactly as follows:

```text
schema=1
kind=certificate-export
service=<inventory-service>
request_id=<request-id>
operation=<issue|migrate|renew>
target=<target-principal>
source_kind=csr-response
source_response_sha256=<sha256>
source_response_signature_sha256=<sha256>
certificate_sha256=<sha256>
certificate_spki_sha256=<sha256>
chain_sha256=<sha256>
fullchain_sha256=<sha256>
issuer_root=<root-generation>
issuer_intermediate=<intermediate-generation>
serial=<uppercase-even-length-hex>
not_before_epoch=<canonical-decimal-epoch>
not_after_epoch=<canonical-decimal-epoch>
candidate_state=pending
deployment_state=unfinalized
response_principal=<response-principal>
created_epoch=<original-response-creation-epoch>
```

The manifest has one final newline and no publication timestamp. Record its
reported digest and resolve only that exact artifact:

```bash
platform-pki-certificate-export resolve platform-example \
  --request-id 0123456789abcdef0123456789abcdef \
  --manifest-sha256 <sha256>
```

The default `path` format prints only the absolute artifact directory to
standard output. `--format json` emits deterministic, secret-free pinned
resolution metadata. Resolution revalidates the exact artifact, embedded signed
response, chain, source identities, and retained historical response trust. It
rechecks the complete artifact and source identities immediately before output,
requires the embedded response and candidate target to remain equal to current
inventory, never scans for another request, and never infers a `current` or
`latest` artifact.

These exports are explicitly pending and unfinalized. This command does not
select a deployment candidate, finalize evidence, activate a certificate,
modify managed-key state, delete a key, or change the existing mutable
`platform-pki-export-ansible` workflow.

## Host-Local Candidate Decisions

`platform-pki-csr-candidate verify SERVICE --request-id ID` validates the exact
immutable candidate, response, signing transaction, replay records, historical
issuer, retained response trust, and explicit certificate export. Text and JSON
status distinguish `pending`, `finalized`, and `abandoned`, plus `active` or
`superseded` accepted evidence. This is historical signer evidence, not current
live-state discovery.

`finalize` and `abandon` additionally require the exact artifact-manifest digest
and canonical deployment evidence plus its detached schema-2 deployer
signature. Unless `--yes` is used, a TTY must confirm the exact action, service,
and request ID. Evidence binds the request, response, response signature,
candidate, export, canonical 64-lowercase-hex nonce, certificate, certificate
SPKI, chain, full chain, inventory
validation boundary, target, action, result, and deployment principal. Its
validity interval is at most 86400 seconds with 300 seconds clock skew.

The deployment evidence is printable ASCII, has one trailing newline, and uses
this exact field order:

```text
schema
request_id
nonce
operation
service
target
request_sha256
response_sha256
response_signature_sha256
candidate_sha256
artifact_request_id
artifact_manifest_sha256
certificate_sha256
certificate_spki_sha256
chain_sha256
fullchain_sha256
action
result
local_certificate_sha256
local_key_spki_sha256
local_key_certificate_match
served_certificate_sha256
served_intermediate_sha256
validation_boundary_sha256
validation_result
activation_epoch
validation_epoch
rollback_state
rollback_hold_until_epoch
deployment_principal
created_epoch
expires_epoch
```

`schema=1`, `artifact_request_id=request_id`, and `action` is exactly
`finalize` or `abandon` as invoked. No target private key is an input or output.
The certificate export intentionally omits the signer-internal candidate file.
Downstream evidence producers derive `candidate_sha256` by reconstructing the
exact canonical candidate record from the authenticated response and the exact
response/signature digests, as specified in
[Candidate Digest Reconstruction](handoffs/pki-host-local-csr-handoff.md#candidate-digest-reconstruction).
The signer compares that digest with its immutable internal record during every
decision; a transport-supplied unsigned digest is never authoritative.

Finalization accepts only exact activated local and served certificate/SPKI and
issuer-intermediate evidence with passed validation and ordered canonical
epochs. Issue has no predecessor. Migration and renewal require retained
rollback state through at least the inventory hold; renewal also requires the
exact active accepted-evidence predecessor. Abandonment accepts exact
not-activated or signer-known rolled-back evidence. Rolled-back evidence must
record passed validation, ordered activation and validation epochs, the exact
restored predecessor leaf and intermediate, `rollback_state=restored`, and the
full inventory hold. Abandonment does not revoke a certificate.

Outcomes are immutable four-file mode-`600` trees under
`state/csr/outcomes/<service>/<request-id>/`; schema-2 deployer trust is retained
with each accepted decision. `state/csr/active/<service>` is an atomic
mode-`600` pointer to accepted historical evidence, not a live-state pointer.
Status, renewal signing, and renewal finalization strictly parse every pointer
scalar and authenticate the referenced immutable outcome, retained deployer
trust, signature, complete source transaction/export, and recursive predecessor
chain before accepting it.
Candidate, response, replay, transaction, and export trees are never removed.
Managed migration keys and Ansible exports remain byte-for-byte and
metadata-identical; all managed material remains through rollback hold and any
cleanup requires separate approval. Finalization recovery is resume-only from
`state/csr/finalization-recovery-journal`; it never inverts the action or rolls
back or reuses CA state. The journal binds every candidate, response, export,
retained response-trust, outcome-stage, and active-pointer identity and digest;
recovery accepts only the exact pre- or post-rename object states.

## Host-Local Exchange Runbooks

The signer commands do not implement network transport, target activation, or
GitLab integration. Use the transport-neutral ownership and workspace contract
in [Host-Local PKI CSR Handoff](handoffs/pki-host-local-csr-handoff.md), then
select one reviewed workflow:

- [GitLab Generic Package Exchange for Host-Local PKI](pki-gitlab-package-exchange.md)
  defines the proposed production CI exchange through one dedicated private
  GitLab 18.11 project. GitLab remains untrusted transport and the offline
  signer never connects to it.
- [Development Direct SSH/SFTP Host-Local CSR Runbook](pki-host-local-csr-development-runbook.md)
  defines the development-only direct host-to-VM registry migration design and
  manual handoff. It is not executable or crash-safe, and the current
  development host is not production offline custody.

Neither document authorizes a live request, CA mutation, target restart,
deployment, rollback, finalization, or cleanup. Exact protocol signatures,
replay state, artifact pins, and separate operation approvals remain mandatory.

## Issue And Verify A Service Certificate

```bash
platform-pki-service-issue \
  platform-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki-service-verify platform-example
```

Use `--min-days` to set the required remaining validity. Verification checks
chain trust, the private-key match, certificate purpose, inventory SANs, and
remaining lifetime.

Generated files:

```text
~/.config/platform-infrastructure/pki/services/platform-example/private/tls.key
~/.config/platform-infrastructure/pki/services/platform-example/csr/tls.csr
~/.config/platform-infrastructure/pki/services/platform-example/certs/tls.crt
~/.config/platform-infrastructure/pki/services/platform-example/chain/ca-chain.crt
~/.config/platform-infrastructure/pki/services/platform-example/chain/fullchain.crt
~/.config/platform-infrastructure/pki/services/platform-example/openssl.cnf
```

`platform-pki-service-issue` refuses to overwrite an existing service certificate. Use `platform-pki-service-renew` after the first issuance.
Issuance validates inventory, CA state, paths, ownership, modes, links, file
types, and the next CA serial destination before mutation. It then holds the
root and intermediate operation locks in fixed order while staging signing,
publishing the service artifacts and intermediate database update, and running
`platform-pki-service-verify`. Signing, publication, verification, and handled
signal failures restore identity-matched prior state. Existing private keys are
reused by default; `--rotate-key` archives the old key only when the complete
transaction commits.

The intermediate OpenSSL configuration used for issuance must retain the
managed signing contract. Include directives, global directives, external or
escaping CA paths, unsupported `CA_default` directives, and alternate CA or
policy selection are rejected before signing. Database, serial, issued-certificate,
private-key, certificate, and optional CRL or random-state paths must remain
under the intermediate CA directory and are redirected to private staging.
Every publication destination is identity-checked against its locked preflight
snapshot immediately before replacement or no-clobber publication.

## Renew A Service Certificate

Renewal archives the previous certificate material under:

```text
~/.config/platform-infrastructure/pki/services/<service>/archive/<timestamp>/
```

By default, renewal reuses the existing service private key:

```bash
platform-pki-service-renew \
  platform-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

Rotate the service private key explicitly when needed:

```bash
platform-pki-service-renew platform-example --rotate-key
```

Renewal requires existing service private-key state and validates inventory,
CA state, path ancestry, file ownership, modes, links, and the closed OpenSSL
signing contract before mutation. It holds root and intermediate operation
locks in that order while signing against staged CA state, archiving previous
service files, publishing replacements, and verifying the result. Signing,
publication, verification, and handled signal failures restore the CA database,
service key, certificate files, and archive state. If a published destination
is replaced by foreign state during recovery, that state and the locked staging
directory are preserved for manual recovery rather than overwritten.

The renew command does not deploy anything to remote hosts. Deployment belongs in `platform-config`.

## Print Certificate Details

```bash
platform-pki-print-cert platform-example
```

The command prints subject, issuer, serial, validity dates, SANs, key usage, extended key usage, and SHA-256 fingerprint.

Use `platform-pki-print-cert --help` for the generated command reference and
`platform-pki-print-cert --version` for the installed platform-tools version.

## Export For Ansible

Export all generated inventory services by default:

```bash
platform-pki-export-ansible --force
```

Export only selected services by passing names:

```bash
platform-pki-export-ansible platform-example --force
```

Output layout:

```text
~/.config/platform-infrastructure/pki/export/ansible/
├── ca/
│   └── root-ca.crt
└── services/
    └── platform-example/
        ├── tls.crt
        ├── tls.key
        ├── ca-chain.crt
        └── fullchain.crt
```

The export directory contains service private keys and must stay outside Git.
Custom `--export-dir` values must be absolute paths. Existing export path
components must be owned by the current user or root, must not be unsafe
writable directories, and must not contain symlink components. The immediate
export parent must already exist, be owned by the current user, and must not be
group- or world-writable. The helper builds the complete export in an exclusive
mode-700 same-parent directory, reads source bytes through no-follow
identity-checked descriptors, synchronizes every staged file and directory,
rechecks all source and destination identities, and atomically publishes the
whole directory. Existing export roots must remain owner-only mode `700`. An
absent destination is never clobbered. `--force` atomically exchanges only the
validated existing top-level directory and never rolls back the new export
after publication. Safe cleanup unlinks hostile symlinks as directory entries
without following their targets and rechecks every snapshotted entry immediately
before unlinking its name. Incomplete cleanup leaves the displaced directory
under the reported owner-only recovery name. For custom destinations, the exact
authorization marker inode and accepted bytes remain descriptor-pinned from
authorization through a final recheck immediately before exchange.

This whole-directory publication deliberately improves interruption safety over
the retained Bash implementation. Before the atomic publication point, a copy,
source-race, durability, or injected failure leaves an existing export and its
byte/metadata/identity tree untouched. A stage with completed immutable
readiness is removed only through the same exact-name cleanup primitive; a
partial or not-yet-ready stage is retained mode `700` and its precise evidence
path is reported rather than recursively traversed. After the publication
point, the new complete export remains authoritative even if displaced-tree
cleanup or final durability reporting fails.

An export inside the PKI tree must stay under its `export/` directory. Forced
replacement of an existing custom export requires the marker written by this
version of the helper; the default `export/ansible` path remains compatible
with exports created by earlier versions.

### Why Two Controller Copies Exist

Under the current managed-key workflow, `services/<service>/private/tls.key` is
the controller's signing and renewal input. `platform-pki-export-ansible` makes
a second key-bearing copy under `export/ansible/services/<service>/tls.key`
because existing `platform-config` roles copy that export to the destination.
Protected PKI backups include both trees because they preserve the complete
current state. The custody report classifies every retained export key as a
duplicate by role; it deliberately does not compare or hash private-key bytes.

These copies are compatibility-bound migration inputs, not the target custody
model. A custody finding is not deletion authorization. Retain the active
controller key, export, destination rollback pair, renewal history, and relevant
encrypted backups until a fresh destination-generated key has a signed
certificate, strict endpoint and real-client validation has succeeded, and the
approved rollback and evidence holds have expired. Quarantine requires separate
authorization and identity-bound evidence. Unlinking a current file does not
erase copies retained in historical backups and must not be described as secure
erasure.

Use `platform-pki-export-ansible --help` for generated option details and
`platform-pki-export-ansible --version` for the installed version.

## Report Encryption And Custody

Inspect the managed PKI layout without decrypting or parsing private keys:

```bash
platform-pki-custody-report
```

Use schema-1 JSON for automation:

```bash
platform-pki-custody-report --format json
```

The report classifies root and intermediate authorities, controller service
keys, Ansible-export key copies, backups, private inventory, CA databases,
legacy quarantine, and public artifacts. Each material record states observed
encryption evidence, recommended custody, backup policy, and structural status. Findings
cover unconfirmed CA-key encryption, controller leaf keys, duplicate export
keys, plaintext or malformed backups, missing or unsafe receipts, unsafe file
metadata, and unexpected `*.key` files. Block-device ancestry is reported
separately as evidence and does not by itself create an encryption finding.

The command acquires the standard lifecycle, root, intermediate, inventory, and
export locks and rejects unresolved recovery journals. Like other operationally
read-only PKI commands, it may prepare missing standard control directories and
lock files; it does not modify keys, certificates, databases, inventory,
exports, or backups.

For validated private-key files, the command reads only the first PEM header
line. `BEGIN ENCRYPTED PRIVATE KEY` is reported as
`encrypted-pkcs8-header`, `BEGIN PRIVATE KEY` as
`plaintext-pkcs8-header`, and any legacy, unreadable, or unrecognized envelope
as `unknown` or `unreadable`. These values are header evidence, not
cryptographic validation. The command never asks for a passphrase, invokes
OpenSSL on a private key, decrypts, hashes, copies, or prints key content. It
similarly reports the public first-line `age-encryption.org/v1` marker as
`age-v1-header` rather than claiming successful backup decryption.
Header inspection uses a descriptor-bound Python byte reader, stops at the
first newline or byte 257, rejects NUL bytes, and reports lines longer than 256
bytes as findings. Receipt parsing reads at most 65,537 bytes from the verified
descriptor, rejects content above 64 KiB, and validates the exact schema-2
field set plus the bound archive path, device, inode, size, mode, and owner. It
does not hash the archive payload. Visible and hidden backup entries are both
inspected, and orphan receipts are reported.

When available, util-linux `findmnt` and `lsblk` report whether the PKI mount's
block-device ancestry includes `crypto_LUKS`. The evidence values are
`luks-ancestor`, `no-luks-ancestor`, and `unknown`; absence of a LUKS ancestor
does not claim absence of native filesystem or directory encryption. Overlay,
network, unavailable-command, and unsupported storage stacks are reported as
`unknown`. A recognized header or LUKS ancestor does not prove recipient
custody, archive recoverability, or protection while mounted.

Operational controls that cannot be established from local structure remain
explicitly `unknown`: CA-key cryptographic validation, backup decryption and
archive-digest validation, offline CA custody, backup-recipient separation, an
offsite backup copy, isolated restore rehearsal, and target-host leaf custody.
Exit status is 0 when there are no structural findings, 2 when findings exist,
and 1 for parser, configuration, or unsafe-layout errors.

`platform-pki-ca-passphrase-verify` intentionally remains separate from this
report. Supplying a passphrase changes the trust and secret-access boundary, and
a prior successful check does not establish the report's current operational
controls.

## Back Up PKI State

Backups include the full PKI working directory, including CA private keys,
managed service private keys, issued certificates, CSRs, CA database files,
inventory, exports, and host-local replay, transaction, candidate, and response
state. When the backup output directory is inside the PKI directory, it is
excluded from the archive to avoid recursive backups.

The backup command acquires the full lifecycle, root, intermediate, inventory,
and export lock matrix and accepts only a complete legacy or generation-aware
layout. It refuses unresolved recovery state. Each successful archive also
publishes a mode-600 `<archive>.receipt` that binds the archive identity and
SHA-256 digest to its layout and public-state manifest digest. Keep that receipt
with the protected archive; one-time legacy migration requires it.

Use `age` recipient encryption for non-interactive backups:

```bash
platform-pki-backup --age-recipient "$AGE_RECIPIENT"
```

If no `--age-recipient` is provided, `age` passphrase mode is used and prompts interactively:

```bash
platform-pki-backup
```

Output path:

```text
~/.config/platform-infrastructure/pki/backups/platform-pki-YYYYMMDD-HHMMSS.tar.gz.age
```

The default `~/.config/platform-infrastructure/pki/backups/` output directory is not included in generated backup archives.

Plain unencrypted archives require an explicit override:

```bash
platform-pki-backup --allow-plain-backup
```

Use `platform-pki-backup --help` for generated option details and
`platform-pki-backup --version` for the installed platform-tools version.

Plain backup output uses `.tar.gz` and still contains secrets. Keep it outside Git and move it to encrypted storage as soon as practical.

## Migrate Legacy CA State

Normal CA and service commands require generation-aware state. On a legacy
layout they safely prepare missing private control directories, acquire the
required persistent locks, and stop with migration guidance before reading or
mutating authority state. Inventory installation, protected backup, and
`platform-pki-ca-rollover status|migrate` remain available so migration can be
completed. Mixed legacy and generation authority paths are rejected as
incomplete or ambiguous state.

First install the canonical inventory and create a new independent protected
backup. Then inspect status and migrate with that backup's receipt:

```bash
platform-pki-inventory-install
platform-pki-backup --age-recipient "$AGE_RECIPIENT"
platform-pki-ca-rollover status
platform-pki-ca-rollover migrate \
  --backup-receipt /secure/path/platform-pki-....tar.gz.age.receipt
```

`status` exits 0 for ready generation-aware state, 1 for legacy state, and 2
for recovery-required, incomplete, or ambiguous state. It is the only rollover
operation allowed to inspect an unresolved journal.

Resume or roll back an interrupted migration only through its exact journaled
transaction ID:

```bash
platform-pki-ca-rollover recover \
  --transaction migrate-20260730-120000-1234 \
  --action rollback \
  --yes
```

Recovery validates the journal, backup receipt, transaction directory,
identity-and-digest-bound service snapshot, and authority identities before
mutation. A migration command failure never starts a second in-process rollback:
it preserves an unresolved journal and marker, blocks normal commands, and
requires explicit `recover`. Missing or replaced evidence is preserved and rejected. Recovery
records and fsyncs pending and completed state around every mutation, so another
`recover` invocation can continue after a recovery-process crash. Fresh root
and first-intermediate bootstrap operations use the same durable journal
discipline and automatically roll back handled failures; `--force` never
recursively deletes unproven authority state.

Interactive migration requires typing the exact root and intermediate public
SHA-256 fingerprints. Non-interactive migration additionally requires `--yes`,
`--expected-root-sha256`, and `--expected-intermediate-sha256`. Use
`--private-repo` when the canonical private repository is not
`../platform-private` relative to the current directory.

Migration verifies the backup receipt and archive identity, public certificate
chain, current public-state digest, and semantic equality between installed
inventory and `<private-repo>/pki/services.yml`. Under the full migration lock
matrix it safely creates missing private `authorities/roots` and
`authorities/intermediates` destination parents used by legacy installations
that predate generation-aware initialization, then revalidates the legacy
layout. It records a recovery journal, reserves `g1` and `g1-i1`, and moves
legacy CA directories on the same filesystem. It regenerates managed OpenSSL
paths, publishes service issuer records, quarantines legacy scaffolding with
provenance, and publishes
`state/active-issuer` last. It durably publishes the identity-bound migration
provenance directory before marking the transaction journal committed. Existing
keys are not copied, hashed, parsed, or regenerated. Provenance includes a
deterministically ordered relative-path manifest with object identities and
non-secret file digests; potentially private quarantine contents are marked
secret and are not hashed. A completed valid migration
is an idempotent no-op.

The migration journal binds original and published identities for managed
configurations, reservations, the backup-session record, service issuer
records, quarantined entries, and the active manifest. Recovery accepts only
the exact journaled legacy or generation location for each authority and fails
closed if both paths exist. Bootstrap rollback likewise restores only exact
transaction-owned CA database, sidecar, serial, and `newcerts/` state. A fully
verified bootstrap rollback publishes an `abandoned` reservation and never
deletes or reuses that generation ID; retries allocate the next available ID.

Backup receipts are valid for legacy migration for 24 hours, carry a unique
session, and bind both public state and metadata-only private state, including
keys and files under passphrase or quarantine paths. Migration does not read or
hash private-key or passphrase content.

Certificate issuance checks actual ASN.1 validity against the issuer.
`--issuer-safety-days` defaults to one day for first-intermediate creation,
service issuance, and renewal.

Inventory installation prefers atomic exchange. A guarded ordinary atomic-rename
fallback is supported when the filesystem or rootless container runtime does
not support `RENAME_EXCHANGE`. The fallback performs a final identity recheck
under cooperative same-UID lifecycle/root/intermediate/inventory locks. This excludes
cooperating commands but does not protect against a malicious same-UID process,
which remains inside the documented trust boundary.

## Prepare a Rollover Candidate

Create a fresh protected generation-layout backup immediately before
preparation. Intermediate preparation signs a new intermediate under the active
root; root preparation creates a new root and first intermediate and snapshots
the reviewed private trust-consumer checklist:

```bash
platform-pki-ca-rollover prepare \
  --type intermediate \
  --backup-receipt /secure/path/platform-pki-....tar.gz.age.receipt \
  --intermediate-name "Platform G1-I2 Intermediate CA" \
  --org Platform \
  --country PL \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass

platform-pki-ca-rollover prepare \
  --type root \
  --backup-receipt /secure/path/platform-pki-....tar.gz.age.receipt \
  --root-name "Platform G2 Root CA" \
  --intermediate-name "Platform G2-I1 Intermediate CA" \
  --org Platform \
  --country PL \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass \
  --private-repo ../platform-private
```

Preparation leaves `state/active-issuer` unchanged. It publishes public
candidate metadata under `state/rollovers/` and selects it through
`state/active-rollover`; `platform-pki-ca-rollover status --format json`
provides machine-readable active, candidate, expiry, fingerprint, trust, and
old-issuer service data. Status validates deterministic complete-tree manifests
for the published candidates and rollover state, including object identity and
non-secret file digests; private key and passphrase contents are never hashed.
Missing, unsafe, unexpected, or changed tree entries and service issuer
manifests are rejected. Prepared status exits 1 because operator action is
still required. Activation, acknowledgement, lifecycle rollback, retirement,
and completion are not implemented yet.

If preparation or recovery is interrupted, `status` exits 2 and reports the
exact transaction. Use `recover --transaction ID --action resume|rollback
--yes`; recovery verifies journaled source, destination, backup, and tree
identities before each mutation and can be re-run after another interruption.
Rollback restores the fresh-backup session marker to its pre-prepare state.
Sensitive copy, key-generation, CSR, certificate, signing-database, and
`newcerts` destinations are pre-created and durably identity-journaled before a
child process can write them. Completed staged root database sources use full
nanosecond identities. A child interruption is either captured as exact partial
state for explicit rollback or retained as fail-closed evidence that recovery
will not delete.
Terminal cleanup records an explicit resumed or rolled-back outcome and keeps a
recovery marker until transaction staging and the journal have both been
removed. Immutable write-ahead transaction manifests keep pending publication
recoverable. Each replacement identity-unlinks only its journaled predecessor,
and terminal cleanup removes the final external manifest only after transaction
staging. Missing prior unlinks resume safely, identity mismatches fail closed,
and a retained terminal receipt binds the exact journal and marker identities
used for their final checked unlink.

## List Expiry

```bash
platform-pki-list-expiry --warn-days 90 --critical-days 30
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All certificates are OK. |
| `1` | Warning threshold reached, or a parser/configuration error occurred. |
| `2` | At least one certificate is within the critical threshold. |
| `3` | A generated certificate is missing. |

The shared generated CLI contract uses status 1 for parser and configuration
errors. Inspect stderr to distinguish those errors from a warning report.
Missing status 3 takes precedence when other certificates are warning or
critical.

## Safety Rules

Do not commit anything generated under `~/.config/platform-infrastructure/pki/`.

Do not commit CA passphrases or passphrase files. If automation needs passphrase files, keep them outside Git, use mode `600` or stricter, use a first-line passphrase of at least 16 characters with non-whitespace content, and prefer short-lived secret-manager mounts. Use separate production credentials and independent recovery paths; do not reuse CA passphrases for backups.

Do not issue service certificates without SANs.

Do not use the root CA to sign service certificates directly.

Deployment to hosts belongs in `platform-config`, not in these helper scripts.

## Future Migration To ACME Or step-ca

These OpenSSL helpers are an initial private PKI, bootstrap path, break-glass fallback, and appliance support path.

A future `step-ca` or ACME workflow can replace manual service certificate issuance for services that support automated enrollment. The surrounding pieces remain useful:

- CA trust installation through `platform-config`.
- Certificate deployment for non-ACME appliances.
- Expiry checks and monitoring alerts.
- Documentation of certificate ownership and file locations.
- OpenSSL-based fallback for recovery or isolated environments.
