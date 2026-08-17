# Development Direct SSH/SFTP Host-Local CSR Runbook

> **STATUS: DEVELOPMENT-ONLY FULL-LIFECYCLE DESIGN AND MANUAL HANDOFF; NOT AN EXECUTABLE OR CRASH-SAFE RUNBOOK; NOT LIVE AUTHORIZATION.**
>
> This document describes an intended `registry-dev` managed-to-host-local
> migration on `dev-registry-01` using the current development host and CA. The
> active registry, managed predecessor, current inventory, and applicable issuer
> are hypotheses until every preflight binding below is established. Writing or
> reviewing this document authorizes no connection, key generation, signing, CA
> mutation, target mutation, restart, validation, rollback, finalization,
> abandonment, account provisioning, or cleanup.
>
> Target request automation, constrained SFTP transport, activation, target
> journaling/recovery, canonical validation-file construction, and deployment
> evidence construction are not implemented. Every live phase requires separate
> exact authorization. Signer finalization records authenticated historical
> evidence; it never discovers or claims current live state.

This is a full-lifecycle design/manual handoff with no GitLab exchange. It is not
a currently executable full lifecycle. Canonical references:

- [OpenSSL PKI Helpers](pki-openssl.md)
- [Authenticated Host-Local CSR Signing](pki-openssl.md#authenticated-host-local-csr-signing)
- [Immutable Certificate-Only Export](pki-openssl.md#immutable-certificate-only-export)
- [Host-Local Candidate Decisions](pki-openssl.md#host-local-candidate-decisions)
- [Host-Local PKI CSR Handoff](handoffs/pki-host-local-csr-handoff.md)
- [Production GitLab Package Exchange](pki-gitlab-package-exchange.md)

If this document conflicts with either canonical PKI document, stop. Do not
change field order, substitute a signature, or invent a helper command.

Command templates use the production `platform-pki <command>` interface. Legacy
v2 alias names are not installed.

## Inert Command Convention
Every command block is a template, not a script. A consequential block starts
with a guard such as:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate live authorization required}"
```

Setting that variable is not authorization. Execute only one reviewed command
inside its separately authorized phase. Never put a passphrase, private key,
real key payload, or private value in Git, `/tmp`, shell history, argv, chat, or
a ticket. Do not source this document.

## Migration Hypothesis And Selection Gate
The intended migration is valid only if preflight proves all of these facts at
one reviewed boundary:

- The actual active Zot service on `dev-registry-01` uses the observed target
  certificate and matching private key.
- That exact active target certificate equals the signer-side managed
  `registry-dev` predecessor certificate byte-for-byte and by SHA-256.
- The signer-side managed service tree and mutable Ansible export are complete,
  protected, and preserved for rollback.
- The installed current inventory is the reviewed `registry-dev` host-local
  migration inventory and binds target, names, boundary, profile, lifetime, and
  14-day hold exactly.
- The current generation-aware issuer state is ready, has no unresolved journal,
  and is the state that owns the managed predecessor and will own the migration
  replay, transaction, candidate, response, and outcome.

Only after those bindings are established does active migration selection
supersede an isolated CA design. If any binding is absent, different, stale, or
unknown, abort active registry mutation. Use a separately named parallel
`issue` endpoint with an isolated CA and explicitly separate client trust; never
describe it as migration of the active registry.

## Intended Pilot Values
| Field | Reviewed intended value |
| --- | --- |
| Service | `registry-dev` |
| Target | `dev-registry-01` |
| Operation after the selection gate | `migrate` |
| Common name | `registry.dev` |
| DNS SANs | `registry.dev`, `dev-registry-01` |
| IP SAN | `192.168.20.61` |
| Profile | `server-p384-sha384-v1` |
| Request/deployment key | `/etc/ssh/ssh_host_ed25519_key`, separate namespaces |
| Rollback hold | `1209600` seconds, exactly 14 days |
| Local validation | Strict Zot checks on `dev-registry-01` |
| Client validation | Strict TLS/read-only OCI from `dev-registry-runner-01` |
| Endpoint | `https://registry.dev/v2/` |

Namespaces are exactly `platform-pki-csr-request-v1`,
`platform-pki-csr-approval-v1`, `platform-pki-csr-response-v1`, and
`platform-pki-csr-deployment-v1` for request, approval, response, and deployment.

## Preflight And Abort Rules
Abort if any item is false, unknown, or changes:

- Separate authorization exists for the exact phase.
- The migration selection gate above has passed with preserved evidence.
- Current CA layout is generation-aware and ready; no rollover, CSR signing, or
  finalization journal exists; no relevant process remains active.
- Inventory is exact: `key_custody: host-local`, target `dev-registry-01`, the
  canonical boundary digest, and `rollback_hold_seconds: 1209600`.
- Current development host, target, and runner clocks are strict UTC.
- Active CA passphrases are available through current-user-owned, singly-linked,
  mode-`600` secret mounts outside Git.
- A fresh encrypted PKI backup/receipt and reviewed rollback evidence exist.
- Prior target cert/key/config and signer managed state remain identity-bound.
- Frozen schema-2 trust described below is separately provisioned and unchanged.
- The per-request constrained SFTP account/identity, chroot, spool, host pin, and
  permissions described below are implemented, tested, and independently
  reviewed.
- Exact receipt-trust, validation-boundary, and validation-result builders and
  parsers implement the canonical handoff schemas and pass focused tests.
- Signed records have enough remaining validity for the next phase.

Abort on unexpected entries, changed identity, symlink, hard link, unsafe mode
or owner, digest/signature mismatch, wrong principal/namespace, stale record,
replayed ID/nonce, ambiguous transfer, changed trust, restart uncertainty,
validation failure, or unresolved journal. Preserve evidence; never alter bytes
to make a retry pass.

Existing commands establish only part of preflight:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate authorization required}" && platform-pki ca-rollover status --namespace "${DEV_NAMESPACE:?current development namespace required}" --format json
```

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate authorization required}" && platform-pki ca-passphrase-verify --namespace "${DEV_NAMESPACE:?current development namespace required}" --root-pass-file "${DEV_ROOT_PASS_FILE:?mode-600 secret mount required}" --intermediate-pass-file "${DEV_INTERMEDIATE_PASS_FILE:?mode-600 secret mount required}"
```

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate backup authorization required}" && platform-pki backup --namespace "${DEV_NAMESPACE:?current development namespace required}" --age-recipient "${DEV_BACKUP_AGE_RECIPIENT:?reviewed recipient required}"
```

Do not use `--allow-plain-backup`. Never delete a journal to pass preflight.

## Frozen Schema-2 Trust
Trust is separately provisioned public policy, never payload supplied by a
request or response. Freeze exact schema-2 five-file trees at:

```text
Target: /var/lib/platform-config/pki/host-local/registry-dev/trust/<reviewed-trust-id>/
Host:   <exchange-root>/registry-dev/<request-id>/trust/
```

Each contains exactly `policy`, `requesters.allowed_signers`,
`approvers.allowed_signers`, `responses.allowed_signers`, and
`deployers.allowed_signers`. Record the directory identity, every file identity,
and every file SHA-256 before request creation. The host tree must byte-match the
reviewed source and the installed signer tree at
`<namespace>/pki/inventory/csr-trust/` at signing and decision time. Target and
host independently pin the same reviewed lifecycle trust.

The collection receipt records exact SHA-256 digests as
`trust_policy_sha256`, `request_trust_sha256`, `approval_trust_sha256`,
`response_trust_sha256`, and `deployment_trust_sha256` for `policy` and the four
allowed-signers files, respectively. The six response files never contain or
convey trust. Target activation rejects a changed response-trust file, identity,
or digest; evidence handling rejects changed deployment trust. The signer does
not technically bind request-time deployer trust until decision acceptance, so
schema-2 trust installation is prohibited while any request/candidate is
pending. Rotation starts only new requests after an empty-pending-state gate; it
never silently changes an in-flight request. The trust installer now rejects an
actual schema-2 change unless every retained signer candidate has an
authenticated finalized or abandoned outcome. This signer-side lifecycle-locked
gate cannot detect requests that remain only in this external workspace, so no
end-to-end rotation is permitted until the manual or automated lifecycle also
proves that external pending-request state is empty.

## Host Workspace
Use an owner-only mode-`700` root outside Git, the PKI tree, `/tmp`, and shared
storage:

```text
<exchange-root>/registry-dev/<request-id>/
|-- trust/                         # exact frozen schema-2 five-file tree
|-- request/
|   |-- tls.csr
|   |-- request
|   |-- request.sig
|   `-- collection-receipt
|-- approval/{approval,approval.sig}
|-- response/{artifact,tls.crt,ca-chain.crt,fullchain.crt,response,response.sig}
|-- evidence/<deployment-sha256>/{deployment,deployment.sig,validation-boundary,validation-result,validation-result.sig}
`-- transport/{request-download.batch,response-upload.batch,evidence-download.batch}
```

Files are singly linked and mode `600`. No `tls.key` is permitted. Approver and
response private keys stay outside this tree.

The controller creates `collection-receipt` only after collection verification.
Use the exact ordered schema in the canonical handoff's
[Controller Workspace And Transport Contract](handoffs/pki-host-local-csr-handoff.md#controller-workspace-and-transport-contract).
Do not omit or locally extend its five trust-digest fields. The receipt remains
non-authoritative and is not signer input.

## Constrained SFTP Spool
The SFTP identity and spool do not exist as an implemented repository feature.
The run is blocked until they are provisioned, tested, and reviewed.

Provision a unique account and client identity for this exact request ID, with
no shell, forwarding, PTY, command execution, or reuse by another request. Force
`internal-sftp` into a per-request chroot. Never permit root SSH. Every chroot
ancestor is root-owned and not writable by the account. Under the root-owned
physical chroot, use:

```text
<sftp-chroot>/registry-dev/<request-id>/
|-- out/request/                  # root-owned; account-readable, nonwritable
|   |-- tls.csr
|   |-- request
|   `-- request.sig
|-- out/evidence/<deployment-sha256>/  # root-owned; readable, nonwritable
|   |-- deployment
|   |-- deployment.sig
|   |-- validation-boundary
|   |-- validation-result
|   `-- validation-result.sig
`-- in/response/                  # account-writable transport intake
    |-- artifact.part
    |-- tls.crt.part
    |-- ca-chain.crt.part
    |-- fullchain.crt.part
    |-- response.part
    `-- response.sig.part
```

Inside the per-request chroot, SFTP sees only `/out` and `/in`; it never sees
`/etc/zot`, `/var/lib/platform-config`, the target key, root-only
request/evidence state, or another request ID. The unique account and identity
must be disabled after the exact lifecycle transfer closes and retained only as
non-secret custody metadata. Do not use bind mounts from root-only Zot state
into the chroot.

Root-side manual transitions are required and not implemented:

1. Request export identity-checks root-only pending source and spool destination,
   copies only `tls.csr`, `request`, `request.sig` to same-parent temporary
   files, rechecks sources, publishes no-clobber, and rechecks finals.
2. Response import snapshots all six account-writable `.part` identities and
   digests, validates exact allowlist, response signature, frozen response trust,
   request/artifact/profile bindings, and no extras, then copies only those six
   into a root-owned same-parent stage using temporary files/no-clobber
   publication. It rechecks spool sources and root destinations afterward.
3. Evidence export identity-checks one exact digest-keyed root-only evidence
   source and spool destination, exports only the five exact evidence files
   through temporary files/no-clobber publication, then rechecks source and
   finals. It never scans for an attempt.

The writable spool is untrusted transport state. SFTP success, owner, filename,
and spool digest are not PKI authority.

## SSH Host Pin And Client Controls
Every SFTP invocation uses all of:

```text
-o BatchMode=yes
-o IdentitiesOnly=yes
-o StrictHostKeyChecking=yes
-o HostKeyAlgorithms=ssh-ed25519
-o UpdateHostKeys=no
-o UserKnownHostsFile=<dedicated-owner-only-known-hosts>
-o GlobalKnownHostsFile=/dev/null
-i <dedicated-owner-only-sftp-client-identity>
```

The dedicated `known_hosts` contains exactly one unhashed line matching the
exact endpoint (including bracketed port form when applicable), exactly key type
`ssh-ed25519`, and exactly one base64 key field. It has no marker, hostname list,
comment, certificate, alternate host key, or additional line. Enroll it through
an independent authenticated process; never use `accept-new` or `ssh-keyscan` as
enrollment.

After strict parsing, `transport_host_key_sha256` is lowercase hexadecimal
SHA-256 over the binary SSH public-key blob obtained by base64-decoding the
line's third field. It is not the SHA-256 of text, a fingerprint display, or the
decoded Ed25519 raw key alone. Do not use an ad hoc shell parser. With exactly
one allowed key and `HostKeyAlgorithms=ssh-ed25519`,
`StrictHostKeyChecking=yes` binds negotiation to that reviewed key.

Use explicit `-b` batches, no wildcard, recursion, archive, `scp`, or `rsync`.
The invocation template is:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate transport authorization required}" && sftp -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UpdateHostKeys=no -o UserKnownHostsFile="${DEV_KNOWN_HOSTS:?dedicated pin required}" -o GlobalKnownHostsFile=/dev/null -i "${DEV_SFTP_IDENTITY:?per-request identity required}" -b "${SFTP_BATCH_FILE:?explicit batch required}" "${DEV_SFTP_USER:?per-request no-shell account required}@dev-registry-01"
```

## Phase 1: Root-Local Request Setup
This is a manual privileged target boundary, not an implemented command. Create
a fresh request ID, validate it before path use, and create its directory
no-clobber:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate request authorization required}" && \
  umask 077 && \
  REQUEST_ID=$(openssl rand -hex 16) && \
  [[ $REQUEST_ID =~ ^[0-9a-f]{32}$ ]] && \
  sudo mkdir -m 700 -- "/etc/zot/tls-pending/$REQUEST_ID" && \
  PENDING_DIR="/etc/zot/tls-pending/$REQUEST_ID"
```

`mkdir` must fail if the destination exists. Never select another ID after any
state has been published without preserving and reviewing the first attempt.
Generate and validate the nonce separately:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate request authorization required}" && NONCE=$(openssl rand -hex 32) && [[ $NONCE =~ ^[0-9a-f]{64}$ ]]
```

Retain it only in protected state.

Publish `request.cnf` through a fixed privileged boundary: write exact bytes to
`$PENDING_DIR/.request.cnf.part` under `umask 077`, fsync as required by the
reviewed manual procedure, identity-check an absent destination, and use
same-parent `mv --no-copy --update=none-fail` to `request.cnf`. Its exact content:

```ini
[req]
prompt = no
distinguished_name = dn
req_extensions = ext

[dn]
CN = registry.dev

[ext]
subjectAltName = DNS:registry.dev,DNS:dev-registry-01,IP:192.168.20.61
```

Generate the P-384 key and exact CSR under `umask 077`:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate request authorization required}" && sudo sh -c 'umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "$1/tls.key"' sh "${PENDING_DIR:?validated pending directory required}"
```

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate request authorization required}" && sudo openssl req -new -sha384 -key "${PENDING_DIR:?validated pending directory required}/tls.key" -config "${PENDING_DIR:?validated pending directory required}/request.cnf" -out "${PENDING_DIR:?validated pending directory required}/tls.csr"
```

Verify CSR signature, P-384 key, exact subject/SANs, no unreviewed extensions,
and equal key/CSR DER SPKI digests using protected same-directory files, never
`/tmp`. Build canonical `request` in this exact order:

```text
schema=1
request_id=<32-lowercase-hex>
nonce=<64-lowercase-hex>
created_epoch=<canonical-decimal-epoch>
expires_epoch=<canonical-decimal-epoch>
operation=migrate
service=registry-dev
target=dev-registry-01
requester_principal=dev-registry-01
inventory_sha256=<exact-installed-inventory-sha256>
csr_sha256=<tls.csr-sha256>
csr_spki_sha256=<DER-SPKI-sha256>
current_cert_sha256=<exact-proven-managed-predecessor-sha256>
profile=server-p384-sha384-v1
response_principal=<exact-policy-response-principal>
```

Request lifetime is positive and at most 604800 seconds; never backdate. Sign
with `/etc/ssh/ssh_host_ed25519_key` under the request namespace. Verify with the
frozen target `requesters.allowed_signers`. Root must open mode-`600` request
bytes inside the fixed privileged boundary; unprivileged shell redirection is
forbidden:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate request authorization required}" && sudo ssh-keygen -Y sign -f /etc/ssh/ssh_host_ed25519_key -n platform-pki-csr-request-v1 "${PENDING_DIR:?validated pending directory required}/request"
```

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate request authorization required}" && sudo sh -c 'exec ssh-keygen -Y verify -f "$1" -I dev-registry-01 -n platform-pki-csr-request-v1 -s "$2/request.sig" < "$2/request"' sh "${TARGET_REQUEST_TRUST:?frozen requester trust required}" "${PENDING_DIR:?validated pending directory required}"
```

Identity-check and remove only transient `request.cnf` and derived public files.
Recheck the final root-only tree contains exactly singly-linked mode-`600`
`tls.key`, `tls.csr`, `request`, `request.sig`. The key never enters the spool.

## Phase 2: Root Export And Host Collection
Root exports exactly three files to `out/request`. The host SFTP batch is exactly:

```text
get /out/request/tls.csr <local-stage>/tls.csr.part
get /out/request/request <local-stage>/request.part
get /out/request/request.sig <local-stage>/request.sig.part
```

The host verifies file metadata, CSR/profile/SPKI, canonical request, freshness,
managed predecessor, inventory, and request signature against frozen request
trust. It no-clobber-publishes the three files locally and creates the canonical
controller-produced receipt with `transport_host_key_sha256`,
all five canonical trust digests. Recheck all files and frozen trust identities.
Set `transport=sftp`; collection is not approval.

## Phase 3: Dedicated Approval
Use a dedicated development Ed25519 approver key on the development host, not
the target, CA, response, or transport key. After exact human review, create:

```text
schema=1
request_id=<request-request_id>
nonce=<request-nonce>
created_epoch=<canonical-decimal-epoch>
expires_epoch=<canonical-decimal-epoch>
approver_principal=<exact-policy-approver-principal>
request_sha256=<exact-request-sha256>
csr_sha256=<request-csr-sha256>
inventory_sha256=<request-inventory-sha256>
operation=migrate
service=registry-dev
target=dev-registry-01
profile=server-p384-sha384-v1
```

Approval cannot predate request and lasts at most 86400 seconds. The 24-hour
delay applies only if requester and approver resolve to the same Ed25519 key.
Separate target and approver keys permit immediate post-review approval, never
backdating or skipped review. Sign/verify under
`platform-pki-csr-approval-v1` against frozen approver trust.

For the removable-media profile, use `platform-pki offline-csr approve` with
the explicit service, `migrate` operation, request ID, three-file request
directory, protected approval key, and exact protected five-file destination.
That supported route performs the review, canonical record creation, signature,
verification, and no-clobber publication. The manual commands below remain
development evidence for this direct SFTP profile; they are not a second
production implementation.

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate approval authorization required}" && ssh-keygen -Y sign -f "${DEV_APPROVER_KEY:?protected dedicated approver key required}" -n platform-pki-csr-approval-v1 "${APPROVAL_DIR:?protected approval directory required}/approval"
```

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate approval authorization required}" && ssh-keygen -Y verify -f "${DEV_APPROVERS_ALLOWED_SIGNERS:?frozen approver trust required}" -I "${DEV_APPROVER_PRINCIPAL:?policy principal required}" -n platform-pki-csr-approval-v1 -s "${APPROVAL_DIR:?protected approval directory required}/approval.sig" < "${APPROVAL_DIR:?protected approval directory required}/approval"
```

## Phase 4: Existing Migration Signer
For the removable-media profile, use `platform-pki offline-csr sign` with the
explicit `migrate` coordinates and exact five-file approved directory. It
delegates to this same signer after authenticated review. For this direct SFTP
profile, after the selection gate and separate CA mutation authorization, use
exact `platform-pki service-issue`; do not pass `--current-cert-file`, `--days`,
or `--rotate-key`:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate CA signing authorization required}" && platform-pki service-issue registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --intermediate-pass-file "${DEV_INTERMEDIATE_PASS_FILE:?mode-600 secret mount required}" --csr-file "${REQUEST_DIR:?protected request directory required}/tls.csr" --request-file "${REQUEST_DIR:?protected request directory required}/request" --request-signature "${REQUEST_DIR:?protected request directory required}/request.sig" --approval-file "${APPROVAL_DIR:?protected approval directory required}/approval" --approval-signature "${APPROVAL_DIR:?protected approval directory required}/approval.sig" --response-key "${DEV_RESPONSE_KEY:?protected response key required}"
```

It consumes request ID/nonce before CA mutation, preserves managed state, and
publishes a pending certificate-only candidate/response. It performs no target
action.

## Phase 5: Export, Upload, And Root Import
Publish and digest-pin the exact six-file export:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate export authorization required}" && platform-pki certificate-export publish registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --request-id "${REQUEST_ID:?exact request ID required}"
```

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate export authorization required}" && platform-pki certificate-export resolve registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --request-id "${REQUEST_ID:?exact request ID required}" --manifest-sha256 "${ARTIFACT_MANIFEST_SHA256:?exact digest required}" --format path
```

The response batch uploads exactly six files, never trust:

```text
put <response>/artifact /in/response/artifact.part
put <response>/tls.crt /in/response/tls.crt.part
put <response>/ca-chain.crt /in/response/ca-chain.crt.part
put <response>/fullchain.crt /in/response/fullchain.crt.part
put <response>/response /in/response/response.part
put <response>/response.sig /in/response/response.sig.part
```

Root imports only those six after full validation and frozen response-trust
identity/digest recheck. Any changed response trust or spool source aborts.

## Phase 6: Manual Activation And Rollback
**Not implemented and not crash-safe.** Before mutation verify exact imported
response, frozen response trust, request/response/artifact/candidate bindings,
target key/CSR/cert match, exact profile/SANs/chain/issuer/validity, predecessor,
managed signer preservation, and no target journal/conflict.

Stage exactly:

```text
/etc/zot/tls-versions/<request-id>/
|-- tls.key
|-- tls.csr
|-- tls.crt
|-- ca-chain.crt
|-- fullchain.crt
|-- response
|-- response.sig
`-- artifact
```

Publish one complete same-filesystem version no-copy/no-clobber; never `latest`
or independent cert/key switches. Before Zot mutation, a future implementation
must fsync an identity-bound
`/var/lib/platform-config/pki/host-local/registry-dev/activation-journal` with
exact pre-state, stage, version, active/rollback records, configuration identity,
one recovery action, and a canonical initial deployment `created_epoch` reserved
immediately before mutation. The rollback deadline is at least that epoch plus
1209600, and the initial deployment bytes reuse the exact epoch. Publish the
journal-bound active and rollback records as part of mutation before validation;
on failure restore their exact predecessors or retain recovery-required state.
This manual design cannot claim durable recovery.

After separate activation/restart authorization, select the exact version,
restart the reviewed Zot unit, run strict local checks, then strict TLS and
read-only OCI checks from `dev-registry-runner-01`. Insecure TLS or mutating OCI
is not acceptance evidence. If validation cannot complete within the canonical
300-second epoch-ordering window, treat that as failure. On failure restore only
the identity-matched predecessor, restart/validate it, retain evidence, and stop.
Never alter CA state to undo deployment.

## Phase 7: Validation And Deployment Evidence
Use the exact canonical `validation-boundary` and `validation-result` schemas in
the [canonical handoff](handoffs/pki-host-local-csr-handoff.md#canonical-validation-files).
This run remains blocked until exact builders/parsers and versioned check
semantics are implemented and tested. Do not hash an ad hoc result.
`validation-result.sig` authenticates exact detailed review evidence under the
frozen deployment key and namespace; signed canonical deployment fields remain
authoritative for the signer candidate decision.

Reconstruct `candidate_sha256` exactly from authenticated response/export bytes
using the handoff's
[Candidate Digest Reconstruction](handoffs/pki-host-local-csr-handoff.md#candidate-digest-reconstruction).
Do not omit, reorder, or reinterpret any field. Use the first verified chain PEM
certificate digest exactly as specified there.

Canonical deployment field order remains:

```text
schema=1
request_id=<request-id>
nonce=<request-nonce>
operation=migrate
service=registry-dev
target=dev-registry-01
request_sha256=<request-sha256>
response_sha256=<response-sha256>
response_signature_sha256=<response.sig-sha256>
candidate_sha256=<exact-reconstructed-candidate-sha256>
artifact_request_id=<same-request-id>
artifact_manifest_sha256=<artifact-sha256>
certificate_sha256=<candidate-tls.crt-sha256>
certificate_spki_sha256=<candidate-SPKI-sha256>
chain_sha256=<ca-chain.crt-sha256>
fullchain_sha256=<fullchain.crt-sha256>
action=finalize
result=activated
local_certificate_sha256=<candidate-tls.crt-sha256>
local_key_spki_sha256=<candidate-SPKI-sha256>
local_key_certificate_match=true
served_certificate_sha256=<candidate-tls.crt-sha256>
served_intermediate_sha256=<exact-first-verified-chain-certificate-sha256>
validation_boundary_sha256=<exact-inventory-boundary-sha256>
validation_result=passed
activation_epoch=<canonical-decimal-epoch>
validation_epoch=<canonical-decimal-epoch>
rollback_state=retained
rollback_hold_until_epoch=<at-least-created_epoch-plus-1209600>
deployment_principal=dev-registry-01
created_epoch=<canonical-decimal-epoch>
expires_epoch=<canonical-decimal-epoch>
```

Evidence lasts at most 86400 seconds;
`activation_epoch <= validation_epoch <= created_epoch + 300`; hold is measured
from evidence creation. Sign with `/etc/ssh/ssh_host_ed25519_key` under
`platform-pki-csr-deployment-v1` and verify against frozen deployer trust.
Build `deployment` in a protected same-parent stage, derive and verify its
digest, then build/sign the digest-bound `validation-result`. After both
signatures and all cross-bindings pass, publish the complete directory
no-clobber as
`evidence/<request-id>/<deployment-sha256>/`.

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate evidence authorization required}" && sudo ssh-keygen -Y sign -f /etc/ssh/ssh_host_ed25519_key -n platform-pki-csr-deployment-v1 "${EVIDENCE_STAGE:?protected same-parent evidence stage required}/deployment"
```

Root must also open deployment bytes inside a fixed privileged verification
boundary; do not redirect a root-only evidence file from an unprivileged shell.

After building the canonical `validation-result` with the exact deployment
digest, sign and reverify its exact bytes under the same deployment namespace
and frozen deployer trust:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate evidence authorization required}" && sudo ssh-keygen -Y sign -f /etc/ssh/ssh_host_ed25519_key -n platform-pki-csr-deployment-v1 "${EVIDENCE_STAGE:?protected same-parent evidence stage required}/validation-result"
```

Root exports exactly five files to `out/evidence`; host fetches exactly:

```text
get /out/evidence/<deployment-sha256>/deployment <local-stage>/deployment.part
get /out/evidence/<deployment-sha256>/deployment.sig <local-stage>/deployment.sig.part
get /out/evidence/<deployment-sha256>/validation-boundary <local-stage>/validation-boundary.part
get /out/evidence/<deployment-sha256>/validation-result <local-stage>/validation-result.part
get /out/evidence/<deployment-sha256>/validation-result.sig <local-stage>/validation-result.sig.part
```

Host verifies metadata, exact schemas/digests, frozen trust, deployment
signature, and validation-result signature before no-clobber publication.
Supplemental files do not replace signed deployment fields.

## Phase 8: Historical Decision
Verify signer state, then independently recheck live target state:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate verification authorization required}" && platform-pki csr-candidate verify registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --request-id "${REQUEST_ID:?exact request ID required}" --format json
```

Output includes `live_state_claimed:false`. With separate finalization
authorization, use a TTY and do not add `--yes`:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate finalization authorization required}" && platform-pki csr-candidate finalize registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --request-id "${REQUEST_ID:?exact request ID required}" --artifact-manifest-sha256 "${ARTIFACT_MANIFEST_SHA256:?exact digest required}" --evidence-file "${EVIDENCE_DIR:?protected evidence directory required}/deployment" --evidence-signature "${EVIDENCE_DIR:?protected evidence directory required}/deployment.sig"
```

Finalization records historical evidence; it performs no deployment/discovery.

## Implemented Versus Manual
| Existing command | Implemented boundary |
| --- | --- |
| `platform-pki ca-rollover status` | CA/recovery status, not target state. |
| `platform-pki ca-passphrase-verify` | Point-in-time active CA key check. |
| `platform-pki backup` | Protected archive/receipt, not restore proof. |
| `platform-pki csr-trust-install` | Reviewed signer public trust installation. |
| `platform-pki service-issue` | Authenticated issue/migration pending candidate. |
| `platform-pki service-renew` | Authenticated renewal from accepted predecessor. |
| `platform-pki csr-recover` | Exact signing or resume-only finalization recovery. |
| `platform-pki certificate-export publish/resolve` | Exact six-file digest-pinned export. |
| `platform-pki csr-candidate verify/finalize/abandon` | Historical authenticated decisions; no live action. |

Host-local interruption recovery remains `platform-pki csr-recover`; managed
renewal uses `platform-pki service-recover`.

| Manual/future operation | Status |
| --- | --- |
| Migration hypothesis preflight | Manual; must prove exact active/predecessor/issuer/inventory state. |
| Per-request chroot/internal-sftp account, identity, and spool | Not implemented; provisioning gate. |
| Root request/evidence export and response import | Manual, no-clobber, exact allowlists. |
| Target request/version/journal/activation/recovery | Manual; future `platform-config`; not crash-safe. |
| Collection receipt and validation files | Canonical schemas documented; builders/parsers not implemented. |
| Zot restart/local/runner validation | Manual live operations. |
| Deployment evidence construction/signing | Manual; future `platform-config`. |
| Key/export cleanup | Not authorized. |

There is no executable target-request, target-activate, target-rollback,
receipt-builder, spool-export/import, or evidence-builder helper here.

## Renewal Design
Renewal is part of this full-lifecycle design/manual handoff only after migration
has a finalized authenticated active accepted-evidence predecessor. Recheck live
state, preserve current version, generate fresh key/CSR/ID/nonce, set
`operation=renew`, and bind exact current accepted certificate:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate renewal authorization required}" && platform-pki service-renew registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --intermediate-pass-file "${DEV_INTERMEDIATE_PASS_FILE:?mode-600 secret mount required}" --csr-file "${REQUEST_DIR:?renewal request directory required}/tls.csr" --request-file "${REQUEST_DIR:?renewal request directory required}/request" --request-signature "${REQUEST_DIR:?renewal request directory required}/request.sig" --approval-file "${APPROVAL_DIR:?renewal approval directory required}/approval" --approval-signature "${APPROVAL_DIR:?renewal approval directory required}/approval.sig" --response-key "${DEV_RESPONSE_KEY:?protected response key required}" --current-cert-file "${CURRENT_CERT_FILE:?exact accepted certificate required}"
```

Do not use `--days` or `--rotate-key`. Repeat exact export, constrained transport,
manual activation, validation, evidence, and decision design.

## Abandonment Design
For never activated candidate evidence, retain the full canonical deployment
schema and set exactly:

```text
action=abandon
result=not-activated
served_certificate_sha256=none
served_intermediate_sha256=none
validation_result=not-run
activation_epoch=none
validation_epoch=none
rollback_state=none
rollback_hold_until_epoch=none
```

For actual restored and strictly validated signer-known predecessor, set exactly:

```text
action=abandon
result=rolled-back
served_certificate_sha256=<exact-restored-predecessor-leaf-sha256>
served_intermediate_sha256=<exact-restored-predecessor-intermediate-sha256>
validation_result=passed
activation_epoch=<actual-candidate-activation-epoch>
validation_epoch=<actual-restored-predecessor-validation-epoch>
rollback_state=restored
rollback_hold_until_epoch=<at-least-created_epoch-plus-1209600>
```

Sign/transfer complete evidence and invoke interactively without `--yes`:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate abandonment authorization required}" && platform-pki csr-candidate abandon registry-dev --namespace "${DEV_NAMESPACE:?current development namespace required}" --request-id "${REQUEST_ID:?exact request ID required}" --artifact-manifest-sha256 "${ARTIFACT_MANIFEST_SHA256:?exact digest required}" --evidence-file "${EVIDENCE_DIR:?protected evidence directory required}/deployment" --evidence-signature "${EVIDENCE_DIR:?protected evidence directory required}/deployment.sig"
```

Abandonment is not revocation and deletes nothing.

## Recovery And Retry
Signing recovery uses exact journaled transaction and response key when required:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate signing recovery authorization required}" && platform-pki csr-recover --namespace "${DEV_NAMESPACE:?current development namespace required}" --transaction "csr-${REQUEST_ID:?journaled request ID required}" --response-key "${DEV_RESPONSE_KEY:?exact protected response key required}"
```

Omit `--response-key` only if journaled signature exists. Without `--yes`, confirm
the TTY. Pre-commit recovery restores exact CA state but consumes ID/nonce;
post-commit recovery never rolls back/re-signs and resumes exact publication.

Finalization recovery uses no transaction/response key and is resume-only:

```bash
: "${PKI_LIVE_AUTHORIZATION:?separate finalization recovery authorization required}" && platform-pki csr-recover --namespace "${DEV_NAMESPACE:?current development namespace required}"
```

Do not use `--yes`; confirm `recover candidate finalization`. It never inverts a
decision or rolls back target/CA state.

Exact export publish is idempotent; retry same service/request ID, never force,
latest, or another request. SFTP retry uses same bytes and fresh `.part` intake.
Root export/import never overwrites a final or trusts an ambiguous spool result.
If deployment evidence expires before signer acceptance while the exact identity
remains active, use the canonical fresh-attempt procedure: under lock, journal a
new `created_epoch`, atomically extend the rollback deadline, repeat every local
and remote validation within 300 seconds, and create/sign wholly new deployment
and validation-result bytes. Changing only timestamps is forbidden.

## Retention And Cleanup
Retain signer replay, transaction, candidate, response, export, trust, outcome,
and accepted historical pointer state; target pending/version, active, rollback,
journal, spool custody, and evidence state; local request, approval, response,
receipt, validation, and deployment evidence; managed controller key/export,
service tree, predecessor target pair/config, renewal history, and backups.

No cleanup is authorized. Do not delete, unlink, quarantine, rewrite, deduplicate,
hard-link, or permission-broaden any listed state. Expiry of the 14-day hold
permits a separate review, not cleanup. Unlinking does not prove secure erasure.

## Documentation Evidence
This document was derived from repository commands, canonical documentation, and
tests. Writing it did not establish the migration hypotheses, provision SFTP,
contact a host, inspect live state, run PKI commands, validate credentials, or
verify any live phase.
