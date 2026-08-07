# GitLab Generic Package Exchange for Host-Local PKI

> **STATUS: SELECTED PRODUCTION TRANSPORT DESIGN; NOT IMPLEMENTED,
> RUNTIME-VERIFIED, OR LIVE-AUTHORIZED.**
>
> This document selects self-managed GitLab CE 18.11.3 Generic Packages as the
> production online exchange for public host-local PKI artifacts. It is a design
> and future operator runbook, not an execution contract. It authorizes no live
> request, signing, activation, restart, validation, rollback, finalization,
> abandonment, token creation, package deletion, or cleanup.

Canonical PKI schemas, signature namespaces, commands, timing, replay state,
candidate state, and finalization remain in [OpenSSL PKI Helpers](pki-openssl.md),
especially [Authenticated Host-Local CSR Signing](pki-openssl.md#authenticated-host-local-csr-signing),
[Immutable Certificate-Only Export](pki-openssl.md#immutable-certificate-only-export),
and [Host-Local Candidate Decisions](pki-openssl.md#host-local-candidate-decisions).
Transport-neutral ownership and controller/target state remain in
[Host-Local PKI CSR Handoff](handoffs/pki-host-local-csr-handoff.md). Stop if
this design conflicts with either canonical document.

The [development direct SSH/SFTP runbook](pki-host-local-csr-development-runbook.md)
is a different development transport. It is not the production break-glass
path defined below and is not evidence of production readiness.

## Security Boundary

GitLab is an authenticated online transport for public artifacts. It is not a
PKI approver, signer, trust anchor, replay database, deployment authority,
source of current state, immutable archive, or sole recovery channel.

The target leaf key never leaves the target. The approver and signer are
disconnected from GitLab and other networks. Their private approval, CA, and
response-signing keys never enter a networked host. Human transfer operators
move allowlisted public bytes through controlled media. HTTPS, GitLab
authentication, package metadata, and GitLab SHA256 values are transport
evidence only; consumers independently validate canonical records, detached
signatures, frozen trust, exact digests, identities, freshness, and lifecycle.

No token value may enter a package payload, CI artifact, cache, log, exception,
controlled-media bundle, Git repository, ticket, or chat. Token values also
must not be expanded into command arguments or URLs. GitLab necessarily creates,
stores, validates, and revokes credential state; this design does not claim that
GitLab itself contains no credential material.

One project cannot grant permissions by package-name prefix to otherwise equal
project roles. A publisher capable of one family may attempt another family.
Canonical signatures prevent authority escalation, but cannot prevent package
blocking, deletion, quota exhaustion, or other denial of service.

## Architecture And Roles
| Role | Required responsibility | Forbidden responsibility |
| --- | --- | --- |
| Target | Generate and retain the leaf key; sign the request; activate one exact pinned response; sign deployment evidence. | Export the leaf key; select newest; trust GitLab as PKI authority. |
| CI/controller | Collect request files; create the collection receipt; preserve frozen requester, response, and deployer trust; publish and retrieve exact coordinates; run separately gated request and activation jobs. | Hold approver, CA, response-signing, or leaf keys; infer approval or live state. |
| GitLab transport | Store four Generic Package families in one dedicated private project and enforce configured package access. | Promise atomic multi-file publication, immutability, PKI authorization, or recovery sufficiency. |
| Online retrieval/transfer station | Enumerate, download, hash, and validate exact packages; stage allowlisted public files for controlled media. | Hold an approver or CA private key; choose newest package attempts. |
| Offline approver | Review the exact request and create `approval` and `approval.sig` while disconnected. | Connect to GitLab or place its private key on any networked host. |
| Transfer operator | Maintain media custody and move only stage-specific public allowlists. | Introduce exchange-provided trust or supply transport evidence as signer input. |
| Offline signer | Verify exact canonical command inputs, installed trust, inventory, freshness, and replay state; sign and later record exact deployment evidence. | Connect to GitLab; receive a leaf key; trust collection or transport records. |
| Real-client validator | Perform strict TLS and reviewed read-only application validation from the inventory-bound boundary. | Disable TLS validation, activate a certificate, or replace target-signed evidence. |

## Dedicated Project
Use one dedicated private project with Generic Packages enabled. Do not place
application source, unrelated packages, ordinary CI artifacts, releases, or
container images in it. Narrow exchange CI configuration is permitted.

The image is `18.11.3-ce.0`; visibility is private. Use only placeholders
`<PKI_EXCHANGE_PROJECT_ID>`, `<PKI_EXCHANGE_PROJECT_PATH>`, and
`<GITLAB_ORIGIN>` outside protected configuration.

Resolve placeholders only from protected configuration. Before any API request,
the future helper must bind the configured origin, project ID, and project path
to one provisioned exchange-project record, then address all package endpoints
by that exact project ID. It must not infer the project from package results.

## Package Coordinates
For exact canonical inventory service `<service>`, package names are:

```text
pki-exchange-request-<service>
pki-exchange-approval-<service>
pki-exchange-response-<service>
pki-exchange-evidence-<service>
```

The request ID is exactly 32 lowercase hexadecimal characters matching
`[0-9a-f]{32}`. Package versions are stage-specific:

| Stage | Exact `package_version` |
| --- | --- |
| Request | `<request-id>` |
| Approval | `<request-id>-<approval-file-sha256>` |
| Response | `<request-id>` |
| Evidence | `<request-id>-<deployment-file-sha256>` |

Each suffix is 64 lowercase hexadecimal characters and hashes the exact
canonical `approval` or `deployment` file, not its detached signature. The
digest suffix makes each fresh approval or deployment-evidence attempt a new
immutable coordinate. It is not a selector. The operator/controller must supply
the exact full stage version; no consumer may discover or choose newest, latest,
first, last, highest ID, or a neighboring digest suffix.

One file is transferred by each exact Generic Package endpoint:

```text
PUT /api/v4/projects/:id/packages/generic/:package_name/:package_version/:file_name
GET /api/v4/projects/:id/packages/generic/:package_name/:package_version/:file_name
```

Metadata endpoints are:

```text
GET /api/v4/projects/:id/packages?package_type=generic&package_name=:package_name&package_version=:package_version&status=:status
GET /api/v4/projects/:id/packages/:package_id/package_files
```

The `package_name` filter is fuzzy and never selects authority. The helper must
locally require exact package type, name, and version after querying through the
already bound project-ID endpoint.

## Package Status
Query every GitLab 18.11 documented package status explicitly, consuming every
page for each query: `default`, `hidden`, `processing`, `error`,
`pending_destruction`, and `deprecated`. Reject an unrecognized status.

Exactly one exact package object across all status queries is permitted. Accept
only status `default`. An exact `processing` object may be polled only for a
fixed, reviewed maximum attempt count and interval configured in the future
helper. Each poll repeats all status queries. Exhausting the bound fails closed.
An exact object in `hidden`, `error`, `pending_destruction`, `deprecated`, an
unknown status, or more than one status/object blocks the coordinate and opens
an incident. Status order and package ID never choose among objects.

After exact `default` acceptance, consume every package-file page and require
the exact stage file multiset and one asset per filename. Requery all statuses
and files immediately before publication success, media export, activation, or
evidence acceptance.

## Stage Allowlists
Each package contains exactly its payload plus `stage-manifest`:

| Stage | Exact payload in manifest order |
| --- | --- |
| Request | `tls.csr`, `request`, `request.sig`, `collection-receipt` |
| Approval | `approval`, `approval.sig` |
| Response | `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`, `response`, `response.sig` |
| Evidence | `deployment`, `deployment.sig`, `validation-boundary`, `validation-result`, `validation-result.sig` |

Directories, archives, hidden files, nested paths, duplicate filenames,
alternate names, and extras are forbidden. The controller creates
`collection-receipt` only after validating the three target-produced request
files under the exact [controller workspace schema](handoffs/pki-host-local-csr-handoff.md#controller-workspace-and-transport-contract).
It is audit evidence, not signer input.

The six response payload files are the immutable certificate export and contain
no leaf key. Frozen requester, response, and deployer trust is separately
provisioned and is never package payload. Before request creation, the
controller must retain the exact protected trust paths, identities, and digests;
collection records the five canonical trust digests in its receipt. Every
normal or break-glass activation requires the exact expected response-trust
digest and rejects a changed current trust file or trust supplied by the
response package. Evidence handling applies the same rule to deployer trust.

The evidence supplemental files must conform to the canonical
[validation-boundary and validation-result schemas](handoffs/pki-host-local-csr-handoff.md#canonical-validation-files).
Until their builders and parsers are implemented and tested, production
readiness is blocked. The signed canonical `deployment` fields remain authority;
supplemental files support exact reconstruction and validation but cannot
override them.

## Stage Manifest
`stage-manifest` is unsigned transport completion evidence, not PKI approval,
authority, replay protection, trust, or deployment evidence. It lists payload
only and never lists or hashes itself. It is printable ASCII with LF endings,
one final newline, no blanks, and this exact ordered grammar:

```text
schema=1
kind=pki-exchange-stage
stage=<request|approval|response|evidence>
service=<canonical-inventory-service>
request_id=<32-lowercase-hex>
package_version=<exact-stage-version>
payload_count=<4|2|6|5>
payload=<first-allowlisted-filename> sha256=<64-lowercase-hex>
payload=<next-allowlisted-filename> sha256=<64-lowercase-hex>
```

There is one `payload` line per allowlisted payload in table order. For approval,
the `package_version` suffix must equal the `approval` payload digest. For
evidence, it must equal the `deployment` payload digest. Request and response
`package_version` must equal `request_id`. Unknown, duplicate, reordered, or
trailing fields; CRLF; uppercase digests; missing final newline; and a listed
`stage-manifest` fail closed.

The publisher hashes protected local source, uploads payload files one at a
time, and uploads `stage-manifest` last. Manifest presence marks only attempted
completion. Consumers accept only after exact status/list checks, GitLab
`file_sha256` comparison, fresh local download hashing, manifest validation,
and independent canonical protocol verification all pass.

## Non-Atomic Publication
Generic multi-file upload is not atomic. Missing manifest, partial or extra
files, duplicate assets, digest disagreement, or conflicting bytes make the
coordinate unusable. Never approve, transfer to signer/target, activate, or
finalize from it.

GitLab checksum headers may be absent for redirected object-storage downloads.
Use package-file API SHA256 plus locally computed SHA256, and never headers
alone. A successful HTTP status proves only one request was accepted.

The future helper must implement application-level publish-once:

1. Acquire a protected CI `resource_group` keyed by exact project, stage,
   service, and full package version; one global exchange lock is also safe.
2. Query every documented status and all exact files before upload.
3. If absent, upload each payload once and the manifest last.
4. Resume a manifest-absent partial only when every existing asset exactly
   matches the protected original source; upload only missing exact files.
5. Treat a complete exact package as idempotent success after full revalidation.
6. Preserve and fail on any conflict, duplicate, unexpected manifest, ambiguous
   timeout, status anomaly, or uncertain source identity.

The configured duplicate behavior and this multi-file resume behavior must be
fixture-tested against exact GitLab image `18.11.3-ce.0`, including distinct
files in one name/version, repeated filenames, partial resume, and conflict.
Documentation or behavior on another version is insufficient runtime evidence.

## GitLab Controls And Limits
GitLab 18.11 permits duplicate behavior to be configured; its default allows
additional assets for the same name/version. Duplicate settings are not
immutability. Before implementation can be ready:

1. Disable Generic duplicate publication at the owning group with no exception
   matching `pki-exchange-*`.
2. Protect Generic packages matching `pki-exchange-*`. Permit push only to the
   CI publisher role and set deletion to a role the publisher does not hold, or
   the most restrictive supported setting.
3. Disable project package cleanup. Generic cleanup can delete older duplicate
   assets and must never run for this project.
4. Remove unrelated members, tokens, deploy tokens, schedules, integrations,
   and administrators where organizationally possible. Protect exchange CI
   configuration, triggering refs, runners, and environments.

Protection is access control, not write-once storage. Authorized higher roles
and administrators can change settings or delete package files, packages, the
project, backups, or storage. The API exposes package and file deletion.
Application controls cannot defeat a compromised administrator.

GitLab CE/Free must not be represented as providing Premium audit events. Keep
available pipeline/job records, package metadata, job-token authentication logs
where applicable, independent digests, and protected custody records. GitLab
administrators can alter or delete GitLab-local evidence; none is PKI authority.

## Credentials And Endpoint Allowlist
Primary publishers are protected manual CI jobs using `CI_JOB_TOKEN` on
protected refs and runners. Bind cross-project access to the exact exchange
project allowlist. Where supported, grant only fine-grained `READ_PACKAGES` and
`ADMIN_PACKAGES` needed for the allowed package endpoints. The protected
triggering user and effective publisher role must be able to push protected
packages but must not have package-delete, protection-setting, project-setting,
or membership authority. Fine-grained endpoint permission never overrides role
and package-protection denial.

An external online transfer downloader should use a dedicated deploy token with
only `read_package_registry` where Generic Package and project-protection
behavior is compatible. It receives no write scope. A dedicated project access
token with `api` and Developer role is a documented fallback only: `api` is
broad, and package protection must still deny deletion and settings authority.
No human directly publishes a package; disconnected outputs return to a
protected controller workspace and protected CI publishes them.

The audited helper allows only these methods and endpoint shapes:

```text
GET  /api/v4/projects/:id/packages?...exact approved query keys...
GET  /api/v4/projects/:id/packages/:package_id/package_files
GET  /api/v4/projects/:id/packages/generic/:name/:version/:file
PUT  /api/v4/projects/:id/packages/generic/:name/:version/:file
```

It rejects `DELETE`, settings, membership, token-management, arbitrary project,
and unrecognized endpoints. It validates redirect destinations under a reviewed
policy, never forwards credentials to an unapproved origin, constructs headers
without token bytes in argv/URLs, suppresses tracing, redacts errors, and never
persists token values in workspace or artifacts. Credentials remain revocable,
purpose-specific, expiration-bound, and inventoried by non-secret identifier.

## Offline Approval
1. Protected CI or the online retrieval station receives the exact request
   package version from the operator, queries all statuses, downloads each exact
   file, and independently verifies package, manifest, request signature, CSR,
   inventory binding, service, target, profile, and freshness.
2. The station writes a custody record and transfers only the four request
   payload files plus `stage-manifest` and the custody record to fresh controlled
   media. No credential or newly introduced trust key crosses this boundary.
3. The disconnected approver rehashes and revalidates the exact request against
   independently provisioned trust and policy, then creates canonical `approval`
   and `approval.sig`. The approver private key never enters a networked host.
4. Only `approval` and `approval.sig` return through controlled media into a
   protected controller workspace. The controller validates both, derives the
   approval-file digest version, creates `stage-manifest`, and protected CI
   publishes that exact approval attempt. Humans never publish directly.

A GitLab manual-job approval may gate CI, but never replaces detached PKI
`approval.sig` under `platform-pki-csr-approval-v1`.

## Offline Signer Input Boundary
The transfer station downloads the operator-supplied exact request and approval
versions and validates both complete packages. Controlled media may carry
transport records for custody, but the signer command-input stage contains
exactly `tls.csr`, `request`, `request.sig`, `approval`, and `approval.sig`.

Only those five are supplied to the canonical issue, migrate, or renew command.
`collection-receipt`, both `stage-manifest` files, package metadata, GitLab
checksums, and custody records are stored separately and are never command
inputs, signer trust, approval, or replay evidence. Signer trust and inventory
are independently installed protected local state.

The signer exports exactly the six response payload files. A transfer operator
moves them out through controlled media; the controller verifies them against
the independently frozen response trust and protected request state, creates the
response manifest, and protected CI publishes the response package at version
`<request-id>`.

## Fresh Attempts And Asynchronous Flow
Requests are valid for at most 604800 seconds. Approvals and deployment evidence
are each valid for at most 86400 seconds, with canonical clock-skew rules. An
approval that expires while its request remains valid may be recreated after
full disconnected review. New canonical approval bytes and signature produce a
new digest-suffixed approval version; every prior attempt remains retained.

If deployment evidence expires before signer acceptance, the target and
real-client boundary must repeat all required current-state, local, served-chain,
rollback, and application revalidation under the canonical evidence-attempt
journal. It reserves a fresh `created_epoch`, atomically extends the rollback
hold, and creates/signs fresh deployment and validation-result bytes. The new
deployment digest creates a new evidence version. Copying old results, changing
only timestamps, shortening the hold, or mutating an existing package is
forbidden.

If request freshness fails, or response freshness/acceptance policy fails before
activation, terminate that lifecycle attempt under canonical policy and create
a wholly fresh request ID and nonce. Never reuse the prior ID, nonce, request,
approval version, or response coordinate. Permanent signer state remains.

The complete asynchronous flow is:

1. A separately authorized manual request job generates and retains the target
   key, creates/signs the request, collects the three public target files,
   creates `collection-receipt` with `transport=ssh`, publishes request version
   `<request-id>`, and ends pending without activation.
2. The disconnected approval flow publishes one exact digest-suffixed approval
   attempt through protected CI.
3. The transfer operator supplies only the exact five signer command inputs.
   The offline signer verifies and signs through canonical commands, records
   permanent replay/transaction state, and publishes a local exact certificate
   export without network access.
4. Controlled media returns the six response files. Protected CI publishes
   response version `<request-id>`.
5. A separate manually authorized activation pipeline receives exact service,
   request ID, response package version, artifact-manifest SHA256, and the
   protected frozen response- and deployment-trust digests captured at request
   collection. It downloads no inferred package and verifies the separately
   provisioned trust.
6. The same future target activation helper verifies key/CSR/certificate,
   response signature, profile, chain, SANs, validity, exact artifact pin, and
   reconstructed candidate digest before durable activation and restart/reload.
7. The target and real-client validator perform strict canonical validation.
   The target creates signed deployment evidence, canonical supplemental
   validation files, and the detached validation-result signature. Protected CI
   publishes the operator-supplied exact
   digest-suffixed evidence attempt.
8. Controlled media carries the exact evidence payload to the offline signer.
   The operator may review the authenticated supplemental files, but supplies
   only `deployment` and `deployment.sig` to exact `finalize` or `abandon`.
   GitLab never claims or discovers live deployment.

## Production Break-Glass Import
GitLab must never be the sole recovery channel, especially when replacing a
future GitLab certificate issued by this PKI. Maintain an independent protected
copy of every activation-eligible exact response package: six response payload
files plus its `stage-manifest`, full exact package coordinate, package/manifest
digests, and custody record. Separately retain the exact frozen response-trust
snapshot and protected digest captured before request creation. Trust is not made
authoritative merely by appearing on recovery media.

The production break-glass design requires all of the following before use:

1. Read-only, custody-controlled removable media containing the exact retained
   response material and separately identified frozen trust snapshot/digests.
2. A pre-provisioned management workstation and controller local-transport mode
   that do not depend on GitLab package, DNS, TLS, database, or object storage.
3. The same future target activation helper used by normal transport, with an
   input provider that reads the exact local package instead of weakening any
   verification or state transition.
4. Operator-supplied exact service, request ID, artifact-manifest digest,
   response package identity, and expected frozen-trust digest.
5. Full manifest, response signature, independently provisioned trust, target
   key/CSR, certificate profile/chain, rollback, local validation, and strict
   real-client validation. TLS verification is never disabled.
6. The normal signed evidence return, offline finalization, incident custody,
   and retention rules.

Do not improvise with the development runbook, email, browser downloads, a new
trust file, or insecure TLS. Production readiness remains blocked until this
local mode, read-only media procedure, same-helper behavior, GitLab-certificate
circular-dependency scenario, and recovery custody are implemented and
rehearsed without production mutation.

## Retention And Failure Rules
Keep package cleanup disabled and retain every request, response, approval
attempt, evidence attempt, stage manifest, digest, and custody record. Define no
automatic duration. Separate deletion review is possible only after a canonical
terminal outcome and after certificate, predecessor, rollback, evidence, audit,
backup, legal, and operational policies permit it. It requires exact package
IDs/digests and explicit deletion authorization. Signer replay, transaction,
candidate, response, export, outcome, retained-trust, and historical-pointer
state remains permanently under canonical rules.

Retries are byte-exact at the same coordinate. A matching manifest-absent
partial may resume from protected original source; a complete exact package is
idempotent. Never repair a conflict, replace an expired attempt, append an ad hoc
retry suffix, delete an asset to make checks pass, or reuse a consumed request
ID or nonce.

- Missing manifest or payload: incomplete and unusable.
- Invalid list, digest, suffix, status, signature, freshness, trust, inventory,
  profile, chain, replay, lifecycle, or evidence: stop before the next phase.
- Conflict, duplicate, unknown status, or ambiguous object: preserve and open an
  incident; never choose by time or ID.
- Ambiguous upload response: query every status and exact file before any exact
  retry.
- GitLab outage: remain pending or use only the implemented, rehearsed production
  break-glass path. Never connect the signer or disable TLS.
- Activation/validation failure: use only identity-bound target recovery,
  preserve evidence, and create canonical abandonment evidence when permitted.

## Incident And Restore
1. Stop publishers and activation jobs; keep cleanup disabled and do not delete,
   overwrite, hide, deprecate, or republish affected coordinates.
2. Revoke suspected credentials and runner access. Record non-secret credential
   identifiers and times, never token values.
3. Preserve all status-query pages, package/file metadata, digests, pipeline/job
   records, available job-token authentication logs, controller stages, target
   journals, signer state, media, and custody records.
4. Determine authority only from independent canonical signatures, protected
   trust, target state, and signer state. GitLab compromise does not authorize
   re-signing, activation, finalization, abandonment, revocation, or deletion.
5. Quarantine conflicting coordinates. Restore transport only from independently
   verified exact bytes after protections, credentials, runners, duplicate
   behavior, cleanup, and administrator actions are reviewed.

A registry, database, object-storage, or full-instance restore may reintroduce
partial, old, duplicate, hidden, deprecated, or deleted assets. Suspend all
consumption after restore, upgrade, storage repair, or administrator intervention
until every in-flight coordinate passes all-status enumeration, exact file and
digest checks, and comparison with independent canonical state.

## Readiness Checklist

- [ ] Status remains selected design only; downstream implementation, runtime
  verification, and every live authorization are still separate gates.
- [ ] Image is exactly `18.11.3-ce.0`, or this design is re-evaluated against the
  deployed version's official documentation and fixtures.
- [ ] One private project is bound by protected exact ID/path/origin; package
  registry, protection, duplicate denial, and cleanup disablement are verified.
- [ ] Exact 18.11.3 fixtures cover distinct multi-file upload, duplicate denial,
  partial resume, conflicts, all statuses, pagination, bounded processing polls,
  digest-suffixed attempts, and concurrent `resource_group` publishers.
- [ ] CI publishers use exact allowlists and endpoint restrictions; publisher
  roles cannot delete packages or change project/package settings.
- [ ] External download is read-only; broad `api` Developer project tokens are
  documented fallback only; no human directly publishes.
- [ ] No token value reaches payloads, artifacts, logs, media, argv, URLs, Git,
  tickets, or chat; helper errors and redirects are tested for redaction.
- [ ] Offline approval media ingress/egress and exact five-file signer command
  input boundary are implemented, custody-tested, and free of private keys.
- [ ] The exact policy and requester, approver, response, and deployer trust are
  separately provisioned before request creation, captured as five receipt
  digests, rechecked through decision, and absent from package payloads.
- [ ] Canonical validation-boundary/result schemas and parsers are present;
  `validation-result.sig` authenticates exact detailed results under frozen
  deployer trust, and fresh evidence repeats strict target and client validation.
- [ ] No fuzzy/newest selection exists; every stage receives its exact package
  version and all prior approval/evidence attempts remain retained.
- [ ] Schema-2 trust rotation is blocked while any request/candidate is pending.
  The installer now lifecycle-locks and authenticates persisted candidate/outcome
  state; transport automation must still prove that no external request remains
  pending before rotation.
- [ ] Normal activation and local break-glass import use the same exact helper,
  artifact pin, trust digest, durable target state, rollback, and validation.
- [ ] Read-only recovery media and the GitLab-certificate circular-dependency
  procedure are implemented and rehearsed without disabling TLS.
- [ ] Request, signing, activation/restart, validation, rollback rehearsal,
  finalization/abandonment, incident recovery, and deletion each retain separate
  live authorization.

## Version-Pinned GitLab References

- [Generic Packages](https://docs.gitlab.com/18.11/user/packages/generic_packages/)
- [Package Protection Rules](https://docs.gitlab.com/18.11/user/packages/package_registry/package_protection_rules/)
- [Packages API](https://docs.gitlab.com/18.11/api/packages/)
- [CI/CD Job Token](https://docs.gitlab.com/18.11/ci/jobs/ci_job_token/)
- [Package Registry Cleanup](https://docs.gitlab.com/18.11/user/packages/package_registry/reduce_package_registry_storage/)

These sources support the selected design only. No GitLab instance, package
operation, helper, pipeline, credential, approver station, signer, target,
break-glass path, or runtime behavior has been verified by this document.
