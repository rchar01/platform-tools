# GitLab Generic Package Exchange for Host-Local PKI

> **STATUS: TRANSPORT HELPER IMPLEMENTED WITH FAKE HTTPS TESTS; NOT
> GITLAB-RUNTIME-VERIFIED, END-TO-END PRODUCTION-READY, OR LIVE-AUTHORIZED.**
>
> This document selects self-managed GitLab CE 18.11.3 Generic Packages as the
> production online exchange for public host-local PKI artifacts. The Generic
> Package helper implements this transport contract, but the document remains a
> design and future operator runbook for the full workflow. It authorizes no live
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

The [development host-local registry runbook](pki-host-local-csr-development-runbook.md)
points to the implemented transport-neutral lifecycle. It does not make this
GitLab transport runtime-qualified or production-ready.

Transfer-station directories, GitLab project controls and credentials, target
SSH preparation, and offline workspace setup are canonical in the public
[`platform-config` PKI Exchange Setup](https://codeberg.org/rch/platform-config/src/branch/main/docs/pki-exchange-setup.md).

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
| Online controller/transfer station | Pull request and evidence through pinned SSH; create the collection receipt; preserve frozen requester, response, and deployer trust; publish and retrieve exact coordinates; run separately gated target operations. | Hold approver, CA, response-signing, or leaf keys; infer approval or live state. |
| GitLab transport | Store five Generic Package families in one dedicated private project and enforce configured package access. | Promise atomic multi-file publication, immutability, PKI authorization, or recovery sufficiency. |
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
the helper must bind the configured origin, project ID, and project path
to one provisioned exchange-project record, then address all package endpoints
by that exact project ID. It must not infer the project from package results.

## Package Coordinates
For exact canonical inventory service `<service>`, package names are:

```text
pki-exchange-request-<service>
pki-exchange-approval-<service>
pki-exchange-response-<service>
pki-exchange-evidence-<service>
pki-exchange-outcome-<service>
```

The request ID is exactly 32 lowercase hexadecimal characters matching
`[0-9a-f]{32}`. Package versions are stage-specific:

| Stage | Exact `package_version` |
| --- | --- |
| Request | `<request-id>` |
| Approval | `<request-id>-<approval-file-sha256>` |
| Response | `<request-id>` |
| Evidence | `<request-id>-<deployment-file-sha256>` |
| Outcome | `<request-id>-<outcome-file-sha256>` |

Each suffix is 64 lowercase hexadecimal characters and hashes the exact
canonical `approval`, `deployment`, or `outcome` file, not its detached
signature. The digest suffix makes each fresh approval, deployment-evidence, or
terminal-outcome attempt a new
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
fixed, reviewed maximum attempt count and interval configured in the helper.
Each poll repeats all status queries. Exhausting the bound fails closed.
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
| Outcome | `outcome`, `outcome.sig`, `deployment`, `deployment.sig`, `deployers.allowed_signers`, `decision` |

Directories, archives, hidden files, nested paths, duplicate filenames,
alternate names, and extras are forbidden. The controller creates
`collection-receipt` only after validating the three target-produced request
files under the exact [controller workspace schema](handoffs/pki-host-local-csr-handoff.md#controller-workspace-and-transport-contract).
It is audit evidence, not signer input.

The six response payload files are the immutable certificate export and contain
no leaf key. Frozen requester, response, and activation-time deployer trust is
separately provisioned and is never selected from request, response, or evidence
payloads. The outcome family intentionally carries the exact signer-retained
`deployers.allowed_signers` bytes as historical terminal evidence; consumers
must authenticate the signed outcome and exact digest bindings and must not
treat those package bytes as current trust. Before request creation, the
controller must retain the exact protected trust paths, identities, and digests;
collection records the five canonical trust digests in its receipt. Every
normal or break-glass activation requires the exact expected response-trust
digest and rejects a changed current trust file or trust supplied by the
response package. Evidence handling applies the same rule to deployer trust.

The evidence supplemental files must conform to the canonical
[validation-boundary and validation-result schemas](handoffs/pki-host-local-csr-handoff.md#canonical-validation-files).
The transport helper parses their exact grammar and cross-bindings, but full
production readiness remains separately gated. The signed canonical
`deployment` fields remain authority; supplemental files support exact
reconstruction and validation but cannot override them.

## Stage Manifest
`stage-manifest` is unsigned transport completion evidence, not PKI approval,
authority, replay protection, trust, or deployment evidence. It lists payload
only and never lists or hashes itself. It is printable ASCII with LF endings,
one final newline, no blanks, and this exact ordered grammar:

```text
schema=1
kind=pki-exchange-stage
stage=<request|approval|response|evidence|outcome>
service=<canonical-inventory-service>
request_id=<32-lowercase-hex>
package_version=<exact-stage-version>
payload_count=<4|2|6|5|6>
payload=<first-allowlisted-filename> sha256=<64-lowercase-hex>
payload=<next-allowlisted-filename> sha256=<64-lowercase-hex>
```

There is one `payload` line per allowlisted payload in table order. For approval,
the `package_version` suffix must equal the `approval` payload digest. For
evidence, it must equal the `deployment` payload digest. For outcome, it must
equal the `outcome` payload digest. Request and response `package_version` must
equal `request_id`. Unknown, duplicate, reordered, or
trailing fields; CRLF; uppercase digests; missing final newline; and a listed
`stage-manifest` fail closed.

The publisher hashes protected local source, uploads payload files one at a
time, and uploads `stage-manifest` last. Manifest presence marks only attempted
completion. Consumers accept only after exact status/list checks, GitLab
`file_sha256` comparison, fresh local download hashing, manifest validation,
and independent canonical protocol verification all pass.

The implemented `platform-pki gitlab-package` command exposes
generic `publish` and `download` operations. Both require explicit stage,
service, target, request ID, exact full package version, protected project
record, token file/type, and CA file. Publish accepts one protected payload-only
`--source-dir` and generates the manifest. Download accepts one exact
`--destination-dir`; after complete validation and a second coordinate
inspection, it publishes payload plus manifest from a same-parent protected
stage with atomic no-clobber rename. An exact safe existing destination is
idempotent and a conflict is preserved and rejected. Request transport also
requires the reviewed inventory record, frozen five-file trust directory, and
transport host-key digest so its existing CSR, request-signature, inventory,
receipt, and trust validation is not weakened.

## Non-Atomic Publication
Generic multi-file upload is not atomic. Missing manifest, partial or extra
files, duplicate assets, digest disagreement, or conflicting bytes make the
coordinate unusable. Never approve, transfer to signer/target, activate, or
finalize from it.

GitLab checksum headers may be absent for redirected object-storage downloads.
Use package-file API SHA256 plus locally computed SHA256, and never headers
alone. A successful HTTP status proves only one request was accepted.

The helper implements application-level resume and idempotency within one
invocation. External publication must serialize each exact coordinate:

1. Acquire a protected CI `resource_group` or an equivalent reviewed operator
   lock keyed by exact project, stage, service, and full package version; one
   global exchange lock is also safe. The helper does not acquire this lock.
2. The helper queries every documented status and all exact files before upload.
3. If absent, it uploads each payload once and the manifest last.
4. It resumes a manifest-absent partial only when every existing asset exactly
   matches the protected original source; upload only missing exact files.
5. It treats a complete exact package as idempotent success after full
   revalidation.
6. It preserves and fails on any conflict, duplicate, unexpected manifest, ambiguous
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
Primary publishers are protected manual CI jobs using a dedicated project
access token with `api` scope and the minimum package-push role. Provide it only
through a protected masked file variable on protected refs and runners. The
helper requires `GET /api/v4/projects/:id`, but current GitLab ordinary and
fine-grained job-token documentation does not list that endpoint. Treat
`CI_JOB_TOKEN` as unqualified until exact-version runtime tests prove the
complete endpoint set or the authentication design removes that request. The
effective publisher role must be able to push protected packages but must not
have package-delete, protection-setting, project-setting, or membership
authority. Token permission never overrides role and package-protection denial.

GitLab 18.11's Generic Packages documentation explicitly supports an external
online transfer downloader using a dedicated project access token with `api`
scope and Developer role. This credential is not inherently read-only. The
helper permits only GET requests in reader operations, but the same credential
can call broader APIs outside the helper. Role-based package protection cannot
deny publication to a Developer reader while allowing a Developer publisher; it
may still impose a higher deletion threshold. Treat this as a qualification
blocker unless the narrower `read_api` scope passes complete exact-version tests
or the credential design changes. GitLab describes `read_api` as including
package-registry reads but does not document it for the complete Generic Package
project-token flow; tests must cover project authentication, package listing,
package-file listing, and download.
The helper authenticates `GET /api/v4/projects/:id` before every package
operation, and deploy tokens cannot authenticate the GitLab public API, so a
deploy token with only `read_package_registry` cannot run the complete helper.
A publisher project access token needs `api` and the minimum package-push role;
`api` is broad, so package protection must still deny deletion and settings
authority.
Disconnected outputs return to a protected online workspace. An explicitly
authorized transfer operator may run the helper with a dedicated protected
publisher credential, or protected CI may publish them. Neither path gives the
offline approver or signer network access.

The audited helper allows only these methods and endpoint shapes:

```text
GET  /api/v4/projects/:id
GET  /api/v4/projects/:id/packages?...exact approved query keys...
GET  /api/v4/projects/:id/packages/:package_id/package_files
GET  /api/v4/projects/:id/packages/generic/:name/:version/:file
PUT  /api/v4/projects/:id/packages/generic/:name/:version/:file
```

It rejects `DELETE`, settings, membership, token-management, arbitrary project,
unrecognized endpoints, and every redirect. It never forwards credentials to
another origin, constructs headers
without token bytes in argv/URLs, suppresses tracing, redacts errors, and never
persists token values in workspace or artifacts. Credentials remain revocable,
purpose-specific, expiration-bound, and inventoried by non-secret identifier.

## Offline Approval
1. Protected CI or the online retrieval station receives the exact request
   package version from the operator, queries all statuses, downloads each exact
   file, and independently verifies package, manifest, request signature, CSR,
   inventory binding, service, target, profile, and freshness.
2. The station retains `collection-receipt`, `stage-manifest`, package metadata,
   and its custody record in the protected online workspace. It transfers only
   `tls.csr`, `request`, and `request.sig` to fresh controlled media. No
   credential, transport record, or newly introduced trust key crosses this
   boundary.
3. The disconnected approver rehashes and revalidates the exact request against
   independently provisioned trust and policy, then creates canonical `approval`
   and `approval.sig`. The approver private key never enters a networked host.
4. Only `approval` and `approval.sig` return through controlled media into a
   protected controller workspace. The controller validates both, derives the
   approval-file digest version, creates `stage-manifest`, and an authorized
   online transfer station or protected CI publishes that exact approval
   attempt.

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
   response manifest, and an authorized online transfer station or protected CI
   publishes the response package at version `<request-id>`.

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
2. The disconnected approval flow returns one exact digest-suffixed approval
   attempt for publication by an authorized online transfer station or protected
   CI.
3. The transfer operator supplies only the exact five signer command inputs.
   The offline signer verifies and signs through canonical commands, records
   permanent replay/transaction state, and publishes a local exact certificate
   export without network access.
4. Controlled media returns the six response files. The authorized online
   transfer station publishes response version `<request-id>`.
5. A separate manually authorized target operation receives exact service,
   request ID, response package version, artifact-manifest SHA256, and the
   protected frozen response- and deployment-trust digests captured at request
   collection. It downloads no inferred package and verifies the separately
   provisioned trust.
6. The implemented target lifecycle helper verifies key/CSR/certificate,
   response signature, profile, chain, SANs, validity, exact artifact pin, and
   reconstructed candidate digest before durable activation and restart/reload.
7. The target and real-client validator perform strict canonical validation.
   The target creates signed deployment evidence, canonical supplemental
   validation files, and the detached validation-result signature. The
   authorized online transfer station publishes the operator-supplied exact
   digest-suffixed evidence attempt.
8. Controlled media carries the exact evidence payload to the offline signer.
   The operator may review the authenticated supplemental files, but supplies
   only `deployment` and `deployment.sig` to exact `finalize` or `abandon`.
   GitLab never claims or discovers live deployment.
9. After the signer publishes and reauthenticates the immutable six-file
   terminal outcome export, controlled media returns those exact files.
   The authorized online transfer station publishes outcome version
   `<request-id>-<sha256(exact-outcome-bytes)>`. Retrieval reports historical
   signer evidence only and never claims current target state.
10. The transfer station downloads that exact outcome coordinate, pushes only
    the six outcome payload files through pinned SSH, and invokes the target's
    authenticated check then import sequence. It verifies terminal status,
    decision preflight, normal configuration convergence, and smoke checks
    before separately authorized exact cleanup.

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
3. The same implemented target lifecycle helper used by normal transport, with an
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
trust file, or insecure TLS. Production readiness remains blocked until the
read-only media procedure, same-helper behavior, GitLab-certificate
circular-dependency scenario, and recovery custody are reviewed and rehearsed
without production mutation.

## Retention And Failure Rules
Keep package cleanup disabled and retain every request, response, approval
attempt, evidence attempt, terminal outcome package, stage manifest, digest, and
custody record. Define no
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

- [x] The five-family helper, bounded fake HTTPS transport tests, exact manifest
  contract, publish/resume, and atomic no-clobber download are implemented.
- [ ] Exact GitLab runtime verification, end-to-end workflow qualification, and
  every live authorization remain separate gates.
- [ ] Image is exactly `18.11.3-ce.0`, or this design is re-evaluated against the
  deployed version's official documentation and fixtures.
- [ ] One private project is bound by protected exact ID/path/origin; package
  registry, protection, duplicate denial, and cleanup disablement are verified.
- [ ] Exact 18.11.3 fixtures cover distinct multi-file upload, duplicate denial,
  partial resume, conflicts, all statuses, pagination, bounded processing polls,
  digest-suffixed attempts, and concurrent `resource_group` publishers.
- [ ] CI publishers use exact allowlists and endpoint restrictions; publisher
  roles cannot delete packages or change project/package settings.
- [ ] External download either qualifies a narrower truly read-only credential
  against every helper endpoint or explicitly accepts the documented `api`
  Developer token's write capability; role-based package protection cannot
  separate same-role reader and publisher push access, and no human directly
  publishes.
- [ ] No token value reaches payloads, artifacts, logs, media, argv, URLs, Git,
  tickets, or chat; helper errors and redirects are tested for redaction.
- [ ] Offline approval media ingress/egress and exact five-file signer command
  input boundary are implemented, custody-tested, and free of private keys.
- [ ] The exact policy and requester, approver, response, and deployer trust are
  separately provisioned before request creation, captured as five receipt
  digests, and rechecked through decision. Outcome payload may retain the exact
  historical deployer trust only as signed digest-bound terminal evidence; it
  never selects current trust.
- [ ] Canonical validation-boundary/result schemas and parsers are present;
  `validation-result.sig` authenticates exact detailed results under frozen
  deployer trust, and fresh evidence repeats strict target and client validation.
- [ ] No fuzzy/newest selection exists; every stage receives its exact package
  version and all prior approval/evidence/outcome attempts remain retained.
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

These sources support the selected design and implemented API shape. Fake HTTPS
tests do not verify a GitLab instance. No live package operation, pipeline,
credential, approver station, signer, target, break-glass path, or production
runtime behavior has been verified by this document.
