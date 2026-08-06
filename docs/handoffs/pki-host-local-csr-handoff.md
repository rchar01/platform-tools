# Host-Local PKI CSR Handoff

## Status

This is the ownership and workflow handoff from `platform-tools` to
`platform-config`. It does not authorize a live request, deployment, restart,
migration, or key cleanup.

`platform-tools` implements reviewed trust installation, canonical signed
request and approval validation, authenticated P-384 CSR issue/migration/renew,
permanent replay state, certificate-only pending candidates, signed responses,
transactional CA publication, deterministic signer recovery, exact immutable
certificate-only export publication, and authenticated candidate evidence
verification/finalization/abandonment. It does not implement target request
collection, implicit/current candidate selection, live deployment or discovery,
service restart, revocation, or key cleanup. Those operations belong to
`platform-config` and remain separately gated from live execution.

The first downstream pilot is the dev Zot registry. Other services follow only
after its request, signing, activation, validation, rollback, and evidence path
passes this contract.

## Ownership

| Owner | Responsibility |
| --- | --- |
| `platform-tools` | Validate inventory and authenticated requests; enforce replay and candidate state; sign with the active intermediate; transactionally update CA state; publish authenticated certificate-only responses; verify deployment evidence; record immutable outcomes and accepted historical pointers; never receive a host leaf key. |
| `platform-config` | Generate and retain the destination key; build and authenticate the request; fetch only public request material; verify and activate one digest-pinned response; reload, validate, roll back, and return authenticated evidence. |
| `platform-private` | Store reviewed non-secret service, environment, target, identity, profile, trust-key, deployment, and validation policy. It stores no generated key, CSR, certificate, signature, or live exchange bundle. |
| Outside-Git state | Hold CA state, trusted signing identities, requests, responses, replay/candidate state, deployment evidence, target keys, and target pending/active/rollback state. |

`platform-tools` does not SSH to a target, deploy a certificate, reload a
service, or infer deployment from signer-side state. `platform-config` does not
hold a CA key, mutate a CA database, authorize names from CSR content, or copy a
leaf private key to the controller.

## Trust Boundary

A CSR signature proves possession of its private key. It does not prove that an
authorized host requested the identity in the CSR. An authenticated SSH fetch
also does not remain authoritative after its connection ends unless exact bytes
and the verified host identity are durably bound.

The completed protocol must enforce all of these independent proofs:

1. The target signs the exact canonical request bytes with its pre-provisioned
   SSH host identity under a dedicated PKI request namespace.
2. The request controller preserves the exact signed request, detached
   signature, and CSR bytes for transfer to the offline signer. Collection
   receipts remain a downstream requirement, not a signer input in schema 1.
3. A dedicated approver signs the exact reviewed request digest and bound CSR,
   inventory, operation, service, target, and profile. The approver private key
   is not stored on the Ansible controller.
4. The offline signer verifies the preserved target and approver signatures,
   inventory authorization, freshness, and replay state before CA mutation.
5. A dedicated offline response signer authenticates the exact response bytes.
   Its public key is pinned by the artifact controller and target. The CA key is
   never reused for exchange signatures.

Transferred public keys are not trust anchors. Host, approver, or response-key
replacement requires a separately authenticated provisioning procedure.

## Exchange Contract

The protocol uses bounded, canonical, versioned manifests and detached
signatures. Unknown or duplicate fields, noncanonical encoding, trailing data,
unsafe files, changed identities, expired records, and replayed IDs or nonces
fail before CA mutation or target activation.

The schema-1 request binds the request ID and nonce, creation and expiry times,
operation, service, target, requester principal, exact inventory and CSR
digests, CSR public-key digest, current-certificate digest when applicable,
fixed profile, and response principal. The schema-1 approval binds its creation
and expiry times, approver principal, exact request digest, and the request ID,
nonce, CSR, inventory, operation, service, target, and profile. The schema-1
response binds the request and approval digests, all request identities, issued
leaf/public-key/chain digests, issuer generations, serial, validity, pending
candidate state, response principal, and creation time. Exact ordered fields
and CLI examples are documented in
[Authenticated Host-Local CSR Signing](../pki-openssl.md#authenticated-host-local-csr-signing).
Schema 1 uses `target` as the canonical target inventory identity and requires
`requester_principal` to equal it exactly. Verification uses the installed
allowed-signers key for that principal, so one trusted requester cannot submit
for another target. A future distinct requester-to-target relationship requires
an explicit protected mapping and a versioned schema change.

The deployment evidence binds the request and response, immutable artifact,
target identity, local key/certificate match, served leaf and issuer,
validation boundary and result, activation time, rollback hold, and authorized
deployment signer.

The installed trust contract freezes OpenSSH `ssh-keygen -Y` detached Ed25519
signatures, the request, approval, and response namespaces, request and
approval timing limits, exact canonical request/approval/response schemas,
immutable signer response paths, and no automatic replay/candidate deletion.
Schema-2 deployment evidence, signer-side finalization/abandonment, and rollback
holds are now frozen. Target-side collection and live activation remain outside
this repository.

## Platform-Tools Prerequisite

The trust bootstrap accepts the exact schema-1 four-file set or the exact
schema-2 five-file set that adds `deployers.allowed_signers` from
`<private-repo>/pki/csr-trust`, and atomically installs validated public contents under
`<pki-dir>/inventory/csr-trust`. Allowed-signer records contain only a unique
principal, `ssh-ed25519`, and a valid public-key payload; the policy pins exactly
one approver and response principal. The exact policy schema and safety rules
are documented in [Host-Local CSR Trust](../pki-openssl.md#host-local-csr-trust).
Installing this trust performs no signing. A later authenticated issue or renew
invocation consumes the installed public trust.

The public signing path extends the existing transactional commands:

```text
platform-pki-service-issue SERVICE --csr-file PATH <authenticated-request-inputs>
platform-pki-service-renew SERVICE --csr-file PATH <authenticated-request-inputs>
```

`--csr-file` is allowed only for inventory `key_custody: host-local`, conflicts
with `--rotate-key`, and never authorizes CSR-controlled names or extensions.
The signer derives subject, SANs, EKU, key usage, and validity from one locked
inventory snapshot. It validates the CSR signature and approved EC P-384
profile, rejects unexpected or conflicting extensions, and proves the issued
certificate public key matches the CSR.

For a new service with no managed identity, issue may create a host-local
candidate directly. An existing service uses the explicit sequence:

```text
managed -> migration-pending -> host-local
```

Signing a migration request creates a certificate-only candidate and leaves the
managed identity and key-bearing export available for rollback. Only
authenticated deployment evidence may commit `host-local`. Abandonment returns
to `managed` without reusing request IDs or deleting evidence. Host-local
renewal creates another candidate; it does not replace a deployed identity by
signer-side inference.

The response is an immutable certificate-only artifact containing the leaf,
chain, response manifest, and response signature. It contains no leaf key, CA
key, passphrase, private inventory snapshot, or mutable Ansible export.

`platform-pki-certificate-export publish SERVICE --request-id ID` bridges one
explicit pending response into
`export/certificates/v1/artifacts/<service>/<request-id>/`. It validates the
exact source trees and the original signing transaction's retained response
trust snapshot, then publishes only `artifact`, `tls.crt`, `ca-chain.crt`,
`fullchain.crt`, `response`, and `response.sig`. The artifact states
`candidate_state=pending` and `deployment_state=unfinalized` and has no
publication timestamp.

Downstream automation must pin the reported artifact-manifest digest and call
`platform-pki-certificate-export resolve` with the exact service, request ID,
and digest. The resolver never scans or infers `current` or `latest`; its result
is not deployment evidence and does not authorize activation.

## Approved Registry Pilot Decisions

The public implementation must expose these as strict reviewed inputs rather
than silently selecting alternatives:

| Decision | Registry pilot value |
| --- | --- |
| Request and deployment signer | The target's pinned Ed25519 SSH host key, used under separate request and deployment namespaces |
| Target signer path | `/etc/ssh/ssh_host_ed25519_key` on `dev-registry-01` |
| Minimum rollback hold | 1209600 seconds (14 days) |
| Local validation | Strict Zot health and served-certificate validation on `dev-registry-01` |
| Real-client validation boundary | Strict TLS and read-only OCI validation from `dev-registry-runner-01` |

Using one physical host key does not merge protocol authority. The request and
deployment signatures use different namespaces and separately reviewed
`requesters.allowed_signers` and `deployers.allowed_signers` files. The private
host key remains on `dev-registry-01` and is never copied to the controller.

## Target State Contract

The coding agent must implement the registry pilot with these ownership
boundaries. Equivalent paths require a reviewed handoff update before coding;
they must not be chosen implicitly by an Ansible role.

```text
/etc/zot/
├── tls-pending/<request-id>/
│   ├── tls.key
│   ├── tls.csr
│   ├── request
│   └── request.sig
└── tls-versions/<request-id>/
    ├── tls.key
    ├── tls.csr
    ├── tls.crt
    ├── ca-chain.crt
    ├── fullchain.crt
    ├── response
    ├── response.sig
    └── artifact

/var/lib/platform-config/pki/host-local/registry-dev/
├── lock
├── active
├── rollback
├── activation-journal
├── validation-boundary
└── evidence/<request-id>/
    ├── deployment
    ├── deployment.sig
    └── validation-result
```

All state directories are root-owned mode `700`. Private keys, lock files,
journals, pointer records, request records, signatures, and evidence files are
mode `600` and singly linked. Public certificate files may be mode `600` or
`644`, but the implementation must choose one mode and verify it exactly.
Symlinks, hard-linked files, unexpected entries, unsafe ancestors, and
cross-filesystem publication are rejected.

`tls-pending/<request-id>` is created under the same parent filesystem as
`tls-versions`. Activation publishes the complete version with a no-copy,
no-clobber rename. Zot configuration points to the exact versioned certificate
and key paths; it does not use `latest`, a mutable certificate directory, or an
independently switched pair of symlinks. The strict `active` and `rollback`
records bind request ID, artifact digest, certificate/SPKI digests, version
path identity, activation time, and rollback deadline. They are records, not
filesystem inference.

The activation journal is written and fsynced before changing Zot
configuration or service state. It binds exact pre-state, staged-state, target
version, prior active record, rollback record, Zot configuration identity, and
the only allowed recovery action. Recovery never changes CA state and never
selects another artifact.

## Controller Exchange Contract

The controller uses one explicit owner-only outside-Git root supplied by
`PLATFORM_CONFIG_PKI_EXCHANGE_ROOT`. It must be mounted read-write into the
development container as a narrow dedicated mount; the complete
`~/.config/platform-infrastructure/` tree remains read-only.

```text
<exchange-root>/registry-dev/<request-id>/
├── request/
│   ├── tls.csr
│   ├── request
│   ├── request.sig
│   └── collection-receipt
├── response/
│   ├── artifact
│   ├── tls.crt
│   ├── ca-chain.crt
│   ├── fullchain.crt
│   ├── response
│   └── response.sig
└── evidence/
    ├── deployment
    ├── deployment.sig
    ├── validation-boundary
    └── validation-result
```

The controller never receives `tls.key`. Collection must use an explicit
allowlist of the four public request files; activation transfer must use the
exact six-file certificate export. `fetch`, `slurp`, registered output, facts,
debug, diffs, lookups, controller temporary files, and exception output must
never handle the private key.

The request run receives the exact reviewed inventory digest and response
principal as non-secret inputs. It does not copy the private inventory to the
target. The activation run receives an exact service, request ID, artifact
manifest digest, and response-trust snapshot; it never scans for a newer
response.

Response and deployment trust remain frozen from request collection through
finalization. A pending run must fail if the reviewed trust snapshot identity
changes. Trust rotation is a separate operation: publish and review the new
public trust, install it atomically, update target/controller pins, and begin
only new requests. Historical signer verification uses transaction-retained
trust; no public key supplied by an exchange bundle becomes trusted.

## Platform-Config Request Run

The request run is an explicit Ansible phase and never activates or restarts a
service.

1. Validate the reviewed service/host policy, target paths, OpenSSL availability,
   UTC time, current state, and absence of unresolved local transactions.
2. Under an owner-only pending generation, create an EC P-384 key with umask
   `077`, then create and locally verify the CSR from exact reviewed identities.
3. Build the canonical request, sign it with the pinned SSH host identity, and
   re-verify the signature locally.
4. Fetch only the CSR, request manifest, detached host signature, and non-secret
   collection inputs into an owner-only outside-Git controller directory.
5. Verify the host signature through the authenticated inventory binding and
   write the collection receipt. End with the request pending.

For `registry-dev`, require `operation=migrate` while the managed identity is
active. The request uses `target=requester_principal=dev-registry-01`,
`profile=server-p384-sha384-v1`, the exact reviewed inventory digest, the
current managed certificate digest, and the policy response principal. Generate
the request ID and nonce from the kernel CSPRNG. Request validity must not
exceed the signer policy.

`community.crypto` is not currently installed. The initial implementation uses
`ansible.builtin.command` with `argv` for OpenSSL and SSH-signing operations. It
must not use `shell`, command strings, pipelines, or unvalidated OpenSSL
configuration interpolation.

The private key must never be handled by `fetch`, `slurp`, controller-side
`copy src=`, lookups, registered stdout, facts, debug output, diffs, controller
temporary files, or command-line values.

## Platform-Config Activation Run

Activation is a separate phase requiring an authenticated response and explicit
live-change authorization.

1. Match the response to one pending local request and verify signer identity,
   exact manifest/signature, request and artifact digests, and target binding.
2. On the target, verify certificate/key and CSR/public-key matches, exact CN and
   SANs, chain, issuer, `CA:FALSE`, key usage, `serverAuth`, validity, and minimum
   remaining lifetime.
3. Stage the local key and certificate-only response as one immutable version.
   Preserve the prior active pair as rollback before changing a live pointer.
4. Activate atomically, restart or reload the application, and run strict local
   and external endpoint validation.
5. On failure, restore only identity-matched prior state, restart it, verify old
   service health, retain the journal/evidence, and fail closed.
6. Return authenticated deployment evidence. Do not delete the old pair or any
   controller/export key as part of activation.

The registry activation run must additionally:

1. Resolve only the operator-supplied service, request ID, and artifact digest.
2. Verify `response.sig` under `platform-pki-csr-response-v1` against the frozen
   reviewed response trust before copying any version into active paths.
3. Stop before mutation unless the pending key, CSR, response, artifact,
   certificate profile, chain, SANs, validity, and all recorded digests agree.
4. Preserve the exact prior Zot configuration and active identity as rollback
   state before selecting the new version.
5. Validate the restarted service locally, then validate strict TLS and a
   read-only OCI request from `dev-registry-runner-01` with the exact reviewed
   trust bundle. Insecure TLS flags are prohibited acceptance evidence.
6. Record served leaf and intermediate digests from the real-client boundary.
7. Build the exact deployment schema documented in `docs/pki-openssl.md`, set a
   rollback deadline at least 1209600 seconds after evidence creation, and sign
   it with `/etc/ssh/ssh_host_ed25519_key` under
   `platform-pki-csr-deployment-v1`.
8. Fetch only deployment evidence, its detached signature, and the canonical
   validation files into the controller exchange root.

The canonical validation-boundary file is retained alongside the evidence and
its SHA-256 digest must equal `validation_boundary_sha256` in the reviewed PKI
inventory. It binds `registry-dev`, `dev-registry-01`,
`dev-registry-runner-01`, `https://registry.dev/v2/`, the local Zot check, strict
TLS verification, served leaf/intermediate inspection, and read-only OCI API
validation. The coding agent must define and test one exact ordered schema; it
must not hash an ad hoc Ansible result.

Check mode creates no key, CSR, nonce, request, certificate, pointer, restart,
or consumed state. Repeating either successful phase is idempotent. A conflicting
pending request, response, active version, or transaction requires explicit
recovery or abandonment.

## Registry Pilot

The first target is `dev-registry-01` for service `registry-dev`:

| Field | Required value |
| --- | --- |
| Common name | `registry.dev` |
| DNS SANs | `registry.dev`, `dev-registry-01` |
| IP SAN | `192.168.20.61` |
| Endpoint | `https://registry.dev/v2/` |

The pilot requires separate authorization for request generation, signing,
activation/restart, mutating client tests, rollback rehearsal, and later key
quarantine. Acceptance requires strict TLS validation, the expected served
public key and chain, accepted `/v2/` behavior, real Podman pull/push and Helm
client validation where authorized, and a proven rollback path.

Controller service keys, mutable exports, destination rollback material, and
historical encrypted backups remain through their approved holds. Quarantine
and deletion are separate evidence-bound actions; unlinking does not establish
secure erasure.

## Required Platform-Config Tests

- Static checks reject any task that transfers, logs, registers, or exposes the
  private key.
- Request and activation check mode make no changes; normal reruns are
  idempotent.
- Reject symlinks, hard links, unsafe ownership/modes, stale IDs, substitutions,
  changed files, and unresolved journals.
- Reject wrong key, CSR, request, response signer, service, target, inventory,
  SAN, EKU, issuer, chain, validity, digest, request ID, nonce, and artifact.
- Prove no target mutation occurs before complete candidate validation.
- Inject staging, pointer, restart, strict-health, interruption, and rollback
  failures; preserve old service health or fail closed with recovery evidence.
- Exercise a disposable Rocky/Zot target before any real VM.
- Run `make verify`, syntax/check mode for both phases, and the separately
  authorized `make smoke-registry ENV=dev` acceptance.

The default test graph must include a static safety test that rejects any
private-key transfer/logging primitive and validates the two-playbook
separation. An opt-in disposable Rocky/Zot scenario must cover request,
activation, interruption, exact rollback, evidence generation, check-mode
non-mutation, and idempotency before a real VM is used.

## Coding And Live Gates

Public `platform-config` coding may implement this contract without changing
real inventory or contacting a live host. It must use separate explicit request
and activation playbooks; neither is imported by `site.yml` or normal registry
convergence.

The coding agent must not change `platform-private`, set
`key_custody: host-local`, remove managed registry inputs, enable strict client
validation in real inventory, or run a live request. Those changes require a
separate reviewed private-data handoff and authorization after public tests pass.

Live activation remains blocked until reviewed schema-2 public trust, the exact
validation-boundary record and digest, the 14-day rollback policy, the narrow
controller exchange mount, and target/client syntax and check-mode evidence are
present. Registry request generation, signing, activation/restart, mutating
client tests, rollback rehearsal, finalization, quarantine, and cleanup each
require separate authorization.

Do not substitute a leaf-key self-signature, a digest-only manifest, an
authenticated transport session, or a public key supplied with a request for
these durable trust bindings. Signer evidence, replay, candidates,
transactions, outcomes, and immutable exports are never deleted by
`platform-config`.
