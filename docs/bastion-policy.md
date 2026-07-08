# Bastion Policy

`platform-bastion-policy` validates and renders Kubernetes bastion access-policy documents.

The source policy is a private YAML document with `apiVersion: bastion.access/v1`. It is the single source of truth for host bastion access and for the Kubernetes CSR policy projection used by the bastion certificate controller flow.

Real policies can reveal users, groups, cluster endpoints, and access intent. Keep real policy files in `platform-private`; only fake examples belong in this repository.

## Requirements

- `python3`
- `PyYAML`

## Render Flow

```text
platform-private access policy
  -> platform-bastion-policy validation and rendering
  -> platform-config managed host file and Kubernetes ConfigMap
```

`platform-tools` renders files only. `platform-config` owns host deployment and Kubernetes apply workflows. `platform-k8s-bastion` owns the runtime behavior that consumes `/etc/bastion/access-policy.yaml`.

## Outputs

- Host bastion config: `/etc/bastion/access-policy.yaml`
- Kubernetes CSR policy ConfigMap: `bastion-system/bastion-csr-policy`, key `policy.yaml`

## Validate A Policy

```bash
platform-bastion-policy validate \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml
```

Validation checks the API version, required sections, TTL ordering, Linux-compatible user/group names, and user group references.

## Render The Host Policy

```bash
POLICY_OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-policy.XXXXXX")"

platform-bastion-policy render-host \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml \
  --output "$POLICY_OUT_DIR/access-policy.yaml"
```

Host rendering validates the source policy and writes the full policy unchanged except for deterministic YAML formatting. Output files are created with owner-only permissions and must not already exist.

## Render The CSR ConfigMap

```bash
platform-bastion-policy render-csr-configmap \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml \
  --name bastion-csr-policy \
  --namespace bastion-system \
  --output "$POLICY_OUT_DIR/bastion-csr-policy.configmap.yaml"
```

The ConfigMap projection includes only:

- `apiVersion: bastion.csr-policy/v1`
- `csr.signerName`
- `csr.groupPrefix`
- `csr.ttl.minSeconds`
- `csr.ttl.defaultSeconds`
- `csr.ttl.maxSeconds`
- `csr.cleanup.retentionSeconds`
- `groups`
- `users`

It omits host-only fields: `cluster`, `daemon`, `bootstrap`, and `csr.renewal`.

## Source Policy Schema

Top-level fields:

- `apiVersion`: must be `bastion.access/v1`.
- `cluster`: host-only Kubernetes cluster connection metadata.
- `csr`: certificate signing request policy shared by the host and controller.
- `bootstrap`: host-only bootstrap credential lifetime policy.
- `daemon`: host-only daemon settings.
- `groups`: allowed access groups and group metadata.
- `users`: allowed Linux users and their required groups.

Required `cluster` fields:

- `name`: non-empty cluster name.
- `server`: non-empty Kubernetes API server URL.
- `caFile`: non-empty path to the host CA file.

Required `csr` fields:

- `signerName`: non-empty Kubernetes CSR signer name.
- `groupPrefix`: non-empty group prefix used by the runtime/controller.
- `ttl.minSeconds`: integer minimum certificate lifetime.
- `ttl.defaultSeconds`: integer default certificate lifetime.
- `ttl.maxSeconds`: integer maximum certificate lifetime.
- `renewal.thresholdSeconds`: integer host renewal threshold.
- `cleanup.retentionSeconds`: integer controller cleanup retention.

The CSR TTL values must satisfy:

```text
csr.ttl.minSeconds <= csr.ttl.defaultSeconds <= csr.ttl.maxSeconds
```

Required `bootstrap` fields:

- `ttl.defaultSeconds`: integer default bootstrap lifetime.
- `ttl.maxSeconds`: integer maximum bootstrap lifetime.

The bootstrap TTL values must satisfy:

```text
bootstrap.ttl.defaultSeconds <= bootstrap.ttl.maxSeconds
```

Required `daemon` fields:

- `allowedLoginGroup`: non-empty Linux group allowed to use the daemon.
- `socket.path`: non-empty daemon socket path.
- `request.maxBytes`: integer maximum request size.
- `request.timeoutSeconds`: integer request timeout.
- `rateLimit.failureBackoffSeconds`: integer failure backoff.

`groups` must be a mapping. Group names must match the current runtime Linux-name pattern:

```text
^[a-z_][a-z0-9_-]{0,31}$
```

`users` must be a mapping. User names must match the same Linux-name pattern as groups. Each user must define `ensureGroups` as a non-empty list of group names, and every referenced group must exist under `groups`.

User and group names must match the full pattern value; newline-suffixed names and other control-character variants are rejected.

## Examples

Public fake examples live under `examples/bastion-policy/`:

- `access-policy.example.yaml`
- `bastion-csr-policy.configmap.example.yaml`

Run the example validation directly from a checkout:

```bash
./bin/platform-bastion-policy validate \
  --input examples/bastion-policy/access-policy.example.yaml
```

## Testing

Run the bastion policy render tests from this repository:

```bash
make test-bastion-policy
```
