# Direct Host-Local PKI Exchange

`platform-pki direct-exchange` moves exact public host-local PKI packages
between an operator transfer station and the restricted target endpoint managed
by `platform-config`. The operator client belongs to `platform-tools`; the
target facade, forced-command account, sudo broker, spool, and lifecycle helper
belong to `platform-config`.

The target never receives GitLab credentials and the exchange never transfers
`tls.key`. Every operation uses one protected endpoint record, a dedicated SSH
identity, an exact `known_hosts` record, and the reviewed host-key fingerprint.

## Commands

Pull an exact request:

```bash
platform-pki direct-exchange request-pull \
  /outside-git/endpoints/registry-dev.json \
  0123456789abcdef0123456789abcdef \
  /outside-git/intake/request-0123456789abcdef0123456789abcdef
```

Pull exact deployment evidence:

```bash
platform-pki direct-exchange evidence-pull \
  /outside-git/endpoints/registry-dev.json \
  0123456789abcdef0123456789abcdef \
  <artifact-sha256> <deployment-sha256> \
  /outside-git/intake/evidence-<deployment-sha256>
```

Push an authenticated response or terminal outcome:

```bash
platform-pki direct-exchange response-push \
  /outside-git/endpoints/registry-dev.json \
  0123456789abcdef0123456789abcdef \
  <artifact-sha256> /outside-git/response

platform-pki direct-exchange outcome-push \
  /outside-git/endpoints/registry-dev.json \
  0123456789abcdef0123456789abcdef \
  <artifact-sha256> <deployment-sha256> <outcome-sha256> \
  /outside-git/outcome
```

Pull destinations are no-clobber-published owner-only directories and verified
after every file is written. Successful `request-pull` and `evidence-pull`
compact JSON output includes `destination_dir`, the canonical absolute
destination directory validated by the command. Downstream commands should
consume and record `destination_dir` rather than reconstructing the path from
request or artifact coordinates.
Push inputs must be owner-only directories containing exactly the fixed package
allowlist. Coordinates, frame metadata, file sizes, remote results, endpoint
paths, identity metadata, and the host-key pin fail closed on disagreement.

Use the complete Ansible lifecycle and ordering procedure in the
[`platform-config` host-local registry PKI workflow](https://codeberg.org/rch/platform-config/src/branch/main/docs/registry-host-local-pki-workflow.md).
