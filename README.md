<div align="center">
  <img src="assets/brand/platform-tools-forge-avatar-transparent-512.png" width="256" alt="platform-tools logo">

  <h1>platform-tools</h1>

  <p>Shared helper tools for platform infrastructure, PKI, Proxmox, SSH, bastion policy, and local operator workflows.</p>
</div>

---

`platform-tools` provides reusable command-line helpers used across the platform project repositories.

Canonical repository: <https://codeberg.org/rch/platform-tools>

All shared platform helper tools live in this repository. The platform repositories are split by responsibility so provisioning, configuration, deployment, runtime tooling, private operator config, template building, and shared helpers can evolve independently.

## Platform Repositories

| Repository | Purpose |
| --- | --- |
| [`platform-config`](https://codeberg.org/rch/platform-config) | Configures operating systems and services with Ansible. |
| [`platform-deployments`](https://codeberg.org/rch/platform-deployments) | Owns Helm chart source plus deployment values and overlays. |
| [`platform-infra`](https://codeberg.org/rch/platform-infra) | Provisions Proxmox VMs with OpenTofu and exposes handoff outputs. |
| [`platform-k8s-bastion`](https://codeberg.org/rch/platform-k8s-bastion) | Provides runtime commands and libraries for Kubernetes bastion hosts. |
| `platform-private` | Stores private environment-specific operator config; secrets still stay outside Git. |
| [`platform-template-builder`](https://codeberg.org/rch/platform-template-builder) | Builds reusable Proxmox VM templates from upstream Linux cloud images. |
| [`platform-tools`](https://codeberg.org/rch/platform-tools) | Provides shared helper tools used by the platform project repositories. |

## Tools

| Tool | Purpose |
| --- | --- |
| `platform-ssh-init` | Create purpose-specific SSH identities and optional SSH config blocks. |
| `platform-vm-env-collect` | Collect VM environment facts for rebuild planning. |
| `platform-runtime-evidence` | Collect secret-free PKI runtime and installation evidence from one reviewed environment. |
| `platform-config-init` | Create the local outside-Git secret namespace under `~/.config/platform-infrastructure/`. |
| `platform-proxmox-token-init` | Bootstrap the Proxmox API user/token expected by platform OpenTofu runs. |
| `platform-proxmox-vm-cleanup` | Stop and destroy exactly one Proxmox VM by VMID with confirmation and optional SSH execution. |
| `platform-proxmox-vm-snapshot` | Create, list, roll back, and delete short-lived Proxmox VE 9 development snapshots. |
| `platform-pki` | Unified Python PKI and operator exchange interface for all maintained PKI routes. |
| `platform-bastion-policy` | Validate and render Kubernetes bastion access-policy documents. |

PKI operations use only `platform-pki <command>`. Production packaging generates
and installs one PKI executable, `platform-pki`; the 18 v2 compatibility aliases
are not part of the current command surface.

Operator-side host-local transport is provided by
`platform-pki direct-exchange ...` for pinned restricted SSH and
`platform-pki gitlab-package ...` for exact GitLab Generic Packages. Ansible and
target-side exchange components remain in `platform-config`.

## Install

Clone the canonical tools repository and install maintained CLI helpers into `~/.local/bin`:

```bash
git clone https://codeberg.org/rch/platform-tools
cd platform-tools
make install
```

Use another install directory when needed. PKI helpers install template assets
under `SHARE_DIR`; they no longer install or load shared shell libraries:

```bash
make install \
  INSTALL_DIR="$PWD/.tools/bin" \
  SHARE_DIR="$PWD/.tools/share/platform-tools"
```

Ensure the install directory is on `PATH` when using tools by command name.

### Upgrade From v2.3.0

Version 3.0.0 is the unified-only PKI command boundary. It requires Python 3.14
or newer on every host that executes `platform-pki`.

Before installing v3.0.0 over a v2.3.0 installation, inspect these exact
legacy paths under `INSTALL_DIR`:

- `platform-pki-init`
- `platform-pki-inventory-install`
- `platform-pki-print-cert`
- `platform-pki-list-expiry`
- `platform-pki-service-verify`
- `platform-pki-export-ansible`
- `platform-pki-backup`
- `platform-pki-custody-report`
- `platform-pki-ca-passphrase-verify`
- `platform-pki-root-create`
- `platform-pki-intermediate-create`
- `platform-pki-csr-recover`
- `platform-pki-service-issue`
- `platform-pki-service-renew`
- `platform-pki-csr-trust-install`
- `platform-pki-certificate-export`
- `platform-pki-csr-candidate`
- `platform-pki-ca-rollover`

Remove or relocate each listed path manually after inspection. Do not use a
wildcard deletion such as `rm platform-pki-*`; similarly named protocol,
archive, marker, or local operator files are not cleanup targets. `make install`
checks every exact legacy path, including dangling symlinks, before any install
mutation. If one exists, installation fails and lists it; the installer never
deletes or replaces a legacy alias.

Update automation to the corresponding `platform-pki <command>` route before
cleanup. A copied or renamed `platform-pki` archive still behaves canonically as
`platform-pki`; its filename does not select a legacy route.

## Requirements

Core local requirements:

- `bash`
- `make`
- standard Unix tools such as `awk`, `cmp`, `cp`, `date`, `find`, `grep`, `mkdir`, `mktemp`, `od`, `sed`, `sha256sum`, `stat`, `tar`, and `tr`

PKI helpers require:

- `openssl`
- util-linux `flock` and Linux procfs at `/proc` for stable operation-lock identity checks
- GNU `date` for certificate expiry calculations
- GNU `mv` with `--no-copy`, `--update=none-fail`, and `--exchange`; inventory publication supports a guarded rename fallback, while CSR trust replacement requires atomic exchange
- OpenSSH `ssh-keygen` for validating trust keys and signing or verifying host-local CSR exchange manifests
- `tar` with `--no-wildcards` support for safe PKI backup exclusions
- `age` for encrypted `platform-pki backup` output; plain `.tar.gz` backup requires explicit `--allow-plain-backup`
- Python 3.14 or newer for the unified `platform-pki` zipapp
- Linux `O_TMPFILE`, linkable `/proc/self/fd` entries, and reliable advisory locks on the PKI filesystem for Python-backed operational lock acquisition
- optional util-linux `findmnt` and `lsblk` for `platform-pki custody-report` LUKS-ancestry evidence; unsupported storage ancestry is reported as `unknown`

SSH and Proxmox helpers require:

- `ssh` for remote execution modes
- `pveum` on the Proxmox host for `platform-proxmox-token-init`
- `qm` on the Proxmox host for `platform-proxmox-vm-cleanup`
- `pvesh`, `jq`, and Linux procfs at `/proc` on a single-node Proxmox VE 9 host for `platform-proxmox-vm-snapshot`, plus `qm` for mutations; local `jq` is also required with `--ssh`
- `jq` on the Proxmox host when `platform-proxmox-token-init --write-token-file` is used over SSH

Bastion policy helpers require:

- `python3`
- `PyYAML`

Optional verification tools:

- `shellcheck` for `make shellcheck`
- `gitleaks` for local secret scanning

## Development Containers

The canonical tooling uses two rootless Podman containers with the repository
mounted at `/workspace`. The Debian 13 development image contains the pinned
Bashly generator, ShellCheck, and shfmt. The separate Python 3.14 test image
contains pytest and the external tools exercised by maintained tests. Neither
container mounts host SSH keys, private configuration, PKI state, or the Podman
socket. Current final acceptance is performed on `amd64`; the development
image retains reviewed ShellCheck and shfmt mappings for `amd64` and `arm64`.

Open an interactive development shell:

```bash
make shell
```

Run all maintained checks across both pinned containers:

```bash
make container-check
```

This is the canonical final acceptance command. It verifies the seven
non-PKI Bashly artifacts and runs ShellCheck in the development image, then runs syntax checks,
the complete pytest aggregate once, and the archive smoke in the test image. Do
not run `make test` immediately before it unless a separate host-environment
comparison is intentional.

The aggregate runs non-rollover test targets with two bounded Make jobs, then
runs the durability-heavy rollover suite alone with its own four pytest workers.
Set `TEST_MAKE_JOBS` from 1 through 4 to adjust the first pool; `1` preserves
serial non-rollover execution. Both worker settings are forwarded into the
test container:

```bash
make container-check TEST_MAKE_JOBS=1
TEST_MAKE_JOBS=4 ./scripts/in-test-container make test
```

The two pools never overlap. Avoid unbounded `make -j` or pytest `-n auto` runs;
the subprocess harness and PKI tests perform real process supervision and
filesystem work.

Run only the generic pytest harness contract tests:

```bash
make test-python-infrastructure
```

Run the deterministic Python PKI foundation and primitive checks:

```bash
./scripts/in-test-container make test-platform-pki-foundation
```

This target includes real Python/util-linux contention, replacement-race,
fork/exec descriptor-inheritance, anonymous-publication process-death, and lock
holder process-death checks for the Python ordered-lock primitive. It also tests
Linux no-clobber file/directory rename, exact file/directory exchange, owned
same-parent staging and cleanup, source-file synchronization, immutable
parent-bound directory readiness, descriptor-relative tree durability, and
guarded exact replacement of an existing file or directory. Replacement uses
Linux `RENAME_EXCHANGE`, durably validates both names, and never claims rollback.
It identity-unlinks displaced regular files, but retains a complete displaced
directory at the source name for later command-journaled cleanup. Replacement
results report the old destination identity, `REMOVED` or `RETAINED` disposition,
and retained directory readiness evidence. Directory tree claims require
parent-bound readiness returned by `fsync_tree`. Migrated operational commands
and the unified rollover recovery route use these primitives at their mutation
and publication boundaries.

Run only the durable-publication checkpoint tests:

```bash
./scripts/in-test-container make test-platform-pki-publication
```

Run the authoritative PKI rollover pytest scenarios:

```bash
make test-pki-ca-rollover
```

Run the same complete suite through the generated unified recovery command:

```bash
make test-pki-ca-rollover-python-recover
```

`platform-pki ca-rollover` uses Python handlers for migration, status,
preparation, and recovery. Frozen final-Bash executables, libraries, and source
fragments remain only under `tests/pki/oracles/` as historical test evidence.

Within `make test`, the authoritative rollover target runs only after the
non-rollover pool and uses four workers by default. Invoking the rollover target
directly does not run that pool. Run the serial diagnostic target directly when
comparing ordering or timing. The pinned test image includes pytest-xdist;
host-only runs must provide it separately:

```bash
make test-python-pki-rollover
```

Set `PKI_PYTEST_WORKERS` from 1 through 4 to override the authoritative target's
bounded default or benchmark the parallel target directly:

```bash
make test-pki-ca-rollover PKI_PYTEST_WORKERS=2
make test-python-pki-rollover-parallel
make test-python-pki-rollover-parallel PKI_PYTEST_WORKERS=4
```

Run the authoritative Python rollover parser group without creating PKI seed
state:

```bash
make test-pki-ca-rollover-parser
```

Run the focused immutable certificate-only export scenarios:

```bash
make test-pki-certificate-export
```

Run the focused authenticated terminal CSR outcome export scenarios:

```bash
make test-pki-csr-outcome
```

Run the focused removable-media CSR approval and signing facade scenarios:

```bash
make test-pki-offline-csr
```

Generate the seven non-PKI Bashly-backed executables and verify that committed
output is current:

```bash
make generate
make verify-generated
```

Edit maintained non-PKI Bashly source under `bashly/<tool>/`, not the
corresponding generated file under `bin/`. PKI source is maintained under
`src/platform_pki/`; its frozen Bash evidence under `tests/pki/oracles/` must
not be edited. See [`docs/development.md`](docs/development.md) for the full workflow.

All maintained shell commands use the same generated CLI contract: leading
`--help`/`-h` and `--version`/`-v` write to stdout and exit 0, while parser
errors write to stderr and exit 1. `platform-bastion-policy` follows the same
public contract through Python argparse. Commands with subcommands provide
command-specific help as `COMMAND --help` or `COMMAND -h`.
Generated shell-command help uses a restrained color palette on interactive
terminals. Colors are disabled automatically for pipes and redirects; set
`NO_COLOR=1` to disable them explicitly. Command result, warning, and error
logs remain uncolored.

Set `PLATFORM_TOOLS_DEV_IMAGE` or `PLATFORM_TOOLS_TEST_IMAGE` to override the
local image names. Run a focused target in the pinned test environment with:

```bash
./scripts/in-test-container make test-command-contract
```

The wrapper targets require Podman, Bash, and Make on the host.

## Verify

Run syntax checks for maintained scripts:

```bash
make verify
```

Run ShellCheck when it is available:

```bash
make shellcheck
```

Run maintained behavior tests:

```bash
make test
```

All maintained test orchestration uses pytest. The tests still execute real
generated non-PKI Bash commands, Python PKI zipapps, frozen Bash oracles,
external tools, PTYs, inherited file descriptors,
self-streamed SSH, and executable fakes as subprocesses. Coverage includes the
cross-command CLI contract and a disposable installation smoke test for every
command, including installed PKI template lookup without Ruby, Bashly, shell
libraries, or checkout source paths at runtime.

Run only the isolated SSH identity helper tests:

```bash
make test-platform-ssh-init
```

Run only the fake-backed Proxmox token bootstrap tests, which never contact a
real Proxmox host:

```bash
make test-proxmox-token-init
```

Run only the fake-backed Proxmox VM cleanup tests, which never contact a real
Proxmox host or mutate a VM:

```bash
make test-proxmox-vm-cleanup
```

Run only the fake-backed Proxmox VM snapshot tests, which never contact a real
Proxmox host or mutate a live VM:

```bash
make test-proxmox-vm-snapshot
```

## Quick Usage

Create a purpose-specific SSH key directly:

```bash
platform-ssh-init \
  --key-path ~/.ssh/platform-example_ed25519 \
  --comment "platform example" \
  --print-public-key
```

Or use a config file from private operator config:

```bash
platform-ssh-init ../platform-private/infra/ssh/production-cloud-init.env --print-public-key
```

Collect facts from a VM:

```bash
sudo platform-vm-env-collect
```

Collect PKI runtime and installation evidence without reading PKI state or
executing the installed `platform-pki` artifact:

```bash
platform-runtime-evidence \
  --identity operator-01 \
  --role operator-controller \
  --owner platform-operator \
  --executes-pki yes \
  --install-dir /home/operator/.local/bin \
  > operator-01.runtime-evidence
```

Use `--invoke-version` only when executing the selected artifact's
`--version` route is explicitly approved. Point `--probe-dir` at the reviewed
PKI filesystem when its `O_TMPFILE`, procfs-link, and advisory-lock results are
intended as filesystem readiness evidence. Collection does not certify a role;
review the fixed-order schema-1 record and its `runtime_status` as described in
[`docs/platform-runtime-evidence.md`](docs/platform-runtime-evidence.md).

Create the outside-Git local secret namespace with `infra/`, `config/`, and `pki/`:

```bash
platform-config-init
```

Bootstrap the Proxmox API token identity over SSH:

```bash
platform-proxmox-token-init \
  --ssh root@<proxmox-ip> \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path / \
  --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token
```

Check Proxmox token bootstrap prerequisites first:

```bash
platform-proxmox-token-init --ssh root@<proxmox-ip> --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token --check
```

Token-file output is staged beside the destination with mode `600`. Absent
destinations use atomic no-clobber publication. Validated existing non-empty
files are preserved unless `--force` is explicitly supplied; see the token
helper documentation for the existing-file trust boundary.

Clean up one Proxmox VM by VMID after verifying the printed target:

```bash
platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --vmid 9900
```

Without `--yes`, cleanup requires an interactive TTY and confirmation containing
exactly the selected VMID. Redirected input and unavailable input are refused.
After confirmation, the helper re-inspects the VMID, exact name, and status and
aborts on drift before and after resolving the supported destroy command. A
running VM is checked again after stop. Remote destruction consumes a
five-minute, owner-only authorization record persisted on the Proxmox host;
the fixed remote command receives VM and token data over standard input rather
than login-shell syntax, and the generated remote child reads the nonce from a
protected file descriptor rather than argv, closing that descriptor before any
authorization or Proxmox child command. Aged interrupted publication and
consume artifacts are reaped only after strict owner, mode, link-count,
device/inode, and non-symlink checks. `--ssh` accepts
only a DNS-name/IPv4 `host` or `user@host` destination; option-like, whitespace,
shell-metacharacter, and bracketed IPv6 values are rejected.

Create a short-lived development snapshot for one exact VM:

```bash
platform-proxmox-vm-snapshot create \
  --ssh root@192.0.2.10 \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 101 \
  --snapshot-name before-upgrade
```

Snapshot create, rollback, and delete require an interactive TTY unless
`--yes` is supplied. Generated subcommand parsing exposes only options that
apply to the selected operation; private self-streaming protocol flags remain
hidden from public help.

Initialize PKI state and issue a test service certificate from inventory:

```bash
platform-pki init
platform-pki inventory-install
platform-pki root-create --name "Platform Example Root CA" --org "Platform Example" --country "PL"
platform-pki intermediate-create --name "Platform Example Intermediate CA" --org "Platform Example" --country "PL"
platform-pki service-issue platform-example
platform-pki service-verify platform-example
platform-pki list-expiry
platform-pki custody-report
```

PKI initialization paths must be absolute, non-root, and symlink-free.
`platform-pki init` creates `inventory/services.yml.example`, not active
inventory. `platform-pki inventory-install` installs
`../platform-private/pki/services.yml` by default; use `--private-repo` for a
different private repository. Before a byte-different replacement, the command
durably preserves the exact active bytes under the owner-only,
content-addressed `inventory/history/<sha256>.yml` store. It never overwrites or
automatically removes history; an unsafe or conflicting snapshot blocks the
replacement. Retain these snapshots with signer backups because authenticated
CSR history uses the exact snapshot named by its signed inventory digest while
still requiring the service's current policy to match. `platform-pki init
--force` refreshes only the example and does not replace active inventory, CA
keys, certificates, or database state. Existing PKI directories must be owned
by the current user and must not be group- or world-writable.
Managed service transaction recovery uses:

```bash
platform-pki service-recover \
  --transaction service-0123456789abcdef0123456789abcdef
```

Recovery requires exact interactive confirmation or `--yes`. Host-local issue,
migration, and renewal continue to recover through `platform-pki csr-recover`.

Service inventory may set `key_custody: host-local`; such entries must also set
canonical `target`, `validation_boundary_sha256`, and positive-decimal
`rollback_hold_seconds` scalars. Managed entries must omit all four fields.
Authenticated host-local issue,
migration, and renewal accept a host-generated P-384 CSR plus canonical request
and approval manifests, detached OpenSSH signatures, and a trusted response
signing key. They publish immutable certificate-only pending candidates and
signed responses under `state/csr/`; they never receive or publish the host
private key. `platform-pki csr-candidate` verifies one exact exported candidate
and can accept bounded-time schema-2 deployment evidence as finalized or
abandoned historical evidence. It performs no live operation and never claims
live state. Active predecessor pointers are accepted only after replaying the
complete authenticated immutable outcome and source history; certificate export
also requires the signed target to equal current inventory. Abandonment is not
revocation. Managed keys and exports remain
through the configured hold and require separate cleanup approval. Explicit
host-local Ansible export remains rejected.

For a reviewed removable-media handoff, `platform-pki offline-csr approve`
authenticates an exact three-file request directory and atomically publishes an
exact protected five-file approval directory. `platform-pki offline-csr sign`
reopens that exact directory, presents the authoritative signer precommit
review, and delegates issue, migration, or renewal to the existing host-local
writer. Both commands require explicit service, operation, and request ID and an
exact TTY confirmation unless `--yes` is supplied. The same human may operate
the distinct approval and CA roles, but this is key separation, not independent
human approval. Protected keys may prompt more than once because trust, signing,
and race-safe key rechecks are separate OpenSSH operations; each prompt names
its key role and phase. Identical requester and approver keys retain the
protocol's 24-hour delay. Signing does not export a response or act on a target,
and any retained signing transaction recovers only through
`platform-pki csr-recover`.

Publish or resolve one exact certificate-only pending response:

```bash
platform-pki certificate-export publish platform-example \
  --request-id 0123456789abcdef0123456789abcdef

platform-pki certificate-export resolve platform-example \
  --request-id 0123456789abcdef0123456789abcdef \
  --manifest-sha256 <sha256>
```

Publication contains no private key; resolution requires the reported exact
manifest digest and performs no deployment or finalization.

After a candidate has an authenticated immutable finalized or abandoned signer
outcome, publish or resolve its exact historical outcome package:

```bash
platform-pki csr-outcome publish platform-example \
  --request-id 0123456789abcdef0123456789abcdef \
  --outcome-key /absolute/path/to/response-signing-key

platform-pki csr-outcome resolve platform-example \
  --request-id 0123456789abcdef0123456789abcdef \
  --manifest-sha256 <sha256> \
  --format json
```

The external Ed25519 key must exactly match the immutable retained response
signer principal and trust for that request. The signer publishes no key or new
trust. Resolution reauthenticates the six-file package and retained source and
reports terminal historical action/state without claiming current target state.

Install reviewed public trust before signing:

```bash
platform-pki csr-trust-install
platform-pki csr-trust-install --private-repo /absolute/path/to/platform-private
```

The command accepts the exact four-file schema-1 signing/export trust set or
the exact five-file schema-2 set that adds `deployers.allowed_signers` under
`<private-repo>/pki/csr-trust` and atomically installs a protected snapshot at
`<pki-dir>/inventory/csr-trust`. It installs no private key and performs no
signing itself. Installation holds the lifecycle, root, intermediate, and
inventory locks. Initial schema-2 installation and identical protected content
are allowed, but any actual change involving schema 2 fails closed while a
retained candidate lacks an authenticated immutable finalized or abandoned
outcome. Malformed, conflicting, or recovery-required candidate/outcome state
also blocks replacement; retained terminal history alone does not. See
[`docs/pki-openssl.md`](docs/pki-openssl.md#host-local-csr-trust) for the exact
policy, manifest, signing, response, and recovery contracts.

Version 2 changes initialization and CA state incompatibly. Before using normal
CA or service commands with an existing 1.x PKI, install the reviewed private
inventory, create a fresh protected backup, inspect rollover status, and run the
explicit receipt-backed migration documented in
[`docs/pki-openssl.md`](docs/pki-openssl.md#migrate-legacy-ca-state). Migration
preserves existing keys, certificates, and active issuer identity; it does not
rotate the CA.

Fresh CA state begins with immutable root `g1` and intermediate `g1-i1`
generations, with the active pair selected by a protected manifest. Generation
reservations are monotonic: failed or interrupted bootstrap IDs remain
permanently abandoned, and retries allocate the next root or intermediate ID.
Existing singleton CA state is changed only through explicit, receipt-backed
`platform-pki ca-rollover migrate`. Inventory installation, protected backup,
and rollover status/migration prepare missing private control directories for
that workflow. Other PKI commands reject legacy state with migration guidance
after acquiring persistent locks. On generation-aware state, receipt-backed
`platform-pki ca-rollover prepare --type intermediate|root` creates immutable
candidate generations without changing the active issuer. Root preparation
also requires the reviewed `pki/trust-consumers.yml` checklist from the private
repository. `status --format text|json` reports public active and candidate
metadata after validating complete digest-bound candidate/state trees and every
service issuer manifest. Preparation pre-creates and journals sensitive child
outputs, records full nanosecond identities for staged CA database sources, and
uses immutable write-ahead transaction manifests. It verifies strict critical
CA certificate profiles and retains recovery-required state until
crash-resumable terminal cleanup completes. Terminal receipts bind the exact
journal and marker identities before either control file is removed. Superseded
and final transaction-tree manifests are identity-unlinked in journaled order;
missing prior unlinks resume safely, while replacement objects fail closed.
Recovery-required JSON uses schema 2 and reports the validated terminal outcome
and exact `resume` or `rollback` action; every retained preparation journal
blocks normal PKI commands even after its mutation outcome is committed.
Activation, acknowledgement, rollback, retirement, and completion
remain unavailable pending immutable export and evidence support.

For non-interactive PKI automation with encrypted CA keys, pass restricted passphrase files such as `--root-pass-file /run/secrets/platform-pki-root-pass` and `--intermediate-pass-file /run/secrets/platform-pki-intermediate-pass`. See `docs/pki-openssl.md` for the full flow, migration procedure, and safety rules.

Validate a candidate passphrase against the active encrypted key and certificate
without changing CA state:

```bash
platform-pki ca-passphrase-verify \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

It holds the standard lifecycle, root, and intermediate locks,
passes secrets to OpenSSL through inherited descriptors, suppresses OpenSSL
diagnostics, and writes no persistent validation receipt. Success is
point-in-time evidence; `platform-pki custody-report` continues to report
cryptographic validation as `unknown`.

Service issuance refuses an existing certificate, reuses an existing private
key unless `--rotate-key` is requested, and transactionally publishes service
artifacts with the intermediate CA database only after successful signing and
verification.

`platform-pki custody-report --format text|json` classifies managed root,
intermediate, service, export, backup, inventory, CA-database, legacy, and
public-artifact roles. It inspects metadata, storage ancestry, `age` headers,
and only the first PEM header line of validated private-key files. It reports
offline custody, recipient separation, offsite copies, restore rehearsal, and
target-host leaf custody as `unknown` because filesystem structure cannot prove
those operational controls. Metadata-only scans
are descriptor-relative, stay on the PKI filesystem, and do not stage private
path lists. Header reads consume at most 257 bytes, receipt reads reject content
above 65,536 bytes, and receipt archive digests are recorded compatibility
fields rather than values verified by this report.

Service renewal requires an existing private key, reuses it unless
`--rotate-key` is requested, and archives previous service material while
transactionally replacing the certificate and intermediate CA database. Both
operations hold ordered root, intermediate, and inventory locks through
verification and consume one validated inventory snapshot. Interrupted managed
renewal uses `platform-pki service-recover`;
host-local renewal continues to use `csr-recover`.

`platform-pki root-create` uses a Python transaction writer. It generates
the key and certificate in private staging,
passes passphrase files to OpenSSL through inherited descriptors, and publishes
the immutable generation without clobbering an existing destination. It refuses
an existing bootstrap or active issuer; `--force` cannot replace unproven
generation state. Handled failures and explicit recovery remove only
identity-bound transaction state and preserve the reserved ID as abandoned.
PKI paths used in the schema-3 recovery journal must be ASCII. Root keys remain
encrypted by default, and unencrypted root keys require the explicit
`--allow-unencrypted-root-key` opt-in.

`platform-pki intermediate-create` uses a Python schema-3 transaction writer.
It binds both passphrase files to
OpenSSL through inherited descriptors and stages its key, CSR, certificate,
chain, and exact root CA database update. Authoritative root files are copied
through identity-checked descriptors and rechecked before publication. It
refuses an existing active issuer;
`--force` cannot replace unproven generation state. Failed signing, publication,
or recovery restores the exact root database state and permanently abandons the
allocated intermediate ID. Intermediate keys
remain encrypted by default, and unencrypted keys require the explicit
`--allow-unencrypted-intermediate-key` opt-in. CA mutation locks use a fixed
root-before-intermediate acquisition order and cover complete generation,
signing, and publication transactions.

Validate and render a Kubernetes bastion access policy:

```bash
POLICY_OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-policy.XXXXXX")"

platform-bastion-policy validate \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml

platform-bastion-policy render-host \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml \
  --output "$POLICY_OUT_DIR/access-policy.yaml"

platform-bastion-policy render-csr-configmap \
  --input ../platform-private/config/files/k8s-bastion/dev/access-policy.yaml \
  --name bastion-csr-policy \
  --namespace bastion-system \
  --output "$POLICY_OUT_DIR/bastion-csr-policy.configmap.yaml"
```

Add a name guard and non-interactive confirmation for automation:

```bash
platform-proxmox-vm-cleanup \
  --ssh root@<proxmox-ip> \
  --identity-file ~/.ssh/platform-template-builder_ed25519 \
  --vmid 9900 \
  --name platform-template-smoke-9900 \
  --yes
```

If running directly from a checkout before install:

```bash
sudo ./bin/platform-vm-env-collect
./bin/platform-runtime-evidence --identity operator-01 --role operator-controller --owner unassigned --executes-pki yes --install-dir "$HOME/.local/bin"
./bin/platform-config-init
./bin/platform-proxmox-token-init --ssh root@<proxmox-ip>
./bin/platform-proxmox-vm-cleanup --ssh root@<proxmox-ip> --identity-file ~/.ssh/platform-template-builder_ed25519 --vmid 9900
./bin/platform-proxmox-vm-snapshot list --ssh root@192.0.2.10 --identity-file ~/.ssh/platform-template-builder_ed25519 --vmid 101
./bin/platform-pki init
./bin/platform-bastion-policy validate --input examples/bastion-policy/access-policy.example.yaml
```

## Documentation

| Document | Purpose |
| --- | --- |
| `docs/ssh-identity-helper.md` | SSH helper usage with CLI flags or config files, private config layout, and CI/CD expectations. |
| `docs/platform-vm-env-collect.md` | VM environment collector usage, output structure, and safety notes. |
| `docs/platform-runtime-evidence.md` | Secret-free PKI runtime, artifact, prerequisite, capability, and exact legacy-alias evidence collection. |
| `docs/platform-config-init.md` | Local outside-Git secret namespace initialization for platform secrets. |
| `docs/bastion-policy.md` | Kubernetes bastion access-policy validation and rendering flow. |
| `docs/pki-openssl.md` | OpenSSL PKI helper usage, state layout, and safety model. |
| `docs/pki-direct-exchange.md` | Pinned restricted-SSH operator transfer commands for host-local PKI packages. |
| `docs/pki-gitlab-package-exchange.md` | Implemented GitLab 18.11.3 Generic Package exchange contract and remaining production gates. |
| `docs/pki-host-local-csr-development-runbook.md` | Pointer to the implemented cross-repository host-local registry PKI workflow and signer-side references. |
| `docs/proxmox-token-init.md` | Proxmox API user/token bootstrap helper and manual `pveum` reference. |
| `docs/proxmox-vm-cleanup.md` | Safe single-VM Proxmox cleanup helper usage and safety model. |
| `docs/proxmox-vm-snapshot.md` | Proxmox VE 9 development snapshot workflows, safety model, and environment-tag gate. |
| `docs/handoffs/config-namespace-handoff.md` | Downstream ownership notes for the local secret namespace. |
| `docs/handoffs/pki-host-local-csr-handoff.md` | Implemented signer contract, transport-neutral controller workspace, and platform-config lifecycle contract for host-local leaf keys. |
| `docs/handoffs/tofu-ansible-handoff.md` | Example OpenTofu/Ansible handoff from a collected VM report. |
| `assets/brand/` | Project brand assets for release metadata and forge profiles. |

## Security

Keep real secrets outside Git. Do not commit VM collection output, generated archives, SSH keys, private `.env` files, token files, PKI CA material, service private keys, issued real certificates, PKI exports, PKI backups, or copied private configuration.

Use `~/.config/platform-infrastructure/` for local secret material. Private but non-secret operator configuration belongs in private Git, such as `platform-private`.

Collected VM reports and PKI exports can contain sensitive environment details even when they do not contain obvious passwords. Review generated files before sharing them.

PKI passphrase files are plaintext secrets. Keep them outside Git, restrict them to mode `600` or stricter, use a first-line passphrase of at least 16 characters with non-whitespace content, and prefer temporary secret-manager mounts over long-lived files. The parser minimum is not a production entropy recommendation: use separate secret-manager-generated root and intermediate credentials with independent recovery copies, and keep backup recipients separate from both CA passphrases and archived data.

PKI Ansible exports contain service private keys. The controller service key and
its Ansible-export copy are compatibility inputs for the current deployment
workflow, not the desired custody end state. Do not remove either copy solely
because the custody report flags it; retain it until a validated host-local
migration, rollback hold, and separately authorized quarantine complete. Custom
export directories must be absolute paths with current-user-owned parents that
are not group- or world-writable and do not contain symlink components.

Real bastion access policies can reveal users, groups, cluster endpoints, and access intent. Keep real policies in `platform-private`; only fake examples belong in this repository.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
