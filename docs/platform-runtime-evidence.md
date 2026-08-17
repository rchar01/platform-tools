# PKI Runtime Evidence Collector

`platform-runtime-evidence` collects a secret-free, state-free record for one
reviewed host or immutable image. It supports PKI execution-host and installation
inventory; it does not certify an environment for a particular operational
role.

## Basic Usage

Provide the reviewed identity, role, accountable owner, execution
classification, and exact installation directory explicitly:

```bash
platform-runtime-evidence \
  --identity operator-01 \
  --role operator-controller \
  --owner platform-operator \
  --executes-pki yes \
  --install-dir /home/operator/.local/bin \
  > operator-01.runtime-evidence
```

Use `unassigned` for an owner that has not been assigned. Use `unknown` for
`--executes-pki` when the execution responsibility is not established; do not
guess from installed files alone.

The installation, selected artifact, and probe paths must be absolute. The
installation directory may be absent, but it must be a real directory rather
than a symlink when present. The probe directory must already exist and must not
be a symlink. To protect descriptor-relative cleanup from untrusted namespace
replacement, it must either deny group/other writes or use sticky-directory
protection, as `/tmp` normally does, and be owned by the collector UID or root.
The opened parent is identity-checked against the reviewed path. Processes with
the collector's own UID are inside this boundary and must not concurrently
replace the probe path or workspace; interruption can retain the mode-700
workspace for review rather than risk deleting an unbound object.

By default, the selected artifact is `INSTALL_DIR/platform-pki`, and capability
probes use `${TMPDIR:-/tmp}`. Override those boundaries when the reviewed
artifact or relevant PKI filesystem is elsewhere:

```bash
platform-runtime-evidence \
  --identity signer-image@sha256:REVIEWED \
  --role offline-signer \
  --owner unassigned \
  --executes-pki unknown \
  --install-dir /usr/local/bin \
  --platform-pki /opt/platform-tools/bin/platform-pki \
  --probe-dir /var/lib/platform-pki
```

`--probe-dir` determines which filesystem is tested for `O_TMPFILE`, linking an
anonymous file through `/proc/self/fd`, and advisory locking. Use the reviewed
PKI filesystem when those results will support PKI readiness review.

## Artifact Execution

The collector does not execute the selected `platform-pki` artifact by default.
It records `platform_pki_version_status=not-invoked` and
`platform_pki_version=not-invoked`.

When executing only its public version route is approved, add:

```bash
--invoke-version
```

This option requires the selected path to be an executable regular file. The
collector rechecks its metadata and digest, copies the exact bytes into a sealed
in-memory snapshot, and executes only that snapshot. It records the exit status
and the percent-encoded first output line; an artifact version failure remains
evidence rather than making collection fail.

## Output Contract

Standard output is one fixed-order schema-1 record with one `key=value` field
per line. Percent signs, non-NUL ASCII control bytes, and DEL in observed values
are encoded as `%25`, `%01` through `%1F`, and `%7F`. The record includes:

- explicit identity, role, owner, PKI execution status, and installation path;
- kernel, architecture, and operating-system release fields;
- resolved `python3` path, version, and Python 3.14-or-newer result;
- selected artifact type, owner UID, mode, link count, size, SHA-256, and
  identity-stability result;
- the state of each of the 18 exact retired `platform-pki-*` alias paths;
- resolved paths and first-line versions for applicable external tools;
- GNU `mv` and `tar` option observations, procfs presence, and bounded
  filesystem capability-probe results; and
- an aggregate `runtime_status` for triage.

Path states are `absent`, `regular-file`, `directory`, `symlink`,
`dangling-symlink`, or `other`. Exact alias symlinks are classified without
following them.

`runtime_status` has these meanings:

| Value | Meaning |
| --- | --- |
| `not-applicable` | The reviewed input says this environment does not execute `platform-pki`. |
| `unknown` | Whether this environment executes `platform-pki` remains unresolved. |
| `blocked` | An executing environment lacks Python 3.14+, a stable executable regular artifact, or absence of all 18 exact aliases. |
| `role-review-required` | Generic artifact, Python, and alias gates passed; a reviewer must still evaluate tool and filesystem evidence for the exact role. |

A zero exit status means evidence collection completed. It does not mean the
environment passed a release, security, custody, or operational readiness gate.
Missing tools and unsupported features are recorded where possible instead of
causing collection failure.

## Safety Boundary

The collector:

- reads no PKI namespace, keys, certificates, journals, inventory, trust, or
  other generated PKI state;
- does not recurse through the installation directory or follow exact alias
  symlinks;
- opens a regular selected artifact without following a final symlink, hashes
  it through that descriptor, and reports whether mutation-relevant metadata and
  the final path identity stayed stable;
- executes an explicitly requested artifact version query from a sealed
  in-memory snapshot whose bytes match the recorded digest;
- runs only read-only version or help queries against prerequisite tools;
- creates one random mode-700 directory below the probe directory and removes
  only its exact `linked` and `lock` entries before removing that directory;
  group/other-writable probe parents are accepted only with sticky-directory
  protection and collector-UID or root ownership; and
- does not install software, remove aliases, mutate PKI state, or contact remote
  systems.

Treat the resulting record as environment metadata. Review it before sharing,
especially when hostnames, account names, installation paths, or tool versions
are sensitive in the receiving context.

## Verification

Run the focused behavior tests in the pinned test container:

```bash
./scripts/in-test-container make test-platform-runtime-evidence
```

After changing Bashly source, regenerate and verify the committed artifact in
the development container:

```bash
./scripts/in-container make generate
./scripts/in-container make verify-generated shellcheck
```
