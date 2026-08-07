# Development

Use the repository development container for Bashly generation and shell
linting. Run syntax and behavior tests in the separate Python test container.
The host needs Podman, Bash, and Make; Ruby, Bashly, and the pinned Python test
stack stay in their respective containers.

## Interactive Workflow

Open a rootless Podman development shell:

```bash
make shell
```

The repository is mounted at `/workspace`. The container uses a temporary home
directory and does not mount host SSH keys, private platform configuration, PKI
state, or the Podman socket.

Run Bashly and shell-lint checks inside the shell while developing:

```bash
make verify-generated
make shellcheck
```

The development image intentionally does not include pytest or the external PKI
test runtime. Run focused checks in the pinned test image from the host:

```bash
./scripts/in-test-container make verify
./scripts/in-test-container make test-command-contract
```

Use the one-shot equivalent from the host when an interactive shell is not
needed:

```bash
make container-check
```

`make container-check` is the canonical final acceptance command. It builds the
pinned development image to verify generated artifacts and run ShellCheck, then
builds the pinned test image to run syntax checks, execute the `make test`
aggregate once, and run the container-only archive smoke. Do not run a separate
full `make test` immediately beforehand unless an intentional
host-versus-container comparison is required.

The aggregate runs all non-rollover targets included by `make test` with two
bounded Make jobs by default, waits for them to finish, then runs the
durability-heavy rollover suite alone with four pytest workers. The archive
smoke remains a separate container-only phase after the aggregate.
`scripts/in-test-container` forwards both settings so host-side overrides affect
the test container:

```bash
make container-check TEST_MAKE_JOBS=1
make container-check TEST_MAKE_JOBS=4 PKI_PYTEST_WORKERS=2
```

Both variables accept integers from 1 through 4. Use `TEST_MAKE_JOBS=1` for
serial non-rollover ordering diagnostics. Do not use unbounded Make jobs or
pytest `-n auto`; the test harness supervises real process trees and the PKI
suites perform filesystem durability operations.

The CSR signing, certificate-export, candidate, and schema-2 trust-install
suites create one immutable PKI seed per pytest process. Every test receives a
metadata-preserving private copy with its managed OpenSSL paths rebased and
fresh signed exchange timestamps, avoiding repeated root and intermediate
creation while retaining per-test state and process isolation.

Python-migration contracts and semantic state-copy helpers live in
`tests/pki/migration_contract.py` and `tests/pki/migration_harness.py`. Their
infrastructure tests preserve hard-link relationships, compare within-tree
identity transitions without comparing raw inode numbers across copies, and
rebase only validated managed OpenSSL `dir` assignments. Interrupted trees must
be recovered in place because copying invalidates journal-bound identities.
The differential runner executes separately supplied Bash and Python entry
points on sibling copies with independent `HOME`, XDG, and temporary directories;
each command test must explicitly declare any output or content normalization.

## Generated Bash Tools

Bashly-backed command source lives under `bashly/<tool>/`. The corresponding
`bin/<tool>` file is generated, committed, installed, and must not be edited by
hand.

After changing a Bashly declaration, command partial, or library, regenerate
the executable inside the container:

```bash
make generate
```

Verify that committed output is deterministic and current:

```bash
make verify-generated
```

This check generates twice in temporary directories and compares both results
with the committed executable. It does not rewrite the working tree.

`VERSION` is the repository CLI version source. Bashly embeds it in generated
executables so installed commands do not need Ruby, Bashly, or repository
source files at runtime.

Every maintained shell command is Bashly-backed. The generated parsers treat
`--help`/`-h` and `--version`/`-v` as global options when they appear before
command-specific options. These actions write to stdout and exit 0; parser and
validation errors write to stderr and exit 1. Commands with subcommands also
provide `COMMAND --help` and `COMMAND -h`. Nonempty `--flag=value` forms are
accepted; an empty equals-form value is invalid. Long option abbreviations are
not accepted. Keep these stock Bashly rules consistent across shell tools
rather than maintaining custom generator templates. The Python
`platform-bastion-policy` command implements the same public help, version,
stream, exact-option, and parser-error contract with argparse.

Generated shell-command usage uses Bashly's standard color library for section
captions, commands, arguments, flags, and environment-variable labels. Every
workspace calls `enable_auto_colors`, so redirected and piped help remains plain
text, and a nonempty `NO_COLOR` value disables color explicitly. This applies
only to generated usage; application result and log output is intentionally
unchanged.

Run the focused cross-tool and installed-layout checks directly when changing
the command inventory, installation, or parser contract:

```bash
make test-command-contract
make test-installed-tools
```

The installation check first verifies a disposable repository `.tmp` install,
then installs and executes an isolated runtime copy from an outside-checkout
state directory under an empty environment with isolated HOME/XDG paths and a
minimal runtime `PATH`. Ruby, Bashly, checkout paths and source workspaces,
shell startup hooks, Python import overrides, and PKI source overrides are
unavailable. It smokes every installed command and initializes PKI only under
an explicit temporary namespace; installed PKI library and templates resolve
through the runtime `SHARE_DIR` as the isolated XDG data location.

## Python Test Infrastructure

All maintained test orchestration lives under `tests/`. The shared
helpers run exact argument vectors with `shell=False`, isolated process groups,
tracked Linux-procfs descendants, pidfd-bound escaped-descendant signals, and
bounded reader and process cleanup.
Timeouts send `TERM`, wait for a bounded grace period, then send `KILL`; signal
exits use shell-style statuses such as 137 for `SIGKILL`. Controlled stdin,
no-echo PTYs, optional controlling terminals, explicit inherited descriptors,
streamed input, paused processes, and concurrent consumers preserve protocol
boundaries. The tree-copy fixture uses `cp -a` for lifecycle metadata.

Run the harness contracts, one marker, or one exact node with:

```bash
make test-python-infrastructure
python3 -m pytest -m infrastructure
python3 -m pytest tests/test_harness.py::test_process_runner_kills_timed_out_process_group
```

Authoritative PKI rollover scenarios run with:

```bash
make test-pki-ca-rollover
make test-python-pki-rollover
python3 -m pytest -m pki tests/pki/test_ca_rollover_*.py
```

The first target routes to the bounded parallel target, so `make test` executes
the suite exactly once, after the non-rollover Make pool, with four workers by
default. The test container pins `pytest-xdist`; use the direct serial
target for ordering diagnostics or override the bounded worker count from 1
through 4:

```bash
make test-pki-ca-rollover PKI_PYTEST_WORKERS=2
make test-python-pki-rollover-parallel
make test-python-pki-rollover-parallel PKI_PYTEST_WORKERS=4
```

Each worker uses isolated pytest temporary storage and its own PKI seed. The
worker count is restricted to 1 through 4 because rollover tests perform real
filesystem durability operations. Before shell retirement, three four-worker
runs completed the then-221-test suite without failures or skips in 560.24,
548.54, and 548.57 seconds, compared with the 2501.68-second serial baseline.
Two shell-harness-only progress tests were removed with the retired shell suite.
The authoritative suite now collects 224 tests. Keep the serial target available
for ordering and diagnostic checks.

All 79 inventoried shell scenario groups have authoritative pytest mappings.
The retired shell paths and selectors remain historical evidence in the
migration ledger, pinned to the final retained-shell revision `1ecbca5`.

The aggregate-composition review found that parser ordering and ordering across
independent workspaces are shell harness details, not product invariants. Python
directly preserves producer-to-consumer file identities, successful preparation
followed by overlap rejection, cumulative crashes on one recovery transaction,
both migration recovery actions, and successful migration followed by an
idempotent rerun. The root publication test also derives a parseable bad-signature
certificate from the actual prepared G2 root and requires both OpenSSL and the
application validator to reject it. These same-test data and state dependencies,
rather than global test order, must remain covered after shell retirement.

### PKI Rollover Shell Retirement

The final retained-shell revision is `1ecbca5`. Independent review found no
residual shell-specific product, process, signal, race, hostile-state, parser, or
same-transaction invariant. The retired shell suite's progress records,
selectors, and final `ok` line were test-harness diagnostics rather than product
contracts.

Focused retirement verification covers the parser target, rollover fixture
module, infrastructure tests, and dry-run target ownership. The accepted
revision's final `make container-check` run passed on `amd64` on 2026-08-04:
1,268 aggregate tests and 10 separate container-only archive tests passed, for
1,278 tests total, followed by ShellCheck.

Run the focused authoritative Python parser group without generating PKI seed
state:

```bash
make test-pki-ca-rollover-parser
```

The no-argument `make test-pki-ca-rollover` target runs the complete Python
suite.

## Container Updates

The development image uses a digest-pinned Debian 13 Ruby base, the matching
immutable Debian snapshot, exact direct package versions, checksum-verified
ShellCheck and shfmt binaries, and the Bashly dependency graph locked in
`Gemfile.lock`. Its reviewed ShellCheck and shfmt asset mappings support
`amd64` and `arm64`; builds reject other architectures.

The test image uses a digest-pinned Python 3.14 Debian 13 base, its matching
immutable Debian snapshot, exact direct system packages, and pinned pytest,
pytest-xdist, PyYAML, and transitive dependency versions. It intentionally
excludes Ruby, Bashly, ShellCheck, shfmt, anyio, and typeguard.

Update each base digest with its matching snapshot and package pins, inspect
upstream release notes, regenerate all Bashly-backed tools when generator inputs
change, and run clean builds:

```bash
podman build --no-cache -f Containerfile.dev .
podman build --no-cache -f Containerfile.test .
make container-check
```

The dated Debian snapshots keep reviewed package versions available. Do not mix
either language base with a different operating-system package snapshot. Final
test-image acceptance is currently performed on `amd64`.
