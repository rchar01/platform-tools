# Development

Use the repository development container for generation, tests, and static
checks. The host needs Podman, Bash, and Make; Ruby and Bashly stay in the
container.

## Interactive Workflow

Open a rootless Podman development shell:

```bash
make shell
```

The repository is mounted at `/workspace`. The container uses a temporary home
directory and does not mount host SSH keys, private platform configuration, PKI
state, or the Podman socket.

Run focused checks inside the shell while developing:

```bash
make verify-generated
make verify
make shellcheck
make test-command-contract
```

Use the one-shot equivalent from the host when an interactive shell is not
needed:

```bash
make container-check
```

`make container-check` is the canonical final acceptance command. It builds the
pinned image, runs static and generated checks, executes the Python-only
`make test` aggregate once, runs the container-only archive smoke, and runs
ShellCheck. Do not run a separate full `make test` immediately beforehand unless
an intentional host-versus-container comparison is required.

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

All maintained test orchestration lives under `tests/python/`. The shared
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
python3 -m pytest tests/python/test_harness.py::test_process_runner_kills_timed_out_process_group
```

Authoritative PKI rollover scenarios run with:

```bash
make test-pki-ca-rollover
make test-python-pki-rollover
python3 -m pytest -m pki tests/python/pki/test_ca_rollover_*.py
```

The first target routes to the bounded parallel target, so `make test` executes
the suite exactly once with four workers by default. The development container
pins `pytest-xdist`; use the direct serial target for ordering diagnostics or
override the bounded worker count from 1 through 4:

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
Two shell-harness-only progress tests were removed with the retired shell suite,
so the authoritative suite now collects 219 tests. Keep the serial target
available for ordering and diagnostic checks.

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
module, infrastructure tests, and dry-run target ownership. The single final
`make container-check` acceptance run passed on `amd64` on 2026-08-03: all
1,252 aggregate tests and 10 container-only archive tests passed, followed by
ShellCheck. Arm64 image support remains available but its runtime behavior is
outside the accepted migration scope and unverified.

Run the focused authoritative Python parser group without generating PKI seed
state:

```bash
make test-pki-ca-rollover-parser
```

The no-argument `make test-pki-ca-rollover` target runs the complete Python
suite.

## Generator Updates

The development image uses a digest-pinned Debian 13 Ruby base, the matching
immutable Debian snapshot, exact direct package versions, checksum-verified
ShellCheck and shfmt binaries, and the Bashly dependency graph locked in
`Gemfile.lock`. Its reviewed ShellCheck and shfmt asset mappings support
`amd64` and `arm64`; builds reject other architectures. Update these inputs
together, inspect upstream release notes, regenerate all Bashly-backed tools,
and run a clean build:

```bash
podman build --no-cache -f Containerfile.dev .
make container-check
```

The dated Debian snapshot keeps reviewed package versions available. Refresh
the base digest and snapshot timestamp together so the image does not mix a
Ruby base with a different operating-system package snapshot.
