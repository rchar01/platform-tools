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

Run the maintained checks inside the shell:

```bash
make verify-generated
make verify
make test
make shellcheck
```

Use the one-shot equivalent from the host when an interactive shell is not
needed:

```bash
make container-check
```

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

Generic pytest helpers under `tests/python/` run commands as exact argument
vectors with `shell=False` and isolated process groups. Timeouts send `TERM`,
wait for a bounded grace period, then send `KILL`; signal exits use shell-style
statuses such as 137 for `SIGKILL`. The tree-copy fixture uses `cp -a` to
preserve the filesystem metadata exercised by lifecycle tests.

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
python3 -m pytest -m pki tests/python/pki
```

The first target routes to the direct Python target, so `make test` executes the
suite exactly once. The development container also pins `pytest-xdist` and
provides an opt-in four-worker run for faster local feedback:

```bash
make test-python-pki-rollover-parallel
make test-python-pki-rollover-parallel PKI_PYTEST_WORKERS=4
```

Each worker uses isolated pytest temporary storage and its own PKI seed. The
worker count is restricted to 1 through 4 because rollover tests perform real
filesystem durability operations. Three four-worker runs completed all 221
tests without failures or skips in 560.24, 548.54, and 548.57 seconds, compared
with the 2501.68-second serial baseline. The final run preserved the noexec-safe
executable-wrapper layout and left no wrapper directories. Keep the serial suite
available for compatibility and diagnostic checks.

All 79 inventoried shell scenario groups have pytest parity mappings. Python is
authoritative; the shell aggregate remains available under
`make test-pki-ca-rollover-shell` until the separate shell-retirement change is
complete.

The aggregate-composition review found that parser ordering and ordering across
independent workspaces are shell harness details, not product invariants. Python
directly preserves producer-to-consumer file identities, successful preparation
followed by overlap rejection, cumulative crashes on one recovery transaction,
both migration recovery actions, and successful migration followed by an
idempotent rerun. The root publication test also derives a parseable bad-signature
certificate from the actual prepared G2 root and requires both OpenSSL and the
application validator to reject it. These same-test data and state dependencies,
rather than global test order, must remain covered after shell retirement.

### Completing the PKI Rollover Test Migration

Complete these gates before deleting `tests/pki/test-ca-rollover.sh`:

1. Reconcile every migration-ledger row with its implementation commit, focused
   parity evidence, and independent review; no final row may retain a `pending`
   commit or `dual-run-retained` disposition after retirement.
2. Keep the aggregate-composition review current when either suite changes.
   Preserve the direct prepared-root corruption check, same-transaction recovery
   matrices, both rollback and resume outcomes, and migration idempotence without
   depending on global pytest execution order.
3. From the final dual-run revision, run the serial Python suite and the retained
   no-argument shell aggregate under bounded process-group supervision, then run
   `make test` and `make container-check` with both implementations enabled.
4. Run the final container verification on `amd64` and record architecture and
   tool versions with the observed results. The migration acceptance scope is
   `amd64` only by operator decision; preserve arm64 image support but describe
   it as unverified rather than blocking this migration.
5. Obtain an independent correctness and security review covering scenario
   parity, metadata-only secret handling, crash cleanup, aggregate composition,
   and readiness to retire the shell authority.
6. Keep `test-pki-ca-rollover` routed to the Python suite exactly once from
   `make test`, keep `test-pki-ca-rollover-parser` routed to the seed-free Python
   parser module, and retain explicit shell compatibility targets until review.
7. Keep `README.md`, this guide, `AGENTS.md`, and `pytest.ini` aligned with Python
   authority and the temporary shell compatibility targets.
8. From the authority-switch revision, run the focused parser target, the full
   Python rollover target, the retained shell compatibility target, `make test`,
   and `make container-check`; then obtain an independent correctness and
   security review of the authority switch.
9. Retire the shell implementation only in a subsequent separate change. Remove
   or replace the shell progress contracts in `test_ca_rollover_fixtures.py`,
   and delete the shell aggregate only if the authority-switch review found no
   residual shell-specific invariant; otherwise retain the smallest focused
   shell contract.
10. From the shell-retirement revision, rerun the focused parser target, the
    full rollover target, `make test`, and `make container-check`, then obtain a
    final independent review proving that no stale shell path or scenario was
    lost.
11. Update the migration plan and ledger with the authority-switch and retirement
    evidence. Identify Python as authoritative, preserve historical shell
    locators, replace `dual-run-retained` with a retired disposition, and close
    only the migration-specific gates that were actually verified.

Run the focused authoritative Python parser group without generating PKI seed
state:

```bash
make test-pki-ca-rollover-parser
```

The no-argument `make test-pki-ca-rollover` target runs the complete Python
suite. Use `make test-pki-ca-rollover-parser-shell` or
`make test-pki-ca-rollover-shell` for retained shell compatibility.

For long aggregate diagnostics, enable path-free elapsed-time records for the
active preparation, recovery, migration, hostile-state, and race scenario:

```bash
PLATFORM_PKI_TEST_PROGRESS=1 make test-pki-ca-rollover-shell
```

Progress is written to standard error as `start` and `pass` records. It is
disabled by default and does not replace the aggregate target's final status or
the planned outer process-group timeout.

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
