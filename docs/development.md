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

Migrated PKI rollover scenarios run separately with:

```bash
make test-python-pki-rollover
python3 -m pytest -m pki tests/python/pki
```

Migration proceeds one scenario at a time. The equivalent case in
`tests/pki/test-ca-rollover.sh` remains authoritative and enabled until the
pytest replacement has demonstrated observable parity and passed independent
review.

Run the focused authoritative parser group without generating PKI seed state:

```bash
make test-pki-ca-rollover-parser
```

The no-argument `make test-pki-ca-rollover` target still runs the parser group
and the complete lifecycle matrix.

For long aggregate diagnostics, enable path-free elapsed-time records for the
active preparation, recovery, migration, hostile-state, and race scenario:

```bash
PLATFORM_PKI_TEST_PROGRESS=1 make test-pki-ca-rollover
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
