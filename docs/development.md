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

## Generator Updates

The development image pins the Bashly image digest and direct Alpine package
versions. Update the base digest and package pins together, inspect upstream
release notes, regenerate all Bashly-backed tools, and run a clean build:

```bash
podman build --no-cache -f Containerfile.dev .
make container-check
```

Alpine package repositories remain mutable. Exact package versions make
changes fail visibly, but old versions can eventually disappear and require a
reviewed pin refresh.
