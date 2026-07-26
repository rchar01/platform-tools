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

The generated parser treats `--help` and `--version` as global options when
they appear before command-specific options. Nonempty `--flag=value` forms are
accepted; an empty equals-form value is an invalid option. Keep these stock
Bashly rules consistent across migrated tools rather than maintaining custom
generator templates.

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
