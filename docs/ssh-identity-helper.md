# SSH Identity Helper

`platform-ssh-init` creates purpose-specific local SSH keypairs and can print SSH config blocks, append host aliases to `~/.ssh/config`, test host access, and print public keys for cloud-init workflows.

The tool is optional for downstream repositories. It is a setup helper, not a runtime dependency. CI/CD should normally provide keys through its secret system instead of generating keys during a pipeline.

## Install

Clone the canonical `platform-tools` repository and install the tool into `~/.local/bin`:

```bash
git clone https://codeberg.org/rch/platform-tools
cd platform-tools
make install
```

Use another install directory when needed:

```bash
make install INSTALL_DIR="$PWD/.tools/bin"
```

Ensure the install directory is on `PATH` when invoking `platform-ssh-init` by command name.

Downstream repositories such as `https://codeberg.org/rch/platform-infra` should reference this tool from `platform-tools` instead of carrying their own copy.

## Usage Modes

`platform-ssh-init` supports two equivalent input modes:

- Config file mode for repeatable project workflows and private repositories.
- CLI flag mode for one-off keys or Make loops that derive key paths from VM names.

If both are used, CLI flags override config file values:

```text
defaults < config file < CLI flags
```

Do not pass secrets through CLI flags. SSH key path, comment, host, user, and alias are not secret values, so CLI flags are acceptable for this helper.

## Config Files

Config files are optional, but they remain useful for repeatable repository workflows. Real operator config files belong in private repositories such as `platform-private`, not in `platform-tools` or `~/.config/platform-infrastructure/`.

Config files use a strict `NAME=value` parser, not shell execution. Only the variables in the schema below are accepted. Blank lines and full-line comments are allowed; arbitrary shell commands, command substitution, and unsupported variable names are rejected. `${HOME}`, `$HOME`, and leading `~` are expanded for convenience.

Example private layout:

```text
platform-private/
  template-builder/
    ssh/template-builder.env
  infra/
    ssh/production-cloud-init.env
    ssh/dev-cloud-init.env
```

## Config Schema

| Variable | Required | Purpose |
|---|---|---|
| `SSH_KEY_PATH` | yes, unless `--key-path` is used | Local private key path to create or reuse. |
| `SSH_KEY_COMMENT` | no | Comment stored in the generated public key. |
| `SSH_HOST` | no | Hostname or IP for an SSH config block. |
| `SSH_USER` | no | SSH user for the host alias. Defaults to the current local user. |
| `SSH_ALIAS` | no | Local `~/.ssh/config` host alias. Required with `SSH_HOST` for host config output. |
| `SSH_TEST_COMMAND` | no | Remote command used by `--test`. Defaults to `hostname`. |

## CLI Flags

Direct input flags map to the config schema:

| Flag | Equivalent config variable |
|---|---|
| `--key-path <path>` | `SSH_KEY_PATH` |
| `--comment <text>` | `SSH_KEY_COMMENT` |
| `--host <host>` | `SSH_HOST` |
| `--user <user>` | `SSH_USER` |
| `--alias <alias>` | `SSH_ALIAS` |
| `--test-command <cmd>` | `SSH_TEST_COMMAND` |

Example with host config output:

```bash
platform-ssh-init \
  --key-path ~/.ssh/platform-template-builder_ed25519 \
  --comment "platform template builder" \
  --host 192.0.2.10 \
  --user root \
  --alias pve-template-builder
```

## Private Config File Example

Run with a config file owned by private operator config:

```bash
platform-ssh-init ../platform-private/template-builder/ssh/template-builder.env
```

Append the generated host block to `~/.ssh/config`:

```bash
platform-ssh-init ../platform-private/template-builder/ssh/template-builder.env --write-config
```

Test direct SSH access defined by the config:

```bash
platform-ssh-init ../platform-private/template-builder/ssh/template-builder.env --test
```

## Cloud-Init Public Key Example

Use a private config file when the key path is managed by a downstream repo:

```bash
platform-ssh-init ../platform-private/infra/ssh/production-cloud-init.env --print-public-key
```

For one-off or generated per-VM keys, prefer CLI flags in the loop rather than creating one env file per VM. The VM-specific key path and comment can be derived from the VM name:

```bash
vm=vm01
platform-ssh-init \
  --key-path "~/.ssh/platform-${vm}-cloud-init_ed25519" \
  --comment "platform ${vm} cloud-init" \
  --empty-passphrase \
  --print-public-key
```

Use this for workflows such as `platform-infra`, where OpenTofu injects an SSH public key into cloned VMs through cloud-init.

Minimal config-file shape for the same workflow:

```text
SSH_KEY_PATH="${HOME}/.ssh/platform-production-cloud-init_ed25519"
SSH_KEY_COMMENT="platform production cloud-init"
```

Remote-host config files may also include host metadata:

```text
SSH_KEY_PATH="${HOME}/.ssh/platform-template-builder_ed25519"
SSH_KEY_COMMENT="platform template builder"
SSH_HOST="192.0.2.10"
SSH_USER="root"
SSH_ALIAS="pve-template-builder"
SSH_TEST_COMMAND="hostname"
```

Do not use one shared SSH key for every platform purpose. Prefer purpose-specific keys such as:

```text
~/.ssh/platform-template-builder_ed25519
~/.ssh/platform-infra-cloud-init_ed25519
~/.ssh/platform-config-ansible_ed25519
```

Existing private keys are reused, but their mode is corrected to `600`. Public key files are corrected to `644`.

## Action Flags

| Flag | Behavior |
|---|---|
| `--empty-passphrase` | Create a new key without prompting for a passphrase. Use only when you intentionally want an unencrypted local private key. |
| `--write-config` | Append the generated host block to `~/.ssh/config`. Requires `SSH_HOST` and `SSH_ALIAS` from a config file or `--host` and `--alias` flags. |
| `--test` | Run `SSH_TEST_COMMAND` or `hostname` over SSH using `SSH_HOST`, `SSH_USER`, and `SSH_KEY_PATH`; it does not use custom options from `~/.ssh/config`. Keep custom test commands read-only. |
| `--print-public-key` | Print the generated or existing public key. |

## CI/CD

CI/CD should usually skip this tool. Pipelines should receive private keys and config files through the CI secret system or a checked-out private repository.

After placing the key and SSH config, downstream repositories should run their own verification commands, for example:

```bash
ssh pve-template-builder 'hostname'
make check-tools TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder
```

## Downstream Repositories

- `platform-template-builder`: may wrap this tool with `make init-ssh`, but template builds only require working SSH access.
- `platform-infra`: may use this tool to create a cloud-init SSH keypair, but OpenTofu workflows should only need the resulting public key.
- `platform-config`: may use a purpose-specific Ansible SSH key, but Ansible runtime should only require an available key and inventory.
