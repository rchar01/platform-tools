# Proxmox Token Init

`platform-proxmox-token-init` bootstraps the Proxmox API identity used by platform OpenTofu runs.

This is Proxmox control-plane bootstrap work. It belongs in `platform-tools`, not in `platform-infra`.

```text
platform-tools = operator/bootstrap helpers
platform-infra = OpenTofu VM lifecycle using an existing API token
```

## Requirements

Run the helper on a Proxmox host or use `--ssh` from an operator workstation. The remote SSH user must be able to run `pveum` and manage Proxmox users, API tokens, and ACLs.

Automatic token-file writing with `--write-token-file` requires `jq` on the Proxmox host so the helper can parse the one-time secret from `pveum` JSON output. Without `jq`, omit `--write-token-file` and copy the token line from the remote command output manually.

Do not run this helper with shell tracing enabled, because token creation output includes a one-time secret.

## Usage

Install the shared tools on your operator workstation, then run the explicit SSH workflow:

```bash
platform-proxmox-token-init \
  --ssh root@<proxmox-ip> \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path / \
  --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token
```

This streams the helper over SSH, runs `pveum` on the Proxmox host, captures a newly generated token secret over the encrypted SSH connection, and writes it locally with mode `600`.

Use the Proxmox IP address until you have a trusted hostname or SSH alias. `root@pve` only works when `pve` resolves through DNS, `/etc/hosts`, or a `Host pve` block in `~/.ssh/config`.

Check prerequisites before creating anything:

```bash
platform-proxmox-token-init \
  --ssh root@<proxmox-ip> \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path / \
  --write-token-file ~/.config/platform-infrastructure/infra/proxmox.token \
  --check
```

Check mode verifies the exact workflow requested by the flags. With `--write-token-file`, it checks the automatic token-file workflow and requires remote `jq`. Without `--write-token-file`, it checks the manual token output workflow and treats `jq` as optional. It does not create users, tokens, or ACLs.

To print the generated token line instead of writing it automatically:

```bash
platform-proxmox-token-init \
  --ssh root@<proxmox-ip> \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path /
```

If already running on the Proxmox host, run:

```bash
platform-proxmox-token-init \
  --proxmox-user tofu@pve \
  --token-id platform \
  --role Administrator \
  --path /
```

Run directly from a checkout before install:

```bash
./bin/platform-proxmox-token-init
```

Default identity:

| Setting | Default |
| --- | --- |
| User | `tofu@pve` |
| Token ID | `platform` |
| Token format | `tofu@pve!platform=TOKEN_SECRET` |
| Initial role | `Administrator` |
| ACL path | `/` |
| Privilege separation | `0` |

The broad `Administrator` role is for initial private platform validation. Replace it with a least-privilege role after basic provisioning works.

## What It Does

The helper:

- Checks that `pveum` exists on the Proxmox host.
- Ensures the Proxmox user exists.
- Creates the API token if it does not already exist.
- Grants the initial ACL to the user.
- Prints or writes the next step for storing the generated token outside Git.

Equivalent manual commands:

```bash
pveum user add tofu@pve --comment "OpenTofu automation user"
pveum user token add tofu@pve platform --privsep 0
pveum aclmod / -user tofu@pve -role Administrator
```

These manual `pveum` commands are the source-of-truth behavior. The helper only wraps them with existence checks and clearer next-step output.

## Token Secret Caveat

Proxmox only shows the token secret when the token is created.

If `tofu@pve!platform` already exists, the helper cannot recover the existing secret. It will print a warning like:

```text
Token tofu@pve!platform already exists. Proxmox cannot show the existing secret.
Delete and recreate the token if you lost the token secret.
```

The helper does not delete or recreate existing tokens. If `--write-token-file` is used and the token already exists, nothing is written because Proxmox cannot reveal the old secret.

When the helper creates a new token with `jq` available, it validates the generated full token ID and the UUID-shaped secret before printing or writing it. If parsing or validation fails, the helper refuses to print raw `pveum` output because that output may contain the one-time secret.

## Store The Token

With `--write-token-file`, the helper writes the newly generated token line into:

```text
~/.config/platform-infrastructure/infra/proxmox.token
```

The file should contain one raw line only:

```text
tofu@pve!platform=TOKEN_SECRET
```

Without `--write-token-file`, copy the generated token line into that file manually.

Use `platform-config-init` to create the local outside-Git secret namespace before running the token helper:

```bash
platform-config-init
```

Keep `~/.config/platform-infrastructure/infra/proxmox.token` mode `600` and do not commit token values into any `platform-*` repository.

## Manual API Verification

The helper does not call the Proxmox HTTPS API with the generated token. Keep that as an explicit troubleshooting step so the API endpoint and TLS behavior are visible to the operator.

Verify the stored token manually from the operator workstation:

```bash
curl -kfsS \
  -H "Authorization: PVEAPIToken=$(< ~/.config/platform-infrastructure/infra/proxmox.token)" \
  https://<proxmox-ip>:8006/api2/json/version
```

A successful response includes Proxmox version data, for example:

```json
{"data":{"version":"9.1.1","repoid":"...","release":"9.1"}}
```

Common failures:

- `401 Unauthorized`: the token line is malformed, the token secret is wrong, or the remote token was deleted/recreated after the local file was written.
- Connection refused or timeout: check the Proxmox IP address, routing, firewall, and API port `8006`.
- TLS certificate error without `-k`: expected with a self-signed Proxmox certificate unless the local trust store has been configured.

This check proves the token can authenticate to the Proxmox API. It does not prove the token has enough authorization for every OpenTofu VM operation; keep the documented initial ACL in place until the first provisioning workflow succeeds.

## Options

```text
Usage: platform-proxmox-token-init [options]

Options:
  --ssh <user@host>              SSH target for the Proxmox host.
  --write-token-file <path>      Write a newly generated token line to this
                                 local file with mode 600. Refuses to overwrite
                                 a non-empty file unless --force is set.
  --force                        Allow --write-token-file to overwrite a
                                 non-empty local token file.
  --check                        Check local and Proxmox host prerequisites
                                 without creating users, tokens, or ACLs.
  --proxmox-user <userid>        Proxmox API user ID. Default: tofu@pve
  --user <userid>                Alias for --proxmox-user.
  --token-id <id>                Proxmox token ID. Default: platform
  --role <role>                  Initial role to grant. Default: Administrator
  --path <acl-path>              ACL path to grant. Default: /
  --comment <text>               User comment. Default: OpenTofu automation user
  -h, --help                     Show this help.
```

`--ssh root@<proxmox-ip>` controls how the helper reaches the Proxmox host. `--proxmox-user tofu@pve` controls the Proxmox API identity created inside Proxmox. They are different users in different systems.

With `--privsep 0`, the token inherits the user's ACLs. If you later use a privilege-separated token, grant permissions to the token identity instead of relying on inherited user permissions.
