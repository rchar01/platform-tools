info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

validate_not_empty() {
  [[ -n $1 ]] || printf '%s\n' 'must not be empty'
}

expand_path() {
  case $1 in
    \~) printf '%s\n' "$HOME" ;;
    \~/*) printf '%s/%s\n' "$HOME" "${1:2}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

default_config_dir() {
  printf '%s/platform-infrastructure\n' "${XDG_CONFIG_HOME:-$HOME/.config}"
}

write_if_missing() {
  local path=$1
  local content_name=$2

  if [[ -e "$path" ]]; then
    chmod 600 "$path"
    info "Kept existing file: $path"
    return 0
  fi

  "$content_name" >"$path"
  chmod 600 "$path"
  ok "Created $path"
}

ensure_secret_dir() {
  local path=$1

  mkdir -p "$path"
  chmod 700 "$path"
  ok "Namespace directory ready: $path"
}

content_readme() {
  cat <<'EOF'
# Platform Infrastructure Local Config

This directory stores local platform secret material that must stay outside Git.

Shared namespaces:

- `infra/`: OpenTofu and infrastructure bootstrap secrets, for example tokens.
- `config/`: Ansible and service secrets, for example certs, keys, kubeconfigs, and passwords.
- `pki/`: CA state, issued certificates, service private keys, exports, and backups managed by PKI helpers.

This initializer creates only the shared root namespaces. Each downstream platform project or helper owns its concrete secret subdirectories and files.

Common environment variables:

```bash
export PLATFORM_INFRASTRUCTURE_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/config"
export PLATFORM_INFRASTRUCTURE_PKI_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/pki"
```

Usage example:

```bash
tofu plan -var-file=../../../platform-private/infra/production.tfvars
```

Store the Proxmox token as one raw line in `infra/proxmox.token`. Do not export the token into the shell session unless a downstream tool explicitly requires it.

Do not commit real values from this directory into any `platform-*` repository.

Private but non-secret operator config belongs in private Git, for example `platform-private`.
EOF
}
