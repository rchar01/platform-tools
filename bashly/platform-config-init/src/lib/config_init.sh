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

This directory stores local platform secrets and machine-specific security-sensitive records that must stay outside Git.

Shared namespaces:

- `infra/`: OpenTofu and infrastructure bootstrap material, for example tokens and reviewed local CA files.
- `config/`: Ansible and service inputs, for example keys, kubeconfigs, passwords, and pinned endpoint records.
- `pki/`: current authoritative CA state, issued certificates, service private keys, exports, and backups managed by PKI helpers.

This initializer creates only `infra/`, `config/`, `pki/`, and this README. Each downstream platform project, helper, or explicit workflow owns its concrete subdirectories and files.

Related PKI paths are intentionally not created here:

- `pki-exchange/`: workflow-owned controller and transport workspace beside `pki/`.
- `${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-offline/<exact-protocol-service>/`: generation-specific offline custody and staging workspaces.
- `${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-keys/<trust-domain>/`: stable approval and response operator keys external to authoritative PKI backups.

Keep `pki/` for current authoritative state. Keep `pki-exchange/` for current workflow state and retained exchange history. Quarantine retired, suspect, or unmanaged material in a separate owner-only path outside both trees; do not mix quarantine with current state.

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

Desired private non-secret configuration belongs in private Git, for example `platform-private`. Keep only secrets and machine-specific security-sensitive records here.
EOF
}
