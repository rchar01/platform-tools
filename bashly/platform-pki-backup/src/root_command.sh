SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then
  COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then
  COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else
  COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh
fi
[[ -r $COMMON_PATH ]] || {
  printf '[ERROR] platform-pki-common.sh not found\n' >&2
  exit 1
}
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"

new_backup_path() {
  local extension=$1
  local timestamp base candidate n

  timestamp=$(date -u '+%Y%m%d-%H%M%S')
  base="${BACKUP_DIR}/platform-pki-${timestamp}${extension}"
  candidate=$base
  n=1
  while [[ -e $candidate || -L $candidate ]]; do
    candidate=$(printf '%s/platform-pki-%s-%02d%s' "$BACKUP_DIR" "$timestamp" "$n" "$extension")
    n=$((n + 1))
  done
  printf '%s\n' "$candidate"
}

publish_backup() {
  local source=$1
  local extension=$2

  while true; do
    FINAL_PATH=$(new_backup_path "$extension")
    if ln "$source" "$FINAL_PATH"; then
      rm -f "$source"
      chmod 600 "$FINAL_PATH"
      return 0
    fi
    if [[ ! -e $FINAL_PATH && ! -L $FINAL_PATH ]]; then
      pki_die "Failed to publish PKI backup: $FINAL_PATH"
    fi
  done
}

add_tar_exclude_if_in_pki() {
  local path=$1
  local rel

  case ${path}/ in
    "${PKI_REAL}"/*)
      rel=${path#"$PKI_REAL"/}
      TAR_EXCLUDES+=(--no-wildcards --exclude "${PKI_BASE}/${rel}")
      ;;
  esac
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
BACKUP_DIR=${args[--backup-dir]:-}
ALLOW_PLAIN=false
if [[ -v args[--allow-plain-backup] ]]; then
  ALLOW_PLAIN=true
fi
AGE_RECIPIENTS=()
# Bashly shell-quotes each repeatable value before joining the aggregate.
# shellcheck disable=SC2294
eval "AGE_RECIPIENTS=(${args[--age-recipient]:-})"

NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
BACKUP_DIR=${BACKUP_DIR:-${PKI_DIR}/backups}
BACKUP_DIR=$(pki_expand_path "$BACKUP_DIR")

pki_require_cmd tar
TAR_HELP=$(tar --help 2>/dev/null || true)
case $TAR_HELP in
  *--no-wildcards*) ;;
  *) pki_die 'tar with --no-wildcards support is required for safe PKI backup exclusions' ;;
esac
pki_require_pki_dir
pki_prepare_dir "$BACKUP_DIR"

PKI_REAL=$(cd -- "$PKI_DIR" && pwd -P)
BACKUP_REAL=$(cd -- "$BACKUP_DIR" && pwd -P)
BACKUP_INPUT=$(cd -- "$(dirname -- "$BACKUP_DIR")" && pwd -P)/$(basename -- "$BACKUP_DIR")
PKI_BASE=$(basename -- "$PKI_REAL")
TAR_EXCLUDES=()

if [[ $BACKUP_REAL == "$PKI_REAL" ]]; then
  pki_die "Backup directory cannot be the PKI directory itself: $BACKUP_DIR"
fi

add_tar_exclude_if_in_pki "$BACKUP_REAL"
if [[ $BACKUP_INPUT != "$BACKUP_REAL" ]]; then
  add_tar_exclude_if_in_pki "$BACKUP_INPUT"
fi

TMP_DIR=$(mktemp -d "$BACKUP_REAL/.platform-pki-backup.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_ARCHIVE="$TMP_DIR/platform-pki.tar.gz"

pki_warn "PKI backup contains secrets, including private keys and CA database files"
tar "${TAR_EXCLUDES[@]}" -C "$(dirname -- "$PKI_REAL")" -czf "$TMP_ARCHIVE" "$PKI_BASE"
chmod 600 "$TMP_ARCHIVE"

if [[ $ALLOW_PLAIN == true ]]; then
  publish_backup "$TMP_ARCHIVE" '.tar.gz'
  pki_warn "Created unencrypted PKI backup because --allow-plain-backup was used: $FINAL_PATH"
  exit 0
fi

pki_require_cmd age
TMP_ENCRYPTED="$TMP_DIR/platform-pki.tar.gz.age"

if [[ ${#AGE_RECIPIENTS[@]} -gt 0 ]]; then
  AGE_CMD=(age)
  for recipient in "${AGE_RECIPIENTS[@]}"; do
    AGE_CMD+=(-r "$recipient")
  done
  AGE_CMD+=(-o "$TMP_ENCRYPTED" "$TMP_ARCHIVE")
  "${AGE_CMD[@]}"
else
  age -p -o "$TMP_ENCRYPTED" "$TMP_ARCHIVE"
fi

chmod 600 "$TMP_ENCRYPTED"
publish_backup "$TMP_ENCRYPTED" '.tar.gz.age'
pki_ok "Created encrypted PKI backup: $FINAL_PATH"
