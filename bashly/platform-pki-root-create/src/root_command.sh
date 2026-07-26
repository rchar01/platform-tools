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

require_private_ca_dir() {
  local path=$1 label=$2 mode owner current_uid

  [[ -d $path && ! -L $path ]] || pki_die "$label must be a non-symlink directory: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label permissions: $path"
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label owner: $path"
  current_uid=$(id -u)
  [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label metadata: $path"
  [[ $owner == "$current_uid" ]] || pki_die "$label is not owned by the current user: $path"
  if (( (8#$mode & 022) != 0 )); then
    pki_die "$label is group- or world-writable: $path"
  fi
}

require_safe_destination() {
  local path=$1 label=$2 mode owner links current_uid

  [[ ! -L $path ]] || pki_die "$label must not be a symlink: $path"
  [[ ! -e $path || -f $path ]] || pki_die "$label must be a regular file: $path"
  [[ ! -e $path ]] && return 0
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label permissions: $path"
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label owner: $path"
  links=$(stat -c '%h' "$path") || pki_die "Cannot inspect $label link count: $path"
  current_uid=$(id -u)
  [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ && $links =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label metadata: $path"
  [[ $owner == "$current_uid" ]] || pki_die "$label is not owned by the current user: $path"
  [[ $links == 1 ]] || pki_die "$label must not be hard-linked: $path"
  if (( (8#$mode & 022) != 0 )); then
    pki_die "$label is group- or world-writable: $path"
  fi
}

restore_root_material() {
  local i destination backup expected_identity current_identity rollback_status=0

  for ((i = ${#TRANSACTION_DESTINATIONS[@]} - 1; i >= 0; i--)); do
    [[ ${TRANSACTION_PUBLISHED[i]:-false} == true ]] || continue
    destination=${TRANSACTION_DESTINATIONS[i]}
    backup=${TRANSACTION_BACKUPS[i]}
    expected_identity=${TRANSACTION_PUBLISHED_IDENTITIES[i]}
    if [[ -e $destination || -L $destination ]]; then
      if [[ ! -f $destination || -L $destination ]]; then
        printf '[ERROR] Published root CA destination was replaced; preserving it and transaction staging: %s\n' "$destination" >&2
        rollback_status=1
        continue
      fi
      current_identity=$(stat -c '%d:%i' "$destination") || {
        rollback_status=1
        continue
      }
      if [[ $current_identity != "$expected_identity" ]]; then
        printf '[ERROR] Published root CA destination identity changed; preserving it and transaction staging: %s\n' "$destination" >&2
        rollback_status=1
        continue
      fi
      rm -f -- "$destination" || {
        rollback_status=1
        continue
      }
    fi
    if [[ ${TRANSACTION_ORIGINALS[i]} == true ]]; then
      ln -- "$backup" "$destination" || rollback_status=1
    fi
  done
  return "$rollback_status"
}

finish_root_create() {
  local status=$? rollback_status=0

  trap - EXIT
  trap '' HUP INT TERM
  if [[ ${TRANSACTION_ACTIVE:-false} == true && ${TRANSACTION_COMMITTED:-false} != true ]]; then
    restore_root_material || rollback_status=1
  fi
  if (( rollback_status != 0 )); then
    printf '[ERROR] Failed to restore root CA transaction; preserved staging and locks for recovery: %s\n' "${STAGE_DIR:-unknown}" >&2
    exit 1
  fi
  if [[ -n ${STAGE_DIR:-} ]]; then
    rm -rf -- "$STAGE_DIR" || rollback_status=1
  fi
  if [[ -n ${LOCK_DIR:-} ]]; then
    rmdir "$LOCK_DIR" 2>/dev/null || rollback_status=1
  fi
  if [[ ${ROOT_OPERATION_LOCK_HELD:-false} == true ]]; then
    pki_release_operation_lock "$ROOT_OPERATION_LOCK" 2>/dev/null || rollback_status=1
  fi
  if (( rollback_status != 0 )); then
    printf '[ERROR] Failed to restore or clean up root CA transaction\n' >&2
    status=1
  fi
  exit "$status"
}

publish_root_material() {
  local i source destination backup source_identity
  local -a sources

  sources=("$STAGE_CONF" "$STAGE_KEY" "$STAGE_CERT")
  TRANSACTION_DESTINATIONS=("$ROOT_CONF" "$ROOT_KEY" "$ROOT_CERT")
  TRANSACTION_BACKUPS=('' '' '')
  TRANSACTION_ORIGINALS=(false false false)
  TRANSACTION_PUBLISHED=()
  TRANSACTION_PUBLISHED_IDENTITIES=()
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    destination=${TRANSACTION_DESTINATIONS[i]}
    if [[ -e $destination ]]; then
      backup="$STAGE_DIR/backup-$i"
      cp -p -- "$destination" "$backup" || pki_die "Failed to back up existing root CA material: $destination"
      TRANSACTION_BACKUPS[i]=$backup
      TRANSACTION_ORIGINALS[i]=true
    fi
  done

  TRANSACTION_ACTIVE=true
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    source=${sources[i]}
    destination=${TRANSACTION_DESTINATIONS[i]}
    source_identity=$(stat -c '%d:%i' "$source") || pki_die "Cannot inspect staged root CA material identity: $source"
    if [[ $FORCE == true || $destination == "$ROOT_CONF" ]]; then
      mv -f -- "$source" "$destination" || pki_die "Failed to publish root CA material: $destination"
      TRANSACTION_PUBLISHED[i]=true
      TRANSACTION_PUBLISHED_IDENTITIES[i]=$source_identity
    else
      ln -- "$source" "$destination" || pki_die "Root CA material appeared during creation; refusing to overwrite: $destination"
      TRANSACTION_PUBLISHED[i]=true
      TRANSACTION_PUBLISHED_IDENTITIES[i]=$source_identity
      rm -f -- "$source"
    fi
  done
  TRANSACTION_COMMITTED=true
  TRANSACTION_ACTIVE=false
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
NAME=${args[--name]}
ORG=${args[--org]}
COUNTRY=${args[--country]}
DAYS=${args[--days]:-${PLATFORM_PKI_ROOT_DAYS:-3650}}
ROOT_PASS_FILE=${args[--root-pass-file]:-}
FORCE=false
ALLOW_UNENCRYPTED=false
if [[ -v args[--force] ]]; then
  FORCE=true
fi
if [[ -v args[--allow-unencrypted-root-key] ]]; then
  ALLOW_UNENCRYPTED=true
fi

pki_validate_days "$DAYS"
pki_validate_openssl_config_value 'Root CA common name' "$NAME"
pki_validate_openssl_config_value 'Organization name' "$ORG"
pki_validate_openssl_config_value 'Country code' "$COUNTRY"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_validate_openssl_config_value 'PKI directory' "$PKI_DIR"
if [[ -n $ROOT_PASS_FILE ]]; then
  ROOT_PASS_FILE=$(pki_expand_path "$ROOT_PASS_FILE")
  pki_require_pass_file "$ROOT_PASS_FILE"
fi

pki_require_cmd openssl
ROOT_CA_DIR="$PKI_DIR/root-ca"
ROOT_KEY=$(pki_root_key)
ROOT_CERT=$(pki_root_cert)
ROOT_CONF="$ROOT_CA_DIR/openssl.cnf"

validate_root_operation_state() {
  pki_require_no_symlink_path_components "$NAMESPACE" 'Namespace'
  pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
  pki_require_pki_dir
  require_private_ca_dir "$PKI_DIR" 'PKI directory'
  require_private_ca_dir "$ROOT_CA_DIR" 'Root CA directory'
  require_private_ca_dir "$ROOT_CA_DIR/private" 'Root CA private directory'
  require_private_ca_dir "$ROOT_CA_DIR/certs" 'Root CA certificate directory'
  require_safe_destination "$ROOT_CA_DIR/index.txt" 'Root CA index'
  require_safe_destination "$ROOT_CA_DIR/index.txt.attr" 'Root CA index attributes'
  require_safe_destination "$ROOT_CA_DIR/serial" 'Root CA serial'
  require_safe_destination "$ROOT_CA_DIR/crlnumber" 'Root CA CRL number'
  require_safe_destination "$ROOT_CONF" 'Root CA configuration'
  require_safe_destination "$ROOT_KEY" 'Root CA key'
  require_safe_destination "$ROOT_CERT" 'Root CA certificate'

  if [[ $FORCE != true ]]; then
    [[ ! -e $ROOT_KEY ]] || pki_die "Root key exists; use --force to overwrite: $ROOT_KEY"
    [[ ! -e $ROOT_CERT ]] || pki_die "Root certificate exists; use --force to overwrite: $ROOT_CERT"
  fi
}

validate_root_operation_state

umask 077
ROOT_OPERATION_LOCK=$(pki_root_operation_lock)
ROOT_OPERATION_LOCK_HELD=false
LOCK_DIR=''
STAGE_DIR=''
TRANSACTION_ACTIVE=false
TRANSACTION_COMMITTED=false
TRANSACTION_DESTINATIONS=()
TRANSACTION_BACKUPS=()
TRANSACTION_ORIGINALS=()
TRANSACTION_PUBLISHED=()
TRANSACTION_PUBLISHED_IDENTITIES=()
trap finish_root_create EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# CA mutation locks are always acquired root first, then intermediate when needed.
pki_acquire_operation_lock "$ROOT_OPERATION_LOCK" 'root CA operation'
ROOT_OPERATION_LOCK_HELD=true
validate_root_operation_state
pki_init_ca_db "$ROOT_CA_DIR"
LOCK_DIR="$ROOT_CA_DIR/.platform-pki-root-create.lock"
mkdir "$LOCK_DIR" 2>/dev/null || pki_die "Another root CA creation is in progress: $LOCK_DIR"
STAGE_DIR=$(mktemp -d "$ROOT_CA_DIR/.platform-pki-root-create.XXXXXX") || {
  pki_die 'Cannot create root CA staging directory'
}

STAGE_KEY="$STAGE_DIR/root-ca.key"
STAGE_CERT="$STAGE_DIR/root-ca.crt"
STAGE_CONF="$STAGE_DIR/openssl.cnf"
pki_write_root_config "$STAGE_CONF" "$COUNTRY" "$ORG" "$NAME"
chmod 600 "$STAGE_CONF"

if [[ $ALLOW_UNENCRYPTED == true ]]; then
  pki_warn 'Creating an unencrypted root CA private key because --allow-unencrypted-root-key was used'
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "$STAGE_KEY"
elif [[ -n $ROOT_PASS_FILE ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -pass "file:$ROOT_PASS_FILE" -out "$STAGE_KEY"
else
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -out "$STAGE_KEY"
fi
chmod 600 "$STAGE_KEY"

REQ_CMD=(openssl req -config "$STAGE_CONF" -key "$STAGE_KEY" -new -x509 -days "$DAYS" -sha384 -extensions v3_root_ca -out "$STAGE_CERT")
if [[ -n $ROOT_PASS_FILE ]]; then
  REQ_CMD+=(-passin "file:$ROOT_PASS_FILE")
fi
"${REQ_CMD[@]}"
chmod 644 "$STAGE_CERT"

CERT_PUBLIC_KEY="$STAGE_DIR/cert.pub"
KEY_PUBLIC_KEY="$STAGE_DIR/key.pub"
openssl x509 -in "$STAGE_CERT" -pubkey -noout >"$CERT_PUBLIC_KEY"
PKEY_CMD=(openssl pkey -in "$STAGE_KEY" -pubout -out "$KEY_PUBLIC_KEY")
if [[ -n $ROOT_PASS_FILE ]]; then
  PKEY_CMD+=(-passin "file:$ROOT_PASS_FILE")
fi
"${PKEY_CMD[@]}"
cmp -s "$CERT_PUBLIC_KEY" "$KEY_PUBLIC_KEY" || pki_die 'Generated root CA key and certificate do not match'

publish_root_material
pki_ok "Created root CA certificate: $ROOT_CERT"
