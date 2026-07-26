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

restore_intermediate_transaction() {
  local i destination backup expected_identity current_identity rollback_status=0

  for ((i = ${#TRANSACTION_DESTINATIONS[@]} - 1; i >= 0; i--)); do
    [[ ${TRANSACTION_PUBLISHED[i]:-false} == true ]] || continue
    destination=${TRANSACTION_DESTINATIONS[i]}
    backup=${TRANSACTION_BACKUPS[i]}
    expected_identity=${TRANSACTION_PUBLISHED_IDENTITIES[i]}
    if [[ -e $destination || -L $destination ]]; then
      if [[ ! -f $destination || -L $destination ]]; then
        printf '[ERROR] Published CA destination was replaced; preserving it and transaction staging: %s\n' "$destination" >&2
        rollback_status=1
        continue
      fi
      current_identity=$(stat -c '%d:%i' "$destination") || {
        rollback_status=1
        continue
      }
      if [[ $current_identity != "$expected_identity" ]]; then
        printf '[ERROR] Published CA destination identity changed; preserving it and transaction staging: %s\n' "$destination" >&2
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

finish_intermediate_create() {
  local status=$? rollback_status=0

  trap - EXIT
  trap '' HUP INT TERM
  if [[ ${TRANSACTION_ACTIVE:-false} == true && ${TRANSACTION_COMMITTED:-false} != true ]]; then
    restore_intermediate_transaction || rollback_status=1
  fi
  if (( rollback_status != 0 )); then
    printf '[ERROR] Failed to restore intermediate CA transaction; preserved staging and locks for recovery: %s\n' "${STAGE_DIR:-unknown}" >&2
    exit 1
  fi
  if [[ -n ${STAGE_DIR:-} ]]; then
    rm -rf -- "$STAGE_DIR" || rollback_status=1
  fi
  if [[ -n ${LOCK_DIR:-} ]]; then
    rmdir "$LOCK_DIR" 2>/dev/null || rollback_status=1
  fi
  if [[ ${INTERMEDIATE_OPERATION_LOCK_HELD:-false} == true ]]; then
    pki_release_operation_lock "$INTERMEDIATE_OPERATION_LOCK" 2>/dev/null || rollback_status=1
  fi
  if [[ ${ROOT_OPERATION_LOCK_HELD:-false} == true ]]; then
    pki_release_operation_lock "$ROOT_OPERATION_LOCK" 2>/dev/null || rollback_status=1
  fi
  if (( rollback_status != 0 )); then
    printf '[ERROR] Failed to restore or clean up intermediate CA transaction\n' >&2
    status=1
  fi
  exit "$status"
}

publish_intermediate_transaction() {
  local i source destination backup source_identity

  TRANSACTION_BACKUPS=()
  TRANSACTION_ORIGINALS=()
  TRANSACTION_PUBLISHED=()
  TRANSACTION_PUBLISHED_IDENTITIES=()
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    destination=${TRANSACTION_DESTINATIONS[i]}
    if [[ -e $destination ]]; then
      backup="$STAGE_DIR/backup-$i"
      cp -p -- "$destination" "$backup" || pki_die "Failed to back up existing CA state: $destination"
      TRANSACTION_BACKUPS[i]=$backup
      TRANSACTION_ORIGINALS[i]=true
    else
      TRANSACTION_BACKUPS[i]=''
      TRANSACTION_ORIGINALS[i]=false
    fi
  done

  TRANSACTION_ACTIVE=true
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    source=${TRANSACTION_SOURCES[i]}
    destination=${TRANSACTION_DESTINATIONS[i]}
    source_identity=$(stat -c '%d:%i' "$source") || pki_die "Cannot inspect staged CA state identity: $source"
    if [[ ${TRANSACTION_REPLACE[i]} == true ]]; then
      mv -f -- "$source" "$destination" || pki_die "Failed to publish CA state: $destination"
      TRANSACTION_PUBLISHED[i]=true
      TRANSACTION_PUBLISHED_IDENTITIES[i]=$source_identity
    else
      ln -- "$source" "$destination" || pki_die "Intermediate CA material appeared during creation; refusing to overwrite: $destination"
      TRANSACTION_PUBLISHED[i]=true
      TRANSACTION_PUBLISHED_IDENTITIES[i]=$source_identity
      rm -f -- "$source"
    fi
  done
  TRANSACTION_COMMITTED=true
  TRANSACTION_ACTIVE=false
}

write_staged_root_config() {
  local source=$1 destination=$2 line replacements=0

  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "dir = $ROOT_CA_DIR" ]]; then
      printf 'dir = %s\n' "$STAGE_ROOT_DIR" >>"$destination"
      replacements=$((replacements + 1))
    else
      printf '%s\n' "$line" >>"$destination"
    fi
  done <"$source"
  [[ $replacements -eq 1 ]] || pki_die "Root CA configuration has an unexpected directory setting: $source"
}

canonicalize_openssl_serial() {
  local serial=${1^^}

  while [[ $serial == 00* && ${#serial} -gt 2 ]]; do
    serial=${serial#00}
  done
  printf '%s\n' "$serial"
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
NAME=${args[--name]}
ORG=${args[--org]}
COUNTRY=${args[--country]}
DAYS=${args[--days]:-${PLATFORM_PKI_INTERMEDIATE_DAYS:-1825}}
ROOT_PASS_FILE=${args[--root-pass-file]:-}
INTERMEDIATE_PASS_FILE=${args[--intermediate-pass-file]:-}
FORCE=false
ALLOW_UNENCRYPTED=false
[[ -v args[--force] ]] && FORCE=true
[[ -v args[--allow-unencrypted-intermediate-key] ]] && ALLOW_UNENCRYPTED=true

pki_validate_days "$DAYS"
pki_validate_openssl_config_value 'Intermediate CA common name' "$NAME"
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
if [[ -n $INTERMEDIATE_PASS_FILE ]]; then
  INTERMEDIATE_PASS_FILE=$(pki_expand_path "$INTERMEDIATE_PASS_FILE")
  pki_require_pass_file "$INTERMEDIATE_PASS_FILE"
fi

pki_require_cmd openssl
ROOT_CA_DIR="$PKI_DIR/root-ca"
INTERMEDIATE_CA_DIR="$PKI_DIR/intermediate-ca"
ROOT_KEY=$(pki_root_key)
ROOT_CERT=$(pki_root_cert)
ROOT_CONF="$ROOT_CA_DIR/openssl.cnf"
INT_KEY=$(pki_intermediate_key)
INT_CERT=$(pki_intermediate_cert)
INT_CSR="$INTERMEDIATE_CA_DIR/csr/intermediate-ca.csr"
INT_CONF="$INTERMEDIATE_CA_DIR/openssl.cnf"
INT_CHAIN=$(pki_ca_chain)

validate_intermediate_operation_state() {
  local specification sidecar

  pki_require_no_symlink_path_components "$NAMESPACE" 'Namespace'
  pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
  pki_require_pki_dir
  for specification in \
    "$PKI_DIR|PKI directory" \
    "$ROOT_CA_DIR|Root CA directory" \
    "$ROOT_CA_DIR/private|Root CA private directory" \
    "$ROOT_CA_DIR/certs|Root CA certificate directory" \
    "$ROOT_CA_DIR/newcerts|Root CA new-certificates directory" \
    "$INTERMEDIATE_CA_DIR|Intermediate CA directory" \
    "$INTERMEDIATE_CA_DIR/private|Intermediate CA private directory" \
    "$INTERMEDIATE_CA_DIR/certs|Intermediate CA certificate directory" \
    "$INTERMEDIATE_CA_DIR/csr|Intermediate CA CSR directory"; do
    require_private_ca_dir "${specification%%|*}" "${specification#*|}"
  done

  for specification in \
    "$ROOT_CA_DIR/index.txt|Root CA index" \
    "$ROOT_CA_DIR/index.txt.attr|Root CA index attributes" \
    "$ROOT_CA_DIR/serial|Root CA serial" \
    "$ROOT_CA_DIR/crlnumber|Root CA CRL number" \
    "$ROOT_CONF|Root CA configuration" \
    "$ROOT_KEY|Root CA key" \
    "$ROOT_CERT|Root CA certificate" \
    "$INTERMEDIATE_CA_DIR/index.txt|Intermediate CA index" \
    "$INTERMEDIATE_CA_DIR/index.txt.attr|Intermediate CA index attributes" \
    "$INTERMEDIATE_CA_DIR/serial|Intermediate CA serial" \
    "$INTERMEDIATE_CA_DIR/crlnumber|Intermediate CA CRL number" \
    "$INT_CONF|Intermediate CA configuration" \
    "$INT_KEY|Intermediate CA key" \
    "$INT_CERT|Intermediate CA certificate" \
    "$INT_CSR|Intermediate CA CSR" \
    "$INT_CHAIN|Intermediate CA chain"; do
    require_safe_destination "${specification%%|*}" "${specification#*|}"
  done
  pki_require_file "$ROOT_KEY"
  pki_require_file "$ROOT_CERT"
  pki_require_file "$ROOT_CONF"

  if [[ $FORCE != true ]]; then
    [[ ! -e $INT_KEY ]] || pki_die "Intermediate key exists; use --force to overwrite: $INT_KEY"
    [[ ! -e $INT_CERT ]] || pki_die "Intermediate certificate exists; use --force to overwrite: $INT_CERT"
  fi

  ROOT_SERIAL=$(<"$ROOT_CA_DIR/serial")
  [[ $ROOT_SERIAL =~ ^[0-9A-Fa-f]+$ ]] || pki_die "Root CA serial is invalid: $ROOT_SERIAL"
  (( ${#ROOT_SERIAL} >= 2 && ${#ROOT_SERIAL} % 2 == 0 )) || \
    pki_die "Root CA serial must contain an even number of hexadecimal digits: $ROOT_SERIAL"
  ISSUED_SERIAL=$(canonicalize_openssl_serial "$ROOT_SERIAL")
  ROOT_NEWCERT="$ROOT_CA_DIR/newcerts/$ISSUED_SERIAL.pem"
  require_safe_destination "$ROOT_NEWCERT" 'Root CA issued-certificate destination'
  [[ ! -e $ROOT_NEWCERT && ! -L $ROOT_NEWCERT ]] || \
    pki_die "Root CA issued-certificate destination already exists: $ROOT_NEWCERT"
  for sidecar in index.txt.old index.txt.attr.old serial.old; do
    require_safe_destination "$ROOT_CA_DIR/$sidecar" "Root CA $sidecar"
  done
}

# This preflight rejects collisions and unsafe state without creating a lock.
validate_intermediate_operation_state

umask 077
ROOT_OPERATION_LOCK=$(pki_root_operation_lock)
INTERMEDIATE_OPERATION_LOCK=$(pki_intermediate_operation_lock)
ROOT_OPERATION_LOCK_HELD=false
INTERMEDIATE_OPERATION_LOCK_HELD=false
LOCK_DIR=''
STAGE_DIR=''
TRANSACTION_ACTIVE=false
TRANSACTION_COMMITTED=false
TRANSACTION_DESTINATIONS=()
TRANSACTION_SOURCES=()
TRANSACTION_REPLACE=()
TRANSACTION_BACKUPS=()
TRANSACTION_ORIGINALS=()
TRANSACTION_PUBLISHED=()
TRANSACTION_PUBLISHED_IDENTITIES=()
trap finish_intermediate_create EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Fixed ordering prevents deadlocks with root replacement and later CA consumers.
pki_acquire_operation_lock "$ROOT_OPERATION_LOCK" 'root CA operation'
ROOT_OPERATION_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_OPERATION_LOCK" 'intermediate CA operation'
INTERMEDIATE_OPERATION_LOCK_HELD=true
# Revalidate every transaction input after cooperating mutations are excluded.
validate_intermediate_operation_state
LOCK_DIR="$INTERMEDIATE_CA_DIR/.platform-pki-intermediate-create.lock"
mkdir "$LOCK_DIR" 2>/dev/null || pki_die "Another intermediate CA creation is in progress: $LOCK_DIR"
STAGE_DIR=$(mktemp -d "$INTERMEDIATE_CA_DIR/.platform-pki-intermediate-create.XXXXXX") || {
  pki_die 'Cannot create intermediate CA staging directory'
}

STAGE_ROOT_DIR="$STAGE_DIR/root-ca"
STAGE_INT_DIR="$STAGE_DIR/intermediate-ca"
mkdir -m 700 "$STAGE_ROOT_DIR" "$STAGE_ROOT_DIR/private" "$STAGE_ROOT_DIR/certs" \
  "$STAGE_ROOT_DIR/newcerts" "$STAGE_INT_DIR" "$STAGE_INT_DIR/private" \
  "$STAGE_INT_DIR/certs" "$STAGE_INT_DIR/csr"
cp -p -- "$ROOT_KEY" "$STAGE_ROOT_DIR/private/root-ca.key"
cp -p -- "$ROOT_CERT" "$STAGE_ROOT_DIR/certs/root-ca.crt"
for file in index.txt index.txt.attr serial crlnumber; do
  cp -p -- "$ROOT_CA_DIR/$file" "$STAGE_ROOT_DIR/$file"
done
write_staged_root_config "$ROOT_CONF" "$STAGE_ROOT_DIR/openssl.cnf"
chmod 600 "$STAGE_ROOT_DIR/openssl.cnf"

INTERMEDIATE_DB_NEW_FILES=()
for file in index.txt index.txt.attr serial crlnumber; do
  if [[ -e $INTERMEDIATE_CA_DIR/$file ]]; then
    cp -p -- "$INTERMEDIATE_CA_DIR/$file" "$STAGE_INT_DIR/$file"
  else
    INTERMEDIATE_DB_NEW_FILES+=("$file")
  fi
done
pki_init_ca_db "$STAGE_INT_DIR"
for file in "${INTERMEDIATE_DB_NEW_FILES[@]}"; do
  chmod 600 "$STAGE_INT_DIR/$file"
done

pki_write_intermediate_config "$STAGE_INT_DIR/openssl.cnf" "$COUNTRY" "$ORG" "$NAME"
chmod 600 "$STAGE_INT_DIR/openssl.cnf"

STAGE_KEY="$STAGE_INT_DIR/private/intermediate-ca.key"
STAGE_CSR="$STAGE_INT_DIR/csr/intermediate-ca.csr"
STAGE_CERT="$STAGE_INT_DIR/certs/intermediate-ca.crt"
STAGE_CHAIN="$STAGE_INT_DIR/certs/ca-chain.crt"
if [[ $ALLOW_UNENCRYPTED == true ]]; then
  pki_warn 'Creating an unencrypted intermediate CA private key because --allow-unencrypted-intermediate-key was used'
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "$STAGE_KEY"
elif [[ -n $INTERMEDIATE_PASS_FILE ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -pass "file:$INTERMEDIATE_PASS_FILE" -out "$STAGE_KEY"
else
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -out "$STAGE_KEY"
fi
chmod 600 "$STAGE_KEY"

REQ_CMD=(openssl req -config "$STAGE_INT_DIR/openssl.cnf" -key "$STAGE_KEY" -new -sha384 -out "$STAGE_CSR")
[[ -n $INTERMEDIATE_PASS_FILE ]] && REQ_CMD+=(-passin "file:$INTERMEDIATE_PASS_FILE")
"${REQ_CMD[@]}"
chmod 600 "$STAGE_CSR"
CA_CMD=(openssl ca -batch -config "$STAGE_ROOT_DIR/openssl.cnf" -extensions v3_intermediate_ca -days "$DAYS" -notext -md sha384 -in "$STAGE_CSR" -out "$STAGE_CERT")
[[ -n $ROOT_PASS_FILE ]] && CA_CMD+=(-passin "file:$ROOT_PASS_FILE")
"${CA_CMD[@]}"
chmod 644 "$STAGE_CERT"
cat "$STAGE_CERT" "$ROOT_CERT" >"$STAGE_CHAIN"
chmod 644 "$STAGE_CHAIN"

CERT_PUBLIC_KEY="$STAGE_DIR/cert.pub"
KEY_PUBLIC_KEY="$STAGE_DIR/key.pub"
openssl x509 -in "$STAGE_CERT" -pubkey -noout >"$CERT_PUBLIC_KEY"
PKEY_CMD=(openssl pkey -in "$STAGE_KEY" -pubout -out "$KEY_PUBLIC_KEY")
[[ -n $INTERMEDIATE_PASS_FILE ]] && PKEY_CMD+=(-passin "file:$INTERMEDIATE_PASS_FILE")
"${PKEY_CMD[@]}"
cmp -s "$CERT_PUBLIC_KEY" "$KEY_PUBLIC_KEY" || pki_die 'Generated intermediate CA key and certificate do not match'
openssl verify -CAfile "$ROOT_CERT" "$STAGE_CERT" >/dev/null || pki_die 'Generated intermediate CA certificate does not verify against the root CA'

TRANSACTION_SOURCES=(
  "$STAGE_INT_DIR/openssl.cnf" "$STAGE_KEY" "$STAGE_CSR" "$STAGE_CERT" "$STAGE_CHAIN"
  "$STAGE_ROOT_DIR/index.txt" "$STAGE_ROOT_DIR/index.txt.attr" "$STAGE_ROOT_DIR/serial"
  "$STAGE_ROOT_DIR/index.txt.old" "$STAGE_ROOT_DIR/index.txt.attr.old" "$STAGE_ROOT_DIR/serial.old"
  "$STAGE_ROOT_DIR/newcerts/$ISSUED_SERIAL.pem"
)
TRANSACTION_DESTINATIONS=(
  "$INT_CONF" "$INT_KEY" "$INT_CSR" "$INT_CERT" "$INT_CHAIN"
  "$ROOT_CA_DIR/index.txt" "$ROOT_CA_DIR/index.txt.attr" "$ROOT_CA_DIR/serial"
  "$ROOT_CA_DIR/index.txt.old" "$ROOT_CA_DIR/index.txt.attr.old" "$ROOT_CA_DIR/serial.old"
  "$ROOT_NEWCERT"
)
TRANSACTION_REPLACE=(true "$FORCE" true "$FORCE" true true true true true true true false)
for file in "${INTERMEDIATE_DB_NEW_FILES[@]}"; do
  TRANSACTION_SOURCES+=("$STAGE_INT_DIR/$file")
  TRANSACTION_DESTINATIONS+=("$INTERMEDIATE_CA_DIR/$file")
  TRANSACTION_REPLACE+=(false)
done
publish_intermediate_transaction
pki_ok "Created intermediate CA certificate: $INT_CERT"
