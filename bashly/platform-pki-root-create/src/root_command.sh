SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then
  COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then
  COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else
  COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh
fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"

root_fault() { [[ ${PLATFORM_PKI_ROOT_CRASH_AT:-} != "$1" ]] || kill -KILL "$$"; [[ ${PLATFORM_PKI_ROOT_SIGNAL_AT:-} != "$1" ]] || kill -TERM "$$"; [[ ${PLATFORM_PKI_ROOT_FAIL_AT:-} != "$1" ]] || pki_die "Injected root bootstrap failure at $1"; }

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
NAME=${args[--name]}
ORG=${args[--org]}
COUNTRY=${args[--country]}
DAYS=${args[--days]:-${PLATFORM_PKI_ROOT_DAYS:-3650}}
ROOT_PASS_FILE=${args[--root-pass-file]:-}
FORCE=false; [[ -v args[--force] ]] && FORCE=true
ALLOW_UNENCRYPTED=false; [[ -v args[--allow-unencrypted-root-key] ]] && ALLOW_UNENCRYPTED=true

pki_validate_days "$DAYS"
pki_validate_openssl_config_value 'Root CA common name' "$NAME"
pki_validate_openssl_config_value 'Organization name' "$ORG"
pki_validate_openssl_config_value 'Country code' "$COUNTRY"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}; PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_validate_openssl_config_value 'PKI directory' "$PKI_DIR"
if [[ -n $ROOT_PASS_FILE ]]; then ROOT_PASS_FILE=$(pki_expand_path "$ROOT_PASS_FILE"); pki_require_pass_file "$ROOT_PASS_FILE"; fi
pki_require_cmd openssl
pki_require_pki_dir
pki_prepare_control_state
pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'

ROOT_LOCK=$(pki_root_operation_lock)
STAGE_DIR=''
JOURNAL=$(pki_recovery_journal); RECOVERY_MARKER=$(pki_recovery_marker); ROOT_PUBLISHED=false; TRANSACTION_STARTED=false; COMMITTED=false
write_root_journal() {
  pki_write_journal "$JOURNAL" "schema=3
operation=root-bootstrap
transaction=$TXN_ID
phase=$1
generation=$ROOT_ID
authority_dir=$ROOT_CA_DIR
authority_identity=${ROOT_PUBLISHED_ID:-${STAGE_ID:-none}}
stage_dir=${STAGE_DIR:-none}
stage_identity=${STAGE_ID:-none}
transaction_dir=$TXN_DIR
transaction_identity=$TXN_DIR_ID
reservation=$RESERVATION
reservation_identity=${RESERVATION_IDENTITY:-absent}
reservation_reserved_identity=$RESERVED_STAGE_ID
reservation_consumed_identity=${CONSUMED_STAGE_ID:-absent}
reservation_abandoned_identity=$ABANDONED_STAGE_ID
bootstrap_identity=${BOOTSTRAP_ID:-absent}
recovery_action=${RECOVERY_ACTION:-none}
recovery_step=${RECOVERY_STEP:-none}
committed=${2:-false}
"
}
rollback_root_bootstrap() {
  local bootstrap current
  bootstrap=$(pki_bootstrap_root_manifest)
  # Validate every rollback input before the first mutation.
  current=$(pki_file_identity_or_absent "$bootstrap"); [[ $current == absent ]] || pki_require_file_identity "$bootstrap" "${BOOTSTRAP_ID:-absent}" 'Bootstrap root manifest'
  [[ ! -e $ROOT_CA_DIR && ! -L $ROOT_CA_DIR || $ROOT_PUBLISHED == true && -d $ROOT_CA_DIR && ! -L $ROOT_CA_DIR && $(pki_dir_identity "$ROOT_CA_DIR") == "$ROOT_PUBLISHED_ID" ]] || return 1
  [[ -z $STAGE_DIR || ! -e $STAGE_DIR && ! -L $STAGE_DIR || -d $STAGE_DIR && ! -L $STAGE_DIR && $(pki_dir_identity "$STAGE_DIR") == "$STAGE_ID" ]] || return 1
  current=$(pki_file_identity_or_absent "$RESERVATION"); [[ $current == absent || $current == "$RESERVED_STAGE_ID" || $current == "${CONSUMED_STAGE_ID:-absent}" || $current == "$ABANDONED_STAGE_ID" ]] || return 1
  [[ $current == "$ABANDONED_STAGE_ID" ]] || pki_require_file_identity "$ABANDONED_STAGE" "$ABANDONED_STAGE_ID" 'Abandoned root reservation stage'
  RECOVERY_ACTION=rollback
  if [[ $(pki_file_identity_or_absent "$bootstrap") != absent ]]; then RECOVERY_STEP='bootstrap-pending'; write_root_journal recovering; pki_remove_identity_file "$bootstrap" "$BOOTSTRAP_ID" || return 1; RECOVERY_STEP='bootstrap-done'; write_root_journal recovering; fi
  if [[ -d $ROOT_CA_DIR ]]; then RECOVERY_STEP='authority-pending'; write_root_journal recovering; pki_remove_journaled_tree "$ROOT_CA_DIR" "$ROOT_PUBLISHED_ID" "$PKI_DIR/authorities/roots" || return 1; RECOVERY_STEP='authority-done'; write_root_journal recovering; fi
  if [[ -n $STAGE_DIR && -d $STAGE_DIR ]]; then RECOVERY_STEP='stage-pending'; write_root_journal recovering; pki_remove_journaled_tree "$STAGE_DIR" "$STAGE_ID" "$PKI_DIR/authorities/roots" || return 1; STAGE_DIR=''; RECOVERY_STEP='stage-done'; write_root_journal recovering; fi
  current=$(pki_file_identity_or_absent "$RESERVATION"); if [[ $current != "$ABANDONED_STAGE_ID" ]]; then RECOVERY_STEP='reservation-pending'; write_root_journal recovering; pki_publish_staged_file "$ABANDONED_STAGE" "$RESERVATION"; RESERVATION_IDENTITY=$ABANDONED_STAGE_ID; RECOVERY_STEP='reservation-done'; write_root_journal recovering; fi
  RECOVERY_STEP=complete; write_root_journal rolled-back true; rm -f -- "$RECOVERY_MARKER"; pki_fsync "$(dirname -- "$RECOVERY_MARKER")"
}
finish_root_create() {
  local status=$?
  trap - EXIT
  if [[ $TRANSACTION_STARTED == true && $COMMITTED != true ]]; then
    pki_atomic_write "$RECOVERY_MARKER" "transaction=$TXN_ID
action=run platform-pki-ca-rollover recover
"
    rollback_root_bootstrap || status=1
  fi
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}
trap finish_root_create EXIT
trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
umask 077
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_require_no_unresolved_journal

[[ ! -e $(pki_active_issuer_manifest) && ! -L $(pki_active_issuer_manifest) ]] || \
  pki_die 'An active issuer exists; use platform-pki-ca-rollover instead of replacing the root CA'
[[ ! -e $(pki_bootstrap_root_manifest) && ! -L $(pki_bootstrap_root_manifest) ]] || \
  pki_die 'A bootstrap root already exists; create its first intermediate or recover it'
pki_require_empty_authority_layout
[[ $FORCE != true ]] || pki_die '--force cannot delete unproven root state; recover the journaled disposable transaction instead'
ROOT_ID=$(pki_next_root_generation); ROOT_CA_DIR=$(pki_root_authority_dir "$ROOT_ID")
RESERVATION=$(pki_generation_reservation "$ROOT_ID")
TXN_ID="root-bootstrap-$(date -u '+%Y%m%d-%H%M%S')-$$"; TXN_DIR="$PKI_DIR/state/rollover/$TXN_ID"; mkdir -m 700 "$TXN_DIR"; TXN_DIR_ID=$(pki_dir_identity "$TXN_DIR")
RESERVED_STAGE="$TXN_DIR/reservation-reserved"; pki_atomic_write "$RESERVED_STAGE" "generation=$ROOT_ID
kind=root
status=reserved
transaction=$TXN_ID
"; RESERVED_STAGE_ID=$(pki_file_object_state "$RESERVED_STAGE")
ABANDONED_STAGE="$TXN_DIR/reservation-abandoned"; pki_atomic_write "$ABANDONED_STAGE" "generation=$ROOT_ID
kind=root
status=abandoned
transaction=$TXN_ID
"; ABANDONED_STAGE_ID=$(pki_file_object_state "$ABANDONED_STAGE"); pki_fsync_tree "$TXN_DIR"
TRANSACTION_STARTED=true; write_root_journal prepared
root_fault after-journal
RESERVATION_IDENTITY=absent; pki_publish_staged_file "$RESERVED_STAGE" "$RESERVATION"; RESERVATION_IDENTITY=$RESERVED_STAGE_ID; write_root_journal reserved
root_fault after-reservation
STAGE_DIR=$(mktemp -d "$PKI_DIR/authorities/roots/.platform-pki-root-create.XXXXXX") || pki_die 'Cannot create root staging directory'
STAGE_ID=$(pki_dir_identity "$STAGE_DIR"); write_root_journal staged
mkdir -m 700 "$STAGE_DIR/certs" "$STAGE_DIR/private" "$STAGE_DIR/crl" "$STAGE_DIR/newcerts"
pki_init_ca_db "$STAGE_DIR"
chmod 600 "$STAGE_DIR/index.txt" "$STAGE_DIR/index.txt.attr" "$STAGE_DIR/serial" "$STAGE_DIR/crlnumber"
STAGE_KEY="$STAGE_DIR/private/root-ca.key"; STAGE_CERT="$STAGE_DIR/certs/root-ca.crt"; STAGE_CONF="$STAGE_DIR/openssl.cnf"
pki_write_root_config "$STAGE_CONF" "$COUNTRY" "$ORG" "$NAME" "$ROOT_CA_DIR"; chmod 600 "$STAGE_CONF"
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
[[ -z $ROOT_PASS_FILE ]] || REQ_CMD+=(-passin "file:$ROOT_PASS_FILE")
"${REQ_CMD[@]}"; chmod 644 "$STAGE_CERT"
openssl x509 -in "$STAGE_CERT" -pubkey -noout >"$STAGE_DIR/cert.pub"
PKEY_CMD=(openssl pkey -in "$STAGE_KEY" -pubout -out "$STAGE_DIR/key.pub"); [[ -z $ROOT_PASS_FILE ]] || PKEY_CMD+=(-passin "file:$ROOT_PASS_FILE")
"${PKEY_CMD[@]}"; cmp -s "$STAGE_DIR/cert.pub" "$STAGE_DIR/key.pub" || pki_die 'Generated root CA key and certificate do not match'
rm -f "$STAGE_DIR/cert.pub" "$STAGE_DIR/key.pub"
pki_fsync_tree "$STAGE_DIR"
FINGERPRINT=$(openssl x509 -in "$STAGE_CERT" -noout -fingerprint -sha256); FINGERPRINT=${FINGERPRINT#*=}; FINGERPRINT=${FINGERPRINT//:/}
mv -T -- "$STAGE_DIR" "$ROOT_CA_DIR" || pki_die "Cannot publish root generation: $ROOT_CA_DIR"; ROOT_PUBLISHED_ID=$STAGE_ID; ROOT_PUBLISHED=true; STAGE_DIR=''; [[ $(pki_dir_identity "$ROOT_CA_DIR") == "$ROOT_PUBLISHED_ID" ]] || pki_die 'Published root authority identity changed'; pki_fsync "$(dirname -- "$ROOT_CA_DIR")"; write_root_journal authority-published
root_fault after-authority
pki_atomic_write "$TXN_DIR/reservation-consumed" "generation=$ROOT_ID
kind=root
status=consumed
fingerprint_sha256=$FINGERPRINT
transaction=$TXN_ID
"; CONSUMED_STAGE="$TXN_DIR/reservation-consumed"; CONSUMED_STAGE_ID=$(pki_file_object_state "$CONSUMED_STAGE"); write_root_journal reservation-consume-pending; pki_publish_staged_file "$CONSUMED_STAGE" "$RESERVATION"; RESERVATION_IDENTITY=$CONSUMED_STAGE_ID; write_root_journal reservation-consumed
root_fault after-reservation-consumed
pki_atomic_write "$(pki_bootstrap_root_manifest)" "root=$ROOT_ID
fingerprint_sha256=$FINGERPRINT
"
BOOTSTRAP_ID=$(pki_file_identity "$(pki_bootstrap_root_manifest)"); write_root_journal bootstrap-published; root_fault after-bootstrap
write_root_journal complete true; COMMITTED=true
pki_ok "Created root CA generation $ROOT_ID: $ROOT_CA_DIR/certs/root-ca.crt"
