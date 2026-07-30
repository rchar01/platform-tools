SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh; fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"

intermediate_fault() { [[ ${PLATFORM_PKI_INTERMEDIATE_CRASH_AT:-} != "$1" ]] || kill -KILL "$$"; [[ ${PLATFORM_PKI_INTERMEDIATE_SIGNAL_AT:-} != "$1" ]] || kill -TERM "$$"; [[ ${PLATFORM_PKI_INTERMEDIATE_FAIL_AT:-} != "$1" ]] || pki_die "Injected intermediate bootstrap failure at $1"; }

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}; PKI_DIR=${args[--pki-dir]:-}
NAME=${args[--name]}; ORG=${args[--org]}; COUNTRY=${args[--country]}
DAYS=${args[--days]:-${PLATFORM_PKI_INTERMEDIATE_DAYS:-1825}}
ISSUER_SAFETY_DAYS=${args[--issuer-safety-days]}
ROOT_PASS_FILE=${args[--root-pass-file]:-}; INTERMEDIATE_PASS_FILE=${args[--intermediate-pass-file]:-}
FORCE=false; [[ -v args[--force] ]] && FORCE=true
ALLOW_UNENCRYPTED=false; [[ -v args[--allow-unencrypted-intermediate-key] ]] && ALLOW_UNENCRYPTED=true
pki_validate_days "$DAYS"; pki_validate_openssl_config_value 'Intermediate CA common name' "$NAME"
pki_validate_openssl_config_value 'Organization name' "$ORG"; pki_validate_openssl_config_value 'Country code' "$COUNTRY"
NAMESPACE=$(pki_expand_path "$NAMESPACE"); PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}; PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_validate_openssl_config_value 'PKI directory' "$PKI_DIR"
if [[ -n $ROOT_PASS_FILE ]]; then ROOT_PASS_FILE=$(pki_expand_path "$ROOT_PASS_FILE"); pki_require_pass_file "$ROOT_PASS_FILE"; fi
if [[ -n $INTERMEDIATE_PASS_FILE ]]; then INTERMEDIATE_PASS_FILE=$(pki_expand_path "$INTERMEDIATE_PASS_FILE"); pki_require_pass_file "$INTERMEDIATE_PASS_FILE"; fi
pki_require_cmd openssl; pki_require_pki_dir

ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock)
STAGE_DIR=''; ROOT_BACKUP_DIR=''; ROOT_MUTATED=false
JOURNAL=$(pki_recovery_journal); RECOVERY_MARKER=$(pki_recovery_marker); INTERMEDIATE_PUBLISHED=false; ACTIVE_PUBLISHED=false; BOOTSTRAP_REMOVED=false; TRANSACTION_STARTED=false; COMMITTED=false
ROOT_DB_KEYS=(index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert)
declare -gA ROOT_DB_PATH=() ROOT_DB_PRE=() ROOT_DB_POST=() ROOT_DB_BACKUP=() ROOT_DB_BACKUP_ID=()
for key in "${ROOT_DB_KEYS[@]}"; do ROOT_DB_PRE[$key]=pending; ROOT_DB_POST[$key]=pending; ROOT_DB_BACKUP_ID[$key]=absent; done
write_intermediate_journal() {
  local key db_fields=''
  for key in "${ROOT_DB_KEYS[@]}"; do
    db_fields+="root_${key}_pre_identity=${ROOT_DB_PRE[$key]}
root_${key}_post_identity=${ROOT_DB_POST[$key]}
root_${key}_backup_identity=${ROOT_DB_BACKUP_ID[$key]}
"
  done
  pki_write_journal "$JOURNAL" "schema=3
operation=intermediate-bootstrap
transaction=$TXN_ID
phase=$1
root_generation=$ROOT_ID
intermediate_generation=$INTERMEDIATE_ID
root_dir=$ROOT_CA_DIR
intermediate_dir=$INTERMEDIATE_CA_DIR
intermediate_identity=${INTERMEDIATE_PUBLISHED_ID:-none}
stage_dir=${STAGE_DIR:-none}
stage_identity=${STAGE_ID:-none}
root_stage=${STAGE_ROOT:-none}
root_stage_identity=${STAGE_ROOT_ID:-none}
transaction_dir=$TXN_DIR
transaction_identity=$TXN_DIR_ID
bootstrap_fingerprint=${BOOTSTRAP_FINGERPRINT:-none}
issued_serial=${ISSUED_SERIAL:-none}
reservation=$RESERVATION
reservation_identity=${RESERVATION_IDENTITY:-absent}
reservation_reserved_identity=$RESERVED_STAGE_ID
reservation_consumed_identity=${CONSUMED_STAGE_ID:-absent}
reservation_abandoned_identity=$ABANDONED_STAGE_ID
active_identity=${ACTIVE_IDENTITY:-absent}
bootstrap_identity=${BOOTSTRAP_IDENTITY:-absent}
bootstrap_rollback_identity=$BOOTSTRAP_ROLLBACK_ID
root_mutated=$ROOT_MUTATED
recovery_action=${RECOVERY_ACTION:-none}
recovery_step=${RECOVERY_STEP:-none}
$db_fields
committed=${2:-false}
"
}
rollback_intermediate_bootstrap() {
  local failed=0 key current active
  active=$(pki_active_issuer_manifest)
  # Validate every rollback input before the first mutation.
  current=$(pki_file_identity_or_absent "$active"); if [[ $current != absent ]]; then [[ $ACTIVE_PUBLISHED == true ]] || failed=1; pki_require_file_identity "$active" "$ACTIVE_IDENTITY" 'Active issuer manifest'; fi
  current=$(pki_file_identity_or_absent "$BOOTSTRAP")
  if [[ $current == "$BOOTSTRAP_ROLLBACK_ID" ]]; then BOOTSTRAP_REMOVED=true
  elif [[ $current != absent ]]; then pki_require_file_identity "$BOOTSTRAP" "$BOOTSTRAP_IDENTITY" 'Bootstrap root manifest'
  elif [[ $BOOTSTRAP_REMOVED != true ]]; then failed=1
  fi
  [[ $current != absent ]] || pki_require_file_identity "$BOOTSTRAP_ROLLBACK_STAGE" "$BOOTSTRAP_ROLLBACK_ID" 'Bootstrap rollback stage'
  [[ ! -e $INTERMEDIATE_CA_DIR && ! -L $INTERMEDIATE_CA_DIR || $INTERMEDIATE_PUBLISHED == true && -d $INTERMEDIATE_CA_DIR && ! -L $INTERMEDIATE_CA_DIR && $(pki_dir_identity "$INTERMEDIATE_CA_DIR") == "$INTERMEDIATE_PUBLISHED_ID" ]] || failed=1
  [[ -z $STAGE_DIR || ! -e $STAGE_DIR && ! -L $STAGE_DIR || -d $STAGE_DIR && ! -L $STAGE_DIR && $(pki_dir_identity "$STAGE_DIR") == "$STAGE_ID" ]] || failed=1
  current=$(pki_file_identity_or_absent "$RESERVATION"); [[ $current == "$RESERVED_STAGE_ID" || $current == "${CONSUMED_STAGE_ID:-absent}" || $current == "$ABANDONED_STAGE_ID" ]] || failed=1
  [[ $current == "$ABANDONED_STAGE_ID" ]] || pki_require_file_identity "$ABANDONED_STAGE" "$ABANDONED_STAGE_ID" 'Abandoned intermediate reservation stage'
  if [[ $ROOT_MUTATED == true ]]; then
    for key in "${ROOT_DB_KEYS[@]}"; do
      current=$(pki_file_identity_or_absent "${ROOT_DB_PATH[$key]}")
      [[ $current == "${ROOT_DB_PRE[$key]}" || $current == "${ROOT_DB_POST[$key]}" || $current == "${ROOT_DB_BACKUP_ID[$key]}" ]] || failed=1
      if [[ $current == "${ROOT_DB_POST[$key]}" && ${ROOT_DB_PRE[$key]} != "${ROOT_DB_POST[$key]}" && ${ROOT_DB_PRE[$key]} != absent ]]; then
        pki_require_file_identity "${ROOT_DB_BACKUP[$key]}" "${ROOT_DB_BACKUP_ID[$key]}" "Root $key rollback copy" || failed=1
      fi
    done
  fi
  (( failed == 0 )) || { pki_atomic_write "$RECOVERY_MARKER" "transaction=$TXN_ID
action=run platform-pki-ca-rollover recover
"; return 1; }
  RECOVERY_ACTION=rollback
  if [[ $ACTIVE_PUBLISHED == true ]]; then RECOVERY_STEP='active-pending'; write_intermediate_journal recovering; pki_remove_identity_file "$active" "$ACTIVE_IDENTITY" || failed=1; RECOVERY_STEP='active-done'; write_intermediate_journal recovering; fi
  current=$(pki_file_identity_or_absent "$BOOTSTRAP")
  if [[ $current == absent ]]; then RECOVERY_STEP='bootstrap-pending'; write_intermediate_journal recovering; pki_publish_staged_file "$BOOTSTRAP_ROLLBACK_STAGE" "$BOOTSTRAP" || failed=1; RECOVERY_STEP='bootstrap-done'; write_intermediate_journal recovering; fi
  if [[ $ROOT_MUTATED == true ]]; then
    for key in "${ROOT_DB_KEYS[@]}"; do
      current=$(pki_file_identity_or_absent "${ROOT_DB_PATH[$key]}")
      if [[ $current == "${ROOT_DB_POST[$key]}" && ${ROOT_DB_PRE[$key]} != "${ROOT_DB_POST[$key]}" ]]; then RECOVERY_STEP="root-$key-pending"; write_intermediate_journal recovering; pki_restore_journaled_file "${ROOT_DB_PATH[$key]}" "${ROOT_DB_PRE[$key]}" "${ROOT_DB_POST[$key]}" "${ROOT_DB_BACKUP[$key]}" "${ROOT_DB_BACKUP_ID[$key]}" "Root $key" || failed=1; RECOVERY_STEP="root-$key-done"; write_intermediate_journal recovering; fi
    done
    pki_fsync "$ROOT_CA_DIR"
  fi
  if [[ $INTERMEDIATE_PUBLISHED == true ]]; then RECOVERY_STEP='authority-pending'; write_intermediate_journal recovering; pki_remove_journaled_tree "$INTERMEDIATE_CA_DIR" "$INTERMEDIATE_PUBLISHED_ID" "$PKI_DIR/authorities/intermediates" || failed=1; RECOVERY_STEP='authority-done'; write_intermediate_journal recovering; fi
  if [[ -n $STAGE_DIR && -d $STAGE_DIR ]]; then RECOVERY_STEP='stage-pending'; write_intermediate_journal recovering; pki_remove_journaled_tree "$STAGE_DIR" "$STAGE_ID" "$PKI_DIR/authorities/intermediates" || failed=1; STAGE_DIR=''; RECOVERY_STEP='stage-done'; write_intermediate_journal recovering; fi
  if (( failed == 0 )); then
    current=$(pki_file_identity_or_absent "$RESERVATION")
    if [[ $current != "$ABANDONED_STAGE_ID" ]]; then RECOVERY_STEP='reservation-pending'; write_intermediate_journal recovering; pki_publish_staged_file "$ABANDONED_STAGE" "$RESERVATION" || failed=1; RESERVATION_IDENTITY=$ABANDONED_STAGE_ID; RECOVERY_STEP='reservation-done'; write_intermediate_journal recovering; fi
  fi
  if (( failed == 0 )); then write_intermediate_journal rolled-back true; rm -f -- "$RECOVERY_MARKER"; pki_fsync "$(dirname -- "$RECOVERY_MARKER")"; else pki_atomic_write "$RECOVERY_MARKER" "transaction=$TXN_ID
"; fi
  return "$failed"
}
finish_intermediate() {
  local status=$? cleanup_stage=true
  trap - EXIT
  if [[ $TRANSACTION_STARTED == true && $COMMITTED != true ]]; then rollback_intermediate_bootstrap || { status=1; cleanup_stage=false; }; fi
  [[ $cleanup_stage != true || -z $STAGE_DIR || ! -d $STAGE_DIR ]] || pki_remove_journaled_tree "$STAGE_DIR" "$STAGE_ID" "$PKI_DIR/authorities/intermediates" || status=1
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}
trap finish_intermediate EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
umask 077
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_require_no_unresolved_journal
[[ ! -e $(pki_active_issuer_manifest) && ! -L $(pki_active_issuer_manifest) ]] || \
  pki_die 'An active issuer exists; use platform-pki-ca-rollover instead of replacing the intermediate CA'
BOOTSTRAP=$(pki_bootstrap_root_manifest)
[[ -f $BOOTSTRAP && ! -L $BOOTSTRAP ]] || pki_die 'Bootstrap root manifest is missing; create the root CA first'
pki_read_state_record "$BOOTSTRAP" 'Bootstrap root manifest'
[[ ${#PKI_RECORD[@]} -eq 2 && ${PKI_RECORD[root]:-} =~ ^g[1-9][0-9]*$ && ${PKI_RECORD[fingerprint_sha256]:-} =~ ^[0-9A-Fa-f]{64}$ ]] || pki_die 'Bootstrap root manifest is invalid'
ROOT_ID=${PKI_RECORD[root]}; ROOT_CA_DIR=$(pki_root_authority_dir "$ROOT_ID"); INTERMEDIATE_ID=$(pki_next_intermediate_generation "$ROOT_ID"); INTERMEDIATE_CA_DIR=$(pki_intermediate_authority_dir "$INTERMEDIATE_ID")
BOOTSTRAP_FINGERPRINT=${PKI_RECORD[fingerprint_sha256]}; BOOTSTRAP_IDENTITY=$(pki_file_identity "$BOOTSTRAP")
pki_require_private_dir "$ROOT_CA_DIR" 'Root authority generation'
ROOT_KEY=$(pki_root_key "$ROOT_ID"); ROOT_CERT=$(pki_root_cert "$ROOT_ID"); ROOT_CONF="$ROOT_CA_DIR/openssl.cnf"
for path in "$ROOT_KEY" "$ROOT_CERT" "$ROOT_CONF" "$ROOT_CA_DIR/index.txt" "$ROOT_CA_DIR/index.txt.attr" "$ROOT_CA_DIR/serial"; do pki_require_file "$path"; done
[[ $FORCE != true ]] || pki_die '--force cannot delete unproven intermediate state; recover the journaled disposable transaction instead'
RESERVATION=$(pki_generation_reservation "$INTERMEDIATE_ID")
TXN_ID="intermediate-bootstrap-$(date -u '+%Y%m%d-%H%M%S')-$$"; TXN_DIR="$PKI_DIR/state/rollover/$TXN_ID"; mkdir -m 700 "$TXN_DIR"; TXN_DIR_ID=$(pki_dir_identity "$TXN_DIR")
RESERVED_STAGE="$TXN_DIR/reservation-reserved"; pki_atomic_write "$RESERVED_STAGE" "generation=$INTERMEDIATE_ID
kind=intermediate
status=reserved
transaction=$TXN_ID
"; RESERVED_STAGE_ID=$(pki_file_object_state "$RESERVED_STAGE")
ABANDONED_STAGE="$TXN_DIR/reservation-abandoned"; pki_atomic_write "$ABANDONED_STAGE" "generation=$INTERMEDIATE_ID
kind=intermediate
status=abandoned
transaction=$TXN_ID
"; ABANDONED_STAGE_ID=$(pki_file_object_state "$ABANDONED_STAGE")
BOOTSTRAP_ROLLBACK_STAGE="$TXN_DIR/bootstrap-rollback"; pki_atomic_write "$BOOTSTRAP_ROLLBACK_STAGE" "root=$ROOT_ID
fingerprint_sha256=$BOOTSTRAP_FINGERPRINT
"; BOOTSTRAP_ROLLBACK_ID=$(pki_file_object_state "$BOOTSTRAP_ROLLBACK_STAGE"); pki_fsync_tree "$TXN_DIR"
TRANSACTION_STARTED=true; write_intermediate_journal prepared
intermediate_fault after-journal
RESERVATION_IDENTITY=absent; pki_publish_staged_file "$RESERVED_STAGE" "$RESERVATION"; RESERVATION_IDENTITY=$RESERVED_STAGE_ID; write_intermediate_journal reserved
intermediate_fault after-reservation
STAGE_DIR=$(mktemp -d "$PKI_DIR/authorities/intermediates/.platform-pki-intermediate-create.XXXXXX")
STAGE_ID=$(pki_dir_identity "$STAGE_DIR"); write_intermediate_journal staged
STAGE_ROOT="$STAGE_DIR/root"; STAGE_INT="$STAGE_DIR/intermediate"; ROOT_BACKUP_DIR="$STAGE_DIR/root-backup"
mkdir -m 700 "$STAGE_ROOT" "$STAGE_ROOT/private" "$STAGE_ROOT/certs" "$STAGE_ROOT/newcerts" "$STAGE_ROOT/crl" \
  "$STAGE_INT" "$STAGE_INT/private" "$STAGE_INT/certs" "$STAGE_INT/csr" "$STAGE_INT/newcerts" "$STAGE_INT/crl" "$ROOT_BACKUP_DIR"
STAGE_ROOT_ID=$(pki_dir_identity "$STAGE_ROOT")
cp -p "$ROOT_KEY" "$STAGE_ROOT/private/root-ca.key"; cp -p "$ROOT_CERT" "$STAGE_ROOT/certs/root-ca.crt"
for file in index.txt index.txt.attr serial crlnumber; do cp -p "$ROOT_CA_DIR/$file" "$STAGE_ROOT/$file"; cp -p "$ROOT_CA_DIR/$file" "$ROOT_BACKUP_DIR/$file"; done
for file in index.txt.old index.txt.attr.old serial.old crlnumber.old; do [[ ! -e $ROOT_CA_DIR/$file ]] || cp -p "$ROOT_CA_DIR/$file" "$ROOT_BACKUP_DIR/$file"; done
pki_write_root_config "$STAGE_ROOT/openssl.cnf" "$COUNTRY" "$ORG" "$NAME" "$STAGE_ROOT"; chmod 600 "$STAGE_ROOT/openssl.cnf"
pki_init_ca_db "$STAGE_INT"; chmod 600 "$STAGE_INT/index.txt" "$STAGE_INT/index.txt.attr" "$STAGE_INT/serial" "$STAGE_INT/crlnumber"
pki_write_intermediate_config "$STAGE_INT/openssl.cnf" "$COUNTRY" "$ORG" "$NAME" "$INTERMEDIATE_CA_DIR"; chmod 600 "$STAGE_INT/openssl.cnf"
INT_KEY="$STAGE_INT/private/intermediate-ca.key"; INT_CSR="$STAGE_INT/csr/intermediate-ca.csr"; INT_CERT="$STAGE_INT/certs/intermediate-ca.crt"
if [[ $ALLOW_UNENCRYPTED == true ]]; then pki_warn 'Creating an unencrypted intermediate CA private key because --allow-unencrypted-intermediate-key was used'; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "$INT_KEY"
elif [[ -n $INTERMEDIATE_PASS_FILE ]]; then openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -pass "file:$INTERMEDIATE_PASS_FILE" -out "$INT_KEY"
else openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -out "$INT_KEY"; fi
chmod 600 "$INT_KEY"
REQ_CMD=(openssl req -config "$STAGE_INT/openssl.cnf" -key "$INT_KEY" -new -sha384 -out "$INT_CSR"); [[ -z $INTERMEDIATE_PASS_FILE ]] || REQ_CMD+=(-passin "file:$INTERMEDIATE_PASS_FILE"); "${REQ_CMD[@]}"; chmod 600 "$INT_CSR"
ISSUED_SERIAL=$(<"$STAGE_ROOT/serial"); ISSUED_SERIAL=${ISSUED_SERIAL^^}; while [[ $ISSUED_SERIAL == 00* && ${#ISSUED_SERIAL} -gt 2 ]]; do ISSUED_SERIAL=${ISSUED_SERIAL#00}; done
ROOT_DB_PATH[index]="$ROOT_CA_DIR/index.txt"; ROOT_DB_PATH[index_attr]="$ROOT_CA_DIR/index.txt.attr"; ROOT_DB_PATH[serial]="$ROOT_CA_DIR/serial"; ROOT_DB_PATH[crlnumber]="$ROOT_CA_DIR/crlnumber"
ROOT_DB_PATH[index_old]="$ROOT_CA_DIR/index.txt.old"; ROOT_DB_PATH[index_attr_old]="$ROOT_CA_DIR/index.txt.attr.old"; ROOT_DB_PATH[serial_old]="$ROOT_CA_DIR/serial.old"; ROOT_DB_PATH[crlnumber_old]="$ROOT_CA_DIR/crlnumber.old"; ROOT_DB_PATH[newcert]="$ROOT_CA_DIR/newcerts/$ISSUED_SERIAL.pem"
ROOT_DB_BACKUP[index]="$ROOT_BACKUP_DIR/index.txt"; ROOT_DB_BACKUP[index_attr]="$ROOT_BACKUP_DIR/index.txt.attr"; ROOT_DB_BACKUP[serial]="$ROOT_BACKUP_DIR/serial"; ROOT_DB_BACKUP[crlnumber]="$ROOT_BACKUP_DIR/crlnumber"
ROOT_DB_BACKUP[index_old]="$ROOT_BACKUP_DIR/index.txt.old"; ROOT_DB_BACKUP[index_attr_old]="$ROOT_BACKUP_DIR/index.txt.attr.old"; ROOT_DB_BACKUP[serial_old]="$ROOT_BACKUP_DIR/serial.old"; ROOT_DB_BACKUP[crlnumber_old]="$ROOT_BACKUP_DIR/crlnumber.old"; ROOT_DB_BACKUP[newcert]=none
for key in "${ROOT_DB_KEYS[@]}"; do ROOT_DB_PRE[$key]=$(pki_file_identity_or_absent "${ROOT_DB_PATH[$key]}"); [[ ${ROOT_DB_PRE[$key]} == absent || $key == newcert ]] || ROOT_DB_BACKUP_ID[$key]=$(pki_file_object_state "${ROOT_DB_BACKUP[$key]}"); done
[[ ${ROOT_DB_PRE[newcert]} == absent ]] || pki_die 'Root issued-certificate destination already exists'
CA_CMD=(openssl ca -batch -config "$STAGE_ROOT/openssl.cnf" -extensions v3_intermediate_ca -days "$DAYS" -notext -md sha384 -in "$INT_CSR" -out "$INT_CERT"); [[ -z $ROOT_PASS_FILE ]] || CA_CMD+=(-passin "file:$ROOT_PASS_FILE"); "${CA_CMD[@]}"; chmod 644 "$INT_CERT"
cat "$INT_CERT" "$ROOT_CERT" >"$STAGE_INT/certs/ca-chain.crt"; chmod 644 "$STAGE_INT/certs/ca-chain.crt"
openssl verify -CAfile "$ROOT_CERT" "$INT_CERT" >/dev/null || pki_die 'Generated intermediate does not verify against bootstrap root'
pki_validate_child_validity "$INT_CERT" "$ROOT_CERT" "$ISSUER_SAFETY_DAYS"
FINGERPRINT=$(openssl x509 -in "$INT_CERT" -noout -fingerprint -sha256); FINGERPRINT=${FINGERPRINT#*=}; FINGERPRINT=${FINGERPRINT//:/}
pki_fsync_tree "$STAGE_DIR"
INTERMEDIATE_PUBLISHED_ID=$(pki_dir_identity "$STAGE_INT")
mv -T "$STAGE_INT" "$INTERMEDIATE_CA_DIR" || pki_die 'Cannot publish intermediate generation'; INTERMEDIATE_PUBLISHED=true; [[ $(pki_dir_identity "$INTERMEDIATE_CA_DIR") == "$INTERMEDIATE_PUBLISHED_ID" ]] || pki_die 'Published intermediate authority identity changed'; pki_fsync_rename_parents "$STAGE_DIR" "$(dirname -- "$INTERMEDIATE_CA_DIR")"; write_intermediate_journal intermediate-published
intermediate_fault after-intermediate
ROOT_MUTATED=true
for key in index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old; do file=${ROOT_DB_PATH[$key]#"$ROOT_CA_DIR/"}; if [[ -e $STAGE_ROOT/$file ]]; then ROOT_DB_POST[$key]=$(pki_file_object_state "$STAGE_ROOT/$file"); else ROOT_DB_POST[$key]=${ROOT_DB_PRE[$key]}; fi; done
ROOT_DB_POST[newcert]=$(pki_file_object_state "$STAGE_ROOT/newcerts/$ISSUED_SERIAL.pem"); write_intermediate_journal root-db-pending
for key in index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old; do
  file=${ROOT_DB_PATH[$key]#"$ROOT_CA_DIR/"}; [[ ! -e $STAGE_ROOT/$file ]] || { write_intermediate_journal "root-$key-pending"; intermediate_fault "root-$key-pending"; pki_publish_staged_file "$STAGE_ROOT/$file" "${ROOT_DB_PATH[$key]}"; write_intermediate_journal "root-$key-done"; intermediate_fault "root-$key-done"; }
done
ROOT_NEWCERT=${ROOT_DB_PATH[newcert]}; pki_require_file_identity "$ROOT_NEWCERT" absent 'Root issued-certificate destination'; write_intermediate_journal root-newcert-pending; intermediate_fault root-newcert-pending; pki_publish_staged_file "$STAGE_ROOT/newcerts/$ISSUED_SERIAL.pem" "$ROOT_NEWCERT"; write_intermediate_journal root-newcert-done; intermediate_fault root-newcert-done; pki_fsync "$ROOT_CA_DIR"; pki_fsync "$ROOT_CA_DIR/newcerts"; write_intermediate_journal root-db-published
intermediate_fault after-root-db
pki_atomic_write "$TXN_DIR/reservation-consumed" "generation=$INTERMEDIATE_ID
kind=intermediate
status=consumed
fingerprint_sha256=$FINGERPRINT
transaction=$TXN_ID
"; CONSUMED_STAGE="$TXN_DIR/reservation-consumed"; CONSUMED_STAGE_ID=$(pki_file_object_state "$CONSUMED_STAGE"); write_intermediate_journal reservation-consume-pending; pki_publish_staged_file "$CONSUMED_STAGE" "$RESERVATION"; RESERVATION_IDENTITY=$CONSUMED_STAGE_ID; write_intermediate_journal reservation-consumed; intermediate_fault after-reservation-consumed
pki_publish_active_issuer "$ROOT_ID" "$INTERMEDIATE_ID"
ACTIVE_IDENTITY=$(pki_file_identity "$(pki_active_issuer_manifest)"); ACTIVE_PUBLISHED=true; write_intermediate_journal active-published
intermediate_fault after-active
[[ $(pki_file_identity "$BOOTSTRAP") == "$BOOTSTRAP_IDENTITY" ]] || pki_die 'Bootstrap manifest changed during intermediate creation'
pki_remove_identity_file "$BOOTSTRAP" "$BOOTSTRAP_IDENTITY" || pki_die 'Cannot remove identity-matched bootstrap manifest'; BOOTSTRAP_REMOVED=true
intermediate_fault after-bootstrap
pki_require_private_dir "$STAGE_ROOT" 'Sensitive root signing stage'; [[ $(pki_dir_identity "$STAGE_ROOT") == "$STAGE_ROOT_ID" ]] || pki_die 'Sensitive root signing stage identity changed before cleanup'
write_intermediate_journal cleanup-pending; intermediate_fault cleanup-pending
pki_remove_journaled_tree "$STAGE_ROOT" "$STAGE_ROOT_ID" "$STAGE_DIR" || pki_die 'Cannot remove sensitive root signing stage'
intermediate_fault cleanup-removed; write_intermediate_journal cleanup-done; intermediate_fault cleanup-done
write_intermediate_journal complete true; COMMITTED=true; ROOT_MUTATED=false
pki_ok "Created intermediate CA generation $INTERMEDIATE_ID: $INTERMEDIATE_CA_DIR/certs/intermediate-ca.crt"
