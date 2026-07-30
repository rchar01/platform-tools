SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh; fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"

fault() {
  [[ ${PLATFORM_PKI_MIGRATE_CRASH_AT:-} != "$1" ]] || kill -KILL "$$"
  [[ ${PLATFORM_PKI_MIGRATE_FAIL_AT:-} != "$1" ]] || {
    pki_die "Injected migration interruption at $1"
  }
}

read_receipt() {
  local line key value
  declare -gA RECEIPT=()
  [[ -f $BACKUP_RECEIPT && ! -L $BACKUP_RECEIPT ]] || pki_die "Backup receipt must be a non-symlink regular file: $BACKUP_RECEIPT"
  [[ $(stat -c '%u:%a:%h' "$BACKUP_RECEIPT") == "$(id -u):600:1" ]] || pki_die 'Backup receipt must be current-user-owned, singly linked, and mode 600'
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^([a-z0-9_]+)=(.*)$ ]] || pki_die 'Backup receipt has invalid content'
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    [[ ! -v RECEIPT[$key] ]] || pki_die "Backup receipt contains duplicate field: $key"
    RECEIPT[$key]=$value
  done <"$BACKUP_RECEIPT"
  for key in schema layout session backup_path backup_device backup_inode backup_size backup_mode backup_owner archive_sha256 created_at created_epoch state_manifest_sha256 private_metadata_sha256; do
    [[ -v RECEIPT[$key] && -n ${RECEIPT[$key]} ]] || pki_die "Backup receipt is missing field: $key"
  done
  [[ ${#RECEIPT[@]} -eq 14 && ${RECEIPT[schema]} == 2 && ${RECEIPT[layout]} == legacy && ${RECEIPT[session]} =~ ^[0-9a-f]{32}$ && ${RECEIPT[created_epoch]} =~ ^[0-9]+$ ]] || pki_die 'Backup receipt is not a supported legacy-layout receipt'
  now=$(date -u +%s); (( now >= 10#${RECEIPT[created_epoch]} && now - 10#${RECEIPT[created_epoch]} <= 86400 )) || pki_die 'Backup receipt is older than the 24-hour migration freshness window'
  ARCHIVE=${RECEIPT[backup_path]}
  [[ $ARCHIVE == /* && -f $ARCHIVE && ! -L $ARCHIVE ]] || pki_die "Backup archive is missing or unsafe: $ARCHIVE"
  [[ $(stat -c '%d:%i:%s:%a:%u:%h' "$ARCHIVE") == "${RECEIPT[backup_device]}:${RECEIPT[backup_inode]}:${RECEIPT[backup_size]}:${RECEIPT[backup_mode]}:${RECEIPT[backup_owner]}:1" ]] || pki_die 'Backup archive identity no longer matches its receipt'
  archive_hash=$(sha256sum "$ARCHIVE"); [[ ${archive_hash%% *} == "${RECEIPT[archive_sha256]}" ]] || pki_die 'Backup archive digest no longer matches its receipt'
}

transform_config() {
  local source=$1 destination=$2 old=$3 new=$4 line replacements=0
  : >"$destination"
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "dir = $old" ]]; then printf 'dir = %s\n' "$new" >>"$destination"; replacements=$((replacements + 1))
    else printf '%s\n' "$line" >>"$destination"; fi
  done <"$source"
  [[ $replacements -eq 1 ]] || pki_die "Managed OpenSSL configuration has an unexpected directory: $source"
  chmod 600 "$destination"
}

write_journal() {
  pki_write_journal "$JOURNAL" "schema=2
operation=legacy-migrate
transaction=$TXN_ID
phase=$1
legacy_root=$LEGACY_ROOT
legacy_intermediate=$LEGACY_INT
new_root=$NEW_ROOT
new_intermediate=$NEW_INT
root_source_identity=$ROOT_SOURCE_ID
intermediate_source_identity=$INT_SOURCE_ID
root_sha256=$ROOT_FP
intermediate_sha256=$INT_FP
transaction_dir=$TXN_DIR
transaction_identity=$TXN_IDENTITY
provenance_stage=$PROVENANCE_STAGE
provenance_dir=$PROVENANCE_DIR
provenance_identity=$PROVENANCE_IDENTITY
provenance_manifest=$PROVENANCE_MANIFEST
provenance_manifest_identity=$PROVENANCE_MANIFEST_IDENTITY
provenance_manifest_sha256=$PROVENANCE_MANIFEST_SHA256
receipt_identity=$RECEIPT_IDENTITY
services_sha256=$SERVICES_SHA256
services_identity=$SERVICES_IDENTITY
backup_receipt=$BACKUP_RECEIPT
private_repo=$PRIVATE_REPO
backup_session=$BACKUP_SESSION
backup_session_original_identity=$BACKUP_SESSION_ORIGINAL_ID
backup_session_published_identity=$BACKUP_SESSION_PUBLISHED_ID
root_reservation=$ROOT_RESERVATION
root_reservation_original_identity=$ROOT_RESERVATION_ORIGINAL_ID
root_reservation_reserved_identity=$ROOT_RESERVATION_RESERVED_ID
root_reservation_consumed_identity=$ROOT_RESERVATION_CONSUMED_ID
root_reservation_rollback_identity=${ROOT_RESERVATION_ROLLBACK_ID:-absent}
intermediate_reservation=$INT_RESERVATION
intermediate_reservation_original_identity=$INT_RESERVATION_ORIGINAL_ID
intermediate_reservation_reserved_identity=$INT_RESERVATION_RESERVED_ID
intermediate_reservation_consumed_identity=$INT_RESERVATION_CONSUMED_ID
intermediate_reservation_rollback_identity=${INT_RESERVATION_ROLLBACK_ID:-absent}
root_config_original_identity=$ROOT_CONFIG_ORIGINAL_ID
root_config_published_identity=$ROOT_CONFIG_PUBLISHED_ID
root_config_rollback_identity=${ROOT_CONFIG_ROLLBACK_ID:-absent}
root_config_backup_identity=$ROOT_CONFIG_BACKUP_ID
intermediate_config_original_identity=$INT_CONFIG_ORIGINAL_ID
intermediate_config_published_identity=$INT_CONFIG_PUBLISHED_ID
intermediate_config_rollback_identity=${INT_CONFIG_ROLLBACK_ID:-absent}
intermediate_config_backup_identity=$INT_CONFIG_BACKUP_ID
issuer_ledger=$ISSUER_LEDGER
issuer_ledger_identity=$ISSUER_LEDGER_ID
issuer_ledger_sha256=$ISSUER_LEDGER_SHA256
quarantine_ledger=$QUARANTINE_LEDGER
quarantine_ledger_identity=$QUARANTINE_LEDGER_ID
quarantine_ledger_sha256=$QUARANTINE_LEDGER_SHA256
active_manifest=$ACTIVE_MANIFEST
active_original_identity=$ACTIVE_ORIGINAL_ID
active_published_identity=$ACTIVE_PUBLISHED_ID
committed=${2:-false}
"
}

require_authority_location() {
  local legacy=$1 generation=$2 identity=$3 label=$4 legacy_exists=false generation_exists=false
  [[ ! -e $legacy && ! -L $legacy ]] || legacy_exists=true
  [[ ! -e $generation && ! -L $generation ]] || generation_exists=true
  [[ $legacy_exists != "$generation_exists" ]] || pki_die "$label paths are simultaneously present or absent"
  if [[ $legacy_exists == true ]]; then [[ -d $legacy && ! -L $legacy && $(stat -c '%d:%i' "$legacy") == "$identity" ]] || pki_die "$label legacy identity changed"
  else [[ -d $generation && ! -L $generation && $(stat -c '%d:%i' "$generation") == "$identity" ]] || pki_die "$label generation identity changed"; fi
}

require_ledger() {
  local path=$1 identity=$2 digest=$3 label=$4 actual
  pki_require_file_identity "$path" "$identity" "$label"
  actual=$(sha256sum "$path"); [[ ${actual%% *} == "$digest" ]] || pki_die "$label digest changed"
}

preflight_migration_mutations() {
  local service issuer original published stage basename identity source destination
  pki_require_file_identity "$BACKUP_RECEIPT" "$RECEIPT_IDENTITY" 'Migration backup receipt'
  require_ledger "$ISSUER_LEDGER" "$ISSUER_LEDGER_ID" "$ISSUER_LEDGER_SHA256" 'Migration issuer ledger'
  require_ledger "$QUARANTINE_LEDGER" "$QUARANTINE_LEDGER_ID" "$QUARANTINE_LEDGER_SHA256" 'Migration quarantine ledger'
  require_ledger "$TXN_DIR/services" "$SERVICES_IDENTITY" "$SERVICES_SHA256" 'Migration service snapshot'
  pki_validate_provenance_manifest "$PROVENANCE_STAGE" "$PROVENANCE_MANIFEST" "$PROVENANCE_MANIFEST_IDENTITY" "$PROVENANCE_MANIFEST_SHA256"
  require_authority_location "$LEGACY_ROOT" "$NEW_ROOT" "$ROOT_SOURCE_ID" 'Root authority'; [[ -d $LEGACY_ROOT ]] || pki_die 'Root authority moved before migration mutation'
  require_authority_location "$LEGACY_INT" "$NEW_INT" "$INT_SOURCE_ID" 'Intermediate authority'; [[ -d $LEGACY_INT ]] || pki_die 'Intermediate authority moved before migration mutation'
  pki_require_file_identity "$LEGACY_ROOT/openssl.cnf" "$ROOT_CONFIG_ORIGINAL_ID" 'Root OpenSSL configuration'
  pki_require_file_identity "$LEGACY_INT/openssl.cnf" "$INT_CONFIG_ORIGINAL_ID" 'Intermediate OpenSSL configuration'
  pki_require_file_identity "$TXN_DIR/root-openssl.new" "$ROOT_CONFIG_PUBLISHED_ID" 'Staged root OpenSSL configuration'
  pki_require_file_identity "$TXN_DIR/intermediate-openssl.new" "$INT_CONFIG_PUBLISHED_ID" 'Staged intermediate OpenSSL configuration'
  pki_require_file_identity "$TXN_DIR/root-openssl.rollback" "$ROOT_CONFIG_ROLLBACK_ID" 'Staged root OpenSSL rollback'
  pki_require_file_identity "$TXN_DIR/intermediate-openssl.rollback" "$INT_CONFIG_ROLLBACK_ID" 'Staged intermediate OpenSSL rollback'
  pki_require_file_identity "$BACKUP_SESSION" "$BACKUP_SESSION_ORIGINAL_ID" 'Backup migration session'
  pki_require_file_identity "$TXN_DIR/backup-session.publish" "$BACKUP_SESSION_PUBLISHED_ID" 'Staged backup migration session'
  pki_require_file_identity "$ROOT_RESERVATION" "$ROOT_RESERVATION_ORIGINAL_ID" 'Root generation reservation'
  pki_require_file_identity "$INT_RESERVATION" "$INT_RESERVATION_ORIGINAL_ID" 'Intermediate generation reservation'
  pki_require_file_identity "$TXN_DIR/root-reserved.publish" "$ROOT_RESERVATION_RESERVED_ID" 'Staged root reservation'
  pki_require_file_identity "$TXN_DIR/intermediate-reserved.publish" "$INT_RESERVATION_RESERVED_ID" 'Staged intermediate reservation'
  pki_require_file_identity "$TXN_DIR/root-consumed.publish" "$ROOT_RESERVATION_CONSUMED_ID" 'Staged consumed root reservation'
  pki_require_file_identity "$TXN_DIR/intermediate-consumed.publish" "$INT_RESERVATION_CONSUMED_ID" 'Staged consumed intermediate reservation'
  pki_require_file_identity "$TXN_DIR/root-abandoned.publish" "$ROOT_RESERVATION_ROLLBACK_ID" 'Staged abandoned root reservation'
  pki_require_file_identity "$TXN_DIR/intermediate-abandoned.publish" "$INT_RESERVATION_ROLLBACK_ID" 'Staged abandoned intermediate reservation'
  pki_require_file_identity "$ACTIVE_MANIFEST" "$ACTIVE_ORIGINAL_ID" 'Active issuer manifest'
  pki_require_file_identity "$TXN_DIR/active.publish" "$ACTIVE_PUBLISHED_ID" 'Staged active issuer manifest'
  pki_require_file_identity "$PROVENANCE_DIR" absent 'Migration provenance destination'
  while IFS='|' read -r service original published; do
    issuer=$(pki_service_issuer "$service"); stage="$TXN_DIR/issuer-stage/$service"
    pki_require_file_identity "$issuer" "$original" "Service $service issuer"
    pki_require_file_identity "$stage" "$published" "Staged issuer $service"
  done <"$ISSUER_LEDGER"
  while IFS='|' read -r basename identity; do
    source="$PKI_DIR/$basename"; destination="$TXN_DIR/quarantine/$basename"
    pki_require_file_identity "$source" "$identity" 'Legacy quarantine source'
    pki_require_file_identity "$destination" absent 'Legacy quarantine destination'
  done <"$QUARANTINE_LEDGER"
}

finish_migrate() {
  local status=$?
  trap - EXIT; trap '' HUP INT TERM
  if [[ ${MUTATION_STARTED:-false} == true && ${COMMITTED:-false} != true ]]; then
    pki_atomic_write "$RECOVERY_MARKER" "transaction=$TXN_ID
action=run platform-pki-ca-rollover recover
" || status=1
  fi
  [[ -z ${SNAPSHOT_DIR:-} || ! -d $SNAPSHOT_DIR ]] || rm -rf "$SNAPSHOT_DIR"
  [[ ${EXPORT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$EXPORT_LOCK" 2>/dev/null || status=1
  [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}; PKI_DIR=${args[--pki-dir]:-}
BACKUP_RECEIPT=$(pki_expand_path "${args[--backup-receipt]}"); PRIVATE_REPO=$(pki_expand_path "${args[--private-repo]}")
YES=false; [[ -v args[--yes] ]] && YES=true
EXPECTED_ROOT=${args[--expected-root-sha256]:-}; EXPECTED_INT=${args[--expected-intermediate-sha256]:-}
NAMESPACE=$(pki_expand_path "$NAMESPACE"); PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}; PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_require_cmd openssl; pki_require_cmd sha256sum; pki_require_pki_dir; pki_prepare_control_state
[[ $BACKUP_RECEIPT == /* ]] || BACKUP_RECEIPT="$(pwd -P)/$BACKUP_RECEIPT"
[[ $PRIVATE_REPO == /* ]] || PRIVATE_REPO="$(pwd -P)/$PRIVATE_REPO"
read_receipt

ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock)
INVENTORY_LOCK=$(pki_inventory_operation_lock); EXPORT_LOCK=$(pki_export_operation_lock)
SNAPSHOT_DIR=''; MUTATION_STARTED=false; COMMITTED=false
trap finish_migrate EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_acquire_operation_lock "$EXPORT_LOCK" 'export operation'; EXPORT_LOCK_HELD=true
pki_require_no_unresolved_journal
LAYOUT=$(pki_detect_layout)
if [[ $LAYOUT == generation ]]; then
  pki_load_active_issuer_snapshot
  [[ $ACTIVE_ROOT_ID == g1 && $ACTIVE_INTERMEDIATE_ID == g1-i1 ]] || pki_die 'Existing generation layout is not the completed legacy migration pair'
  pki_ok 'Legacy PKI migration is already complete; no changes made'
  exit 0
fi
[[ $LAYOUT == legacy ]] || pki_die "Legacy migration refuses incomplete or ambiguous layout: $LAYOUT"
[[ $(pki_public_state_digest legacy) == "${RECEIPT[state_manifest_sha256]}" ]] || pki_die 'Current public PKI state differs from the backed-up state manifest'
[[ $(pki_private_metadata_digest) == "${RECEIPT[private_metadata_sha256]}" ]] || pki_die 'Current private metadata differs from the backed-up state'

LEGACY_ROOT="$PKI_DIR/root-ca"; LEGACY_INT="$PKI_DIR/intermediate-ca"
NEW_ROOT=$(pki_root_authority_dir g1); NEW_INT=$(pki_intermediate_authority_dir g1-i1)
for dir in "$LEGACY_ROOT" "$LEGACY_INT"; do pki_require_private_dir "$dir" 'Legacy CA directory'; done
ROOT_CERT="$LEGACY_ROOT/certs/root-ca.crt"; INT_CERT="$LEGACY_INT/certs/intermediate-ca.crt"
for path in "$ROOT_CERT" "$INT_CERT" "$LEGACY_ROOT/openssl.cnf" "$LEGACY_INT/openssl.cnf"; do pki_require_file "$path"; done
openssl verify -CAfile "$ROOT_CERT" "$INT_CERT" >/dev/null || pki_die 'Legacy intermediate does not verify against the legacy root'
ROOT_FP=$(openssl x509 -in "$ROOT_CERT" -noout -fingerprint -sha256); ROOT_FP=${ROOT_FP#*=}; ROOT_FP=${ROOT_FP//:/}; ROOT_FP=${ROOT_FP^^}
INT_FP=$(openssl x509 -in "$INT_CERT" -noout -fingerprint -sha256); INT_FP=${INT_FP#*=}; INT_FP=${INT_FP//:/}; INT_FP=${INT_FP^^}
if [[ $YES == true ]]; then
  [[ $EXPECTED_ROOT =~ ^[0-9A-Fa-f]{64}$ && $EXPECTED_INT =~ ^[0-9A-Fa-f]{64}$ ]] || pki_die '--yes requires both expected 64-hex SHA-256 fingerprints'
  [[ ${EXPECTED_ROOT^^} == "$ROOT_FP" && ${EXPECTED_INT^^} == "$INT_FP" ]] || pki_die 'Expected CA fingerprints do not match legacy certificates'
else
  [[ -t 0 ]] || pki_die 'Migration confirmation requires a TTY or --yes with both expected fingerprints'
  printf 'Type migrate %s %s to continue: ' "$ROOT_FP" "$INT_FP" >&2
  IFS= read -r confirmation
  [[ $confirmation == "migrate $ROOT_FP $INT_FP" ]] || pki_die 'Migration confirmation did not match'
fi

SNAPSHOT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-migrate.XXXXXX")
pki_load_inventory_snapshot "$SNAPSHOT_DIR"
pki_validate_legacy_state
PRIVATE_INVENTORY="$PRIVATE_REPO/pki/services.yml"
pki_require_no_symlink_path_components "$PRIVATE_REPO" 'Private repository'
[[ -f $PRIVATE_INVENTORY && ! -L $PRIVATE_INVENTORY ]] || pki_die "Canonical private inventory is missing or unsafe: $PRIVATE_INVENTORY"
[[ $(stat -c '%u:%h:%a' "$PRIVATE_INVENTORY") == "$(id -u):1:600" ]] || pki_die 'Canonical private inventory must be current-user-owned, singly linked, and mode 600'
pki_validate_inventory_file "$PRIVATE_INVENTORY" "$SNAPSHOT_DIR/private-canonical"
LC_ALL=C sort "$INVENTORY_CANONICAL" >"$SNAPSHOT_DIR/local-sorted"; LC_ALL=C sort "$SNAPSHOT_DIR/private-canonical" >"$SNAPSHOT_DIR/private-sorted"
cmp -s "$SNAPSHOT_DIR/local-sorted" "$SNAPSHOT_DIR/private-sorted" || pki_die 'Active inventory differs semantically from the canonical private inventory; install and review it before migration'

while IFS= read -r service; do
  cert=$(pki_service_cert "$service"); [[ -e $cert ]] || continue
  [[ -f $cert && ! -L $cert ]] || pki_die "Current service certificate is unsafe: $cert"
  openssl verify -CAfile "$ROOT_CERT" -untrusted "$INT_CERT" "$cert" >/dev/null || pki_die "Service does not verify through the legacy issuer: $service"
done < <(pki_inventory_services)
ROOT_SOURCE_ID=$(stat -c '%d:%i' "$LEGACY_ROOT"); INT_SOURCE_ID=$(stat -c '%d:%i' "$LEGACY_INT")
[[ $(stat -c '%d' "$LEGACY_ROOT") == $(stat -c '%d' "$PKI_DIR/authorities/roots") && $(stat -c '%d' "$LEGACY_INT") == $(stat -c '%d' "$PKI_DIR/authorities/intermediates") ]] || pki_die 'Legacy CA directories and generation destinations must be on the same filesystem'
ROOT_RESERVATION=$(pki_generation_reservation g1); INT_RESERVATION=$(pki_generation_reservation g1-i1)
ROOT_RESERVATION_ORIGINAL_ID=$(pki_file_identity_or_absent "$ROOT_RESERVATION"); INT_RESERVATION_ORIGINAL_ID=$(pki_file_identity_or_absent "$INT_RESERVATION")
for record in "$ROOT_RESERVATION|g1|root|$ROOT_FP|$ROOT_SOURCE_ID|$ROOT_RESERVATION_ORIGINAL_ID" "$INT_RESERVATION|g1-i1|intermediate|$INT_FP|$INT_SOURCE_ID|$INT_RESERVATION_ORIGINAL_ID"; do
  path=${record%%|*}; rest=${record#*|}; generation=${rest%%|*}; rest=${rest#*|}; kind=${rest%%|*}; rest=${rest#*|}; fp=${rest%%|*}; rest=${rest#*|}; identity=${rest%%|*}; original_id=${rest#*|}
  [[ $original_id == absent ]] && continue
  pki_read_state_record "$path" 'Legacy migration generation reservation'
  [[ ${#PKI_RECORD[@]} -eq 5 && ${PKI_RECORD[generation]:-} == "$generation" && ${PKI_RECORD[kind]:-} == "$kind" && ${PKI_RECORD[status]:-} == abandoned && ${PKI_RECORD[fingerprint_sha256]:-} == "$fp" && ${PKI_RECORD[source_identity]:-} == "$identity" && $(pki_file_object_state "$path") == "$original_id" ]] || pki_die "Generation reservation cannot be safely adopted: $path"
done

TXN_ID="migrate-$(date -u '+%Y%m%d-%H%M%S')-$$"; TXN_DIR="$PKI_DIR/state/rollover/$TXN_ID"; mkdir -m 700 "$TXN_DIR"; TXN_IDENTITY=$(pki_dir_identity "$TXN_DIR"); RECEIPT_IDENTITY=$(pki_file_identity "$BACKUP_RECEIPT")
cp -p "$LEGACY_ROOT/openssl.cnf" "$TXN_DIR/root-openssl.cnf"; cp -p "$LEGACY_INT/openssl.cnf" "$TXN_DIR/intermediate-openssl.cnf"
transform_config "$LEGACY_ROOT/openssl.cnf" "$TXN_DIR/root-openssl.new" "$LEGACY_ROOT" "$NEW_ROOT"
transform_config "$LEGACY_INT/openssl.cnf" "$TXN_DIR/intermediate-openssl.new" "$LEGACY_INT" "$NEW_INT"
ROOT_CONFIG_ORIGINAL_ID=$(pki_file_object_state "$LEGACY_ROOT/openssl.cnf"); INT_CONFIG_ORIGINAL_ID=$(pki_file_object_state "$LEGACY_INT/openssl.cnf")
ROOT_CONFIG_BACKUP_ID=$(pki_file_object_state "$TXN_DIR/root-openssl.cnf"); INT_CONFIG_BACKUP_ID=$(pki_file_object_state "$TXN_DIR/intermediate-openssl.cnf")
ROOT_CONFIG_PUBLISHED_ID=$(pki_file_object_state "$TXN_DIR/root-openssl.new"); INT_CONFIG_PUBLISHED_ID=$(pki_file_object_state "$TXN_DIR/intermediate-openssl.new")
printf 'public_state_sha256=%s\n' "${RECEIPT[state_manifest_sha256]}" >"$TXN_DIR/baseline"
for private in "$LEGACY_ROOT/private/root-ca.key" "$LEGACY_INT/private/intermediate-ca.key"; do [[ ! -e $private ]] || stat -c 'private_metadata=%n|%d|%i|%u|%a|%s|%y|%z' "$private" >>"$TXN_DIR/baseline"; done
chmod 600 "$TXN_DIR"/*; mkdir -m 700 "$TXN_DIR/issuer-stage" "$TXN_DIR/quarantine"
while IFS= read -r service; do [[ ! -f $(pki_service_cert "$service") ]] || printf '%s\n' "$service"; done < <(pki_inventory_services) >"$TXN_DIR/services"; chmod 600 "$TXN_DIR/services"; pki_fsync "$TXN_DIR/services"; SERVICES_IDENTITY=$(pki_file_identity "$TXN_DIR/services"); SERVICES_SHA256=$(sha256sum "$TXN_DIR/services"); SERVICES_SHA256=${SERVICES_SHA256%% *}; pki_fsync "$TXN_DIR"
JOURNAL=$(pki_recovery_journal); RECOVERY_MARKER=$(pki_recovery_marker); ACTIVE_MANIFEST=$(pki_active_issuer_manifest)
ACTIVE_ORIGINAL_ID=$(pki_file_identity_or_absent "$ACTIVE_MANIFEST"); [[ $ACTIVE_ORIGINAL_ID == absent ]] || pki_die 'Legacy migration active manifest destination already exists'
BACKUP_SESSION="$PKI_DIR/state/rollover/backup-session-${RECEIPT[session]}"; BACKUP_SESSION_ORIGINAL_ID=$(pki_file_identity_or_absent "$BACKUP_SESSION"); [[ $BACKUP_SESSION_ORIGINAL_ID == absent ]] || pki_die 'Backup migration session was already consumed'
pki_atomic_write "$TXN_DIR/backup-session.publish" "session=${RECEIPT[session]}
archive_sha256=${RECEIPT[archive_sha256]}
transaction=$TXN_ID
"; BACKUP_SESSION_PUBLISHED_ID=$(pki_file_object_state "$TXN_DIR/backup-session.publish")
pki_atomic_write "$TXN_DIR/root-reserved.publish" "generation=g1
kind=root
status=reserved
fingerprint_sha256=$ROOT_FP
source_identity=$ROOT_SOURCE_ID
"; ROOT_RESERVATION_RESERVED_ID=$(pki_file_object_state "$TXN_DIR/root-reserved.publish")
pki_atomic_write "$TXN_DIR/intermediate-reserved.publish" "generation=g1-i1
kind=intermediate
status=reserved
fingerprint_sha256=$INT_FP
source_identity=$INT_SOURCE_ID
"; INT_RESERVATION_RESERVED_ID=$(pki_file_object_state "$TXN_DIR/intermediate-reserved.publish")
pki_atomic_write "$TXN_DIR/root-consumed.publish" "generation=g1
kind=root
status=consumed
fingerprint_sha256=$ROOT_FP
source_identity=$ROOT_SOURCE_ID
"; ROOT_RESERVATION_CONSUMED_ID=$(pki_file_object_state "$TXN_DIR/root-consumed.publish")
pki_atomic_write "$TXN_DIR/intermediate-consumed.publish" "generation=g1-i1
kind=intermediate
status=consumed
fingerprint_sha256=$INT_FP
source_identity=$INT_SOURCE_ID
"; INT_RESERVATION_CONSUMED_ID=$(pki_file_object_state "$TXN_DIR/intermediate-consumed.publish")
pki_atomic_write "$TXN_DIR/root-abandoned.publish" "generation=g1
kind=root
status=abandoned
fingerprint_sha256=$ROOT_FP
source_identity=$ROOT_SOURCE_ID
"; ROOT_RESERVATION_ROLLBACK_ID=$(pki_file_object_state "$TXN_DIR/root-abandoned.publish")
pki_atomic_write "$TXN_DIR/intermediate-abandoned.publish" "generation=g1-i1
kind=intermediate
status=abandoned
fingerprint_sha256=$INT_FP
source_identity=$INT_SOURCE_ID
"; INT_RESERVATION_ROLLBACK_ID=$(pki_file_object_state "$TXN_DIR/intermediate-abandoned.publish")
cp -p "$TXN_DIR/root-openssl.cnf" "$TXN_DIR/root-openssl.rollback"; ROOT_CONFIG_ROLLBACK_ID=$(pki_file_object_state "$TXN_DIR/root-openssl.rollback")
cp -p "$TXN_DIR/intermediate-openssl.cnf" "$TXN_DIR/intermediate-openssl.rollback"; INT_CONFIG_ROLLBACK_ID=$(pki_file_object_state "$TXN_DIR/intermediate-openssl.rollback")
pki_atomic_write "$TXN_DIR/active.publish" "root=g1
intermediate=g1-i1
"; ACTIVE_PUBLISHED_ID=$(pki_file_object_state "$TXN_DIR/active.publish")
ISSUER_LEDGER="$TXN_DIR/issuer-identities"; : >"$ISSUER_LEDGER"
while IFS= read -r service; do issuer=$(pki_service_issuer "$service"); original=$(pki_file_identity_or_absent "$issuer"); [[ $original == absent ]] || pki_die "Service issuer record already exists during legacy migration: $issuer"; stage="$TXN_DIR/issuer-stage/$service"; pki_atomic_write "$stage" "root=g1
intermediate=g1-i1
"; printf '%s|%s|%s\n' "$service" "$original" "$(pki_file_object_state "$stage")" >>"$ISSUER_LEDGER"; done <"$TXN_DIR/services"
chmod 600 "$ISSUER_LEDGER"; pki_fsync "$ISSUER_LEDGER"; ISSUER_LEDGER_ID=$(pki_file_identity "$ISSUER_LEDGER"); ISSUER_LEDGER_SHA256=$(sha256sum "$ISSUER_LEDGER"); ISSUER_LEDGER_SHA256=${ISSUER_LEDGER_SHA256%% *}
QUARANTINE_LEDGER="$TXN_DIR/quarantine-identities"; : >"$QUARANTINE_LEDGER"
for old in "$PKI_DIR/pki.env" "$PKI_DIR/openssl-root.cnf.tpl" "$PKI_DIR/openssl-intermediate.cnf.tpl" "$PKI_DIR/openssl-service.cnf.tpl"; do [[ ! -e $old && ! -L $old ]] && continue; [[ -f $old && ! -L $old ]] || pki_die "Legacy quarantine source is unsafe: $old"; basename=$(basename -- "$old"); destination="$TXN_DIR/quarantine/$basename"; pki_require_file_identity "$destination" absent 'Legacy quarantine destination'; printf '%s|%s\n' "$basename" "$(pki_file_object_state "$old")" >>"$QUARANTINE_LEDGER"; done
chmod 600 "$QUARANTINE_LEDGER"; pki_fsync "$QUARANTINE_LEDGER"; QUARANTINE_LEDGER_ID=$(pki_file_identity "$QUARANTINE_LEDGER"); QUARANTINE_LEDGER_SHA256=$(sha256sum "$QUARANTINE_LEDGER"); QUARANTINE_LEDGER_SHA256=${QUARANTINE_LEDGER_SHA256%% *}; pki_fsync_tree "$TXN_DIR"
if [[ ! -e $PKI_DIR/legacy && ! -L $PKI_DIR/legacy ]]; then mkdir -m 700 "$PKI_DIR/legacy"; pki_fsync "$PKI_DIR"; fi
pki_require_private_dir "$PKI_DIR/legacy" 'Migration provenance directory'
PROVENANCE_STAGE="$PKI_DIR/legacy/.$TXN_ID.publish"; PROVENANCE_DIR="$PKI_DIR/legacy/$TXN_ID"; pki_require_file_identity "$PROVENANCE_STAGE" absent 'Migration provenance stage'; pki_require_file_identity "$PROVENANCE_DIR" absent 'Migration provenance destination'
cp -a "$TXN_DIR" "$PROVENANCE_STAGE"
while IFS='|' read -r basename identity; do [[ -n $basename ]] || continue; pki_require_file_identity "$PKI_DIR/$basename" "$identity" 'Legacy provenance source'; cp -p -- "$PKI_DIR/$basename" "$PROVENANCE_STAGE/quarantine/$basename"; done <"$QUARANTINE_LEDGER"
printf 'Legacy singleton CA directories were moved without copying private keys.\nOriginal managed OpenSSL configurations and quarantined legacy scaffolding are retained here.\n' >"$PROVENANCE_STAGE/README"; chmod 600 "$PROVENANCE_STAGE/README"
PROVENANCE_MANIFEST="$PROVENANCE_STAGE/provenance-manifest"; pki_atomic_write "$PROVENANCE_MANIFEST" "$(pki_provenance_manifest "$PROVENANCE_STAGE")"
PROVENANCE_MANIFEST_IDENTITY=$(pki_file_identity "$PROVENANCE_MANIFEST"); PROVENANCE_MANIFEST_SHA256=$(sha256sum "$PROVENANCE_MANIFEST"); PROVENANCE_MANIFEST_SHA256=${PROVENANCE_MANIFEST_SHA256%% *}
pki_fsync_tree "$PROVENANCE_STAGE"; PROVENANCE_IDENTITY=$(pki_dir_identity "$PROVENANCE_STAGE")
preflight_migration_mutations
write_journal pre-mutation
MUTATION_STARTED=true
fault after-journal
pki_require_file_identity "$BACKUP_SESSION" "$BACKUP_SESSION_ORIGINAL_ID" 'Backup migration session'; pki_publish_staged_file "$TXN_DIR/backup-session.publish" "$BACKUP_SESSION"
pki_require_file_identity "$ROOT_RESERVATION" "$ROOT_RESERVATION_ORIGINAL_ID" 'Root generation reservation'; pki_publish_staged_file "$TXN_DIR/root-reserved.publish" "$ROOT_RESERVATION"
pki_require_file_identity "$INT_RESERVATION" "$INT_RESERVATION_ORIGINAL_ID" 'Intermediate generation reservation'; pki_publish_staged_file "$TXN_DIR/intermediate-reserved.publish" "$INT_RESERVATION"
write_journal reserved; fault after-reservations
require_authority_location "$LEGACY_ROOT" "$NEW_ROOT" "$ROOT_SOURCE_ID" 'Root authority'; pki_require_file_identity "$NEW_ROOT" absent 'Root generation destination'; mv -T "$LEGACY_ROOT" "$NEW_ROOT"; [[ $(stat -c '%d:%i' "$NEW_ROOT") == "$ROOT_SOURCE_ID" ]] || pki_die 'Migrated root authority identity changed'; pki_fsync_rename_parents "$(dirname -- "$LEGACY_ROOT")" "$(dirname -- "$NEW_ROOT")"; write_journal root-renamed; fault after-root-rename
require_authority_location "$LEGACY_INT" "$NEW_INT" "$INT_SOURCE_ID" 'Intermediate authority'; pki_require_file_identity "$NEW_INT" absent 'Intermediate generation destination'; mv -T "$LEGACY_INT" "$NEW_INT"; [[ $(stat -c '%d:%i' "$NEW_INT") == "$INT_SOURCE_ID" ]] || pki_die 'Migrated intermediate authority identity changed'; pki_fsync_rename_parents "$(dirname -- "$LEGACY_INT")" "$(dirname -- "$NEW_INT")"; write_journal intermediate-renamed; fault after-intermediate-rename
pki_require_file_identity "$NEW_ROOT/openssl.cnf" "$ROOT_CONFIG_ORIGINAL_ID" 'Root OpenSSL configuration'; pki_require_file_identity "$NEW_INT/openssl.cnf" "$INT_CONFIG_ORIGINAL_ID" 'Intermediate OpenSSL configuration'; pki_publish_staged_file "$TXN_DIR/root-openssl.new" "$NEW_ROOT/openssl.cnf"; pki_publish_staged_file "$TXN_DIR/intermediate-openssl.new" "$NEW_INT/openssl.cnf"
write_journal configs-published; fault after-configs
while IFS='|' read -r service original published; do [[ -n $service ]] || continue; issuer=$(pki_service_issuer "$service"); stage="$TXN_DIR/issuer-stage/$service"; pki_require_file_identity "$issuer" "$original" "Service $service issuer"; pki_require_file_identity "$stage" "$published" "Service $service staged issuer"; pki_publish_staged_file "$stage" "$issuer"; done <"$ISSUER_LEDGER"
write_journal issuers-published; fault after-issuers
while IFS='|' read -r basename identity; do [[ -n $basename ]] || continue; source="$PKI_DIR/$basename"; destination="$TXN_DIR/quarantine/$basename"; pki_require_file_identity "$source" "$identity" 'Legacy quarantine source'; pki_require_file_identity "$destination" absent 'Legacy quarantine destination'; mv -T -- "$source" "$destination"; pki_fsync_rename_parents "$(dirname -- "$source")" "$(dirname -- "$destination")"; pki_require_file_identity "$destination" "$identity" 'Published quarantine entry'; done <"$QUARANTINE_LEDGER"
write_journal quarantined; fault after-quarantine
pki_require_file_identity "$ROOT_RESERVATION" "$ROOT_RESERVATION_RESERVED_ID" 'Reserved root generation'; pki_publish_staged_file "$TXN_DIR/root-consumed.publish" "$ROOT_RESERVATION"
pki_require_file_identity "$INT_RESERVATION" "$INT_RESERVATION_RESERVED_ID" 'Reserved intermediate generation'; pki_publish_staged_file "$TXN_DIR/intermediate-consumed.publish" "$INT_RESERVATION"
write_journal active-pending; pki_require_file_identity "$ACTIVE_MANIFEST" "$ACTIVE_ORIGINAL_ID" 'Active issuer manifest'; pki_publish_staged_file "$TXN_DIR/active.publish" "$ACTIVE_MANIFEST"; write_journal active-published; fault after-active
pki_require_file_identity "$PROVENANCE_DIR" absent 'Migration provenance destination'; mv -T -- "$PROVENANCE_STAGE" "$PROVENANCE_DIR"; pki_fsync_rename_parents "$(dirname -- "$PROVENANCE_STAGE")" "$(dirname -- "$PROVENANCE_DIR")"; [[ $(pki_dir_identity "$PROVENANCE_DIR") == "$PROVENANCE_IDENTITY" ]] || pki_die 'Migration provenance identity changed during publication'; write_journal provenance-published
write_journal complete true; rm -f -- "$RECOVERY_MARKER"; pki_fsync "$(dirname -- "$RECOVERY_MARKER")"; COMMITTED=true
pki_remove_journaled_tree "$TXN_DIR" "$TXN_IDENTITY" "$(dirname -- "$TXN_DIR")" || pki_die 'Cannot remove committed migration transaction staging'
pki_ok 'Migrated legacy PKI state to root g1 and intermediate g1-i1'
