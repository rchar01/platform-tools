SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh; fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"
pki_reject_repeated_options --namespace --pki-dir --type --backup-receipt --root-name --intermediate-name --org --country --root-days --intermediate-days --root-pass-file --intermediate-pass-file --issuer-safety-days --private-repo

require_trusted_ancestors() {
  local path=$1 label=$2 current='' component mode owner uid
  local -a components
  uid=$(id -u); IFS='/' read -r -a components <<<"$path"; [[ $path != /* ]] || current=/
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    if [[ $current == / ]]; then current="/$component"; elif [[ -n $current ]]; then current="$current/$component"; else current=$component; fi
    [[ -d $current && ! -L $current ]] || pki_die "$label ancestor must be a non-symlink directory: $current"
    mode=$(stat -c '%a' "$current"); owner=$(stat -c '%u' "$current")
    [[ $owner == "$uid" || $owner == 0 ]] || pki_die "$label ancestor is not owned by current user or root: $current"
    (( (8#$mode & 022) == 0 || (8#$mode & 01000) != 0 )) || pki_die "$label ancestor is group- or world-writable without sticky bit: $current"
  done
}

prepare_fault() {
  [[ ${PLATFORM_PKI_PREPARE_CRASH_AT:-} != "$1" ]] || kill -KILL "$$"
  [[ ${PLATFORM_PKI_PREPARE_SIGNAL_AT:-} != "$1" ]] || kill -TERM "$$"
  [[ ${PLATFORM_PKI_PREPARE_FAIL_AT:-} != "$1" ]] || pki_die "Injected rollover preparation failure at $1"
}

cert_fingerprint() { local value; value=$(openssl x509 -in "$1" -noout -fingerprint -sha256); value=${value#*=}; printf '%s\n' "${value//:/}"; }
cert_public_key_digest() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f1; }
cert_expiry() { date -u -d "$(openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//')" '+%Y-%m-%dT%H:%M:%SZ'; }
require_ca_certificate() { openssl x509 -in "$1" -noout -text | grep -Fq 'CA:TRUE' || pki_die "Certificate is not a CA certificate: $1"; }
require_key_match() {
  local key=$1 cert=$2 pass_file=$3 directory=$4
  openssl x509 -in "$cert" -pubkey -noout >"$directory/cert.pub"
  local -a command=(openssl pkey -in "$key" -pubout -out "$directory/key.pub")
  [[ -z $pass_file ]] || command+=(-passin "file:$pass_file")
  "${command[@]}"; cmp -s "$directory/cert.pub" "$directory/key.pub" || pki_die "Private key and certificate do not match: $cert"
  rm -f -- "$directory/cert.pub" "$directory/key.pub"
}

read_backup_receipt() {
  local key now archive_hash archive_identity
  RECEIPT_IDENTITY=$(pki_file_identity "$BACKUP_RECEIPT"); pki_read_state_record "$BACKUP_RECEIPT" 'Backup receipt'; [[ $(pki_file_identity "$BACKUP_RECEIPT") == "$RECEIPT_IDENTITY" ]] || pki_die 'Backup receipt changed after validation'
  unset -v RECEIPT; declare -gA RECEIPT=(); for key in "${!PKI_RECORD[@]}"; do RECEIPT[$key]=${PKI_RECORD[$key]}; done; unset -v PKI_RECORD
  for key in schema layout session backup_path backup_device backup_inode backup_size backup_mode backup_owner archive_sha256 created_at created_epoch state_manifest_sha256 private_metadata_sha256; do [[ -v RECEIPT[$key] ]] || pki_die "Backup receipt is missing field: $key"; done
  [[ ${#RECEIPT[@]} -eq 14 && ${RECEIPT[schema]} == 2 && ${RECEIPT[layout]} == generation && ${RECEIPT[session]} =~ ^[0-9a-f]{32}$ && ${RECEIPT[created_epoch]} =~ ^[0-9]+$ ]] || pki_die 'Backup receipt is not a supported generation-layout receipt'
  now=$(date -u +%s); (( now >= 10#${RECEIPT[created_epoch]} && now - 10#${RECEIPT[created_epoch]} <= 86400 )) || pki_die 'Backup receipt is older than the 24-hour preparation freshness window'
  ARCHIVE=${RECEIPT[backup_path]}; [[ $ARCHIVE == /* && -f $ARCHIVE && ! -L $ARCHIVE ]] || pki_die 'Backup archive path is unsafe or missing'
  [[ $(stat -c '%d:%i:%s:%a:%u:%h' "$ARCHIVE") == "${RECEIPT[backup_device]}:${RECEIPT[backup_inode]}:${RECEIPT[backup_size]}:${RECEIPT[backup_mode]}:${RECEIPT[backup_owner]}:1" ]] || pki_die 'Backup archive identity no longer matches its receipt'
  archive_identity=$(pki_file_identity "$ARCHIVE"); archive_hash=$(sha256sum "$ARCHIVE"); [[ $(pki_file_identity "$ARCHIVE") == "$archive_identity" ]] || pki_die 'Backup archive changed while hashing'; [[ ${archive_hash%% *} == "${RECEIPT[archive_sha256]}" ]] || pki_die 'Backup archive digest no longer matches its receipt'
}

validate_trust_consumers() {
  local source=$1 canonical=$3 line consumer='' kind='' line_number=0 saw_document=false saw_consumers=false count=0 before after mode owner links fd
  local -A seen=()
  [[ -f $source && ! -L $source && -r $source ]] || pki_die "Trust consumer source must be a readable non-symlink regular file: $source"
  before=$(pki_file_identity "$source"); owner=$(stat -c '%u' "$source"); mode=$(stat -c '%a' "$source"); links=$(stat -c '%h' "$source")
  [[ $owner == "$(id -u)" && $links == 1 ]] || pki_die 'Trust consumer source must be current-user-owned and singly linked'
  (( (8#$mode & 022) == 0 )) || pki_die 'Trust consumer source is group- or world-writable'
  exec {fd}<"$source" || pki_die 'Cannot open trust consumer source'
  after=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$fd")
  [[ $after == "$before" && $(pki_file_identity "$source") == "$before" ]] || { exec {fd}<&-; pki_die 'Trust consumer source changed while being opened'; }
  [[ $(pki_file_identity "$source") == "$before" ]] || { exec {fd}<&-; pki_die 'Trust consumer source changed before validation'; }
  TRUST_VALIDATED_SOURCE_IDENTITY=$before
  : >"$canonical"
  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1)); [[ $line != *$'\t'* && ! $line =~ [[:cntrl:]] ]] || pki_die "Trust consumer checklist contains unsupported characters at line $line_number"
    [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue
    if [[ $line == '---' ]]; then [[ $saw_document == false && $saw_consumers == false ]] || pki_die "Trust consumer document marker is duplicate or misplaced at line $line_number"; saw_document=true; continue; fi
    if [[ $line == consumers: ]]; then [[ $saw_consumers == false ]] || pki_die 'Trust consumer checklist contains duplicate consumers'; saw_consumers=true; continue; fi
    [[ $saw_consumers == true ]] || pki_die "Trust consumer content exists outside consumers at line $line_number"
    if [[ $line =~ ^\ \ ([A-Za-z0-9][A-Za-z0-9_.-]*):$ ]]; then
      [[ -z $consumer || -n $kind ]] || pki_die "Trust consumer $consumer is missing kind"
      consumer=${BASH_REMATCH[1]}; [[ ! -v seen[$consumer] ]] || pki_die "Trust consumer ID is duplicated: $consumer"; seen[$consumer]=1; kind=''; count=$((count + 1)); continue
    fi
    if [[ $line =~ ^\ \ \ \ kind:[[:space:]]+(managed|manual)$ ]]; then
      [[ -n $consumer && -z $kind ]] || pki_die "Trust consumer kind is duplicate or misplaced at line $line_number"
      kind=${BASH_REMATCH[1]}; printf '%s\t%s\n' "$consumer" "$kind" >>"$canonical"; continue
    fi
    pki_die "Unsupported trust consumer grammar at line $line_number"
  done <&"$fd"
  exec {fd}<&-
  [[ $(pki_file_identity "$source") == "$before" ]] || pki_die 'Trust consumer source changed while being validated'
  [[ $saw_consumers == true && $count -gt 0 ]] || pki_die 'Trust consumer checklist must contain at least one consumer'
  [[ -z $consumer || -n $kind ]] || pki_die "Trust consumer $consumer is missing kind"
}

write_prepare_journal_raw() {
  local phase=$1 committed=${2:-false} key content=''
  PREP[phase]=$phase; PREP[committed]=$committed
  while IFS= read -r key; do content+="$key=${PREP[$key]}
"; done < <(printf '%s\n' "${!PREP[@]}" | LC_ALL=C sort)
  pki_write_journal "$JOURNAL" "$content"
}
refresh_transaction_manifest() {
  local sequence staging final value
  [[ ${PREP[transaction_identity]:-none} != none && -d ${TXN_DIR:-} ]] || return 0
  sequence=$((10#${PREP[transaction_tree_manifest_sequence]} + 1))
  staging="$(dirname -- "$TXN_DIR")/.$TXN_ID.transaction-tree.$sequence"
  final=$staging
  [[ ! -e $staging && ! -L $staging ]] || pki_die 'Preparation transaction manifest path is occupied'
  pki_tree_manifest "$TXN_DIR" >"$staging"; chmod 600 "$staging"; pki_fsync "$staging"
  PREP[transaction_tree_manifest_pending]=$staging
  PREP[transaction_tree_manifest_pending_destination]=$final
  PREP[transaction_tree_manifest_pending_identity]=$(pki_file_identity "$staging")
  value=$(sha256sum "$staging"); PREP[transaction_tree_manifest_pending_sha256]=${value%% *}
  write_prepare_journal_raw "${PREP[phase]}" "${PREP[committed]}"
  prepare_fault transaction-manifest-staged
  [[ $(pki_file_identity "$final") == "${PREP[transaction_tree_manifest_pending_identity]}" ]] || pki_die 'Preparation transaction manifest identity changed before publication'
  prepare_fault transaction-manifest-published
  PREP[transaction_tree_manifest]=$final
  PREP[transaction_tree_manifest_identity]=${PREP[transaction_tree_manifest_pending_identity]}
  PREP[transaction_tree_manifest_sha256]=${PREP[transaction_tree_manifest_pending_sha256]}
  PREP[transaction_tree_manifest_sequence]=$sequence
  PREP[transaction_tree_manifest_pending]=none
  PREP[transaction_tree_manifest_pending_destination]=none
  PREP[transaction_tree_manifest_pending_identity]=none
  PREP[transaction_tree_manifest_pending_sha256]=none
  write_prepare_journal_raw "${PREP[phase]}" "${PREP[committed]}"
}
write_prepare_journal() { write_prepare_journal_raw "$@"; }
prepare_checkpoint() { PREP[recovery_step]=$1; refresh_transaction_manifest; write_prepare_journal recovering; prepare_fault "$1"; }
prepare_file_destination() {
  local path=$1 field=$2 mode=$3 checkpoint=$4
  [[ ! -e $path && ! -L $path ]] || pki_die "Preparation output destination already exists: $path"
  : >"$path"; chmod "$mode" "$path"; pki_fsync "$path"
  PREP[${field}_pre_identity]=$(pki_file_identity "$path")
  prepare_checkpoint "$checkpoint-pending"
}
prepare_child_failed() {
  local checkpoint=$1 field path
  shift
  while (( $# )); do field=$1; path=$2; shift 2; PREP[${field}_partial_identity]=$(pki_file_identity "$path"); done
  prepare_checkpoint "$checkpoint-child-failed"
  pki_die "Sensitive child operation failed during $checkpoint"
}
prepare_copy_file() {
  local source=$1 destination=$2 field=$3 mode=$4 checkpoint=$5 status copy_command=${PLATFORM_PKI_PREPARE_CP:-cp}
  prepare_file_destination "$destination" "$field" "$mode" "$checkpoint"
  set +e; "$copy_command" -p -- "$source" "$destination"; status=$?; set -e
  (( status == 0 )) || prepare_child_failed "$checkpoint" "$field" "$destination"
  chmod "$mode" "$destination"; pki_fsync "$destination"; PREP[${field}_identity]=$(pki_file_identity "$destination")
  prepare_checkpoint "$checkpoint-done"
}
finish_prepare_transaction() {
  local journal_identity marker_identity receipt
  PREP[recovery_action]=resume; PREP[terminal_outcome]=resumed; PREP[recovery_step]=terminal-transaction-pending
  write_prepare_journal terminal-cleanup true; COMMITTED=true
  pki_atomic_write "$MARKER" "transaction=$TXN_ID
operation=rollover-prepare
terminal_outcome=resumed
"
  prepare_fault terminal-transaction-pending
  pki_remove_manifested_tree "$TXN_DIR" "${PREP[transaction_identity]}" "$(dirname -- "$TXN_DIR")" "${PREP[transaction_tree_manifest]}" "${PREP[transaction_tree_manifest_identity]}" "${PREP[transaction_tree_manifest_sha256]}" || pki_die 'Cannot remove committed preparation staging'
  PREP[recovery_step]=terminal-transaction-done; write_prepare_journal terminal-cleanup true; prepare_fault terminal-transaction-done
  PREP[recovery_step]=terminal-journal-pending; write_prepare_journal terminal-cleanup true; prepare_fault terminal-journal-pending
  journal_identity=$(pki_file_identity "$JOURNAL"); marker_identity=$(pki_file_identity "$MARKER"); receipt=$(pki_terminal_receipt "$TXN_ID")
  pki_atomic_write "$receipt" "transaction=$TXN_ID
operation=rollover-prepare
terminal_outcome=resumed
journal_identity=$journal_identity
marker_identity=$marker_identity
"
  pki_remove_identity_file "$JOURNAL" "$journal_identity" terminal-journal || pki_die 'Preparation journal changed before terminal unlink'; prepare_fault terminal-journal-done
  pki_remove_identity_file "$MARKER" "$marker_identity" terminal-marker || pki_die 'Preparation marker changed before terminal unlink'
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}; PKI_DIR=${args[--pki-dir]:-}; TYPE=${args[--type]}
BACKUP_RECEIPT=$(pki_expand_path "${args[--backup-receipt]}"); ROOT_NAME=${args[--root-name]:-}; INTERMEDIATE_NAME=${args[--intermediate-name]}; ORG=${args[--org]}; COUNTRY=${args[--country]}
ROOT_DAYS=${args[--root-days]:-${PLATFORM_PKI_ROOT_DAYS:-3650}}; INTERMEDIATE_DAYS=${args[--intermediate-days]:-${PLATFORM_PKI_INTERMEDIATE_DAYS:-1825}}; ISSUER_SAFETY_DAYS=${args[--issuer-safety-days]}
ROOT_PASS_FILE=${args[--root-pass-file]:-}; INTERMEDIATE_PASS_FILE=${args[--intermediate-pass-file]:-}; PRIVATE_REPO=${args[--private-repo]:-}
if [[ $TYPE == intermediate ]]; then
  [[ -z $ROOT_NAME && ! -v args[--root-days] && -z $PRIVATE_REPO ]] || pki_die '--root-name, --root-days, and --private-repo are forbidden for intermediate preparation'
else
  [[ -n $ROOT_NAME ]] || pki_die '--root-name is required for root preparation'
  PRIVATE_REPO=${PRIVATE_REPO:-../platform-private}
fi
pki_validate_days "$ROOT_DAYS"; pki_validate_days "$INTERMEDIATE_DAYS"; pki_validate_days "$ISSUER_SAFETY_DAYS"
for value in "$INTERMEDIATE_NAME" "$ORG" "$COUNTRY"; do pki_validate_openssl_config_value 'Rollover certificate field' "$value"; done
[[ $TYPE != root ]] || pki_validate_openssl_config_value 'Rollover root common name' "$ROOT_NAME"
NAMESPACE=$(pki_expand_path "$NAMESPACE"); PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}; PKI_DIR=$(pki_expand_path "$PKI_DIR"); pki_validate_openssl_config_value 'PKI directory' "$PKI_DIR"
[[ $BACKUP_RECEIPT == /* ]] || BACKUP_RECEIPT="$(pwd -P)/$BACKUP_RECEIPT"
if [[ -n $ROOT_PASS_FILE ]]; then ROOT_PASS_FILE=$(pki_expand_path "$ROOT_PASS_FILE"); pki_require_pass_file "$ROOT_PASS_FILE"; fi
if [[ -n $INTERMEDIATE_PASS_FILE ]]; then INTERMEDIATE_PASS_FILE=$(pki_expand_path "$INTERMEDIATE_PASS_FILE"); pki_require_pass_file "$INTERMEDIATE_PASS_FILE"; fi
if [[ -z $ROOT_PASS_FILE || -z $INTERMEDIATE_PASS_FILE ]]; then [[ -t 0 && -t 1 ]] || pki_die 'Preparation without all required passphrase files requires an interactive TTY'; fi
pki_require_cmd openssl; pki_require_cmd sha256sum; pki_require_cmd mv; pki_require_pki_dir; pki_prepare_control_state

ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); INVENTORY_LOCK=$(pki_inventory_operation_lock); EXPORT_LOCK=$(pki_export_operation_lock)
PRE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-prepare.XXXXXX"); TRANSACTION_STARTED=false; COMMITTED=false
finish_prepare() {
  local status=$?; trap - EXIT
  if [[ $TRANSACTION_STARTED == true && $COMMITTED != true ]]; then pki_atomic_write "$MARKER" "transaction=$TXN_ID
action=run platform-pki-ca-rollover recover
" || status=1; fi
  rm -rf -- "$PRE_TMP"
  [[ ${EXPORT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$EXPORT_LOCK" 2>/dev/null || status=1
  [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}
trap finish_prepare EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; umask 077
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_acquire_operation_lock "$EXPORT_LOCK" 'export operation'; EXPORT_LOCK_HELD=true
pki_require_no_unresolved_journal
[[ $(pki_detect_layout) == generation ]] || pki_die 'Rollover preparation requires a complete generation-aware layout'
pki_load_active_issuer_snapshot; ACTIVE_MANIFEST=$(pki_active_issuer_manifest); ACTIVE_IDENTITY=$(pki_file_identity "$ACTIVE_MANIFEST")
POINTER=$(pki_active_rollover_pointer); [[ ! -e $POINTER && ! -L $POINTER ]] || pki_die 'An active rollover already exists'
shopt -s nullglob; existing_rollovers=("$PKI_DIR/state/rollovers"/*); shopt -u nullglob; (( ${#existing_rollovers[@]} == 0 )) || pki_die 'Existing rollover state must be completed or recovered before preparation'
pki_load_inventory_snapshot "$PRE_TMP"; MAX_SERVICE_DAYS=${PLATFORM_PKI_SERVICE_DAYS:-397}; pki_validate_days "$MAX_SERVICE_DAYS"
while IFS=$'\t' read -r _ field value; do if [[ $field == days ]] && (( 10#$value > 10#$MAX_SERVICE_DAYS )); then MAX_SERVICE_DAYS=$value; fi; done <"$INVENTORY_CANONICAL"
read_backup_receipt
[[ $(pki_public_state_digest generation) == "${RECEIPT[state_manifest_sha256]}" ]] || pki_die 'Current public PKI state differs from the backed-up state manifest'
[[ $(pki_private_metadata_digest) == "${RECEIPT[private_metadata_sha256]}" ]] || pki_die 'Current private metadata differs from the backed-up state'
TRUST_SOURCE=none; TRUST_SOURCE_IDENTITY=none; TRUST_SNAPSHOT_SHA256=none
if [[ $TYPE == root ]]; then
  PRIVATE_REPO=$(pki_expand_path "$PRIVATE_REPO"); [[ $PRIVATE_REPO == /* ]] || PRIVATE_REPO="$(pwd -P)/$PRIVATE_REPO"; pki_require_no_symlink_path_components "$PRIVATE_REPO" 'Private repository'; require_trusted_ancestors "$PRIVATE_REPO" 'Private repository'; PRIVATE_REPO_STATE=$(stat -c '%d:%i:%a:%u:%Y:%Z' "$PRIVATE_REPO") || pki_die 'Cannot inspect private repository'; PRIVATE_REPO=$(cd -- "$PRIVATE_REPO" && pwd -P) || pki_die 'Private repository does not exist'; [[ $(stat -c '%d:%i:%a:%u:%Y:%Z' "$PRIVATE_REPO") == "$PRIVATE_REPO_STATE" ]] || pki_die 'Private repository changed during resolution'; require_trusted_ancestors "$PRIVATE_REPO/pki" 'Trust consumer source'
  TRUST_SOURCE="$PRIVATE_REPO/pki/trust-consumers.yml"; validate_trust_consumers "$TRUST_SOURCE" unused "$PRE_TMP/trust-consumers.canonical"; TRUST_SOURCE_IDENTITY=$TRUST_VALIDATED_SOURCE_IDENTITY; TRUST_SNAPSHOT_SHA256=$(sha256sum "$TRUST_SOURCE"); [[ $(pki_file_identity "$TRUST_SOURCE") == "$TRUST_SOURCE_IDENTITY" ]] || pki_die 'Trust consumer source changed while being hashed'; TRUST_SNAPSHOT_SHA256=${TRUST_SNAPSHOT_SHA256%% *}
fi
OLD_ROOT_CERT=$(pki_root_cert "$ACTIVE_ROOT_ID"); OLD_INT_CERT=$(pki_intermediate_cert "$ACTIVE_INTERMEDIATE_ID")
OLD_ROOT_FP=$(cert_fingerprint "$OLD_ROOT_CERT"); OLD_INT_FP=$(cert_fingerprint "$OLD_INT_CERT"); OLD_ROOT_KEY_FP=$(cert_public_key_digest "$OLD_ROOT_CERT"); OLD_INT_KEY_FP=$(cert_public_key_digest "$OLD_INT_CERT")
if [[ $TYPE == intermediate ]]; then openssl x509 -in "$OLD_ROOT_CERT" -checkend "$(((10#$INTERMEDIATE_DAYS + 10#$ISSUER_SAFETY_DAYS) * 86400))" -noout >/dev/null || pki_die 'Requested intermediate validity exceeds the active root validity safety margin'
else (( 10#$ROOT_DAYS >= 10#$INTERMEDIATE_DAYS + 10#$ISSUER_SAFETY_DAYS )) || pki_die 'Requested intermediate validity exceeds the candidate root validity safety margin'; fi
(( 10#$INTERMEDIATE_DAYS >= 10#$MAX_SERVICE_DAYS + 10#$ISSUER_SAFETY_DAYS )) || pki_die 'Requested intermediate validity cannot cover the maximum inventory service lifetime and safety margin'
if [[ $TYPE == root ]]; then CANDIDATE_ROOT_ID=$(pki_next_root_generation); CANDIDATE_INTERMEDIATE_ID=$(pki_next_intermediate_generation "$CANDIDATE_ROOT_ID")
else CANDIDATE_ROOT_ID=$ACTIVE_ROOT_ID; CANDIDATE_INTERMEDIATE_ID=$(pki_next_intermediate_generation "$ACTIVE_ROOT_ID"); fi
ROOT_TOKEN=${CANDIDATE_ROOT_ID^^}; INT_TOKEN=${CANDIDATE_INTERMEDIATE_ID^^}
ROOT_NAME_UPPER=${ROOT_NAME^^}; INTERMEDIATE_NAME_UPPER=${INTERMEDIATE_NAME^^}
if [[ $TYPE == root ]]; then [[ $ROOT_NAME_UPPER =~ (^|[^A-Z0-9])$ROOT_TOKEN([^A-Z0-9]|$) && $INTERMEDIATE_NAME_UPPER =~ (^|[^A-Z0-9])$INT_TOKEN([^A-Z0-9]|$) ]] || pki_die 'Root and intermediate names must identify their new generation IDs'
else [[ $INTERMEDIATE_NAME_UPPER =~ (^|[^A-Z0-9])$INT_TOKEN([^A-Z0-9]|$) ]] || pki_die 'Intermediate name must identify its new generation ID'; fi
CANDIDATE_ROOT_DIR=$(pki_root_authority_dir "$CANDIDATE_ROOT_ID"); CANDIDATE_INT_DIR=$(pki_intermediate_authority_dir "$CANDIDATE_INTERMEDIATE_ID")
[[ ! -e $CANDIDATE_INT_DIR && ! -L $CANDIDATE_INT_DIR ]] || pki_die 'Candidate intermediate destination already exists'
[[ $TYPE != root || ! -e $CANDIDATE_ROOT_DIR && ! -L $CANDIDATE_ROOT_DIR ]] || pki_die 'Candidate root destination already exists'

TXN_ID="prepare-$TYPE-$(date -u '+%Y%m%d-%H%M%S')-$$"; JOURNAL=$(pki_recovery_journal); MARKER=$(pki_recovery_marker); TXN_DIR="$PKI_DIR/state/rollover/$TXN_ID"; LONG_DIR=$(pki_rollover_transaction_dir "$TXN_ID"); LONG_STAGE="$TXN_DIR/rollover-state"
ROOT_RESERVATION=$(pki_generation_reservation "$CANDIDATE_ROOT_ID"); INT_RESERVATION=$(pki_generation_reservation "$CANDIDATE_INTERMEDIATE_ID"); BACKUP_SESSION="$PKI_DIR/state/rollover/backup-session-${RECEIPT[session]}"
declare -A PREP=( [schema]=5 [operation]=rollover-prepare [transaction]="$TXN_ID" [type]="$TYPE" [phase]=planned [committed]=false [recovery_action]=none [recovery_step]=none [active_root]="$ACTIVE_ROOT_ID" [active_intermediate]="$ACTIVE_INTERMEDIATE_ID" [active_manifest]="$ACTIVE_MANIFEST" [active_identity]="$ACTIVE_IDENTITY" [candidate_root]="$CANDIDATE_ROOT_ID" [candidate_intermediate]="$CANDIDATE_INTERMEDIATE_ID" [candidate_root_dir]="$CANDIDATE_ROOT_DIR" [candidate_intermediate_dir]="$CANDIDATE_INT_DIR" [candidate_root_identity]=none [candidate_intermediate_identity]=none [candidate_root_key_identity]=none [candidate_root_cert_identity]=none [candidate_root_cert_sha256]=none [candidate_intermediate_key_identity]=none [candidate_intermediate_cert_identity]=none [candidate_intermediate_cert_sha256]=none [candidate_chain_identity]=none [candidate_chain_sha256]=none [transaction_dir]="$TXN_DIR" [transaction_identity]=none [stage_dir]=none [stage_identity]=none [root_stage]=none [root_stage_identity]=none [root_stage_key_identity]=none [long_stage]="$LONG_STAGE" [long_dir]="$LONG_DIR" [long_identity]=none [long_manifest_identity]=none [long_manifest_sha256]=none [trust_snapshot_identity]=none [pointer]="$POINTER" [pointer_identity]=absent [backup_receipt]="$BACKUP_RECEIPT" [receipt_identity]="$RECEIPT_IDENTITY" [backup_session]="$BACKUP_SESSION" [backup_session_identity]=absent [root_reservation]="$ROOT_RESERVATION" [root_reservation_reserved_identity]=absent [root_reservation_consumed_identity]=absent [root_reservation_abandoned_identity]=absent [intermediate_reservation]="$INT_RESERVATION" [intermediate_reservation_reserved_identity]=absent [intermediate_reservation_consumed_identity]=absent [intermediate_reservation_abandoned_identity]=absent [root_fingerprint]=none [intermediate_fingerprint]=none [root_expiry]=none [intermediate_expiry]=none [trust_bundle_sha256]=none [trust_snapshot_sha256]="$TRUST_SNAPSHOT_SHA256" [trust_source]="$TRUST_SOURCE" [trust_source_identity]="$TRUST_SOURCE_IDENTITY" [issued_serial]=none [root_mutated]=false )
PREP[terminal_outcome]=none; PREP[backup_session_original_identity]=$(pki_file_identity_or_absent "$BACKUP_SESSION")
PREP[root_stage_private_identity]=none; PREP[intermediate_stage_identity]=none; PREP[intermediate_stage_private_identity]=none
PREP[candidate_intermediate_csr_identity]=none
PREP[transaction_tree_manifest]=none; PREP[transaction_tree_manifest_identity]=none; PREP[transaction_tree_manifest_sha256]=none
PREP[transaction_tree_manifest_sequence]=0; PREP[transaction_tree_manifest_pending]=none; PREP[transaction_tree_manifest_pending_destination]=none; PREP[transaction_tree_manifest_pending_identity]=none; PREP[transaction_tree_manifest_pending_sha256]=none
PREP[candidate_root_tree_manifest]=none; PREP[candidate_root_tree_manifest_identity]=none; PREP[candidate_root_tree_manifest_sha256]=none
PREP[candidate_intermediate_tree_manifest]=none; PREP[candidate_intermediate_tree_manifest_identity]=none; PREP[candidate_intermediate_tree_manifest_sha256]=none
PREP[root_stage_tree_manifest]=none; PREP[root_stage_tree_manifest_identity]=none; PREP[root_stage_tree_manifest_sha256]=none
PREP[long_tree_manifest]=none; PREP[long_tree_manifest_identity]=none; PREP[long_tree_manifest_sha256]=none
PREP[stage_tree_manifest]=none; PREP[stage_tree_manifest_identity]=none; PREP[stage_tree_manifest_sha256]=none
ROOT_DB_KEYS=(index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert); declare -A ROOT_DB_PATH=() ROOT_DB_PRE=() ROOT_DB_POST=() ROOT_DB_BACKUP=() ROOT_DB_BACKUP_ID=()
for key in "${ROOT_DB_KEYS[@]}"; do PREP[root_${key}_pre_identity]=pending; PREP[root_${key}_post_identity]=pending; PREP[root_${key}_backup_identity]=absent; PREP[root_${key}_rollback_identity]=absent; PREP[root_${key}_source_identity]=absent; PREP[signing_${key}_pre_identity]=none; PREP[signing_${key}_partial_identity]=none; PREP[signing_${key}_was_absent]=false; done
for key in trust_snapshot root_stage_key root_stage_cert root_stage_index root_stage_index_backup root_stage_index_attr root_stage_index_attr_backup root_stage_serial root_stage_serial_backup root_stage_crlnumber root_stage_crlnumber_backup root_stage_index_old_backup root_stage_index_attr_old_backup root_stage_serial_old_backup root_stage_crlnumber_old_backup candidate_root_key candidate_root_cert candidate_intermediate_key candidate_intermediate_csr candidate_intermediate_cert candidate_chain; do PREP[${key}_pre_identity]=none; PREP[${key}_partial_identity]=none; done
TRANSACTION_STARTED=true; write_prepare_journal planned; prepare_fault after-journal

prepare_checkpoint transaction-dir-pending; mkdir -m 700 "$TXN_DIR"; pki_fsync "$(dirname -- "$TXN_DIR")"; PREP[transaction_identity]=$(pki_dir_identity "$TXN_DIR"); prepare_checkpoint transaction-dir-done
prepare_checkpoint long-stage-pending; mkdir -m 700 "$LONG_STAGE"; PREP[long_identity]=$(pki_dir_identity "$LONG_STAGE"); prepare_checkpoint long-stage-created
[[ $TYPE != root ]] || { pki_require_file_identity "$TRUST_SOURCE" "$TRUST_SOURCE_IDENTITY" 'Trust consumer source'; prepare_copy_file "$TRUST_SOURCE" "$LONG_STAGE/trust-consumers.yml" trust_snapshot 600 trust-snapshot; }
prepare_checkpoint long-stage-done
pki_atomic_write "$TXN_DIR/backup-session.publish" "session=${RECEIPT[session]}
archive_sha256=${RECEIPT[archive_sha256]}
transaction=$TXN_ID
"; PREP[backup_session_identity]=$(pki_file_object_state "$TXN_DIR/backup-session.publish")
generation=$CANDIDATE_INTERMEDIATE_ID; kind=intermediate; pki_atomic_write "$TXN_DIR/$kind-reserved" "generation=$generation
kind=$kind
status=reserved
transaction=$TXN_ID
"; pki_atomic_write "$TXN_DIR/$kind-consumed" "generation=$generation
kind=$kind
status=consumed
transaction=$TXN_ID
"; pki_atomic_write "$TXN_DIR/$kind-abandoned" "generation=$generation
kind=$kind
status=abandoned
transaction=$TXN_ID
"; PREP[${kind}_reservation_reserved_identity]=$(pki_file_object_state "$TXN_DIR/$kind-reserved"); PREP[${kind}_reservation_consumed_identity]=$(pki_file_object_state "$TXN_DIR/$kind-consumed"); PREP[${kind}_reservation_abandoned_identity]=$(pki_file_object_state "$TXN_DIR/$kind-abandoned")
if [[ $TYPE == root ]]; then generation=$CANDIDATE_ROOT_ID; kind=root; pki_atomic_write "$TXN_DIR/root-reserved" "generation=$generation
kind=root
status=reserved
transaction=$TXN_ID
"; pki_atomic_write "$TXN_DIR/root-consumed" "generation=$generation
kind=root
status=consumed
transaction=$TXN_ID
"; pki_atomic_write "$TXN_DIR/root-abandoned" "generation=$generation
kind=root
status=abandoned
transaction=$TXN_ID
"; PREP[root_reservation_reserved_identity]=$(pki_file_object_state "$TXN_DIR/root-reserved"); PREP[root_reservation_consumed_identity]=$(pki_file_object_state "$TXN_DIR/root-consumed"); PREP[root_reservation_abandoned_identity]=$(pki_file_object_state "$TXN_DIR/root-abandoned"); fi
pki_fsync_tree "$TXN_DIR"; write_prepare_journal transaction-staged; prepare_fault after-transaction
prepare_checkpoint backup-session-pending; pki_require_file_identity "$BACKUP_SESSION" absent 'Backup preparation session'; pki_publish_staged_file "$TXN_DIR/backup-session.publish" "$BACKUP_SESSION"; prepare_checkpoint backup-session-done
if [[ $TYPE == root ]]; then prepare_checkpoint reserve-root-pending; pki_publish_staged_file "$TXN_DIR/root-reserved" "$ROOT_RESERVATION"; prepare_checkpoint reserve-root-done; fi
prepare_checkpoint reserve-intermediate-pending; pki_publish_staged_file "$TXN_DIR/intermediate-reserved" "$INT_RESERVATION"; prepare_checkpoint reserve-intermediate-done; write_prepare_journal reserved; prepare_fault after-reservations

STAGE_DIR="$TXN_DIR/stage"; PREP[stage_dir]=$STAGE_DIR; prepare_checkpoint stage-dir-pending; mkdir -m 700 "$STAGE_DIR"; PREP[stage_identity]=$(pki_dir_identity "$STAGE_DIR"); prepare_checkpoint stage-dir-done
if [[ $TYPE == intermediate ]]; then
  STAGE_ROOT="$STAGE_DIR/root"; STAGE_INT="$STAGE_DIR/intermediate"; ROOT_BACKUP_DIR="$STAGE_DIR/root-backup"; PREP[root_stage]=$STAGE_ROOT; prepare_checkpoint sensitive-stage-pending
  prepare_checkpoint sensitive-root-stage-pending; mkdir -m 700 "$STAGE_ROOT"; PREP[root_stage_identity]=$(pki_dir_identity "$STAGE_ROOT"); prepare_checkpoint sensitive-root-stage-done
  prepare_checkpoint sensitive-root-private-pending; mkdir -m 700 "$STAGE_ROOT/private"; PREP[root_stage_private_identity]=$(pki_dir_identity "$STAGE_ROOT/private"); prepare_checkpoint sensitive-root-private-done
  mkdir -m 700 "$STAGE_ROOT/certs" "$STAGE_ROOT/newcerts" "$STAGE_ROOT/crl"; prepare_checkpoint sensitive-intermediate-stage-pending; mkdir -m 700 "$STAGE_INT"; PREP[intermediate_stage_identity]=$(pki_dir_identity "$STAGE_INT"); prepare_checkpoint sensitive-intermediate-stage-done
  prepare_checkpoint sensitive-intermediate-private-pending; mkdir -m 700 "$STAGE_INT/private"; PREP[intermediate_stage_private_identity]=$(pki_dir_identity "$STAGE_INT/private"); prepare_checkpoint sensitive-intermediate-private-done
  mkdir -m 700 "$STAGE_INT/certs" "$STAGE_INT/csr" "$STAGE_INT/newcerts" "$STAGE_INT/crl" "$ROOT_BACKUP_DIR"
  ROOT_CA_DIR=$(pki_root_authority_dir "$ACTIVE_ROOT_ID"); ROOT_KEY=$(pki_root_key "$ACTIVE_ROOT_ID"); ROOT_CERT=$(pki_root_cert "$ACTIVE_ROOT_ID")
  prepare_copy_file "$ROOT_KEY" "$STAGE_ROOT/private/root-ca.key" root_stage_key 600 copied-root-key
  prepare_copy_file "$ROOT_CERT" "$STAGE_ROOT/certs/root-ca.crt" root_stage_cert 644 copied-root-cert
  for spec in 'index.txt:index' 'index.txt.attr:index_attr' 'serial:serial' 'crlnumber:crlnumber'; do
    file=${spec%%:*}; key=${spec#*:}
    prepare_copy_file "$ROOT_CA_DIR/$file" "$STAGE_ROOT/$file" "root_stage_$key" 600 "copied-root-$key"
    prepare_copy_file "$ROOT_CA_DIR/$file" "$ROOT_BACKUP_DIR/$file" "root_stage_${key}_backup" 600 "backup-root-$key"
  done
  for spec in 'index.txt.old:index_old' 'index.txt.attr.old:index_attr_old' 'serial.old:serial_old' 'crlnumber.old:crlnumber_old'; do file=${spec%%:*}; key=${spec#*:}; [[ ! -e $ROOT_CA_DIR/$file ]] || prepare_copy_file "$ROOT_CA_DIR/$file" "$ROOT_BACKUP_DIR/$file" "root_stage_${key}_backup" 600 "backup-root-$key"; done
  pki_write_root_config "$STAGE_ROOT/openssl.cnf" "$COUNTRY" "$ORG" "$INTERMEDIATE_NAME" "$STAGE_ROOT"; chmod 600 "$STAGE_ROOT/openssl.cnf"; prepare_checkpoint sensitive-stage-done
else
  STAGE_ROOT="$STAGE_DIR/root"; STAGE_INT="$STAGE_DIR/intermediate"; prepare_checkpoint candidate-root-stage-pending
  prepare_checkpoint candidate-root-directory-pending; mkdir -m 700 "$STAGE_ROOT"; PREP[root_stage_identity]=$(pki_dir_identity "$STAGE_ROOT"); prepare_checkpoint candidate-root-directory-done
  prepare_checkpoint candidate-root-private-pending; mkdir -m 700 "$STAGE_ROOT/private"; PREP[root_stage_private_identity]=$(pki_dir_identity "$STAGE_ROOT/private"); prepare_checkpoint candidate-root-private-done
  mkdir -m 700 "$STAGE_ROOT/certs" "$STAGE_ROOT/newcerts" "$STAGE_ROOT/crl"; prepare_checkpoint candidate-intermediate-directory-pending; mkdir -m 700 "$STAGE_INT"; PREP[intermediate_stage_identity]=$(pki_dir_identity "$STAGE_INT"); prepare_checkpoint candidate-intermediate-directory-done
  prepare_checkpoint candidate-intermediate-private-pending; mkdir -m 700 "$STAGE_INT/private"; PREP[intermediate_stage_private_identity]=$(pki_dir_identity "$STAGE_INT/private"); prepare_checkpoint candidate-intermediate-private-done
  mkdir -m 700 "$STAGE_INT/certs" "$STAGE_INT/csr" "$STAGE_INT/newcerts" "$STAGE_INT/crl"
  pki_init_ca_db "$STAGE_ROOT"; chmod 600 "$STAGE_ROOT/index.txt" "$STAGE_ROOT/index.txt.attr" "$STAGE_ROOT/serial" "$STAGE_ROOT/crlnumber"; pki_write_root_config "$STAGE_ROOT/openssl.cnf" "$COUNTRY" "$ORG" "$ROOT_NAME" "$STAGE_ROOT"; chmod 600 "$STAGE_ROOT/openssl.cnf"; prepare_checkpoint candidate-root-stage-done
  ROOT_KEY="$STAGE_ROOT/private/root-ca.key"; ROOT_CERT="$STAGE_ROOT/certs/root-ca.crt"
  prepare_file_destination "$ROOT_KEY" candidate_root_key 600 root-key
  command=("${PLATFORM_PKI_PREPARE_OPENSSL:-openssl}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -out "$ROOT_KEY"); [[ -z $ROOT_PASS_FILE ]] || command+=(-pass "file:$ROOT_PASS_FILE")
  set +e; "${command[@]}"; status=$?; set -e; (( status == 0 )) || prepare_child_failed root-key candidate_root_key "$ROOT_KEY"
  chmod 600 "$ROOT_KEY"; pki_fsync "$ROOT_KEY"; PREP[candidate_root_key_identity]=$(pki_file_identity "$ROOT_KEY"); prepare_checkpoint root-key-done
  prepare_file_destination "$ROOT_CERT" candidate_root_cert 644 root-certificate
  command=("${PLATFORM_PKI_PREPARE_OPENSSL:-openssl}" req -config "$STAGE_ROOT/openssl.cnf" -key "$ROOT_KEY" -new -x509 -days "$ROOT_DAYS" -sha384 -extensions v3_root_ca -out "$ROOT_CERT"); [[ -z $ROOT_PASS_FILE ]] || command+=(-passin "file:$ROOT_PASS_FILE")
  set +e; "${command[@]}"; status=$?; set -e; (( status == 0 )) || prepare_child_failed root-certificate candidate_root_cert "$ROOT_CERT"
  chmod 644 "$ROOT_CERT"; pki_fsync "$ROOT_CERT"; PREP[candidate_root_cert_identity]=$(pki_file_identity "$ROOT_CERT"); prepare_checkpoint root-certificate-done
fi
prepare_checkpoint intermediate-stage-config-pending; pki_init_ca_db "$STAGE_INT"; chmod 600 "$STAGE_INT/index.txt" "$STAGE_INT/index.txt.attr" "$STAGE_INT/serial" "$STAGE_INT/crlnumber"; pki_write_intermediate_config "$STAGE_INT/openssl.cnf" "$COUNTRY" "$ORG" "$INTERMEDIATE_NAME" "$CANDIDATE_INT_DIR"; chmod 600 "$STAGE_INT/openssl.cnf"; prepare_checkpoint intermediate-stage-config-done
INT_KEY="$STAGE_INT/private/intermediate-ca.key"; INT_CSR="$STAGE_INT/csr/intermediate-ca.csr"; INT_CERT="$STAGE_INT/certs/intermediate-ca.crt"
prepare_file_destination "$INT_KEY" candidate_intermediate_key 600 intermediate-key
command=("${PLATFORM_PKI_PREPARE_OPENSSL:-openssl}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -out "$INT_KEY"); [[ -z $INTERMEDIATE_PASS_FILE ]] || command+=(-pass "file:$INTERMEDIATE_PASS_FILE")
set +e; "${command[@]}"; status=$?; set -e; (( status == 0 )) || prepare_child_failed intermediate-key candidate_intermediate_key "$INT_KEY"
chmod 600 "$INT_KEY"; pki_fsync "$INT_KEY"; PREP[candidate_intermediate_key_identity]=$(pki_file_identity "$INT_KEY"); prepare_checkpoint intermediate-key-done
prepare_file_destination "$INT_CSR" candidate_intermediate_csr 600 intermediate-csr
command=("${PLATFORM_PKI_PREPARE_OPENSSL:-openssl}" req -config "$STAGE_INT/openssl.cnf" -key "$INT_KEY" -new -sha384 -out "$INT_CSR"); [[ -z $INTERMEDIATE_PASS_FILE ]] || command+=(-passin "file:$INTERMEDIATE_PASS_FILE")
set +e; "${command[@]}"; status=$?; set -e; (( status == 0 )) || prepare_child_failed intermediate-csr candidate_intermediate_csr "$INT_CSR"
chmod 600 "$INT_CSR"; pki_fsync "$INT_CSR"; PREP[candidate_intermediate_csr_identity]=$(pki_file_identity "$INT_CSR"); prepare_checkpoint intermediate-csr-done
ISSUED_SERIAL=$(<"$STAGE_ROOT/serial"); ISSUED_SERIAL=${ISSUED_SERIAL^^}; while [[ $ISSUED_SERIAL == 00* && ${#ISSUED_SERIAL} -gt 2 ]]; do ISSUED_SERIAL=${ISSUED_SERIAL#00}; done; PREP[issued_serial]=$ISSUED_SERIAL
prepare_file_destination "$INT_CERT" candidate_intermediate_cert 644 intermediate-signing
for spec in "index:$STAGE_ROOT/index.txt" "index_attr:$STAGE_ROOT/index.txt.attr" "serial:$STAGE_ROOT/serial" "crlnumber:$STAGE_ROOT/crlnumber" "index_old:$STAGE_ROOT/index.txt.old" "index_attr_old:$STAGE_ROOT/index.txt.attr.old" "serial_old:$STAGE_ROOT/serial.old" "crlnumber_old:$STAGE_ROOT/crlnumber.old" "newcert:$STAGE_ROOT/newcerts/$ISSUED_SERIAL.pem"; do key=${spec%%:*}; path=${spec#*:}; if [[ ! -e $path && ! -L $path ]]; then PREP[signing_${key}_was_absent]=true; : >"$path"; chmod 600 "$path"; fi; PREP[signing_${key}_pre_identity]=$(pki_file_identity "$path"); done
prepare_checkpoint intermediate-signing-db-ready
command=("${PLATFORM_PKI_PREPARE_OPENSSL:-openssl}" ca -batch -config "$STAGE_ROOT/openssl.cnf" -extensions v3_intermediate_ca -days "$INTERMEDIATE_DAYS" -notext -md sha384 -in "$INT_CSR" -out "$INT_CERT"); [[ -z $ROOT_PASS_FILE ]] || command+=(-passin "file:$ROOT_PASS_FILE")
set +e; "${command[@]}"; status=$?; set -e
if (( status != 0 )); then for spec in "candidate_intermediate_cert:$INT_CERT" "signing_index:$STAGE_ROOT/index.txt" "signing_index_attr:$STAGE_ROOT/index.txt.attr" "signing_serial:$STAGE_ROOT/serial" "signing_crlnumber:$STAGE_ROOT/crlnumber" "signing_index_old:$STAGE_ROOT/index.txt.old" "signing_index_attr_old:$STAGE_ROOT/index.txt.attr.old" "signing_serial_old:$STAGE_ROOT/serial.old" "signing_crlnumber_old:$STAGE_ROOT/crlnumber.old" "signing_newcert:$STAGE_ROOT/newcerts/$ISSUED_SERIAL.pem"; do key=${spec%%:*}; path=${spec#*:}; PREP[${key}_partial_identity]=$(pki_file_identity "$path"); done; prepare_checkpoint intermediate-signing-child-failed; pki_die 'Sensitive child operation failed during intermediate-signing'; fi
for spec in "index_old:$STAGE_ROOT/index.txt.old" "index_attr_old:$STAGE_ROOT/index.txt.attr.old" "serial_old:$STAGE_ROOT/serial.old" "crlnumber_old:$STAGE_ROOT/crlnumber.old" "newcert:$STAGE_ROOT/newcerts/$ISSUED_SERIAL.pem"; do key=${spec%%:*}; path=${spec#*:}; if [[ ${PREP[signing_${key}_was_absent]} == true && $(pki_file_identity "$path") == "${PREP[signing_${key}_pre_identity]}" ]]; then pki_remove_identity_file "$path" "${PREP[signing_${key}_pre_identity]}" || pki_die "Cannot remove unused signing output placeholder: $path"; fi; done
chmod 644 "$INT_CERT"; pki_fsync_tree "$STAGE_ROOT"; pki_fsync "$INT_CERT"; PREP[candidate_intermediate_cert_identity]=$(pki_file_identity "$INT_CERT"); prepare_checkpoint intermediate-signing-done
CHAIN="$STAGE_INT/certs/ca-chain.crt"; prepare_file_destination "$CHAIN" candidate_chain 644 chain
set +e; cat "$INT_CERT" "$ROOT_CERT" >"$CHAIN"; status=$?; set -e; (( status == 0 )) || prepare_child_failed chain candidate_chain "$CHAIN"
chmod 644 "$CHAIN"; pki_fsync "$CHAIN"; PREP[candidate_chain_identity]=$(pki_file_identity "$CHAIN"); prepare_checkpoint chain-done
if [[ $TYPE == root ]]; then prepare_checkpoint candidate-root-config-pending; pki_write_root_config "$STAGE_ROOT/openssl.cnf" "$COUNTRY" "$ORG" "$ROOT_NAME" "$CANDIDATE_ROOT_DIR"; chmod 600 "$STAGE_ROOT/openssl.cnf"; prepare_checkpoint candidate-root-config-done; fi
require_key_match "$ROOT_KEY" "$ROOT_CERT" "$ROOT_PASS_FILE" "$STAGE_DIR"; require_key_match "$INT_KEY" "$INT_CERT" "$INTERMEDIATE_PASS_FILE" "$STAGE_DIR"; require_ca_certificate "$ROOT_CERT"; require_ca_certificate "$INT_CERT"
pki_require_ca_certificate_profile "$ROOT_CERT" 1 'Candidate root certificate'; pki_require_ca_certificate_profile "$INT_CERT" 0 'Candidate intermediate certificate'
pki_require_ca_self_signature "$ROOT_CERT" 'Candidate root'; openssl verify -CAfile "$ROOT_CERT" "$INT_CERT" >/dev/null || pki_die 'Candidate intermediate chain is invalid'; pki_validate_child_validity "$INT_CERT" "$ROOT_CERT" "$ISSUER_SAFETY_DAYS"
openssl x509 -in "$INT_CERT" -checkend "$(((10#$MAX_SERVICE_DAYS + 10#$ISSUER_SAFETY_DAYS) * 86400))" -noout >/dev/null || pki_die 'Candidate intermediate validity cannot cover the maximum inventory service lifetime and safety margin'
ROOT_FP=$(cert_fingerprint "$ROOT_CERT"); INT_FP=$(cert_fingerprint "$INT_CERT"); ROOT_KEY_FP=$(cert_public_key_digest "$ROOT_CERT"); INT_KEY_FP=$(cert_public_key_digest "$INT_CERT")
[[ $ROOT_FP != "$OLD_ROOT_FP" || $TYPE == intermediate ]] || pki_die 'Candidate root certificate fingerprint matches the active root'; [[ $INT_FP != "$OLD_INT_FP" ]] || pki_die 'Candidate intermediate certificate fingerprint matches the active intermediate'; [[ $ROOT_KEY_FP != "$OLD_ROOT_KEY_FP" || $TYPE == intermediate ]] || pki_die 'Candidate root public key matches the active root'; [[ $INT_KEY_FP != "$OLD_INT_KEY_FP" ]] || pki_die 'Candidate intermediate public key matches the active intermediate'
[[ $(openssl x509 -in "$INT_CERT" -noout -subject -nameopt RFC2253) != "$(openssl x509 -in "$OLD_INT_CERT" -noout -subject -nameopt RFC2253)" ]] || pki_die 'Candidate intermediate subject matches the active intermediate'
if [[ $TYPE == root ]]; then [[ $(openssl x509 -in "$ROOT_CERT" -noout -subject -nameopt RFC2253) != "$(openssl x509 -in "$OLD_ROOT_CERT" -noout -subject -nameopt RFC2253)" ]] || pki_die 'Candidate root subject matches the active root'; cat "$OLD_ROOT_CERT" "$ROOT_CERT" >"$PRE_TMP/trust-bundle.pem"; TRUST_BUNDLE_SHA256=$(sha256sum "$PRE_TMP/trust-bundle.pem"); TRUST_BUNDLE_SHA256=${TRUST_BUNDLE_SHA256%% *}; else TRUST_BUNDLE_SHA256=none; fi
PREP[root_fingerprint]=$ROOT_FP; PREP[intermediate_fingerprint]=$INT_FP; PREP[root_expiry]=$(cert_expiry "$ROOT_CERT"); PREP[intermediate_expiry]=$(cert_expiry "$INT_CERT"); PREP[trust_bundle_sha256]=$TRUST_BUNDLE_SHA256
if [[ $TYPE == intermediate ]]; then
  ROOT_DB_PATH[index]="$ROOT_CA_DIR/index.txt"; ROOT_DB_PATH[index_attr]="$ROOT_CA_DIR/index.txt.attr"; ROOT_DB_PATH[serial]="$ROOT_CA_DIR/serial"; ROOT_DB_PATH[crlnumber]="$ROOT_CA_DIR/crlnumber"; ROOT_DB_PATH[index_old]="$ROOT_CA_DIR/index.txt.old"; ROOT_DB_PATH[index_attr_old]="$ROOT_CA_DIR/index.txt.attr.old"; ROOT_DB_PATH[serial_old]="$ROOT_CA_DIR/serial.old"; ROOT_DB_PATH[crlnumber_old]="$ROOT_CA_DIR/crlnumber.old"; ROOT_DB_PATH[newcert]="$ROOT_CA_DIR/newcerts/$ISSUED_SERIAL.pem"
  ROOT_DB_BACKUP[index]="$ROOT_BACKUP_DIR/index.txt"; ROOT_DB_BACKUP[index_attr]="$ROOT_BACKUP_DIR/index.txt.attr"; ROOT_DB_BACKUP[serial]="$ROOT_BACKUP_DIR/serial"; ROOT_DB_BACKUP[crlnumber]="$ROOT_BACKUP_DIR/crlnumber"; ROOT_DB_BACKUP[index_old]="$ROOT_BACKUP_DIR/index.txt.old"; ROOT_DB_BACKUP[index_attr_old]="$ROOT_BACKUP_DIR/index.txt.attr.old"; ROOT_DB_BACKUP[serial_old]="$ROOT_BACKUP_DIR/serial.old"; ROOT_DB_BACKUP[crlnumber_old]="$ROOT_BACKUP_DIR/crlnumber.old"; ROOT_DB_BACKUP[newcert]=none
  for key in "${ROOT_DB_KEYS[@]}"; do ROOT_DB_PRE[$key]=$(pki_file_identity_or_absent_full "${ROOT_DB_PATH[$key]}"); [[ ${ROOT_DB_PRE[$key]} == absent || $key == newcert ]] || ROOT_DB_BACKUP_ID[$key]=$(pki_file_identity "${ROOT_DB_BACKUP[$key]}"); file=${ROOT_DB_PATH[$key]#"$ROOT_CA_DIR/"}; if [[ $key == newcert ]]; then ROOT_DB_POST[$key]=$(pki_file_identity "$STAGE_ROOT/newcerts/$ISSUED_SERIAL.pem"); elif [[ -e $STAGE_ROOT/$file ]]; then ROOT_DB_POST[$key]=$(pki_file_identity "$STAGE_ROOT/$file"); else ROOT_DB_POST[$key]=${ROOT_DB_PRE[$key]}; fi; PREP[root_${key}_pre_identity]=${ROOT_DB_PRE[$key]}; PREP[root_${key}_post_identity]=${ROOT_DB_POST[$key]}; PREP[root_${key}_backup_identity]=${ROOT_DB_BACKUP_ID[$key]:-absent}; PREP[root_${key}_rollback_identity]=${ROOT_DB_BACKUP_ID[$key]:-absent}; PREP[root_${key}_source_identity]=$(pki_file_identity_or_absent_full "$STAGE_ROOT/$file"); done
  [[ ${ROOT_DB_PRE[newcert]} == absent ]] || pki_die 'Root issued-certificate destination already exists'; PREP[root_mutated]=true
fi
prepare_checkpoint evidence-stage-pending
if [[ $TYPE == root ]]; then
  PREP[candidate_root_tree_manifest]="$LONG_STAGE/candidate-root-tree.manifest"; pki_tree_manifest "$STAGE_ROOT" >"${PREP[candidate_root_tree_manifest]}"
  chmod 600 "${PREP[candidate_root_tree_manifest]}"; PREP[candidate_root_tree_manifest_identity]=$(pki_file_identity "${PREP[candidate_root_tree_manifest]}"); value=$(sha256sum "${PREP[candidate_root_tree_manifest]}"); PREP[candidate_root_tree_manifest_sha256]=${value%% *}
else
  PREP[root_stage_tree_manifest]="$LONG_STAGE/root-signing-stage-tree.manifest"; pki_tree_manifest "$STAGE_ROOT" >"${PREP[root_stage_tree_manifest]}"
  chmod 600 "${PREP[root_stage_tree_manifest]}"; PREP[root_stage_tree_manifest_identity]=$(pki_file_identity "${PREP[root_stage_tree_manifest]}"); value=$(sha256sum "${PREP[root_stage_tree_manifest]}"); PREP[root_stage_tree_manifest_sha256]=${value%% *}
fi
PREP[candidate_intermediate_tree_manifest]="$LONG_STAGE/candidate-intermediate-tree.manifest"; pki_tree_manifest "$STAGE_INT" >"${PREP[candidate_intermediate_tree_manifest]}"
chmod 600 "${PREP[candidate_intermediate_tree_manifest]}"; PREP[candidate_intermediate_tree_manifest_identity]=$(pki_file_identity "${PREP[candidate_intermediate_tree_manifest]}"); value=$(sha256sum "${PREP[candidate_intermediate_tree_manifest]}"); PREP[candidate_intermediate_tree_manifest_sha256]=${value%% *}
PREP[stage_tree_manifest]="$TXN_DIR/stage-tree.manifest"; pki_tree_manifest "$STAGE_DIR" >"${PREP[stage_tree_manifest]}"
chmod 600 "${PREP[stage_tree_manifest]}"; PREP[stage_tree_manifest_identity]=$(pki_file_identity "${PREP[stage_tree_manifest]}"); value=$(sha256sum "${PREP[stage_tree_manifest]}"); PREP[stage_tree_manifest_sha256]=${value%% *}
cat >"$LONG_STAGE/manifest" <<EOF
schema=1
transaction=$TXN_ID
type=$TYPE
phase=prepared
created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
old_root=$ACTIVE_ROOT_ID
old_intermediate=$ACTIVE_INTERMEDIATE_ID
candidate_root=$CANDIDATE_ROOT_ID
candidate_intermediate=$CANDIDATE_INTERMEDIATE_ID
old_root_fingerprint=$OLD_ROOT_FP
old_intermediate_fingerprint=$OLD_INT_FP
candidate_root_fingerprint=$ROOT_FP
candidate_intermediate_fingerprint=$INT_FP
candidate_root_expiry=${PREP[root_expiry]}
candidate_intermediate_expiry=${PREP[intermediate_expiry]}
trust_bundle_sha256=$TRUST_BUNDLE_SHA256
trust_snapshot_sha256=$TRUST_SNAPSHOT_SHA256
candidate_root_tree_sha256=${PREP[candidate_root_tree_manifest_sha256]}
candidate_intermediate_tree_sha256=${PREP[candidate_intermediate_tree_manifest_sha256]}
backup_state_sha256=${RECEIPT[state_manifest_sha256]}
EOF
chmod 600 "$LONG_STAGE/manifest"; PREP[long_manifest_identity]=$(pki_file_identity "$LONG_STAGE/manifest"); value=$(sha256sum "$LONG_STAGE/manifest"); PREP[long_manifest_sha256]=${value%% *}; if [[ $TYPE == root ]]; then PREP[trust_snapshot_identity]=$(pki_file_identity "$LONG_STAGE/trust-consumers.yml"); fi
PREP[long_tree_manifest]="$LONG_STAGE/tree.manifest"; pki_tree_manifest "$LONG_STAGE" tree.manifest >"${PREP[long_tree_manifest]}"; chmod 600 "${PREP[long_tree_manifest]}"; PREP[long_tree_manifest_identity]=$(pki_file_identity "${PREP[long_tree_manifest]}"); value=$(sha256sum "${PREP[long_tree_manifest]}"); PREP[long_tree_manifest_sha256]=${value%% *}
pki_atomic_write "$TXN_DIR/active-rollover.publish" "transaction=$TXN_ID
tree_manifest_sha256=${PREP[long_tree_manifest_sha256]}
"; PREP[pointer_identity]=$(pki_file_object_state "$TXN_DIR/active-rollover.publish"); pki_fsync_tree "$TXN_DIR"; prepare_checkpoint evidence-stage-done
if [[ $TYPE == root ]]; then PREP[candidate_root_identity]=$(pki_dir_identity "$STAGE_ROOT"); PREP[candidate_root_key_identity]=$(pki_file_identity "$ROOT_KEY"); PREP[candidate_root_cert_identity]=$(pki_file_identity "$ROOT_CERT")
else PREP[candidate_root_identity]=$(pki_dir_identity "$ROOT_CA_DIR"); PREP[candidate_root_key_identity]=$(pki_file_identity "$(pki_root_key "$ACTIVE_ROOT_ID")"); PREP[candidate_root_cert_identity]=$(pki_file_identity "$(pki_root_cert "$ACTIVE_ROOT_ID")"); fi
value=$(sha256sum "$ROOT_CERT"); PREP[candidate_root_cert_sha256]=${value%% *}; PREP[candidate_intermediate_identity]=$(pki_dir_identity "$STAGE_INT"); PREP[candidate_intermediate_key_identity]=$(pki_file_identity "$INT_KEY"); PREP[candidate_intermediate_cert_identity]=$(pki_file_identity "$INT_CERT"); value=$(sha256sum "$INT_CERT"); PREP[candidate_intermediate_cert_sha256]=${value%% *}; PREP[candidate_chain_identity]=$(pki_file_identity "$STAGE_INT/certs/ca-chain.crt"); value=$(sha256sum "$STAGE_INT/certs/ca-chain.crt"); PREP[candidate_chain_sha256]=${value%% *}; PREP[long_identity]=$(pki_dir_identity "$LONG_STAGE"); write_prepare_journal staged; prepare_fault after-staged

if [[ $TYPE == root ]]; then pki_validate_tree_manifest "$STAGE_ROOT" "${PREP[candidate_root_tree_manifest]}" "${PREP[candidate_root_tree_manifest_identity]}" "${PREP[candidate_root_tree_manifest_sha256]}"; prepare_checkpoint publish-root-pending; mv --no-copy --update=none-fail -T -- "$STAGE_ROOT" "$CANDIDATE_ROOT_DIR"; pki_fsync_rename_parents "$STAGE_DIR" "$(dirname -- "$CANDIDATE_ROOT_DIR")"; prepare_checkpoint publish-root-done; prepare_fault after-root-candidate; fi
pki_validate_tree_manifest "$STAGE_INT" "${PREP[candidate_intermediate_tree_manifest]}" "${PREP[candidate_intermediate_tree_manifest_identity]}" "${PREP[candidate_intermediate_tree_manifest_sha256]}"
prepare_checkpoint publish-intermediate-pending; mv --no-copy --update=none-fail -T -- "$STAGE_INT" "$CANDIDATE_INT_DIR"; pki_fsync_rename_parents "$STAGE_DIR" "$(dirname -- "$CANDIDATE_INT_DIR")"; prepare_checkpoint publish-intermediate-done; prepare_fault after-intermediate-candidate
if [[ $TYPE == intermediate ]]; then
  pki_validate_tree_manifest "$STAGE_ROOT" "${PREP[root_stage_tree_manifest]}" "${PREP[root_stage_tree_manifest_identity]}" "${PREP[root_stage_tree_manifest_sha256]}"
  for key in "${ROOT_DB_KEYS[@]}"; do file=${ROOT_DB_PATH[$key]#"$ROOT_CA_DIR/"}; [[ $key != newcert ]] || file="newcerts/$ISSUED_SERIAL.pem"; [[ ! -e $STAGE_ROOT/$file ]] || { prepare_checkpoint "publish-root-db-$key-pending"; pki_require_file_identity "$STAGE_ROOT/$file" "${PREP[root_${key}_source_identity]}" "Staged root $key publication source"; pki_publish_staged_file_exact "$STAGE_ROOT/$file" "${ROOT_DB_PATH[$key]}"; PREP[root_${key}_post_identity]=$PKI_PUBLISHED_FILE_IDENTITY; prepare_checkpoint "publish-root-db-$key-done"; }; done
  pki_fsync "$ROOT_CA_DIR"; pki_fsync "$ROOT_CA_DIR/newcerts"; prepare_fault after-root-db
fi
if [[ $TYPE == root ]]; then prepare_checkpoint consume-root-pending; pki_publish_staged_file "$TXN_DIR/root-consumed" "$ROOT_RESERVATION"; prepare_checkpoint consume-root-done; fi
prepare_checkpoint consume-intermediate-pending; pki_publish_staged_file "$TXN_DIR/intermediate-consumed" "$INT_RESERVATION"; prepare_checkpoint consume-intermediate-done; prepare_fault after-consumed
if [[ $TYPE == intermediate ]]; then prepare_checkpoint cleanup-root-stage-pending; pki_remove_manifested_tree "$STAGE_ROOT" "${PREP[root_stage_identity]}" "$STAGE_DIR" "${PREP[root_stage_tree_manifest]}" "${PREP[root_stage_tree_manifest_identity]}" "${PREP[root_stage_tree_manifest_sha256]}" || pki_die 'Cannot remove sensitive root signing stage'; prepare_fault cleanup-root-stage-removed; prepare_checkpoint cleanup-root-stage-done; fi
pki_validate_tree_manifest "$LONG_STAGE" "${PREP[long_tree_manifest]}" "${PREP[long_tree_manifest_identity]}" "${PREP[long_tree_manifest_sha256]}" tree.manifest
prepare_checkpoint publish-state-pending; mv --no-copy --update=none-fail -T -- "$LONG_STAGE" "$LONG_DIR"; pki_fsync_rename_parents "$TXN_DIR" "$(dirname -- "$LONG_DIR")"; prepare_checkpoint publish-state-done; prepare_fault after-state
prepare_checkpoint publish-pointer-pending; pki_publish_staged_file "$TXN_DIR/active-rollover.publish" "$POINTER"; prepare_checkpoint publish-pointer-done; prepare_fault after-pointer
finish_prepare_transaction
pki_ok "Prepared $TYPE rollover transaction $TXN_ID with candidate $CANDIDATE_ROOT_ID/$CANDIDATE_INTERMEDIATE_ID"
