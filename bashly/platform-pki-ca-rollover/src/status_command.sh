SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh; fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"
pki_reject_repeated_options --namespace --pki-dir --format

cert_fingerprint() { local value; value=$(openssl x509 -in "$1" -noout -fingerprint -sha256); value=${value#*=}; printf '%s\n' "${value//:/}"; }
cert_expiry() { date -u -d "$(openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//')" '+%Y-%m-%dT%H:%M:%SZ'; }
json_services() { local service first=true; printf '['; for service in "$@"; do [[ $first == true ]] || printf ','; printf '"%s"' "$service"; first=false; done; printf ']'; }

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}; PKI_DIR=${args[--pki-dir]:-}; FORMAT=${args[--format]}
NAMESPACE=$(pki_expand_path "$NAMESPACE"); PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}; PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_require_cmd openssl; pki_require_pki_dir; pki_prepare_control_state
ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); INVENTORY_LOCK=$(pki_inventory_operation_lock); EXPORT_LOCK=$(pki_export_operation_lock)
# shellcheck disable=SC2329  # Invoked by the EXIT trap.
finish_status() { local status=$?; trap - EXIT; [[ ${EXPORT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$EXPORT_LOCK" 2>/dev/null || status=2; [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=2; [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=2; [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=2; exit "$status"; }
trap finish_status EXIT
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_acquire_operation_lock "$EXPORT_LOCK" 'export operation'; EXPORT_LOCK_HELD=true
JOURNAL=$(pki_recovery_journal); MARKER=$(pki_recovery_marker); declare -A PKI_RECORD=()
MARKER_TRANSACTION=unknown; MARKER_OPERATION=unknown; MARKER_OUTCOME=none
if [[ -e $MARKER || -L $MARKER ]]; then
  [[ -f $MARKER && ! -L $MARKER && $(stat -c '%u:%a:%h' "$MARKER") == "$(id -u):600:1" ]] || pki_die "PKI recovery marker is unsafe: $MARKER"
  pki_read_state_record "$MARKER" 'PKI recovery marker'
  MARKER_TRANSACTION=${PKI_RECORD[transaction]:-unknown}; MARKER_OPERATION=${PKI_RECORD[operation]:-unknown}; MARKER_OUTCOME=${PKI_RECORD[terminal_outcome]:-none}
  if [[ $MARKER_OUTCOME != none ]]; then
    [[ ${#PKI_RECORD[@]} -eq 3 && $MARKER_OPERATION == rollover-prepare && $MARKER_OUTCOME =~ ^(resumed|rolled-back)$ ]] || pki_die 'PKI recovery marker has invalid terminal preparation state'
  fi
  unset -v PKI_RECORD; declare -A PKI_RECORD=()
fi
if [[ -e $JOURNAL || -L $JOURNAL ]]; then pki_read_state_record "$JOURNAL" 'PKI recovery journal'; fi
if [[ -e $MARKER || ( -e $JOURNAL || -L $JOURNAL ) && ( ${PKI_RECORD[operation]:-} == rollover-prepare || ${PKI_RECORD[committed]:-true} != true ) ]]; then
  RECOVERY_TRANSACTION=${PKI_RECORD[transaction]:-$MARKER_TRANSACTION}; RECOVERY_OPERATION=${PKI_RECORD[operation]:-$MARKER_OPERATION}; RECOVERY_PHASE=${PKI_RECORD[phase]:-terminal-cleanup}; TERMINAL_OUTCOME=${PKI_RECORD[terminal_outcome]:-$MARKER_OUTCOME}; REQUIRED_ACTION=rollback
  [[ $RECOVERY_TRANSACTION =~ ^[a-z0-9-]+$ ]] || RECOVERY_TRANSACTION=unknown; [[ $RECOVERY_OPERATION =~ ^[a-z0-9-]+$ ]] || RECOVERY_OPERATION=unknown; [[ $RECOVERY_PHASE =~ ^[a-z0-9-]+$ ]] || RECOVERY_PHASE=unknown
  if [[ $RECOVERY_OPERATION == rollover-prepare ]]; then
    [[ $TERMINAL_OUTCOME == none || $TERMINAL_OUTCOME =~ ^(resumed|rolled-back)$ ]] || pki_die 'Preparation recovery state has an invalid terminal outcome'
    if [[ $TERMINAL_OUTCOME == resumed ]]; then REQUIRED_ACTION=resume
    elif [[ $TERMINAL_OUTCOME == rolled-back ]]; then REQUIRED_ACTION=rollback
    elif [[ ${PKI_RECORD[recovery_action]:-none} =~ ^(resume|rollback)$ ]]; then REQUIRED_ACTION=${PKI_RECORD[recovery_action]}
    elif [[ ${PKI_RECORD[candidate_intermediate_identity]:-none} != none ]]; then REQUIRED_ACTION=resume
    fi
  fi
  if [[ $FORMAT == json ]]; then printf '{"schema":2,"status":"recovery-required","recovery_required":true,"transaction":"%s","operation":"%s","phase":"%s","terminal_outcome":"%s","required_action":"%s"}\n' "$RECOVERY_TRANSACTION" "$RECOVERY_OPERATION" "$RECOVERY_PHASE" "$TERMINAL_OUTCOME" "$REQUIRED_ACTION"
  else printf 'status=recovery-required\nrecovery_required=true\ntransaction=%s\noperation=%s\nphase=%s\nterminal_outcome=%s\nrequired_action=%s\naction=run platform-pki-ca-rollover recover --transaction %s --action %s\n' "$RECOVERY_TRANSACTION" "$RECOVERY_OPERATION" "$RECOVERY_PHASE" "$TERMINAL_OUTCOME" "$REQUIRED_ACTION" "$RECOVERY_TRANSACTION" "$REQUIRED_ACTION"; fi
  exit 2
fi
LAYOUT=$(pki_detect_layout)
if [[ $LAYOUT == legacy ]]; then if [[ $FORMAT == json ]]; then printf '{"schema":1,"status":"legacy","recovery_required":false,"required_action":"backup-and-migrate"}\n'; else printf 'status=legacy\nrecovery_required=false\naction=run platform-pki-backup, then platform-pki-ca-rollover migrate\n'; fi; exit 1; fi
[[ $LAYOUT == generation ]] || { if [[ $FORMAT == json ]]; then printf '{"schema":1,"status":"%s","recovery_required":false,"required_action":"repair-layout"}\n' "$LAYOUT"; else printf 'status=%s\nrecovery_required=false\naction=repair incomplete or ambiguous PKI layout before continuing\n' "$LAYOUT"; fi; exit 2; }
pki_load_active_issuer_snapshot
ACTIVE_ROOT_FP=$(cert_fingerprint "$(pki_root_cert "$ACTIVE_ROOT_ID")"); ACTIVE_INT_FP=$(cert_fingerprint "$(pki_intermediate_cert "$ACTIVE_INTERMEDIATE_ID")"); ACTIVE_ROOT_EXPIRY=$(cert_expiry "$(pki_root_cert "$ACTIVE_ROOT_ID")"); ACTIVE_INT_EXPIRY=$(cert_expiry "$(pki_intermediate_cert "$ACTIVE_INTERMEDIATE_ID")")
STATUS_ACTIVE_ROOT=$ACTIVE_ROOT_ID; STATUS_ACTIVE_INT=$ACTIVE_INTERMEDIATE_ID
shopt -s nullglob
for service_dir in "$PKI_DIR/services"/*; do
  [[ -d $service_dir && ! -L $service_dir ]] || pki_die "Service state directory is unsafe: $service_dir"
  service=$(basename -- "$service_dir"); pki_validate_service_name "$service"; issuer="$service_dir/issuer"
  [[ -f $issuer && ! -L $issuer ]] || pki_die "Service $service issuer manifest is missing or unsafe"
  pki_read_pair_manifest "$issuer" "Service $service issuer"
done
shopt -u nullglob
ACTIVE_ROOT_ID=$STATUS_ACTIVE_ROOT; ACTIVE_INTERMEDIATE_ID=$STATUS_ACTIVE_INT
POINTER=$(pki_active_rollover_pointer)
if [[ ! -e $POINTER && ! -L $POINTER ]]; then
  shopt -s nullglob
  for service_dir in "$PKI_DIR/services"/*; do service=$(basename -- "$service_dir"); pki_read_pair_manifest "$service_dir/issuer" "Service $service issuer"; [[ $ACTIVE_ROOT_ID == "$STATUS_ACTIVE_ROOT" && $ACTIVE_INTERMEDIATE_ID == "$STATUS_ACTIVE_INT" ]] || pki_die "Service $service issuer does not select the active issuer"; done
  shopt -u nullglob
  if [[ $FORMAT == json ]]; then printf '{"schema":1,"status":"ready","recovery_required":false,"phase":"idle","active":{"root":{"generation":"%s","fingerprint_sha256":"%s","expires_at":"%s"},"intermediate":{"generation":"%s","fingerprint_sha256":"%s","expires_at":"%s"}},"candidate":null,"retired":[],"trust_snapshot_sha256":null,"services_on_old_issuer":[],"required_action":null}\n' "$ACTIVE_ROOT_ID" "$ACTIVE_ROOT_FP" "$ACTIVE_ROOT_EXPIRY" "$ACTIVE_INTERMEDIATE_ID" "$ACTIVE_INT_FP" "$ACTIVE_INT_EXPIRY"
  else printf 'status=ready\nrecovery_required=false\nphase=idle\nactive_root=%s\nactive_root_fingerprint_sha256=%s\nactive_root_expires_at=%s\nactive_intermediate=%s\nactive_intermediate_fingerprint_sha256=%s\nactive_intermediate_expires_at=%s\ncandidate_root=none\ncandidate_intermediate=none\nretired=none\ntrust_snapshot_sha256=none\nservices_on_old_issuer=none\naction=none\n' "$ACTIVE_ROOT_ID" "$ACTIVE_ROOT_FP" "$ACTIVE_ROOT_EXPIRY" "$ACTIVE_INTERMEDIATE_ID" "$ACTIVE_INT_FP" "$ACTIVE_INT_EXPIRY"; fi
  exit 0
fi
pki_read_state_record "$POINTER" 'Active rollover pointer'; [[ ${#PKI_RECORD[@]} -eq 2 && ${PKI_RECORD[transaction]:-} =~ ^prepare-(root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+$ && ${PKI_RECORD[tree_manifest_sha256]:-} =~ ^[0-9a-f]{64}$ ]] || pki_die 'Active rollover pointer is invalid'; TRANSACTION=${PKI_RECORD[transaction]}; ROLLOVER_TREE_SHA256=${PKI_RECORD[tree_manifest_sha256]}; ROLLOVER_DIR=$(pki_rollover_transaction_dir "$TRANSACTION"); MANIFEST="$ROLLOVER_DIR/manifest"
[[ -d $ROLLOVER_DIR && ! -L $ROLLOVER_DIR ]] || pki_die 'Rollover transaction state directory is unsafe'; pki_require_no_symlink_path_components "$ROLLOVER_DIR" 'Rollover transaction state'
pki_validate_tree_manifest "$ROLLOVER_DIR" "$ROLLOVER_DIR/tree.manifest" "$(pki_file_identity "$ROLLOVER_DIR/tree.manifest")" "$ROLLOVER_TREE_SHA256" tree.manifest
pki_read_state_record "$MANIFEST" 'Rollover manifest'
for field in schema transaction type phase created_at old_root old_intermediate candidate_root candidate_intermediate old_root_fingerprint old_intermediate_fingerprint candidate_root_fingerprint candidate_intermediate_fingerprint candidate_root_expiry candidate_intermediate_expiry trust_bundle_sha256 trust_snapshot_sha256 candidate_root_tree_sha256 candidate_intermediate_tree_sha256 backup_state_sha256; do [[ -v PKI_RECORD[$field] ]] || pki_die "Rollover manifest is missing field: $field"; done
[[ ${#PKI_RECORD[@]} -eq 20 && ${PKI_RECORD[schema]} == 1 && ${PKI_RECORD[transaction]} == "$TRANSACTION" && ${PKI_RECORD[type]} =~ ^(root|intermediate)$ && ${PKI_RECORD[phase]} == prepared ]] || pki_die 'Rollover transaction manifest is invalid'
OLD_ROOT=${PKI_RECORD[old_root]}; OLD_INT=${PKI_RECORD[old_intermediate]}; CANDIDATE_ROOT=${PKI_RECORD[candidate_root]}; CANDIDATE_INT=${PKI_RECORD[candidate_intermediate]}
for value in "$OLD_ROOT" "$CANDIDATE_ROOT"; do pki_validate_root_generation "$value"; done; for value in "$OLD_INT" "$CANDIDATE_INT"; do pki_validate_intermediate_generation "$value"; done
[[ $OLD_ROOT == "$ACTIVE_ROOT_ID" && $OLD_INT == "$ACTIVE_INTERMEDIATE_ID" && $OLD_INT == "$OLD_ROOT"-i* && $CANDIDATE_INT == "$CANDIDATE_ROOT"-i* ]] || pki_die 'Prepared rollover generation relationships are invalid'
[[ ${PKI_RECORD[created_at]} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ && ${PKI_RECORD[old_root_fingerprint]} =~ ^[0-9A-F]{64}$ && ${PKI_RECORD[old_intermediate_fingerprint]} =~ ^[0-9A-F]{64}$ && ${PKI_RECORD[candidate_root_fingerprint]} =~ ^[0-9A-F]{64}$ && ${PKI_RECORD[candidate_intermediate_fingerprint]} =~ ^[0-9A-F]{64}$ && ${PKI_RECORD[backup_state_sha256]} =~ ^[0-9a-f]{64}$ ]] || pki_die 'Rollover manifest public metadata is invalid'
if [[ ${PKI_RECORD[type]} == root ]]; then [[ $CANDIDATE_ROOT != "$OLD_ROOT" && ${PKI_RECORD[trust_bundle_sha256]} =~ ^[0-9a-f]{64}$ && ${PKI_RECORD[trust_snapshot_sha256]} =~ ^[0-9a-f]{64}$ && ${PKI_RECORD[candidate_root_tree_sha256]} =~ ^[0-9a-f]{64}$ ]] || pki_die 'Root rollover trust metadata is invalid'; else [[ $CANDIDATE_ROOT == "$OLD_ROOT" && ${PKI_RECORD[trust_bundle_sha256]} == none && ${PKI_RECORD[trust_snapshot_sha256]} == none && ${PKI_RECORD[candidate_root_tree_sha256]} == none ]] || pki_die 'Intermediate rollover trust metadata is invalid'; fi
[[ ${PKI_RECORD[candidate_intermediate_tree_sha256]} =~ ^[0-9a-f]{64}$ ]] || pki_die 'Candidate intermediate tree metadata is invalid'
CANDIDATE_ROOT_CERT=$(pki_root_cert "$CANDIDATE_ROOT"); CANDIDATE_INT_CERT=$(pki_intermediate_cert "$CANDIDATE_INT"); pki_require_file "$CANDIDATE_ROOT_CERT"; pki_require_file "$CANDIDATE_INT_CERT"
if [[ ${PKI_RECORD[type]} == root ]]; then pki_validate_tree_manifest "$(pki_root_authority_dir "$CANDIDATE_ROOT")" "$ROLLOVER_DIR/candidate-root-tree.manifest" "$(pki_file_identity "$ROLLOVER_DIR/candidate-root-tree.manifest")" "${PKI_RECORD[candidate_root_tree_sha256]}"; fi
pki_validate_tree_manifest "$(pki_intermediate_authority_dir "$CANDIDATE_INT")" "$ROLLOVER_DIR/candidate-intermediate-tree.manifest" "$(pki_file_identity "$ROLLOVER_DIR/candidate-intermediate-tree.manifest")" "${PKI_RECORD[candidate_intermediate_tree_sha256]}"
[[ $ACTIVE_ROOT_FP == "${PKI_RECORD[old_root_fingerprint]}" && $ACTIVE_INT_FP == "${PKI_RECORD[old_intermediate_fingerprint]}" && $(cert_fingerprint "$CANDIDATE_ROOT_CERT") == "${PKI_RECORD[candidate_root_fingerprint]}" && $(cert_fingerprint "$CANDIDATE_INT_CERT") == "${PKI_RECORD[candidate_intermediate_fingerprint]}" && $(cert_expiry "$CANDIDATE_ROOT_CERT") == "${PKI_RECORD[candidate_root_expiry]}" && $(cert_expiry "$CANDIDATE_INT_CERT") == "${PKI_RECORD[candidate_intermediate_expiry]}" ]] || pki_die 'Prepared candidate public metadata changed'
services=(); shopt -s nullglob; for service_dir in "$PKI_DIR/services"/*; do service=$(basename -- "$service_dir"); issuer="$service_dir/issuer"; pki_read_pair_manifest "$issuer" "Service $service issuer"; if [[ $ACTIVE_ROOT_ID == "$OLD_ROOT" && $ACTIVE_INTERMEDIATE_ID == "$OLD_INT" ]]; then services+=("$service"); elif [[ $ACTIVE_ROOT_ID != "$CANDIDATE_ROOT" || $ACTIVE_INTERMEDIATE_ID != "$CANDIDATE_INT" ]]; then pki_die "Service $service issuer selects an unknown rollover pair"; fi; done; shopt -u nullglob
if [[ $FORMAT == json ]]; then
  SERVICES_JSON=$(json_services "${services[@]}"); printf '{"schema":1,"status":"prepared","recovery_required":false,"transaction":"%s","type":"%s","phase":"prepared","active":{"root":{"generation":"%s","fingerprint_sha256":"%s","expires_at":"%s"},"intermediate":{"generation":"%s","fingerprint_sha256":"%s","expires_at":"%s"}},"candidate":{"root":{"generation":"%s","fingerprint_sha256":"%s","expires_at":"%s"},"intermediate":{"generation":"%s","fingerprint_sha256":"%s","expires_at":"%s"}},"retired":[],"trust_bundle_sha256":"%s","trust_snapshot_sha256":"%s","services_on_old_issuer":%s,"required_action":"immutable-export-evidence"}\n' "$TRANSACTION" "${PKI_RECORD[type]}" "$OLD_ROOT" "${PKI_RECORD[old_root_fingerprint]}" "$ACTIVE_ROOT_EXPIRY" "$OLD_INT" "${PKI_RECORD[old_intermediate_fingerprint]}" "$ACTIVE_INT_EXPIRY" "$CANDIDATE_ROOT" "${PKI_RECORD[candidate_root_fingerprint]}" "${PKI_RECORD[candidate_root_expiry]}" "$CANDIDATE_INT" "${PKI_RECORD[candidate_intermediate_fingerprint]}" "${PKI_RECORD[candidate_intermediate_expiry]}" "${PKI_RECORD[trust_bundle_sha256]}" "${PKI_RECORD[trust_snapshot_sha256]}" "$SERVICES_JSON"
else
  services_text=none; (( ${#services[@]} == 0 )) || services_text=$(IFS=,; printf '%s' "${services[*]}")
  printf 'status=prepared\nrecovery_required=false\ntransaction=%s\ntype=%s\nphase=prepared\nactive_root=%s\nactive_root_fingerprint_sha256=%s\nactive_root_expires_at=%s\nactive_intermediate=%s\nactive_intermediate_fingerprint_sha256=%s\nactive_intermediate_expires_at=%s\ncandidate_root=%s\ncandidate_root_fingerprint_sha256=%s\ncandidate_root_expires_at=%s\ncandidate_intermediate=%s\ncandidate_intermediate_fingerprint_sha256=%s\ncandidate_intermediate_expires_at=%s\nretired=none\ntrust_bundle_sha256=%s\ntrust_snapshot_sha256=%s\nservices_on_old_issuer=%s\naction=immutable export/evidence milestone required before activation\n' "$TRANSACTION" "${PKI_RECORD[type]}" "$OLD_ROOT" "${PKI_RECORD[old_root_fingerprint]}" "$ACTIVE_ROOT_EXPIRY" "$OLD_INT" "${PKI_RECORD[old_intermediate_fingerprint]}" "$ACTIVE_INT_EXPIRY" "$CANDIDATE_ROOT" "${PKI_RECORD[candidate_root_fingerprint]}" "${PKI_RECORD[candidate_root_expiry]}" "$CANDIDATE_INT" "${PKI_RECORD[candidate_intermediate_fingerprint]}" "${PKI_RECORD[candidate_intermediate_expiry]}" "${PKI_RECORD[trust_bundle_sha256]}" "${PKI_RECORD[trust_snapshot_sha256]}" "$services_text"
fi
exit 1
