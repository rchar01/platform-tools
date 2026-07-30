SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh; fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}; PKI_DIR=${args[--pki-dir]:-}
NAMESPACE=$(pki_expand_path "$NAMESPACE"); PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}; PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_require_pki_dir; pki_prepare_control_state
ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock)
INVENTORY_LOCK=$(pki_inventory_operation_lock); EXPORT_LOCK=$(pki_export_operation_lock)
finish_status() {
  local status=$?
  trap - EXIT
  [[ ${EXPORT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$EXPORT_LOCK" 2>/dev/null || status=2
  [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=2
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=2
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=2
  exit "$status"
}
trap finish_status EXIT
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_acquire_operation_lock "$EXPORT_LOCK" 'export operation'; EXPORT_LOCK_HELD=true
JOURNAL=$(pki_recovery_journal); MARKER=$(pki_recovery_marker); declare -A PKI_RECORD=()
if [[ -e $MARKER || -L $MARKER ]]; then
  [[ -f $MARKER && ! -L $MARKER && $(stat -c '%u:%a:%h' "$MARKER") == "$(id -u):600:1" ]] || pki_die "PKI recovery marker is unsafe: $MARKER"
fi
if [[ -e $JOURNAL || -L $JOURNAL ]]; then
  pki_read_state_record "$JOURNAL" 'PKI recovery journal'
fi
if [[ -e $MARKER || ${PKI_RECORD[committed]:-true} != true ]]; then
  printf 'status=recovery-required\ntransaction=%s\naction=run platform-pki-ca-rollover recover\n' "${PKI_RECORD[transaction]:-unknown}"
  exit 2
fi
LAYOUT=$(pki_detect_layout)
case $LAYOUT in
  legacy)
    printf 'status=legacy\naction=run platform-pki-backup, then platform-pki-ca-rollover migrate\n'
    exit 1
    ;;
  generation)
    pki_load_active_issuer_snapshot
    printf 'status=ready\nactive_root=%s\nactive_intermediate=%s\n' "$ACTIVE_ROOT_ID" "$ACTIVE_INTERMEDIATE_ID"
    ;;
  *)
    printf 'status=%s\naction=repair incomplete or ambiguous PKI layout before continuing\n' "$LAYOUT"
    exit 2
    ;;
esac
