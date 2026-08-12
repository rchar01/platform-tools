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

SERVICE=${args[service]}
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
MIN_DAYS=${args[--min-days]:-30}

pki_validate_service_name "$SERVICE"
pki_validate_days "$MIN_DAYS"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")

pki_require_cmd openssl
pki_require_pki_dir
pki_prepare_control_state
pki_require_inventory
ROOT_LOCK=$(pki_root_operation_lock)
INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock)
INVENTORY_LOCK=$(pki_inventory_operation_lock)
SNAPSHOT_DIR=''
finish_verify() {
  local status=$?
  trap - EXIT
  [[ -z $SNAPSHOT_DIR ]] || rm -rf -- "$SNAPSHOT_DIR"
  [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}
trap finish_verify EXIT
umask 077
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_require_generation_layout
SNAPSHOT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-service-verify.XXXXXX") || pki_die 'Cannot create inventory snapshot directory'
pki_load_active_issuer_snapshot
pki_load_inventory_snapshot "$SNAPSHOT_DIR"
pki_verify_service_certificate "$SERVICE" "$MIN_DAYS"

pki_ok "Verified service certificate: $SERVICE"
