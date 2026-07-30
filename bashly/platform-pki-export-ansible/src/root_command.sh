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

require_trusted_path_components() {
  local path=$1 label=$2 current component mode owner current_uid
  local -a components

  current_uid=$(id -u)
  case $path in
    /*) current='' ;;
    *) current='.' ;;
  esac
  IFS='/' read -r -a components <<<"$path"
  for component in "${components[@]}"; do
    [[ -n $component && $component != . ]] || continue
    if [[ $current == / || -z $current ]]; then
      current="/${component}"
    else
      current="${current}/${component}"
    fi
    [[ ! -L $current ]] || pki_die "$label path component must not be a symlink: $current"
    [[ ! -e $current || -d $current ]] || pki_die "$label path component is not a directory: $current"
    if [[ -d $current ]]; then
      mode=$(stat -c '%a' "$current") || pki_die "Cannot inspect $label path component permissions: $current"
      [[ $mode =~ ^[0-7]+$ ]] || pki_die "Cannot parse $label path component permissions: $current"
      if (( (8#$mode & 022) != 0 && (8#$mode & 01000) == 0 )); then
        pki_die "$label path component is group- or world-writable without sticky bit: $current"
      fi
      owner=$(stat -c '%u' "$current") || pki_die "Cannot inspect $label path component owner: $current"
      [[ $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label path component owner: $current"
      if [[ $owner != "$current_uid" && $owner != 0 ]]; then
        pki_die "$label path component is not owned by current user or root: $current"
      fi
    fi
  done
}

require_private_dir() {
  local path=$1 label=$2 mode owner current_uid

  [[ -d $path ]] || pki_die "$label directory is missing: $path"
  [[ ! -L $path ]] || pki_die "$label directory must not be a symlink: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label directory permissions: $path"
  [[ $mode =~ ^[0-7]+$ ]] || pki_die "Cannot parse $label directory permissions: $path"
  if (( (8#$mode & 022) != 0 )); then
    pki_die "$label directory is group- or world-writable: $path"
  fi
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label directory owner: $path"
  current_uid=$(id -u)
  [[ $owner == "$current_uid" ]] || pki_die "$label directory is not owned by the current user: $path"
}

prepare_fresh_dir() {
  local path=$1
  [[ ! -e $path && ! -L $path ]] || pki_die "Export path unexpectedly exists: $path"
  mkdir -m 700 "$path"
}

copy_file() {
  local source=$1 target=$2 mode=$3 target_dir target_name tmp

  pki_require_file "$source"
  target_dir=$(dirname -- "$target")
  target_name=$(basename -- "$target")
  [[ -d $target_dir && ! -L $target_dir ]] || pki_die "Export target directory is unsafe: $target_dir"
  [[ ! -e $target && ! -L $target ]] || pki_die "Export target already exists: $target"
  if ! (
    tmp=$(mktemp "${target_dir}/.${target_name}.tmp.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    cp "$source" "$tmp" &&
      chmod "$mode" "$tmp" &&
      ln -T -- "$tmp" "$target"
  ); then
    pki_die "Failed to publish export file without overwriting: $target"
  fi
}

write_export_marker() {
  local target=$1 tmp

  if ! (
    tmp=$(mktemp "${EXPORT_DIR}/.marker.tmp.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    printf '%s\n' 'platform-pki-export-ansible' >"$tmp" &&
      chmod 600 "$tmp" &&
      ln -T -- "$tmp" "$target"
  ); then
    pki_die "Failed to publish export marker without overwriting: $target"
  fi
}

service_is_generated() {
  local service=$1
  [[ -f $(pki_service_key "$service") && -f $(pki_service_cert "$service") && \
    -f $(pki_service_chain "$service") && -f $(pki_service_fullchain "$service") && \
    -f $(pki_service_issuer "$service") ]]
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
EXPORT_DIR=${args[--export-dir]:-}
EXPORT_DIR_PROVIDED=false
if [[ -v args[--export-dir] ]]; then
  EXPORT_DIR_PROVIDED=true
fi
FORCE=false
if [[ -v args[--force] ]]; then
  FORCE=true
fi
SERVICES=()
# Bashly shell-quotes each repeatable value before joining the aggregate.
# shellcheck disable=SC2294
eval "SERVICES=(${args[services]:-})"

for service in "${SERVICES[@]}"; do
  pki_validate_service_name "$service"
done
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
case $PKI_DIR in
  /*) ;;
  *) PKI_DIR="$(pwd -P)/$PKI_DIR" ;;
esac
EXPORT_DIR=${EXPORT_DIR:-${PKI_DIR}/export/ansible}
EXPORT_DIR=$(pki_expand_path "$EXPORT_DIR")
if [[ $EXPORT_DIR_PROVIDED == true ]]; then
  case $EXPORT_DIR in
    /*) ;;
    *) pki_die '--export-dir must be an absolute path' ;;
  esac
fi
EXPORT_PARENT=$(dirname -- "$EXPORT_DIR")
umask 077

pki_require_pki_dir
pki_require_inventory
ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); INVENTORY_LOCK=$(pki_inventory_operation_lock); EXPORT_LOCK=$(pki_export_operation_lock)
SNAPSHOT_DIR=''
finish_export() {
  local status=$?
  trap - EXIT
  [[ -z $SNAPSHOT_DIR ]] || rm -rf -- "$SNAPSHOT_DIR"
  [[ ${EXPORT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$EXPORT_LOCK" 2>/dev/null || status=1
  [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}
trap finish_export EXIT
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_acquire_operation_lock "$EXPORT_LOCK" 'export operation'; EXPORT_LOCK_HELD=true
SNAPSHOT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-export-ansible.XXXXXX") || pki_die 'Cannot create inventory snapshot directory'
pki_load_active_issuer_snapshot
pki_load_inventory_snapshot "$SNAPSHOT_DIR"
pki_require_file "$(pki_root_cert)"
require_trusted_path_components "$EXPORT_PARENT" 'Export parent'
require_private_dir "$EXPORT_PARENT" 'Export parent'
PKI_REAL=$(cd -- "$PKI_DIR" && pwd -P)
EXPORT_PARENT_REAL=$(cd -- "$EXPORT_PARENT" && pwd -P)
EXPORT_REAL="${EXPORT_PARENT_REAL}/$(basename -- "$EXPORT_DIR")"
DEFAULT_EXPORT_REAL="${PKI_REAL}/export/ansible"

if [[ $PKI_REAL == "$EXPORT_REAL" || $PKI_REAL == "$EXPORT_REAL"/* ]]; then
  pki_die "Export directory must not equal or contain the PKI directory: $EXPORT_DIR"
fi
case ${EXPORT_REAL}/ in
  "${PKI_REAL}"/*)
    [[ $EXPORT_REAL != "${PKI_REAL}/export" ]] || \
      pki_die "Export directory must be below the PKI export directory: $EXPORT_DIR"
    case ${EXPORT_REAL}/ in
      "${PKI_REAL}/export/"*) ;;
      *) pki_die "Export directory inside the PKI tree must be under its export directory: $EXPORT_DIR" ;;
    esac
    ;;
esac

[[ ! -L $EXPORT_DIR ]] || pki_die "Export directory must not be a symlink: $EXPORT_DIR"

if [[ ${#SERVICES[@]} -eq 0 ]]; then
  while IFS= read -r service || [[ -n $service ]]; do
    [[ -n $service ]] || continue
    if service_is_generated "$service"; then
      SERVICES+=("$service")
    else
      pki_warn "Skipping service without generated certificate files: $service"
    fi
  done < <(pki_inventory_services)
else
  for service in "${SERVICES[@]}"; do
    pki_require_service_in_inventory "$service"
    service_is_generated "$service" || pki_die "Generated certificate files are incomplete for service: $service"
  done
fi

[[ ${#SERVICES[@]} -gt 0 ]] || pki_die 'No generated service certificates found to export'

if [[ -e $EXPORT_DIR && $FORCE != true ]]; then
  pki_die "Export directory exists; use --force to replace it: $EXPORT_DIR"
fi
if [[ -e $EXPORT_DIR ]]; then
  require_trusted_path_components "$EXPORT_DIR" 'Export'
  require_private_dir "$EXPORT_DIR" 'Export'
  if [[ $EXPORT_REAL != "$DEFAULT_EXPORT_REAL" ]]; then
    marker="$EXPORT_DIR/.platform-pki-ansible-export"
    [[ -f $marker && ! -L $marker && $(<"$marker") == 'platform-pki-export-ansible' ]] || \
      pki_die "Refusing to replace unmarked custom export directory: $EXPORT_DIR"
  fi
  rm -rf "$EXPORT_DIR"
fi
prepare_fresh_dir "$EXPORT_DIR"
write_export_marker "$EXPORT_DIR/.platform-pki-ansible-export"
prepare_fresh_dir "$EXPORT_DIR/ca"
prepare_fresh_dir "$EXPORT_DIR/services"

copy_file "$(pki_root_cert)" "$EXPORT_DIR/ca/root-ca.crt" 644
for service in "${SERVICES[@]}"; do
  pki_load_service_issuer_snapshot "$service"
  pki_require_file "$(pki_root_cert "$SERVICE_ROOT_ID")"
  pki_require_file "$(pki_intermediate_cert "$SERVICE_INTERMEDIATE_ID")"
  target_dir="$EXPORT_DIR/services/$service"
  prepare_fresh_dir "$target_dir"
  copy_file "$(pki_service_cert "$service")" "$target_dir/tls.crt" 644
  copy_file "$(pki_service_key "$service")" "$target_dir/tls.key" 600
  copy_file "$(pki_service_chain "$service")" "$target_dir/ca-chain.crt" 644
  copy_file "$(pki_service_fullchain "$service")" "$target_dir/fullchain.crt" 644
  pki_ok "Exported service: $service"
done

pki_warn "Export contains service private keys: $EXPORT_DIR"
pki_ok "Ansible export ready: $EXPORT_DIR"
