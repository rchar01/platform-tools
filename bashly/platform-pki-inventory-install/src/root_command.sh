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

require_trusted_ancestors() {
  local path=$1 label=$2 current='' component mode owner uid
  local -a components
  uid=$(id -u)
  IFS='/' read -r -a components <<<"$path"
  [[ $path != /* ]] || current=/
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    if [[ $current == / ]]; then current="/$component"; elif [[ -n $current ]]; then current="$current/$component"; else current=$component; fi
    [[ -d $current && ! -L $current ]] || pki_die "$label ancestor must be a non-symlink directory: $current"
    mode=$(stat -c '%a' "$current") || pki_die "Cannot inspect $label ancestor permissions: $current"
    owner=$(stat -c '%u' "$current") || pki_die "Cannot inspect $label ancestor owner: $current"
    [[ $owner == "$uid" || $owner == 0 ]] || pki_die "$label ancestor is not owned by current user or root: $current"
    (( (8#$mode & 022) == 0 || (8#$mode & 01000) != 0 )) || pki_die "$label ancestor is group- or world-writable without sticky bit: $current"
  done
}

require_source() {
  local mode owner links uid
  [[ -f $SOURCE && ! -L $SOURCE && -r $SOURCE ]] || pki_die "Inventory source must be a readable non-symlink regular file: $SOURCE"
  SOURCE_STATE=$(stat -c '%d|%i|%h|%s|%a|%u|%y|%z' "$SOURCE") || pki_die 'Cannot snapshot inventory source identity'
  IFS='|' read -r _ _ links _ mode owner _ _ <<<"$SOURCE_STATE"
  uid=$(id -u)
  [[ $owner == "$uid" ]] || pki_die "Inventory source is not owned by the current user: $SOURCE"
  [[ $links == 1 ]] || pki_die "Inventory source must not be hard-linked: $SOURCE"
  (( (8#$mode & 022) == 0 )) || pki_die "Inventory source is group- or world-writable: $SOURCE"
  [[ -f $SOURCE && ! -L $SOURCE && $(stat -c '%d|%i|%h|%s|%a|%u|%y|%z' "$SOURCE") == "$SOURCE_STATE" ]] || \
    pki_die 'Inventory source changed during validation'
}

require_private_directory() {
  local path=$1 label=$2 mode owner uid
  [[ -d $path && ! -L $path ]] || pki_die "$label must be a non-symlink directory: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label permissions: $path"
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label owner: $path"
  uid=$(id -u)
  [[ $owner == "$uid" ]] || pki_die "$label is not owned by the current user: $path"
  (( (8#$mode & 022) == 0 )) || pki_die "$label is group- or world-writable: $path"
}

snapshot_directory() {
  stat -c '%d:%i:%a:%u' "$1" || pki_die "Cannot snapshot directory identity: $1"
}

recheck_directory() {
  local path=$1 expected=$2 label=$3
  [[ -d $path && ! -L $path ]] || pki_die "$label changed after validation"
  [[ $(stat -c '%d:%i:%a:%u' "$path") == "$expected" ]] || pki_die "$label identity or metadata changed after validation"
}

recheck_install_directories() {
  recheck_directory "$PKI_DIR" "$PKI_STATE" 'PKI directory'
  recheck_directory "$PKI_DIR/root-ca" "$ROOT_DIR_STATE" 'Root CA directory'
  recheck_directory "$PKI_DIR/intermediate-ca" "$INTERMEDIATE_DIR_STATE" 'Intermediate CA directory'
  recheck_directory "$PKI_DIR/inventory" "$INVENTORY_DIR_STATE" 'Inventory directory'
}

recheck_source_directories() {
  recheck_directory "$PRIVATE_REPO_REAL" "$PRIVATE_REPO_DIR_STATE" 'Private repository'
  recheck_directory "$(dirname -- "$SOURCE")" "$SOURCE_DIR_STATE" 'Inventory source directory'
}

snapshot_destination() {
  local mode owner links uid
  if [[ -e $DESTINATION || -L $DESTINATION ]]; then
    [[ -f $DESTINATION && ! -L $DESTINATION ]] || pki_die "Inventory destination must be a non-symlink regular file: $DESTINATION"
    mode=$(stat -c '%a' "$DESTINATION") || pki_die "Cannot inspect inventory destination permissions: $DESTINATION"
    owner=$(stat -c '%u' "$DESTINATION") || pki_die "Cannot inspect inventory destination owner: $DESTINATION"
    links=$(stat -c '%h' "$DESTINATION") || pki_die "Cannot inspect inventory destination link count: $DESTINATION"
    uid=$(id -u)
    [[ $owner == "$uid" ]] || pki_die "Inventory destination is not owned by the current user: $DESTINATION"
    [[ $links == 1 ]] || pki_die "Inventory destination must not be hard-linked: $DESTINATION"
    (( (8#$mode & 022) == 0 )) || pki_die "Inventory destination is group- or world-writable: $DESTINATION"
    DESTINATION_STATE="present:$(stat -c '%d:%i' "$DESTINATION")"
    DESTINATION_MODE=$mode
  else
    DESTINATION_STATE=absent
    DESTINATION_MODE=''
  fi
}

recheck_destination() {
  local current
  if [[ -e $DESTINATION || -L $DESTINATION ]]; then
    [[ $DESTINATION_STATE == present:* && -f $DESTINATION && ! -L $DESTINATION ]] || pki_die 'Inventory destination changed after validation'
    current=$(stat -c '%d:%i' "$DESTINATION") || pki_die 'Cannot recheck inventory destination identity'
    [[ $current == "${DESTINATION_STATE#present:}" ]] || pki_die 'Inventory destination identity changed after validation'
  else
    [[ $DESTINATION_STATE == absent ]] || pki_die 'Inventory destination disappeared after validation'
  fi
}

remove_owned_path() {
  local path=$1 expected=$2
  [[ -z $path ]] && return 0
  # The owner-only parent and operation locks exclude cooperating commands.
  # A malicious process with the same UID is outside the PKI trust boundary.
  [[ -f $path && ! -L $path ]] || return 1
  [[ $(stat -c '%d:%i' "$path") == "$expected" ]] || return 1
  rm -f -- "$path" || return 1
  [[ ! -e $path && ! -L $path ]]
}

preserve_publication() {
  PRESERVE_PUBLICATION_STATE=true
  pki_die "$1; recovery artifacts: ${STAGE:-none} ${PUBLICATION_GUARD:-none} ${PUBLICATION_GUARD_BASE:-none}"
}

finish_install() {
  local status=$? recovery_dir
  trap - EXIT
  if [[ ${PRESERVE_PUBLICATION_STATE:-false} != true ]]; then
    if [[ -n ${STAGE:-} ]] && ! remove_owned_path "$STAGE" "${STAGE_IDENTITY:-}"; then
      PRESERVE_PUBLICATION_STATE=true
      status=1
    fi
    if [[ -n ${PUBLICATION_GUARD:-} ]] && ! remove_owned_path "$PUBLICATION_GUARD" "${PUBLICATION_GUARD_IDENTITY:-}"; then
      PRESERVE_PUBLICATION_STATE=true
      status=1
    fi
    if [[ -n ${PUBLICATION_GUARD_BASE:-} ]] && ! remove_owned_path "$PUBLICATION_GUARD_BASE" "${PUBLICATION_GUARD_BASE_IDENTITY:-}"; then
      PRESERVE_PUBLICATION_STATE=true
      status=1
    fi
  fi
  [[ -z ${CANONICAL:-} ]] || rm -f -- "$CANONICAL"
  if [[ ${PRESERVE_PUBLICATION_STATE:-false} == true ]]; then
    recovery_dir=$(cd -- "$PINNED_INVENTORY_DIR" 2>/dev/null && pwd -P) || recovery_dir=$PKI_DIR/inventory
    pki_warn "Inventory publication requires recovery; retained locks: $ROOT_LOCK $INTERMEDIATE_LOCK ${recovery_dir}/.platform-pki-inventory-operation.lock"
  else
    [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=1
    [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
    [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  fi
  [[ -z ${INVENTORY_DIR_FD:-} ]] || exec {INVENTORY_DIR_FD}<&-
  exit "$status"
}

require_exchange_mv() {
  local help
  help=$(mv --help 2>/dev/null) || pki_die 'GNU mv is required'
  for option in --exchange --no-copy none-fail; do
    grep -F -- "$option" <<<"$help" >/dev/null || \
      pki_die 'GNU mv with --exchange, --no-copy, and --update=none-fail is required'
  done
}

open_inventory_directory() {
  exec {INVENTORY_DIR_FD}<"$PKI_DIR/inventory" || pki_die 'Cannot open inventory directory'
  PINNED_INVENTORY_DIR="/proc/self/fd/$INVENTORY_DIR_FD"
  [[ -d $PINNED_INVENTORY_DIR ]] || pki_die 'Opened inventory descriptor is not a directory'
  [[ $(stat -Lc '%d:%i:%a:%u' "$PINNED_INVENTORY_DIR") == "$INVENTORY_DIR_STATE" ]] || \
    pki_die 'Opened inventory directory identity differs from validated directory'
  recheck_directory "$PKI_DIR/inventory" "$INVENTORY_DIR_STATE" 'Inventory directory'
}

publish_absent_destination() {
  local staged_identity
  staged_identity=$(stat -c '%d:%i' "$STAGE") || pki_die 'Cannot inspect staged inventory identity'
  mv --no-copy --update=none-fail -T -- "$STAGE" "$DESTINATION" || \
    pki_die 'Inventory destination appeared before publication'
  [[ -f $DESTINATION && ! -L $DESTINATION && $(stat -c '%d:%i' "$DESTINATION") == "$staged_identity" ]] || \
    pki_die 'Published inventory identity is invalid'
  STAGE=''
}

publish_existing_destination() {
  local expected=${DESTINATION_STATE#present:} staged_identity old_identity rollback_destination_identity
  staged_identity=$(stat -c '%d:%i' "$STAGE") || pki_die 'Cannot inspect staged inventory identity'
  PUBLICATION_GUARD_BASE=$(mktemp "$PINNED_INVENTORY_DIR/.platform-pki-inventory-guard.XXXXXX") || \
    pki_die 'Cannot create inventory publication guard'
  PUBLICATION_GUARD_BASE_IDENTITY=$(stat -c '%d:%i' "$PUBLICATION_GUARD_BASE") || \
    pki_die 'Cannot inspect inventory publication guard base'
  PUBLICATION_GUARD="$PUBLICATION_GUARD_BASE.link"
  ln -T -- "$DESTINATION" "$PUBLICATION_GUARD" || pki_die 'Inventory destination changed before publication guard'
  PUBLICATION_GUARD_IDENTITY=$(stat -c '%d:%i' "$PUBLICATION_GUARD") || \
    pki_die 'Cannot inspect inventory publication guard'
  [[ $(stat -c '%d:%i' "$PUBLICATION_GUARD") == "$expected" && \
    $(stat -c '%d:%i' "$DESTINATION") == "$expected" ]] || \
    pki_die 'Inventory destination identity changed before publication'

  mv --exchange --no-copy -T -- "$STAGE" "$DESTINATION" || pki_die 'Cannot exchange staged and active inventory'
  old_identity=$(stat -c '%d:%i' "$STAGE") || preserve_publication 'Cannot inspect exchanged inventory identity'
  STAGE_IDENTITY=$old_identity
  if [[ $old_identity != "$expected" || $(stat -c '%d:%i' "$PUBLICATION_GUARD") != "$expected" || \
    $(stat -c '%d:%i' "$DESTINATION") != "$staged_identity" ]]; then
    if [[ -f $STAGE && ! -L $STAGE && -f $DESTINATION && ! -L $DESTINATION && \
      $(stat -c '%d:%i' "$DESTINATION") == "$staged_identity" ]]; then
      rollback_destination_identity=$old_identity
      mv --exchange --no-copy -T -- "$STAGE" "$DESTINATION" || \
        preserve_publication 'Cannot restore raced inventory publication'
      [[ $(stat -c '%d:%i' "$STAGE") == "$staged_identity" && \
        $(stat -c '%d:%i' "$DESTINATION") == "$rollback_destination_identity" ]] || \
        preserve_publication 'Restored inventory publication has unexpected identities'
      STAGE_IDENTITY=$staged_identity
    else
      preserve_publication 'Inventory changed during publication'
    fi
    pki_die 'Inventory destination changed during publication'
  fi

  remove_owned_path "$PUBLICATION_GUARD" "$PUBLICATION_GUARD_IDENTITY" || \
    preserve_publication 'Cannot remove identity-matched inventory publication guard'
  PUBLICATION_GUARD=''
  remove_owned_path "$PUBLICATION_GUARD_BASE" "$PUBLICATION_GUARD_BASE_IDENTITY" || \
    preserve_publication 'Cannot remove identity-matched inventory publication guard base'
  PUBLICATION_GUARD_BASE=''
  remove_owned_path "$STAGE" "$STAGE_IDENTITY" || \
    preserve_publication 'Cannot remove identity-matched previous inventory'
  STAGE=''
}

reject_repeated_options() {
  local option count argument
  for option in --private-repo --namespace --pki-dir; do
    count=0
    for argument in "${command_line_args[@]}"; do
      [[ $argument == "$option" || $argument == "$option="* ]] && count=$((count + 1))
    done
    (( count <= 1 )) || pki_die "Option must not be repeated: $option"
  done
}

reject_repeated_options
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
PRIVATE_REPO=${args[--private-repo]}
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
PHYSICAL_CWD=$(pwd -P) || pki_die 'Cannot resolve physical current directory'
PRIVATE_REPO=$(pki_expand_path "$PRIVATE_REPO")
[[ $PRIVATE_REPO == /* ]] || PRIVATE_REPO="$PHYSICAL_CWD/$PRIVATE_REPO"
pki_require_no_symlink_path_components "$PRIVATE_REPO" 'Private repository'
require_trusted_ancestors "$PRIVATE_REPO" 'Private repository'
PRIVATE_REPO_STATE=$(stat -c '%d:%i:%a:%u:%Y:%Z' "$PRIVATE_REPO") || pki_die "Cannot inspect private repository: $PRIVATE_REPO"
PRIVATE_REPO_REAL=$(cd -- "$PRIVATE_REPO" && pwd -P) || pki_die "Private repository does not exist: $PRIVATE_REPO"
[[ $(stat -c '%d:%i:%a:%u:%Y:%Z' "$PRIVATE_REPO") == "$PRIVATE_REPO_STATE" ]] || pki_die 'Private repository changed during resolution'
SOURCE="$PRIVATE_REPO_REAL/pki/services.yml"
require_trusted_ancestors "$(dirname -- "$SOURCE")" 'Inventory source'
require_source
pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
pki_require_pki_dir
pki_require_cmd ln
require_exchange_mv
PKI_REAL=$(cd -- "$PKI_DIR" && pwd -P) || pki_die "Cannot resolve PKI directory: $PKI_DIR"
if [[ $PRIVATE_REPO_REAL == "$PKI_REAL" || $PRIVATE_REPO_REAL == "$PKI_REAL"/* ]]; then
  pki_die 'Private repository must not resolve inside the PKI destination tree'
fi
require_private_directory "$PKI_DIR" 'PKI directory'
require_private_directory "$PKI_DIR/root-ca" 'Root CA directory'
require_private_directory "$PKI_DIR/intermediate-ca" 'Intermediate CA directory'
require_private_directory "$PKI_DIR/inventory" 'Inventory directory'

PRIVATE_REPO_DIR_STATE=$(snapshot_directory "$PRIVATE_REPO_REAL")
SOURCE_DIR_STATE=$(snapshot_directory "$(dirname -- "$SOURCE")")
PKI_STATE=$(snapshot_directory "$PKI_DIR")
ROOT_DIR_STATE=$(snapshot_directory "$PKI_DIR/root-ca")
INTERMEDIATE_DIR_STATE=$(snapshot_directory "$PKI_DIR/intermediate-ca")
INVENTORY_DIR_STATE=$(snapshot_directory "$PKI_DIR/inventory")
open_inventory_directory
DESTINATION="$PINNED_INVENTORY_DIR/services.yml"
ROOT_LOCK=$(pki_root_operation_lock); INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); INVENTORY_LOCK=$(pki_inventory_operation_lock)
INVENTORY_LOCK="$PINNED_INVENTORY_DIR/.platform-pki-inventory-operation.lock"
STAGE=''; STAGE_IDENTITY=''; CANONICAL=''; PUBLICATION_GUARD=''; PUBLICATION_GUARD_IDENTITY=''
PUBLICATION_GUARD_BASE=''; PUBLICATION_GUARD_BASE_IDENTITY=''; PRESERVE_PUBLICATION_STATE=false
ROOT_LOCK_HELD=false; INTERMEDIATE_LOCK_HELD=false; INVENTORY_LOCK_HELD=false
trap finish_install EXIT
umask 077
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
recheck_source_directories
recheck_install_directories
snapshot_destination
STAGE=$(mktemp "$PINNED_INVENTORY_DIR/.platform-pki-inventory-install.XXXXXX") || pki_die 'Cannot create inventory staging file'
STAGE_IDENTITY=$(stat -c '%d:%i' "$STAGE") || pki_die 'Cannot inspect inventory staging identity'
recheck_install_directories
recheck_source_directories
cp -P -- "$SOURCE" "$STAGE" || pki_die 'Cannot copy inventory source into staging'
[[ -f $STAGE && ! -L $STAGE && $(stat -c '%h' "$STAGE") == 1 ]] || pki_die 'Staged inventory must be a singly linked regular file'
chmod 600 "$STAGE" || pki_die 'Cannot secure staged inventory'
[[ $(stat -c '%d|%i|%h|%s|%a|%u|%y|%z' "$SOURCE") == "$SOURCE_STATE" ]] || pki_die 'Inventory source changed while staging'
recheck_source_directories
CANONICAL="$STAGE.canonical"
pki_validate_inventory_file "$STAGE" "$CANONICAL"
rm -f -- "$CANONICAL"
CANONICAL=''

if [[ $DESTINATION_STATE == present:* ]] && cmp -s -- "$STAGE" "$DESTINATION"; then
  if [[ $DESTINATION_MODE == 600 ]]; then
    pki_ok "Inventory already current: $PKI_DIR/inventory/services.yml"
    exit 0
  fi
  status=normalized
else
  [[ $DESTINATION_STATE == absent ]] && status=installed || status=updated
fi
recheck_install_directories
recheck_destination
if [[ $DESTINATION_STATE == absent ]]; then
  publish_absent_destination
else
  publish_existing_destination
fi
recheck_install_directories
pki_ok "Inventory $status: $PKI_DIR/inventory/services.yml"
