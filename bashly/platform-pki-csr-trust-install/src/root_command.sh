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
CSR_COMMON_PATH=$(dirname -- "$COMMON_PATH")/platform-pki-csr-sign.sh
CANDIDATE_COMMON_PATH=$(dirname -- "$COMMON_PATH")/platform-pki-csr-candidate.sh
[[ -r $CSR_COMMON_PATH && -r $CANDIDATE_COMMON_PATH ]] || { printf '[ERROR] PKI CSR shared libraries not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-csr-sign.sh disable=SC1091
source "$CSR_COMMON_PATH"
# shellcheck source=../../../../lib/platform-pki-csr-candidate.sh disable=SC1091
source "$CANDIDATE_COMMON_PATH"

pki_reject_repeated_options --private-repo --namespace --pki-dir
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
PRIVATE_REPO=${args[--private-repo]}
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
PRIVATE_REPO=$(pki_expand_path "$PRIVATE_REPO")
[[ $PRIVATE_REPO == /* ]] || PRIVATE_REPO="$(pwd -P)/$PRIVATE_REPO"
SOURCE=$PRIVATE_REPO/pki/csr-trust
DESTINATION=$PKI_DIR/inventory/csr-trust
STAGE=''
STAGE_IDENTITY=''
DESTINATION_IDENTITY=''

require_trusted_ancestors() {
  local path=$1 label=$2 current='' component mode owner
  local -a components
  IFS='/' read -r -a components <<<"$path"
  [[ $path != /* ]] || current=/
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    if [[ $current == / ]]; then current="/$component"; elif [[ -n $current ]]; then current="$current/$component"; else current=$component; fi
    [[ -d $current && ! -L $current ]] || pki_die "$label ancestor must be a non-symlink directory: $current"
    mode=$(stat -c '%a' "$current") || pki_die "Cannot inspect $label ancestor permissions: $current"
    owner=$(stat -c '%u' "$current") || pki_die "Cannot inspect $label ancestor owner: $current"
    [[ $owner == "$(id -u)" || $owner == 0 ]] || pki_die "$label ancestor is not owned by current user or root: $current"
    (( (8#$mode & 022) == 0 || (8#$mode & 01000) != 0 )) || pki_die "$label ancestor is group- or world-writable without sticky bit: $current"
  done
}

require_source_file() {
  local path=$1 mode
  [[ -f $path && ! -L $path && -r $path ]] || pki_die "CSR trust source must be a readable non-symlink regular file: $path"
  [[ $(stat -c '%u:%h' "$path") == "$(id -u):1" ]] || pki_die "CSR trust source must be current-user-owned and singly linked: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect CSR trust source permissions: $path"
  (( (8#$mode & 022) == 0 )) || pki_die "CSR trust source is group- or world-writable: $path"
  (( $(stat -c '%s' "$path") <= 65536 )) || pki_die "CSR trust source exceeds 65536 bytes: $path"
}

validate_text_file() {
  python3 - "$1" <<'PY' || pki_die "CSR trust source must be bounded ASCII text with one trailing newline: $1"
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
if not data or len(data) > 65536 or not data.endswith(b"\n") or data.endswith(b"\n\n"):
    raise SystemExit(1)
if any(byte < 32 and byte != 10 for byte in data) or any(byte > 126 for byte in data):
    raise SystemExit(1)
PY
}

validate_policy() {
  local path=$1
  local -a lines=()
  mapfile -t lines <"$path"
  [[ ${lines[0]:-} == schema=1 || ${lines[0]:-} == schema=2 ]] || pki_die 'CSR trust policy schema must be 1 or 2'
  TRUST_SCHEMA=${lines[0]#schema=}
  if [[ $TRUST_SCHEMA == 1 ]]; then
    [[ ${#lines[@]} -eq 10 ]] || pki_die 'CSR trust schema 1 policy must contain exactly 10 ordered fields'
    deployment_offset=0
  else
    [[ ${#lines[@]} -eq 12 ]] || pki_die 'CSR trust schema 2 policy must contain exactly 12 ordered fields'
    [[ ${lines[4]} == deployment_namespace=platform-pki-csr-deployment-v1 ]] || pki_die 'CSR trust deployment namespace is invalid'
    deployment_offset=1
  fi
  [[ ${lines[1]} == request_namespace=platform-pki-csr-request-v1 ]] || pki_die 'CSR trust request namespace is invalid'
  [[ ${lines[2]} == approval_namespace=platform-pki-csr-approval-v1 ]] || pki_die 'CSR trust approval namespace is invalid'
  [[ ${lines[3]} == response_namespace=platform-pki-csr-response-v1 ]] || pki_die 'CSR trust response namespace is invalid'
  [[ ${lines[4 + deployment_offset]} == request_max_age_seconds=604800 ]] || pki_die 'CSR trust request maximum age must be 604800 seconds'
  [[ ${lines[5 + deployment_offset]} == sole_operator_min_delay_seconds=86400 ]] || pki_die 'CSR trust sole-operator delay must be 86400 seconds'
  [[ ${lines[6 + deployment_offset]} == approval_max_age_seconds=86400 ]] || pki_die 'CSR trust approval maximum age must be 86400 seconds'
  if [[ $TRUST_SCHEMA == 2 ]]; then
    [[ ${lines[8]} == deployment_max_age_seconds=86400 ]] || pki_die 'CSR trust deployment maximum age must be 86400 seconds'
  fi
  [[ ${lines[7 + 2 * deployment_offset]} == clock_skew_seconds=300 ]] || pki_die 'CSR trust clock skew must be 300 seconds'
  [[ ${lines[8 + 2 * deployment_offset]} =~ ^approver_principal=([a-z0-9][a-z0-9.-]*)$ ]] || pki_die 'CSR trust approver principal is invalid'
  APPROVER_PRINCIPAL=${BASH_REMATCH[1]}
  [[ ${lines[9 + 2 * deployment_offset]} =~ ^response_principal=([a-z0-9][a-z0-9.-]*)$ ]] || pki_die 'CSR trust response principal is invalid'
  RESPONSE_PRINCIPAL=${BASH_REMATCH[1]}
  if [[ $TRUST_SCHEMA == 1 ]]; then
    TRUST_FILES=(approvers.allowed_signers policy requesters.allowed_signers responses.allowed_signers)
  else
    TRUST_FILES=(approvers.allowed_signers deployers.allowed_signers policy requesters.allowed_signers responses.allowed_signers)
  fi
}

validate_allowed_signers() {
  local path=$1 label=$2 required=${3:-} line principal algorithm key extra key_file key_identity count=0
  local -A seen=()
  while IFS= read -r line || [[ -n $line ]]; do
    IFS=' ' read -r principal algorithm key extra <<<"$line"
    [[ -n $principal && $principal =~ ^[a-z0-9][a-z0-9.-]*$ && $algorithm == ssh-ed25519 && $key =~ ^[A-Za-z0-9+/]+={0,2}$ && -z $extra ]] || \
      pki_die "$label must contain only no-options Ed25519 allowed-signer records"
    [[ ! -v seen[$principal] ]] || pki_die "$label contains duplicate principal: $principal"
    seen[$principal]=1
    key_file=$(mktemp "${TMPDIR:-/tmp}/platform-pki-csr-public-key.XXXXXX") || pki_die 'Cannot stage CSR trust public-key validation'
    printf 'ssh-ed25519 %s\n' "$key" >"$key_file"
    key_identity=$(pki_file_identity "$key_file") || pki_die 'Cannot snapshot CSR trust public-key validation file identity'
    if ! ssh-keygen -l -f "$key_file" >/dev/null 2>&1; then
      pki_remove_identity_file "$key_file" "$key_identity" || pki_die 'CSR trust public-key validation file changed before cleanup'
      pki_die "$label contains an invalid Ed25519 public key"
    fi
    pki_remove_identity_file "$key_file" "$key_identity" || pki_die 'CSR trust public-key validation file changed before cleanup'
    count=$((count + 1))
  done <"$path"
  (( count > 0 )) || pki_die "$label must contain at least one signer"
  [[ -z $required || -v seen[$required] ]] || pki_die "$label does not contain required principal: $required"
  if [[ -n $required && $count -ne 1 ]]; then pki_die "$label must contain exactly the pinned principal: $required"; fi
}

validate_trust_tree() {
  local root=$1 path
  local -a actual=()
  while IFS= read -r -d '' path; do actual+=("$(basename -- "$path")"); done < <(find "$root" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  [[ ${actual[0]:-} == approvers.allowed_signers ]] || pki_die 'CSR trust directory has an invalid file set'
  require_source_file "$root/policy"; validate_text_file "$root/policy"
  validate_policy "$root/policy"
  [[ ${actual[*]} == "${TRUST_FILES[*]}" ]] || pki_die 'CSR trust directory must contain exactly policy and the allowed_signers files required by its policy schema'
  for path in "${TRUST_FILES[@]}"; do require_source_file "$root/$path"; validate_text_file "$root/$path"; done
  validate_allowed_signers "$root/requesters.allowed_signers" 'CSR requester trust'
  validate_allowed_signers "$root/approvers.allowed_signers" 'CSR approver trust' "$APPROVER_PRINCIPAL"
  validate_allowed_signers "$root/responses.allowed_signers" 'CSR response trust' "$RESPONSE_PRINCIPAL"
  [[ $TRUST_SCHEMA != 2 ]] || validate_allowed_signers "$root/deployers.allowed_signers" 'CSR deployer trust'
}

snapshot_source_tree() {
  local name value
  SOURCE_DIR_IDENTITY=$(stat -c '%d:%i:%u:%a:%y:%z' "$SOURCE") || pki_die 'Cannot snapshot CSR trust source directory'
  unset -v SOURCE_IDENTITIES
  declare -gA SOURCE_IDENTITIES=()
  for name in "${TRUST_FILES[@]}"; do
    value=$(pki_file_identity "$SOURCE/$name") || pki_die "Cannot snapshot CSR trust source: $name"
    SOURCE_IDENTITIES[$name]=$value
  done
}

recheck_source_tree() {
  local name
  [[ -d $SOURCE && ! -L $SOURCE && $(stat -c '%d:%i:%u:%a:%y:%z' "$SOURCE") == "$SOURCE_DIR_IDENTITY" ]] || \
    pki_die 'CSR trust source directory changed during installation'
  for name in "${TRUST_FILES[@]}"; do
    [[ -f $SOURCE/$name && ! -L $SOURCE/$name && $(pki_file_identity "$SOURCE/$name") == "${SOURCE_IDENTITIES[$name]}" ]] || \
      pki_die "CSR trust source changed during installation: $name"
  done
}

snapshot_staged_tree() {
  local name value
  unset -v STAGED_IDENTITIES
  declare -gA STAGED_IDENTITIES=()
  for name in "${STAGED_TRUST_FILES[@]}"; do
    value=$(pki_file_identity "$STAGE/$name") || pki_die "Cannot snapshot staged CSR trust: $name"
    STAGED_IDENTITIES[$name]=$value
  done
}

recheck_staged_tree() {
  local name
  [[ -d $STAGE && ! -L $STAGE && $(pki_dir_identity "$STAGE") == "$STAGE_IDENTITY" ]] || pki_die 'Staged CSR trust directory changed before publication'
  validate_trust_tree "$STAGE"
  [[ $TRUST_SCHEMA == "$STAGED_TRUST_SCHEMA" && ${TRUST_FILES[*]} == "${STAGED_TRUST_FILES[*]}" ]] || pki_die 'Staged CSR trust schema changed before publication'
  for name in "${STAGED_TRUST_FILES[@]}"; do
    [[ -f $STAGE/$name && ! -L $STAGE/$name && $(pki_file_identity "$STAGE/$name") == "${STAGED_IDENTITIES[$name]}" ]] || pki_die "Staged CSR trust changed before publication: $name"
  done
}

validate_installed_trust() {
  local name
  pki_require_private_dir "$DESTINATION" 'Installed CSR trust directory'
  validate_trust_tree "$DESTINATION"
  for name in "${TRUST_FILES[@]}"; do
    [[ -f $DESTINATION/$name && ! -L $DESTINATION/$name && $(stat -c '%u:%a:%h' "$DESTINATION/$name") == "$(id -u):600:1" ]] || \
      pki_die "Installed CSR trust file is unsafe: $DESTINATION/$name"
  done
}

snapshot_installed_tree() {
  local name value
  INSTALLED_TRUST_SCHEMA=$TRUST_SCHEMA
  INSTALLED_TRUST_FILES=("${TRUST_FILES[@]}")
  unset -v INSTALLED_IDENTITIES
  declare -gA INSTALLED_IDENTITIES=()
  for name in "${INSTALLED_TRUST_FILES[@]}"; do
    value=$(pki_file_identity "$DESTINATION/$name") || pki_die "Cannot snapshot installed CSR trust: $name"
    INSTALLED_IDENTITIES[$name]=$value
  done
}

recheck_installed_tree() {
  local name
  [[ -n $DESTINATION_IDENTITY && -d $DESTINATION && ! -L $DESTINATION && $(pki_dir_identity "$DESTINATION") == "$DESTINATION_IDENTITY" ]] || pki_die 'Installed CSR trust changed before publication'
  validate_installed_trust
  [[ $TRUST_SCHEMA == "$INSTALLED_TRUST_SCHEMA" && ${TRUST_FILES[*]} == "${INSTALLED_TRUST_FILES[*]}" ]] || pki_die 'Installed CSR trust schema changed before publication'
  for name in "${INSTALLED_TRUST_FILES[@]}"; do
    [[ -f $DESTINATION/$name && ! -L $DESTINATION/$name && $(pki_file_identity "$DESTINATION/$name") == "${INSTALLED_IDENTITIES[$name]}" ]] || pki_die "Installed CSR trust changed before publication: $name"
  done
}

finish_trust_install() {
  local status=$?
  trap - EXIT
  if [[ -n $STAGE && -n $STAGE_IDENTITY && -d $STAGE && ! -L $STAGE ]]; then
    pki_remove_journaled_tree "$STAGE" "$STAGE_IDENTITY" "$(dirname -- "$STAGE")" 2>/dev/null || status=1
  fi
  [[ ${INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  [[ ${LIFECYCLE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$LIFECYCLE_LOCK" 2>/dev/null || status=1
  exit "$status"
}

pki_require_cmd ssh-keygen
pki_require_cmd python3
pki_require_cmd mv
pki_require_cmd openssl
pki_require_cmd sha256sum
pki_require_cmd cmp
pki_require_no_symlink_path_components "$PRIVATE_REPO" 'Private repository'
require_trusted_ancestors "$PRIVATE_REPO" 'Private repository'
PRIVATE_REPO=$(cd -- "$PRIVATE_REPO" && pwd -P) || pki_die "Private repository does not exist: $PRIVATE_REPO"
SOURCE=$PRIVATE_REPO/pki/csr-trust
[[ -d $SOURCE && ! -L $SOURCE ]] || pki_die "CSR trust source directory is missing or unsafe: $SOURCE"
require_trusted_ancestors "$SOURCE" 'CSR trust source'
validate_trust_tree "$SOURCE"
SOURCE_TRUST_SCHEMA=$TRUST_SCHEMA
snapshot_source_tree
pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
pki_require_pki_dir
pki_prepare_control_state
pki_require_private_dir "$PKI_DIR/inventory" 'Inventory directory'
PKI_REAL=$(cd -- "$PKI_DIR" && pwd -P) || pki_die "Cannot resolve PKI directory: $PKI_DIR"
[[ $PRIVATE_REPO != "$PKI_REAL" && $PRIVATE_REPO != "$PKI_REAL"/* ]] || pki_die 'Private repository must not be inside the PKI destination tree'

LIFECYCLE_LOCK=$(pki_lifecycle_operation_lock)
ROOT_LOCK=$(pki_root_operation_lock)
INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock)
INVENTORY_LOCK=$(pki_inventory_operation_lock)
LIFECYCLE_LOCK_HELD=false; ROOT_LOCK_HELD=false; INTERMEDIATE_LOCK_HELD=false; INVENTORY_LOCK_HELD=false
trap finish_trust_install EXIT
umask 077
pki_acquire_operation_lock "$LIFECYCLE_LOCK" 'PKI lifecycle operation'; LIFECYCLE_LOCK_HELD=true
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_LOCK" 'inventory operation'; INVENTORY_LOCK_HELD=true
pki_require_no_unresolved_journal
recheck_source_tree

STAGE=$(mktemp -d "$PKI_DIR/inventory/.platform-pki-csr-trust.XXXXXX") || pki_die 'Cannot create CSR trust staging directory'
STAGE_IDENTITY=$(pki_dir_identity "$STAGE") || pki_die 'Cannot snapshot CSR trust staging identity'
for name in "${TRUST_FILES[@]}"; do
  cp -P -- "$SOURCE/$name" "$STAGE/$name" || pki_die "Cannot stage CSR trust file: $name"
  chmod 600 "$STAGE/$name" || pki_die "Cannot secure staged CSR trust file: $name"
done
recheck_source_tree
validate_trust_tree "$STAGE"
STAGED_TRUST_FILES=("${TRUST_FILES[@]}")
STAGED_TRUST_SCHEMA=$TRUST_SCHEMA
[[ $STAGED_TRUST_SCHEMA == "$SOURCE_TRUST_SCHEMA" ]] || pki_die 'CSR trust source schema changed during staging'
pki_fsync_tree "$STAGE"
snapshot_staged_tree

INSTALLED_TRUST_SCHEMA=''
if [[ -e $DESTINATION || -L $DESTINATION ]]; then
  validate_installed_trust
  DESTINATION_IDENTITY=$(pki_dir_identity "$DESTINATION") || pki_die 'Cannot snapshot installed CSR trust identity'
  snapshot_installed_tree
fi
TRUST_FILES=("${STAGED_TRUST_FILES[@]}")
same=true
if [[ -d $DESTINATION && ! -L $DESTINATION ]]; then
  for name in "${TRUST_FILES[@]}"; do cmp -s -- "$STAGE/$name" "$DESTINATION/$name" || same=false; done
else
  same=false
fi
if [[ $same == true ]]; then
  recheck_installed_tree
  pki_ok "CSR trust already current: $DESTINATION"
  exit 0
fi

if [[ $STAGED_TRUST_SCHEMA == 2 || $INSTALLED_TRUST_SCHEMA == 2 ]]; then
  CANDIDATE_STATE_DIGEST=$(pki_candidate_require_no_pending_outcomes) || pki_die 'CSR candidate and outcome state validation failed'
  recheck_source_tree
fi
recheck_staged_tree

if [[ -e $DESTINATION || -L $DESTINATION ]]; then
  recheck_installed_tree
  [[ -z ${CANDIDATE_STATE_DIGEST:-} ]] || pki_candidate_require_historical_state_digest "$CANDIDATE_STATE_DIGEST"
  recheck_installed_tree
  old_identity=$DESTINATION_IDENTITY
  new_identity=$STAGE_IDENTITY
  mv --exchange --no-copy -T -- "$STAGE" "$DESTINATION" || pki_die 'Cannot atomically exchange installed CSR trust'
  [[ $(pki_dir_identity "$DESTINATION") == "$new_identity" && $(pki_dir_identity "$STAGE") == "$old_identity" ]] || \
    pki_die 'CSR trust exchange identity check failed'
  pki_fsync "$PKI_DIR/inventory"
  pki_remove_journaled_tree "$STAGE" "$old_identity" "$PKI_DIR/inventory" || pki_die 'Cannot remove prior CSR trust after publication'
  STAGE=''
  status=updated
else
  new_identity=$STAGE_IDENTITY
  [[ -z ${CANDIDATE_STATE_DIGEST:-} ]] || pki_candidate_require_historical_state_digest "$CANDIDATE_STATE_DIGEST"
  mv --no-copy --update=none-fail -T -- "$STAGE" "$DESTINATION" || pki_die 'CSR trust destination appeared before publication'
  [[ $(pki_dir_identity "$DESTINATION") == "$new_identity" ]] || pki_die 'Published CSR trust identity is invalid'
  STAGE=''
  pki_fsync "$PKI_DIR/inventory"
  status=installed
fi
pki_ok "CSR trust $status: $DESTINATION"
