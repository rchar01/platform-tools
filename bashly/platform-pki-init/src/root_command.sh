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

copy_template() {
  local source=$1
  local target=$2
  local target_dir tmp

  if [[ -e $target && $FORCE != true ]]; then
    pki_info "Kept existing file: $target"
    return 0
  fi
  [[ ! -L $target ]] || pki_die "Template destination must not be a symlink: $target"
  [[ ! -e $target || -f $target ]] || pki_die "Template destination must be a regular file: $target"

  target_dir=$(dirname -- "$target")
  if ! (
    tmp=$(mktemp "$target_dir/.platform-pki-init.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    cp "$source" "$tmp" &&
      chmod 600 "$tmp" &&
      mv -f -- "$tmp" "$target"
  ); then
    pki_die "Failed to replace template: $target"
  fi
  pki_ok "Wrote $target"
}

require_safe_init_path() {
  local path=$1
  local label=$2
  local current='' component mode owner current_uid probe
  local -a components

  current_uid=$(id -u)
  [[ $path == /* ]] || pki_die "$label must be an absolute path: $path"
  [[ $path != / ]] || pki_die "$label must not be the filesystem root"
  [[ $path != */ ]] || pki_die "$label must not end with a slash: $path"
  [[ $path != *$'\n'* && $path != *$'\r'* ]] || pki_die "$label must not contain newlines"
  case $path in
    *//*|*/./*|*/.|*/../*|*/..) pki_die "$label must not contain empty, dot, or parent components: $path" ;;
  esac

  IFS='/' read -r -a components <<<"$path"
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    current="${current}/${component}"
    [[ ! -L $current ]] || pki_die "$label path component must not be a symlink: $current"
    [[ ! -e $current || -d $current ]] || pki_die "$label path component is not a directory: $current"
    if [[ -d $current ]]; then
      mode=$(stat -c '%a' "$current") || pki_die "Cannot inspect $label path component permissions: $current"
      owner=$(stat -c '%u' "$current") || pki_die "Cannot inspect $label path component owner: $current"
      [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label path component metadata: $current"
      if (( (8#$mode & 022) != 0 && (8#$mode & 01000) == 0 )); then
        pki_die "$label path component is group- or world-writable without sticky bit: $current"
      fi
      if [[ $owner != "$current_uid" && $owner != 0 ]]; then
        pki_die "$label path component is not owned by current user or root: $current"
      fi
      if [[ $current == "$path" && $owner != "$current_uid" ]]; then
        pki_die "$label directory is not owned by the current user: $path"
      fi
    fi
  done

  probe=$path
  while [[ ! -e $probe && ! -L $probe ]]; do
    probe=$(dirname -- "$probe")
  done
  [[ -d $probe && ! -L $probe && -w $probe ]] || pki_die "$label has no writable trusted creation parent: $probe"
}

prepare_private_path() {
  local path=$1
  local label=$2
  local current='' component mode owner current_uid
  local -a components

  current_uid=$(id -u)
  IFS='/' read -r -a components <<<"$path"
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    current="${current}/${component}"
    if [[ -e $current || -L $current ]]; then
      [[ -d $current && ! -L $current ]] || pki_die "$label path component must be a non-symlink directory: $current"
    else
      mkdir -m 700 -- "$current" || pki_die "Cannot create $label path component: $current"
      [[ -d $current && ! -L $current ]] || pki_die "$label path component changed during creation: $current"
    fi

    mode=$(stat -c '%a' "$current") || pki_die "Cannot inspect $label path component permissions: $current"
    owner=$(stat -c '%u' "$current") || pki_die "Cannot inspect $label path component owner: $current"
    [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label path component metadata: $current"
    if (( (8#$mode & 022) != 0 && (8#$mode & 01000) == 0 )); then
      pki_die "$label path component is group- or world-writable without sticky bit: $current"
    fi
    if [[ $owner != "$current_uid" && $owner != 0 ]]; then
      pki_die "$label path component is not owned by current user or root: $current"
    fi
    if [[ $current == "$path" && $owner != "$current_uid" ]]; then
      pki_die "$label directory is not owned by the current user: $path"
    fi
  done

  chmod 700 "$path"
}

require_safe_existing_pki_tree() {
  local path=$1
  local unsafe item mode owner current_uid

  [[ -d $path ]] || return 0
  current_uid=$(id -u)
  unsafe=$(find "$path" -type l -print -quit) || pki_die "Cannot inspect existing PKI directory: $path"
  [[ -z $unsafe ]] || pki_die "Existing PKI state must not contain symlinks: $unsafe"
  unsafe=$(find "$path" -type f -links +1 -print -quit) || pki_die "Cannot inspect existing PKI directory: $path"
  [[ -z $unsafe ]] || pki_die "Existing PKI state must not contain hard-linked files: $unsafe"

  while IFS= read -r -d '' item; do
    mode=$(stat -c '%a' "$item") || pki_die "Cannot inspect private directory permissions: $item"
    owner=$(stat -c '%u' "$item") || pki_die "Cannot inspect private directory owner: $item"
    [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse private directory metadata: $item"
    [[ $owner == "$current_uid" ]] || pki_die "Private directory is not owned by the current user: $item"
    if (( (8#$mode & 022) != 0 )); then
      pki_die "Private directory is group- or world-writable: $item"
    fi
  done < <(find "$path" -type d -name private -print0)

  while IFS= read -r -d '' item; do
    mode=$(stat -c '%a' "$item") || pki_die "Cannot inspect private key permissions: $item"
    owner=$(stat -c '%u' "$item") || pki_die "Cannot inspect private key owner: $item"
    [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse private key metadata: $item"
    [[ $owner == "$current_uid" ]] || pki_die "Private key is not owned by the current user: $item"
    if (( (8#$mode & 077) != 0 )); then
      pki_die "Private key permissions are too open; use chmod 600 or stricter: $item"
    fi
  done < <(find "$path" -type f -name '*.key' -print0)
}

require_pki_templates() {
  [[ -f $TEMPLATE_DIR/services.yml.example && \
    ! -L $TEMPLATE_DIR/services.yml.example && \
    -r $TEMPLATE_DIR/services.yml.example ]] || \
    pki_die "Required PKI template is missing or unsafe: $TEMPLATE_DIR/services.yml.example"
}

require_safe_destination_layout() {
  local path mode owner current_uid

  current_uid=$(id -u)

  for path in \
    "$NAMESPACE" "$PKI_DIR" "$PKI_DIR/inventory" \
    "$PKI_DIR/root-ca" "$PKI_DIR/root-ca/certs" \
    "$PKI_DIR/root-ca/private" "$PKI_DIR/root-ca/crl" \
    "$PKI_DIR/root-ca/newcerts" "$PKI_DIR/intermediate-ca" \
    "$PKI_DIR/intermediate-ca/certs" "$PKI_DIR/intermediate-ca/csr" \
    "$PKI_DIR/intermediate-ca/private" "$PKI_DIR/intermediate-ca/crl" \
    "$PKI_DIR/intermediate-ca/newcerts" "$PKI_DIR/services" \
    "$PKI_DIR/export" "$PKI_DIR/export/ansible" "$PKI_DIR/backups"; do
    if [[ -e $path || -L $path ]]; then
      [[ -d $path && ! -L $path ]] || pki_die "PKI directory destination must be a non-symlink directory: $path"
      mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect PKI directory destination permissions: $path"
      owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect PKI directory destination owner: $path"
      [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse PKI directory destination metadata: $path"
      [[ $owner == "$current_uid" ]] || pki_die "PKI directory destination is not owned by the current user: $path"
      if (( (8#$mode & 022) != 0 )); then
        pki_die "PKI directory destination is group- or world-writable: $path"
      fi
    fi
  done

  for path in \
    "$PKI_DIR/root-ca/index.txt" "$PKI_DIR/root-ca/index.txt.attr" \
    "$PKI_DIR/root-ca/serial" "$PKI_DIR/root-ca/crlnumber" \
    "$PKI_DIR/intermediate-ca/index.txt" \
    "$PKI_DIR/intermediate-ca/index.txt.attr" \
    "$PKI_DIR/intermediate-ca/serial" \
    "$PKI_DIR/intermediate-ca/crlnumber" \
    "$PKI_DIR/inventory/services.yml.example"; do
    if [[ -e $path || -L $path ]]; then
      [[ -f $path && ! -L $path ]] || pki_die "PKI file destination must be a non-symlink regular file: $path"
      owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect PKI file destination owner: $path"
      mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect PKI file destination permissions: $path"
      [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse PKI file destination metadata: $path"
      [[ $owner == "$current_uid" ]] || pki_die "PKI file destination is not owned by the current user: $path"
      if (( (8#$mode & 022) != 0 )); then
        pki_die "PKI file destination is group- or world-writable: $path"
      fi
    fi
  done
}

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
FORCE=false
if [[ -v args[--force] ]]; then
  FORCE=true
fi

NAMESPACE=$(pki_expand_path "$NAMESPACE")
if [[ -z $PKI_DIR ]]; then
  PKI_DIR=${NAMESPACE}/pki
else
  PKI_DIR=$(pki_expand_path "$PKI_DIR")
fi

if [[ $NAMESPACE == "$PKI_DIR" || $NAMESPACE == "$PKI_DIR"/* ]]; then
  pki_die "PKI directory must not equal or contain the namespace: $PKI_DIR"
fi

require_safe_init_path "$NAMESPACE" 'Namespace'
require_safe_init_path "$PKI_DIR" 'PKI directory'
require_safe_existing_pki_tree "$PKI_DIR"
TEMPLATE_DIR=$(pki_template_dir) || pki_die 'PKI templates not found'
require_pki_templates
require_safe_destination_layout

prepare_private_path "$NAMESPACE" 'Namespace'
prepare_private_path "$PKI_DIR" 'PKI directory'

for dir in \
  "$PKI_DIR/inventory" \
  "$PKI_DIR/root-ca" "$PKI_DIR/root-ca/certs" "$PKI_DIR/root-ca/private" "$PKI_DIR/root-ca/crl" "$PKI_DIR/root-ca/newcerts" \
  "$PKI_DIR/intermediate-ca" "$PKI_DIR/intermediate-ca/certs" "$PKI_DIR/intermediate-ca/csr" "$PKI_DIR/intermediate-ca/private" "$PKI_DIR/intermediate-ca/crl" "$PKI_DIR/intermediate-ca/newcerts" \
  "$PKI_DIR/services" "$PKI_DIR/export" "$PKI_DIR/export/ansible" "$PKI_DIR/backups"; do
  prepare_private_path "$dir" 'PKI directory'
done

pki_init_ca_db "$PKI_DIR/root-ca"
pki_init_ca_db "$PKI_DIR/intermediate-ca"
chmod 600 "$PKI_DIR/root-ca/index.txt" "$PKI_DIR/root-ca/serial" "$PKI_DIR/root-ca/crlnumber" "$PKI_DIR/root-ca/index.txt.attr"
chmod 600 "$PKI_DIR/intermediate-ca/index.txt" "$PKI_DIR/intermediate-ca/serial" "$PKI_DIR/intermediate-ca/crlnumber" "$PKI_DIR/intermediate-ca/index.txt.attr"

copy_template "$TEMPLATE_DIR/services.yml.example" "$PKI_DIR/inventory/services.yml.example"

pki_ok "PKI directory ready: $PKI_DIR"
