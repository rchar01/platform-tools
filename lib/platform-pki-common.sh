#!/usr/bin/env bash

pki_info() { printf '[INFO] %s\n' "$*"; }
pki_ok() { printf '[OK] %s\n' "$*"; }
pki_warn() { printf '[WARN] %s\n' "$*" >&2; }
pki_die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

pki_command_exists() {
  command -v "$1" >/dev/null 2>&1
}

pki_require_cmd() {
  pki_command_exists "$1" || pki_die "$1 is required"
}

pki_expand_path() {
  case $1 in
    \~) printf '%s\n' "$HOME" ;;
    \~/*) printf '%s/%s\n' "$HOME" "${1:2}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

pki_default_namespace() {
  printf '%s/platform-infrastructure\n' "${XDG_CONFIG_HOME:-$HOME/.config}"
}

pki_default_pki_dir() {
  printf '%s/pki\n' "$(pki_default_namespace)"
}

pki_resolve_common_path() {
  local script_dir
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[1]}")" && pwd -P)

  if [[ -n "${PLATFORM_TOOLS_LIB_DIR:-}" && -r "${PLATFORM_TOOLS_LIB_DIR}/platform-pki-common.sh" ]]; then
    printf '%s\n' "${PLATFORM_TOOLS_LIB_DIR}/platform-pki-common.sh"
    return 0
  fi

  if [[ -r "${script_dir}/../lib/platform-pki-common.sh" ]]; then
    printf '%s\n' "${script_dir}/../lib/platform-pki-common.sh"
    return 0
  fi

  if [[ -r "${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh" ]]; then
    printf '%s\n' "${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh"
    return 0
  fi

  if [[ -r '/usr/local/share/platform-tools/lib/platform-pki-common.sh' ]]; then
    printf '%s\n' '/usr/local/share/platform-tools/lib/platform-pki-common.sh'
    return 0
  fi

  return 1
}

pki_template_dir() {
  local script_dir
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[1]}")" && pwd -P)

  if [[ -n "${PLATFORM_TOOLS_TEMPLATE_DIR:-}" && -d "${PLATFORM_TOOLS_TEMPLATE_DIR}/pki" ]]; then
    printf '%s\n' "${PLATFORM_TOOLS_TEMPLATE_DIR}/pki"
    return 0
  fi

  if [[ -d "${script_dir}/../templates/pki" ]]; then
    printf '%s\n' "${script_dir}/../templates/pki"
    return 0
  fi

  if [[ -d "${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/templates/pki" ]]; then
    printf '%s\n' "${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/templates/pki"
    return 0
  fi

  if [[ -d '/usr/local/share/platform-tools/templates/pki' ]]; then
    printf '%s\n' '/usr/local/share/platform-tools/templates/pki'
    return 0
  fi

  return 1
}

pki_validate_service_name() {
  [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || pki_die "Invalid service name: $1"
}

pki_validate_openssl_config_value() {
  local label=$1
  local value=$2

  [[ -n "$value" ]] || pki_die "$label must be non-empty"
  [[ "$value" != *'$'* ]] || pki_die "$label must not contain OpenSSL variable expansion syntax"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || pki_die "$label must not contain newlines"
  [[ ! "$value" =~ [[:cntrl:]] ]] || pki_die "$label must not contain control characters"
  [[ ! "$value" =~ ^[[:space:]] && ! "$value" =~ [[:space:]]$ ]] || pki_die "$label must not start or end with whitespace"
}

pki_validate_dns_name_value() {
  local label=$1
  local value=$2

  pki_validate_openssl_config_value "$label" "$value"
  (( ${#value} <= 253 )) || pki_die "$label must be at most 253 characters"
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] || pki_die "$label must be a DNS name using letters, digits, dots, and hyphens"
}

pki_validate_ipv4_literal() {
  local value=$1
  local octet
  local -a octets

  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$value"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
  return 0
}

pki_validate_ip_value() {
  local label=$1
  local value=$2

  pki_validate_openssl_config_value "$label" "$value"
  pki_validate_ipv4_literal "$value" || pki_die "$label must be a valid IPv4 address"
}

pki_validate_service_inventory_values() {
  local service=$1
  local common_name=$2
  local dns_file=$3
  local ips_file=$4
  local value

  pki_validate_dns_name_value "common_name for service $service" "$common_name"
  while IFS= read -r value || [[ -n "$value" ]]; do
    [[ -n "$value" ]] || continue
    pki_validate_dns_name_value "DNS SAN for service $service" "$value"
  done <"$dns_file"
  while IFS= read -r value || [[ -n "$value" ]]; do
    [[ -n "$value" ]] || continue
    pki_validate_ip_value "IP SAN for service $service" "$value"
  done <"$ips_file"
}

pki_validate_days() {
  local value=$1 normalized
  [[ $value =~ ^[0-9]+$ ]] || pki_die "Days value must be numeric: $value"
  normalized=${value#"${value%%[!0]*}"}
  [[ -n $normalized ]] || normalized=0
  (( ${#normalized} < 6 || (${#normalized} == 6 && 10#$normalized <= 365000) )) || \
    pki_die "Days value must be at most 365000: $value"
  (( 10#$normalized >= 1 )) || pki_die "Days value must be at least 1: $value"
}

pki_reject_repeated_options() {
  local option count argument
  for option in "$@"; do
    count=0
    # shellcheck disable=SC2154  # Provided by Bashly before command dispatch.
    for argument in "${command_line_args[@]}"; do [[ $argument == "$option" || $argument == "$option="* ]] && count=$((count + 1)); done
    (( count <= 1 )) || pki_die "Option must not be repeated: $option"
  done
}

pki_reject_explicit_empty_options() {
  local option argument index
  for option in "$@"; do
    # shellcheck disable=SC2154  # Provided by Bashly before command dispatch.
    for ((index = 0; index < ${#command_line_args[@]}; index++)); do
      argument=${command_line_args[index]}
      if [[ $argument == "$option=" || ( $argument == "$option" && -z ${command_line_args[index + 1]:-} ) ]]; then
        pki_die "Option must not be empty: $option"
      fi
    done
  done
}

pki_inventory_file() {
  printf '%s/inventory/services.yml\n' "$PKI_DIR"
}

pki_require_inventory() {
  local inventory
  inventory=$(pki_inventory_file)
  [[ -r "$inventory" ]] || pki_die "Service inventory is missing or unreadable: $inventory; run platform-pki-inventory-install"
}

pki_inventory_parse_value() {
  local value=$1

  [[ -n $value ]] || pki_die 'Inventory value must be non-empty'
  if [[ $value == "'"* || $value == '"'* ]]; then
    local quote=${value:0:1}
    [[ ${#value} -ge 2 && ${value: -1} == "$quote" ]] || pki_die 'Inventory value has unmatched quotes'
    value=${value:1:${#value}-2}
    [[ $value != *"$quote"* ]] || pki_die 'Inventory value contains an unsupported embedded quote'
  elif [[ $value == *"'"* || $value == *'"'* ]]; then
    pki_die 'Inventory value contains an unsupported quote'
  fi
  [[ $value != *\\* ]] || pki_die 'Inventory value contains unsupported backslash syntax'
  [[ $value != *'#'* ]] || pki_die 'Inventory inline comments are not supported'
  printf '%s\n' "$value"
}

pki_validate_inventory_file() {
  local inventory=$1 canonical=$2 line value service='' field='' line_number=0
  local saw_services=false saw_document=false service_count=0 list_count=0
  local -A services_seen=() fields_seen=() values_seen=()

  if ! cmp -s -- "$inventory" <(LC_ALL=C tr -d '\000' <"$inventory"); then
    pki_die 'Inventory NUL bytes are not supported'
  fi
  : >"$canonical" || pki_die "Cannot create parsed inventory: $canonical"
  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1))
    [[ $line != *$'\t'* ]] || pki_die "Inventory tabs are not supported at line $line_number"
    [[ ! $line =~ [[:cntrl:]] ]] || pki_die "Inventory control characters are not supported at line $line_number"
    [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue
    if [[ $line == '---' ]]; then
      [[ $saw_document == false && $saw_services == false ]] || pki_die "Inventory document marker is misplaced at line $line_number"
      saw_document=true
      continue
    fi
    [[ $line != '...' ]] || pki_die "Inventory document end markers are not supported at line $line_number"
    if [[ $line == 'services:' ]]; then
      [[ $saw_services == false ]] || pki_die "Inventory contains duplicate services at line $line_number"
      saw_services=true
      continue
    fi
    [[ $saw_services == true ]] || pki_die "Inventory content outside services at line $line_number"

    if [[ $line =~ ^\ \ ([A-Za-z0-9][A-Za-z0-9_.-]*):$ ]]; then
      if [[ -n $field && $field != common_name && $field != days && $list_count -eq 0 ]]; then
        pki_die "Inventory $field list for service $service must not be empty"
      fi
      service=${BASH_REMATCH[1]}
      [[ ! -v services_seen[$service] ]] || pki_die "Inventory contains duplicate service: $service"
      services_seen[$service]=1
      service_count=$((service_count + 1))
      field=''
      list_count=0
      continue
    fi
    [[ -n $service ]] || pki_die "Inventory requires a service key at line $line_number"

    if [[ $line =~ ^\ \ \ \ (common_name|days):[[:space:]]+(.+)$ ]]; then
      if [[ -n $field && $field != common_name && $field != days && $list_count -eq 0 ]]; then
        pki_die "Inventory $field list for service $service must not be empty"
      fi
      field=${BASH_REMATCH[1]}
      [[ ! -v fields_seen["$service:$field"] ]] || pki_die "Inventory contains duplicate $field field for service $service"
      fields_seen["$service:$field"]=1
      value=$(pki_inventory_parse_value "${BASH_REMATCH[2]}")
      if [[ $field == common_name ]]; then
        pki_validate_dns_name_value "common_name for service $service" "$value"
      else
        pki_validate_days "$value"
      fi
      printf '%s\t%s\t%s\n' "$service" "$field" "$value" >>"$canonical"
      list_count=0
      continue
    fi
    if [[ $line =~ ^\ \ \ \ (dns|ips):$ ]]; then
      if [[ -n $field && $field != common_name && $field != days && $list_count -eq 0 ]]; then
        pki_die "Inventory $field list for service $service must not be empty"
      fi
      field=${BASH_REMATCH[1]}
      [[ ! -v fields_seen["$service:$field"] ]] || pki_die "Inventory contains duplicate $field field for service $service"
      fields_seen["$service:$field"]=1
      list_count=0
      continue
    fi
    if [[ $line =~ ^\ \ \ \ \ \ -[[:space:]]+(.+)$ ]]; then
      [[ $field == dns || $field == ips ]] || pki_die "Inventory list item has no dns or ips field at line $line_number"
      value=$(pki_inventory_parse_value "${BASH_REMATCH[1]}")
      [[ ! -v values_seen["$service:$field:$value"] ]] || pki_die "Inventory contains duplicate $field SAN for service $service: $value"
      values_seen["$service:$field:$value"]=1
      if [[ $field == dns ]]; then
        pki_validate_dns_name_value "DNS SAN for service $service" "$value"
      else
        pki_validate_ip_value "IP SAN for service $service" "$value"
      fi
      printf '%s\t%s\t%s\n' "$service" "$field" "$value" >>"$canonical"
      list_count=$((list_count + 1))
      continue
    fi
    pki_die "Unsupported inventory grammar at line $line_number"
  done <"$inventory"

  [[ $saw_services == true ]] || pki_die 'Inventory must contain exactly one services mapping'
  [[ $service_count -gt 0 ]] || pki_die 'Inventory must define at least one service'
  if [[ -n $field && $field != common_name && $field != days && $list_count -eq 0 ]]; then
    pki_die "Inventory $field list for service $service must not be empty"
  fi
  for service in "${!services_seen[@]}"; do
    [[ -v fields_seen["$service:common_name"] ]] || pki_die "common_name is missing for service: $service"
    [[ -v fields_seen["$service:dns"] || -v fields_seen["$service:ips"] ]] || pki_die "Service must define at least one DNS or IP SAN: $service"
  done
}

pki_load_inventory_snapshot() {
  local snapshot_dir=$1 inventory before after mode
  inventory=$(pki_inventory_file)
  pki_require_inventory
  [[ -f $inventory && ! -L $inventory ]] || pki_die "Service inventory must be a non-symlink regular file: $inventory"
  before=$(stat -c '%d|%i|%h|%s|%a|%u|%y|%z' "$inventory") || pki_die "Cannot inspect service inventory: $inventory"
  [[ $(stat -c '%u' "$inventory") == "$(id -u)" ]] || pki_die "Service inventory is not owned by the current user: $inventory"
  [[ $(stat -c '%h' "$inventory") == 1 ]] || pki_die "Service inventory must not be hard-linked: $inventory"
  mode=$(stat -c '%a' "$inventory") || pki_die "Cannot inspect service inventory permissions: $inventory"
  (( (8#$mode & 022) == 0 )) || pki_die "Service inventory is group- or world-writable: $inventory"
  [[ -f $inventory && ! -L $inventory && $(stat -c '%d|%i|%h|%s|%a|%u|%y|%z' "$inventory") == "$before" ]] || \
    pki_die 'Service inventory changed during validation'
  cp -P -- "$inventory" "$snapshot_dir/services.yml" || pki_die 'Cannot copy service inventory snapshot'
  [[ -f $snapshot_dir/services.yml && ! -L $snapshot_dir/services.yml ]] || pki_die 'Service inventory snapshot is not a regular file'
  chmod 600 "$snapshot_dir/services.yml" || pki_die 'Cannot secure service inventory snapshot'
  after=$(stat -c '%d|%i|%h|%s|%a|%u|%y|%z' "$inventory") || pki_die "Cannot recheck service inventory: $inventory"
  [[ $before == "$after" ]] || pki_die 'Service inventory changed while its snapshot was created'
  pki_validate_inventory_file "$snapshot_dir/services.yml" "$snapshot_dir/canonical"
  INVENTORY_CANONICAL="$snapshot_dir/canonical"
}

pki_inventory_services() {
  [[ -n ${INVENTORY_CANONICAL:-} ]] || pki_die 'Service inventory snapshot is not loaded'
  awk -F '\t' '!seen[$1]++ { print $1 }' "$INVENTORY_CANONICAL"
}

pki_inventory_scalar() {
  local service=$1
  local field=$2
  [[ -n ${INVENTORY_CANONICAL:-} ]] || pki_die 'Service inventory snapshot is not loaded'
  awk -F '\t' -v service="$service" -v field="$field" '$1 == service && $2 == field { print $3; exit }' "$INVENTORY_CANONICAL"
}

pki_inventory_array() {
  local service=$1
  local field=$2
  [[ -n ${INVENTORY_CANONICAL:-} ]] || pki_die 'Service inventory snapshot is not loaded'
  awk -F '\t' -v service="$service" -v field="$field" '$1 == service && $2 == field { print $3 }' "$INVENTORY_CANONICAL"
}

pki_require_service_in_inventory() {
  local service=$1
  if ! pki_inventory_services | grep -Fx -- "$service" >/dev/null 2>&1; then
    pki_die "Service is not defined in $(pki_inventory_file): $service"
  fi
}

pki_require_file() {
  [[ -f "$1" ]] || pki_die "Required file is missing: $1"
}

pki_file_identity() {
  stat -c '%d:%i:%u:%a:%h:%s:%y:%z:%F' -- "$1"
}

pki_file_object_state() {
  stat -c '%d:%i:%u:%a:%h:%s:%F' -- "$1"
}

pki_dir_identity() {
  stat -c '%d:%i:%u:%a:%F' -- "$1"
}

pki_fsync() {
  sync -f -- "$1" || pki_die "Cannot fsync: $1"
}

pki_fsync_tree() {
  local root=$1 path
  while IFS= read -r -d '' path; do pki_fsync "$path"; done < <(find "$root" -depth -print0)
  pki_fsync "$(dirname -- "$root")"
}

pki_remove_identity_file() {
  local path=$1 expected=$2 label=${3:-identity-file} current marker release
  [[ -f $path && ! -L $path ]] || return 1
  current=$(pki_file_identity "$path") || return 1
  [[ $current == "$expected" || $(pki_file_object_state "$path") == "$expected" ]] || return 1
  if [[ ${PLATFORM_PKI_UNLINK_PAUSE_AT:-} == "$label" ]]; then
    marker=${PLATFORM_PKI_UNLINK_PAUSE_MARKER:?}; release=${PLATFORM_PKI_UNLINK_PAUSE_RELEASE:?}
    : >"$marker" || return 1
    while [[ ! -e $release ]]; do sleep 0.01; done
  fi
  [[ $(pki_file_identity "$path") == "$current" ]] || return 1
  rm -f -- "$path" || return 1
  pki_fsync "$(dirname -- "$path")"
}

pki_terminal_receipt() {
  [[ $1 =~ ^prepare-(root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || pki_die "Invalid rollover transaction ID: $1"
  printf '%s/state/rollover/terminal-%s\n' "$PKI_DIR" "$1"
}

pki_file_identity_or_absent() {
  local path=$1
  if [[ ! -e $path && ! -L $path ]]; then
    printf '%s\n' absent || return 1
    return 0
  fi
  [[ -f $path && ! -L $path ]] || pki_die "Expected a regular file or absent path: $path"
  pki_file_object_state "$path"
}

pki_file_identity_or_absent_full() {
  local path=$1
  if [[ ! -e $path && ! -L $path ]]; then printf '%s\n' absent || return 1; return 0; fi
  [[ -f $path && ! -L $path ]] || pki_die "Expected a regular file or absent path: $path"
  pki_file_identity "$path"
}

pki_require_file_identity() {
  local path=$1 expected=$2 label=$3
  if [[ $expected == absent ]]; then
    [[ ! -e $path && ! -L $path ]] || pki_die "$label appeared unexpectedly: $path"
  else
    [[ -f $path && ! -L $path && ( $(pki_file_identity "$path") == "$expected" || $(pki_file_object_state "$path") == "$expected" ) ]] || \
      pki_die "$label identity changed: $path"
  fi
}

pki_restore_journaled_file() {
  local path=$1 pre_identity=$2 post_identity=$3 backup=$4 backup_identity=$5 label=$6
  pki_require_file_identity "$path" "$post_identity" "$label published state"
  [[ $pre_identity != "$post_identity" ]] || return 0
  if [[ $pre_identity == absent ]]; then
    local current_identity
    current_identity=$(pki_file_identity "$path") || return 1
    pki_remove_identity_file "$path" "$current_identity" || return 1
    return 0
  fi
  pki_require_file_identity "$backup" "$backup_identity" "$label rollback copy"
  pki_publish_staged_file "$backup" "$path"
}

pki_restore_journaled_file_exact() {
  local path=$1 pre_identity=$2 post_identity=$3 backup=$4 backup_identity=$5 label=$6
  pki_require_file_identity "$path" "$post_identity" "$label published state"
  [[ $pre_identity != "$post_identity" ]] || return 0
  if [[ $pre_identity == absent ]]; then pki_remove_identity_file "$path" "$post_identity" || return 1; return 0; fi
  pki_require_file_identity "$backup" "$backup_identity" "$label rollback copy"
  pki_publish_staged_file_exact "$backup" "$path"
}

pki_remove_journaled_tree() {
  local path=$1 expected=$2 parent=$3
  [[ $(dirname -- "$path") == "$parent" && -d $path && ! -L $path ]] || return 1
  [[ $(pki_dir_identity "$path") == "$expected" ]] || return 1
  [[ $(stat -c '%u:%a:%h' "$path") == "$(id -u):700:2" || $(stat -c '%u:%a' "$path") == "$(id -u):700" ]] || return 1
  rm -rf -- "$path" || return 1
  pki_fsync "$parent"
}

pki_remove_manifested_tree() {
  local root=$1 root_identity=$2 parent=$3 manifest=$4 manifest_identity=$5 manifest_digest=$6 excluded=${7:-}
  local line type relative identity digest path current actual_digest
  local -A manifest_type_map=() manifest_identity_map=()
  local -a paths=()

  [[ $(dirname -- "$root") == "$parent" && -d $root && ! -L $root ]] || return 1
  [[ $(pki_dir_identity "$root") == "$root_identity" ]] || return 1
  pki_require_file_identity "$manifest" "$manifest_identity" 'PKI cleanup tree manifest'
  actual_digest=$(sha256sum "$manifest") || return 1
  [[ ${actual_digest%% *} == "$manifest_digest" ]] || return 1

  while IFS='|' read -r type relative identity digest; do
    [[ -n $type && -n $relative && -n $identity && -n $digest && $relative != /* && $relative != . && $relative != .. && $relative != ../* && $relative != */../* && $relative != */.. ]] || return 1
    [[ $type == directory || $type == 'regular file' || $type == 'regular empty file' ]] || return 1
    [[ ! -v manifest_type_map[$relative] ]] || return 1
    manifest_type_map[$relative]=$type
    manifest_identity_map[$relative]=$identity
  done <"$manifest"
  [[ $(pki_file_identity "$manifest") == "$manifest_identity" ]] || return 1

  while IFS= read -r -d '' path; do
    relative=${path#"$root"/}
    [[ $relative != "$path" && $relative != *'|'* && $relative != *$'\n'* ]] || return 1
    [[ -z $excluded || $relative != "$excluded" ]] || continue
    [[ -v manifest_type_map[$relative] ]] || return 1
    type=$(stat -c '%F' -- "$path") || return 1
    [[ $type == "${manifest_type_map[$relative]}" ]] || return 1
    if [[ $type == directory ]]; then current=$(pki_dir_identity "$path"); else [[ -f $path && ! -L $path ]] || return 1; current=$(pki_file_identity "$path"); fi
    [[ $current == "${manifest_identity_map[$relative]}" ]] || return 1
    paths+=("$path")
  done < <(find "$root" -mindepth 1 -depth -xdev -print0)

  for path in "${paths[@]}"; do
    relative=${path#"$root"/}; type=${manifest_type_map[$relative]}; identity=${manifest_identity_map[$relative]}
    if [[ $type == directory ]]; then
      [[ -d $path && ! -L $path && $(pki_dir_identity "$path") == "$identity" ]] || return 1
      rmdir -- "$path" || return 1
    else
      pki_remove_identity_file "$path" "$identity" || return 1
    fi
  done
  if [[ -n $excluded ]]; then
    [[ $manifest == "$root/$excluded" ]] || return 1
    pki_remove_identity_file "$manifest" "$manifest_identity" || return 1
  fi
  [[ $(pki_dir_identity "$root") == "$root_identity" ]] || return 1
  rmdir -- "$root" || return 1
  pki_fsync "$parent"
}

pki_require_pass_file() {
  local path=$1
  local mode
  local passphrase

  [[ -f "$path" ]] || pki_die "Passphrase file is missing: $path"
  [[ -r "$path" ]] || pki_die "Passphrase file is not readable: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect passphrase file permissions: $path"
  [[ $mode =~ ^[0-7]+$ ]] || pki_die "Cannot parse passphrase file permissions: $path"
  if (( (8#$mode & 077) != 0 )); then
    pki_die "Passphrase file permissions are too open; use chmod 600 or stricter: $path"
  fi
  IFS= read -r passphrase <"$path" || [[ -n "$passphrase" ]] || pki_die "Passphrase file first line is empty: $path"
  [[ -n "$passphrase" ]] || pki_die "Passphrase file first line is empty: $path"
  [[ $passphrase =~ [^[:space:]] ]] || pki_die "Passphrase file first line must contain non-whitespace characters: $path"
  (( ${#passphrase} >= 16 )) || pki_die "Passphrase file first line must be at least 16 characters: $path"
}

pki_require_pki_dir() {
  [[ -d "$PKI_DIR" ]] || pki_die "PKI directory does not exist; run platform-pki-init first: $PKI_DIR"
}

pki_prepare_control_state() {
  pki_require_private_dir "$PKI_DIR" 'PKI directory'
  pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
  local dir
  for dir in "$PKI_DIR/locks" "$PKI_DIR/state" "$PKI_DIR/state/rollover" "$PKI_DIR/state/rollovers" "$PKI_DIR/state/generation-reservations"; do
    if [[ ! -e $dir && ! -L $dir ]]; then
      mkdir -m 700 -- "$dir" 2>/dev/null || [[ -d $dir && ! -L $dir ]] || pki_die "Cannot create PKI control directory: $dir"
    fi
    pki_require_private_dir "$dir" 'PKI control directory'
  done
}

pki_require_no_symlink_path_components() {
  local path=$1 label=$2 current='' component
  local -a components

  IFS='/' read -r -a components <<<"$path"
  [[ $path != /* ]] || current=/
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    if [[ $current == / ]]; then
      current="/$component"
    elif [[ -n $current ]]; then
      current="$current/$component"
    else
      current=$component
    fi
    [[ ! -L $current ]] || pki_die "$label path component must not be a symlink: $current"
  done
}

pki_lifecycle_operation_lock() { printf '%s/locks/lifecycle\n' "$PKI_DIR"; }
pki_root_operation_lock() { printf '%s/locks/root\n' "$PKI_DIR"; }
pki_intermediate_operation_lock() { printf '%s/locks/intermediate\n' "$PKI_DIR"; }
pki_inventory_operation_lock() { printf '%s/locks/inventory\n' "$PKI_DIR"; }
pki_export_operation_lock() { printf '%s/locks/export\n' "$PKI_DIR"; }

declare -Ag PKI_LOCK_FDS=()
PKI_AUTO_LIFECYCLE=false

pki_require_private_dir() {
  local path=$1 label=$2 mode owner
  [[ -d $path && ! -L $path ]] || pki_die "$label must be a non-symlink directory: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label permissions: $path"
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label owner: $path"
  [[ $mode == 700 && $owner == "$(id -u)" ]] || pki_die "$label must be current-user-owned with mode 700: $path"
}

pki_acquire_operation_lock() {
  local path=$1 label=$2 lock_dir before after fd lifecycle
  pki_require_cmd flock
  lock_dir=$(dirname -- "$path")
  pki_require_private_dir "$lock_dir" 'PKI lock directory'
  lifecycle=$(pki_lifecycle_operation_lock)
  if [[ $path != "$lifecycle" && ! -v PKI_LOCK_FDS[$lifecycle] ]]; then
    pki_acquire_operation_lock "$lifecycle" 'PKI lifecycle operation'
    PKI_AUTO_LIFECYCLE=true
  fi
  [[ ! -v PKI_LOCK_FDS[$path] ]] || pki_die "Lock was acquired more than once: $path"
  if [[ ! -e $path && ! -L $path ]]; then
    ( umask 077; : >"$path" ) || pki_die "Cannot create $label lock: $path"
  fi
  [[ -f $path && ! -L $path ]] || pki_die "$label lock must be a non-symlink regular file: $path"
  before=$(stat -c '%d:%i:%u:%a:%h:%F' "$path") || pki_die "Cannot inspect $label lock: $path"
  [[ $before == *":$(id -u):600:1:regular empty file" || $before == *":$(id -u):600:1:regular file" ]] || \
    pki_die "$label lock must be current-user-owned, singly linked, and mode 600: $path"
  exec {fd}<>"$path" || pki_die "Cannot open $label lock: $path"
  after=$(stat -Lc '%d:%i:%u:%a:%h:%F' "/proc/self/fd/$fd") || {
    exec {fd}>&-
    pki_die "Cannot inspect opened $label lock descriptor"
  }
  [[ $after == "$before" && $(stat -c '%d:%i:%u:%a:%h:%F' "$path") == "$before" ]] || {
    exec {fd}>&-
    pki_die "$label lock identity changed while opening: $path"
  }
  flock -n "$fd" || {
    exec {fd}>&-
    pki_die "Another $label is in progress: $path"
  }
  PKI_LOCK_FDS[$path]=$fd
}

pki_release_operation_lock() {
  local path=$1 fd lifecycle
  [[ -v PKI_LOCK_FDS[$path] ]] || return 0
  fd=${PKI_LOCK_FDS[$path]}
  flock -u "$fd" || return 1
  exec {fd}>&-
  unset 'PKI_LOCK_FDS[$path]'
  lifecycle=$(pki_lifecycle_operation_lock)
  if [[ $path != "$lifecycle" && $PKI_AUTO_LIFECYCLE == true && ${#PKI_LOCK_FDS[@]} -eq 1 && -v PKI_LOCK_FDS[$lifecycle] ]]; then
    PKI_AUTO_LIFECYCLE=false
    pki_release_operation_lock "$lifecycle"
  fi
}

pki_recovery_journal() { printf '%s/state/rollover/journal\n' "$PKI_DIR"; }
pki_recovery_marker() { printf '%s/state/rollover/recovery-required\n' "$PKI_DIR"; }
pki_active_rollover_pointer() { printf '%s/state/active-rollover\n' "$PKI_DIR"; }
pki_rollover_transaction_dir() { [[ $1 =~ ^prepare-(root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+$ ]] || pki_die "Invalid rollover transaction ID: $1"; printf '%s/state/rollovers/%s\n' "$PKI_DIR" "$1"; }

pki_require_no_unresolved_journal() {
  local journal marker
  journal=$(pki_recovery_journal)
  marker=$(pki_recovery_marker)
  if [[ -e $marker || -L $marker ]]; then
    [[ -f $marker && ! -L $marker && $(stat -c '%u:%a:%h' "$marker") == "$(id -u):600:1" ]] || pki_die "PKI recovery marker is unsafe: $marker"
    pki_die "PKI recovery is required before this command can continue: $marker"
  fi
  if [[ -e $journal || -L $journal ]]; then
    pki_read_state_record "$journal" 'PKI recovery journal'
    [[ ${PKI_RECORD[operation]:-} != rollover-prepare && ${PKI_RECORD[committed]:-} == true ]] || \
      pki_die "PKI recovery is required before this command can continue: $journal"
  fi
}

pki_validate_root_generation() { [[ $1 =~ ^g[1-9][0-9]*$ ]] || pki_die "Invalid root generation ID: $1"; }
pki_validate_intermediate_generation() { [[ $1 =~ ^g[1-9][0-9]*-i[1-9][0-9]*$ ]] || pki_die "Invalid intermediate generation ID: $1"; }
pki_root_authority_dir() { pki_validate_root_generation "$1"; printf '%s/authorities/roots/%s\n' "$PKI_DIR" "$1"; }
pki_intermediate_authority_dir() { pki_validate_intermediate_generation "$1"; printf '%s/authorities/intermediates/%s\n' "$PKI_DIR" "$1"; }
pki_active_issuer_manifest() { printf '%s/state/active-issuer\n' "$PKI_DIR"; }
pki_bootstrap_root_manifest() { printf '%s/state/bootstrap-root\n' "$PKI_DIR"; }
pki_generation_reservation() { printf '%s/state/generation-reservations/%s\n' "$PKI_DIR" "$1"; }

pki_next_root_generation() {
  local path name number max=0
  local -a paths=()
  shopt -s nullglob
  paths=("$PKI_DIR/state/generation-reservations"/g* "$PKI_DIR/authorities/roots"/g*)
  shopt -u nullglob
  for path in "${paths[@]}"; do
    name=$(basename -- "$path")
    if [[ $path == */generation-reservations/* && $name =~ ^g[1-9][0-9]*-i[1-9][0-9]*$ ]]; then continue; fi
    [[ $name =~ ^g([1-9][0-9]*)$ ]] || pki_die "Invalid root generation state entry: $path"
    number=${BASH_REMATCH[1]}
    if [[ $path == */generation-reservations/* ]]; then
      [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' "$path") == "$(id -u):600:1" ]] || pki_die "Unsafe root generation reservation: $path"
    else
      pki_require_private_dir "$path" 'Root authority generation'
    fi
    (( 10#$number > max )) && max=$((10#$number))
  done
  printf 'g%d\n' "$((max + 1))"
}

pki_next_intermediate_generation() {
  local root=$1 path name number max=0
  local -a paths=()
  pki_validate_root_generation "$root"
  shopt -s nullglob
  paths=("$PKI_DIR/state/generation-reservations/$root"-i* "$PKI_DIR/authorities/intermediates/$root"-i*)
  shopt -u nullglob
  for path in "${paths[@]}"; do
    name=$(basename -- "$path")
    [[ $name =~ ^${root}-i([1-9][0-9]*)$ ]] || pki_die "Invalid intermediate generation state entry: $path"
    number=${BASH_REMATCH[1]}
    if [[ $path == */generation-reservations/* ]]; then
      [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' "$path") == "$(id -u):600:1" ]] || pki_die "Unsafe intermediate generation reservation: $path"
    else
      pki_require_private_dir "$path" 'Intermediate authority generation'
    fi
    (( 10#$number > max )) && max=$((10#$number))
  done
  printf '%s-i%d\n' "$root" "$((max + 1))"
}

pki_fsync_rename_parents() {
  local source_parent=$1 destination_parent=$2
  pki_fsync "$source_parent"
  [[ $destination_parent == "$source_parent" ]] || pki_fsync "$destination_parent"
}

pki_provenance_manifest() {
  local root=$1 path relative identity digest type
  pki_validate_managed_tree "$root" 'Migration provenance'
  while IFS= read -r -d '' path; do
    relative=${path#"$root"/}
    [[ $relative != "$path" && $relative != *'|'* && $relative != *$'\n'* ]] || pki_die "Migration provenance contains an unsafe path: $path"
    [[ $relative != provenance-manifest ]] || continue
    type=$(stat -c '%F' "$path")
    if [[ $type == directory ]]; then
      identity=$(pki_dir_identity "$path"); digest='-'
    else
      identity=$(pki_file_identity "$path")
      case $relative in
        quarantine/*) digest=secret ;;
        *) digest=$(sha256sum "$path"); digest=${digest%% *} ;;
      esac
    fi
    printf '%s|%s|%s|%s\n' "$type" "$relative" "$identity" "$digest"
  done < <(find "$root" -mindepth 1 -xdev -print0 | LC_ALL=C sort -z)
}

pki_validate_provenance_manifest() {
  local root=$1 manifest=$2 expected_identity=$3 expected_digest=$4 actual tmp
  pki_require_file_identity "$manifest" "$expected_identity" 'Migration provenance manifest'
  actual=$(sha256sum "$manifest"); [[ ${actual%% *} == "$expected_digest" ]] || pki_die 'Migration provenance manifest digest changed'
  tmp=$(mktemp "${TMPDIR:-/tmp}/platform-pki-provenance.XXXXXX") || pki_die 'Cannot stage migration provenance validation'
  pki_provenance_manifest "$root" >"$tmp" || { rm -f -- "$tmp"; pki_die 'Cannot generate migration provenance manifest'; }
  cmp -s "$manifest" "$tmp" || { rm -f -- "$tmp"; pki_die 'Migration provenance contents do not match their manifest'; }
  rm -f -- "$tmp"
}

pki_tree_manifest() {
  local root=$1 excluded=${2:-} excluded_second=${3:-} path relative type identity digest
  pki_validate_managed_tree "$root" 'Managed PKI tree'
  while IFS= read -r -d '' path; do
    relative=${path#"$root"/}
    [[ $relative != "$path" && $relative != *'|'* && $relative != *$'\n'* ]] || \
      pki_die "Managed PKI tree contains an unsafe path: $path"
    [[ -z $excluded || $relative != "$excluded" ]] || continue
    [[ -z $excluded_second || $relative != "$excluded_second" ]] || continue
    type=$(stat -c '%F' -- "$path")
    case $type in
      directory)
        identity=$(pki_dir_identity "$path")
        digest=-
        ;;
      'regular file'|'regular empty file')
        identity=$(pki_file_identity "$path")
        case $relative in
          private/*|*/private/*|*.key|*passphrase*) digest=secret ;;
          *) digest=$(sha256sum "$path"); digest=${digest%% *} ;;
        esac
        ;;
      *) pki_die "Managed PKI tree contains an unsupported object: $path" ;;
    esac
    printf '%s|%s|%s|%s\n' "$type" "$relative" "$identity" "$digest"
  done < <(find "$root" -mindepth 1 -xdev -print0 | LC_ALL=C sort -z)
}

pki_validate_tree_manifest() {
  local root=$1 manifest=$2 expected_identity=$3 expected_digest=$4 excluded=${5:-} actual tmp
  pki_require_file_identity "$manifest" "$expected_identity" 'PKI tree manifest'
  actual=$(sha256sum "$manifest"); [[ ${actual%% *} == "$expected_digest" ]] || pki_die 'PKI tree manifest digest changed'
  tmp=$(mktemp "${TMPDIR:-/tmp}/platform-pki-tree.XXXXXX") || pki_die 'Cannot stage PKI tree validation'
  pki_tree_manifest "$root" "$excluded" >"$tmp" || { rm -f -- "$tmp"; pki_die 'Cannot generate PKI tree manifest'; }
  cmp -s "$manifest" "$tmp" || { rm -f -- "$tmp"; pki_die "PKI tree contents do not match their manifest: $root"; }
  rm -f -- "$tmp"
}

pki_require_ca_certificate_profile() {
  local certificate=$1 pathlen=$2 label=$3 constraints usage
  constraints=$(openssl x509 -in "$certificate" -noout -ext basicConstraints) || pki_die "$label Basic Constraints are unreadable"
  usage=$(openssl x509 -in "$certificate" -noout -ext keyUsage) || pki_die "$label Key Usage is unreadable"
  [[ $constraints == $'X509v3 Basic Constraints: critical\n    CA:TRUE, pathlen:'"$pathlen" ]] || \
    pki_die "$label must have critical CA:TRUE Basic Constraints with pathlen:$pathlen"
  [[ $usage == $'X509v3 Key Usage: critical\n    Certificate Sign, CRL Sign' ]] || \
    pki_die "$label must have critical Certificate Sign and CRL Sign Key Usage only"
}

pki_require_ca_self_signature() {
  local certificate=$1 label=$2
  openssl verify -check_ss_sig -CAfile "$certificate" "$certificate" >/dev/null || pki_die "$label self-signature is invalid"
}

pki_read_pair_manifest() {
  local path=$1 prefix=$2 first second mode owner links before after fd
  local -a lines=()
  [[ -f $path && ! -L $path ]] || pki_die "$prefix manifest must be a non-symlink regular file: $path"
  mode=$(stat -c '%a' "$path"); owner=$(stat -c '%u' "$path"); links=$(stat -c '%h' "$path")
  [[ $mode == 600 && $owner == "$(id -u)" && $links == 1 ]] || \
    pki_die "$prefix manifest must be current-user-owned, singly linked, and mode 600: $path"
  before=$(pki_file_identity "$path") || pki_die "Cannot inspect $prefix manifest"
  exec {fd}<"$path" || pki_die "Cannot open $prefix manifest"
  after=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$fd") || { exec {fd}<&-; pki_die "Cannot inspect opened $prefix manifest"; }
  [[ $before == "$after" && $(pki_file_identity "$path") == "$before" ]] || { exec {fd}<&-; pki_die "$prefix manifest identity changed while opening"; }
  mapfile -t -u "$fd" lines
  exec {fd}<&-
  [[ $(pki_file_identity "$path") == "$before" ]] || pki_die "$prefix manifest changed while reading"
  [[ ${#lines[@]} -eq 2 ]] || pki_die "$prefix manifest has invalid content: $path"
  first=${lines[0]}; second=${lines[1]}
  [[ $first == root=* && $second == intermediate=* ]] || pki_die "$prefix manifest has invalid content: $path"
  ACTIVE_ROOT_ID=${first#root=}
  ACTIVE_INTERMEDIATE_ID=${second#intermediate=}
  pki_validate_root_generation "$ACTIVE_ROOT_ID"
  pki_validate_intermediate_generation "$ACTIVE_INTERMEDIATE_ID"
  [[ $ACTIVE_INTERMEDIATE_ID == "$ACTIVE_ROOT_ID"-i* ]] || pki_die "$prefix manifest selects mismatched generations"
}

pki_load_active_issuer_snapshot() {
  pki_require_no_unresolved_journal
  pki_read_pair_manifest "$(pki_active_issuer_manifest)" 'Active issuer'
  ROOT_CA_DIR=$(pki_root_authority_dir "$ACTIVE_ROOT_ID")
  INTERMEDIATE_CA_DIR=$(pki_intermediate_authority_dir "$ACTIVE_INTERMEDIATE_ID")
  pki_require_private_dir "$ROOT_CA_DIR" 'Root authority generation'
  pki_require_private_dir "$INTERMEDIATE_CA_DIR" 'Intermediate authority generation'
  openssl verify -CAfile "$(pki_root_cert)" "$(pki_intermediate_cert)" >/dev/null || \
    pki_die 'Active intermediate does not verify against its recorded root'
}

pki_service_issuer() { printf '%s/issuer\n' "$(pki_service_dir "$1")"; }

pki_load_service_issuer_snapshot() {
  local service=$1 saved_root=${ACTIVE_ROOT_ID:-} saved_intermediate=${ACTIVE_INTERMEDIATE_ID:-}
  pki_read_pair_manifest "$(pki_service_issuer "$service")" "Service $service issuer"
  SERVICE_ROOT_ID=$ACTIVE_ROOT_ID
  SERVICE_INTERMEDIATE_ID=$ACTIVE_INTERMEDIATE_ID
  ACTIVE_ROOT_ID=$saved_root
  ACTIVE_INTERMEDIATE_ID=$saved_intermediate
}

pki_atomic_write() {
  local destination=$1 content=$2 directory tmp line state=absent state_object='' guard='' published
  directory=$(dirname -- "$destination")
  pki_require_private_dir "$directory" 'State publication directory'
  if [[ -e $destination || -L $destination ]]; then
    [[ -f $destination && ! -L $destination && $(stat -c '%u:%a:%h' "$destination") == "$(id -u):600:1" ]] || \
      pki_die "State destination is unsafe: $destination"
    state=$(pki_file_identity "$destination") || pki_die "Cannot inspect state destination: $destination"
    state_object=$(stat -c '%d:%i' "$destination")
  fi
  tmp=$(mktemp "$directory/.platform-pki-state.XXXXXX") || pki_die "Cannot stage state file: $destination"
  : >"$tmp"
  while IFS= read -r line || [[ -n $line ]]; do
    # Bashly indents command source; normalize generated multiline literals.
    [[ $line != '  '* ]] || line=${line#'  '}
    [[ -n $line ]] || continue
    printf '%s\n' "$line" >>"$tmp" || { rm -f -- "$tmp"; pki_die "Cannot write staged state file: $destination"; }
  done < <(printf '%s' "$content")
  chmod 600 "$tmp" || { rm -f -- "$tmp"; pki_die "Cannot secure staged state file: $destination"; }
  pki_fsync "$tmp"
  published=$(pki_file_object_state "$tmp")
  if [[ $state == absent ]]; then
    ln -- "$tmp" "$destination" || { rm -f -- "$tmp"; pki_die "State destination appeared before publication: $destination"; }
    rm -f -- "$tmp"
    [[ $(pki_file_object_state "$destination") == "$published" ]] || pki_die "State publication identity check failed: $destination"
  else
    guard=$(mktemp "$directory/.platform-pki-state-guard.XXXXXX") || { rm -f -- "$tmp"; pki_die 'Cannot stage state publication guard'; }
    rm -f -- "$guard"
    ln -- "$destination" "$guard" || { rm -f -- "$tmp"; pki_die "State destination changed before publication: $destination"; }
    [[ $(stat -c '%d:%i' "$destination") == "$state_object" && $(stat -c '%d:%i' "$guard") == "$state_object" && $(stat -c '%h' "$destination") == 2 ]] || \
      { rm -f -- "$tmp" "$guard"; pki_die "State destination identity changed before publication: $destination"; }
    mv -f -- "$tmp" "$destination" || { rm -f -- "$tmp" "$guard"; pki_die "Cannot publish state file: $destination"; }
    [[ $(pki_file_object_state "$destination") == "$published" && $(stat -c '%d:%i' "$guard") == "$state_object" && $(stat -c '%h' "$guard") == 1 ]] || \
      pki_die "State publication identity check failed: $destination"
    rm -f -- "$guard"
  fi
  pki_fsync "$directory"
}

pki_write_journal() {
  pki_atomic_write "$1" "$2"
  pki_fsync "$1"
  pki_fsync "$(dirname -- "$1")"
}

pki_publish_staged_file() {
  local source=$1 destination=$2 directory expected_object='' published guard destination_mode
  directory=$(dirname -- "$destination")
  [[ -f $source && ! -L $source && $(stat -c '%u:%h' "$source") == "$(id -u):1" ]] || pki_die "Staged publication file is unsafe: $source"
  pki_fsync "$source"; published=$(pki_file_object_state "$source")
  if [[ -e $destination || -L $destination ]]; then
    [[ -f $destination && ! -L $destination && $(stat -c '%u:%h' "$destination") == "$(id -u):1" ]] || pki_die "Publication destination is unsafe: $destination"
    destination_mode=$(stat -c '%a' "$destination"); (( (8#$destination_mode & 022) == 0 )) || pki_die "Publication destination is writable by group or world: $destination"
    expected_object=$(stat -c '%d:%i' "$destination")
    guard=$(mktemp "$directory/.platform-pki-publish-guard.XXXXXX"); rm -f -- "$guard"
    ln -- "$destination" "$guard" || pki_die "Publication destination changed before guard: $destination"
    [[ $(stat -c '%d:%i:%h' "$destination") == "$expected_object:2" && $(stat -c '%d:%i' "$guard") == "$expected_object" ]] || pki_die "Publication destination identity changed before replacement: $destination"
    mv -f -T -- "$source" "$destination" || pki_die "Cannot publish staged file: $destination"
    [[ $(pki_file_object_state "$destination") == "$published" && $(stat -c '%d:%i:%h' "$guard") == "$expected_object:1" ]] || pki_die "Published file identity is invalid: $destination"
    rm -f -- "$guard"
  else
    ln -- "$source" "$destination" || pki_die "Publication destination appeared: $destination"
    rm -f -- "$source"
    [[ $(pki_file_object_state "$destination") == "$published" ]] || pki_die "Published file identity is invalid: $destination"
  fi
  pki_fsync "$directory"
}

pki_publish_staged_file_exact() {
  local source=$1 destination=$2 directory expected published_object guard destination_mode
  directory=$(dirname -- "$destination")
  [[ -f $source && ! -L $source && $(stat -c '%u:%h' "$source") == "$(id -u):1" ]] || pki_die "Staged publication file is unsafe: $source"
  pki_fsync "$source"; published_object=$(stat -c '%d:%i' "$source")
  if [[ -e $destination || -L $destination ]]; then
    [[ -f $destination && ! -L $destination && $(stat -c '%u:%h' "$destination") == "$(id -u):1" ]] || pki_die "Publication destination is unsafe: $destination"
    destination_mode=$(stat -c '%a' "$destination"); (( (8#$destination_mode & 022) == 0 )) || pki_die "Publication destination is writable by group or world: $destination"
    expected=$(pki_file_identity "$destination")
    guard=$(mktemp "$directory/.platform-pki-publish-guard.XXXXXX"); rm -f -- "$guard"
    [[ $(pki_file_identity "$destination") == "$expected" ]] || pki_die "Publication destination identity changed before guard: $destination"
    ln -- "$destination" "$guard" || pki_die "Publication destination changed before guard: $destination"
    [[ $(stat -c '%d:%i:%h' "$destination") == "$(stat -c '%d:%i' "$guard"):2" ]] || pki_die "Publication destination identity changed before replacement: $destination"
    mv --no-copy -f -T -- "$source" "$destination" || pki_die "Cannot publish staged file: $destination"
    [[ $(stat -c '%d:%i' "$destination") == "$published_object" && $(stat -c '%h' "$guard") == 1 ]] || pki_die "Published file identity is invalid: $destination"
    rm -f -- "$guard"
  else
    mv --no-copy --update=none-fail -T -- "$source" "$destination" || pki_die "Publication destination appeared: $destination"
    [[ $(stat -c '%d:%i' "$destination") == "$published_object" ]] || pki_die "Published file identity is invalid: $destination"
  fi
  pki_fsync "$directory"
  # shellcheck disable=SC2034  # Consumed by Phase 6A callers after sourcing this library.
  PKI_PUBLISHED_FILE_IDENTITY=$(pki_file_identity "$destination")
}

pki_read_state_record() {
  local path=$1 prefix=$2 line key value before after fd
  unset -v PKI_RECORD
  declare -gA PKI_RECORD=()
  [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' "$path") == "$(id -u):600:1" ]] || pki_die "$prefix is unsafe: $path"
  before=$(pki_file_identity "$path"); exec {fd}<"$path" || pki_die "Cannot open $prefix"
  after=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$fd")
  [[ $before == "$after" && $(pki_file_identity "$path") == "$before" ]] || { exec {fd}<&-; pki_die "$prefix identity changed while opening"; }
  while IFS= read -r -u "$fd" line || [[ -n $line ]]; do
    [[ $line =~ ^([a-z0-9_]+)=([^[:cntrl:]]*)$ ]] || { exec {fd}<&-; pki_die "$prefix has invalid content"; }
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    [[ ! -v PKI_RECORD[$key] ]] || { exec {fd}<&-; pki_die "$prefix contains duplicate field: $key"; }
    PKI_RECORD[$key]=$value
  done
  exec {fd}<&-
  [[ $(pki_file_identity "$path") == "$before" ]] || pki_die "$prefix changed while reading"
}

pki_private_metadata_digest() {
  local tmp path digest
  tmp=$(mktemp "${TMPDIR:-/tmp}/platform-pki-private-metadata.XXXXXX") || pki_die 'Cannot stage private metadata manifest'
  while IFS= read -r -d '' path; do
    case ${path#"$PKI_DIR"/} in
      */private/*|private/*|*/quarantine/*|quarantine/*|*passphrase*|*pass-file*|*.key) ;;
      *) continue ;;
    esac
    [[ -f $path && ! -L $path ]] || { rm -f "$tmp"; pki_die "Private state path is unsafe: $path"; }
    printf '%s|%s\n' "${path#"$PKI_DIR"/}" "$(stat -c '%d:%i:%u:%a:%h:%s:%y:%z:%F' "$path")" >>"$tmp"
  done < <(find "$PKI_DIR" \( -type f -o -type l \) -print0)
  LC_ALL=C sort -o "$tmp" "$tmp"; digest=$(sha256sum "$tmp"); rm -f "$tmp"; printf '%s\n' "${digest%% *}"
}

pki_validate_managed_tree() {
  local root=$1 label=$2 path mode owner links type
  [[ -d $root && ! -L $root ]] || pki_die "$label must be a non-symlink directory: $root"
  while IFS= read -r -d '' path; do
    [[ ! -L $path ]] || pki_die "$label contains a symbolic link: $path"
    owner=$(stat -c '%u' "$path"); mode=$(stat -c '%a' "$path"); links=$(stat -c '%h' "$path"); type=$(stat -c '%F' "$path")
    [[ $owner == "$(id -u)" ]] || pki_die "$label contains foreign-owned state: $path"
    (( (8#$mode & 022) == 0 )) || pki_die "$label contains group- or world-writable state: $path"
    case $type in
      directory) ;;
      'regular file'|'regular empty file') [[ $links == 1 ]] || pki_die "$label contains hard-linked state: $path" ;;
      *) pki_die "$label contains an unsupported path type: $path" ;;
    esac
  done < <(find "$root" -xdev -print0)
}

pki_validate_legacy_state() {
  local service path required certs_dir
  local -A inventory_services=()
  pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
  pki_validate_managed_tree "$PKI_DIR/root-ca" 'Legacy root CA'
  pki_validate_managed_tree "$PKI_DIR/intermediate-ca" 'Legacy intermediate CA'
  pki_validate_managed_tree "$PKI_DIR/services" 'Legacy service state'
  pki_validate_managed_tree "$PKI_DIR/export" 'Legacy export state'
  for required in \
    root-ca/private/root-ca.key root-ca/certs/root-ca.crt root-ca/openssl.cnf root-ca/index.txt root-ca/index.txt.attr root-ca/serial root-ca/crlnumber \
    intermediate-ca/private/intermediate-ca.key intermediate-ca/certs/intermediate-ca.crt intermediate-ca/certs/ca-chain.crt \
    intermediate-ca/openssl.cnf intermediate-ca/index.txt intermediate-ca/index.txt.attr intermediate-ca/serial intermediate-ca/crlnumber; do
    [[ -f $PKI_DIR/$required && ! -L $PKI_DIR/$required ]] || pki_die "Legacy PKI state is incomplete: $PKI_DIR/$required"
  done
  for service in $(pki_inventory_services); do inventory_services[$service]=1; done
  while IFS= read -r -d '' path; do
    service=$(basename -- "$path")
    pki_validate_service_name "$service"
    [[ -v inventory_services[$service] ]] || pki_die "Legacy service directory is absent from inventory: $service"
    certs_dir="$path/certs"
    if [[ -d $certs_dir ]]; then
      [[ -f $certs_dir/tls.crt && ! -L $certs_dir/tls.crt ]] || pki_die "Legacy service certificate directory is incomplete: $service"
      while IFS= read -r -d '' required; do [[ $required == "$certs_dir/tls.crt" ]] || pki_die "Legacy service certificate directory contains unexpected state: $required"; done < <(find "$certs_dir" -mindepth 1 -maxdepth 1 -type f -print0)
    fi
  done < <(find "$PKI_DIR/services" -mindepth 1 -maxdepth 1 -type d -print0)
  while IFS= read -r -d '' path; do
    service=${path#"$PKI_DIR/services/"}; service=${service%%/*}
    [[ -v inventory_services[$service] ]] || pki_die "Legacy service certificate is absent from inventory: $service"
    openssl x509 -in "$path" -noout >/dev/null || pki_die "Legacy service certificate is invalid: $path"
  done < <(find "$PKI_DIR/services" -mindepth 3 -maxdepth 3 -path '*/certs/tls.crt' -type f -print0)
  openssl x509 -in "$PKI_DIR/root-ca/certs/root-ca.crt" -noout >/dev/null || pki_die 'Legacy root certificate is invalid'
  openssl x509 -in "$PKI_DIR/intermediate-ca/certs/intermediate-ca.crt" -noout >/dev/null || pki_die 'Legacy intermediate certificate is invalid'
  for path in "$PKI_DIR/root-ca/newcerts" "$PKI_DIR/intermediate-ca/newcerts"; do
    while IFS= read -r -d '' required; do openssl x509 -in "$required" -noout >/dev/null || pki_die "Legacy newcerts entry is invalid: $required"; done < <(find "$path" -mindepth 1 -maxdepth 1 -type f -print0)
  done
}

pki_validate_child_validity() {
  local child=$1 issuer=$2 safety_days=$3 child_start child_end issuer_end now
  pki_validate_days "$safety_days"
  child_start=$(date -u -d "$(openssl x509 -in "$child" -noout -startdate | sed 's/^notBefore=//')" +%s) || pki_die 'Cannot parse child certificate notBefore'
  child_end=$(date -u -d "$(openssl x509 -in "$child" -noout -enddate | sed 's/^notAfter=//')" +%s) || pki_die 'Cannot parse child certificate notAfter'
  issuer_end=$(date -u -d "$(openssl x509 -in "$issuer" -noout -enddate | sed 's/^notAfter=//')" +%s) || pki_die 'Cannot parse issuer certificate notAfter'
  now=$(date -u +%s)
  (( child_start <= now + 300 )) || pki_die 'Child certificate notBefore is more than five minutes in the future'
  (( child_start <= now && child_end > now )) || pki_die 'Child certificate is not currently valid'
  (( child_end <= issuer_end - 10#$safety_days * 86400 )) || pki_die "Child certificate exceeds issuer validity safety margin of $safety_days day(s)"
}

pki_publish_active_issuer() {
  local root=$1 intermediate=$2
  pki_validate_root_generation "$root"
  pki_validate_intermediate_generation "$intermediate"
  [[ $intermediate == "$root"-i* ]] || pki_die 'Cannot publish mismatched active issuer generations'
  pki_atomic_write "$(pki_active_issuer_manifest)" "root=$root
intermediate=$intermediate
"
}

pki_publish_service_issuer() {
  local service=$1 root=$2 intermediate=$3
  pki_atomic_write "$(pki_service_issuer "$service")" "root=$root
intermediate=$intermediate
"
}

pki_detect_layout() {
  local legacy_any=false legacy_complete=false generation_any=false generation_complete=false
  local active authorities roots intermediates first second extra root_id intermediate_id path
  local -a generation_paths
  [[ ! -e $PKI_DIR/root-ca && ! -L $PKI_DIR/root-ca && ! -e $PKI_DIR/intermediate-ca && ! -L $PKI_DIR/intermediate-ca ]] || legacy_any=true
  [[ -d $PKI_DIR/root-ca && ! -L $PKI_DIR/root-ca && -d $PKI_DIR/intermediate-ca && ! -L $PKI_DIR/intermediate-ca ]] && legacy_complete=true
  active=$(pki_active_issuer_manifest)
  authorities=$PKI_DIR/authorities
  roots=$authorities/roots
  intermediates=$authorities/intermediates
  for path in "$authorities" "$roots" "$intermediates"; do
    if [[ (-e $path || -L $path) && (! -d $path || -L $path) ]]; then
      generation_any=true
      break
    fi
  done
  generation_paths=(
    "$active"
    "$(pki_bootstrap_root_manifest)"
    "$roots"/* "$roots"/.[!.]* "$roots"/..?*
    "$intermediates"/* "$intermediates"/.[!.]* "$intermediates"/..?*
  )
  for path in "${generation_paths[@]}"; do
    [[ ! -e $path && ! -L $path ]] || { generation_any=true; break; }
  done
  if [[ -f $active && ! -L $active ]]; then
    IFS= read -r first <"$active" || first=''
    IFS= read -r second < <(tail -n +2 "$active") || second=''
    IFS= read -r extra < <(tail -n +3 "$active") || extra=''
    root_id=${first#root=}; intermediate_id=${second#intermediate=}
    if [[ -z $extra && $first == root=* && $second == intermediate=* &&
      $root_id =~ ^g[1-9][0-9]*$ && $intermediate_id =~ ^g[1-9][0-9]*-i[1-9][0-9]*$ &&
      $intermediate_id == "$root_id"-i* && -d $PKI_DIR/authorities/roots/$root_id &&
      ! -L $PKI_DIR/authorities/roots/$root_id && -d $PKI_DIR/authorities/intermediates/$intermediate_id &&
      ! -L $PKI_DIR/authorities/intermediates/$intermediate_id ]]; then
      generation_complete=true
    fi
  fi
  if [[ $legacy_complete == true && $generation_any == false ]]; then printf '%s\n' legacy
  elif [[ $generation_complete == true && $legacy_any == false ]]; then printf '%s\n' generation
  elif [[ $legacy_any == false && $generation_any == false ]]; then printf '%s\n' empty
  else printf '%s\n' partial; fi
}

pki_die_legacy_migration_required() {
  pki_die 'Legacy PKI state requires migration; create a fresh backup and follow platform-pki-ca-rollover status/migrate'
}

pki_require_generation_layout() {
  local layout
  pki_require_no_unresolved_journal
  layout=$(pki_detect_layout)
  case $layout in
    generation) ;;
    legacy) pki_die_legacy_migration_required ;;
    empty) pki_die 'Generation-aware PKI state does not exist; create the root and intermediate authorities first' ;;
    *) pki_die 'PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status' ;;
  esac
}

pki_require_empty_authority_layout() {
  local layout
  layout=$(pki_detect_layout)
  case $layout in
    empty) ;;
    legacy) pki_die_legacy_migration_required ;;
    *) pki_die 'PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status' ;;
  esac
}

pki_reject_legacy_authorities() {
  local layout
  layout=$(pki_detect_layout)
  case $layout in
    legacy) pki_die_legacy_migration_required ;;
    partial)
      if [[ -e $PKI_DIR/root-ca || -L $PKI_DIR/root-ca || -e $PKI_DIR/intermediate-ca || -L $PKI_DIR/intermediate-ca ]]; then
        pki_die 'PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status'
      fi
      ;;
  esac
}

pki_public_state_digest() {
  local layout=$1 tmp path hash relative
  local -a roots=()
  pki_require_cmd sha256sum
  tmp=$(mktemp "${TMPDIR:-/tmp}/platform-pki-state-manifest.XXXXXX") || pki_die 'Cannot stage public state manifest'
  case $layout in
    legacy) roots=("$PKI_DIR/inventory" "$PKI_DIR/root-ca" "$PKI_DIR/intermediate-ca" "$PKI_DIR/services" "$PKI_DIR/export") ;;
    generation) roots=("$PKI_DIR/inventory" "$PKI_DIR/authorities" "$PKI_DIR/state/active-issuer" "$PKI_DIR/services" "$PKI_DIR/export") ;;
    *) rm -f "$tmp"; pki_die "Cannot digest unsupported PKI layout: $layout" ;;
  esac
  for path in "${roots[@]}"; do
    [[ -e $path ]] || continue
    if [[ -f $path ]]; then
      hash=$(sha256sum "$path"); printf '%s  %s\n' "${hash%% *}" "${path#"$PKI_DIR"/}" >>"$tmp"
      continue
    fi
    while IFS= read -r -d '' relative; do
      case $relative in */private/*|*/backups/*|*.key) continue ;; esac
      hash=$(sha256sum "$relative") || { rm -f "$tmp"; pki_die "Cannot hash public PKI state: $relative"; }
      printf '%s  %s\n' "${hash%% *}" "${relative#"$PKI_DIR"/}" >>"$tmp"
    done < <(find "$path" -type f -print0)
  done
  LC_ALL=C sort -o "$tmp" "$tmp"
  hash=$(sha256sum "$tmp"); rm -f "$tmp"; printf '%s\n' "${hash%% *}"
}

pki_prepare_dir() {
  mkdir -p "$1"
  chmod 700 "$1"
}

pki_prepare_public_dir() {
  mkdir -p "$1"
  chmod 755 "$1"
}

pki_init_ca_db() {
  local ca_dir=$1
  [[ -f "${ca_dir}/index.txt" ]] || : >"${ca_dir}/index.txt"
  [[ -f "${ca_dir}/index.txt.attr" ]] || printf '%s\n' 'unique_subject = no' >"${ca_dir}/index.txt.attr"
  [[ -f "${ca_dir}/serial" ]] || printf '%s\n' '1000' >"${ca_dir}/serial"
  [[ -f "${ca_dir}/crlnumber" ]] || printf '%s\n' '1000' >"${ca_dir}/crlnumber"
}

pki_service_dir() {
  printf '%s/services/%s\n' "$PKI_DIR" "$1"
}

pki_service_key() {
  printf '%s/private/tls.key\n' "$(pki_service_dir "$1")"
}

pki_service_cert() {
  printf '%s/certs/tls.crt\n' "$(pki_service_dir "$1")"
}

pki_service_chain() {
  printf '%s/chain/ca-chain.crt\n' "$(pki_service_dir "$1")"
}

pki_service_fullchain() {
  printf '%s/chain/fullchain.crt\n' "$(pki_service_dir "$1")"
}

pki_new_service_archive_dir() {
  local service=$1
  local archive_root base candidate n

  archive_root="$(pki_service_dir "$service")/archive"
  mkdir -p "$archive_root"
  chmod 700 "$archive_root"
  base="${archive_root}/$(date -u '+%Y%m%d-%H%M%S')"
  candidate=$base
  n=1
  while [[ -e "$candidate" ]]; do
    candidate=$(printf '%s-%02d' "$base" "$n")
    n=$((n + 1))
  done
  mkdir -p "$candidate"
  chmod 700 "$candidate"
  printf '%s\n' "$candidate"
}

pki_root_cert() {
  local id=${1:-${ACTIVE_ROOT_ID:-}}
  [[ -n $id ]] || pki_die 'Root generation snapshot is not loaded'
  printf '%s/certs/root-ca.crt\n' "$(pki_root_authority_dir "$id")"
}

pki_root_key() {
  local id=${1:-${ACTIVE_ROOT_ID:-}}
  [[ -n $id ]] || pki_die 'Root generation snapshot is not loaded'
  printf '%s/private/root-ca.key\n' "$(pki_root_authority_dir "$id")"
}

pki_intermediate_cert() {
  local id=${1:-${ACTIVE_INTERMEDIATE_ID:-}}
  [[ -n $id ]] || pki_die 'Intermediate generation snapshot is not loaded'
  printf '%s/certs/intermediate-ca.crt\n' "$(pki_intermediate_authority_dir "$id")"
}

pki_intermediate_key() {
  local id=${1:-${ACTIVE_INTERMEDIATE_ID:-}}
  [[ -n $id ]] || pki_die 'Intermediate generation snapshot is not loaded'
  printf '%s/private/intermediate-ca.key\n' "$(pki_intermediate_authority_dir "$id")"
}

pki_ca_chain() {
  local id=${1:-${ACTIVE_INTERMEDIATE_ID:-}}
  [[ -n $id ]] || pki_die 'Intermediate generation snapshot is not loaded'
  printf '%s/certs/ca-chain.crt\n' "$(pki_intermediate_authority_dir "$id")"
}

pki_write_root_config() {
  local path=$1
  local country=$2
  local org=$3
  local name=$4
  local ca_dir=${5:-${ROOT_CA_DIR:-}}
  [[ -n $ca_dir ]] || pki_die 'Root authority directory is not resolved'
  cat >"$path" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = $ca_dir
certs = \$dir/certs
crl_dir = \$dir/crl
new_certs_dir = \$dir/newcerts
database = \$dir/index.txt
serial = \$dir/serial
private_key = \$dir/private/root-ca.key
certificate = \$dir/certs/root-ca.crt
default_md = sha384
policy = policy_platform
email_in_dn = no
copy_extensions = none
unique_subject = no

[ policy_platform ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
prompt = no
distinguished_name = dn
default_md = sha384
x509_extensions = v3_root_ca
string_mask = utf8only

[ dn ]
C = $country
O = $org
CN = $name

[ v3_root_ca ]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
}

pki_write_intermediate_config() {
  local path=$1
  local country=$2
  local org=$3
  local name=$4
  local ca_dir=${5:-${INTERMEDIATE_CA_DIR:-}}
  [[ -n $ca_dir ]] || pki_die 'Intermediate authority directory is not resolved'
  cat >"$path" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = $ca_dir
certs = \$dir/certs
crl_dir = \$dir/crl
new_certs_dir = \$dir/newcerts
database = \$dir/index.txt
serial = \$dir/serial
private_key = \$dir/private/intermediate-ca.key
certificate = \$dir/certs/intermediate-ca.crt
default_md = sha384
policy = policy_platform
email_in_dn = no
copy_extensions = none
unique_subject = no

[ policy_platform ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
prompt = no
distinguished_name = dn
default_md = sha384
string_mask = utf8only

[ dn ]
C = $country
O = $org
CN = $name

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
}

pki_write_service_config() {
  local path=$1
  local common_name=$2
  local dns_file=$3
  local ips_file=$4
  local n=1
  local value

  cat >"$path" <<EOF
[ req ]
prompt = no
distinguished_name = dn
default_md = sha384
req_extensions = req_ext
string_mask = utf8only

[ dn ]
CN = $common_name

[ req_ext ]
subjectAltName = @alt_names

[ server_cert ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ alt_names ]
EOF

  while IFS= read -r value || [[ -n "$value" ]]; do
    [[ -n "$value" ]] || continue
    printf 'DNS.%d = %s\n' "$n" "$value" >>"$path"
    n=$((n + 1))
  done <"$dns_file"

  n=1
  while IFS= read -r value || [[ -n "$value" ]]; do
    [[ -n "$value" ]] || continue
    printf 'IP.%d = %s\n' "$n" "$value" >>"$path"
    n=$((n + 1))
  done <"$ips_file"
}

pki_make_public_key_file() {
  local input_type=$1
  local input=$2
  local output=$3

  case $input_type in
    cert) openssl x509 -in "$input" -pubkey -noout >"$output" ;;
    key) openssl pkey -in "$input" -pubout >"$output" ;;
    *) pki_die "Unsupported public key input type: $input_type" ;;
  esac
}

pki_key_matches_cert() {
  local key=$1
  local cert=$2
  local tmpdir
  tmpdir=$(mktemp -d)
  pki_make_public_key_file cert "$cert" "$tmpdir/cert.pub"
  pki_make_public_key_file key "$key" "$tmpdir/key.pub"
  if cmp -s "$tmpdir/cert.pub" "$tmpdir/key.pub"; then
    rm -rf "$tmpdir"
    return 0
  fi
  rm -rf "$tmpdir"
  return 1
}

pki_cert_days_left() {
  local cert=$1
  local not_after end_epoch now_epoch
  not_after=$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')
  end_epoch=$(date -u -d "$not_after" +%s)
  now_epoch=$(date -u +%s)
  printf '%s\n' $(( (end_epoch - now_epoch) / 86400 ))
}

pki_cert_not_after_iso() {
  local cert=$1
  local not_after
  not_after=$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')
  date -u -d "$not_after" '+%Y-%m-%dT%H:%M:%SZ'
}

pki_cert_has_dns_san() {
  openssl x509 -in "$1" -noout -ext subjectAltName | grep -F "DNS:$2" >/dev/null 2>&1
}

pki_cert_has_ip_san() {
  openssl x509 -in "$1" -noout -ext subjectAltName | grep -F "IP Address:$2" >/dev/null 2>&1
}

pki_cert_has_ca_false() {
  openssl x509 -in "$1" -noout -ext basicConstraints | grep -F 'CA:FALSE' >/dev/null 2>&1
}

pki_cert_has_server_auth() {
  openssl x509 -in "$1" -noout -ext extendedKeyUsage | grep -F 'TLS Web Server Authentication' >/dev/null 2>&1
}

pki_verify_service_certificate() {
  local service=$1 min_days=$2 key cert root_cert int_cert dns ip

  pki_require_service_in_inventory "$service"
  key=$(pki_service_key "$service")
  cert=$(pki_service_cert "$service")
  pki_load_service_issuer_snapshot "$service"
  root_cert=$(pki_root_cert "$SERVICE_ROOT_ID")
  int_cert=$(pki_intermediate_cert "$SERVICE_INTERMEDIATE_ID")
  pki_require_file "$key"
  pki_require_file "$cert"
  pki_require_file "$root_cert"
  pki_require_file "$int_cert"
  openssl verify -CAfile "$root_cert" -untrusted "$int_cert" "$cert" >/dev/null
  pki_key_matches_cert "$key" "$cert" || pki_die "Private key does not match certificate for service: $service"
  pki_cert_has_ca_false "$cert" || pki_die "Certificate is missing CA:false: $cert"
  pki_cert_has_server_auth "$cert" || pki_die "Certificate is missing serverAuth EKU: $cert"
  while IFS= read -r dns || [[ -n $dns ]]; do
    [[ -n $dns ]] || continue
    pki_cert_has_dns_san "$cert" "$dns" || pki_die "Certificate is missing DNS SAN '${dns}': $cert"
  done < <(pki_inventory_array "$service" dns)
  while IFS= read -r ip || [[ -n $ip ]]; do
    [[ -n $ip ]] || continue
    pki_cert_has_ip_san "$cert" "$ip" || pki_die "Certificate is missing IP SAN '${ip}': $cert"
  done < <(pki_inventory_array "$service" ips)
  openssl x509 -in "$cert" -checkend "$(( min_days * 86400 ))" -noout >/dev/null || \
    pki_die "Certificate has less than ${min_days} days remaining: $cert"
}
