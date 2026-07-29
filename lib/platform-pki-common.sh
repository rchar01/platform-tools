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

pki_root_operation_lock() {
  printf '%s/root-ca/.platform-pki-root-operation.lock\n' "$PKI_DIR"
}

pki_intermediate_operation_lock() {
  printf '%s/intermediate-ca/.platform-pki-intermediate-operation.lock\n' "$PKI_DIR"
}

pki_inventory_operation_lock() {
  printf '%s/inventory/.platform-pki-inventory-operation.lock\n' "$PKI_DIR"
}

pki_acquire_operation_lock() {
  local path=$1 label=$2

  mkdir -- "$path" 2>/dev/null || pki_die "Another $label is in progress: $path"
  chmod 700 "$path" || {
    rmdir "$path" 2>/dev/null || true
    pki_die "Cannot secure $label lock: $path"
  }
}

pki_release_operation_lock() {
  local path=$1

  rmdir "$path"
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
  printf '%s/root-ca/certs/root-ca.crt\n' "$PKI_DIR"
}

pki_root_key() {
  printf '%s/root-ca/private/root-ca.key\n' "$PKI_DIR"
}

pki_intermediate_cert() {
  printf '%s/intermediate-ca/certs/intermediate-ca.crt\n' "$PKI_DIR"
}

pki_intermediate_key() {
  printf '%s/intermediate-ca/private/intermediate-ca.key\n' "$PKI_DIR"
}

pki_ca_chain() {
  printf '%s/intermediate-ca/certs/ca-chain.crt\n' "$PKI_DIR"
}

pki_write_root_config() {
  local path=$1
  local country=$2
  local org=$3
  local name=$4
  cat >"$path" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = $PKI_DIR/root-ca
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
  cat >"$path" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = $PKI_DIR/intermediate-ca
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
  root_cert=$(pki_root_cert)
  int_cert=$(pki_intermediate_cert)
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
