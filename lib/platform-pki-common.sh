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

pki_validate_days() {
  [[ $1 =~ ^[0-9]+$ ]] || pki_die "Days value must be numeric: $1"
  (( $1 >= 1 )) || pki_die "Days value must be at least 1: $1"
}

pki_inventory_file() {
  printf '%s/inventory/services.yml\n' "$PKI_DIR"
}

pki_require_inventory() {
  local inventory
  inventory=$(pki_inventory_file)
  [[ -r "$inventory" ]] || pki_die "Service inventory is missing or unreadable: $inventory"
}

pki_inventory_services() {
  local inventory
  inventory=$(pki_inventory_file)
  awk '
    /^services:[[:space:]]*$/ { in_services = 1; next }
    in_services && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ {
      name = $1
      sub(/:$/, "", name)
      print name
    }
  ' "$inventory"
}

pki_inventory_scalar() {
  local service=$1
  local field=$2
  local inventory
  inventory=$(pki_inventory_file)
  awk -v service="$service" -v field="$field" '
    /^services:[[:space:]]*$/ { in_services = 1; next }
    in_services && $0 == "  " service ":" { in_service = 1; next }
    in_service && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { exit }
    in_service {
      prefix = "    " field ":"
      if (index($0, prefix) == 1) {
        value = substr($0, length(prefix) + 1)
        sub(/^[[:space:]]+/, "", value)
        sub(/[[:space:]]+$/, "", value)
        gsub(/^"|"$/, "", value)
        gsub(/^'\''|'\''$/, "", value)
        print value
        exit
      }
    }
  ' "$inventory"
}

pki_inventory_array() {
  local service=$1
  local field=$2
  local inventory
  inventory=$(pki_inventory_file)
  awk -v service="$service" -v field="$field" '
    /^services:[[:space:]]*$/ { in_services = 1; next }
    in_services && $0 == "  " service ":" { in_service = 1; next }
    in_service && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { exit }
    in_service && $0 == "    " field ":" { in_array = 1; next }
    in_array && /^    [A-Za-z0-9_.-]+:/ { exit }
    in_array && /^      - / {
      value = substr($0, 9)
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      gsub(/^"|"$/, "", value)
      gsub(/^'\''|'\''$/, "", value)
      print value
    }
  ' "$inventory"
}

pki_require_service_in_inventory() {
  local service=$1
  pki_require_inventory
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

  [[ -f "$path" ]] || pki_die "Passphrase file is missing: $path"
  [[ -r "$path" ]] || pki_die "Passphrase file is not readable: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect passphrase file permissions: $path"
  [[ $mode =~ ^[0-7]+$ ]] || pki_die "Cannot parse passphrase file permissions: $path"
  if (( (8#$mode & 077) != 0 )); then
    pki_die "Passphrase file permissions are too open; use chmod 600 or stricter: $path"
  fi
}

pki_require_pki_dir() {
  [[ -d "$PKI_DIR" ]] || pki_die "PKI directory does not exist; run platform-pki-init first: $PKI_DIR"
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
