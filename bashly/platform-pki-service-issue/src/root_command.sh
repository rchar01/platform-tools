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

require_private_dir() {
  local path=$1 label=$2 mode owner current_uid

  [[ -d $path && ! -L $path ]] || pki_die "$label must be a non-symlink directory: $path"
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label permissions: $path"
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label owner: $path"
  current_uid=$(id -u)
  [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label metadata: $path"
  [[ $owner == "$current_uid" ]] || pki_die "$label is not owned by the current user: $path"
  (( (8#$mode & 022) == 0 )) || pki_die "$label is group- or world-writable: $path"
}

require_safe_file() {
  local path=$1 label=$2 private=${3:-false} mode owner links current_uid

  [[ ! -L $path ]] || pki_die "$label must not be a symlink: $path"
  [[ ! -e $path || -f $path ]] || pki_die "$label must be a regular file: $path"
  [[ ! -e $path ]] && return 0
  mode=$(stat -c '%a' "$path") || pki_die "Cannot inspect $label permissions: $path"
  owner=$(stat -c '%u' "$path") || pki_die "Cannot inspect $label owner: $path"
  links=$(stat -c '%h' "$path") || pki_die "Cannot inspect $label link count: $path"
  current_uid=$(id -u)
  [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ && $links =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label metadata: $path"
  [[ $owner == "$current_uid" ]] || pki_die "$label is not owned by the current user: $path"
  [[ $links == 1 ]] || pki_die "$label must not be hard-linked: $path"
  (( (8#$mode & 022) == 0 )) || pki_die "$label is group- or world-writable: $path"
  if [[ $private == true ]]; then
    (( (8#$mode & 077) == 0 )) || pki_die "$label permissions are too open; use chmod 600 or stricter: $path"
  fi
}

require_trusted_ancestors() {
  local path=$1 label=$2 current='' component mode owner current_uid
  local -a components

  current_uid=$(id -u)
  IFS='/' read -r -a components <<<"$path"
  if [[ $path == /* ]]; then current=/; else current=.; fi
  for component in "${components[@]}"; do
    [[ -n $component ]] || continue
    if [[ $current == / ]]; then
      current="/$component"
    elif [[ $current == . ]]; then
      current="./$component"
    else
      current="$current/$component"
    fi
    [[ -d $current && ! -L $current ]] || pki_die "$label ancestor must be a non-symlink directory: $current"
    mode=$(stat -c '%a' "$current") || pki_die "Cannot inspect $label ancestor permissions: $current"
    owner=$(stat -c '%u' "$current") || pki_die "Cannot inspect $label ancestor owner: $current"
    [[ $mode =~ ^[0-7]+$ && $owner =~ ^[0-9]+$ ]] || pki_die "Cannot parse $label ancestor metadata: $current"
    [[ $owner == "$current_uid" || $owner == 0 ]] || pki_die "$label ancestor is not owned by the current user or root: $current"
    if (( (8#$mode & 022) != 0 && (8#$mode & 01000) == 0 )); then
      pki_die "$label ancestor is group- or world-writable without sticky bit: $current"
    fi
  done
}

canonicalize_openssl_serial() {
  local serial=${1^^}
  while [[ $serial == 00* && ${#serial} -gt 2 ]]; do
    serial=${serial#00}
  done
  printf '%s\n' "$serial"
}

process_intermediate_signing_config() {
  local source=$1 destination=${2:-} line trimmed section='' key value expected
  local ca_sections=0 ca_default_sections=0 default_ca_count=0
  local -A required_seen=()

  [[ -z $destination ]] || : >"$destination"
  while IFS= read -r line || [[ -n $line ]]; do
    trimmed=$line
    trimmed=${trimmed#"${trimmed%%[![:space:]]*}"}
    if [[ $trimmed =~ ^\.include([[:space:]=]|$) ]]; then
      pki_die "Intermediate CA configuration must not contain include directives: $source"
    fi
    if [[ $trimmed =~ ^\[[[:space:]]*([^]]+)[[:space:]]*\][[:space:]]*($|[#\;]) ]]; then
      section=${BASH_REMATCH[1]}
      section=${section%"${section##*[![:space:]]}"}
      case $section in
        ca)
          ca_sections=$((ca_sections + 1))
          (( ca_sections == 1 )) || pki_die "Intermediate CA configuration contains duplicate ca sections: $source"
          ;;
        CA_default)
          ca_default_sections=$((ca_default_sections + 1))
          (( ca_default_sections == 1 )) || pki_die "Intermediate CA configuration contains duplicate CA_default sections: $source"
          ;;
      esac
    elif [[ $trimmed =~ ^([A-Za-z0-9_.]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      key=${BASH_REMATCH[1]}
      value=${BASH_REMATCH[2]}
      value=${value%"${value##*[![:space:]]}"}
      if [[ $section == ca && $key == default_ca ]]; then
        [[ $value == CA_default ]] || pki_die "Intermediate CA configuration must select CA_default: $source"
        default_ca_count=$((default_ca_count + 1))
        (( default_ca_count == 1 )) || pki_die "Intermediate CA configuration contains duplicate default_ca settings: $source"
      fi
      case ${key,,} in
        dir|certs|crl_dir|new_certs_dir|database|serial|crlnumber|private_key|certificate|crl|randfile|oid_file)
          [[ $section == CA_default ]] || pki_die "Intermediate CA signing path '$key' must be in CA_default: $source"
          [[ ! -v required_seen[${key,,}] ]] || pki_die "Intermediate CA configuration contains duplicate signing path '$key': $source"
          required_seen[${key,,}]=1
          case ${key,,} in
            dir) expected=$INTERMEDIATE_CA_DIR ;;
            certs) expected="\${dir}/certs" ;;
            crl_dir) expected="\${dir}/crl" ;;
            new_certs_dir) expected="\${dir}/newcerts" ;;
            database) expected="\${dir}/index.txt" ;;
            serial) expected="\${dir}/serial" ;;
            crlnumber) expected="\${dir}/crlnumber" ;;
            private_key) expected="\${dir}/private/intermediate-ca.key" ;;
            certificate) expected="\${dir}/certs/intermediate-ca.crt" ;;
            crl) expected="\${dir}/crl/intermediate-ca.crl" ;;
            randfile) expected="\${dir}/private/.rand" ;;
            oid_file) pki_die "Intermediate CA configuration must not use oid_file during staged signing: $source" ;;
          esac
          # OpenSSL accepts both $dir and ${dir}; normalize only for exact comparison.
          value=${value//\$dir/\$\{dir\}}
          [[ $value == "$expected" ]] || pki_die "Intermediate CA signing path '$key' escapes the managed CA directory: $source"
          if [[ ${key,,} == dir && -n $destination ]]; then
            line="dir = $STAGE_INT_DIR"
          fi
          ;;
      esac
      if [[ $section == CA_default ]]; then
        case ${key,,} in
          dir|certs|crl_dir|new_certs_dir|database|serial|crlnumber|private_key|certificate|crl|randfile|oid_file)
            ;;
          default_md)
            [[ $value == sha384 ]] || pki_die "Intermediate CA configuration has an unsafe default_md: $source"
            ;;
          policy)
            [[ $value == policy_platform ]] || pki_die "Intermediate CA configuration has an unsafe policy section: $source"
            ;;
          email_in_dn)
            [[ $value == no ]] || pki_die "Intermediate CA configuration has an unsafe email_in_dn setting: $source"
            ;;
          copy_extensions)
            [[ $value == none ]] || pki_die "Intermediate CA configuration has an unsafe copy_extensions setting: $source"
            ;;
          unique_subject)
            [[ $value == no ]] || pki_die "Intermediate CA configuration has an unsafe unique_subject setting: $source"
            ;;
          *)
            pki_die "Intermediate CA configuration contains unsupported CA_default directive '$key': $source"
            ;;
        esac
      elif [[ -z $section ]]; then
        pki_die "Intermediate CA configuration contains a global directive '$key': $source"
      fi
    fi
    [[ -z $destination ]] || printf '%s\n' "$line" >>"$destination"
  done <"$source"

  [[ $ca_sections -eq 1 && $ca_default_sections -eq 1 && $default_ca_count -eq 1 ]] || \
    pki_die "Intermediate CA configuration is missing the required ca signing contract: $source"
  for key in dir certs crl_dir new_certs_dir database serial private_key certificate; do
    [[ -v required_seen[$key] ]] || pki_die "Intermediate CA configuration is missing signing path '$key': $source"
  done
}

snapshot_transaction_destinations() {
  local i destination

  TRANSACTION_EXPECTED_STATES=()
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    destination=${TRANSACTION_DESTINATIONS[i]}
    if [[ -e $destination || -L $destination ]]; then
      TRANSACTION_EXPECTED_STATES[i]="present:$(stat -c '%d:%i' "$destination")" || \
        pki_die "Cannot snapshot issuance destination identity: $destination"
    else
      TRANSACTION_EXPECTED_STATES[i]=absent
    fi
  done
}

require_destination_snapshot() {
  local i=$1 destination=${TRANSACTION_DESTINATIONS[$1]} expected=${TRANSACTION_EXPECTED_STATES[$1]} current

  if [[ -e $destination || -L $destination ]]; then
    [[ $expected == present:* ]] || pki_die "Issuance destination appeared after validation; refusing to overwrite: $destination"
    [[ -f $destination && ! -L $destination ]] || pki_die "Issuance destination type changed after validation: $destination"
    current=$(stat -c '%d:%i' "$destination") || pki_die "Cannot recheck issuance destination identity: $destination"
    [[ $current == "${expected#present:}" ]] || pki_die "Issuance destination identity changed after validation: $destination"
  else
    [[ $expected == absent ]] || pki_die "Issuance destination disappeared after validation: $destination"
  fi
}

restore_issue_transaction() {
  local i destination backup expected_identity current_identity rollback_status=0

  for ((i = ${#TRANSACTION_DESTINATIONS[@]} - 1; i >= 0; i--)); do
    [[ ${TRANSACTION_PUBLISHED[i]:-false} == true ]] || continue
    destination=${TRANSACTION_DESTINATIONS[i]}
    backup=${TRANSACTION_BACKUPS[i]}
    expected_identity=${TRANSACTION_PUBLISHED_IDENTITIES[i]}
    if [[ -e $destination || -L $destination ]]; then
      if [[ ! -f $destination || -L $destination ]]; then
        printf '[ERROR] Published issuance destination was replaced; preserving it and transaction staging: %s\n' "$destination" >&2
        rollback_status=1
        continue
      fi
      current_identity=$(stat -c '%d:%i' "$destination") || {
        rollback_status=1
        continue
      }
      if [[ $current_identity != "$expected_identity" ]]; then
        printf '[ERROR] Published issuance destination identity changed; preserving it and transaction staging: %s\n' "$destination" >&2
        rollback_status=1
        continue
      fi
      rm -f -- "$destination" || {
        rollback_status=1
        continue
      }
    fi
    if [[ ${TRANSACTION_ORIGINALS[i]} == true ]]; then
      ln -- "$backup" "$destination" || rollback_status=1
    fi
  done
  return "$rollback_status"
}

finish_service_issue() {
  local status=$? cleanup_status=0 i

  trap - EXIT
  trap '' HUP INT TERM
  if [[ -n ${INVENTORY_TMP_DIR:-} ]]; then
    rm -rf -- "$INVENTORY_TMP_DIR" || cleanup_status=1
    INVENTORY_TMP_DIR=''
  fi
  if [[ ${TRANSACTION_ACTIVE:-false} == true && ${TRANSACTION_COMMITTED:-false} != true ]]; then
    restore_issue_transaction || cleanup_status=1
  fi
  if (( cleanup_status != 0 )); then
    printf '[ERROR] Failed to restore service issuance transaction; preserved staging and locks for recovery: %s\n' "${STAGE_DIR:-unknown}" >&2
    exit 1
  fi
  [[ -z ${STAGE_DIR:-} ]] || rm -rf -- "$STAGE_DIR" || cleanup_status=1
  if [[ ${TRANSACTION_COMMITTED:-false} != true ]]; then
    for ((i = ${#CREATED_DIRS[@]} - 1; i >= 0; i--)); do
      rmdir "${CREATED_DIRS[i]}" 2>/dev/null || true
    done
  fi
  if [[ ${INVENTORY_OPERATION_LOCK_HELD:-false} == true ]]; then
    pki_release_operation_lock "$INVENTORY_OPERATION_LOCK" 2>/dev/null || cleanup_status=1
  fi
  if [[ ${INTERMEDIATE_OPERATION_LOCK_HELD:-false} == true ]]; then
    pki_release_operation_lock "$INTERMEDIATE_OPERATION_LOCK" 2>/dev/null || cleanup_status=1
  fi
  if [[ ${ROOT_OPERATION_LOCK_HELD:-false} == true ]]; then
    pki_release_operation_lock "$ROOT_OPERATION_LOCK" 2>/dev/null || cleanup_status=1
  fi
  if (( cleanup_status != 0 )); then
    printf '[ERROR] Failed to clean up service issuance transaction\n' >&2
    status=1
  fi
  exit "$status"
}

publish_issue_transaction() {
  local i source destination backup source_identity

  TRANSACTION_BACKUPS=()
  TRANSACTION_ORIGINALS=()
  TRANSACTION_PUBLISHED=()
  TRANSACTION_PUBLISHED_IDENTITIES=()
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    destination=${TRANSACTION_DESTINATIONS[i]}
    require_destination_snapshot "$i"
    if [[ -e $destination ]]; then
      backup="$STAGE_DIR/backup-$i"
      cp -p -- "$destination" "$backup" || pki_die "Failed to back up existing issuance state: $destination"
      TRANSACTION_BACKUPS[i]=$backup
      TRANSACTION_ORIGINALS[i]=true
    else
      TRANSACTION_BACKUPS[i]=''
      TRANSACTION_ORIGINALS[i]=false
    fi
  done

  TRANSACTION_ACTIVE=true
  for i in "${!TRANSACTION_DESTINATIONS[@]}"; do
    source=${TRANSACTION_SOURCES[i]}
    destination=${TRANSACTION_DESTINATIONS[i]}
    require_destination_snapshot "$i"
    if [[ -n ${ARCHIVE_DESTINATION_INDEX:-} && $i == "$ARCHIVE_DESTINATION_INDEX" ]]; then
      require_archive_root_snapshot
      if [[ ! -d $ARCHIVE_ROOT ]]; then
        mkdir -m 700 -- "$ARCHIVE_ROOT" || pki_die "Cannot create service archive root: $ARCHIVE_ROOT"
        CREATED_DIRS+=("$ARCHIVE_ROOT")
      fi
      mkdir -m 700 -- "$ARCHIVE_DIR" || pki_die "Service archive destination appeared during publication: $ARCHIVE_DIR"
      CREATED_DIRS+=("$ARCHIVE_DIR")
      require_destination_snapshot "$i"
    fi
    source_identity=$(stat -c '%d:%i' "$source") || pki_die "Cannot inspect staged issuance state identity: $source"
    if [[ ${TRANSACTION_REPLACE[i]} == true ]]; then
      mv -f -- "$source" "$destination" || pki_die "Failed to publish issuance state: $destination"
    else
      ln -- "$source" "$destination" || pki_die "Issuance state appeared during publication; refusing to overwrite: $destination"
      rm -f -- "$source"
    fi
    TRANSACTION_PUBLISHED[i]=true
    TRANSACTION_PUBLISHED_IDENTITIES[i]=$source_identity
  done
}

select_archive_destination() {
  local base candidate n

  ARCHIVE_ROOT="$SERVICE_DIR/archive"
  base="${ARCHIVE_ROOT}/$(date -u '+%Y%m%d-%H%M%S')"
  candidate=$base
  n=1
  while [[ -e $candidate || -L $candidate ]]; do
    candidate=$(printf '%s-%02d' "$base" "$n")
    n=$((n + 1))
  done
  ARCHIVE_DIR=$candidate
  if [[ -e $ARCHIVE_ROOT || -L $ARCHIVE_ROOT ]]; then
    ARCHIVE_ROOT_EXPECTED_STATE="present:$(stat -c '%d:%i' "$ARCHIVE_ROOT")" || \
      pki_die "Cannot snapshot service archive root identity: $ARCHIVE_ROOT"
  else
    ARCHIVE_ROOT_EXPECTED_STATE=absent
  fi
}

require_archive_root_snapshot() {
  local current

  if [[ -e $ARCHIVE_ROOT || -L $ARCHIVE_ROOT ]]; then
    [[ $ARCHIVE_ROOT_EXPECTED_STATE == present:* ]] || \
      pki_die "Service archive root appeared after validation: $ARCHIVE_ROOT"
    [[ -d $ARCHIVE_ROOT && ! -L $ARCHIVE_ROOT ]] || \
      pki_die "Service archive root type changed after validation: $ARCHIVE_ROOT"
    current=$(stat -c '%d:%i' "$ARCHIVE_ROOT") || pki_die "Cannot recheck service archive root identity: $ARCHIVE_ROOT"
    [[ $current == "${ARCHIVE_ROOT_EXPECTED_STATE#present:}" ]] || \
      pki_die "Service archive root identity changed after validation: $ARCHIVE_ROOT"
  else
    [[ $ARCHIVE_ROOT_EXPECTED_STATE == absent ]] || \
      pki_die "Service archive root disappeared after validation: $ARCHIVE_ROOT"
  fi
}

SERVICE=${args[service]}
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
DAYS_OVERRIDE=${args[--days]:-}
DAYS=$DAYS_OVERRIDE
ISSUER_SAFETY_DAYS=${args[--issuer-safety-days]}
INTERMEDIATE_PASS_FILE=${args[--intermediate-pass-file]:-}
ROTATE_KEY=false
[[ -v args[--rotate-key] ]] && ROTATE_KEY=true

pki_validate_service_name "$SERVICE"
[[ -z $DAYS ]] || pki_validate_days "$DAYS"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
pki_validate_openssl_config_value 'PKI directory' "$PKI_DIR"
if [[ -n $INTERMEDIATE_PASS_FILE ]]; then
  INTERMEDIATE_PASS_FILE=$(pki_expand_path "$INTERMEDIATE_PASS_FILE")
  pki_require_pass_file "$INTERMEDIATE_PASS_FILE"
fi
pki_require_cmd openssl

ROOT_CA_DIR=''
INTERMEDIATE_CA_DIR=''
SERVICES_DIR="$PKI_DIR/services"
SERVICE_DIR=$(pki_service_dir "$SERVICE")
KEY=$(pki_service_key "$SERVICE")
CSR="$SERVICE_DIR/csr/tls.csr"
CERT=$(pki_service_cert "$SERVICE")
CHAIN=$(pki_service_chain "$SERVICE")
FULLCHAIN=$(pki_service_fullchain "$SERVICE")
CONF="$SERVICE_DIR/openssl.cnf"
ROOT_CERT=''
INT_KEY=''
INT_CERT=''
INT_CONF=''
INVENTORY=$(pki_inventory_file)
DNS_FILE=''
IPS_FILE=''

validate_issue_state() {
  local specification specification_label sidecar

  pki_require_no_symlink_path_components "$NAMESPACE" 'Namespace'
  pki_require_no_symlink_path_components "$PKI_DIR" 'PKI directory'
  require_trusted_ancestors "$(dirname -- "$INVENTORY")" 'Service inventory'
  pki_require_pki_dir
  for specification in \
    "$PKI_DIR|PKI directory" "$ROOT_CA_DIR|Root CA directory" \
    "$ROOT_CA_DIR/certs|Root CA certificate directory" \
    "$INTERMEDIATE_CA_DIR|Intermediate CA directory" \
    "$INTERMEDIATE_CA_DIR/private|Intermediate CA private directory" \
    "$INTERMEDIATE_CA_DIR/certs|Intermediate CA certificate directory" \
    "$INTERMEDIATE_CA_DIR/newcerts|Intermediate CA new-certificates directory" \
    "$PKI_DIR/inventory|Service inventory directory" \
    "$SERVICES_DIR|Services directory"; do
    require_private_dir "${specification%%|*}" "${specification#*|}"
  done
  if [[ -e $SERVICE_DIR || -L $SERVICE_DIR ]]; then
    require_private_dir "$SERVICE_DIR" 'Service directory'
    for specification in private csr certs chain archive; do
      [[ ! -e $SERVICE_DIR/$specification && ! -L $SERVICE_DIR/$specification ]] || \
        require_private_dir "$SERVICE_DIR/$specification" "Service $specification directory"
    done
  fi

  for specification in \
    "$INVENTORY|Service inventory|false" "$ROOT_CERT|Root CA certificate|false" \
    "$INT_KEY|Intermediate CA key|true" "$INT_CERT|Intermediate CA certificate|false" \
    "$INT_CONF|Intermediate CA configuration|true" \
    "$INTERMEDIATE_CA_DIR/index.txt|Intermediate CA index|true" \
    "$INTERMEDIATE_CA_DIR/index.txt.attr|Intermediate CA index attributes|true" \
    "$INTERMEDIATE_CA_DIR/serial|Intermediate CA serial|true" \
    "$INTERMEDIATE_CA_DIR/crlnumber|Intermediate CA CRL number|true" \
    "$KEY|Service private key|true" "$CSR|Service CSR|true" \
    "$CERT|Service certificate|false" "$CHAIN|Service chain|false" \
    "$FULLCHAIN|Service full chain|false" "$CONF|Service configuration|true"; do
    specification_label=${specification#*|}
    require_safe_file "${specification%%|*}" "${specification_label%|*}" "${specification##*|}"
  done
  for sidecar in index.txt.old index.txt.attr.old serial.old; do
    require_safe_file "$INTERMEDIATE_CA_DIR/$sidecar" "Intermediate CA $sidecar" true
  done
  pki_require_file "$INVENTORY"
  pki_require_file "$ROOT_CERT"
  pki_require_file "$INT_KEY"
  pki_require_file "$INT_CERT"
  pki_require_file "$INT_CONF"
  pki_require_file "$INTERMEDIATE_CA_DIR/index.txt"
  pki_require_file "$INTERMEDIATE_CA_DIR/index.txt.attr"
  pki_require_file "$INTERMEDIATE_CA_DIR/serial"
  pki_require_file "$INTERMEDIATE_CA_DIR/crlnumber"
  process_intermediate_signing_config "$INT_CONF"
  [[ ! -e $CERT && ! -L $CERT ]] || pki_die "Service certificate already exists; use platform-pki-service-renew: $CERT"

  [[ -n ${INVENTORY_CANONICAL:-} ]] || return 0
  pki_require_service_in_inventory "$SERVICE"
  COMMON_NAME=$(pki_inventory_scalar "$SERVICE" common_name)
  [[ -n $COMMON_NAME ]] || pki_die "common_name is missing for service: $SERVICE"
  DAYS=$DAYS_OVERRIDE
  [[ -n $DAYS ]] || DAYS=$(pki_inventory_scalar "$SERVICE" days)
  DAYS=${DAYS:-${PLATFORM_PKI_SERVICE_DAYS:-397}}
  pki_validate_days "$DAYS"
  : >"$DNS_FILE"
  : >"$IPS_FILE"
  pki_inventory_array "$SERVICE" dns >"$DNS_FILE"
  pki_inventory_array "$SERVICE" ips >"$IPS_FILE"
  [[ -s $DNS_FILE || -s $IPS_FILE ]] || pki_die "Service must define at least one DNS or IP SAN: $SERVICE"
  pki_validate_service_inventory_values "$SERVICE" "$COMMON_NAME" "$DNS_FILE" "$IPS_FILE"

  ISSUED_SERIAL=$(<"$INTERMEDIATE_CA_DIR/serial")
  [[ $ISSUED_SERIAL =~ ^[0-9A-Fa-f]+$ ]] || pki_die "Intermediate CA serial is invalid: $ISSUED_SERIAL"
  (( ${#ISSUED_SERIAL} >= 2 && ${#ISSUED_SERIAL} % 2 == 0 )) || \
    pki_die "Intermediate CA serial must contain an even number of hexadecimal digits: $ISSUED_SERIAL"
  ISSUED_SERIAL=$(canonicalize_openssl_serial "$ISSUED_SERIAL")
  INT_NEWCERT="$INTERMEDIATE_CA_DIR/newcerts/$ISSUED_SERIAL.pem"
  require_safe_file "$INT_NEWCERT" 'Intermediate CA issued-certificate destination' false
  [[ ! -e $INT_NEWCERT && ! -L $INT_NEWCERT ]] || \
    pki_die "Intermediate CA issued-certificate destination already exists: $INT_NEWCERT"
}

ROOT_OPERATION_LOCK=$(pki_root_operation_lock)
INTERMEDIATE_OPERATION_LOCK=$(pki_intermediate_operation_lock)
INVENTORY_OPERATION_LOCK=$(pki_inventory_operation_lock)
ROOT_OPERATION_LOCK_HELD=false
INTERMEDIATE_OPERATION_LOCK_HELD=false
INVENTORY_OPERATION_LOCK_HELD=false
STAGE_DIR=''
ARCHIVE_DIR=''
ARCHIVE_ROOT=''
ARCHIVE_DESTINATION_INDEX=''
PUBLISH_KEY=false
INVENTORY_TMP_DIR=''
TRANSACTION_ACTIVE=false
TRANSACTION_COMMITTED=false
TRANSACTION_DESTINATIONS=()
TRANSACTION_SOURCES=()
TRANSACTION_REPLACE=()
TRANSACTION_BACKUPS=()
TRANSACTION_ORIGINALS=()
TRANSACTION_PUBLISHED=()
TRANSACTION_PUBLISHED_IDENTITIES=()
TRANSACTION_EXPECTED_STATES=()
CREATED_DIRS=()
trap finish_service_issue EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

umask 077
INVENTORY_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-service-issue.XXXXXX") || \
  pki_die 'Cannot create inventory staging directory'
DNS_FILE="$INVENTORY_TMP_DIR/dns"
IPS_FILE="$INVENTORY_TMP_DIR/ips"
: >"$DNS_FILE"
: >"$IPS_FILE"
# Root is acquired first because issuance reads root material and mutates the intermediate CA.
pki_acquire_operation_lock "$ROOT_OPERATION_LOCK" 'root CA operation'
ROOT_OPERATION_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_OPERATION_LOCK" 'intermediate CA operation'
INTERMEDIATE_OPERATION_LOCK_HELD=true
pki_acquire_operation_lock "$INVENTORY_OPERATION_LOCK" 'inventory operation'
INVENTORY_OPERATION_LOCK_HELD=true
pki_load_active_issuer_snapshot
ROOT_CERT=$(pki_root_cert)
INT_KEY=$(pki_intermediate_key)
INT_CERT=$(pki_intermediate_cert)
INT_CONF="$INTERMEDIATE_CA_DIR/openssl.cnf"
pki_load_inventory_snapshot "$INVENTORY_TMP_DIR"
validate_issue_state

TRANSACTION_DESTINATIONS=(
  "$CONF" "$CSR" "$CERT" "$CHAIN" "$FULLCHAIN" "$(pki_service_issuer "$SERVICE")"
  "$INTERMEDIATE_CA_DIR/index.txt" "$INTERMEDIATE_CA_DIR/index.txt.attr" "$INTERMEDIATE_CA_DIR/serial"
  "$INTERMEDIATE_CA_DIR/index.txt.old" "$INTERMEDIATE_CA_DIR/index.txt.attr.old" "$INTERMEDIATE_CA_DIR/serial.old"
  "$INT_NEWCERT"
)
TRANSACTION_REPLACE=(true true false true true false true true true true true true false)
if [[ ! -e $KEY || $ROTATE_KEY == true ]]; then
  PUBLISH_KEY=true
  TRANSACTION_DESTINATIONS+=("$KEY")
  [[ $ROTATE_KEY == true ]] && TRANSACTION_REPLACE+=(true) || TRANSACTION_REPLACE+=(false)
fi
if [[ -e $KEY && $ROTATE_KEY == true ]]; then
  select_archive_destination
  ARCHIVE_DESTINATION_INDEX=${#TRANSACTION_DESTINATIONS[@]}
  TRANSACTION_DESTINATIONS+=("$ARCHIVE_DIR/tls.key")
  TRANSACTION_REPLACE+=(false)
fi
snapshot_transaction_destinations

for dir in "$SERVICE_DIR" "$SERVICE_DIR/private" "$SERVICE_DIR/csr" "$SERVICE_DIR/certs" "$SERVICE_DIR/chain"; do
  if [[ ! -e $dir ]]; then
    mkdir -m 700 -- "$dir" || pki_die "Cannot create service directory: $dir"
    CREATED_DIRS+=("$dir")
  fi
done
STAGE_DIR=$(mktemp -d "$INTERMEDIATE_CA_DIR/.platform-pki-service-issue.XXXXXX") || \
  pki_die 'Cannot create service issuance staging directory'
STAGE_INT_DIR="$STAGE_DIR/intermediate-ca"
STAGE_SERVICE_DIR="$STAGE_DIR/service"
mkdir -m 700 "$STAGE_INT_DIR" "$STAGE_INT_DIR/private" "$STAGE_INT_DIR/certs" \
  "$STAGE_INT_DIR/crl" "$STAGE_INT_DIR/newcerts" "$STAGE_SERVICE_DIR"
cp -p -- "$INT_KEY" "$STAGE_INT_DIR/private/intermediate-ca.key"
cp -p -- "$INT_CERT" "$STAGE_INT_DIR/certs/intermediate-ca.crt"
for file in index.txt index.txt.attr serial crlnumber; do
  cp -p -- "$INTERMEDIATE_CA_DIR/$file" "$STAGE_INT_DIR/$file"
done
process_intermediate_signing_config "$INT_CONF" "$STAGE_INT_DIR/openssl.cnf"
chmod 600 "$STAGE_INT_DIR/openssl.cnf"

STAGE_KEY="$STAGE_SERVICE_DIR/tls.key"
STAGE_CSR="$STAGE_SERVICE_DIR/tls.csr"
STAGE_CERT="$STAGE_SERVICE_DIR/tls.crt"
STAGE_CHAIN="$STAGE_SERVICE_DIR/ca-chain.crt"
STAGE_FULLCHAIN="$STAGE_SERVICE_DIR/fullchain.crt"
STAGE_CONF="$STAGE_SERVICE_DIR/openssl.cnf"
STAGE_ISSUER="$STAGE_SERVICE_DIR/issuer"
if [[ -e $KEY && $ROTATE_KEY != true ]]; then
  cp -p -- "$KEY" "$STAGE_KEY"
  pki_info "Reusing existing service private key: $KEY"
else
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "$STAGE_KEY"
fi
chmod 600 "$STAGE_KEY"
pki_write_service_config "$STAGE_CONF" "$COMMON_NAME" "$DNS_FILE" "$IPS_FILE"
chmod 600 "$STAGE_CONF"
openssl req -config "$STAGE_CONF" -key "$STAGE_KEY" -new -sha384 -out "$STAGE_CSR"
chmod 600 "$STAGE_CSR"
CA_CMD=(openssl ca -batch -config "$STAGE_INT_DIR/openssl.cnf" -extfile "$STAGE_CONF" -extensions server_cert -days "$DAYS" -notext -md sha384 -in "$STAGE_CSR" -out "$STAGE_CERT")
[[ -n $INTERMEDIATE_PASS_FILE ]] && CA_CMD+=(-passin "file:$INTERMEDIATE_PASS_FILE")
"${CA_CMD[@]}"
chmod 644 "$STAGE_CERT"
pki_validate_child_validity "$STAGE_CERT" "$INT_CERT" "$ISSUER_SAFETY_DAYS"
cat "$INT_CERT" "$ROOT_CERT" >"$STAGE_CHAIN"
cat "$STAGE_CERT" "$INT_CERT" >"$STAGE_FULLCHAIN"
chmod 644 "$STAGE_CHAIN" "$STAGE_FULLCHAIN"
printf 'root=%s\nintermediate=%s\n' "$ACTIVE_ROOT_ID" "$ACTIVE_INTERMEDIATE_ID" >"$STAGE_ISSUER"
chmod 600 "$STAGE_ISSUER"

TRANSACTION_SOURCES=(
  "$STAGE_CONF" "$STAGE_CSR" "$STAGE_CERT" "$STAGE_CHAIN" "$STAGE_FULLCHAIN" "$STAGE_ISSUER"
  "$STAGE_INT_DIR/index.txt" "$STAGE_INT_DIR/index.txt.attr" "$STAGE_INT_DIR/serial"
  "$STAGE_INT_DIR/index.txt.old" "$STAGE_INT_DIR/index.txt.attr.old" "$STAGE_INT_DIR/serial.old"
  "$STAGE_INT_DIR/newcerts/$ISSUED_SERIAL.pem"
)
if [[ $PUBLISH_KEY == true ]]; then
  TRANSACTION_SOURCES+=("$STAGE_KEY")
fi
if [[ -n $ARCHIVE_DIR ]]; then
  cp -p -- "$KEY" "$STAGE_SERVICE_DIR/archived-tls.key"
  TRANSACTION_SOURCES+=("$STAGE_SERVICE_DIR/archived-tls.key")
fi

publish_issue_transaction
pki_verify_service_certificate "$SERVICE" 30
pki_ok "Verified service certificate: $SERVICE"
TRANSACTION_COMMITTED=true
TRANSACTION_ACTIVE=false
[[ -z $ARCHIVE_DIR ]] || pki_warn "Archived previous service private key: $ARCHIVE_DIR/tls.key"
pki_ok "Issued service certificate: $CERT"
