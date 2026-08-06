#!/usr/bin/env bash

# Authenticated host-local CSR signing transaction shared by issue, renew, and recovery.

PKI_CSR_REQUEST_FIELDS=(
  schema request_id nonce created_epoch expires_epoch operation service target
  requester_principal inventory_sha256 csr_sha256 csr_spki_sha256
  current_cert_sha256 profile response_principal
)
PKI_CSR_APPROVAL_FIELDS=(
  schema request_id nonce created_epoch expires_epoch approver_principal
  request_sha256 csr_sha256 inventory_sha256 operation service target profile
)
PKI_CSR_DB_KEYS=(index index_attr serial index_old index_attr_old serial_old newcert)
PKI_CSR_JOURNAL_FIELDS=(
  schema operation transaction phase committed recovery_step request_id nonce
  operation_kind service target requester_principal approver_principal
  response_principal request_sha256 approval_sha256 inventory_sha256 csr_sha256
  csr_spki_sha256 current_cert_sha256 created_epoch transaction_dir
  transaction_identity response_trust_path response_trust_identity
  response_trust_sha256 sensitive_key_path sensitive_key_identity
  sensitive_key_removed certificate_path certificate_identity certificate_sha256
  chain_path chain_identity chain_sha256 fullchain_path fullchain_identity
  fullchain_sha256 response_manifest_path response_manifest_identity
  response_manifest_sha256 response_signature_path response_signature_identity
  response_signature_sha256 candidate_stage candidate_stage_identity
  candidate_destination candidate_destination_identity response_stage
  response_stage_identity response_destination response_destination_identity
  replay_request_path replay_request_identity replay_request_sha256
  replay_nonce_path replay_nonce_identity replay_nonce_sha256
)
for pki_csr_key in "${PKI_CSR_DB_KEYS[@]}"; do
  PKI_CSR_JOURNAL_FIELDS+=(
    "db_${pki_csr_key}_path" "db_${pki_csr_key}_pre_identity"
    "db_${pki_csr_key}_source" "db_${pki_csr_key}_source_identity"
    "db_${pki_csr_key}_source_object" "db_${pki_csr_key}_post_identity"
    "db_${pki_csr_key}_backup" "db_${pki_csr_key}_backup_identity"
  )
done
unset pki_csr_key

pki_csr_sha256() {
  local value
  value=$(sha256sum -- "$1") || pki_die "Cannot hash CSR protocol file: $1"
  printf '%s\n' "${value%% *}"
}

pki_csr_fault() {
  [[ ${PLATFORM_PKI_CSR_CRASH_AT:-} != "$1" ]] || kill -KILL "$$"
  [[ ${PLATFORM_PKI_CSR_FAIL_AT:-} != "$1" ]] || pki_die "Injected CSR signing failure at $1"
}

pki_csr_require_protocol_file() {
  local path=$1 label=$2 mode owner links size
  [[ -f $path && ! -L $path && -r $path ]] || pki_die "$label must be a readable non-symlink regular file: $path"
  mode=$(stat -c '%a' "$path"); owner=$(stat -c '%u' "$path"); links=$(stat -c '%h' "$path"); size=$(stat -c '%s' "$path")
  [[ $owner == "$(id -u)" && $links == 1 ]] || pki_die "$label must be current-user-owned and singly linked: $path"
  (( (8#$mode & 022) == 0 )) || pki_die "$label is group- or world-writable: $path"
  (( size > 0 && size <= 1048576 )) || pki_die "$label must contain between 1 and 1048576 bytes: $path"
}

pki_csr_copy_protocol_file() {
  local source=$1 destination=$2 label=$3 before
  pki_csr_require_protocol_file "$source" "$label"
  before=$(pki_file_identity "$source")
  cp -P -- "$source" "$destination" || pki_die "Cannot stage $label"
  chmod 600 "$destination" || pki_die "Cannot secure staged $label"
  [[ $(pki_file_identity "$source") == "$before" ]] || pki_die "$label changed while being staged"
}

pki_csr_read_ordered_record() {
  local path=$1 label=$2 destination=$3
  shift 3
  local line key value index=0 before after fd
  local -a fields=("$@")
  local -n record=$destination
  record=()
  pki_csr_require_protocol_file "$path" "$label"
  before=$(pki_file_identity "$path")
  exec {fd}<"$path" || pki_die "Cannot open $label"
  after=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$fd")
  [[ $after == "$before" && $(pki_file_identity "$path") == "$before" ]] || { exec {fd}<&-; pki_die "$label changed while opening"; }
  while IFS= read -r -u "$fd" line || [[ -n $line ]]; do
    (( index < ${#fields[@]} )) || { exec {fd}<&-; pki_die "$label contains extra fields"; }
    [[ $line =~ ^([a-z0-9_]+)=([ -~]+)$ ]] || { exec {fd}<&-; pki_die "$label contains invalid text"; }
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    [[ $key == "${fields[index]}" ]] || { exec {fd}<&-; pki_die "$label field order is invalid at $key"; }
    # shellcheck disable=SC2004 # The nameref targets an associative record.
    record[$key]=$value
    index=$((index + 1))
  done
  exec {fd}<&-
  (( index == ${#fields[@]} )) || pki_die "$label is missing required fields"
  [[ $(pki_file_identity "$path") == "$before" ]] || pki_die "$label changed while being read"
}

pki_csr_write_journal() {
  local key content=''
  for key in "${PKI_CSR_JOURNAL_FIELDS[@]}"; do
    [[ -v CSR_JOURNAL[$key] ]] || pki_die "CSR signing journal field is unset: $key"
    content+="$key=${CSR_JOURNAL[$key]}"$'\n'
  done
  pki_write_journal "$CSR_JOURNAL_PATH" "$content"
}

pki_csr_read_journal() {
  local line key index=0 before opened after fd
  [[ -f $CSR_JOURNAL_PATH && ! -L $CSR_JOURNAL_PATH && $(stat -c '%u:%a:%h' "$CSR_JOURNAL_PATH") == "$(id -u):600:1" ]] || \
    pki_die "CSR signing recovery journal is unsafe: $CSR_JOURNAL_PATH"
  before=$(pki_file_identity "$CSR_JOURNAL_PATH")
  exec {fd}<"$CSR_JOURNAL_PATH" || pki_die 'Cannot open CSR signing recovery journal'
  opened=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$fd") || { exec {fd}<&-; pki_die 'Cannot inspect opened CSR signing recovery journal'; }
  [[ $opened == "$before" && $(pki_file_identity "$CSR_JOURNAL_PATH") == "$before" ]] || { exec {fd}<&-; pki_die 'CSR signing recovery journal identity changed while opening'; }
  unset -v CSR_JOURNAL
  declare -gA CSR_JOURNAL=()
  while IFS= read -r -u "$fd" line || [[ -n $line ]]; do
    [[ $line =~ ^([a-z0-9_]+)=([^[:cntrl:]]*)$ ]] || { exec {fd}<&-; pki_die 'CSR signing recovery journal has invalid content'; }
    (( index < ${#PKI_CSR_JOURNAL_FIELDS[@]} )) || { exec {fd}<&-; pki_die 'CSR signing recovery journal contains extra fields'; }
    key=${line%%=*}
    [[ $key == "${PKI_CSR_JOURNAL_FIELDS[index]}" ]] || { exec {fd}<&-; pki_die "CSR signing recovery journal field order is invalid at $key"; }
    CSR_JOURNAL[$key]=${line#*=}
    index=$((index + 1))
  done
  after=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$fd") || { exec {fd}<&-; pki_die 'Cannot reinspect opened CSR signing recovery journal'; }
  exec {fd}<&-
  [[ $after == "$before" && $(pki_file_identity "$CSR_JOURNAL_PATH") == "$before" ]] || pki_die 'CSR signing recovery journal changed while being read'
  (( index == ${#PKI_CSR_JOURNAL_FIELDS[@]} )) || pki_die 'CSR signing recovery journal is incomplete'
  [[ ${CSR_JOURNAL[schema]} == 1 && ${CSR_JOURNAL[operation]} == csr-sign ]] || pki_die 'CSR signing recovery journal schema is unsupported'
}

pki_csr_require_journal_path() {
  local field=$1 expected=$2 actual
  actual=${CSR_JOURNAL[$field]}
  [[ $actual == none || $actual == "$expected" ]] || pki_die "CSR recovery journal path is outside the state contract: $field"
}

pki_csr_validate_recovery_journal() {
  local key source expected transaction_dir signing_dir
  [[ ${CSR_JOURNAL[request_id]} =~ ^[0-9a-f]{32}$ && ${CSR_JOURNAL[nonce]} =~ ^[0-9a-f]{64}$ ]] || pki_die 'CSR recovery journal request identity is invalid'
  [[ ${CSR_JOURNAL[operation_kind]} == issue || ${CSR_JOURNAL[operation_kind]} == migrate || ${CSR_JOURNAL[operation_kind]} == renew ]] || pki_die 'CSR recovery journal operation is invalid'
  pki_validate_service_name "${CSR_JOURNAL[service]}"
  for key in target requester_principal approver_principal response_principal; do
    [[ ${CSR_JOURNAL[$key]} =~ ^[a-z0-9][a-z0-9.-]*$ ]] || pki_die "CSR recovery journal identity is invalid: $key"
  done
  [[ ${CSR_JOURNAL[committed]} == true || ${CSR_JOURNAL[committed]} == false ]] || pki_die 'CSR recovery journal commit state is invalid'
  [[ ${CSR_JOURNAL[phase]} == planned || ${CSR_JOURNAL[phase]} == ca-committed || ${CSR_JOURNAL[phase]} == terminal ]] || pki_die 'CSR recovery journal phase is invalid'
  [[ ${CSR_JOURNAL[recovery_step]} =~ ^[a-z0-9_-]+$ ]] || pki_die 'CSR recovery journal checkpoint is invalid'
  [[ ${CSR_JOURNAL[transaction]} == "csr-${CSR_JOURNAL[request_id]}" ]] || pki_die 'CSR recovery journal transaction identity is invalid'

  transaction_dir="$PKI_DIR/state/csr/transactions/${CSR_JOURNAL[transaction]}"
  signing_dir=$transaction_dir/signing
  [[ ${CSR_JOURNAL[transaction_dir]} == "$transaction_dir" ]] || pki_die 'CSR recovery transaction path is outside the state contract'
  [[ ${CSR_JOURNAL[response_trust_path]} == "$transaction_dir/responses.allowed_signers" ]] || pki_die 'CSR response trust path is outside the state contract'
  [[ ${CSR_JOURNAL[sensitive_key_path]} == "$signing_dir/private/intermediate-ca.key" ]] || pki_die 'CSR signing key path is outside the state contract'
  [[ ${CSR_JOURNAL[replay_request_path]} == "$PKI_DIR/state/csr/replay/requests/${CSR_JOURNAL[request_id]}" ]] || pki_die 'CSR request replay path is outside the state contract'
  [[ ${CSR_JOURNAL[replay_nonce_path]} == "$PKI_DIR/state/csr/replay/nonces/${CSR_JOURNAL[nonce]}" ]] || pki_die 'CSR nonce replay path is outside the state contract'
  [[ ${CSR_JOURNAL[candidate_stage]} == "$transaction_dir/candidate.publish" && ${CSR_JOURNAL[response_stage]} == "$transaction_dir/response.publish" ]] || pki_die 'CSR publication stage path is outside the state contract'
  [[ ${CSR_JOURNAL[candidate_destination]} == "$PKI_DIR/state/csr/candidates/${CSR_JOURNAL[service]}/${CSR_JOURNAL[request_id]}" ]] || pki_die 'CSR candidate path is outside the state contract'
  [[ ${CSR_JOURNAL[response_destination]} == "$PKI_DIR/state/csr/responses/${CSR_JOURNAL[service]}/${CSR_JOURNAL[request_id]}" ]] || pki_die 'CSR response path is outside the state contract'
  pki_csr_require_journal_path certificate_path "$signing_dir/tls.crt"
  pki_csr_require_journal_path chain_path "$signing_dir/ca-chain.crt"
  pki_csr_require_journal_path fullchain_path "$signing_dir/fullchain.crt"
  pki_csr_require_journal_path response_manifest_path "$signing_dir/response"
  pki_csr_require_journal_path response_signature_path "$signing_dir/response.sig"

  if [[ ${CSR_JOURNAL[db_index_path]} == none ]]; then
    for key in "${PKI_CSR_DB_KEYS[@]}"; do
      for source in path pre_identity source source_identity source_object post_identity backup backup_identity; do
        [[ ${CSR_JOURNAL[db_${key}_${source}]} == none ]] || pki_die 'CSR recovery journal has an incomplete CA database contract'
      done
    done
    [[ ${CSR_JOURNAL[committed]} == false ]] || pki_die 'Committed CSR recovery journal has no CA database contract'
    return
  fi

  ISSUED_SERIAL=${CSR_JOURNAL[db_newcert_path]##*/}; ISSUED_SERIAL=${ISSUED_SERIAL%.pem}
  [[ $ISSUED_SERIAL =~ ^[0-9A-F]+$ && ${#ISSUED_SERIAL} -ge 2 && $((${#ISSUED_SERIAL} % 2)) -eq 0 ]] || pki_die 'CSR recovery journal serial is invalid'
  for key in "${PKI_CSR_DB_KEYS[@]}"; do
    case $key in
      index) source=index.txt ;;
      index_attr) source=index.txt.attr ;;
      serial) source=serial ;;
      index_old) source=index.txt.old ;;
      index_attr_old) source=index.txt.attr.old ;;
      serial_old) source=serial.old ;;
      newcert) source="newcerts/$ISSUED_SERIAL.pem" ;;
    esac
    expected=$INTERMEDIATE_CA_DIR/$source
    [[ ${CSR_JOURNAL[db_${key}_path]} == "$expected" ]] || pki_die "CSR recovery CA path is outside the active intermediate: $key"
    [[ ${CSR_JOURNAL[db_${key}_source]} == "$signing_dir/$source" ]] || pki_die "CSR recovery staged CA path is outside the transaction: $key"
    [[ ${CSR_JOURNAL[db_${key}_backup]} == "$transaction_dir/ca-backup/$key" ]] || pki_die "CSR recovery CA backup path is outside the transaction: $key"
  done
}

pki_csr_record_content() {
  local key value content=''
  shift
  for key in "$@"; do
    value=${CSR_RECORD_VALUES[$key]}
    content+="$key=$value"$'\n'
  done
  printf '%s' "$content"
}

pki_csr_prepare_state_dirs() {
  local dir
  for dir in \
    "$PKI_DIR/state/csr" "$PKI_DIR/state/csr/transactions" \
    "$PKI_DIR/state/csr/replay" "$PKI_DIR/state/csr/replay/requests" \
    "$PKI_DIR/state/csr/replay/nonces" "$PKI_DIR/state/csr/candidates" \
    "$PKI_DIR/state/csr/responses"; do
    if [[ ! -e $dir && ! -L $dir ]]; then mkdir -m 700 -- "$dir" || pki_die "Cannot create CSR protocol state directory: $dir"; pki_fsync "$(dirname -- "$dir")"; fi
    pki_require_private_dir "$dir" 'CSR protocol state directory'
  done
}

pki_csr_load_policy() {
  local trust=$PKI_DIR/inventory/csr-trust path name
  local -a lines=() expected=() actual=()
  pki_require_private_dir "$trust" 'Installed CSR trust directory'
  while IFS= read -r -d '' path; do actual+=("$(basename -- "$path")"); done < <(find "$trust" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  mapfile -t lines <"$trust/policy"
  if [[ ${lines[0]:-} == schema=1 ]]; then
    CSR_TRUST_SCHEMA=1
    expected=(approvers.allowed_signers policy requesters.allowed_signers responses.allowed_signers)
    [[ ${#lines[@]} -eq 10 && \
      ${lines[1]} == request_namespace=platform-pki-csr-request-v1 && \
      ${lines[2]} == approval_namespace=platform-pki-csr-approval-v1 && \
      ${lines[3]} == response_namespace=platform-pki-csr-response-v1 && \
      ${lines[4]} == request_max_age_seconds=604800 && \
      ${lines[5]} == sole_operator_min_delay_seconds=86400 && \
      ${lines[6]} == approval_max_age_seconds=86400 && \
      ${lines[7]} == clock_skew_seconds=300 && \
      ${lines[8]} =~ ^approver_principal=([a-z0-9][a-z0-9.-]*)$ ]] || pki_die 'Installed CSR trust policy is invalid'
    CSR_APPROVER_PRINCIPAL=${BASH_REMATCH[1]}
    [[ ${lines[9]} =~ ^response_principal=([a-z0-9][a-z0-9.-]*)$ ]] || pki_die 'Installed CSR response principal is invalid'
  elif [[ ${lines[0]:-} == schema=2 ]]; then
    CSR_TRUST_SCHEMA=2
    expected=(approvers.allowed_signers deployers.allowed_signers policy requesters.allowed_signers responses.allowed_signers)
    [[ ${#lines[@]} -eq 12 && \
      ${lines[1]} == request_namespace=platform-pki-csr-request-v1 && \
      ${lines[2]} == approval_namespace=platform-pki-csr-approval-v1 && \
      ${lines[3]} == response_namespace=platform-pki-csr-response-v1 && \
      ${lines[4]} == deployment_namespace=platform-pki-csr-deployment-v1 && \
      ${lines[5]} == request_max_age_seconds=604800 && \
      ${lines[6]} == sole_operator_min_delay_seconds=86400 && \
      ${lines[7]} == approval_max_age_seconds=86400 && \
      ${lines[8]} == deployment_max_age_seconds=86400 && \
      ${lines[9]} == clock_skew_seconds=300 && \
      ${lines[10]} =~ ^approver_principal=([a-z0-9][a-z0-9.-]*)$ ]] || pki_die 'Installed CSR trust policy is invalid'
    CSR_APPROVER_PRINCIPAL=${BASH_REMATCH[1]}
    [[ ${lines[11]} =~ ^response_principal=([a-z0-9][a-z0-9.-]*)$ ]] || pki_die 'Installed CSR response principal is invalid'
  else
    pki_die 'Installed CSR trust policy is invalid'
  fi
  [[ ${actual[*]} == "${expected[*]}" ]] || pki_die 'Installed CSR trust directory contains unexpected state'
  unset -v CSR_TRUST_IDENTITIES
  declare -gA CSR_TRUST_IDENTITIES=()
  for path in "${expected[@]}"; do
    [[ -f $trust/$path && ! -L $trust/$path && $(stat -c '%u:%a:%h' "$trust/$path") == "$(id -u):600:1" ]] || pki_die "Installed CSR trust file is unsafe: $trust/$path"
    CSR_TRUST_IDENTITIES[$path]=$(pki_file_identity "$trust/$path")
  done
  CSR_RESPONSE_PRINCIPAL=${BASH_REMATCH[1]}
  CSR_TRUST_DIR=$trust
  pki_csr_validate_allowed_signers "$trust/requesters.allowed_signers" '' false
  pki_csr_validate_allowed_signers "$trust/approvers.allowed_signers" "$CSR_APPROVER_PRINCIPAL" true
  pki_csr_validate_allowed_signers "$trust/responses.allowed_signers" "$CSR_RESPONSE_PRINCIPAL" true
  [[ $CSR_TRUST_SCHEMA != 2 ]] || pki_csr_validate_allowed_signers "$trust/deployers.allowed_signers" '' false
  for name in "${expected[@]}"; do [[ $(pki_file_identity "$trust/$name") == "${CSR_TRUST_IDENTITIES[$name]}" ]] || pki_die "Installed CSR trust changed during validation: $name"; done
}

pki_csr_validate_allowed_signers() {
  local path=$1 required=$2 single=$3 line principal algorithm key extra count=0
  local -A seen=()
  while IFS= read -r line || [[ -n $line ]]; do
    IFS=' ' read -r principal algorithm key extra <<<"$line"
    [[ $principal =~ ^[a-z0-9][a-z0-9.-]*$ && $algorithm == ssh-ed25519 && $key =~ ^[A-Za-z0-9+/]+={0,2}$ && -z $extra ]] || pki_die 'Installed CSR trust contains a noncanonical allowed-signer record'
    [[ ! -v seen[$principal] ]] || pki_die "Installed CSR trust contains duplicate principal: $principal"
    seen[$principal]=1; count=$((count + 1))
  done <"$path"
  (( count > 0 )) || pki_die 'Installed CSR allowed-signer file is empty'
  [[ -z $required || -v seen[$required] ]] || pki_die "Installed CSR trust is missing pinned principal: $required"
  [[ $single != true || $count -eq 1 ]] || pki_die 'Installed CSR pinned signer file contains additional principals'
}

pki_csr_recheck_trust() {
  local name
  for name in "${!CSR_TRUST_IDENTITIES[@]}"; do
    [[ -f $CSR_TRUST_DIR/$name && ! -L $CSR_TRUST_DIR/$name && $(pki_file_identity "$CSR_TRUST_DIR/$name") == "${CSR_TRUST_IDENTITIES[$name]}" ]] || pki_die "Installed CSR trust changed during signing validation: $name"
  done
}

pki_csr_allowed_key() {
  local path=$1 principal=$2 line found='' current algorithm key extra
  while IFS= read -r line || [[ -n $line ]]; do
    IFS=' ' read -r current algorithm key extra <<<"$line"
    [[ $current != "$principal" ]] || { [[ -z $found ]] || pki_die "Duplicate CSR signer principal: $principal"; found=$key; }
  done <"$path"
  [[ -n $found ]] || pki_die "CSR signer principal is not trusted: $principal"
  printf '%s\n' "$found"
}

pki_csr_verify_signature() {
  local allowed=$1 principal=$2 namespace=$3 signature=$4 content=$5 label=$6 before
  before=$(pki_file_identity "$allowed")
  ssh-keygen -Y verify -f "$allowed" -I "$principal" -n "$namespace" -s "$signature" <"$content" >/dev/null 2>&1 || \
    pki_die "$label signature verification failed"
  [[ $(pki_file_identity "$allowed") == "$before" ]] || pki_die "$label trust changed during verification"
}

pki_csr_validate_times() {
  local now request_created request_expires approval_created approval_expires requester_key approver_key
  now=$(date -u +%s)
  request_created=${CSR_REQUEST[created_epoch]}; request_expires=${CSR_REQUEST[expires_epoch]}
  approval_created=${CSR_APPROVAL[created_epoch]}; approval_expires=${CSR_APPROVAL[expires_epoch]}
  for value in "$request_created" "$request_expires" "$approval_created" "$approval_expires"; do [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || pki_die 'CSR protocol timestamps must be canonical decimal epochs'; done
  (( request_expires > request_created && request_expires - request_created <= 604800 )) || pki_die 'CSR request validity interval exceeds policy'
  (( now + 300 >= request_created && now <= request_expires + 300 )) || pki_die 'CSR request is not currently valid'
  (( approval_expires > approval_created && approval_expires - approval_created <= 86400 )) || pki_die 'CSR approval validity interval exceeds policy'
  (( approval_created >= request_created && now + 300 >= approval_created && now <= approval_expires + 300 )) || pki_die 'CSR approval is not currently valid'
  requester_key=$(pki_csr_allowed_key "$CSR_TRUST_DIR/requesters.allowed_signers" "${CSR_REQUEST[requester_principal]}")
  approver_key=$(pki_csr_allowed_key "$CSR_TRUST_DIR/approvers.allowed_signers" "${CSR_APPROVAL[approver_principal]}")
  if [[ $requester_key == "$approver_key" ]]; then
    (( approval_created - request_created >= 86400 )) || pki_die 'Sole-operator CSR approval delay has not elapsed'
  fi
}

pki_csr_require_active_predecessor() {
  declare -F pki_candidate_validate_active_outcome >/dev/null || pki_die 'CSR candidate outcome validator is unavailable'
  # shellcheck disable=SC2034 # The shared candidate validator consumes these globals.
  INVENTORY_TARGET=${CSR_REQUEST[target]}
  # shellcheck disable=SC2034
  VALIDATION_BOUNDARY_SHA256=$(pki_inventory_scalar "$SERVICE" validation_boundary_sha256)
  # shellcheck disable=SC2034
  ROLLBACK_HOLD_SECONDS=$(pki_inventory_scalar "$SERVICE" rollback_hold_seconds)
  # shellcheck disable=SC2034
  CANDIDATE_WORK_DIR=$CSR_INPUT_DIR
  pki_candidate_load_active true
  pki_candidate_validate_active_outcome
  [[ ${CANDIDATE_ACTIVE[certificate_sha256]} == "${CSR_REQUEST[current_cert_sha256]}" ]] || pki_die 'Host-local renewal request does not match the authenticated active accepted evidence'
}

pki_csr_reject_unresolved_predecessor_candidate() {
  local root=$PKI_DIR/state/csr/candidates/$SERVICE path request_id request_path
  local -A pending_request=()
  [[ -d $root && ! -L $root ]] || return 0
  pki_require_private_dir "$root" 'CSR candidate service directory'
  while IFS= read -r -d '' path; do
    request_id=$(basename -- "$path")
    [[ $request_id =~ ^[0-9a-f]{32}$ && -d $path && ! -L $path ]] || pki_die "Unsafe CSR candidate entry blocks renewal: $path"
    [[ -e $PKI_DIR/state/csr/outcomes/$SERVICE/$request_id || -L $PKI_DIR/state/csr/outcomes/$SERVICE/$request_id ]] && continue
    request_path=$PKI_DIR/state/csr/transactions/csr-$request_id/request
    pending_request=()
    pki_csr_read_ordered_record "$request_path" 'Pending CSR request' pending_request "${PKI_CSR_REQUEST_FIELDS[@]}"
    if [[ ${pending_request[operation]} == renew && ${pending_request[service]} == "$SERVICE" && ${pending_request[current_cert_sha256]} == "${CSR_REQUEST[current_cert_sha256]}" ]]; then
      pki_die "An unresolved renewal candidate already exists for the active predecessor: $request_id"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -print0)
}

pki_csr_spki_digest() {
  local input=$1 kind=$2 directory=$3
  if [[ $kind == csr ]]; then openssl req -in "$input" -pubkey -noout >"$directory/public.pem"; else openssl x509 -in "$input" -pubkey -noout >"$directory/public.pem"; fi
  openssl pkey -pubin -in "$directory/public.pem" -outform DER -out "$directory/public.der" >/dev/null 2>&1 || pki_die "Cannot extract public key from $kind"
  pki_csr_sha256 "$directory/public.der"
}

pki_csr_validate_sans() {
  local text=$1 dns=$2 ips=$3 label=$4
  python3 - "$text" "$dns" "$ips" "$label" <<'PY' || pki_die "$label has an invalid or unexpected extension profile"
import pathlib
import re
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
expected = {f"DNS:{value}" for value in pathlib.Path(sys.argv[2]).read_text().splitlines() if value}
expected |= {f"IP Address:{value}" for value in pathlib.Path(sys.argv[3]).read_text().splitlines() if value}
extensions = []
sans = set()
for index, line in enumerate(lines):
    match = re.match(r"^\s+X509v3 ([^:]+):( critical)?\s*$", line)
    if not match:
        continue
    name = match.group(1)
    if name == "extensions":
        continue
    extensions.append((name, bool(match.group(2))))
    if name == "Subject Alternative Name":
        if index + 1 >= len(lines):
            raise SystemExit(1)
        sans = {value.strip() for value in lines[index + 1].strip().split(",")}

label = sys.argv[4]
if label == "CSR":
    try:
        attribute_start = lines.index("        Attributes:")
        signature_start = next(
            index for index, line in enumerate(lines[attribute_start + 1 :], attribute_start + 1)
            if line.startswith("    Signature Algorithm:")
        )
    except (ValueError, StopIteration):
        raise SystemExit(1)
    attribute_headers = [
        line.strip()
        for line in lines[attribute_start + 1 : signature_start]
        if line.startswith("            ") and not line.startswith("                ")
    ]
    if attribute_headers != ["Requested Extensions:"]:
        raise SystemExit(1)
    if extensions != [("Subject Alternative Name", False)]:
        raise SystemExit(1)
else:
    required = {
        ("Basic Constraints", True),
        ("Key Usage", True),
        ("Extended Key Usage", False),
        ("Subject Alternative Name", False),
        ("Subject Key Identifier", False),
        ("Authority Key Identifier", False),
    }
    if set(extensions) != required or len(extensions) != len(required):
        raise SystemExit(1)
if sans != expected:
    raise SystemExit(1)
PY
}

pki_csr_validate_csr() {
  local csr=$1 directory=$2 subject text
  openssl req -in "$csr" -verify -noout >/dev/null 2>&1 || pki_die 'CSR self-signature verification failed'
  subject=$(openssl req -in "$csr" -noout -subject -nameopt RFC2253) || pki_die 'Cannot inspect CSR subject'
  [[ $subject == "subject=CN=$COMMON_NAME" ]] || pki_die 'CSR subject does not match inventory common_name'
  openssl req -in "$csr" -noout -text >"$directory/csr.txt" || pki_die 'Cannot inspect CSR profile'
  text=$(<"$directory/csr.txt")
  [[ $text == *'Public-Key: (384 bit)'* && $text == *'ASN1 OID: secp384r1'* ]] || pki_die 'CSR public key must be EC P-384'
  [[ $(printf '%s\n' "$text" | grep -c '^    Signature Algorithm: ecdsa-with-SHA384$') -eq 1 ]] || pki_die 'CSR signature algorithm must be ECDSA-with-SHA384'
  pki_csr_validate_sans "$directory/csr.txt" "$DNS_FILE" "$IPS_FILE" CSR
  CSR_ACTUAL_SPKI_SHA256=$(pki_csr_spki_digest "$csr" csr "$directory")
}

pki_csr_validate_certificate() {
  local cert=$1 csr=$2 directory=$3 subject text cert_spki serial
  openssl verify -CAfile "$ROOT_CERT" -untrusted "$INT_CERT" "$cert" >/dev/null 2>&1 || pki_die 'Issued host-local certificate chain verification failed'
  subject=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253) || pki_die 'Cannot inspect issued certificate subject'
  [[ $subject == "subject=CN=$COMMON_NAME" ]] || pki_die 'Issued certificate subject does not match inventory'
  openssl x509 -in "$cert" -noout -text >"$directory/certificate.txt" || pki_die 'Cannot inspect issued certificate profile'
  text=$(<"$directory/certificate.txt")
  [[ $text == *'CA:FALSE'* && $text == *'Digital Signature'* && $text == *'TLS Web Server Authentication'* ]] || pki_die 'Issued certificate has an invalid service profile'
  pki_csr_validate_sans "$directory/certificate.txt" "$DNS_FILE" "$IPS_FILE" Certificate
  cert_spki=$(pki_csr_spki_digest "$cert" cert "$directory")
  [[ $cert_spki == "$CSR_ACTUAL_SPKI_SHA256" ]] || pki_die 'Issued certificate public key does not match the CSR'
  serial=$(openssl x509 -in "$cert" -noout -serial); serial=${serial#serial=}; serial=${serial#Serial=}
  [[ ${serial^^} == "$ISSUED_SERIAL" ]] || pki_die 'Issued certificate serial does not match the reserved serial'
}

pki_csr_ensure_replay_record() {
  local path=$1 content=$2 identity_field=$3 label=$4 digest before after expected
  digest=$(printf '%s' "$content" | sha256sum); digest=${digest%% *}
  expected=${CSR_JOURNAL["$identity_field"]:-none}
  if [[ ! -e $path && ! -L $path ]]; then
    [[ $expected == none && ${CSR_JOURNAL[recovery_step]} == planned ]] || pki_die "$label disappeared after its identity was journaled"
    pki_atomic_write "$path" "$content"
  else
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' "$path") == "$(id -u):600:1" ]] || pki_die "$label is unsafe"
    [[ $expected != none || ${CSR_JOURNAL[recovery_step]} == planned ]] || \
      pki_die "$label has no journaled identity outside replay reservation"
  fi
  before=$(pki_file_identity "$path") || pki_die "Cannot inspect $label"
  [[ $expected == none || $before == "$expected" ]] || pki_die "$label identity changed"
  [[ $(pki_csr_sha256 "$path") == "$digest" ]] || pki_die "$label conflicts with the recovery journal"
  after=$(pki_file_identity "$path") || pki_die "Cannot reinspect $label"
  [[ $after == "$before" ]] || pki_die "$label changed while being verified"
  if [[ $expected == none ]]; then CSR_JOURNAL[$identity_field]=$before; fi
  PKI_CSR_REPLAY_DIGEST=$digest
}

pki_csr_ensure_replay() {
  local content
  content="schema=1
request_id=${CSR_JOURNAL[request_id]}
nonce=${CSR_JOURNAL[nonce]}
operation=${CSR_JOURNAL[operation_kind]}
service=${CSR_JOURNAL[service]}
target=${CSR_JOURNAL[target]}
request_sha256=${CSR_JOURNAL[request_sha256]}
approval_sha256=${CSR_JOURNAL[approval_sha256]}
outcome=reserved
"
  pki_csr_ensure_replay_record "${CSR_JOURNAL[replay_request_path]}" "$content" replay_request_identity 'CSR request replay record'
  CSR_JOURNAL[replay_request_sha256]=$PKI_CSR_REPLAY_DIGEST
  content="schema=1
nonce=${CSR_JOURNAL[nonce]}
request_id=${CSR_JOURNAL[request_id]}
request_sha256=${CSR_JOURNAL[request_sha256]}
outcome=reserved
"
  pki_csr_ensure_replay_record "${CSR_JOURNAL[replay_nonce_path]}" "$content" replay_nonce_identity 'CSR nonce replay record'
  CSR_JOURNAL[replay_nonce_sha256]=$PKI_CSR_REPLAY_DIGEST
}

pki_csr_checkpoint() {
  CSR_JOURNAL[recovery_step]=$1
  pki_csr_write_journal
  pki_csr_fault "$1"
}

pki_csr_current_matches() {
  local path=$1 expected_full=$2 expected_object=$3 current
  [[ -e $path && ! -L $path ]] || return 1
  current=$(pki_file_identity "$path") || return 1
  [[ $current == "$expected_full" || $(pki_file_object_state "$path") == "$expected_object" ]]
}

pki_csr_remove_sensitive_key() {
  local path=${CSR_JOURNAL[sensitive_key_path]} current
  if [[ $path == none ]]; then CSR_JOURNAL[sensitive_key_removed]=true; return; fi
  if [[ -e $path || -L $path ]]; then
    [[ -f $path && ! -L $path ]] || pki_die 'Journaled CSR signing key copy has an unsafe replacement'
    [[ ${CSR_JOURNAL[sensitive_key_identity]} != none ]] || pki_die 'Journaled CSR signing key copy has no recorded identity'
    current=$(pki_file_identity "$path")
    if [[ $current != "${CSR_JOURNAL[sensitive_key_identity]}" ]]; then
      pki_die 'Journaled CSR signing key copy identity changed'
    fi
    [[ $(stat -c '%u:%a:%h' "$path") == "$(id -u):600:1" ]] || pki_die 'Journaled CSR signing key copy is unsafe'
    pki_remove_identity_file "$path" "${CSR_JOURNAL[sensitive_key_identity]}" || pki_die 'Cannot remove journaled CSR signing key copy'
  fi
  CSR_JOURNAL[sensitive_key_removed]=true
}

pki_csr_rollback_uncommitted_ca() {
  local key path pre post source_object backup current
  for ((index = ${#PKI_CSR_DB_KEYS[@]} - 1; index >= 0; index--)); do
    key=${PKI_CSR_DB_KEYS[index]}; path=${CSR_JOURNAL[db_${key}_path]}; pre=${CSR_JOURNAL[db_${key}_pre_identity]}
    [[ $path != none ]] || continue
    post=${CSR_JOURNAL[db_${key}_post_identity]}; source_object=${CSR_JOURNAL[db_${key}_source_object]}; backup=${CSR_JOURNAL[db_${key}_backup]}
    current=$(pki_file_identity_or_absent_full "$path")
    if [[ $current == "$pre" ]]; then continue; fi
    if [[ $current != "$post" ]] && ! { [[ $current != absent ]] && [[ $(pki_file_object_state "$path") == "$source_object" ]]; }; then
      pki_die "CSR recovery found non-journaled CA state: $path"
    fi
    if [[ $pre == absent ]]; then pki_remove_identity_file "$path" "$current" || pki_die "Cannot remove partial CSR CA publication: $path"
    else
      pki_require_file_identity "$backup" "${CSR_JOURNAL[db_${key}_backup_identity]}" "CSR CA rollback copy $key"
      pki_publish_staged_file_exact "$backup" "$path"
    fi
  done
}

pki_csr_write_terminal() {
  local outcome=$1 path=${CSR_JOURNAL[transaction_dir]}/terminal
  if [[ ! -e ${CSR_JOURNAL[transaction_dir]} && ! -L ${CSR_JOURNAL[transaction_dir]} ]]; then
    [[ ${CSR_JOURNAL[transaction_identity]} == none ]] || pki_die 'Journaled CSR transaction directory disappeared'
    mkdir -m 700 -- "${CSR_JOURNAL[transaction_dir]}" || pki_die 'Cannot create terminal CSR transaction directory'
    CSR_JOURNAL[transaction_identity]=$(pki_dir_identity "${CSR_JOURNAL[transaction_dir]}")
  fi
  pki_require_private_dir "${CSR_JOURNAL[transaction_dir]}" 'CSR transaction directory'
  [[ ${CSR_JOURNAL[transaction_identity]} == none || $(pki_dir_identity "${CSR_JOURNAL[transaction_dir]}") == "${CSR_JOURNAL[transaction_identity]}" ]] || pki_die 'Journaled CSR transaction directory identity changed'
  pki_atomic_write "$path" "schema=1
transaction=${CSR_JOURNAL[transaction]}
request_id=${CSR_JOURNAL[request_id]}
operation=${CSR_JOURNAL[operation_kind]}
service=${CSR_JOURNAL[service]}
outcome=$outcome
committed=${CSR_JOURNAL[committed]}
"
}

pki_csr_candidate_record_content() {
  cat <<EOF
schema=1
request_id=${CSR_JOURNAL[request_id]}
nonce=${CSR_JOURNAL[nonce]}
operation=${CSR_JOURNAL[operation_kind]}
service=${CSR_JOURNAL[service]}
target=${CSR_JOURNAL[target]}
state=pending
request_sha256=${CSR_JOURNAL[request_sha256]}
approval_sha256=${CSR_JOURNAL[approval_sha256]}
inventory_sha256=${CSR_JOURNAL[inventory_sha256]}
csr_sha256=${CSR_JOURNAL[csr_sha256]}
csr_spki_sha256=${CSR_JOURNAL[csr_spki_sha256]}
certificate_sha256=${CSR_JOURNAL[certificate_sha256]}
chain_sha256=${CSR_JOURNAL[chain_sha256]}
issuer_root=$ACTIVE_ROOT_ID
issuer_intermediate=$ACTIVE_INTERMEDIATE_ID
serial=$ISSUED_SERIAL
response_sha256=${CSR_JOURNAL[response_manifest_sha256]}
response_signature_sha256=${CSR_JOURNAL[response_signature_sha256]}
created_epoch=${CSR_JOURNAL[created_epoch]}
EOF
}

pki_csr_finish_journal() {
  local identity
  CSR_JOURNAL[phase]=terminal
  CSR_JOURNAL[recovery_step]=journal-cleanup-pending
  pki_csr_write_journal
  pki_csr_fault before-journal-cleanup
  identity=$(pki_file_identity "$CSR_JOURNAL_PATH")
  pki_remove_identity_file "$CSR_JOURNAL_PATH" "$identity" terminal-journal || pki_die 'CSR signing journal changed before terminal cleanup'
  CSR_TERMINAL=true
}

pki_csr_require_bound_source() {
  local path=$1 identity=$2 digest=$3 label=$4
  [[ $path != none && $identity != none && $digest =~ ^[0-9a-f]{64}$ ]] || pki_die "$label is incomplete in the CSR recovery journal"
  pki_require_file_identity "$path" "$identity" "$label"
  [[ $(pki_csr_sha256 "$path") == "$digest" ]] || pki_die "$label digest changed"
}

pki_csr_open_response_key() {
  local key=$1 before opened current public expected algorithm payload extra
  pki_csr_require_protocol_file "$key" 'Response signing key'
  (( (8#$(stat -c '%a' "$key") & 077) == 0 )) || pki_die 'Response signing key permissions are too open'
  before=$(pki_file_identity "$key")
  exec {CSR_RESPONSE_KEY_FD}<"$key" || pki_die 'Cannot open response signing key'
  opened=$(stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$CSR_RESPONSE_KEY_FD") || { exec {CSR_RESPONSE_KEY_FD}<&-; CSR_RESPONSE_KEY_FD=''; pki_die 'Cannot inspect opened response signing key'; }
  current=$(pki_file_identity "$key")
  [[ $opened == "$before" && $current == "$before" ]] || { exec {CSR_RESPONSE_KEY_FD}<&-; CSR_RESPONSE_KEY_FD=''; pki_die 'Response signing key identity changed while opening'; }
  public=$(ssh-keygen -y -f "/proc/self/fd/$CSR_RESPONSE_KEY_FD" 2>/dev/null) || { exec {CSR_RESPONSE_KEY_FD}<&-; CSR_RESPONSE_KEY_FD=''; pki_die 'Cannot derive response signing public key'; }
  IFS=' ' read -r algorithm payload extra <<<"$public"
  expected=$(pki_csr_allowed_key "${CSR_JOURNAL[response_trust_path]}" "${CSR_JOURNAL[response_principal]}")
  [[ $algorithm == ssh-ed25519 && $payload == "$expected" ]] || { exec {CSR_RESPONSE_KEY_FD}<&-; CSR_RESPONSE_KEY_FD=''; pki_die 'Response signing key does not match the pinned response signer'; }
  [[ $(pki_file_identity "$key") == "$before" ]] || { exec {CSR_RESPONSE_KEY_FD}<&-; CSR_RESPONSE_KEY_FD=''; pki_die 'Response signing key changed during validation'; }
  CSR_RESPONSE_KEY_PATH=$key
  CSR_RESPONSE_KEY_IDENTITY=$before
}

pki_csr_close_response_key() {
  [[ -z ${CSR_RESPONSE_KEY_FD:-} ]] || exec {CSR_RESPONSE_KEY_FD}<&-
  CSR_RESPONSE_KEY_FD=''
}

pki_csr_sign_response() {
  local key=$1 manifest=${CSR_JOURNAL[response_manifest_path]} signature=${CSR_JOURNAL[response_signature_path]} current status=0
  if [[ ${CSR_JOURNAL[response_signature_identity]} != none || ${CSR_JOURNAL[response_signature_sha256]} != none ]]; then
    [[ ${CSR_JOURNAL[response_signature_identity]} != none && ${CSR_JOURNAL[response_signature_sha256]} =~ ^[0-9a-f]{64}$ ]] || pki_die 'CSR response signature checkpoint is incomplete'
    pki_csr_require_bound_source "$signature" "${CSR_JOURNAL[response_signature_identity]}" "${CSR_JOURNAL[response_signature_sha256]}" 'Journaled CSR response signature'
    pki_csr_verify_signature "${CSR_JOURNAL[response_trust_path]}" "${CSR_JOURNAL[response_principal]}" platform-pki-csr-response-v1 "$signature" "$manifest" 'CSR response'
    return 0
  fi
  if [[ -e $signature || -L $signature ]]; then
    [[ -f $signature && ! -L $signature && $(stat -c '%u:%a:%h' "$signature") == "$(id -u):600:1" ]] || pki_die 'Uncheckpointed CSR response signature is unsafe'
    current=$(pki_file_identity "$signature")
    pki_remove_identity_file "$signature" "$current" || pki_die 'Cannot remove uncheckpointed CSR response signature'
  fi
  [[ -n $key ]] || pki_die 'CSR recovery requires --response-key to complete committed response publication'
  pki_csr_open_response_key "$key"
  ssh-keygen -Y sign -f "/proc/self/fd/$CSR_RESPONSE_KEY_FD" -n platform-pki-csr-response-v1 "$manifest" >/dev/null || status=$?
  if (( status != 0 )); then pki_csr_close_response_key; pki_die 'Response signing failed; recovery-required state is retained'; fi
  [[ $(pki_file_identity "$CSR_RESPONSE_KEY_PATH") == "$CSR_RESPONSE_KEY_IDENTITY" ]] || { pki_csr_close_response_key; pki_die 'Response signing key changed during signing'; }
  pki_csr_close_response_key
  signature=$manifest.sig
  [[ -f $signature && ! -L $signature ]] || pki_die 'Response signing did not create a regular detached signature'
  chmod 600 "$signature"
  pki_csr_verify_signature "${CSR_JOURNAL[response_trust_path]}" "${CSR_JOURNAL[response_principal]}" platform-pki-csr-response-v1 "$signature" "$manifest" 'CSR response'
  CSR_JOURNAL[response_signature_identity]=$(pki_file_identity "$signature"); CSR_JOURNAL[response_signature_sha256]=$(pki_csr_sha256 "$signature")
  pki_csr_checkpoint response-signed
}

pki_csr_validate_artifact_entries() {
  local root=$1 kind=$2 completeness=$3
  [[ ! -e $root && ! -L $root ]] && return 0
  pki_require_private_dir "$root" "CSR $kind artifact directory"
  python3 - "$root" "$kind" "$completeness" "$(id -u)" <<'PY' || pki_die "CSR $kind artifact directory has unexpected or unsafe entries: $root"
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
kind = sys.argv[2]
complete = sys.argv[3] == "complete"
owner = int(sys.argv[4])
expected = {"tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig"}
if kind == "candidate":
    expected.add("candidate")
entries = sorted(os.scandir(root), key=lambda entry: entry.name)
names = {entry.name for entry in entries}
if (complete and names != expected) or (not complete and not names <= expected):
    raise SystemExit(1)
for entry in entries:
    metadata = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(1)
PY
}

pki_csr_prepare_artifact() {
  local kind=$1 root record source destination name content identity_field expected
  if [[ $kind == candidate ]]; then root=${CSR_JOURNAL[candidate_stage]}; record=$root/candidate; identity_field=candidate_stage_identity
  else root=${CSR_JOURNAL[response_stage]}; record=''; identity_field=response_stage_identity; fi
  expected=${CSR_JOURNAL[$identity_field]}
  if [[ ! -e $root && ! -L $root ]]; then
    [[ $expected == none ]] || pki_die "Staged CSR $kind artifact disappeared after its identity was journaled"
    mkdir -m 700 -- "$root" || pki_die "Cannot create staged CSR $kind artifact"
    expected=$(pki_dir_identity "$root") || pki_die "Cannot snapshot staged CSR $kind artifact identity"
    CSR_JOURNAL[$identity_field]=$expected
    pki_csr_write_journal
  else
    [[ $expected != none ]] || pki_die "Unowned staged CSR $kind artifact already exists"
    [[ $(pki_dir_identity "$root") == "$expected" ]] || pki_die "Staged CSR $kind artifact identity changed"
  fi
  pki_require_private_dir "$root" "Staged CSR $kind artifact"
  pki_csr_validate_artifact_entries "$root" "$kind" partial
  for name in tls.crt ca-chain.crt fullchain.crt response response.sig; do
    case $name in
      tls.crt) source=${CSR_JOURNAL[certificate_path]} ;;
      ca-chain.crt) source=${CSR_JOURNAL[chain_path]} ;;
      fullchain.crt) source=${CSR_JOURNAL[fullchain_path]} ;;
      response) source=${CSR_JOURNAL[response_manifest_path]} ;;
      response.sig) source=${CSR_JOURNAL[response_signature_path]} ;;
    esac
    [[ $(pki_dir_identity "$root") == "$expected" ]] || pki_die "Staged CSR $kind artifact identity changed before copy"
    destination=$root/$name
    cp -p -- "$source" "$destination" || pki_die "Cannot stage CSR $kind artifact file: $name"
    chmod 600 "$destination"
  done
  if [[ $kind == candidate ]]; then
    [[ $(pki_dir_identity "$root") == "$expected" ]] || pki_die 'Staged CSR candidate artifact identity changed before record creation'
    content=$(pki_csr_candidate_record_content)$'\n'
    pki_atomic_write "$record" "$content"
  fi
  pki_fsync_tree "$root"
  [[ $(pki_dir_identity "$root") == "$expected" ]] || pki_die "Staged CSR $kind artifact identity changed during preparation"
  pki_csr_validate_artifact_entries "$root" "$kind" complete
}

pki_csr_validate_published_artifact() {
  local root=$1 kind=$2 expected_identity=${3:-none} name expected candidate_digest before after
  before=$(pki_dir_identity "$root") || pki_die "Cannot inspect published CSR $kind artifact identity"
  [[ $expected_identity == none || $before == "$expected_identity" ]] || pki_die "Published CSR $kind artifact identity changed"
  pki_require_private_dir "$root" "Published CSR $kind artifact"
  pki_csr_validate_artifact_entries "$root" "$kind" complete
  for name in tls.crt ca-chain.crt fullchain.crt response response.sig; do
    [[ -f $root/$name && ! -L $root/$name && $(stat -c '%u:%a:%h' "$root/$name") == "$(id -u):600:1" ]] || pki_die "Published CSR $kind artifact is incomplete"
    case $name in
      tls.crt) expected=${CSR_JOURNAL[certificate_sha256]} ;;
      ca-chain.crt) expected=${CSR_JOURNAL[chain_sha256]} ;;
      fullchain.crt) expected=${CSR_JOURNAL[fullchain_sha256]} ;;
      response) expected=${CSR_JOURNAL[response_manifest_sha256]} ;;
      response.sig) expected=${CSR_JOURNAL[response_signature_sha256]} ;;
    esac
    [[ $(pki_csr_sha256 "$root/$name") == "$expected" ]] || pki_die "Published CSR $kind artifact digest changed: $name"
  done
  if [[ $kind == candidate ]]; then
    [[ -f $root/candidate && ! -L $root/candidate && $(stat -c '%u:%a:%h' "$root/candidate") == "$(id -u):600:1" ]] || pki_die 'Published CSR candidate record is missing or unsafe'
    candidate_digest=$(pki_csr_candidate_record_content | sha256sum); candidate_digest=${candidate_digest%% *}
    [[ $(pki_csr_sha256 "$root/candidate") == "$candidate_digest" ]] || pki_die 'Published CSR candidate record changed'
  fi
  after=$(pki_dir_identity "$root") || pki_die "Cannot reinspect published CSR $kind artifact identity"
  [[ $after == "$before" ]] || pki_die "Published CSR $kind artifact changed while being verified"
  PKI_CSR_VALIDATED_ARTIFACT_IDENTITY=$before
}

pki_csr_publish_artifact() {
  local kind=$1 stage destination identity_field stage_identity_field expected allowed_step
  if [[ $kind == candidate ]]; then stage=${CSR_JOURNAL[candidate_stage]}; destination=${CSR_JOURNAL[candidate_destination]}; identity_field=candidate_destination_identity; stage_identity_field=candidate_stage_identity; allowed_step=response-signed
  else stage=${CSR_JOURNAL[response_stage]}; destination=${CSR_JOURNAL[response_destination]}; identity_field=response_destination_identity; stage_identity_field=response_stage_identity; allowed_step=candidate-published; fi
  expected=${CSR_JOURNAL[$identity_field]}
  if [[ -d $destination && ! -L $destination ]]; then
    if [[ $expected == none ]]; then
      [[ ${CSR_JOURNAL[recovery_step]} == "$allowed_step" && ${CSR_JOURNAL[$stage_identity_field]} != none && ! -e $stage && ! -L $stage ]] || \
        pki_die "Published CSR $kind artifact has no identity outside the rename checkpoint window"
      expected=${CSR_JOURNAL[$stage_identity_field]}
    fi
    pki_csr_validate_published_artifact "$destination" "$kind" "$expected"
    if [[ ${CSR_JOURNAL[$identity_field]} == none ]]; then CSR_JOURNAL[$identity_field]=$PKI_CSR_VALIDATED_ARTIFACT_IDENTITY; pki_csr_write_journal; fi
    return 0
  fi
  [[ ! -e $destination && ! -L $destination ]] || pki_die "CSR $kind publication destination is unsafe"
  pki_csr_validate_artifact_entries "$stage" "$kind" complete
  [[ ${CSR_JOURNAL[$stage_identity_field]} != none && $(pki_dir_identity "$stage") == "${CSR_JOURNAL[$stage_identity_field]}" ]] || \
    pki_die "Staged CSR $kind artifact identity changed before publication"
  mv --no-copy --update=none-fail -T -- "$stage" "$destination" || pki_die "Cannot publish CSR $kind artifact"
  pki_fsync_rename_parents "$(dirname -- "$stage")" "$(dirname -- "$destination")"
  pki_csr_validate_published_artifact "$destination" "$kind" "${CSR_JOURNAL[$stage_identity_field]}"
  CSR_JOURNAL[$identity_field]=$PKI_CSR_VALIDATED_ARTIFACT_IDENTITY
  pki_csr_write_journal
}

pki_csr_resume_committed() {
  local response_key=$1 key path current
  for key in "${PKI_CSR_DB_KEYS[@]}"; do
    path=${CSR_JOURNAL[db_${key}_path]}; current=$(pki_file_identity_or_absent_full "$path")
    [[ $current == "${CSR_JOURNAL[db_${key}_post_identity]}" ]] || pki_die "Committed CSR CA state identity changed: $path"
  done
  pki_csr_remove_sensitive_key
  pki_csr_require_bound_source "${CSR_JOURNAL[response_trust_path]}" "${CSR_JOURNAL[response_trust_identity]}" "${CSR_JOURNAL[response_trust_sha256]}" 'Journaled CSR response trust'
  pki_csr_require_bound_source "${CSR_JOURNAL[certificate_path]}" "${CSR_JOURNAL[certificate_identity]}" "${CSR_JOURNAL[certificate_sha256]}" 'Journaled issued certificate'
  pki_csr_require_bound_source "${CSR_JOURNAL[chain_path]}" "${CSR_JOURNAL[chain_identity]}" "${CSR_JOURNAL[chain_sha256]}" 'Journaled CSR CA chain'
  pki_csr_require_bound_source "${CSR_JOURNAL[fullchain_path]}" "${CSR_JOURNAL[fullchain_identity]}" "${CSR_JOURNAL[fullchain_sha256]}" 'Journaled CSR full chain'
  pki_csr_require_bound_source "${CSR_JOURNAL[response_manifest_path]}" "${CSR_JOURNAL[response_manifest_identity]}" "${CSR_JOURNAL[response_manifest_sha256]}" 'Journaled unsigned response'
  pki_csr_sign_response "$response_key"
  pki_csr_require_bound_source "${CSR_JOURNAL[response_signature_path]}" "${CSR_JOURNAL[response_signature_identity]}" "${CSR_JOURNAL[response_signature_sha256]}" 'Journaled CSR response signature'
  pki_csr_validate_artifact_entries "${CSR_JOURNAL[candidate_stage]}" candidate partial
  pki_csr_validate_artifact_entries "${CSR_JOURNAL[response_stage]}" response partial
  [[ -e ${CSR_JOURNAL[candidate_destination]} || -L ${CSR_JOURNAL[candidate_destination]} ]] || pki_csr_prepare_artifact candidate
  [[ -e ${CSR_JOURNAL[response_destination]} || -L ${CSR_JOURNAL[response_destination]} ]] || pki_csr_prepare_artifact response
  pki_csr_publish_artifact candidate; pki_csr_checkpoint candidate-published
  pki_csr_publish_artifact response; pki_csr_checkpoint response-published
  pki_csr_write_terminal published
  pki_csr_finish_journal
  pki_ok "Published host-local CSR response: ${CSR_JOURNAL[response_destination]}"
  pki_ok "Recorded pending host-local candidate: ${CSR_JOURNAL[candidate_destination]}"
}

pki_csr_recover_loaded() {
  local response_key=${1:-}
  pki_csr_ensure_replay
  if [[ ${CSR_JOURNAL[committed]} == true ]]; then
    pki_csr_resume_committed "$response_key"
  else
    pki_csr_rollback_uncommitted_ca
    pki_csr_remove_sensitive_key
    CSR_JOURNAL[phase]=failed-pre-commit
    pki_csr_write_terminal failed-pre-commit
    pki_csr_finish_journal
    pki_ok "Terminalized uncommitted CSR request without reusing its identity: ${CSR_JOURNAL[request_id]}"
  fi
}

pki_csr_release_locks() {
  local status=${1:-0}
  [[ ${CSR_INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CSR_INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${CSR_INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CSR_INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${CSR_ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CSR_ROOT_LOCK" 2>/dev/null || status=1
  return "$status"
}

pki_csr_external_finish() {
  local status=$?
  trap - EXIT
  if [[ ${CSR_JOURNAL_STARTED:-false} == true && ${CSR_TERMINAL:-false} != true ]]; then
    if [[ ${CSR_JOURNAL[committed]:-false} == true ]]; then
      printf '[ERROR] Committed CSR signing requires explicit recovery: %s\n' "${CSR_JOURNAL[transaction]}" >&2
    else
      pki_csr_recover_loaded '' || status=1
    fi
  fi
  if [[ -n ${CSR_INPUT_DIR:-} && -n ${CSR_INPUT_DIR_IDENTITY:-} ]]; then
    pki_remove_journaled_tree "$CSR_INPUT_DIR" "$CSR_INPUT_DIR_IDENTITY" "$(dirname -- "$CSR_INPUT_DIR")" 2>/dev/null || status=1
  fi
  pki_csr_release_locks "$status" || status=1
  exit "$status"
}

pki_csr_initialize_journal() {
  local key transaction=$1
  unset -v CSR_JOURNAL
  declare -gA CSR_JOURNAL=()
  for key in "${PKI_CSR_JOURNAL_FIELDS[@]}"; do CSR_JOURNAL[$key]=none; done
  CSR_JOURNAL[schema]=1
  # shellcheck disable=SC2100 # CSR_JOURNAL is an associative array.
  CSR_JOURNAL[operation]=csr-sign
  CSR_JOURNAL[transaction]=$transaction
  CSR_JOURNAL[phase]=planned; CSR_JOURNAL[committed]=false; CSR_JOURNAL[recovery_step]=planned
  CSR_JOURNAL[request_id]=${CSR_REQUEST[request_id]}; CSR_JOURNAL[nonce]=${CSR_REQUEST[nonce]}
  CSR_JOURNAL[operation_kind]=${CSR_REQUEST[operation]}; CSR_JOURNAL[service]=${CSR_REQUEST[service]}; CSR_JOURNAL[target]=${CSR_REQUEST[target]}
  CSR_JOURNAL[requester_principal]=${CSR_REQUEST[requester_principal]}; CSR_JOURNAL[approver_principal]=${CSR_APPROVAL[approver_principal]}; CSR_JOURNAL[response_principal]=${CSR_REQUEST[response_principal]}
  CSR_JOURNAL[request_sha256]=$CSR_REQUEST_SHA256; CSR_JOURNAL[approval_sha256]=$CSR_APPROVAL_SHA256; CSR_JOURNAL[inventory_sha256]=$CSR_INVENTORY_SHA256
  CSR_JOURNAL[csr_sha256]=$CSR_CSR_SHA256; CSR_JOURNAL[csr_spki_sha256]=$CSR_ACTUAL_SPKI_SHA256; CSR_JOURNAL[current_cert_sha256]=${CSR_REQUEST[current_cert_sha256]}
  CSR_JOURNAL[created_epoch]=$(date -u +%s); CSR_JOURNAL[transaction_dir]="$PKI_DIR/state/csr/transactions/$transaction"
  CSR_JOURNAL[response_trust_path]="${CSR_JOURNAL[transaction_dir]}/responses.allowed_signers"
  CSR_JOURNAL[sensitive_key_path]="${CSR_JOURNAL[transaction_dir]}/signing/private/intermediate-ca.key"
  CSR_JOURNAL[replay_request_path]="$PKI_DIR/state/csr/replay/requests/${CSR_REQUEST[request_id]}"
  CSR_JOURNAL[replay_nonce_path]="$PKI_DIR/state/csr/replay/nonces/${CSR_REQUEST[nonce]}"
  CSR_JOURNAL[candidate_stage]="${CSR_JOURNAL[transaction_dir]}/candidate.publish"
  CSR_JOURNAL[response_stage]="${CSR_JOURNAL[transaction_dir]}/response.publish"
  CSR_JOURNAL[candidate_destination]="$PKI_DIR/state/csr/candidates/$SERVICE/${CSR_REQUEST[request_id]}"
  CSR_JOURNAL[response_destination]="$PKI_DIR/state/csr/responses/$SERVICE/${CSR_REQUEST[request_id]}"
}

pki_csr_build_response_manifest() {
  local cert=$1 manifest=$2 not_before not_after serial
  not_before=$(date -u -d "$(openssl x509 -in "$cert" -noout -startdate | sed 's/^notBefore=//')" +%s)
  not_after=$(date -u -d "$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')" +%s)
  serial=$(openssl x509 -in "$cert" -noout -serial); serial=${serial#serial=}; serial=${serial#Serial=}; serial=${serial^^}
  cat >"$manifest" <<EOF
schema=1
request_id=${CSR_REQUEST[request_id]}
nonce=${CSR_REQUEST[nonce]}
operation=${CSR_REQUEST[operation]}
service=$SERVICE
target=${CSR_REQUEST[target]}
request_sha256=$CSR_REQUEST_SHA256
approval_sha256=$CSR_APPROVAL_SHA256
inventory_sha256=$CSR_INVENTORY_SHA256
csr_sha256=$CSR_CSR_SHA256
csr_spki_sha256=$CSR_ACTUAL_SPKI_SHA256
certificate_sha256=${CSR_JOURNAL[certificate_sha256]}
certificate_spki_sha256=$CSR_ACTUAL_SPKI_SHA256
chain_sha256=${CSR_JOURNAL[chain_sha256]}
issuer_root=$ACTIVE_ROOT_ID
issuer_intermediate=$ACTIVE_INTERMEDIATE_ID
serial=$serial
not_before_epoch=$not_before
not_after_epoch=$not_after
candidate_state=pending
response_principal=$CSR_RESPONSE_PRINCIPAL
created_epoch=${CSR_JOURNAL[created_epoch]}
EOF
  chmod 600 "$manifest"
}

# shellcheck disable=SC2154 # Bashly defines the global args associative array.
pki_csr_sign_external() {
  local command_kind=$1 request_file request_signature approval_file approval_signature csr_file response_key current_cert transaction key source destination
  umask 077
  request_file=$(pki_expand_path "${args[--request-file]}"); request_signature=$(pki_expand_path "${args[--request-signature]}")
  approval_file=$(pki_expand_path "${args[--approval-file]}"); approval_signature=$(pki_expand_path "${args[--approval-signature]}")
  csr_file=$(pki_expand_path "${args[--csr-file]}"); response_key=$(pki_expand_path "${args[--response-key]}"); current_cert=${args[--current-cert-file]:-}
  [[ -z $current_cert ]] || current_cert=$(pki_expand_path "$current_cert")
  pki_require_cmd openssl; pki_require_cmd ssh-keygen; pki_require_cmd python3; pki_require_cmd sha256sum
  pki_require_pki_dir; pki_prepare_control_state
  CSR_ROOT_LOCK=$(pki_root_operation_lock); CSR_INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); CSR_INVENTORY_LOCK=$(pki_inventory_operation_lock)
  CSR_ROOT_LOCK_HELD=false; CSR_INTERMEDIATE_LOCK_HELD=false; CSR_INVENTORY_LOCK_HELD=false; CSR_JOURNAL_STARTED=false; CSR_TERMINAL=false; CSR_INPUT_DIR=''; CSR_INPUT_DIR_IDENTITY=''
  trap pki_csr_external_finish EXIT
  pki_acquire_operation_lock "$CSR_ROOT_LOCK" 'root CA operation'; CSR_ROOT_LOCK_HELD=true
  pki_acquire_operation_lock "$CSR_INTERMEDIATE_LOCK" 'intermediate CA operation'; CSR_INTERMEDIATE_LOCK_HELD=true
  pki_acquire_operation_lock "$CSR_INVENTORY_LOCK" 'inventory operation'; CSR_INVENTORY_LOCK_HELD=true
  pki_require_no_unresolved_journal
  CSR_INPUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-csr-sign.XXXXXX") || pki_die 'Cannot create CSR input staging directory'
  CSR_INPUT_DIR_IDENTITY=$(pki_dir_identity "$CSR_INPUT_DIR") || pki_die 'Cannot snapshot CSR input staging directory identity'
  DNS_FILE=$CSR_INPUT_DIR/dns; IPS_FILE=$CSR_INPUT_DIR/ips; : >"$DNS_FILE"; : >"$IPS_FILE"
  mkdir -m 700 -- "$CSR_INPUT_DIR/inventory"
  pki_load_inventory_snapshot "$CSR_INPUT_DIR/inventory"
  pki_require_service_in_inventory "$SERVICE"
  [[ $(pki_inventory_key_custody "$SERVICE") == host-local ]] || pki_die "--csr-file is allowed only for key_custody: host-local: $SERVICE"
  COMMON_NAME=$(pki_inventory_scalar "$SERVICE" common_name); pki_inventory_array "$SERVICE" dns >"$DNS_FILE"; pki_inventory_array "$SERVICE" ips >"$IPS_FILE"
  pki_validate_service_inventory_values "$SERVICE" "$COMMON_NAME" "$DNS_FILE" "$IPS_FILE"
  DAYS=$(pki_inventory_scalar "$SERVICE" days); DAYS=${DAYS:-${PLATFORM_PKI_SERVICE_DAYS:-397}}; pki_validate_days "$DAYS"
  CSR_INVENTORY_SHA256=$(pki_csr_sha256 "$(pki_inventory_file)")
  pki_csr_load_policy
  pki_csr_copy_protocol_file "$request_file" "$CSR_INPUT_DIR/request" 'CSR request manifest'
  pki_csr_copy_protocol_file "$request_signature" "$CSR_INPUT_DIR/request.sig" 'CSR request signature'
  pki_csr_copy_protocol_file "$approval_file" "$CSR_INPUT_DIR/approval" 'CSR approval manifest'
  pki_csr_copy_protocol_file "$approval_signature" "$CSR_INPUT_DIR/approval.sig" 'CSR approval signature'
  pki_csr_copy_protocol_file "$csr_file" "$CSR_INPUT_DIR/tls.csr" 'Host-local CSR'
  pki_csr_copy_protocol_file "$CSR_TRUST_DIR/responses.allowed_signers" "$CSR_INPUT_DIR/responses.allowed_signers" 'CSR response trust'
  declare -gA CSR_REQUEST=() CSR_APPROVAL=()
  pki_csr_read_ordered_record "$CSR_INPUT_DIR/request" 'CSR request manifest' CSR_REQUEST "${PKI_CSR_REQUEST_FIELDS[@]}"
  pki_csr_read_ordered_record "$CSR_INPUT_DIR/approval" 'CSR approval manifest' CSR_APPROVAL "${PKI_CSR_APPROVAL_FIELDS[@]}"
  [[ ${CSR_REQUEST[schema]} == 1 && ${CSR_APPROVAL[schema]} == 1 ]] || pki_die 'CSR request or approval schema is unsupported'
  [[ ${CSR_REQUEST[request_id]} =~ ^[0-9a-f]{32}$ && ${CSR_REQUEST[nonce]} =~ ^[0-9a-f]{64}$ ]] || pki_die 'CSR request ID or nonce is invalid'
  [[ ${CSR_REQUEST[service]} == "$SERVICE" && ${CSR_REQUEST[target]} =~ ^[a-z0-9][a-z0-9.-]*$ && ${CSR_REQUEST[requester_principal]} =~ ^[a-z0-9][a-z0-9.-]*$ ]] || pki_die 'CSR request service, target, or requester is invalid'
  [[ ${CSR_REQUEST[requester_principal]} == "${CSR_REQUEST[target]}" ]] || pki_die 'CSR requester principal must exactly match the target identity'
  [[ ${CSR_REQUEST[target]} == "$(pki_inventory_scalar "$SERVICE" target)" ]] || pki_die 'CSR request target and requester principal must exactly match inventory target'
  [[ ${CSR_REQUEST[profile]} == server-p384-sha384-v1 && ${CSR_REQUEST[response_principal]} == "$CSR_RESPONSE_PRINCIPAL" ]] || pki_die 'CSR request profile or response signer is invalid'
  if [[ $command_kind == issue ]]; then [[ ${CSR_REQUEST[operation]} == issue || ${CSR_REQUEST[operation]} == migrate ]] || pki_die 'Issue accepts only issue or migrate CSR requests'; else [[ ${CSR_REQUEST[operation]} == renew ]] || pki_die 'Renew accepts only renew CSR requests'; fi
  for key in request_id nonce operation service target csr_sha256 inventory_sha256 profile; do [[ ${CSR_APPROVAL[$key]} == "${CSR_REQUEST[$key]}" ]] || pki_die "CSR approval does not bind request field: $key"; done
  [[ ${CSR_APPROVAL[approver_principal]} == "$CSR_APPROVER_PRINCIPAL" ]] || pki_die 'CSR approval principal does not match policy'
  CSR_REQUEST_SHA256=$(pki_csr_sha256 "$CSR_INPUT_DIR/request"); CSR_APPROVAL_SHA256=$(pki_csr_sha256 "$CSR_INPUT_DIR/approval"); CSR_CSR_SHA256=$(pki_csr_sha256 "$CSR_INPUT_DIR/tls.csr")
  [[ ${CSR_APPROVAL[request_sha256]} == "$CSR_REQUEST_SHA256" && ${CSR_REQUEST[csr_sha256]} == "$CSR_CSR_SHA256" && ${CSR_REQUEST[inventory_sha256]} == "$CSR_INVENTORY_SHA256" ]] || pki_die 'CSR request, approval, inventory, or CSR digest binding failed'
  pki_csr_verify_signature "$CSR_TRUST_DIR/requesters.allowed_signers" "${CSR_REQUEST[requester_principal]}" platform-pki-csr-request-v1 "$CSR_INPUT_DIR/request.sig" "$CSR_INPUT_DIR/request" 'CSR request'
  pki_csr_verify_signature "$CSR_TRUST_DIR/approvers.allowed_signers" "${CSR_APPROVAL[approver_principal]}" platform-pki-csr-approval-v1 "$CSR_INPUT_DIR/approval.sig" "$CSR_INPUT_DIR/approval" 'CSR approval'
  pki_csr_recheck_trust
  pki_csr_validate_times
  pki_csr_validate_csr "$CSR_INPUT_DIR/tls.csr" "$CSR_INPUT_DIR"
  [[ ${CSR_REQUEST[csr_spki_sha256]} == "$CSR_ACTUAL_SPKI_SHA256" ]] || pki_die 'CSR public-key digest binding failed'
  pki_require_generation_layout; pki_load_active_issuer_snapshot
  ROOT_CERT=$(pki_root_cert); INT_KEY=$(pki_intermediate_key); INT_CERT=$(pki_intermediate_cert); INT_CONF="$INTERMEDIATE_CA_DIR/openssl.cnf"
  if [[ ${CSR_REQUEST[operation]} == issue ]]; then
    [[ ${CSR_REQUEST[current_cert_sha256]} == none && ! -e $(pki_service_key "$SERVICE") && ! -e $(pki_service_cert "$SERVICE") ]] || pki_die 'New host-local issue conflicts with existing managed service state'
  elif [[ ${CSR_REQUEST[operation]} == migrate ]]; then
    source=$(pki_service_cert "$SERVICE"); [[ -f $source && -f $(pki_service_key "$SERVICE") ]] || pki_die 'Host-local migration requires preserved managed key and certificate state'
    [[ ${CSR_REQUEST[current_cert_sha256]} == "$(pki_csr_sha256 "$source")" ]] || pki_die 'Migration request does not bind the managed certificate'
  else
    [[ -n $current_cert ]] || pki_die 'Host-local renewal requires --current-cert-file'
    pki_csr_require_protocol_file "$current_cert" 'Current host-local certificate'
    [[ ${CSR_REQUEST[current_cert_sha256]} == "$(pki_csr_sha256 "$current_cert")" ]] || pki_die 'Renewal request does not bind the current certificate'
    pki_csr_require_active_predecessor
    openssl verify -CAfile "$ROOT_CERT" -untrusted "$INT_CERT" "$current_cert" >/dev/null 2>&1 || pki_die 'Current host-local certificate does not verify against the active issuer'
  fi
  pki_csr_prepare_state_dirs
  [[ ${CSR_REQUEST[operation]} != renew ]] || pki_csr_reject_unresolved_predecessor_candidate
  [[ ! -e $PKI_DIR/state/csr/replay/requests/${CSR_REQUEST[request_id]} && ! -L $PKI_DIR/state/csr/replay/requests/${CSR_REQUEST[request_id]} ]] || pki_die 'CSR request ID has already been consumed'
  [[ ! -e $PKI_DIR/state/csr/replay/nonces/${CSR_REQUEST[nonce]} && ! -L $PKI_DIR/state/csr/replay/nonces/${CSR_REQUEST[nonce]} ]] || pki_die 'CSR request nonce has already been consumed'
  transaction="csr-${CSR_REQUEST[request_id]}"; CSR_JOURNAL_PATH=$(pki_csr_recovery_journal); pki_csr_initialize_journal "$transaction"
  [[ ! -e ${CSR_JOURNAL[transaction_dir]} && ! -L ${CSR_JOURNAL[transaction_dir]} ]] || pki_die 'CSR signing transaction path already exists'
  pki_csr_write_journal; CSR_JOURNAL_STARTED=true; pki_csr_fault after-journal
  pki_csr_ensure_replay; pki_csr_checkpoint replay-reserved
  mkdir -m 700 -- "${CSR_JOURNAL[transaction_dir]}" || pki_die 'Cannot create CSR signing transaction directory'
  CSR_JOURNAL[transaction_identity]=$(pki_dir_identity "${CSR_JOURNAL[transaction_dir]}")
  mkdir -m 700 -- "${CSR_JOURNAL[transaction_dir]}/signing" "${CSR_JOURNAL[transaction_dir]}/signing/private" \
    "${CSR_JOURNAL[transaction_dir]}/signing/certs" "${CSR_JOURNAL[transaction_dir]}/signing/crl" \
    "${CSR_JOURNAL[transaction_dir]}/signing/newcerts" "${CSR_JOURNAL[transaction_dir]}/ca-backup"
  for name in request request.sig approval approval.sig tls.csr responses.allowed_signers; do mv --no-copy --update=none-fail -T -- "$CSR_INPUT_DIR/$name" "${CSR_JOURNAL[transaction_dir]}/$name"; done
  CSR_JOURNAL[response_trust_identity]=$(pki_file_identity "${CSR_JOURNAL[response_trust_path]}"); CSR_JOURNAL[response_trust_sha256]=$(pki_csr_sha256 "${CSR_JOURNAL[response_trust_path]}")
  mkdir -m 700 -- "${CSR_JOURNAL[candidate_destination]%/*}" "${CSR_JOURNAL[response_destination]%/*}" 2>/dev/null || { [[ -d ${CSR_JOURNAL[candidate_destination]%/*} && -d ${CSR_JOURNAL[response_destination]%/*} ]] || pki_die 'Cannot create CSR artifact service directories'; }
  pki_require_private_dir "${CSR_JOURNAL[candidate_destination]%/*}" 'CSR candidate service directory'
  pki_require_private_dir "${CSR_JOURNAL[response_destination]%/*}" 'CSR response service directory'
  pki_csr_checkpoint transaction-staged
  STAGE_INT_DIR="${CSR_JOURNAL[transaction_dir]}/signing"; cp -p -- "$INT_KEY" "${CSR_JOURNAL[sensitive_key_path]}"; chmod 600 "${CSR_JOURNAL[sensitive_key_path]}"; CSR_JOURNAL[sensitive_key_identity]=$(pki_file_identity "${CSR_JOURNAL[sensitive_key_path]}")
  cp -p -- "$INT_CERT" "$STAGE_INT_DIR/certs/intermediate-ca.crt"; process_intermediate_signing_config "$INT_CONF" "$STAGE_INT_DIR/openssl.cnf"; chmod 600 "$STAGE_INT_DIR/openssl.cnf"
  ISSUED_SERIAL=$(<"$INTERMEDIATE_CA_DIR/serial"); ISSUED_SERIAL=${ISSUED_SERIAL^^}; while [[ $ISSUED_SERIAL == 00* && ${#ISSUED_SERIAL} -gt 2 ]]; do ISSUED_SERIAL=${ISSUED_SERIAL#00}; done
  [[ $ISSUED_SERIAL =~ ^[0-9A-F]+$ && ${#ISSUED_SERIAL} -ge 2 && $((${#ISSUED_SERIAL} % 2)) -eq 0 ]] || pki_die 'Intermediate CA serial is invalid for CSR signing'
  for key in "${PKI_CSR_DB_KEYS[@]}"; do
    case $key in index) source=index.txt ;; index_attr) source=index.txt.attr ;; serial) source=serial ;; index_old) source=index.txt.old ;; index_attr_old) source=index.txt.attr.old ;; serial_old) source=serial.old ;; newcert) source="newcerts/$ISSUED_SERIAL.pem" ;; esac
    destination=$INTERMEDIATE_CA_DIR/$source; CSR_JOURNAL[db_${key}_path]=$destination; CSR_JOURNAL[db_${key}_pre_identity]=$(pki_file_identity_or_absent_full "$destination")
    CSR_JOURNAL[db_${key}_source]="$STAGE_INT_DIR/$source"; CSR_JOURNAL[db_${key}_backup]="${CSR_JOURNAL[transaction_dir]}/ca-backup/$key"
    if [[ ${CSR_JOURNAL[db_${key}_pre_identity]} != absent ]]; then cp -p -- "$destination" "${CSR_JOURNAL[db_${key}_backup]}"; CSR_JOURNAL[db_${key}_backup_identity]=$(pki_file_identity "${CSR_JOURNAL[db_${key}_backup]}"); fi
  done
  for source in index.txt index.txt.attr serial crlnumber; do cp -p -- "$INTERMEDIATE_CA_DIR/$source" "$STAGE_INT_DIR/$source"; done
  pki_csr_checkpoint signing-ready
  CA_CMD=(openssl ca -batch -config "$STAGE_INT_DIR/openssl.cnf" -extfile "$CSR_INPUT_DIR/service.cnf" -extensions server_cert -days "$DAYS" -notext -md sha384 -in "${CSR_JOURNAL[transaction_dir]}/tls.csr" -out "$STAGE_INT_DIR/tls.crt")
  pki_write_service_config "$CSR_INPUT_DIR/service.cnf" "$COMMON_NAME" "$DNS_FILE" "$IPS_FILE"
  [[ -n ${INTERMEDIATE_PASS_FILE:-} ]] && CA_CMD+=(-passin "file:$INTERMEDIATE_PASS_FILE")
  "${CA_CMD[@]}"; chmod 600 "$STAGE_INT_DIR/tls.crt"
  for key in "${PKI_CSR_DB_KEYS[@]}"; do chmod 600 "${CSR_JOURNAL[db_${key}_source]}"; done
  pki_validate_child_validity "$STAGE_INT_DIR/tls.crt" "$INT_CERT" "$ISSUER_SAFETY_DAYS"
  pki_csr_validate_certificate "$STAGE_INT_DIR/tls.crt" "${CSR_JOURNAL[transaction_dir]}/tls.csr" "$CSR_INPUT_DIR"
  cat "$INT_CERT" "$ROOT_CERT" >"$STAGE_INT_DIR/ca-chain.crt"; cat "$STAGE_INT_DIR/tls.crt" "$INT_CERT" >"$STAGE_INT_DIR/fullchain.crt"; chmod 600 "$STAGE_INT_DIR/ca-chain.crt" "$STAGE_INT_DIR/fullchain.crt"
  CSR_JOURNAL[certificate_path]="$STAGE_INT_DIR/tls.crt"; CSR_JOURNAL[certificate_identity]=$(pki_file_identity "$STAGE_INT_DIR/tls.crt"); CSR_JOURNAL[certificate_sha256]=$(pki_csr_sha256 "$STAGE_INT_DIR/tls.crt")
  CSR_JOURNAL[chain_path]="$STAGE_INT_DIR/ca-chain.crt"; CSR_JOURNAL[chain_identity]=$(pki_file_identity "$STAGE_INT_DIR/ca-chain.crt"); CSR_JOURNAL[chain_sha256]=$(pki_csr_sha256 "$STAGE_INT_DIR/ca-chain.crt")
  CSR_JOURNAL[fullchain_path]="$STAGE_INT_DIR/fullchain.crt"; CSR_JOURNAL[fullchain_identity]=$(pki_file_identity "$STAGE_INT_DIR/fullchain.crt"); CSR_JOURNAL[fullchain_sha256]=$(pki_csr_sha256 "$STAGE_INT_DIR/fullchain.crt")
  CSR_JOURNAL[response_manifest_path]="$STAGE_INT_DIR/response"; CSR_JOURNAL[response_signature_path]="$STAGE_INT_DIR/response.sig"
  pki_csr_build_response_manifest "$STAGE_INT_DIR/tls.crt" "$STAGE_INT_DIR/response"
  CSR_JOURNAL[response_manifest_identity]=$(pki_file_identity "$STAGE_INT_DIR/response"); CSR_JOURNAL[response_manifest_sha256]=$(pki_csr_sha256 "$STAGE_INT_DIR/response")
  for key in "${PKI_CSR_DB_KEYS[@]}"; do source=${CSR_JOURNAL[db_${key}_source]}; [[ -f $source ]] || pki_die "Staged CA signing output is missing: $key"; CSR_JOURNAL[db_${key}_source_identity]=$(pki_file_identity "$source"); CSR_JOURNAL[db_${key}_source_object]=$(pki_file_object_state "$source"); done
  pki_fsync_tree "${CSR_JOURNAL[transaction_dir]}"; pki_csr_checkpoint signing-complete
  pki_csr_remove_sensitive_key; pki_csr_checkpoint sensitive-key-removed
  for key in "${PKI_CSR_DB_KEYS[@]}"; do
    pki_publish_staged_file_exact "${CSR_JOURNAL[db_${key}_source]}" "${CSR_JOURNAL[db_${key}_path]}"
    pki_csr_fault "after-ca-$key-publish"
    CSR_JOURNAL[db_${key}_post_identity]=$PKI_PUBLISHED_FILE_IDENTITY
    pki_csr_checkpoint "ca-$key-published"
  done
  CSR_JOURNAL[committed]=true; CSR_JOURNAL[phase]=ca-committed; pki_csr_checkpoint ca-committed
  pki_csr_resume_committed "$response_key"
  exit 0
}

pki_csr_recover() {
  local response_key=${1:-}
  pki_require_cmd ssh-keygen; pki_require_cmd sha256sum; pki_require_pki_dir; pki_prepare_control_state
  CSR_ROOT_LOCK=$(pki_root_operation_lock); CSR_INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); CSR_INVENTORY_LOCK=$(pki_inventory_operation_lock)
  CSR_ROOT_LOCK_HELD=false; CSR_INTERMEDIATE_LOCK_HELD=false; CSR_INVENTORY_LOCK_HELD=false; CSR_TERMINAL=false
  trap 'status=$?; trap - EXIT; pki_csr_release_locks "$status" || status=1; exit "$status"' EXIT
  pki_acquire_operation_lock "$CSR_ROOT_LOCK" 'root CA operation'; CSR_ROOT_LOCK_HELD=true
  pki_acquire_operation_lock "$CSR_INTERMEDIATE_LOCK" 'intermediate CA operation'; CSR_INTERMEDIATE_LOCK_HELD=true
  pki_acquire_operation_lock "$CSR_INVENTORY_LOCK" 'inventory operation'; CSR_INVENTORY_LOCK_HELD=true
  [[ $(pki_detect_layout) == generation ]] || pki_die 'CSR recovery requires complete generation-aware PKI state'
  CSR_JOURNAL_PATH=$(pki_csr_recovery_journal); [[ -f $CSR_JOURNAL_PATH && ! -L $CSR_JOURNAL_PATH ]] || pki_die 'No CSR signing recovery journal exists'
  pki_csr_read_journal
  [[ ${CSR_JOURNAL[transaction]} == "${args[--transaction]}" ]] || pki_die 'CSR recovery transaction does not match the journal'
  pki_read_pair_manifest "$(pki_active_issuer_manifest)" 'Active issuer'
  ROOT_CA_DIR=$(pki_root_authority_dir "$ACTIVE_ROOT_ID"); INTERMEDIATE_CA_DIR=$(pki_intermediate_authority_dir "$ACTIVE_INTERMEDIATE_ID")
  pki_require_private_dir "$ROOT_CA_DIR" 'Root authority generation'; pki_require_private_dir "$INTERMEDIATE_CA_DIR" 'Intermediate authority generation'
  pki_csr_validate_recovery_journal
  if [[ -e ${CSR_JOURNAL[transaction_dir]} || -L ${CSR_JOURNAL[transaction_dir]} ]]; then
    pki_require_private_dir "${CSR_JOURNAL[transaction_dir]}" 'CSR recovery transaction directory'
    [[ ${CSR_JOURNAL[transaction_identity]} != none ]] || pki_die 'Unowned CSR recovery transaction directory appeared'
    [[ $(pki_dir_identity "${CSR_JOURNAL[transaction_dir]}") == "${CSR_JOURNAL[transaction_identity]}" ]] || pki_die 'CSR recovery transaction directory identity changed'
  else
    [[ ${CSR_JOURNAL[transaction_identity]} == none && ${CSR_JOURNAL[committed]} == false ]] || pki_die 'CSR recovery transaction directory is missing'
  fi
  [[ -z $response_key ]] || response_key=$(pki_expand_path "$response_key")
  pki_csr_recover_loaded "$response_key"
}
