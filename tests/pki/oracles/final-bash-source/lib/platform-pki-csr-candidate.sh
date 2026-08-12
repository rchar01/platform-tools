#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031 # Historical validation intentionally isolates global request context in subshells.

PKI_CANDIDATE_RESPONSE_FIELDS=(
  schema request_id nonce operation service target request_sha256 approval_sha256
  inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256
  certificate_spki_sha256 chain_sha256 issuer_root issuer_intermediate serial
  not_before_epoch not_after_epoch candidate_state response_principal created_epoch
)
PKI_CANDIDATE_RECORD_FIELDS=(
  schema request_id nonce operation service target state request_sha256
  approval_sha256 inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256
  chain_sha256 issuer_root issuer_intermediate serial response_sha256
  response_signature_sha256 created_epoch
)
PKI_CANDIDATE_ARTIFACT_FIELDS=(
  schema kind service request_id operation target source_kind
  source_response_sha256 source_response_signature_sha256 certificate_sha256
  certificate_spki_sha256 chain_sha256 fullchain_sha256 issuer_root
  issuer_intermediate serial not_before_epoch not_after_epoch candidate_state
  deployment_state response_principal created_epoch
)
PKI_CANDIDATE_DEPLOYMENT_FIELDS=(
  schema request_id nonce operation service target request_sha256 response_sha256
  response_signature_sha256 candidate_sha256 artifact_request_id
  artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
  chain_sha256 fullchain_sha256 action result local_certificate_sha256
  local_key_spki_sha256 local_key_certificate_match served_certificate_sha256
  served_intermediate_sha256 validation_boundary_sha256 validation_result
  activation_epoch validation_epoch rollback_state rollback_hold_until_epoch
  deployment_principal created_epoch expires_epoch
)
PKI_CANDIDATE_ACTIVE_FIELDS=(
  schema service target request_id operation certificate_sha256
  certificate_spki_sha256 response_sha256 artifact_manifest_sha256
  deployment_sha256 decision_sha256 activation_epoch rollback_hold_until_epoch
  updated_epoch
)
PKI_CANDIDATE_DECISION_FIELDS=(
  schema action state service target request_id operation request_sha256
  response_sha256 response_signature_sha256 candidate_sha256
  artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
  chain_sha256 fullchain_sha256 deployment_sha256
  deployment_signature_sha256 deployers_sha256 predecessor_kind
  predecessor_request_id predecessor_certificate_sha256
  predecessor_certificate_spki_sha256 predecessor_intermediate_sha256 predecessor_response_sha256
  predecessor_artifact_manifest_sha256 predecessor_deployment_sha256
  predecessor_decision_sha256 resulting_active_request_id created_epoch
)
PKI_CANDIDATE_JOURNAL_FIELDS=(
  schema operation service request_id phase outcome_stage outcome_stage_identity
  outcome_destination outcome_destination_identity active_stage
  active_stage_identity active_destination active_pre_identity active_mode
  active_destination_identity active_pre_sha256 candidate_dir candidate_dir_identity
  response_dir response_dir_identity transaction_dir transaction_dir_identity
  response_trust_path response_trust_identity response_trust_sha256
  candidate_path candidate_identity candidate_sha256 artifact_dir
  artifact_dir_identity artifact_path artifact_identity artifact_sha256
  response_path response_identity response_sha256 response_signature_path
  response_signature_identity response_signature_sha256 deployment_sha256
  deployment_signature_sha256 deployers_sha256 decision_sha256 active_sha256
  outcome_deployment_identity outcome_deployment_signature_identity
  outcome_deployers_identity outcome_decision_identity
)
PKI_CANDIDATE_SOURCE_KEYS=(
  candidate_candidate candidate_tls_crt candidate_ca_chain_crt
  candidate_fullchain_crt candidate_response candidate_response_sig
  response_tls_crt response_ca_chain_crt response_fullchain_crt
  response_response response_response_sig artifact_artifact artifact_tls_crt
  artifact_ca_chain_crt artifact_fullchain_crt artifact_response
  artifact_response_sig
)
for pki_candidate_source_key in "${PKI_CANDIDATE_SOURCE_KEYS[@]}"; do
  PKI_CANDIDATE_JOURNAL_FIELDS+=(
    "source_${pki_candidate_source_key}_identity"
    "source_${pki_candidate_source_key}_sha256"
  )
done
unset pki_candidate_source_key

pki_candidate_load_inventory_snapshot() { pki_load_inventory_snapshot "$1"; }

pki_candidate_sha256() {
  local value before
  [[ -f $1 && ! -L $1 ]] || pki_die "$2 must be a non-symlink regular file: $1"
  before=$(pki_file_identity "$1") || pki_die "Cannot inspect $2"
  value=$(sha256sum -- "$1") || pki_die "Cannot hash $2"
  [[ $(pki_file_identity "$1") == "$before" ]] || pki_die "$2 changed while being hashed"
  printf '%s\n' "${value%% *}"
}

pki_candidate_require_digest() { [[ $1 =~ ^[0-9a-f]{64}$ ]] || pki_die "$2 must be a lowercase SHA-256 digest"; }
pki_candidate_require_epoch() { [[ $1 =~ ^(0|[1-9][0-9]*)$ ]] || pki_die "$2 must be a canonical decimal epoch"; }

pki_candidate_validate_time_math() {
  python3 - "$@" <<'PY'
import sys

kind, *values = sys.argv[1:]
numbers = [int(value) for value in values]
if kind == "fresh":
    created, expires, now = numbers
    valid = expires > created and expires - created <= 86400 and now + 300 >= created and now <= expires + 300
elif kind == "interval":
    created, expires = numbers
    valid = expires > created and expires - created <= 86400
elif kind == "ordered":
    activation, validation, created = numbers
    valid = activation <= validation <= created + 300
else:
    hold, created, seconds = numbers
    valid = hold >= created + seconds
raise SystemExit(0 if valid else 1)
PY
}

pki_candidate_validate_tree() {
  local root=$1 kind=$2
  [[ -d $root && ! -L $root ]] || pki_die "$kind must be a non-symlink directory: $root"
  python3 - "$root" "$kind" "$(id -u)" <<'PY' || pki_die "$kind has unexpected or unsafe entries: $root"
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
kind = sys.argv[2]
owner = int(sys.argv[3])
expected = {
    "candidate": {"candidate", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig"},
    "artifact": {"artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig"},
    "outcome": {"deployment", "deployment.sig", "deployers.allowed_signers", "decision"},
}[kind]
metadata = root.stat(follow_symlinks=False)
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit(1)
entries = list(os.scandir(root))
if {entry.name for entry in entries} != expected:
    raise SystemExit(1)
for entry in entries:
    metadata = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(1)
PY
}

pki_candidate_compare() {
  local first=$1 second=$2 label=$3 first_identity second_identity
  first_identity=$(pki_file_identity "$first"); second_identity=$(pki_file_identity "$second")
  cmp -s -- "$first" "$second" || pki_die "$label differs across immutable CSR artifacts"
  [[ $(pki_file_identity "$first") == "$first_identity" && $(pki_file_identity "$second") == "$second_identity" ]] || pki_die "$label changed while being compared"
}

pki_candidate_spki() {
  local output
  output=$(set -o pipefail; openssl x509 -in "$1" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || pki_die 'Cannot extract candidate certificate public key'
  printf '%s\n' "${output%% *}"
}

pki_candidate_recheck_sources() {
  local key path
  [[ $(pki_dir_identity "$CANDIDATE_DIR") == "$CANDIDATE_IDENTITY" && $(pki_dir_identity "$ARTIFACT_DIR") == "$ARTIFACT_IDENTITY" ]] || pki_die 'CSR candidate source directory identity changed'
  for key in "${!CANDIDATE_SOURCE_IDENTITIES[@]}"; do
    path=${CANDIDATE_SOURCE_PATHS[$key]}
    [[ -f $path && ! -L $path && $(pki_file_identity "$path") == "${CANDIDATE_SOURCE_IDENTITIES[$key]}" ]] || pki_die "CSR candidate source identity changed: $key"
  done
}

pki_candidate_validate_sources() {
  local name digest root_cert intermediate_cert transaction trust trust_identity transaction_identity
  local request_record nonce_record terminal serial not_before not_after
  CANDIDATE_DIR=$PKI_DIR/state/csr/candidates/$SERVICE/$REQUEST_ID
  RESPONSE_DIR=$PKI_DIR/state/csr/responses/$SERVICE/$REQUEST_ID
  ARTIFACT_DIR=$PKI_DIR/export/certificates/v1/artifacts/$SERVICE/$REQUEST_ID
  transaction=$PKI_DIR/state/csr/transactions/csr-$REQUEST_ID
  pki_candidate_validate_tree "$CANDIDATE_DIR" candidate
  pki_csr_validate_artifact_entries "$RESPONSE_DIR" response complete
  pki_candidate_validate_tree "$ARTIFACT_DIR" artifact
  CANDIDATE_IDENTITY=$(pki_dir_identity "$CANDIDATE_DIR")
  ARTIFACT_IDENTITY=$(pki_dir_identity "$ARTIFACT_DIR")
  unset -v CANDIDATE_SOURCE_IDENTITIES CANDIDATE_SOURCE_PATHS
  declare -gA CANDIDATE_SOURCE_IDENTITIES=() CANDIDATE_SOURCE_PATHS=()
  for name in candidate tls.crt ca-chain.crt fullchain.crt response response.sig; do
    CANDIDATE_SOURCE_PATHS[candidate/$name]=$CANDIDATE_DIR/$name
  done
  for name in tls.crt ca-chain.crt fullchain.crt response response.sig; do
    CANDIDATE_SOURCE_PATHS[response/$name]=$RESPONSE_DIR/$name
  done
  for name in artifact tls.crt ca-chain.crt fullchain.crt response response.sig; do
    CANDIDATE_SOURCE_PATHS[artifact/$name]=$ARTIFACT_DIR/$name
  done
  for name in "${!CANDIDATE_SOURCE_PATHS[@]}"; do CANDIDATE_SOURCE_IDENTITIES[$name]=$(pki_file_identity "${CANDIDATE_SOURCE_PATHS[$name]}"); done
  for name in tls.crt ca-chain.crt fullchain.crt response response.sig; do
    pki_candidate_compare "$CANDIDATE_DIR/$name" "$RESPONSE_DIR/$name" "$name"
    pki_candidate_compare "$ARTIFACT_DIR/$name" "$RESPONSE_DIR/$name" "$name"
  done

  unset -v CANDIDATE_RESPONSE CANDIDATE_RECORD CANDIDATE_ARTIFACT
  declare -gA CANDIDATE_RESPONSE=() CANDIDATE_RECORD=() CANDIDATE_ARTIFACT=()
  pki_csr_read_ordered_record "$RESPONSE_DIR/response" 'CSR response' CANDIDATE_RESPONSE "${PKI_CANDIDATE_RESPONSE_FIELDS[@]}"
  pki_csr_read_ordered_record "$CANDIDATE_DIR/candidate" 'CSR candidate' CANDIDATE_RECORD "${PKI_CANDIDATE_RECORD_FIELDS[@]}"
  pki_csr_read_ordered_record "$ARTIFACT_DIR/artifact" 'Certificate export manifest' CANDIDATE_ARTIFACT "${PKI_CANDIDATE_ARTIFACT_FIELDS[@]}"
  [[ $(wc -l <"$RESPONSE_DIR/response") -eq ${#PKI_CANDIDATE_RESPONSE_FIELDS[@]} && $(wc -l <"$CANDIDATE_DIR/candidate") -eq ${#PKI_CANDIDATE_RECORD_FIELDS[@]} && $(wc -l <"$ARTIFACT_DIR/artifact") -eq ${#PKI_CANDIDATE_ARTIFACT_FIELDS[@]} ]] || pki_die 'CSR candidate records are not canonically newline-terminated'
  [[ ${CANDIDATE_RESPONSE[schema]} == 1 && ${CANDIDATE_RECORD[schema]} == 1 && ${CANDIDATE_ARTIFACT[schema]} == 1 ]] || pki_die 'CSR candidate record schema is unsupported'
  [[ ${CANDIDATE_RESPONSE[request_id]} == "$REQUEST_ID" && ${CANDIDATE_RECORD[request_id]} == "$REQUEST_ID" && ${CANDIDATE_ARTIFACT[request_id]} == "$REQUEST_ID" ]] || pki_die 'CSR candidate request ID binding failed'
  [[ ${CANDIDATE_RESPONSE[nonce]} =~ ^[0-9a-f]{64}$ && ${CANDIDATE_RECORD[nonce]} == "${CANDIDATE_RESPONSE[nonce]}" ]] || pki_die 'CSR candidate nonce binding failed'
  [[ ${CANDIDATE_RESPONSE[service]} == "$SERVICE" && ${CANDIDATE_RECORD[service]} == "$SERVICE" && ${CANDIDATE_ARTIFACT[service]} == "$SERVICE" ]] || pki_die 'CSR candidate service binding failed'
  CANDIDATE_TARGET=${CANDIDATE_RESPONSE[target]}
  [[ $CANDIDATE_TARGET =~ ^[a-z0-9][a-z0-9.-]*$ && ${CANDIDATE_RECORD[target]} == "$CANDIDATE_TARGET" && ${CANDIDATE_ARTIFACT[target]} == "$CANDIDATE_TARGET" ]] || pki_die 'CSR candidate target binding failed'
  [[ $CANDIDATE_TARGET == "$INVENTORY_TARGET" ]] || pki_die 'CSR candidate target does not match inventory'
  [[ ${CANDIDATE_RESPONSE[operation]} == issue || ${CANDIDATE_RESPONSE[operation]} == migrate || ${CANDIDATE_RESPONSE[operation]} == renew ]] || pki_die 'CSR candidate operation is invalid'
  [[ ${CANDIDATE_RESPONSE[candidate_state]} == pending && ${CANDIDATE_RECORD[state]} == pending && ${CANDIDATE_ARTIFACT[candidate_state]} == pending && ${CANDIDATE_ARTIFACT[deployment_state]} == unfinalized ]] || pki_die 'CSR candidate is not pending and unfinalized'
  for name in request_id nonce operation service target request_sha256 approval_sha256 inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256 chain_sha256 issuer_root issuer_intermediate serial created_epoch; do
    [[ ${CANDIDATE_RECORD[$name]} == "${CANDIDATE_RESPONSE[$name]}" ]] || pki_die "CSR candidate does not bind response field: $name"
  done
  CANDIDATE_RESPONSE_SHA256=$(pki_candidate_sha256 "$RESPONSE_DIR/response" 'CSR response')
  CANDIDATE_RESPONSE_SIGNATURE_SHA256=$(pki_candidate_sha256 "$RESPONSE_DIR/response.sig" 'CSR response signature')
  CANDIDATE_SHA256=$(pki_candidate_sha256 "$CANDIDATE_DIR/candidate" 'CSR candidate')
  ARTIFACT_MANIFEST_SHA256=$(pki_candidate_sha256 "$ARTIFACT_DIR/artifact" 'Certificate export manifest')
  [[ ${CANDIDATE_RECORD[response_sha256]} == "$CANDIDATE_RESPONSE_SHA256" && ${CANDIDATE_RECORD[response_signature_sha256]} == "$CANDIDATE_RESPONSE_SIGNATURE_SHA256" ]] || pki_die 'CSR candidate signed-response binding failed'
  [[ ${CANDIDATE_ARTIFACT[kind]} == certificate-export && ${CANDIDATE_ARTIFACT[source_kind]} == csr-response && ${CANDIDATE_ARTIFACT[source_response_sha256]} == "$CANDIDATE_RESPONSE_SHA256" && ${CANDIDATE_ARTIFACT[source_response_signature_sha256]} == "$CANDIDATE_RESPONSE_SIGNATURE_SHA256" ]] || pki_die 'Certificate export source binding failed'
  for name in operation target issuer_root issuer_intermediate serial not_before_epoch not_after_epoch response_principal created_epoch; do [[ ${CANDIDATE_ARTIFACT[$name]} == "${CANDIDATE_RESPONSE[$name]}" ]] || pki_die "Certificate export does not bind response field: $name"; done

  CERTIFICATE_SHA256=$(pki_candidate_sha256 "$RESPONSE_DIR/tls.crt" 'Candidate certificate')
  CHAIN_SHA256=$(pki_candidate_sha256 "$RESPONSE_DIR/ca-chain.crt" 'Candidate chain')
  FULLCHAIN_SHA256=$(pki_candidate_sha256 "$RESPONSE_DIR/fullchain.crt" 'Candidate full chain')
  CERTIFICATE_SPKI_SHA256=$(pki_candidate_spki "$RESPONSE_DIR/tls.crt")
  for digest in "${CANDIDATE_RESPONSE[request_sha256]}" "${CANDIDATE_RESPONSE[approval_sha256]}" "${CANDIDATE_RESPONSE[inventory_sha256]}" "${CANDIDATE_RESPONSE[csr_sha256]}" "${CANDIDATE_RESPONSE[csr_spki_sha256]}" "$CERTIFICATE_SHA256" "$CERTIFICATE_SPKI_SHA256" "$CHAIN_SHA256" "$FULLCHAIN_SHA256"; do pki_candidate_require_digest "$digest" 'CSR candidate digest'; done
  [[ ${CANDIDATE_RESPONSE[certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_RESPONSE[certificate_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_RESPONSE[csr_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_RESPONSE[chain_sha256]} == "$CHAIN_SHA256" ]] || pki_die 'CSR candidate certificate digest binding failed'
  [[ ${CANDIDATE_ARTIFACT[certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_ARTIFACT[certificate_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_ARTIFACT[chain_sha256]} == "$CHAIN_SHA256" && ${CANDIDATE_ARTIFACT[fullchain_sha256]} == "$FULLCHAIN_SHA256" ]] || pki_die 'Certificate export certificate digest binding failed'
  pki_validate_root_generation "${CANDIDATE_RESPONSE[issuer_root]}"; pki_validate_intermediate_generation "${CANDIDATE_RESPONSE[issuer_intermediate]}"
  [[ ${CANDIDATE_RESPONSE[issuer_intermediate]} == "${CANDIDATE_RESPONSE[issuer_root]}"-i* ]] || pki_die 'CSR candidate issuer generations do not match'
  root_cert=$(pki_root_cert "${CANDIDATE_RESPONSE[issuer_root]}"); intermediate_cert=$(pki_intermediate_cert "${CANDIDATE_RESPONSE[issuer_intermediate]}")
  openssl verify -CAfile "$root_cert" -untrusted "$intermediate_cert" "$RESPONSE_DIR/tls.crt" >/dev/null 2>&1 || pki_die 'CSR candidate certificate chain verification failed'
  cmp -s -- "$RESPONSE_DIR/ca-chain.crt" <(cat -- "$intermediate_cert" "$root_cert") || pki_die 'CSR candidate chain does not match recorded issuer'
  cmp -s -- "$RESPONSE_DIR/fullchain.crt" <(cat -- "$RESPONSE_DIR/tls.crt" "$intermediate_cert") || pki_die 'CSR candidate full chain is invalid'
  # shellcheck disable=SC2034 # Shared certificate validation consumes these globals.
  CSR_ACTUAL_SPKI_SHA256=$CERTIFICATE_SPKI_SHA256
  # shellcheck disable=SC2034
  ISSUED_SERIAL=${CANDIDATE_RESPONSE[serial]}
  # shellcheck disable=SC2034
  ROOT_CERT=$root_cert
  # shellcheck disable=SC2034
  INT_CERT=$intermediate_cert
  # Historical predecessors remain valid when a renewal intentionally changes
  # the current inventory profile; their exact profile was authenticated by the
  # retained signed response and original signing transaction.
  if [[ -z ${PKI_CSR_OUTCOME_STACK:-} ]]; then pki_csr_validate_certificate "$RESPONSE_DIR/tls.crt" "$transaction/tls.csr" "$CANDIDATE_WORK_DIR"; fi
  [[ $(pki_csr_spki_digest "$transaction/tls.csr" csr "$CANDIDATE_WORK_DIR") == "$CERTIFICATE_SPKI_SHA256" ]] || pki_die 'Retained CSR public key does not match the candidate certificate'
  ISSUER_INTERMEDIATE_SHA256=$(pki_candidate_sha256 "$intermediate_cert" 'Recorded issuer intermediate')
  serial=$(openssl x509 -in "$RESPONSE_DIR/tls.crt" -noout -serial); serial=${serial#*=}; [[ ${serial^^} == "${CANDIDATE_RESPONSE[serial]}" ]] || pki_die 'CSR candidate serial binding failed'
  not_before=$(date -u -d "$(openssl x509 -in "$RESPONSE_DIR/tls.crt" -noout -startdate | sed 's/^notBefore=//')" +%s); not_after=$(date -u -d "$(openssl x509 -in "$RESPONSE_DIR/tls.crt" -noout -enddate | sed 's/^notAfter=//')" +%s)
  [[ $not_before == "${CANDIDATE_RESPONSE[not_before_epoch]}" && $not_after == "${CANDIDATE_RESPONSE[not_after_epoch]}" ]] || pki_die 'CSR candidate validity binding failed'

  pki_require_private_dir "$transaction" 'CSR signing transaction directory'; transaction_identity=$(pki_dir_identity "$transaction")
  trust=$transaction/responses.allowed_signers; pki_csr_require_protocol_file "$trust" 'Retained CSR response trust'; trust_identity=$(pki_file_identity "$trust")
  pki_csr_validate_allowed_signers "$trust" "${CANDIDATE_RESPONSE[response_principal]}" true
  pki_csr_verify_signature "$trust" "${CANDIDATE_RESPONSE[response_principal]}" platform-pki-csr-response-v1 "$RESPONSE_DIR/response.sig" "$RESPONSE_DIR/response" 'CSR response'
  [[ $(pki_file_identity "$trust") == "$trust_identity" && $(pki_dir_identity "$transaction") == "$transaction_identity" ]] || pki_die 'Retained CSR response trust identity changed'
  [[ $(pki_candidate_sha256 "$transaction/request" 'Retained CSR request') == "${CANDIDATE_RESPONSE[request_sha256]}" && $(pki_candidate_sha256 "$transaction/approval" 'Retained CSR approval') == "${CANDIDATE_RESPONSE[approval_sha256]}" && $(pki_candidate_sha256 "$transaction/tls.csr" 'Retained CSR') == "${CANDIDATE_RESPONSE[csr_sha256]}" ]] || pki_die 'Retained CSR transaction binding failed'
  request_record=$PKI_DIR/state/csr/replay/requests/$REQUEST_ID; nonce_record=$PKI_DIR/state/csr/replay/nonces/${CANDIDATE_RESPONSE[nonce]}; terminal=$transaction/terminal
  pki_csr_require_protocol_file "$request_record" 'CSR request replay record'; pki_csr_require_protocol_file "$nonce_record" 'CSR nonce replay record'; pki_csr_require_protocol_file "$terminal" 'CSR signing terminal record'
  if ! grep -Fxq "request_sha256=${CANDIDATE_RESPONSE[request_sha256]}" "$request_record" || ! grep -Fxq 'outcome=reserved' "$request_record"; then pki_die 'CSR request replay record does not bind the candidate'; fi
  if ! grep -Fxq "request_sha256=${CANDIDATE_RESPONSE[request_sha256]}" "$nonce_record" || ! grep -Fxq 'outcome=reserved' "$nonce_record"; then pki_die 'CSR nonce replay record does not bind the candidate'; fi
  if ! grep -Fxq 'outcome=published' "$terminal" || ! grep -Fxq 'committed=true' "$terminal"; then pki_die 'CSR signing transaction is not terminal and committed'; fi
  pki_candidate_recheck_sources
}

pki_candidate_load_active() {
  local required=${1:-false} path=$PKI_DIR/state/csr/active/$SERVICE
  if [[ ! -e $path && ! -L $path ]]; then
    [[ $required != true ]] || pki_die "Host-local active accepted-evidence pointer is missing: $SERVICE"
    ACTIVE_PRESENT=false; ACTIVE_IDENTITY=absent
    return 0
  fi
  unset -v CANDIDATE_ACTIVE; declare -gA CANDIDATE_ACTIVE=()
  [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' "$path") == "$(id -u):600:1" ]] || pki_die 'Host-local active accepted-evidence pointer must be current-user-owned, singly linked, and mode 600'
  pki_csr_read_ordered_record "$path" 'Host-local active accepted-evidence pointer' CANDIDATE_ACTIVE "${PKI_CANDIDATE_ACTIVE_FIELDS[@]}"
  [[ $(wc -l <"$path") -eq ${#PKI_CANDIDATE_ACTIVE_FIELDS[@]} && ${CANDIDATE_ACTIVE[schema]} == 1 && ${CANDIDATE_ACTIVE[service]} == "$SERVICE" && ${CANDIDATE_ACTIVE[target]} == "$INVENTORY_TARGET" ]] || pki_die 'Host-local active accepted-evidence pointer is invalid'
  for name in certificate_sha256 certificate_spki_sha256 response_sha256 artifact_manifest_sha256 deployment_sha256 decision_sha256; do pki_candidate_require_digest "${CANDIDATE_ACTIVE[$name]}" "Active pointer $name"; done
  ACTIVE_PRESENT=true; ACTIVE_IDENTITY=$(pki_file_object_state "$path")
}

pki_candidate_load_retained_records() {
  local name transaction=$PKI_DIR/state/csr/transactions/csr-$REQUEST_ID
  unset -v CANDIDATE_REQUEST CANDIDATE_APPROVAL
  declare -gA CANDIDATE_REQUEST=() CANDIDATE_APPROVAL=()
  pki_csr_read_ordered_record "$transaction/request" 'Retained CSR request' CANDIDATE_REQUEST "${PKI_CSR_REQUEST_FIELDS[@]}"
  pki_csr_read_ordered_record "$transaction/approval" 'Retained CSR approval' CANDIDATE_APPROVAL "${PKI_CSR_APPROVAL_FIELDS[@]}"
  [[ $(wc -l <"$transaction/request") -eq ${#PKI_CSR_REQUEST_FIELDS[@]} && $(wc -l <"$transaction/approval") -eq ${#PKI_CSR_APPROVAL_FIELDS[@]} ]] || pki_die 'Retained CSR request or approval is not canonically newline-terminated'
  [[ ${CANDIDATE_REQUEST[schema]} == 1 && ${CANDIDATE_APPROVAL[schema]} == 1 && ${CANDIDATE_REQUEST[request_id]} == "$REQUEST_ID" && ${CANDIDATE_REQUEST[nonce]} =~ ^[0-9a-f]{64}$ && ${CANDIDATE_REQUEST[nonce]} == "${CANDIDATE_RESPONSE[nonce]}" && ${CANDIDATE_REQUEST[operation]} == "${CANDIDATE_RESPONSE[operation]}" && ${CANDIDATE_REQUEST[service]} == "$SERVICE" && ${CANDIDATE_REQUEST[target]} == "$CANDIDATE_TARGET" && ${CANDIDATE_REQUEST[requester_principal]} == "$CANDIDATE_TARGET" ]] || pki_die 'Retained CSR request identity binding failed'
  [[ $CANDIDATE_TARGET == "$INVENTORY_TARGET" ]] || pki_die 'Retained CSR request target does not match inventory'
  for name in request_id nonce operation service target csr_sha256 inventory_sha256 profile; do [[ ${CANDIDATE_APPROVAL[$name]} == "${CANDIDATE_REQUEST[$name]}" ]] || pki_die "Retained CSR approval does not bind request field: $name"; done
  REQUEST_CURRENT_CERT_SHA256=${CANDIDATE_REQUEST[current_cert_sha256]}
}

pki_candidate_validate_historical_request() {
  local historical_request_id=$1
  [[ $historical_request_id =~ ^[0-9a-f]{32}$ ]] || pki_die 'Historical CSR outcome request ID is invalid'
  [[ :${PKI_CSR_OUTCOME_STACK:-}: != *":$historical_request_id:"* ]] || pki_die 'Historical CSR outcome predecessor chain contains a cycle'
  (
    PKI_CSR_OUTCOME_STACK=${PKI_CSR_OUTCOME_STACK:+$PKI_CSR_OUTCOME_STACK:}$historical_request_id
    REQUEST_ID=$historical_request_id
    pki_candidate_validate_sources
    pki_candidate_load_retained_records
    pki_candidate_validate_recorded_outcome "$PKI_DIR/state/csr/outcomes/$SERVICE/$REQUEST_ID"
  ) || pki_die "Historical CSR outcome authentication failed: $historical_request_id"
}

pki_candidate_validate_active_outcome() {
  local outcome decision_digest name
  local -A active_decision=() active_deployment=()
  [[ $ACTIVE_PRESENT == true ]] || pki_die "Host-local active accepted-evidence pointer is missing: $SERVICE"
  [[ ${CANDIDATE_ACTIVE[request_id]} =~ ^[0-9a-f]{32}$ && (${CANDIDATE_ACTIVE[operation]} == issue || ${CANDIDATE_ACTIVE[operation]} == migrate || ${CANDIDATE_ACTIVE[operation]} == renew) ]] || pki_die 'Host-local active accepted-evidence pointer operation or request ID is invalid'
  pki_candidate_require_epoch "${CANDIDATE_ACTIVE[activation_epoch]}" 'Active pointer activation_epoch'
  pki_candidate_require_epoch "${CANDIDATE_ACTIVE[updated_epoch]}" 'Active pointer updated_epoch'
  if [[ ${CANDIDATE_ACTIVE[operation]} == issue ]]; then
    [[ ${CANDIDATE_ACTIVE[rollback_hold_until_epoch]} == none ]] || pki_die 'Issue active pointer has an unexpected rollback hold'
  else
    pki_candidate_require_epoch "${CANDIDATE_ACTIVE[rollback_hold_until_epoch]}" 'Active pointer rollback_hold_until_epoch'
  fi
  pki_candidate_validate_historical_request "${CANDIDATE_ACTIVE[request_id]}"
  outcome=$PKI_DIR/state/csr/outcomes/$SERVICE/${CANDIDATE_ACTIVE[request_id]}
  pki_csr_read_ordered_record "$outcome/decision" 'Active CSR decision' active_decision "${PKI_CANDIDATE_DECISION_FIELDS[@]}"
  pki_csr_read_ordered_record "$outcome/deployment" 'Active deployment evidence' active_deployment "${PKI_CANDIDATE_DEPLOYMENT_FIELDS[@]}"
  decision_digest=$(pki_candidate_sha256 "$outcome/decision" 'Active CSR decision')
  [[ ${active_decision[action]} == finalize && ${active_decision[state]} == finalized && ${active_decision[resulting_active_request_id]} == "${CANDIDATE_ACTIVE[request_id]}" ]] || pki_die 'Active pointer references a non-finalized CSR outcome'
  for name in service target request_id operation certificate_sha256 certificate_spki_sha256 response_sha256 artifact_manifest_sha256 deployment_sha256; do [[ ${CANDIDATE_ACTIVE[$name]} == "${active_decision[$name]}" ]] || pki_die "Active pointer does not bind authenticated outcome field: $name"; done
  [[ ${CANDIDATE_ACTIVE[decision_sha256]} == "$decision_digest" && ${CANDIDATE_ACTIVE[activation_epoch]} == "${active_deployment[activation_epoch]}" && ${CANDIDATE_ACTIVE[rollback_hold_until_epoch]} == "${active_deployment[rollback_hold_until_epoch]}" && ${CANDIDATE_ACTIVE[updated_epoch]} == "${active_deployment[created_epoch]}" ]] || pki_die 'Active pointer does not bind the authenticated outcome epochs or decision'
}

pki_candidate_load_deployment() {
  local evidence=$1 signature=$2 now name trust_path outcome=$PKI_DIR/state/csr/outcomes/$SERVICE/$REQUEST_ID
  pki_csr_copy_protocol_file "$evidence" "$CANDIDATE_WORK_DIR/deployment" 'Deployment evidence'
  pki_csr_copy_protocol_file "$signature" "$CANDIDATE_WORK_DIR/deployment.sig" 'Deployment evidence signature'
  unset -v CANDIDATE_DEPLOYMENT; declare -gA CANDIDATE_DEPLOYMENT=()
  pki_csr_read_ordered_record "$CANDIDATE_WORK_DIR/deployment" 'Deployment evidence' CANDIDATE_DEPLOYMENT "${PKI_CANDIDATE_DEPLOYMENT_FIELDS[@]}"
  [[ $(wc -l <"$CANDIDATE_WORK_DIR/deployment") -eq ${#PKI_CANDIDATE_DEPLOYMENT_FIELDS[@]} ]] || pki_die 'Deployment evidence is not canonically newline-terminated'
  [[ ${CANDIDATE_DEPLOYMENT[schema]} == 1 && ${CANDIDATE_DEPLOYMENT[request_id]} == "$REQUEST_ID" && ${CANDIDATE_DEPLOYMENT[artifact_request_id]} == "$REQUEST_ID" && ${CANDIDATE_DEPLOYMENT[service]} == "$SERVICE" && ${CANDIDATE_DEPLOYMENT[target]} == "$INVENTORY_TARGET" && ${CANDIDATE_DEPLOYMENT[deployment_principal]} == "$INVENTORY_TARGET" ]] || pki_die 'Deployment evidence identity binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[nonce]} =~ ^[0-9a-f]{64}$ && ${CANDIDATE_DEPLOYMENT[nonce]} == "${CANDIDATE_RESPONSE[nonce]}" ]] || pki_die 'Deployment evidence nonce binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[operation]} == "${CANDIDATE_RESPONSE[operation]}" && ${CANDIDATE_DEPLOYMENT[action]} == "$CANDIDATE_ACTION" ]] || pki_die 'Deployment evidence operation or action binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[request_sha256]} == "${CANDIDATE_RESPONSE[request_sha256]}" && ${CANDIDATE_DEPLOYMENT[response_sha256]} == "$CANDIDATE_RESPONSE_SHA256" && ${CANDIDATE_DEPLOYMENT[response_signature_sha256]} == "$CANDIDATE_RESPONSE_SIGNATURE_SHA256" && ${CANDIDATE_DEPLOYMENT[candidate_sha256]} == "$CANDIDATE_SHA256" && ${CANDIDATE_DEPLOYMENT[artifact_manifest_sha256]} == "$ARTIFACT_MANIFEST_SHA256" ]] || pki_die 'Deployment evidence source binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_DEPLOYMENT[certificate_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_DEPLOYMENT[chain_sha256]} == "$CHAIN_SHA256" && ${CANDIDATE_DEPLOYMENT[fullchain_sha256]} == "$FULLCHAIN_SHA256" ]] || pki_die 'Deployment evidence certificate binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[local_certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_DEPLOYMENT[local_key_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_DEPLOYMENT[local_key_certificate_match]} == true ]] || pki_die 'Deployment evidence local key/certificate binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[validation_boundary_sha256]} == "$VALIDATION_BOUNDARY_SHA256" ]] || pki_die 'Deployment evidence validation boundary does not match inventory'
  for name in request_sha256 response_sha256 response_signature_sha256 candidate_sha256 artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256 chain_sha256 fullchain_sha256 local_certificate_sha256 local_key_spki_sha256 validation_boundary_sha256; do pki_candidate_require_digest "${CANDIDATE_DEPLOYMENT[$name]}" "Deployment evidence $name"; done
  pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[created_epoch]}" 'Deployment evidence created_epoch'; pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[expires_epoch]}" 'Deployment evidence expires_epoch'
  now=$(date -u +%s)
  pki_candidate_validate_time_math fresh "${CANDIDATE_DEPLOYMENT[created_epoch]}" "${CANDIDATE_DEPLOYMENT[expires_epoch]}" "$now" || pki_die 'Deployment evidence is outside its allowed validity interval'
  if [[ -e $outcome || -L $outcome ]]; then
    pki_candidate_validate_tree "$outcome" outcome; trust_path=$outcome/deployers.allowed_signers; CSR_TRUST_DIR=$outcome
    pki_csr_validate_allowed_signers "$trust_path" '' false
  else
    pki_csr_load_policy; [[ $CSR_TRUST_SCHEMA == 2 ]] || pki_die 'Candidate finalization and abandonment require CSR trust policy schema 2'; trust_path=$CSR_TRUST_DIR/deployers.allowed_signers
  fi
  pki_csr_verify_signature "$trust_path" "$INVENTORY_TARGET" platform-pki-csr-deployment-v1 "$CANDIDATE_WORK_DIR/deployment.sig" "$CANDIDATE_WORK_DIR/deployment" 'Deployment evidence'
  DEPLOYERS_IDENTITY=$(pki_file_identity "$trust_path"); DEPLOYMENT_SHA256=$(pki_candidate_sha256 "$CANDIDATE_WORK_DIR/deployment" 'Deployment evidence'); DEPLOYMENT_SIGNATURE_SHA256=$(pki_candidate_sha256 "$CANDIDATE_WORK_DIR/deployment.sig" 'Deployment evidence signature'); DEPLOYERS_SHA256=$(pki_candidate_sha256 "$trust_path" 'Accepted deployer trust')
}

pki_candidate_existing_outcome() {
  local outcome=$PKI_DIR/state/csr/outcomes/$SERVICE/$REQUEST_ID
  local requested_action=$CANDIDATE_ACTION supplied_deployment_sha256=$DEPLOYMENT_SHA256
  local supplied_deployment_signature_sha256=$DEPLOYMENT_SIGNATURE_SHA256 supplied_deployers_sha256=$DEPLOYERS_SHA256
  [[ -e $outcome || -L $outcome ]] || return 1
  pki_candidate_validate_recorded_outcome "$outcome"
  [[ $CANDIDATE_ACTION == "$requested_action" ]] || pki_die 'Existing CSR outcome conflicts with the requested decision'
  [[ $DEPLOYMENT_SHA256 == "$supplied_deployment_sha256" && $DEPLOYMENT_SIGNATURE_SHA256 == "$supplied_deployment_signature_sha256" && $DEPLOYERS_SHA256 == "$supplied_deployers_sha256" ]] || pki_die 'Existing CSR outcome conflicts with the supplied evidence or trust'
  if [[ $requested_action == finalize ]]; then
    pki_candidate_load_active true
    pki_candidate_validate_active_outcome
    [[ ${CANDIDATE_ACTIVE[request_id]} == "$REQUEST_ID" && ${CANDIDATE_ACTIVE[deployment_sha256]} == "$DEPLOYMENT_SHA256" && ${CANDIDATE_ACTIVE[decision_sha256]} == "$(pki_candidate_sha256 "$outcome/decision" 'Existing CSR decision')" ]] || pki_die 'Existing finalized outcome is not the active accepted evidence'
  fi
  pki_ok "Kept exact ${CANDIDATE_DECISION[state]} CSR candidate outcome: $outcome"
  return 0
}

pki_candidate_predecessor() {
  PREDECESSOR_KIND=none; PREDECESSOR_REQUEST_ID=none; PREDECESSOR_CERTIFICATE_SHA256=none; PREDECESSOR_CERTIFICATE_SPKI_SHA256=none
  PREDECESSOR_INTERMEDIATE_SHA256=none; PREDECESSOR_RESPONSE_SHA256=none; PREDECESSOR_ARTIFACT_MANIFEST_SHA256=none; PREDECESSOR_DEPLOYMENT_SHA256=none; PREDECESSOR_DECISION_SHA256=none
  if [[ ${CANDIDATE_RESPONSE[operation]} == renew ]]; then
    pki_candidate_load_active true
    pki_candidate_validate_active_outcome
    [[ ${CANDIDATE_ACTIVE[certificate_sha256]} == "$REQUEST_CURRENT_CERT_SHA256" ]] || pki_die 'Renewal predecessor does not match the request current certificate'
    PREDECESSOR_KIND=host-local; PREDECESSOR_REQUEST_ID=${CANDIDATE_ACTIVE[request_id]}; PREDECESSOR_CERTIFICATE_SHA256=${CANDIDATE_ACTIVE[certificate_sha256]}; PREDECESSOR_CERTIFICATE_SPKI_SHA256=${CANDIDATE_ACTIVE[certificate_spki_sha256]}; PREDECESSOR_RESPONSE_SHA256=${CANDIDATE_ACTIVE[response_sha256]}; PREDECESSOR_ARTIFACT_MANIFEST_SHA256=${CANDIDATE_ACTIVE[artifact_manifest_sha256]}; PREDECESSOR_DEPLOYMENT_SHA256=${CANDIDATE_ACTIVE[deployment_sha256]}; PREDECESSOR_DECISION_SHA256=${CANDIDATE_ACTIVE[decision_sha256]}
    unset -v PREDECESSOR_RESPONSE; declare -gA PREDECESSOR_RESPONSE=(); pki_csr_read_ordered_record "$PKI_DIR/state/csr/responses/$SERVICE/$PREDECESSOR_REQUEST_ID/response" 'Predecessor CSR response' PREDECESSOR_RESPONSE "${PKI_CANDIDATE_RESPONSE_FIELDS[@]}"
    PREDECESSOR_INTERMEDIATE_SHA256=$(pki_candidate_sha256 "$(pki_intermediate_cert "${PREDECESSOR_RESPONSE[issuer_intermediate]}")" 'Predecessor issuer intermediate')
  elif [[ ${CANDIDATE_RESPONSE[operation]} == migrate ]]; then
    pki_candidate_load_active false; [[ $ACTIVE_PRESENT == false ]] || pki_die 'Migration cannot finalize while a host-local active pointer exists'
    local cert=$PKI_DIR/services/$SERVICE/certs/tls.crt
    pki_csr_require_protocol_file "$cert" 'Managed migration predecessor certificate'
    PREDECESSOR_KIND=managed; PREDECESSOR_CERTIFICATE_SHA256=$(pki_candidate_sha256 "$cert" 'Managed migration predecessor certificate'); PREDECESSOR_CERTIFICATE_SPKI_SHA256=$(pki_candidate_spki "$cert")
    [[ $PREDECESSOR_CERTIFICATE_SHA256 == "$REQUEST_CURRENT_CERT_SHA256" ]] || pki_die 'Managed migration predecessor does not match the request current certificate'
    openssl x509 -in "$PKI_DIR/services/$SERVICE/chain/ca-chain.crt" -out "$CANDIDATE_WORK_DIR/predecessor-intermediate.crt" 2>/dev/null || pki_die 'Cannot extract managed predecessor intermediate'
    chmod 600 "$CANDIDATE_WORK_DIR/predecessor-intermediate.crt"; PREDECESSOR_INTERMEDIATE_SHA256=$(pki_candidate_sha256 "$CANDIDATE_WORK_DIR/predecessor-intermediate.crt" 'Managed predecessor intermediate')
    pki_candidate_snapshot_preserved_trees
  else
    pki_candidate_load_active false; [[ $ACTIVE_PRESENT == false ]] || pki_die 'Issue cannot finalize while a host-local active pointer exists'
    [[ $REQUEST_CURRENT_CERT_SHA256 == none ]] || pki_die 'Issue candidate unexpectedly binds a predecessor'
  fi
}

pki_candidate_snapshot_preserved_trees() {
  local root path key
  unset -v CANDIDATE_PRESERVED_PATHS CANDIDATE_PRESERVED_IDENTITIES
  declare -gA CANDIDATE_PRESERVED_PATHS=() CANDIDATE_PRESERVED_IDENTITIES=()
  for root in "$PKI_DIR/services/$SERVICE" "$PKI_DIR/export/ansible/services/$SERVICE"; do
    [[ -e $root || -L $root ]] || continue
    [[ -d $root && ! -L $root ]] || pki_die "Managed migration preservation root is unsafe: $root"
    while IFS= read -r -d '' path; do
      key=${#CANDIDATE_PRESERVED_PATHS[@]}
      CANDIDATE_PRESERVED_PATHS[$key]=$path
      if [[ -d $path && ! -L $path ]]; then CANDIDATE_PRESERVED_IDENTITIES[$key]=$(pki_dir_identity "$path"); elif [[ -f $path && ! -L $path ]]; then CANDIDATE_PRESERVED_IDENTITIES[$key]=$(pki_file_identity "$path"); else pki_die "Managed migration preservation entry is unsafe: $path"; fi
    done < <(find "$root" -xdev -print0)
  done
}

pki_candidate_recheck_preserved_trees() {
  local key path expected
  [[ ${CANDIDATE_RESPONSE[operation]} == migrate ]] || return 0
  for key in "${!CANDIDATE_PRESERVED_PATHS[@]}"; do
    path=${CANDIDATE_PRESERVED_PATHS[$key]}; expected=${CANDIDATE_PRESERVED_IDENTITIES[$key]}
    if [[ -d $path && ! -L $path ]]; then [[ $(pki_dir_identity "$path") == "$expected" ]] || pki_die "Managed migration directory identity changed: $path"; else pki_require_file_identity "$path" "$expected" 'Managed migration file'; fi
  done
}

pki_candidate_validate_action_rules() {
  local created=${CANDIDATE_DEPLOYMENT[created_epoch]}
  if [[ $CANDIDATE_ACTION == finalize ]]; then
    [[ ${CANDIDATE_DEPLOYMENT[result]} == activated && ${CANDIDATE_DEPLOYMENT[served_certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_DEPLOYMENT[served_intermediate_sha256]} == "$ISSUER_INTERMEDIATE_SHA256" && ${CANDIDATE_DEPLOYMENT[validation_result]} == passed ]] || pki_die 'Finalization evidence does not prove the exact activated and validated candidate'
    pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[activation_epoch]}" 'Deployment activation_epoch'; pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[validation_epoch]}" 'Deployment validation_epoch'
    pki_candidate_validate_time_math ordered "${CANDIDATE_DEPLOYMENT[activation_epoch]}" "${CANDIDATE_DEPLOYMENT[validation_epoch]}" "$created" || pki_die 'Finalization activation and validation epochs are inconsistent'
    if [[ ${CANDIDATE_RESPONSE[operation]} == issue ]]; then
      [[ ${CANDIDATE_DEPLOYMENT[rollback_state]} == none && ${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]} == none ]] || pki_die 'Issue finalization must not claim a rollback predecessor'
    else
      pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]}" 'Deployment rollback_hold_until_epoch'
      if [[ ${CANDIDATE_DEPLOYMENT[rollback_state]} != retained ]] || ! pki_candidate_validate_time_math hold "${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]}" "$created" "$ROLLBACK_HOLD_SECONDS"; then pki_die 'Finalization rollback hold is insufficient'; fi
    fi
  elif [[ ${CANDIDATE_DEPLOYMENT[result]} == not-activated ]]; then
    [[ ${CANDIDATE_DEPLOYMENT[served_certificate_sha256]} == none && ${CANDIDATE_DEPLOYMENT[served_intermediate_sha256]} == none && ${CANDIDATE_DEPLOYMENT[validation_result]} == not-run && ${CANDIDATE_DEPLOYMENT[activation_epoch]} == none && ${CANDIDATE_DEPLOYMENT[validation_epoch]} == none && ${CANDIDATE_DEPLOYMENT[rollback_state]} == none && ${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]} == none ]] || pki_die 'Not-activated abandonment evidence is inconsistent'
  elif [[ ${CANDIDATE_DEPLOYMENT[result]} == rolled-back ]]; then
    [[ $PREDECESSOR_KIND != none ]] || pki_die 'Rolled-back abandonment requires a signer-known predecessor'
    pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[activation_epoch]}" 'Deployment activation_epoch'; pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[validation_epoch]}" 'Deployment validation_epoch'; pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]}" 'Deployment rollback_hold_until_epoch'
    [[ ${CANDIDATE_DEPLOYMENT[rollback_state]} == restored && ${CANDIDATE_DEPLOYMENT[validation_result]} == passed && ${CANDIDATE_DEPLOYMENT[served_certificate_sha256]} == "$PREDECESSOR_CERTIFICATE_SHA256" && ${CANDIDATE_DEPLOYMENT[served_intermediate_sha256]} == "$PREDECESSOR_INTERMEDIATE_SHA256" ]] || pki_die 'Rolled-back abandonment evidence does not bind the exact validated predecessor'
    if ! pki_candidate_validate_time_math hold "${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]}" "$created" "$ROLLBACK_HOLD_SECONDS" || ! pki_candidate_validate_time_math ordered "${CANDIDATE_DEPLOYMENT[activation_epoch]}" "${CANDIDATE_DEPLOYMENT[validation_epoch]}" "$created"; then pki_die 'Rolled-back abandonment evidence is inconsistent'; fi
  else
    pki_die 'Abandonment result must be not-activated or rolled-back'
  fi
}

pki_candidate_decision_content() {
  local state=$1 resulting=$2
  printf '%s\n' \
    'schema=1' "action=$CANDIDATE_ACTION" "state=$state" "service=$SERVICE" "target=$CANDIDATE_TARGET" "request_id=$REQUEST_ID" "operation=${CANDIDATE_RESPONSE[operation]}" \
    "request_sha256=${CANDIDATE_RESPONSE[request_sha256]}" "response_sha256=$CANDIDATE_RESPONSE_SHA256" "response_signature_sha256=$CANDIDATE_RESPONSE_SIGNATURE_SHA256" "candidate_sha256=$CANDIDATE_SHA256" "artifact_manifest_sha256=$ARTIFACT_MANIFEST_SHA256" \
    "certificate_sha256=$CERTIFICATE_SHA256" "certificate_spki_sha256=$CERTIFICATE_SPKI_SHA256" "chain_sha256=$CHAIN_SHA256" "fullchain_sha256=$FULLCHAIN_SHA256" "deployment_sha256=$DEPLOYMENT_SHA256" "deployment_signature_sha256=$DEPLOYMENT_SIGNATURE_SHA256" "deployers_sha256=$DEPLOYERS_SHA256" \
    "predecessor_kind=$PREDECESSOR_KIND" "predecessor_request_id=$PREDECESSOR_REQUEST_ID" "predecessor_certificate_sha256=$PREDECESSOR_CERTIFICATE_SHA256" "predecessor_certificate_spki_sha256=$PREDECESSOR_CERTIFICATE_SPKI_SHA256" "predecessor_intermediate_sha256=$PREDECESSOR_INTERMEDIATE_SHA256" "predecessor_response_sha256=$PREDECESSOR_RESPONSE_SHA256" "predecessor_artifact_manifest_sha256=$PREDECESSOR_ARTIFACT_MANIFEST_SHA256" "predecessor_deployment_sha256=$PREDECESSOR_DEPLOYMENT_SHA256" "predecessor_decision_sha256=$PREDECESSOR_DECISION_SHA256" "resulting_active_request_id=$resulting" "created_epoch=${CANDIDATE_DEPLOYMENT[created_epoch]}"
}

pki_candidate_active_content() {
  printf '%s\n' 'schema=1' "service=$SERVICE" "target=$CANDIDATE_TARGET" "request_id=$REQUEST_ID" "operation=${CANDIDATE_RESPONSE[operation]}" "certificate_sha256=$CERTIFICATE_SHA256" "certificate_spki_sha256=$CERTIFICATE_SPKI_SHA256" "response_sha256=$CANDIDATE_RESPONSE_SHA256" "artifact_manifest_sha256=$ARTIFACT_MANIFEST_SHA256" "deployment_sha256=$DEPLOYMENT_SHA256" "decision_sha256=$DECISION_SHA256" "activation_epoch=${CANDIDATE_DEPLOYMENT[activation_epoch]}" "rollback_hold_until_epoch=${CANDIDATE_DEPLOYMENT[rollback_hold_until_epoch]}" "updated_epoch=${CANDIDATE_DEPLOYMENT[created_epoch]}"
}

pki_candidate_prepare_outcome() {
  local state=$1 resulting=$2 parent=$PKI_DIR/state/csr/outcomes/$SERVICE name
  for name in "$PKI_DIR/state/csr/outcomes" "$parent"; do
    if [[ ! -e $name && ! -L $name ]]; then mkdir -m 700 -- "$name" || pki_die "Cannot create CSR outcome directory: $name"; pki_fsync "$(dirname -- "$name")"; fi
    pki_require_private_dir "$name" 'CSR outcome directory'
  done
  OUTCOME_DESTINATION=$parent/$REQUEST_ID
  if [[ $CANDIDATE_ACTION == abandon ]]; then
    OUTCOME_STAGE=$parent/.platform-pki-csr-outcome.$REQUEST_ID.abandon
    if [[ ! -e $OUTCOME_STAGE && ! -L $OUTCOME_STAGE ]]; then mkdir -m 700 -- "$OUTCOME_STAGE" || pki_die 'Cannot create deterministic CSR abandonment stage'; fi
  else
    OUTCOME_STAGE=$(mktemp -d "$parent/.platform-pki-csr-outcome.$REQUEST_ID.XXXXXX") || pki_die 'Cannot create CSR outcome stage'
  fi
  chmod 700 "$OUTCOME_STAGE"; OUTCOME_STAGE_IDENTITY=$(pki_dir_identity "$OUTCOME_STAGE")
  if [[ -z $(find "$OUTCOME_STAGE" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    cp -- "$CANDIDATE_WORK_DIR/deployment" "$OUTCOME_STAGE/deployment"; cp -- "$CANDIDATE_WORK_DIR/deployment.sig" "$OUTCOME_STAGE/deployment.sig"; cp -- "$CSR_TRUST_DIR/deployers.allowed_signers" "$OUTCOME_STAGE/deployers.allowed_signers"
    pki_candidate_decision_content "$state" "$resulting" >"$OUTCOME_STAGE/decision"
    chmod 600 "$OUTCOME_STAGE"/*; pki_fsync_tree "$OUTCOME_STAGE"
  fi
  pki_candidate_validate_tree "$OUTCOME_STAGE" outcome
  DECISION_SHA256=$(pki_candidate_sha256 "$OUTCOME_STAGE/decision" 'Staged CSR decision')
  pki_candidate_validate_outcome "$OUTCOME_STAGE"
}

pki_candidate_remove_outcome_stage() {
  local root=$1 name identity
  pki_candidate_validate_tree "$root" outcome
  for name in deployment deployment.sig deployers.allowed_signers decision; do identity=$(pki_file_identity "$root/$name"); pki_remove_identity_file "$root/$name" "$identity" || pki_die 'Cannot remove validated duplicate CSR outcome stage'; done
  [[ $(pki_dir_identity "$root") == "$OUTCOME_STAGE_IDENTITY" ]] || pki_die 'Duplicate CSR outcome stage identity changed before cleanup'
  rmdir -- "$root" || pki_die 'Cannot remove duplicate CSR outcome stage'; pki_fsync "$(dirname -- "$root")"
}

pki_candidate_remove_work_dir() {
  local root=$1 expected=$2 path identity
  [[ -d $root && ! -L $root && $(pki_dir_identity "$root") == "$expected" ]] || return 1
  while IFS= read -r -d '' path; do
    if [[ -d $path && ! -L $path ]]; then
      identity=$(pki_dir_identity "$path") || return 1
      [[ $(pki_dir_identity "$root") == "$expected" && $(pki_dir_identity "$path") == "$identity" ]] || return 1
      rmdir -- "$path" || return 1
    elif [[ -f $path && ! -L $path ]]; then
      identity=$(pki_file_identity "$path") || return 1
      pki_remove_identity_file "$path" "$identity" || return 1
    else return 1; fi
  done < <(find "$root" -mindepth 1 -depth -xdev -print0)
  [[ $(pki_dir_identity "$root") == "$expected" ]] || return 1
  rmdir -- "$root" || return 1; pki_fsync "$(dirname -- "$root")"
}

pki_candidate_validate_outcome() {
  local root=$1
  pki_candidate_validate_tree "$root" outcome
  [[ $(pki_candidate_sha256 "$root/deployment" 'Outcome deployment evidence') == "$DEPLOYMENT_SHA256" && $(pki_candidate_sha256 "$root/deployment.sig" 'Outcome deployment signature') == "$DEPLOYMENT_SIGNATURE_SHA256" && $(pki_candidate_sha256 "$root/deployers.allowed_signers" 'Outcome deployer trust') == "$DEPLOYERS_SHA256" && $(pki_candidate_sha256 "$root/decision" 'Outcome decision') == "$DECISION_SHA256" ]] || pki_die 'Existing CSR outcome conflicts with the supplied evidence'
}

pki_candidate_write_journal() {
  local key content=''
  for key in "${PKI_CANDIDATE_JOURNAL_FIELDS[@]}"; do content+="$key=${CANDIDATE_FINALIZATION_JOURNAL[$key]}"$'\n'; done
  pki_write_journal "$(pki_csr_finalization_recovery_journal)" "$content"
}

pki_candidate_validate_finalization_journal() {
  local stage=${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage]} destination=${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]}
  local active_stage=${CANDIDATE_FINALIZATION_JOURNAL[active_stage]} active_destination=${CANDIDATE_FINALIZATION_JOURNAL[active_destination]}
  local path name source_key journal_key source_path path_digest stage_present=false destination_present=false active_state
  local -A source_paths=()
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[schema]} == 1 && ${CANDIDATE_FINALIZATION_JOURNAL[operation]} == csr-finalize ]] || pki_die 'CSR finalization recovery journal schema is unsupported'
  pki_validate_service_name "${CANDIDATE_FINALIZATION_JOURNAL[service]}"; [[ ${CANDIDATE_FINALIZATION_JOURNAL[request_id]} =~ ^[0-9a-f]{32}$ ]] || pki_die 'CSR finalization recovery request ID is invalid'
  [[ $stage == "$PKI_DIR/state/csr/outcomes/${CANDIDATE_FINALIZATION_JOURNAL[service]}/.platform-pki-csr-outcome.${CANDIDATE_FINALIZATION_JOURNAL[request_id]}."* && $destination == "$PKI_DIR/state/csr/outcomes/${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}" ]] || pki_die 'CSR finalization outcome path is outside the state contract'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_stage]} == "$PKI_DIR/state/csr/active/.platform-pki-active.${CANDIDATE_FINALIZATION_JOURNAL[service]}."* && ${CANDIDATE_FINALIZATION_JOURNAL[active_destination]} == "$PKI_DIR/state/csr/active/${CANDIDATE_FINALIZATION_JOURNAL[service]}" ]] || pki_die 'CSR finalization active path is outside the state contract'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == create || ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == exchange ]] || pki_die 'CSR finalization active publication mode is invalid'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[phase]} == planned || ${CANDIDATE_FINALIZATION_JOURNAL[phase]} == outcome-published || ${CANDIDATE_FINALIZATION_JOURNAL[phase]} == active-published ]] || pki_die 'CSR finalization recovery phase is invalid'
  case ${CANDIDATE_FINALIZATION_JOURNAL[phase]} in
    planned) [[ ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination_identity]} == none && ${CANDIDATE_FINALIZATION_JOURNAL[active_destination_identity]} == none ]] || pki_die 'Planned CSR finalization journal has publication identities' ;;
    outcome-published) [[ ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination_identity]} == "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}" && ${CANDIDATE_FINALIZATION_JOURNAL[active_destination_identity]} == none ]] || pki_die 'Outcome-published CSR finalization journal identities are inconsistent' ;;
    active-published) [[ ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination_identity]} == "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}" && ${CANDIDATE_FINALIZATION_JOURNAL[active_destination_identity]} == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" ]] || pki_die 'Active-published CSR finalization journal identities are inconsistent' ;;
  esac
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[candidate_dir]} == "$PKI_DIR/state/csr/candidates/${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}" && ${CANDIDATE_FINALIZATION_JOURNAL[candidate_path]} == "${CANDIDATE_FINALIZATION_JOURNAL[candidate_dir]}/candidate" ]] || pki_die 'CSR finalization candidate source path is invalid'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[artifact_dir]} == "$PKI_DIR/export/certificates/v1/artifacts/${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}" && ${CANDIDATE_FINALIZATION_JOURNAL[artifact_path]} == "${CANDIDATE_FINALIZATION_JOURNAL[artifact_dir]}/artifact" ]] || pki_die 'CSR finalization export source path is invalid'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[response_dir]} == "$PKI_DIR/state/csr/responses/${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}" ]] || pki_die 'CSR finalization response directory path is invalid'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[response_path]} == "$PKI_DIR/state/csr/responses/${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}/response" && ${CANDIDATE_FINALIZATION_JOURNAL[response_signature_path]} == "$PKI_DIR/state/csr/responses/${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}/response.sig" ]] || pki_die 'CSR finalization response source path is invalid'
  [[ ${CANDIDATE_FINALIZATION_JOURNAL[transaction_dir]} == "$PKI_DIR/state/csr/transactions/csr-${CANDIDATE_FINALIZATION_JOURNAL[request_id]}" && ${CANDIDATE_FINALIZATION_JOURNAL[response_trust_path]} == "${CANDIDATE_FINALIZATION_JOURNAL[transaction_dir]}/responses.allowed_signers" ]] || pki_die 'CSR finalization retained response trust path is invalid'
  [[ $(pki_dir_identity "${CANDIDATE_FINALIZATION_JOURNAL[candidate_dir]}") == "${CANDIDATE_FINALIZATION_JOURNAL[candidate_dir_identity]}" && $(pki_dir_identity "${CANDIDATE_FINALIZATION_JOURNAL[artifact_dir]}") == "${CANDIDATE_FINALIZATION_JOURNAL[artifact_dir_identity]}" && $(pki_dir_identity "${CANDIDATE_FINALIZATION_JOURNAL[response_dir]}") == "${CANDIDATE_FINALIZATION_JOURNAL[response_dir_identity]}" && $(pki_dir_identity "${CANDIDATE_FINALIZATION_JOURNAL[transaction_dir]}") == "${CANDIDATE_FINALIZATION_JOURNAL[transaction_dir_identity]}" ]] || pki_die 'CSR finalization source directory identity changed'
  pki_require_file_identity "${CANDIDATE_FINALIZATION_JOURNAL[response_trust_path]}" "${CANDIDATE_FINALIZATION_JOURNAL[response_trust_identity]}" 'CSR finalization retained response trust'
  [[ $(pki_candidate_sha256 "${CANDIDATE_FINALIZATION_JOURNAL[response_trust_path]}" 'CSR finalization retained response trust') == "${CANDIDATE_FINALIZATION_JOURNAL[response_trust_sha256]}" ]] || pki_die 'CSR finalization retained response trust digest changed'
  for name in candidate tls.crt ca-chain.crt fullchain.crt response response.sig; do source_paths[candidate/$name]=${CANDIDATE_FINALIZATION_JOURNAL[candidate_dir]}/$name; done
  for name in tls.crt ca-chain.crt fullchain.crt response response.sig; do source_paths[response/$name]=${CANDIDATE_FINALIZATION_JOURNAL[response_dir]}/$name; done
  for name in artifact tls.crt ca-chain.crt fullchain.crt response response.sig; do source_paths[artifact/$name]=${CANDIDATE_FINALIZATION_JOURNAL[artifact_dir]}/$name; done
  for source_key in "${!source_paths[@]}"; do
    journal_key=${source_key//\//_}; journal_key=${journal_key//./_}; journal_key=${journal_key//-/_}; source_path=${source_paths[$source_key]}
    pki_require_file_identity "$source_path" "${CANDIDATE_FINALIZATION_JOURNAL[source_${journal_key}_identity]}" "CSR finalization source $source_key"
    [[ $(pki_candidate_sha256 "$source_path" "CSR finalization source $source_key") == "${CANDIDATE_FINALIZATION_JOURNAL[source_${journal_key}_sha256]}" ]] || pki_die "CSR finalization source digest changed: $source_key"
  done
  for path in candidate artifact response response_signature; do
    pki_require_file_identity "${CANDIDATE_FINALIZATION_JOURNAL[${path}_path]}" "${CANDIDATE_FINALIZATION_JOURNAL[${path}_identity]}" "CSR finalization $path source"
    [[ $(pki_candidate_sha256 "${CANDIDATE_FINALIZATION_JOURNAL[${path}_path]}" "CSR finalization $path source") == "${CANDIDATE_FINALIZATION_JOURNAL[${path}_sha256]}" ]] || pki_die "CSR finalization $path source digest changed"
  done
  for path in deployment_sha256 deployment_signature_sha256 deployers_sha256 decision_sha256 active_sha256 response_trust_sha256; do pki_candidate_require_digest "${CANDIDATE_FINALIZATION_JOURNAL[$path]}" "CSR finalization journal $path"; done
  if [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == create ]]; then
    [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]} == absent && ${CANDIDATE_FINALIZATION_JOURNAL[active_pre_sha256]} == none ]] || pki_die 'CSR finalization create journal has an active predecessor'
  else
    pki_candidate_require_digest "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_sha256]}" 'CSR finalization previous active digest'
  fi
  [[ ! -e $stage && ! -L $stage ]] || stage_present=true
  [[ ! -e $destination && ! -L $destination ]] || destination_present=true
  [[ $stage_present != "$destination_present" ]] || pki_die 'CSR finalization outcome rename state is inconsistent'
  if [[ $destination_present == true ]]; then
    [[ $(pki_dir_identity "$destination") == "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}" ]] || pki_die 'CSR finalization destination identity conflicts with the journal'
    pki_candidate_validate_tree "$destination" outcome
  else
    [[ -d $stage && ! -L $stage && $(pki_dir_identity "$stage") == "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}" ]] || pki_die 'CSR finalization outcome stage is missing or changed'
    pki_candidate_validate_tree "$stage" outcome
  fi
  path=$([[ $destination_present == true ]] && printf '%s' "$destination" || printf '%s' "$stage")
  for name in deployment deployment.sig deployers.allowed_signers decision; do
    case $name in deployment) journal_key=outcome_deployment; path_digest=deployment_sha256 ;; deployment.sig) journal_key=outcome_deployment_signature; path_digest=deployment_signature_sha256 ;; deployers.allowed_signers) journal_key=outcome_deployers; path_digest=deployers_sha256 ;; decision) journal_key=outcome_decision; path_digest=decision_sha256 ;; esac
    pki_require_file_identity "$path/$name" "${CANDIDATE_FINALIZATION_JOURNAL[${journal_key}_identity]}" "CSR finalization outcome $name"
    [[ $(pki_candidate_sha256 "$path/$name" "CSR finalization outcome $name") == "${CANDIDATE_FINALIZATION_JOURNAL[$path_digest]}" ]] || pki_die "CSR finalization outcome digest changed: $name"
  done
  if [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == create ]]; then
    if [[ -f $active_destination && ! -L $active_destination && $(pki_file_object_state "$active_destination") == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" && ! -e $active_stage && ! -L $active_stage ]]; then active_state=published
    elif [[ ! -e $active_destination && ! -L $active_destination && -f $active_stage && ! -L $active_stage && $(pki_file_object_state "$active_stage") == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" ]]; then active_state=staged
    else pki_die 'CSR finalization active create state is inconsistent'; fi
  else
    if [[ -f $active_destination && ! -L $active_destination && $(pki_file_object_state "$active_destination") == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" ]] && { [[ ! -e $active_stage && ! -L $active_stage ]] || [[ -f $active_stage && ! -L $active_stage && $(pki_file_object_state "$active_stage") == "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]}" ]]; }; then active_state=published
    elif [[ -f $active_destination && ! -L $active_destination && $(pki_file_object_state "$active_destination") == "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]}" && -f $active_stage && ! -L $active_stage && $(pki_file_object_state "$active_stage") == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" ]]; then active_state=staged
    else pki_die 'CSR finalization active exchange state is inconsistent'; fi
  fi
  if [[ $active_state == published ]]; then
    [[ $(pki_candidate_sha256 "$active_destination" 'Recovered active pointer') == "${CANDIDATE_FINALIZATION_JOURNAL[active_sha256]}" ]] || pki_die 'Published active pointer content conflicts with the journal'
  else
    [[ $(pki_candidate_sha256 "$active_stage" 'Staged active pointer') == "${CANDIDATE_FINALIZATION_JOURNAL[active_sha256]}" ]] || pki_die 'Staged active pointer content conflicts with the journal'
    if [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == exchange ]]; then [[ $(pki_candidate_sha256 "$active_destination" 'Pre-finalization active pointer') == "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_sha256]}" ]] || pki_die 'Pre-finalization active pointer content conflicts with the journal'; fi
  fi
  case ${CANDIDATE_FINALIZATION_JOURNAL[phase]} in
    planned) [[ $active_state == staged ]] || pki_die 'Planned CSR finalization journal conflicts with active publication state' ;;
    outcome-published) [[ $destination_present == true ]] || pki_die 'Outcome-published CSR finalization journal conflicts with outcome state' ;;
    active-published) [[ $destination_present == true && $active_state == published ]] || pki_die 'Active-published CSR finalization journal conflicts with publication state' ;;
  esac
}

pki_candidate_resume_finalization() {
  local journal current journal_identity
  journal=$(pki_csr_finalization_recovery_journal)
  pki_candidate_validate_finalization_journal
  if [[ ! -e ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]} && ! -L ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]} ]]; then
    [[ -d ${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage]} && ! -L ${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage]} && $(pki_dir_identity "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage]}") == "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}" ]] || pki_die 'Finalization outcome stage identity changed'
    mv --no-copy --update=none-fail -T -- "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage]}" "${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]}" || pki_die 'Cannot publish immutable CSR finalization outcome'
    pki_fsync "$(dirname -- "${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]}")"
  fi
  [[ -d ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]} && ! -L ${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]} && $(pki_dir_identity "${CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]}") == "${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}" ]] || pki_die 'Published finalization outcome identity is inconsistent'
  # shellcheck disable=SC2100 # These are associative-array assignments.
  CANDIDATE_FINALIZATION_JOURNAL[outcome_destination_identity]=${CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]}
  # shellcheck disable=SC2100
  CANDIDATE_FINALIZATION_JOURNAL[phase]=outcome-published
  pki_candidate_write_journal
  pki_candidate_fault outcome-published
  current=$(pki_file_identity_or_absent "${CANDIDATE_FINALIZATION_JOURNAL[active_destination]}")
  if [[ $current == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" ]]; then :
  elif [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == create && $current == absent ]]; then
    mv --no-copy --update=none-fail -T -- "${CANDIDATE_FINALIZATION_JOURNAL[active_stage]}" "${CANDIDATE_FINALIZATION_JOURNAL[active_destination]}" || pki_die 'Cannot publish active accepted-evidence pointer'
  elif [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == exchange && $current == "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]}" ]]; then
    mv --exchange --no-copy -T -- "${CANDIDATE_FINALIZATION_JOURNAL[active_stage]}" "${CANDIDATE_FINALIZATION_JOURNAL[active_destination]}" || pki_die 'Cannot exchange active accepted-evidence pointer'
  else pki_die 'Active accepted-evidence pointer is inconsistent with finalization journal'; fi
  [[ $(pki_file_object_state "${CANDIDATE_FINALIZATION_JOURNAL[active_destination]}") == "${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}" ]] || pki_die 'Published active accepted-evidence pointer identity is invalid'
  CANDIDATE_FINALIZATION_JOURNAL[active_destination_identity]=${CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]}
  # shellcheck disable=SC2100 # This is an associative-array assignment.
  CANDIDATE_FINALIZATION_JOURNAL[phase]=active-published
  pki_candidate_write_journal
  pki_candidate_fault active-published
  if [[ -e ${CANDIDATE_FINALIZATION_JOURNAL[active_stage]} || -L ${CANDIDATE_FINALIZATION_JOURNAL[active_stage]} ]]; then
    [[ ${CANDIDATE_FINALIZATION_JOURNAL[active_mode]} == exchange && $(pki_file_object_state "${CANDIDATE_FINALIZATION_JOURNAL[active_stage]}") == "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]}" ]] || pki_die 'Finalization active-pointer cleanup object is unsafe'
    pki_remove_identity_file "${CANDIDATE_FINALIZATION_JOURNAL[active_stage]}" "${CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]}" || pki_die 'Cannot remove superseded active pointer stage'
  fi
  journal_identity=$(pki_file_identity "$journal"); pki_remove_identity_file "$journal" "$journal_identity" finalization-journal || pki_die 'Finalization journal changed before terminal cleanup'
}

pki_candidate_fault() {
  [[ ${PLATFORM_PKI_CANDIDATE_CRASH_AT:-} != "$1" ]] || kill -KILL "$$"
  [[ ${PLATFORM_PKI_CANDIDATE_FAIL_AT:-} != "$1" ]] || pki_die "Injected CSR candidate failure at $1"
}

pki_candidate_publish_finalize() {
  local active_parent=$PKI_DIR/state/csr/active key source_key journal_key source_path transaction trust
  pki_candidate_prepare_outcome finalized "$REQUEST_ID"
  if [[ -e $OUTCOME_DESTINATION || -L $OUTCOME_DESTINATION ]]; then
    pki_candidate_validate_outcome "$OUTCOME_DESTINATION"; pki_candidate_remove_outcome_stage "$OUTCOME_STAGE"; pki_candidate_load_active true; pki_candidate_validate_active_outcome
    [[ ${CANDIDATE_ACTIVE[request_id]} == "$REQUEST_ID" && ${CANDIDATE_ACTIVE[deployment_sha256]} == "$DEPLOYMENT_SHA256" ]] || pki_die 'Existing finalized outcome is not the active accepted evidence'
    pki_ok "Kept exact finalized CSR candidate outcome: $OUTCOME_DESTINATION"; return
  fi
  if [[ ! -e $active_parent && ! -L $active_parent ]]; then mkdir -m 700 -- "$active_parent" || pki_die 'Cannot create CSR active pointer directory'; pki_fsync "$(dirname -- "$active_parent")"; fi
  pki_require_private_dir "$active_parent" 'CSR active pointer directory'
  ACTIVE_STAGE=$(mktemp "$active_parent/.platform-pki-active.$SERVICE.XXXXXX") || pki_die 'Cannot create active pointer stage'; chmod 600 "$ACTIVE_STAGE"
  pki_candidate_active_content >"$ACTIVE_STAGE"; pki_fsync "$ACTIVE_STAGE"; ACTIVE_STAGE_IDENTITY=$(pki_file_object_state "$ACTIVE_STAGE")
  unset -v CANDIDATE_FINALIZATION_JOURNAL; declare -gA CANDIDATE_FINALIZATION_JOURNAL=()
  for key in "${PKI_CANDIDATE_JOURNAL_FIELDS[@]}"; do CANDIDATE_FINALIZATION_JOURNAL[$key]=none; done
  CANDIDATE_FINALIZATION_JOURNAL[schema]=1; CANDIDATE_FINALIZATION_JOURNAL[operation]=csr-finalize; CANDIDATE_FINALIZATION_JOURNAL[service]=$SERVICE; CANDIDATE_FINALIZATION_JOURNAL[request_id]=$REQUEST_ID; CANDIDATE_FINALIZATION_JOURNAL[phase]=planned
  CANDIDATE_FINALIZATION_JOURNAL[outcome_stage]=$OUTCOME_STAGE; CANDIDATE_FINALIZATION_JOURNAL[outcome_stage_identity]=$OUTCOME_STAGE_IDENTITY; CANDIDATE_FINALIZATION_JOURNAL[outcome_destination]=$OUTCOME_DESTINATION
  CANDIDATE_FINALIZATION_JOURNAL[active_stage]=$ACTIVE_STAGE; CANDIDATE_FINALIZATION_JOURNAL[active_stage_identity]=$ACTIVE_STAGE_IDENTITY; CANDIDATE_FINALIZATION_JOURNAL[active_destination]=$active_parent/$SERVICE; CANDIDATE_FINALIZATION_JOURNAL[active_pre_identity]=$ACTIVE_IDENTITY; CANDIDATE_FINALIZATION_JOURNAL[active_mode]=$([[ $ACTIVE_IDENTITY == absent ]] && printf create || printf exchange)
  if [[ $ACTIVE_IDENTITY == absent ]]; then CANDIDATE_FINALIZATION_JOURNAL[active_pre_sha256]=none; else CANDIDATE_FINALIZATION_JOURNAL[active_pre_sha256]=$(pki_candidate_sha256 "$active_parent/$SERVICE" 'Pre-finalization active pointer'); fi
  CANDIDATE_FINALIZATION_JOURNAL[candidate_dir]=$CANDIDATE_DIR; CANDIDATE_FINALIZATION_JOURNAL[candidate_dir_identity]=$CANDIDATE_IDENTITY; CANDIDATE_FINALIZATION_JOURNAL[candidate_path]=$CANDIDATE_DIR/candidate; CANDIDATE_FINALIZATION_JOURNAL[candidate_identity]=${CANDIDATE_SOURCE_IDENTITIES[candidate/candidate]}; CANDIDATE_FINALIZATION_JOURNAL[candidate_sha256]=$CANDIDATE_SHA256
  CANDIDATE_FINALIZATION_JOURNAL[artifact_dir]=$ARTIFACT_DIR; CANDIDATE_FINALIZATION_JOURNAL[artifact_dir_identity]=$ARTIFACT_IDENTITY; CANDIDATE_FINALIZATION_JOURNAL[artifact_path]=$ARTIFACT_DIR/artifact; CANDIDATE_FINALIZATION_JOURNAL[artifact_identity]=${CANDIDATE_SOURCE_IDENTITIES[artifact/artifact]}; CANDIDATE_FINALIZATION_JOURNAL[artifact_sha256]=$ARTIFACT_MANIFEST_SHA256
  CANDIDATE_FINALIZATION_JOURNAL[response_dir]=$RESPONSE_DIR; CANDIDATE_FINALIZATION_JOURNAL[response_dir_identity]=$(pki_dir_identity "$RESPONSE_DIR")
  CANDIDATE_FINALIZATION_JOURNAL[response_path]=$RESPONSE_DIR/response; CANDIDATE_FINALIZATION_JOURNAL[response_identity]=${CANDIDATE_SOURCE_IDENTITIES[response/response]}; CANDIDATE_FINALIZATION_JOURNAL[response_sha256]=$CANDIDATE_RESPONSE_SHA256; CANDIDATE_FINALIZATION_JOURNAL[response_signature_path]=$RESPONSE_DIR/response.sig; CANDIDATE_FINALIZATION_JOURNAL[response_signature_identity]=${CANDIDATE_SOURCE_IDENTITIES[response/response.sig]}; CANDIDATE_FINALIZATION_JOURNAL[response_signature_sha256]=$CANDIDATE_RESPONSE_SIGNATURE_SHA256
  transaction=$PKI_DIR/state/csr/transactions/csr-$REQUEST_ID; trust=$transaction/responses.allowed_signers
  CANDIDATE_FINALIZATION_JOURNAL[transaction_dir]=$transaction; CANDIDATE_FINALIZATION_JOURNAL[transaction_dir_identity]=$(pki_dir_identity "$transaction")
  CANDIDATE_FINALIZATION_JOURNAL[response_trust_path]=$trust; CANDIDATE_FINALIZATION_JOURNAL[response_trust_identity]=$(pki_file_identity "$trust"); CANDIDATE_FINALIZATION_JOURNAL[response_trust_sha256]=$(pki_candidate_sha256 "$trust" 'Retained response trust')
  for source_key in "${!CANDIDATE_SOURCE_PATHS[@]}"; do
    journal_key=${source_key//\//_}; journal_key=${journal_key//./_}; journal_key=${journal_key//-/_}
    source_path=${CANDIDATE_SOURCE_PATHS[$source_key]}
    CANDIDATE_FINALIZATION_JOURNAL[source_${journal_key}_identity]=${CANDIDATE_SOURCE_IDENTITIES[$source_key]}
    CANDIDATE_FINALIZATION_JOURNAL[source_${journal_key}_sha256]=$(pki_candidate_sha256 "$source_path" "CSR finalization source $source_key")
  done
  CANDIDATE_FINALIZATION_JOURNAL[deployment_sha256]=$DEPLOYMENT_SHA256; CANDIDATE_FINALIZATION_JOURNAL[deployment_signature_sha256]=$DEPLOYMENT_SIGNATURE_SHA256; CANDIDATE_FINALIZATION_JOURNAL[deployers_sha256]=$DEPLOYERS_SHA256; CANDIDATE_FINALIZATION_JOURNAL[decision_sha256]=$DECISION_SHA256; CANDIDATE_FINALIZATION_JOURNAL[active_sha256]=$(pki_candidate_sha256 "$ACTIVE_STAGE" 'Staged active pointer')
  CANDIDATE_FINALIZATION_JOURNAL[outcome_deployment_identity]=$(pki_file_identity "$OUTCOME_STAGE/deployment")
  CANDIDATE_FINALIZATION_JOURNAL[outcome_deployment_signature_identity]=$(pki_file_identity "$OUTCOME_STAGE/deployment.sig")
  CANDIDATE_FINALIZATION_JOURNAL[outcome_deployers_identity]=$(pki_file_identity "$OUTCOME_STAGE/deployers.allowed_signers")
  CANDIDATE_FINALIZATION_JOURNAL[outcome_decision_identity]=$(pki_file_identity "$OUTCOME_STAGE/decision")
  pki_candidate_recheck_sources; pki_candidate_recheck_preserved_trees; [[ $(pki_file_identity "$CSR_TRUST_DIR/deployers.allowed_signers") == "$DEPLOYERS_IDENTITY" ]] || pki_die 'Installed deployer trust changed before finalization'
  pki_candidate_write_journal; CANDIDATE_JOURNAL_STARTED=true; pki_candidate_fault journal-written
  pki_candidate_resume_finalization; CANDIDATE_JOURNAL_STARTED=false
  pki_ok "Finalized authenticated CSR candidate evidence: $OUTCOME_DESTINATION"
}

pki_candidate_publish_abandon() {
  pki_candidate_prepare_outcome abandoned "$([[ $ACTIVE_PRESENT == true ]] && printf '%s' "${CANDIDATE_ACTIVE[request_id]}" || printf none)"
  if [[ -e $OUTCOME_DESTINATION || -L $OUTCOME_DESTINATION ]]; then pki_candidate_validate_outcome "$OUTCOME_DESTINATION"; pki_candidate_remove_outcome_stage "$OUTCOME_STAGE"; pki_ok "Kept exact abandoned CSR candidate outcome: $OUTCOME_DESTINATION"; return; fi
  pki_candidate_recheck_sources; pki_candidate_recheck_preserved_trees; [[ $(pki_file_identity "$CSR_TRUST_DIR/deployers.allowed_signers") == "$DEPLOYERS_IDENTITY" ]] || pki_die 'Installed deployer trust changed before abandonment'
  mv --no-copy --update=none-fail -T -- "$OUTCOME_STAGE" "$OUTCOME_DESTINATION" || pki_die 'Cannot publish immutable CSR abandonment outcome'
  pki_fsync "$(dirname -- "$OUTCOME_DESTINATION")"; pki_candidate_validate_outcome "$OUTCOME_DESTINATION"
  pki_ok "Abandoned authenticated CSR candidate evidence without revocation: $OUTCOME_DESTINATION"
}

pki_candidate_status() {
  local outcome=$PKI_DIR/state/csr/outcomes/$SERVICE/$REQUEST_ID state=pending active_state=inactive
  pki_candidate_load_active false
  if [[ $ACTIVE_PRESENT == true ]]; then pki_candidate_validate_active_outcome; fi
  if [[ -e $outcome || -L $outcome ]]; then
    pki_candidate_validate_recorded_outcome "$outcome"
    state=${CANDIDATE_DECISION[state]}
  fi
  if [[ $ACTIVE_PRESENT == true && ${CANDIDATE_ACTIVE[request_id]} == "$REQUEST_ID" ]]; then
    [[ $state == finalized && ${CANDIDATE_ACTIVE[certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_ACTIVE[certificate_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_ACTIVE[response_sha256]} == "$CANDIDATE_RESPONSE_SHA256" && ${CANDIDATE_ACTIVE[artifact_manifest_sha256]} == "$ARTIFACT_MANIFEST_SHA256" && ${CANDIDATE_ACTIVE[deployment_sha256]} == "${CANDIDATE_DECISION[deployment_sha256]}" && ${CANDIDATE_ACTIVE[decision_sha256]} == "$(pki_candidate_sha256 "$outcome/decision" 'Active CSR decision')" ]] || pki_die 'Active accepted-evidence pointer does not bind the exact finalized outcome'
    active_state=active
  elif [[ $state == finalized ]]; then active_state=superseded; fi
  if [[ $CANDIDATE_FORMAT == json ]]; then
    python3 - "$SERVICE" "$REQUEST_ID" "$state" "$active_state" <<'PY'
import json, sys
print(json.dumps({"schema":1,"kind":"csr-candidate-status","service":sys.argv[1],"request_id":sys.argv[2],"state":sys.argv[3],"accepted_evidence_state":sys.argv[4],"live_state_claimed":False}, sort_keys=True, separators=(",", ":")))
PY
  else
    printf 'service=%s\nrequest_id=%s\nstate=%s\naccepted_evidence_state=%s\nlive_state_claimed=false\n' "$SERVICE" "$REQUEST_ID" "$state" "$active_state"
  fi
}

pki_candidate_validate_recorded_outcome() {
  local outcome=$1 name resulting expected_decision cert now
  local -A predecessor_decision=() predecessor_response=()
  pki_candidate_validate_tree "$outcome" outcome
  unset -v CANDIDATE_DECISION CANDIDATE_DEPLOYMENT
  declare -gA CANDIDATE_DECISION=() CANDIDATE_DEPLOYMENT=()
  pki_csr_read_ordered_record "$outcome/decision" 'CSR candidate decision' CANDIDATE_DECISION "${PKI_CANDIDATE_DECISION_FIELDS[@]}"
  pki_csr_read_ordered_record "$outcome/deployment" 'Recorded deployment evidence' CANDIDATE_DEPLOYMENT "${PKI_CANDIDATE_DEPLOYMENT_FIELDS[@]}"
  [[ $(wc -l <"$outcome/decision") -eq ${#PKI_CANDIDATE_DECISION_FIELDS[@]} && $(wc -l <"$outcome/deployment") -eq ${#PKI_CANDIDATE_DEPLOYMENT_FIELDS[@]} && ${CANDIDATE_DECISION[schema]} == 1 && ${CANDIDATE_DECISION[service]} == "$SERVICE" && ${CANDIDATE_DECISION[target]} == "$CANDIDATE_TARGET" && ${CANDIDATE_DECISION[request_id]} == "$REQUEST_ID" ]] || pki_die 'Recorded CSR candidate outcome identity is invalid'
  [[ (${CANDIDATE_DECISION[action]} == finalize && ${CANDIDATE_DECISION[state]} == finalized) || (${CANDIDATE_DECISION[action]} == abandon && ${CANDIDATE_DECISION[state]} == abandoned) ]] || pki_die 'Recorded CSR candidate decision action and state are inconsistent'
  CANDIDATE_ACTION=${CANDIDATE_DECISION[action]}
  DEPLOYMENT_SHA256=$(pki_candidate_sha256 "$outcome/deployment" 'Recorded deployment evidence')
  DEPLOYMENT_SIGNATURE_SHA256=$(pki_candidate_sha256 "$outcome/deployment.sig" 'Recorded deployment signature')
  DEPLOYERS_SHA256=$(pki_candidate_sha256 "$outcome/deployers.allowed_signers" 'Recorded deployer trust')
  [[ ${CANDIDATE_DEPLOYMENT[schema]} == 1 && ${CANDIDATE_DEPLOYMENT[request_id]} == "$REQUEST_ID" && ${CANDIDATE_DEPLOYMENT[artifact_request_id]} == "$REQUEST_ID" && ${CANDIDATE_DEPLOYMENT[service]} == "$SERVICE" && ${CANDIDATE_DEPLOYMENT[target]} == "$CANDIDATE_TARGET" && ${CANDIDATE_DEPLOYMENT[deployment_principal]} == "$CANDIDATE_TARGET" ]] || pki_die 'Recorded deployment evidence identity is invalid'
  [[ ${CANDIDATE_DEPLOYMENT[nonce]} =~ ^[0-9a-f]{64}$ && ${CANDIDATE_DEPLOYMENT[nonce]} == "${CANDIDATE_RESPONSE[nonce]}" ]] || pki_die 'Recorded deployment evidence nonce binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[operation]} == "${CANDIDATE_RESPONSE[operation]}" && ${CANDIDATE_DEPLOYMENT[action]} == "$CANDIDATE_ACTION" ]] || pki_die 'Recorded deployment evidence operation or action is invalid'
  [[ ${CANDIDATE_DEPLOYMENT[request_sha256]} == "${CANDIDATE_RESPONSE[request_sha256]}" && ${CANDIDATE_DEPLOYMENT[response_sha256]} == "$CANDIDATE_RESPONSE_SHA256" && ${CANDIDATE_DEPLOYMENT[response_signature_sha256]} == "$CANDIDATE_RESPONSE_SIGNATURE_SHA256" && ${CANDIDATE_DEPLOYMENT[candidate_sha256]} == "$CANDIDATE_SHA256" && ${CANDIDATE_DEPLOYMENT[artifact_manifest_sha256]} == "$ARTIFACT_MANIFEST_SHA256" ]] || pki_die 'Recorded deployment evidence source binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_DEPLOYMENT[certificate_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_DEPLOYMENT[chain_sha256]} == "$CHAIN_SHA256" && ${CANDIDATE_DEPLOYMENT[fullchain_sha256]} == "$FULLCHAIN_SHA256" ]] || pki_die 'Recorded deployment evidence certificate binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[local_certificate_sha256]} == "$CERTIFICATE_SHA256" && ${CANDIDATE_DEPLOYMENT[local_key_spki_sha256]} == "$CERTIFICATE_SPKI_SHA256" && ${CANDIDATE_DEPLOYMENT[local_key_certificate_match]} == true ]] || pki_die 'Recorded deployment evidence local certificate binding failed'
  [[ ${CANDIDATE_DEPLOYMENT[validation_boundary_sha256]} == "$VALIDATION_BOUNDARY_SHA256" ]] || pki_die 'Recorded deployment evidence validation boundary does not match inventory'
  for name in request_sha256 response_sha256 response_signature_sha256 candidate_sha256 artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256 chain_sha256 fullchain_sha256 local_certificate_sha256 local_key_spki_sha256 validation_boundary_sha256; do pki_candidate_require_digest "${CANDIDATE_DEPLOYMENT[$name]}" "Recorded deployment evidence $name"; done
  for name in served_certificate_sha256 served_intermediate_sha256; do [[ ${CANDIDATE_DEPLOYMENT[$name]} == none ]] || pki_candidate_require_digest "${CANDIDATE_DEPLOYMENT[$name]}" "Recorded deployment evidence $name"; done
  pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[created_epoch]}" 'Recorded deployment evidence created_epoch'
  pki_candidate_require_epoch "${CANDIDATE_DEPLOYMENT[expires_epoch]}" 'Recorded deployment evidence expires_epoch'
  pki_candidate_validate_time_math interval "${CANDIDATE_DEPLOYMENT[created_epoch]}" "${CANDIDATE_DEPLOYMENT[expires_epoch]}" || pki_die 'Recorded deployment evidence validity interval is invalid'
  [[ $DEPLOYMENT_SHA256 == "${CANDIDATE_DECISION[deployment_sha256]}" && $DEPLOYMENT_SIGNATURE_SHA256 == "${CANDIDATE_DECISION[deployment_signature_sha256]}" && $DEPLOYERS_SHA256 == "${CANDIDATE_DECISION[deployers_sha256]}" ]] || pki_die 'Recorded CSR candidate outcome evidence binding failed'
  pki_csr_validate_allowed_signers "$outcome/deployers.allowed_signers" '' false
  pki_csr_verify_signature "$outcome/deployers.allowed_signers" "$CANDIDATE_TARGET" platform-pki-csr-deployment-v1 "$outcome/deployment.sig" "$outcome/deployment" 'Recorded deployment evidence'

  PREDECESSOR_KIND=none; PREDECESSOR_REQUEST_ID=none; PREDECESSOR_CERTIFICATE_SHA256=none; PREDECESSOR_CERTIFICATE_SPKI_SHA256=none; PREDECESSOR_INTERMEDIATE_SHA256=none; PREDECESSOR_RESPONSE_SHA256=none; PREDECESSOR_ARTIFACT_MANIFEST_SHA256=none; PREDECESSOR_DEPLOYMENT_SHA256=none; PREDECESSOR_DECISION_SHA256=none
  if [[ ${CANDIDATE_RESPONSE[operation]} == renew ]]; then
    PREDECESSOR_REQUEST_ID=${CANDIDATE_DECISION[predecessor_request_id]}
    pki_candidate_validate_historical_request "$PREDECESSOR_REQUEST_ID"
    pki_csr_read_ordered_record "$PKI_DIR/state/csr/outcomes/$SERVICE/$PREDECESSOR_REQUEST_ID/decision" 'Predecessor CSR decision' predecessor_decision "${PKI_CANDIDATE_DECISION_FIELDS[@]}"
    pki_csr_read_ordered_record "$PKI_DIR/state/csr/responses/$SERVICE/$PREDECESSOR_REQUEST_ID/response" 'Predecessor CSR response' predecessor_response "${PKI_CANDIDATE_RESPONSE_FIELDS[@]}"
    [[ ${predecessor_decision[action]} == finalize && ${predecessor_decision[state]} == finalized && ${predecessor_decision[resulting_active_request_id]} == "$PREDECESSOR_REQUEST_ID" ]] || pki_die 'Renewal predecessor outcome is not finalized'
    PREDECESSOR_KIND=host-local; PREDECESSOR_CERTIFICATE_SHA256=${predecessor_decision[certificate_sha256]}; PREDECESSOR_CERTIFICATE_SPKI_SHA256=${predecessor_decision[certificate_spki_sha256]}; PREDECESSOR_RESPONSE_SHA256=${predecessor_decision[response_sha256]}; PREDECESSOR_ARTIFACT_MANIFEST_SHA256=${predecessor_decision[artifact_manifest_sha256]}; PREDECESSOR_DEPLOYMENT_SHA256=${predecessor_decision[deployment_sha256]}; PREDECESSOR_DECISION_SHA256=$(pki_candidate_sha256 "$PKI_DIR/state/csr/outcomes/$SERVICE/$PREDECESSOR_REQUEST_ID/decision" 'Predecessor CSR decision'); PREDECESSOR_INTERMEDIATE_SHA256=$(pki_candidate_sha256 "$(pki_intermediate_cert "${predecessor_response[issuer_intermediate]}")" 'Predecessor issuer intermediate')
    [[ $REQUEST_CURRENT_CERT_SHA256 == "$PREDECESSOR_CERTIFICATE_SHA256" ]] || pki_die 'Recorded renewal request does not bind its authenticated predecessor'
  elif [[ ${CANDIDATE_RESPONSE[operation]} == migrate ]]; then
    cert=$PKI_DIR/services/$SERVICE/certs/tls.crt
    pki_csr_require_protocol_file "$cert" 'Managed migration predecessor certificate'
    PREDECESSOR_KIND=managed; PREDECESSOR_CERTIFICATE_SHA256=$(pki_candidate_sha256 "$cert" 'Managed migration predecessor certificate'); PREDECESSOR_CERTIFICATE_SPKI_SHA256=$(pki_candidate_spki "$cert")
    [[ $REQUEST_CURRENT_CERT_SHA256 == "$PREDECESSOR_CERTIFICATE_SHA256" ]] || pki_die 'Recorded migration request does not bind its managed predecessor'
    openssl x509 -in "$PKI_DIR/services/$SERVICE/chain/ca-chain.crt" -out "$CANDIDATE_WORK_DIR/recorded-predecessor-intermediate.crt" 2>/dev/null || pki_die 'Cannot extract recorded managed predecessor intermediate'
    chmod 600 "$CANDIDATE_WORK_DIR/recorded-predecessor-intermediate.crt"; PREDECESSOR_INTERMEDIATE_SHA256=$(pki_candidate_sha256 "$CANDIDATE_WORK_DIR/recorded-predecessor-intermediate.crt" 'Recorded managed predecessor intermediate')
  else
    [[ $REQUEST_CURRENT_CERT_SHA256 == none ]] || pki_die 'Recorded issue request unexpectedly binds a predecessor'
  fi
  pki_candidate_validate_action_rules
  if [[ $CANDIDATE_ACTION == finalize ]]; then resulting=$REQUEST_ID; else resulting=$([[ $PREDECESSOR_KIND == host-local ]] && printf '%s' "$PREDECESSOR_REQUEST_ID" || printf none); fi
  expected_decision=$(pki_candidate_decision_content "${CANDIDATE_DECISION[state]}" "$resulting")$'\n'
  [[ $(<"$outcome/decision")$'\n' == "$expected_decision" ]] || pki_die 'Recorded CSR candidate decision does not exactly bind its authenticated evidence and predecessor'
  pki_candidate_recheck_sources
}

pki_candidate_state_manifest() {
  local root path identity inventory
  # Terminal authentication consumes retained CSR state, immutable exports, and
  # issuer certificates. Snapshot their complete object identities so a caller
  # never publishes trust after authenticating a mixed-time history view.
  for root in \
    "$PKI_DIR/state/csr" \
    "$PKI_DIR/export/certificates/v1/artifacts" \
    "$PKI_DIR/authorities/roots" \
    "$PKI_DIR/authorities/intermediates" \
    "$PKI_DIR/services" \
    "$PKI_DIR/export/ansible/services"; do
    if [[ ! -e $root && ! -L $root ]]; then
      printf 'absent\t%s\n' "$root"
      continue
    fi
    [[ -d $root && ! -L $root ]] || pki_die "CSR historical state root must be a non-symlink directory: $root"
    while IFS= read -r -d '' path; do
      [[ $path != *$'\n'* && $path != *$'\t'* ]] || pki_die "CSR historical state contains an unsafe path: $path"
      if [[ -d $path && ! -L $path ]]; then
        identity=$(pki_dir_identity "$path") || pki_die "Cannot snapshot CSR historical state directory: $path"
        printf 'directory\t%s\t%s\n' "$path" "$identity"
      elif [[ -f $path && ! -L $path ]]; then
        identity=$(pki_file_identity "$path") || pki_die "Cannot snapshot CSR historical state file: $path"
        printf 'file\t%s\t%s\n' "$path" "$identity"
      else
        pki_die "CSR historical state contains an unsafe entry: $path"
      fi
    done < <(find "$root" -xdev -print0 | LC_ALL=C sort -z)
  done
  inventory=$(pki_inventory_file)
  if [[ ! -e $inventory && ! -L $inventory ]]; then
    printf 'absent\t%s\n' "$inventory"
  elif [[ -f $inventory && ! -L $inventory ]]; then
    identity=$(pki_file_identity "$inventory") || pki_die 'Cannot snapshot current service inventory'
    printf 'file\t%s\t%s\n' "$inventory" "$identity"
  else
    pki_die "Current service inventory is unsafe: $inventory"
  fi
}

pki_candidate_validate_pending_entry() {
  local candidate=$1
  local -A pending_record=()
  pki_candidate_validate_tree "$candidate" candidate
  pki_csr_read_ordered_record "$candidate/candidate" 'Pending CSR candidate' pending_record "${PKI_CANDIDATE_RECORD_FIELDS[@]}"
  [[ $(wc -l <"$candidate/candidate") -eq ${#PKI_CANDIDATE_RECORD_FIELDS[@]} && ${pending_record[schema]} == 1 && ${pending_record[request_id]} == "$REQUEST_ID" && ${pending_record[service]} == "$SERVICE" && ${pending_record[target]} =~ ^[a-z0-9][a-z0-9.-]*$ && ${pending_record[state]} == pending ]] || pki_die 'Pending CSR candidate record is invalid'
}

pki_candidate_authenticate_terminal_history() (
  local work_root=$1 outcome=$PKI_DIR/state/csr/outcomes/$SERVICE/$REQUEST_ID status
  CANDIDATE_WORK_DIR=$work_root/$REQUEST_ID
  mkdir -m 700 -- "$CANDIDATE_WORK_DIR" || pki_die 'Cannot create historical CSR candidate work directory'
  CANDIDATE_WORK_IDENTITY=$(pki_dir_identity "$CANDIDATE_WORK_DIR") || pki_die 'Cannot snapshot historical CSR candidate work directory'
  PKI_CSR_OUTCOME_STACK=$REQUEST_ID
  pki_candidate_validate_sources
  pki_candidate_load_retained_records
  if [[ ${CANDIDATE_RESPONSE[operation]} == migrate ]]; then pki_candidate_snapshot_preserved_trees; fi
  pki_candidate_validate_recorded_outcome "$outcome"
  pki_candidate_recheck_preserved_trees
)

pki_candidate_require_historical_state_digest() {
  local expected=$1 current
  pki_candidate_require_digest "$expected" 'Authenticated CSR historical state digest'
  current=$(pki_candidate_state_manifest | sha256sum) || pki_die 'Cannot recheck CSR historical state manifest'
  current=${current%% *}
  [[ $current == "$expected" ]] || pki_die 'CSR historical state changed before trust publication'
}

pki_candidate_require_no_pending_outcomes() (
  local status=0 work before after candidates=$PKI_DIR/state/csr/candidates outcomes=$PKI_DIR/state/csr/outcomes active=$PKI_DIR/state/csr/active inventory_loaded=false
  local service_path request_path outcome_service outcome_path active_path service request_id coordinate name decision_digest
  local -A coordinates=() request_ids=() finalized=() superseded=() active_requests=() heads=()
  local -A scan_decision=() active_record=() active_decision=() active_deployment=()
  work=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-csr-trust-state.XXXXXX") || pki_die 'Cannot create CSR trust state-validation directory'
  chmod 700 "$work" || pki_die 'Cannot secure CSR trust state-validation directory'
  CANDIDATE_WORK_IDENTITY=$(pki_dir_identity "$work") || pki_die 'Cannot snapshot CSR trust state-validation directory'
  trap 'status=$?; trap - EXIT; pki_candidate_remove_work_dir "$work" "$CANDIDATE_WORK_IDENTITY" || status=1; exit "$status"' EXIT
  before=$work/before; after=$work/after
  pki_candidate_state_manifest >"$before"
  chmod 600 "$before"

  if [[ -e $candidates || -L $candidates ]]; then
    pki_require_private_dir "$candidates" 'CSR candidate state directory'
    while IFS= read -r -d '' service_path; do
      service=${service_path##*/}; pki_validate_service_name "$service"; pki_require_private_dir "$service_path" 'CSR candidate service directory'
      [[ -n $(find "$service_path" -mindepth 1 -maxdepth 1 -print -quit) ]] || pki_die "CSR candidate service directory is unexpectedly empty: $service"
      if [[ $inventory_loaded == false ]]; then
        mkdir -m 700 -- "$work/inventory" || pki_die 'Cannot create CSR trust inventory-validation directory'
        pki_candidate_load_inventory_snapshot "$work/inventory"
        inventory_loaded=true
      fi
      pki_require_service_in_inventory "$service"; [[ $(pki_inventory_key_custody "$service") == host-local ]] || pki_die "Retained CSR candidate service is not host-local in current inventory: $service"
      INVENTORY_TARGET=$(pki_inventory_scalar "$service" target); VALIDATION_BOUNDARY_SHA256=$(pki_inventory_scalar "$service" validation_boundary_sha256); ROLLBACK_HOLD_SECONDS=$(pki_inventory_scalar "$service" rollback_hold_seconds)
      while IFS= read -r -d '' request_path; do
        request_id=${request_path##*/}
        [[ $request_id =~ ^[0-9a-f]{32}$ ]] || pki_die "CSR candidate state contains an invalid request ID: $request_id"
        pki_require_private_dir "$request_path" 'CSR candidate request directory'
        [[ ! -v request_ids[$request_id] ]] || pki_die "CSR candidate request ID is ambiguous across services: $request_id"
        request_ids[$request_id]=1; coordinates[$service/$request_id]=1
        SERVICE=$service; REQUEST_ID=$request_id; outcome_path=$outcomes/$service/$request_id
        if [[ ! -e $outcome_path && ! -L $outcome_path ]]; then
          pki_candidate_validate_pending_entry "$request_path"
          pki_die "CSR trust replacement is blocked by pending candidate: $service/$request_id"
        fi
        pki_candidate_authenticate_terminal_history "$work" || pki_die "CSR candidate terminal history authentication failed: $service/$request_id"
        unset -v scan_decision; declare -A scan_decision=()
        pki_csr_read_ordered_record "$outcome_path/decision" 'Authenticated historical CSR decision' scan_decision "${PKI_CANDIDATE_DECISION_FIELDS[@]}"
        if [[ ${scan_decision[state]} == finalized ]]; then
          finalized[$service/$request_id]=1
          if [[ ${scan_decision[operation]} == renew ]]; then superseded[$service/${scan_decision[predecessor_request_id]}]=1; fi
        fi
      done < <(find "$service_path" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
    done < <(find "$candidates" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  fi

  if [[ -e $outcomes || -L $outcomes ]]; then
    pki_require_private_dir "$outcomes" 'CSR outcome state directory'
    while IFS= read -r -d '' outcome_service; do
      service=${outcome_service##*/}; pki_validate_service_name "$service"; pki_require_private_dir "$outcome_service" 'CSR outcome service directory'
      [[ -n $(find "$outcome_service" -mindepth 1 -maxdepth 1 -print -quit) ]] || pki_die "CSR outcome service directory is unexpectedly empty: $service"
      while IFS= read -r -d '' outcome_path; do
        request_id=${outcome_path##*/}
        [[ $request_id =~ ^[0-9a-f]{32}$ ]] || pki_die "CSR outcome state contains an invalid request ID: $request_id"
        pki_require_private_dir "$outcome_path" 'CSR outcome request directory'
        [[ -v coordinates[$service/$request_id] ]] || pki_die "CSR outcome has no matching retained candidate: $service/$request_id"
      done < <(find "$outcome_service" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
    done < <(find "$outcomes" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  fi

  if [[ -e $active || -L $active ]]; then
    pki_require_private_dir "$active" 'CSR active accepted-evidence directory'
    while IFS= read -r -d '' active_path; do
      service=${active_path##*/}; pki_validate_service_name "$service"
      [[ -f $active_path && ! -L $active_path && $(stat -c '%u:%a:%h' "$active_path") == "$(id -u):600:1" ]] || pki_die "CSR active accepted-evidence pointer is unsafe: $service"
      unset -v active_record active_decision active_deployment
      declare -A active_record=() active_decision=() active_deployment=()
      pki_csr_read_ordered_record "$active_path" 'Historical active accepted-evidence pointer' active_record "${PKI_CANDIDATE_ACTIVE_FIELDS[@]}"
      request_id=${active_record[request_id]}
      [[ $(wc -l <"$active_path") -eq ${#PKI_CANDIDATE_ACTIVE_FIELDS[@]} && ${active_record[schema]} == 1 && ${active_record[service]} == "$service" && ${active_record[target]} =~ ^[a-z0-9][a-z0-9.-]*$ && $request_id =~ ^[0-9a-f]{32}$ && (${active_record[operation]} == issue || ${active_record[operation]} == migrate || ${active_record[operation]} == renew) ]] || pki_die "CSR active accepted-evidence pointer is invalid: $service"
      coordinate=$service/$request_id
      [[ -v coordinates[$coordinate] && -v finalized[$coordinate] && ! -v superseded[$coordinate] ]] || pki_die "CSR active accepted-evidence pointer does not reference a current finalized history head: $coordinate"
      outcome_path=$outcomes/$coordinate
      pki_csr_read_ordered_record "$outcome_path/decision" 'Historical active CSR decision' active_decision "${PKI_CANDIDATE_DECISION_FIELDS[@]}"
      pki_csr_read_ordered_record "$outcome_path/deployment" 'Historical active deployment evidence' active_deployment "${PKI_CANDIDATE_DEPLOYMENT_FIELDS[@]}"
      decision_digest=$(pki_candidate_sha256 "$outcome_path/decision" 'Historical active CSR decision')
      [[ ${active_decision[action]} == finalize && ${active_decision[state]} == finalized && ${active_decision[resulting_active_request_id]} == "$request_id" ]] || pki_die "CSR active accepted-evidence pointer references a non-finalized outcome: $coordinate"
      for name in service target request_id operation certificate_sha256 certificate_spki_sha256 response_sha256 artifact_manifest_sha256 deployment_sha256; do [[ ${active_record[$name]} == "${active_decision[$name]}" ]] || pki_die "CSR active accepted-evidence pointer does not bind outcome field $name: $coordinate"; done
      for name in certificate_sha256 certificate_spki_sha256 response_sha256 artifact_manifest_sha256 deployment_sha256 decision_sha256; do pki_candidate_require_digest "${active_record[$name]}" "Historical active pointer $name"; done
      pki_candidate_require_epoch "${active_record[activation_epoch]}" 'Historical active pointer activation_epoch'; pki_candidate_require_epoch "${active_record[updated_epoch]}" 'Historical active pointer updated_epoch'
      if [[ ${active_record[operation]} == issue ]]; then [[ ${active_record[rollback_hold_until_epoch]} == none ]] || pki_die "Issue active pointer has an unexpected rollback hold: $coordinate"; else pki_candidate_require_epoch "${active_record[rollback_hold_until_epoch]}" 'Historical active pointer rollback_hold_until_epoch'; fi
      [[ ${active_record[decision_sha256]} == "$decision_digest" && ${active_record[activation_epoch]} == "${active_deployment[activation_epoch]}" && ${active_record[rollback_hold_until_epoch]} == "${active_deployment[rollback_hold_until_epoch]}" && ${active_record[updated_epoch]} == "${active_deployment[created_epoch]}" ]] || pki_die "CSR active accepted-evidence pointer does not bind outcome epochs or decision: $coordinate"
      active_requests[$service]=$request_id
    done < <(find "$active" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  fi

  for coordinate in "${!finalized[@]}"; do
    [[ ! -v superseded[$coordinate] ]] || continue
    service=${coordinate%%/*}; request_id=${coordinate#*/}
    [[ ! -v heads[$service] ]] || pki_die "CSR terminal history has multiple active finalized heads: $service"
    heads[$service]=$request_id
    [[ ${active_requests[$service]:-none} == "$request_id" ]] || pki_die "CSR terminal history active pointer is missing or conflicting: $service"
  done
  for service in "${!active_requests[@]}"; do [[ -v heads[$service] ]] || pki_die "CSR active accepted-evidence pointer is orphaned: $service"; done

  pki_candidate_state_manifest >"$after"
  chmod 600 "$after"
  cmp -s -- "$before" "$after" || pki_die 'CSR candidate or outcome state changed during trust validation'
  pki_candidate_sha256 "$after" 'Authenticated CSR historical state manifest'
)

pki_candidate_cleanup() {
  local status=${1:-$?}
  trap - EXIT
  if [[ ${CANDIDATE_JOURNAL_STARTED:-false} == true ]]; then printf '[ERROR] CSR candidate finalization requires explicit recovery\n' >&2; fi
  [[ -z ${CANDIDATE_WORK_DIR:-} || ! -d $CANDIDATE_WORK_DIR ]] || pki_candidate_remove_work_dir "$CANDIDATE_WORK_DIR" "$CANDIDATE_WORK_IDENTITY" || status=1
  [[ ${CANDIDATE_EXPORT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CANDIDATE_EXPORT_LOCK" 2>/dev/null || status=1
  [[ ${CANDIDATE_INVENTORY_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CANDIDATE_INVENTORY_LOCK" 2>/dev/null || status=1
  [[ ${CANDIDATE_INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CANDIDATE_INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${CANDIDATE_ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CANDIDATE_ROOT_LOCK" 2>/dev/null || status=1
  [[ ${CANDIDATE_LIFECYCLE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$CANDIDATE_LIFECYCLE_LOCK" 2>/dev/null || status=1
  return "$status"
}

pki_candidate_run() {
  local action=$1 evidence signature
  SERVICE=${args[service]}; REQUEST_ID=${args[--request-id]}; CANDIDATE_ACTION=$action; CANDIDATE_FORMAT=${args[--format]:-text}
  NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}; PKI_DIR=${args[--pki-dir]:-}; NAMESPACE=$(pki_expand_path "$NAMESPACE"); PKI_DIR=$(pki_expand_path "${PKI_DIR:-$NAMESPACE/pki}")
  pki_validate_service_name "$SERVICE"; [[ $REQUEST_ID =~ ^[0-9a-f]{32}$ ]] || pki_die 'CSR candidate request ID is invalid'
  pki_require_cmd openssl; pki_require_cmd ssh-keygen; pki_require_cmd sha256sum; pki_require_cmd python3; pki_require_cmd cmp
  pki_require_pki_dir; pki_prepare_control_state; umask 077
  CANDIDATE_LIFECYCLE_LOCK=$(pki_lifecycle_operation_lock); CANDIDATE_ROOT_LOCK=$(pki_root_operation_lock); CANDIDATE_INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); CANDIDATE_INVENTORY_LOCK=$(pki_inventory_operation_lock); CANDIDATE_EXPORT_LOCK=$(pki_export_operation_lock)
  CANDIDATE_LIFECYCLE_LOCK_HELD=false; CANDIDATE_ROOT_LOCK_HELD=false; CANDIDATE_INTERMEDIATE_LOCK_HELD=false; CANDIDATE_INVENTORY_LOCK_HELD=false; CANDIDATE_EXPORT_LOCK_HELD=false; CANDIDATE_JOURNAL_STARTED=false
  trap 'status=$?; pki_candidate_cleanup "$status"; exit $?' EXIT
  pki_acquire_operation_lock "$CANDIDATE_LIFECYCLE_LOCK" 'PKI lifecycle operation'; CANDIDATE_LIFECYCLE_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_ROOT_LOCK" 'root CA operation'; CANDIDATE_ROOT_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_INTERMEDIATE_LOCK" 'intermediate CA operation'; CANDIDATE_INTERMEDIATE_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_INVENTORY_LOCK" 'inventory operation'; CANDIDATE_INVENTORY_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_EXPORT_LOCK" 'export operation'; CANDIDATE_EXPORT_LOCK_HELD=true
  pki_require_no_unresolved_journal; pki_require_generation_layout
  CANDIDATE_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-csr-candidate.XXXXXX") || pki_die 'Cannot create CSR candidate work directory'; chmod 700 "$CANDIDATE_WORK_DIR"; CANDIDATE_WORK_IDENTITY=$(pki_dir_identity "$CANDIDATE_WORK_DIR"); mkdir -m 700 "$CANDIDATE_WORK_DIR/inventory"
  pki_candidate_load_inventory_snapshot "$CANDIDATE_WORK_DIR/inventory"; pki_require_service_in_inventory "$SERVICE"; [[ $(pki_inventory_key_custody "$SERVICE") == host-local ]] || pki_die 'CSR candidate command requires key_custody: host-local'
  INVENTORY_TARGET=$(pki_inventory_scalar "$SERVICE" target); VALIDATION_BOUNDARY_SHA256=$(pki_inventory_scalar "$SERVICE" validation_boundary_sha256); ROLLBACK_HOLD_SECONDS=$(pki_inventory_scalar "$SERVICE" rollback_hold_seconds)
  # shellcheck disable=SC2034 # Shared profile validation consumes these globals.
  COMMON_NAME=$(pki_inventory_scalar "$SERVICE" common_name); DNS_FILE=$CANDIDATE_WORK_DIR/dns; IPS_FILE=$CANDIDATE_WORK_DIR/ips; pki_inventory_array "$SERVICE" dns >"$DNS_FILE"; pki_inventory_array "$SERVICE" ips >"$IPS_FILE"
  pki_candidate_validate_sources
  pki_candidate_load_retained_records
  if [[ $action == verify ]]; then pki_candidate_status; return; fi
  [[ ${args[--artifact-manifest-sha256]} == "$ARTIFACT_MANIFEST_SHA256" ]] || pki_die 'Certificate export manifest digest does not match --artifact-manifest-sha256'
  evidence=$(pki_expand_path "${args[--evidence-file]}"); signature=$(pki_expand_path "${args[--evidence-signature]}")
  pki_candidate_load_deployment "$evidence" "$signature"
  if pki_candidate_existing_outcome; then return; fi
  pki_candidate_predecessor; pki_candidate_validate_action_rules
  if [[ $action == finalize ]]; then pki_candidate_publish_finalize; else pki_candidate_publish_abandon; fi
}

pki_candidate_recover() {
  local journal status=0
  pki_require_cmd sha256sum; pki_require_cmd python3; pki_require_pki_dir; pki_prepare_control_state; umask 077
  CANDIDATE_LIFECYCLE_LOCK=$(pki_lifecycle_operation_lock); CANDIDATE_ROOT_LOCK=$(pki_root_operation_lock); CANDIDATE_INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock); CANDIDATE_INVENTORY_LOCK=$(pki_inventory_operation_lock); CANDIDATE_EXPORT_LOCK=$(pki_export_operation_lock)
  CANDIDATE_LIFECYCLE_LOCK_HELD=false; CANDIDATE_ROOT_LOCK_HELD=false; CANDIDATE_INTERMEDIATE_LOCK_HELD=false; CANDIDATE_INVENTORY_LOCK_HELD=false; CANDIDATE_EXPORT_LOCK_HELD=false
  trap 'status=$?; trap - EXIT; pki_candidate_cleanup "$status"; exit $?' EXIT
  pki_acquire_operation_lock "$CANDIDATE_LIFECYCLE_LOCK" 'PKI lifecycle operation'; CANDIDATE_LIFECYCLE_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_ROOT_LOCK" 'root CA operation'; CANDIDATE_ROOT_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_INTERMEDIATE_LOCK" 'intermediate CA operation'; CANDIDATE_INTERMEDIATE_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_INVENTORY_LOCK" 'inventory operation'; CANDIDATE_INVENTORY_LOCK_HELD=true
  pki_acquire_operation_lock "$CANDIDATE_EXPORT_LOCK" 'export operation'; CANDIDATE_EXPORT_LOCK_HELD=true
  [[ $(pki_detect_layout) == generation ]] || pki_die 'CSR finalization recovery requires complete generation-aware PKI state'
  journal=$(pki_csr_finalization_recovery_journal); [[ -f $journal && ! -L $journal ]] || pki_die 'No CSR candidate finalization recovery journal exists'
  unset -v CANDIDATE_FINALIZATION_JOURNAL; declare -gA CANDIDATE_FINALIZATION_JOURNAL=()
  pki_csr_read_ordered_record "$journal" 'CSR candidate finalization recovery journal' CANDIDATE_FINALIZATION_JOURNAL "${PKI_CANDIDATE_JOURNAL_FIELDS[@]}"
  [[ $(wc -l <"$journal") -eq ${#PKI_CANDIDATE_JOURNAL_FIELDS[@]} ]] || pki_die 'CSR candidate finalization recovery journal is not canonically newline-terminated'
  if [[ -n ${args[--transaction]:-} && ${args[--transaction]} != "csr-${CANDIDATE_FINALIZATION_JOURNAL[request_id]}" ]]; then pki_die 'CSR recovery transaction does not match the finalization journal'; fi
  pki_candidate_resume_finalization
  pki_ok "Recovered CSR candidate finalization: ${CANDIDATE_FINALIZATION_JOURNAL[service]}/${CANDIDATE_FINALIZATION_JOURNAL[request_id]}"
}
