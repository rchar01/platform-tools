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

pki_reject_repeated_options --namespace --pki-dir --root-pass-file --intermediate-pass-file
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
ROOT_PASS_FILE=${args[--root-pass-file]:-}
INTERMEDIATE_PASS_FILE=${args[--intermediate-pass-file]:-}
[[ -n $ROOT_PASS_FILE || -n $INTERMEDIATE_PASS_FILE ]] || \
  pki_die 'At least one of --root-pass-file or --intermediate-pass-file is required'

NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
[[ -z $ROOT_PASS_FILE ]] || ROOT_PASS_FILE=$(pki_expand_path "$ROOT_PASS_FILE")
[[ -z $INTERMEDIATE_PASS_FILE ]] || INTERMEDIATE_PASS_FILE=$(pki_expand_path "$INTERMEDIATE_PASS_FILE")

pki_require_cmd openssl
pki_require_cmd cmp
pki_require_pki_dir
pki_prepare_control_state
ROOT_LOCK=$(pki_root_operation_lock)
INTERMEDIATE_LOCK=$(pki_intermediate_operation_lock)
VERIFY_DIR=''
VERIFY_DIR_IDENTITY=''
PASS_FD=''
KEY_FD=''
CERT_FD=''
AUX_FD=''
CAPTURED_OUTPUT=''
CURRENT_UID=$(id -u)

close_pass_descriptor() {
  [[ -z ${PASS_FD:-} ]] || exec {PASS_FD}<&-
  PASS_FD=''
}

close_key_descriptor() {
  [[ -z ${KEY_FD:-} ]] || exec {KEY_FD}<&-
  KEY_FD=''
}

close_cert_descriptor() {
  [[ -z ${CERT_FD:-} ]] || exec {CERT_FD}<&-
  CERT_FD=''
}

close_aux_descriptor() {
  [[ -z ${AUX_FD:-} ]] || exec {AUX_FD}<&-
  AUX_FD=''
}

close_verification_descriptors() {
  close_aux_descriptor
  close_cert_descriptor
  close_key_descriptor
  close_pass_descriptor
}

run_without_verification_descriptors() (
  close_verification_descriptors
  "$@"
)

capture_without_verification_descriptors() {
  local capture_file=$VERIFY_DIR/metadata.capture
  : >"$capture_file" || return 1
  (
    close_verification_descriptors
    "$@" >"$capture_file"
  ) || return 1
  CAPTURED_OUTPUT=''
  IFS= read -r CAPTURED_OUTPUT <"$capture_file" || [[ -n $CAPTURED_OUTPUT ]] || return 1
  : >"$capture_file"
}

capture_opened_descriptor_identity() {
  local role=$1
  local capture_file=$VERIFY_DIR/metadata.capture
  : >"$capture_file" || return 1
  if ! (
    case $role in
      pass)
        close_aux_descriptor
        close_cert_descriptor
        close_key_descriptor
        stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$PASS_FD" >"$capture_file"
        ;;
      key)
        close_aux_descriptor
        close_cert_descriptor
        close_pass_descriptor
        stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$KEY_FD" >"$capture_file"
        ;;
      certificate)
        close_aux_descriptor
        close_key_descriptor
        close_pass_descriptor
        stat -Lc '%d:%i:%u:%a:%h:%s:%y:%z:%F' "/proc/self/fd/$CERT_FD" >"$capture_file"
        ;;
      *) return 1 ;;
    esac
  ); then
    return 1
  fi
  CAPTURED_OUTPUT=''
  IFS= read -r CAPTURED_OUTPUT <"$capture_file" || [[ -n $CAPTURED_OUTPUT ]] || return 1
  : >"$capture_file"
}

# shellcheck disable=SC2329 # Invoked by the EXIT trap.
finish_passphrase_verify() {
  local status=$?
  trap - EXIT
  close_verification_descriptors
  if [[ -n $VERIFY_DIR && -n $VERIFY_DIR_IDENTITY ]]; then
    pki_remove_journaled_tree "$VERIFY_DIR" "$VERIFY_DIR_IDENTITY" "$(dirname -- "$VERIFY_DIR")" 2>/dev/null || status=1
  fi
  [[ ${INTERMEDIATE_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$INTERMEDIATE_LOCK" 2>/dev/null || status=1
  [[ ${ROOT_LOCK_HELD:-false} != true ]] || pki_release_operation_lock "$ROOT_LOCK" 2>/dev/null || status=1
  exit "$status"
}
trap finish_passphrase_verify EXIT
umask 077
pki_acquire_operation_lock "$ROOT_LOCK" 'root CA operation'; ROOT_LOCK_HELD=true
pki_acquire_operation_lock "$INTERMEDIATE_LOCK" 'intermediate CA operation'; INTERMEDIATE_LOCK_HELD=true
pki_require_no_unresolved_journal
pki_require_generation_layout
pki_read_pair_manifest "$(pki_active_issuer_manifest)" 'Active issuer'
ROOT_CA_DIR=$(pki_root_authority_dir "$ACTIVE_ROOT_ID")
INTERMEDIATE_CA_DIR=$(pki_intermediate_authority_dir "$ACTIVE_INTERMEDIATE_ID")
pki_require_private_dir "$ROOT_CA_DIR" 'Root authority generation'
pki_require_private_dir "$INTERMEDIATE_CA_DIR" 'Intermediate authority generation'
VERIFY_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-ca-passphrase-verify.XXXXXX") || \
  pki_die 'Cannot create CA passphrase verification directory'
VERIFY_DIR_IDENTITY=$(pki_dir_identity "$VERIFY_DIR") || \
  pki_die 'Cannot snapshot CA passphrase verification directory identity'

open_passphrase_descriptor() {
  local path=$1 before opened metadata passphrase current
  [[ -f $path && ! -L $path ]] || pki_die "Passphrase file must be a non-symlink regular file: $path"
  capture_without_verification_descriptors stat -c '%u:%a:%h' -- "$path" || \
    pki_die "Cannot inspect passphrase file metadata: $path"; metadata=$CAPTURED_OUTPUT
  [[ $metadata == "$CURRENT_UID:"*':1' ]] || \
    pki_die "Passphrase file must be current-user-owned and singly linked: $path"
  pki_require_pass_file "$path"
  capture_without_verification_descriptors pki_file_identity "$path" || \
    pki_die "Cannot inspect passphrase file: $path"; before=$CAPTURED_OUTPUT
  capture_without_verification_descriptors stat -c '%u:%a:%h' -- "$path" || \
    pki_die "Cannot reinspect passphrase file metadata: $path"; metadata=$CAPTURED_OUTPUT
  [[ -f $path && ! -L $path && $metadata =~ ^${CURRENT_UID}:([0-7]+):1$ ]] || \
    pki_die "Passphrase file changed during validation: $path"
  (( (8#${BASH_REMATCH[1]} & 077) == 0 )) || \
    pki_die "Passphrase file permissions are too open; use chmod 600 or stricter: $path"
  exec {PASS_FD}<"$path" || pki_die "Cannot open passphrase file: $path"
  capture_opened_descriptor_identity pass || pki_die 'Cannot inspect opened passphrase file descriptor'
  opened=$CAPTURED_OUTPUT
  if capture_without_verification_descriptors pki_file_identity "$path"; then current=$CAPTURED_OUTPUT; else current=''; fi
  [[ $opened == "$before" && $current == "$before" ]] || \
    pki_die "Passphrase file identity changed while opening: $path"
  exec {AUX_FD}<"/proc/self/fd/$PASS_FD" || \
    pki_die 'Cannot duplicate passphrase file descriptor for validation'
  IFS= read -r passphrase <&"$AUX_FD" || [[ -n $passphrase ]] || {
    close_aux_descriptor
    pki_die "Passphrase file first line is empty: $path"
  }
  close_aux_descriptor
  [[ -n $passphrase ]] || pki_die "Passphrase file first line is empty: $path"
  [[ $passphrase =~ [^[:space:]] ]] || pki_die "Passphrase file first line must contain non-whitespace characters: $path"
  (( ${#passphrase} >= 16 )) || pki_die "Passphrase file first line must be at least 16 characters: $path"
  unset passphrase
  if capture_without_verification_descriptors pki_file_identity "$path"; then current=$CAPTURED_OUTPUT; else current=''; fi
  [[ $current == "$before" ]] || pki_die "Passphrase file changed during validation: $path"
  PASS_FILE_IDENTITY=$before
}

open_authority_descriptors() {
  local key=$1 certificate=$2 key_before key_opened cert_before cert_opened key_header metadata current
  if capture_without_verification_descriptors stat -c '%u:%a:%h' -- "$key"; then metadata=$CAPTURED_OUTPUT; else metadata=''; fi
  [[ -f $key && ! -L $key && $metadata == "$CURRENT_UID:600:1" ]] || \
    pki_die 'Active CA private key is unsafe'
  if capture_without_verification_descriptors stat -c '%u:%a:%h' -- "$certificate"; then metadata=$CAPTURED_OUTPUT; else metadata=''; fi
  [[ -f $certificate && ! -L $certificate && $metadata == "$CURRENT_UID:644:1" ]] || \
    pki_die 'Active CA certificate is unsafe'
  capture_without_verification_descriptors pki_file_identity "$key" || \
    pki_die 'Cannot inspect active CA private key'; key_before=$CAPTURED_OUTPUT
  capture_without_verification_descriptors pki_file_identity "$certificate" || \
    pki_die 'Cannot inspect active CA certificate'; cert_before=$CAPTURED_OUTPUT
  exec {KEY_FD}<"$key" || pki_die 'Cannot open active CA private key'
  exec {CERT_FD}<"$certificate" || pki_die 'Cannot open active CA certificate'
  capture_opened_descriptor_identity key || pki_die 'Cannot inspect opened active CA private key'; key_opened=$CAPTURED_OUTPUT
  capture_opened_descriptor_identity certificate || pki_die 'Cannot inspect opened active CA certificate'; cert_opened=$CAPTURED_OUTPUT
  if capture_without_verification_descriptors pki_file_identity "$key"; then current=$CAPTURED_OUTPUT; else current=''; fi
  [[ $key_opened == "$key_before" && $current == "$key_before" ]] || \
    pki_die 'Active CA private key identity changed while opening'
  if capture_without_verification_descriptors pki_file_identity "$certificate"; then current=$CAPTURED_OUTPUT; else current=''; fi
  [[ $cert_opened == "$cert_before" && $current == "$cert_before" ]] || \
    pki_die 'Active CA certificate identity changed while opening'
  exec {AUX_FD}<"/proc/self/fd/$KEY_FD" || \
    pki_die 'Cannot duplicate active CA private key descriptor for validation'
  IFS= read -r -n 64 key_header <&"$AUX_FD" || [[ -n $key_header ]] || {
    close_aux_descriptor
    pki_die 'CA passphrase verification failed'
  }
  close_aux_descriptor
  [[ $key_header == '-----BEGIN ENCRYPTED PRIVATE KEY-----' ]] || pki_die 'CA passphrase verification failed'
  unset key_header
  KEY_FILE_IDENTITY=$key_before
  CERT_FILE_IDENTITY=$cert_before
}

verify_authority() {
  local pass_file=$1 key=$2 certificate=$3 output_prefix=$4
  local key_public=$VERIFY_DIR/$output_prefix-key.pub certificate_public=$VERIFY_DIR/$output_prefix-certificate.pub
  local pass_current key_current cert_current
  open_passphrase_descriptor "$pass_file"
  open_authority_descriptors "$key" "$certificate"
  exec {AUX_FD}<"/proc/self/fd/$PASS_FD" || \
    pki_die 'Cannot duplicate passphrase file descriptor for OpenSSL'
  if ! (
    close_cert_descriptor
    close_pass_descriptor
    openssl pkey -in "/proc/self/fd/$KEY_FD" -passin "fd:$AUX_FD" -check -noout \
      >/dev/null 2>&1
  ); then
    close_verification_descriptors
    pki_die 'CA passphrase verification failed'
  fi
  close_aux_descriptor
  exec {AUX_FD}<"/proc/self/fd/$PASS_FD" || \
    pki_die 'Cannot duplicate passphrase file descriptor for OpenSSL'
  if ! (
    close_cert_descriptor
    close_pass_descriptor
    openssl pkey -in "/proc/self/fd/$KEY_FD" -passin "fd:$AUX_FD" -pubout -out "$key_public" \
      >/dev/null 2>&1
  ); then
    close_verification_descriptors
    pki_die 'CA passphrase verification failed'
  fi
  close_aux_descriptor
  if ! (
    close_key_descriptor
    close_pass_descriptor
    openssl x509 -in "/proc/self/fd/$CERT_FD" -pubkey -noout >"$certificate_public" 2>/dev/null
  ); then
    close_verification_descriptors
    pki_die 'CA passphrase verification failed'
  fi
  if ! run_without_verification_descriptors cmp -s "$key_public" "$certificate_public"; then
    close_verification_descriptors
    pki_die 'CA passphrase verification failed'
  fi
  if capture_without_verification_descriptors pki_file_identity "$pass_file"; then pass_current=$CAPTURED_OUTPUT; else pass_current=''; fi
  if capture_without_verification_descriptors pki_file_identity "$key"; then key_current=$CAPTURED_OUTPUT; else key_current=''; fi
  if capture_without_verification_descriptors pki_file_identity "$certificate"; then cert_current=$CAPTURED_OUTPUT; else cert_current=''; fi
  if [[ $pass_current != "$PASS_FILE_IDENTITY" || $key_current != "$KEY_FILE_IDENTITY" || \
    $cert_current != "$CERT_FILE_IDENTITY" ]]; then
    close_verification_descriptors
    pki_die 'CA verification input changed during verification'
  fi
  close_verification_descriptors
}

if [[ -n $ROOT_PASS_FILE ]]; then
  verify_authority "$ROOT_PASS_FILE" "$(pki_root_key)" "$(pki_root_cert)" root
fi
if [[ -n $INTERMEDIATE_PASS_FILE ]]; then
  verify_authority "$INTERMEDIATE_PASS_FILE" "$(pki_intermediate_key)" "$(pki_intermediate_cert)" intermediate
fi

[[ -z $ROOT_PASS_FILE ]] || printf 'root=valid\n'
[[ -z $INTERMEDIATE_PASS_FILE ]] || printf 'intermediate=valid\n'
