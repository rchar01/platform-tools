#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-root-create.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-pki-root-create-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

INIT_TOOL="$ROOT_DIR/bin/platform-pki-init"
TOOL="$ROOT_DIR/bin/platform-pki-root-create"
RECOVER_TOOL="$ROOT_DIR/bin/platform-pki-ca-rollover"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0
PASS_FILE="$TMP_DIR/root.pass"
printf '%s\n' 'root-test-passphrase-123' >"$PASS_FILE"
chmod 600 "$PASS_FILE"

fail() {
  printf 'test-root-create.sh: %s\n' "$*" >&2
  exit 1
}

run_command() {
  set +e
  "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

run_tool() {
  local namespace=$1
  shift
  run_command "$TOOL" --namespace "$namespace" "$@"
}

run_interactive_tool() {
  local namespace=$1 passphrase=$2

  set +e
  yes "$passphrase" | \
    "$TOOL" --namespace "$namespace" --name 'Interactive Root' \
      --org 'Platform Test' --country PL >"$STDOUT" 2>"$STDERR"
  STATUS=${PIPESTATUS[1]}
  set -e
}

init_namespace() {
  local namespace=$1
  run_command "$INIT_TOOL" --namespace "$namespace"
  assert_status 0
}

create_encrypted_root() {
  local namespace=$1
  run_tool "$namespace" \
    --name 'Test Root CA' --org 'Platform Test' --country PL \
    --root-pass-file "$PASS_FILE"
  assert_status 0
}

assert_status() {
  [[ $STATUS -eq $1 ]] || fail "expected status $1, got $STATUS; stdout=$(<"$STDOUT"); stderr=$(<"$STDERR")"
}

assert_empty() {
  [[ ! -s $1 ]] || fail "expected empty output: $(<"$1")"
}

assert_contains() {
  local file=$1 expected=$2
  grep -Fq -- "$expected" "$file" || fail "expected '$expected' in $(<"$file")"
}

assert_mode() {
  local expected=$1 path=$2 actual
  actual=$(stat -c '%a' "$path")
  [[ $actual == "$expected" ]] || fail "expected mode $expected for $path, got $actual"
}

assert_same_hash() {
  local expected=$1 path=$2 actual
  actual=$(sha256sum "$path")
  actual=${actual%% *}
  [[ $actual == "$expected" ]] || fail "unexpected replacement of $path"
}

assert_no_transaction_residue() {
  local root_ca_dir=$1

  if compgen -G "$root_ca_dir/.platform-pki-root-create.*" >/dev/null; then
    fail "root transaction left staging or lock state in $root_ca_dir"
  fi
}

save_transaction_state() {
  local pki_dir=$1

  SAVED_CONF="$pki_dir/authorities/roots/g1/openssl.cnf"
  SAVED_KEY="$pki_dir/authorities/roots/g1/private/root-ca.key"
  SAVED_CERT="$pki_dir/authorities/roots/g1/certs/root-ca.crt"
  SAVED_CONF_HASH=$(file_hash "$SAVED_CONF")
  SAVED_KEY_HASH=$(file_hash "$SAVED_KEY")
  SAVED_CERT_HASH=$(file_hash "$SAVED_CERT")
  SAVED_CONF_MODE=$(stat -c '%a' "$SAVED_CONF")
  SAVED_KEY_MODE=$(stat -c '%a' "$SAVED_KEY")
  SAVED_CERT_MODE=$(stat -c '%a' "$SAVED_CERT")
}

assert_transaction_state_restored() {
  assert_same_hash "$SAVED_CONF_HASH" "$SAVED_CONF"
  assert_same_hash "$SAVED_KEY_HASH" "$SAVED_KEY"
  assert_same_hash "$SAVED_CERT_HASH" "$SAVED_CERT"
  assert_mode "$SAVED_CONF_MODE" "$SAVED_CONF"
  assert_mode "$SAVED_KEY_MODE" "$SAVED_KEY"
  assert_mode "$SAVED_CERT_MODE" "$SAVED_CERT"
  assert_no_transaction_residue "$(dirname -- "$SAVED_CONF")"
}

file_hash() {
  local value
  value=$(sha256sum "$1")
  printf '%s\n' "${value%% *}"
}

assert_key_matches_cert() {
  local key=$1 cert=$2 pass_file=${3:-}
  local cert_pub="$TMP_DIR/cert.pub" key_pub="$TMP_DIR/key.pub"
  openssl x509 -in "$cert" -pubkey -noout >"$cert_pub"
  if [[ -n $pass_file ]]; then
    openssl pkey -in "$key" -passin "file:$pass_file" -pubout -out "$key_pub" >/dev/null 2>&1
  else
    openssl pkey -in "$key" -pubout -out "$key_pub" >/dev/null 2>&1
  fi
  cmp "$cert_pub" "$key_pub" >/dev/null || fail 'root key and certificate do not match'
}

run_command "$TOOL" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-root-create --version | -v'
assert_contains "$STDOUT" '--allow-unencrypted-root-key'
assert_empty "$STDERR"

run_command "$TOOL" --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-root-create $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_command "$TOOL" --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_command "$TOOL" --org Test --country PL
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'missing required flag: --name CN'

run_command "$TOOL" --name '' --org Test --country PL
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'must not be empty'

run_command "$TOOL" --name Test --org Test --country PL --days zero
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Days value must be numeric: zero'

run_command env PLATFORM_PKI_ROOT_DAYS=zero "$TOOL" \
  --namespace "$TMP_DIR/env-invalid" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Days value must be numeric: zero'

dollar_pki="$TMP_DIR/pki-\$variable"
run_command "$TOOL" --namespace "$TMP_DIR/path-validation" \
  --pki-dir "$dollar_pki" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory must not contain OpenSSL variable expansion syntax'
[[ ! -e $dollar_pki ]] || fail 'dollar-containing PKI path created state'

newline_pki="$TMP_DIR/"$'pki\nnewline'
run_command "$TOOL" --namespace "$TMP_DIR/path-validation" \
  --pki-dir "$newline_pki" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory must not contain newlines'
[[ ! -e $newline_pki ]] || fail 'newline-containing PKI path created state'
[[ ! -e $TMP_DIR/path-validation ]] || fail 'invalid PKI paths created namespace state'

run_command "$TOOL" --namespace "$TMP_DIR/injection" \
  --name $'Test\nsubjectAltName = DNS:invalid' --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'must not contain newlines'
[[ ! -e $TMP_DIR/injection ]] || fail 'invalid DN value created namespace state'

encrypted_namespace="$TMP_DIR/encrypted"
init_namespace "$encrypted_namespace"
create_encrypted_root "$encrypted_namespace"
encrypted_pki="$encrypted_namespace/pki"
encrypted_key="$encrypted_pki/authorities/roots/g1/private/root-ca.key"
encrypted_cert="$encrypted_pki/authorities/roots/g1/certs/root-ca.crt"
encrypted_conf="$encrypted_pki/authorities/roots/g1/openssl.cnf"
assert_contains "$STDOUT" "[OK] Created root CA generation g1: $encrypted_cert"
assert_empty "$STDERR"
assert_mode 600 "$encrypted_key"
assert_mode 644 "$encrypted_cert"
assert_mode 600 "$encrypted_conf"
openssl pkey -in "$encrypted_key" -passin "file:$PASS_FILE" -noout >/dev/null 2>&1 || fail 'encrypted key did not open with passphrase file'
if openssl pkey -in "$encrypted_key" -passin pass:wrong -noout >/dev/null 2>&1; then
  fail 'encrypted key opened with the wrong passphrase'
fi
assert_key_matches_cert "$encrypted_key" "$encrypted_cert" "$PASS_FILE"
subject=$(openssl x509 -in "$encrypted_cert" -noout -subject -nameopt RFC2253)
[[ $subject == 'subject=CN=Test Root CA,O=Platform Test,C=PL' ]] || fail "unexpected certificate subject: $subject"

interactive_namespace="$TMP_DIR/interactive"
init_namespace "$interactive_namespace"
interactive_pass='interactive-root-passphrase-123'
run_interactive_tool "$interactive_namespace" "$interactive_pass"
assert_status 0
interactive_key="$interactive_namespace/pki/authorities/roots/g1/private/root-ca.key"
interactive_cert="$interactive_namespace/pki/authorities/roots/g1/certs/root-ca.crt"
openssl pkey -in "$interactive_key" -passin "pass:$interactive_pass" -noout >/dev/null 2>&1 || fail 'interactive encrypted key did not open with its passphrase'
if openssl pkey -in "$interactive_key" -passin pass:wrong -noout >/dev/null 2>&1; then
  fail 'interactive encrypted key opened with the wrong passphrase'
fi
openssl x509 -in "$interactive_cert" -pubkey -noout >"$TMP_DIR/interactive-cert.pub"
openssl pkey -in "$interactive_key" -passin "pass:$interactive_pass" \
  -pubout -out "$TMP_DIR/interactive-key.pub" >/dev/null 2>&1
cmp "$TMP_DIR/interactive-cert.pub" "$TMP_DIR/interactive-key.pub" >/dev/null || fail 'interactive root key and certificate do not match'

fallback_namespace="$TMP_DIR/fallback-days"
init_namespace "$fallback_namespace"
run_tool "$fallback_namespace" --name 'Fallback Root' --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 0
fallback_cert="$fallback_namespace/pki/authorities/roots/g1/certs/root-ca.crt"
openssl x509 -in "$fallback_cert" -checkend $((3649 * 86400)) -noout >/dev/null || fail 'fallback lifetime was shorter than 3650 days'
if openssl x509 -in "$fallback_cert" -checkend $((3651 * 86400)) -noout >/dev/null; then
  fail 'fallback lifetime exceeded 3650 days'
fi

override_namespace="$TMP_DIR/override-days"
init_namespace "$override_namespace"
run_command env PLATFORM_PKI_ROOT_DAYS=2 "$TOOL" \
  --namespace "$override_namespace" --name 'Override Root' --org Test \
  --country PL --days 5 --root-pass-file "$PASS_FILE"
assert_status 0
override_cert="$override_namespace/pki/authorities/roots/g1/certs/root-ca.crt"
openssl x509 -in "$override_cert" -checkend $((4 * 86400)) -noout >/dev/null || fail 'CLI lifetime override was shorter than five days'
if openssl x509 -in "$override_cert" -checkend $((6 * 86400)) -noout >/dev/null; then
  fail '--days did not override PLATFORM_PKI_ROOT_DAYS'
fi

env_namespace="$TMP_DIR/env-days"
init_namespace "$env_namespace"
run_command env PLATFORM_PKI_ROOT_DAYS=2 "$TOOL" \
  --namespace "$env_namespace" --name 'Environment Root' --org Test \
  --country PL --root-pass-file "$PASS_FILE"
assert_status 0
env_cert="$env_namespace/pki/authorities/roots/g1/certs/root-ca.crt"
openssl x509 -in "$env_cert" -checkend 86400 -noout >/dev/null || fail 'environment lifetime was shorter than one day'
if openssl x509 -in "$env_cert" -checkend 259200 -noout >/dev/null; then
  fail 'PLATFORM_PKI_ROOT_DAYS was not used as the lifetime default'
fi

missing_pass="$TMP_DIR/missing.pass"
run_tool "$encrypted_namespace" --name Test --org Test --country PL \
  --root-pass-file "$missing_pass" --force
assert_status 1
assert_contains "$STDERR" 'Passphrase file is missing'

open_pass="$TMP_DIR/open.pass"
printf '%s\n' 'open-test-passphrase-123' >"$open_pass"
chmod 644 "$open_pass"
run_tool "$encrypted_namespace" --name Test --org Test --country PL \
  --root-pass-file "$open_pass" --force
assert_status 1
assert_contains "$STDERR" 'permissions are too open'

short_pass="$TMP_DIR/short.pass"
printf '%s\n' 'short' >"$short_pass"
chmod 600 "$short_pass"
run_tool "$encrypted_namespace" --name Test --org Test --country PL \
  --root-pass-file "$short_pass" --force
assert_status 1
assert_contains "$STDERR" 'at least 16 characters'

run_tool "$encrypted_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE" --allow-unencrypted-root-key --force
assert_status 1
assert_contains "$STDERR" 'conflicting options'

unencrypted_namespace="$TMP_DIR/unencrypted"
init_namespace "$unencrypted_namespace"
run_tool "$unencrypted_namespace" --name 'Unencrypted Root' --org Test \
  --country PL --allow-unencrypted-root-key
assert_status 0
assert_contains "$STDERR" 'Creating an unencrypted root CA private key'
unencrypted_key="$unencrypted_namespace/pki/authorities/roots/g1/private/root-ca.key"
unencrypted_cert="$unencrypted_namespace/pki/authorities/roots/g1/certs/root-ca.crt"
openssl pkey -in "$unencrypted_key" -noout >/dev/null 2>&1 || fail 'unencrypted key requires a passphrase'
assert_key_matches_cert "$unencrypted_key" "$unencrypted_cert"

key_hash=$(file_hash "$encrypted_key")
cert_hash=$(file_hash "$encrypted_cert")
run_tool "$encrypted_namespace" --name Replacement --org Test --country PL \
  --root-pass-file "$PASS_FILE" --force
assert_status 1
assert_contains "$STDERR" "bootstrap root already exists"
assert_same_hash "$key_hash" "$encrypted_key"
assert_same_hash "$cert_hash" "$encrypted_cert"

custom_namespace="$TMP_DIR/custom-namespace"
custom_pki="$TMP_DIR/custom-pki"
run_command "$INIT_TOOL" --namespace "$custom_namespace" --pki-dir "$custom_pki"
assert_status 0
run_command "$TOOL" --namespace "$custom_namespace" --pki-dir "$custom_pki" \
  --name 'Custom PKI Root' --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 0
[[ -f $custom_pki/authorities/roots/g1/certs/root-ca.crt ]] || fail 'explicit PKI directory was not used'

for boundary in after-journal after-reservation after-reservation-consumed after-authority after-bootstrap; do
  fault_namespace="$TMP_DIR/fault-$boundary"; init_namespace "$fault_namespace"
  run_command env PLATFORM_PKI_ROOT_FAIL_AT="$boundary" "$TOOL" --namespace "$fault_namespace" \
    --name 'Fault Root' --org Test --country PL --allow-unencrypted-root-key
  assert_status 1
  fault_pki="$fault_namespace/pki"
  [[ ! -e $fault_pki/authorities/roots/g1 && ! -e $fault_pki/state/bootstrap-root ]] || fail "root state remained after $boundary"
  grep -Fx 'committed=true' "$fault_pki/state/rollover/journal" >/dev/null || fail "root journal was not closed after $boundary"
  if [[ -e $fault_pki/state/generation-reservations/g1 ]]; then grep -Fx 'status=abandoned' "$fault_pki/state/generation-reservations/g1" >/dev/null || fail "root reservation was not abandoned after $boundary"; fi
done

recovery_crash_namespace="$TMP_DIR/recovery-of-recovery"; init_namespace "$recovery_crash_namespace"
run_command env PLATFORM_PKI_ROOT_CRASH_AT=after-bootstrap "$TOOL" --namespace "$recovery_crash_namespace" --name Crash --org Test --country PL --allow-unencrypted-root-key
assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$recovery_crash_namespace/pki/state/rollover/journal")
for recovery_boundary in rollback-bootstrap-pending rollback-bootstrap-done rollback-authority-pending rollback-authority-done rollback-reservation-pending rollback-reservation-done; do
  run_command env PLATFORM_PKI_RECOVER_CRASH_AT="$recovery_boundary" "$RECOVER_TOOL" recover --namespace "$recovery_crash_namespace" --transaction "$transaction" --action rollback --yes
  assert_status 137
done
run_command "$RECOVER_TOOL" recover --namespace "$recovery_crash_namespace" --transaction "$transaction" --action rollback --yes; assert_status 0
grep -Fx 'status=abandoned' "$recovery_crash_namespace/pki/state/generation-reservations/g1" >/dev/null || fail 'recovery-of-recovery lost the root reservation'

retry_namespace="$TMP_DIR/handled-retry"; init_namespace "$retry_namespace"
run_command env PLATFORM_PKI_ROOT_FAIL_AT=after-reservation "$TOOL" --namespace "$retry_namespace" --name Retry --org Test --country PL --allow-unencrypted-root-key; assert_status 1
run_tool "$retry_namespace" --name Retry --org Test --country PL --allow-unencrypted-root-key; assert_status 0
[[ $(<"$retry_namespace/pki/state/bootstrap-root") == root=g2$'\n'fingerprint_sha256=* ]] || fail 'root bootstrap retry did not allocate g2'
grep -Fx 'status=abandoned' "$retry_namespace/pki/state/generation-reservations/g1" >/dev/null || fail 'root bootstrap retry reused its abandoned g1 reservation'
grep -Fx 'status=consumed' "$retry_namespace/pki/state/generation-reservations/g2" >/dev/null || fail 'root bootstrap retry did not consume g2'

hostile_namespace="$TMP_DIR/hostile-generation"; init_namespace "$hostile_namespace"; mkdir -m 700 "$TMP_DIR/foreign-root"; ln -s "$TMP_DIR/foreign-root" "$hostile_namespace/pki/authorities/roots/g1"
run_tool "$hostile_namespace" --name Hostile --org Test --country PL --allow-unencrypted-root-key --force
assert_status 1; [[ -L $hostile_namespace/pki/authorities/roots/g1 && -d $TMP_DIR/foreign-root ]] || fail 'root --force altered hostile generation state'

for boundary in after-journal after-reservation after-reservation-consumed after-authority after-bootstrap; do
  crash_namespace="$TMP_DIR/crash-recovery-$boundary"; init_namespace "$crash_namespace"
  run_command env PLATFORM_PKI_ROOT_CRASH_AT="$boundary" "$TOOL" --namespace "$crash_namespace" --name Crash --org Test --country PL --allow-unencrypted-root-key
  assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$crash_namespace/pki/state/rollover/journal")
  run_command "$RECOVER_TOOL" recover --namespace "$crash_namespace" --transaction "$transaction" --action rollback --yes; assert_status 0
  [[ ! -e $crash_namespace/pki/authorities/roots/g1 && ! -e $crash_namespace/pki/state/bootstrap-root && -f $crash_namespace/pki/state/generation-reservations/g1 ]] || fail "root crash recovery did not preserve its abandoned reservation after $boundary"
  grep -Fx 'status=abandoned' "$crash_namespace/pki/state/generation-reservations/g1" >/dev/null || fail "root crash recovery did not abandon g1 after $boundary"
  run_tool "$crash_namespace" --name Retry --org Test --country PL --allow-unencrypted-root-key; assert_status 0
  grep -Fx 'root=g2' "$crash_namespace/pki/state/bootstrap-root" >/dev/null || fail "root crash retry reused g1 after $boundary"
done

signal_namespace="$TMP_DIR/signal-recovery"; init_namespace "$signal_namespace"
run_command env PLATFORM_PKI_ROOT_SIGNAL_AT=after-authority "$TOOL" --namespace "$signal_namespace" --name Signal --org Test --country PL --allow-unencrypted-root-key
assert_status 143; [[ ! -e $signal_namespace/pki/authorities/roots/g1 && ! -e $signal_namespace/pki/state/bootstrap-root ]] || fail 'root signal rollback left authority state'

openssl_namespace="$TMP_DIR/openssl-failure"; init_namespace "$openssl_namespace"; mkdir -p "$EXEC_DIR/root-openssl-failure"
REAL_OPENSSL=$(command -v openssl); printf '%s\n' '#!/usr/bin/env bash' '[[ ${1:-} != req ]] || exit 42' 'exec "$REAL_OPENSSL" "$@"' >"$EXEC_DIR/root-openssl-failure/openssl"; chmod 755 "$EXEC_DIR/root-openssl-failure/openssl"
run_command env PATH="$EXEC_DIR/root-openssl-failure:$PATH" REAL_OPENSSL="$REAL_OPENSSL" "$TOOL" --namespace "$openssl_namespace" --name Failure --org Test --country PL --allow-unencrypted-root-key
assert_status 42; [[ ! -e $openssl_namespace/pki/authorities/roots/g1 ]] || fail 'OpenSSL failure published root state'

for hostile_case in key-symlink db-hardlink writable-dir; do
  hostile_namespace="$TMP_DIR/hostile-$hostile_case"; init_namespace "$hostile_namespace"; hostile_root="$hostile_namespace/pki/authorities/roots/g1"; mkdir -m 700 -p "$hostile_root/private" "$hostile_root/certs"
  case $hostile_case in
    key-symlink) printf '%s\n' victim >"$TMP_DIR/root-victim"; ln -s "$TMP_DIR/root-victim" "$hostile_root/private/root-ca.key" ;;
    db-hardlink) printf '%s\n' sentinel >"$hostile_root/serial"; chmod 600 "$hostile_root/serial"; ln "$hostile_root/serial" "$TMP_DIR/root-hardlink" ;;
    writable-dir) chmod 777 "$hostile_root/certs" ;;
  esac
  run_tool "$hostile_namespace" --name Hostile --org Test --country PL --allow-unencrypted-root-key --force; assert_status 1
  [[ -d $hostile_root && ! -L $hostile_root ]] || fail "hostile root state was deleted: $hostile_case"
done

printf '%s\n' 'test-root-create.sh: ok'
