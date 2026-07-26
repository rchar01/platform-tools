#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-root-create.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-pki-root-create-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

INIT_TOOL="$ROOT_DIR/bin/platform-pki-init"
TOOL="$ROOT_DIR/bin/platform-pki-root-create"
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

  SAVED_CONF="$pki_dir/root-ca/openssl.cnf"
  SAVED_KEY="$pki_dir/root-ca/private/root-ca.key"
  SAVED_CERT="$pki_dir/root-ca/certs/root-ca.crt"
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
encrypted_key="$encrypted_pki/root-ca/private/root-ca.key"
encrypted_cert="$encrypted_pki/root-ca/certs/root-ca.crt"
encrypted_conf="$encrypted_pki/root-ca/openssl.cnf"
assert_contains "$STDOUT" "[OK] Created root CA certificate: $encrypted_cert"
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
interactive_key="$interactive_namespace/pki/root-ca/private/root-ca.key"
interactive_cert="$interactive_namespace/pki/root-ca/certs/root-ca.crt"
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
fallback_cert="$fallback_namespace/pki/root-ca/certs/root-ca.crt"
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
override_cert="$override_namespace/pki/root-ca/certs/root-ca.crt"
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
env_cert="$env_namespace/pki/root-ca/certs/root-ca.crt"
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
unencrypted_key="$unencrypted_namespace/pki/root-ca/private/root-ca.key"
unencrypted_cert="$unencrypted_namespace/pki/root-ca/certs/root-ca.crt"
openssl pkey -in "$unencrypted_key" -noout >/dev/null 2>&1 || fail 'unencrypted key requires a passphrase'
assert_key_matches_cert "$unencrypted_key" "$unencrypted_cert"

key_hash=$(file_hash "$encrypted_key")
cert_hash=$(file_hash "$encrypted_cert")
conf_hash=$(file_hash "$encrypted_conf")
run_tool "$encrypted_namespace" --name Replacement --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root key exists; use --force to overwrite'
assert_same_hash "$key_hash" "$encrypted_key"
assert_same_hash "$cert_hash" "$encrypted_cert"
assert_same_hash "$conf_hash" "$encrypted_conf"

printf '%s\n' 'database sentinel' >"$encrypted_pki/root-ca/index.txt"
printf '%s\n' 'unrelated sentinel' >"$encrypted_pki/root-ca/unrelated"
run_tool "$encrypted_namespace" --name 'Replacement Root' --org Test \
  --country PL --days 30 --root-pass-file "$PASS_FILE" --force
assert_status 0
[[ $(file_hash "$encrypted_key") != "$key_hash" ]] || fail '--force did not replace root key'
[[ $(file_hash "$encrypted_cert") != "$cert_hash" ]] || fail '--force did not replace root certificate'
[[ $(<"$encrypted_pki/root-ca/index.txt") == 'database sentinel' ]] || fail '--force replaced CA database state'
[[ $(<"$encrypted_pki/root-ca/unrelated") == 'unrelated sentinel' ]] || fail '--force replaced unrelated state'
assert_key_matches_cert "$encrypted_key" "$encrypted_cert" "$PASS_FILE"

mkdir -p "$EXEC_DIR/failing-bin"
REAL_OPENSSL=$(command -v openssl)
cat >"$EXEC_DIR/failing-bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == req ]]; then
  exit 42
fi
exec "$REAL_OPENSSL" "$@"
EOF
chmod 755 "$EXEC_DIR/failing-bin/openssl"
key_hash=$(file_hash "$encrypted_key")
cert_hash=$(file_hash "$encrypted_cert")
conf_hash=$(file_hash "$encrypted_conf")
run_command env PATH="$EXEC_DIR/failing-bin:$PATH" REAL_OPENSSL="$REAL_OPENSSL" \
  "$TOOL" --namespace "$encrypted_namespace" --name 'Failed Replacement' \
  --org Test --country PL --root-pass-file "$PASS_FILE" --force
assert_status 42
assert_same_hash "$key_hash" "$encrypted_key"
assert_same_hash "$cert_hash" "$encrypted_cert"
assert_same_hash "$conf_hash" "$encrypted_conf"
assert_no_transaction_residue "$encrypted_pki/root-ca"

mkdir -p "$EXEC_DIR/publication-bin"
REAL_MV=$(command -v mv)
cat >"$EXEC_DIR/publication-bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f $MV_COUNTER ]]; then
  count=$(<"$MV_COUNTER")
fi
count=$((count + 1))
printf '%s\n' "$count" >"$MV_COUNTER"
if [[ ${MV_FAIL_AT:-0} == "$count" ]]; then
  exit 42
fi
if [[ ${MV_SIGNAL_AT:-0} == "$count" ]]; then
  kill -TERM "$PPID"
  exit 143
fi
exec "$REAL_MV" "$@"
EOF
chmod 755 "$EXEC_DIR/publication-bin/mv"

for fail_at in 2 3; do
  save_transaction_state "$encrypted_pki"
  counter="$TMP_DIR/mv-fail-$fail_at.counter"
  run_command env PATH="$EXEC_DIR/publication-bin:$PATH" \
    REAL_MV="$REAL_MV" MV_COUNTER="$counter" MV_FAIL_AT="$fail_at" \
    "$TOOL" --namespace "$encrypted_namespace" \
    --name "Publication Failure $fail_at" --org Test --country PL \
    --root-pass-file "$PASS_FILE" --force
  assert_status 1
  assert_contains "$STDERR" 'Failed to publish root CA material'
  assert_transaction_state_restored
done

save_transaction_state "$encrypted_pki"
counter="$TMP_DIR/mv-signal.counter"
run_command env PATH="$EXEC_DIR/publication-bin:$PATH" \
  REAL_MV="$REAL_MV" MV_COUNTER="$counter" MV_SIGNAL_AT=3 \
  "$TOOL" --namespace "$encrypted_namespace" \
  --name 'Publication Signal' --org Test --country PL \
  --root-pass-file "$PASS_FILE" --force
assert_status 143
assert_transaction_state_restored

key_only_namespace="$TMP_DIR/key-only"
init_namespace "$key_only_namespace"
key_only="$key_only_namespace/pki/root-ca/private/root-ca.key"
printf '%s\n' 'key sentinel' >"$key_only"
chmod 600 "$key_only"
run_tool "$key_only_namespace" --name 'Key Only Root' --org Test --country PL \
  --root-pass-file "$PASS_FILE" --force
assert_status 0
[[ -f $key_only_namespace/pki/root-ca/certs/root-ca.crt ]] || fail '--force did not complete key-only state'

cert_only_namespace="$TMP_DIR/cert-only"
init_namespace "$cert_only_namespace"
cert_only="$cert_only_namespace/pki/root-ca/certs/root-ca.crt"
printf '%s\n' 'certificate sentinel' >"$cert_only"
chmod 644 "$cert_only"
run_tool "$cert_only_namespace" --name 'Certificate Only Root' --org Test \
  --country PL --root-pass-file "$PASS_FILE" --force
assert_status 0
[[ -f $cert_only_namespace/pki/root-ca/private/root-ca.key ]] || fail '--force did not complete certificate-only state'

symlink_namespace="$TMP_DIR/symlink"
init_namespace "$symlink_namespace"
symlink_victim="$TMP_DIR/symlink-victim"
printf '%s\n' 'symlink victim' >"$symlink_victim"
ln -s "$symlink_victim" "$symlink_namespace/pki/root-ca/private/root-ca.key"
run_tool "$symlink_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE" --force
assert_status 1
assert_contains "$STDERR" 'Root CA key must not be a symlink'
[[ $(<"$symlink_victim") == 'symlink victim' ]] || fail 'symlink destination was modified'

hardlink_namespace="$TMP_DIR/hardlink"
init_namespace "$hardlink_namespace"
hardlink_key="$hardlink_namespace/pki/root-ca/private/root-ca.key"
printf '%s\n' 'hard-link victim' >"$hardlink_key"
chmod 600 "$hardlink_key"
ln "$hardlink_key" "$TMP_DIR/hardlink-victim"
run_tool "$hardlink_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE" --force
assert_status 1
assert_contains "$STDERR" 'Root CA key must not be hard-linked'
[[ $(<"$TMP_DIR/hardlink-victim") == 'hard-link victim' ]] || fail 'hard-link destination was modified'

db_symlink_namespace="$TMP_DIR/db-symlink"
init_namespace "$db_symlink_namespace"
db_symlink_root="$db_symlink_namespace/pki/root-ca"
rm "$db_symlink_root/index.txt"
ln -s "$TMP_DIR/missing-index-target" "$db_symlink_root/index.txt"
run_tool "$db_symlink_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root CA index must not be a symlink'
[[ ! -e $TMP_DIR/missing-index-target ]] || fail 'CA DB symlink target was created'
[[ ! -e $db_symlink_root/private/root-ca.key ]] || fail 'unsafe CA DB created root material'

db_hardlink_namespace="$TMP_DIR/db-hardlink"
init_namespace "$db_hardlink_namespace"
db_hardlink_root="$db_hardlink_namespace/pki/root-ca"
ln "$db_hardlink_root/serial" "$TMP_DIR/serial-hardlink"
run_tool "$db_hardlink_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root CA serial must not be hard-linked'
[[ ! -e $db_hardlink_root/private/root-ca.key ]] || fail 'hard-linked CA DB created root material'

db_type_namespace="$TMP_DIR/db-type"
init_namespace "$db_type_namespace"
db_type_root="$db_type_namespace/pki/root-ca"
rm "$db_type_root/crlnumber"
mkdir "$db_type_root/crlnumber"
run_tool "$db_type_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root CA CRL number must be a regular file'
[[ ! -e $db_type_root/private/root-ca.key ]] || fail 'invalid CA DB type created root material'

db_mode_namespace="$TMP_DIR/db-mode"
init_namespace "$db_mode_namespace"
db_mode_root="$db_mode_namespace/pki/root-ca"
chmod 666 "$db_mode_root/index.txt.attr"
db_mode_hash=$(file_hash "$db_mode_root/index.txt.attr")
run_tool "$db_mode_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root CA index attributes is group- or world-writable'
assert_same_hash "$db_mode_hash" "$db_mode_root/index.txt.attr"
assert_mode 666 "$db_mode_root/index.txt.attr"
[[ ! -e $db_mode_root/private/root-ca.key ]] || fail 'unsafe CA DB mode created root material'

db_owner_namespace="$TMP_DIR/db-owner"
init_namespace "$db_owner_namespace"
db_owner_root="$db_owner_namespace/pki/root-ca"
db_owner_target="$db_owner_root/index.txt"
db_owner_hash=$(file_hash "$db_owner_target")
mkdir -p "$EXEC_DIR/owner-bin"
REAL_STAT=$(command -v stat)
cat >"$EXEC_DIR/owner-bin/stat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -eq 3 && $1 == -c && $2 == %u && $3 == "$STAT_OWNER_TARGET" ]]; then
  printf '%s\n' "$STAT_FAKE_OWNER"
  exit 0
fi
exec "$REAL_STAT" "$@"
EOF
chmod 755 "$EXEC_DIR/owner-bin/stat"
run_command env PATH="$EXEC_DIR/owner-bin:$PATH" REAL_STAT="$REAL_STAT" \
  STAT_OWNER_TARGET="$db_owner_target" STAT_FAKE_OWNER=$(( $(id -u) + 1 )) \
  "$TOOL" --namespace "$db_owner_namespace" --name Test --org Test \
  --country PL --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root CA index is not owned by the current user'
assert_same_hash "$db_owner_hash" "$db_owner_target"
[[ ! -e $db_owner_root/private/root-ca.key ]] || fail 'foreign-owned CA DB created root material'

tree_mode_namespace="$TMP_DIR/tree-mode"
init_namespace "$tree_mode_namespace"
tree_mode_root="$tree_mode_namespace/pki/root-ca"
chmod 777 "$tree_mode_root/certs"
run_tool "$tree_mode_namespace" --name Test --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 1
assert_contains "$STDERR" 'Root CA certificate directory is group- or world-writable'
assert_mode 777 "$tree_mode_root/certs"
[[ ! -e $tree_mode_root/private/root-ca.key ]] || fail 'unsafe root directory mode created material'

custom_namespace="$TMP_DIR/custom-namespace"
custom_pki="$TMP_DIR/custom-pki"
run_command "$INIT_TOOL" --namespace "$custom_namespace" --pki-dir "$custom_pki"
assert_status 0
run_command "$TOOL" --namespace "$custom_namespace" --pki-dir "$custom_pki" \
  --name 'Custom PKI Root' --org Test --country PL \
  --root-pass-file "$PASS_FILE"
assert_status 0
[[ -f $custom_pki/root-ca/certs/root-ca.crt ]] || fail 'explicit PKI directory was not used'

printf '%s\n' 'test-root-create.sh: ok'
