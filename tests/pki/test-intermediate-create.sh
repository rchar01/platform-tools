#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-intermediate-create.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-pki-intermediate-create-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

INIT_TOOL="$ROOT_DIR/bin/platform-pki-init"
ROOT_TOOL="$ROOT_DIR/bin/platform-pki-root-create"
TOOL="$ROOT_DIR/bin/platform-pki-intermediate-create"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0
ROOT_PASS="$TMP_DIR/root.pass"
INT_PASS="$TMP_DIR/intermediate.pass"
printf '%s\n' 'root-test-passphrase-123' >"$ROOT_PASS"
printf '%s\n' 'intermediate-test-passphrase-123' >"$INT_PASS"
chmod 600 "$ROOT_PASS" "$INT_PASS"

fail() {
  printf 'test-intermediate-create.sh: %s\n' "$*" >&2
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

file_hash() {
  local value
  value=$(sha256sum "$1")
  printf '%s\n' "${value%% *}"
}

assert_same_hash() {
  local expected=$1 path=$2
  [[ $(file_hash "$path") == "$expected" ]] || fail "unexpected replacement of $path"
}

assert_no_transaction_residue() {
  local ca_dir=$1 pki=${1%/intermediate-ca}
  if compgen -G "$ca_dir/.platform-pki-intermediate-create.*" >/dev/null; then
    fail "intermediate transaction left staging or lock state in $ca_dir"
  fi
  [[ ! -e $pki/root-ca/.platform-pki-root-operation.lock ]] || \
    fail 'root CA operation lock was not removed'
  [[ ! -e $ca_dir/.platform-pki-intermediate-operation.lock ]] || \
    fail 'intermediate CA operation lock was not removed'
}

init_namespace() {
  local namespace=$1
  run_command "$INIT_TOOL" --namespace "$namespace"
  assert_status 0
}

create_root() {
  local namespace=$1
  run_command "$ROOT_TOOL" --namespace "$namespace" --name 'Test Root CA' \
    --org 'Platform Test' --country PL --root-pass-file "$ROOT_PASS"
  assert_status 0
}

create_intermediate() {
  local namespace=$1
  shift
  run_tool "$namespace" --name 'Test Intermediate CA' --org 'Platform Test' \
    --country PL --root-pass-file "$ROOT_PASS" \
    --intermediate-pass-file "$INT_PASS" "$@"
  assert_status 0
}

save_state() {
  local pki=$1 path
  SAVED_PATHS=(
    "$pki/intermediate-ca/openssl.cnf"
    "$pki/intermediate-ca/private/intermediate-ca.key"
    "$pki/intermediate-ca/csr/intermediate-ca.csr"
    "$pki/intermediate-ca/certs/intermediate-ca.crt"
    "$pki/intermediate-ca/certs/ca-chain.crt"
    "$pki/root-ca/index.txt" "$pki/root-ca/index.txt.attr" "$pki/root-ca/serial"
    "$pki/root-ca/index.txt.old" "$pki/root-ca/index.txt.attr.old" "$pki/root-ca/serial.old"
  )
  SAVED_HASHES=()
  for path in "${SAVED_PATHS[@]}"; do
    SAVED_HASHES+=("$(file_hash "$path")")
  done
  SAVED_NEWCERTS=$(find "$pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
}

assert_state_restored() {
  local pki=$1 i
  for i in "${!SAVED_PATHS[@]}"; do
    assert_same_hash "${SAVED_HASHES[i]}" "${SAVED_PATHS[i]}"
  done
  [[ $(find "$pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$SAVED_NEWCERTS" ]] || \
    fail 'root newcerts changed after failed replacement'
  assert_no_transaction_residue "$pki/intermediate-ca"
}

assert_intermediate_db_defaults() {
  local pki=$1 db="$1/intermediate-ca"

  [[ ! -s $db/index.txt ]] || fail 'initialized intermediate index is not empty'
  [[ $(<"$db/index.txt.attr") == 'unique_subject = no' ]] || \
    fail 'initialized intermediate index attributes are incorrect'
  [[ $(<"$db/serial") == 1000 ]] || fail 'initialized intermediate serial is incorrect'
  [[ $(<"$db/crlnumber") == 1000 ]] || fail 'initialized intermediate CRL number is incorrect'
  for file in index.txt index.txt.attr serial crlnumber; do
    assert_mode 600 "$db/$file"
  done
  openssl ca -config "$db/openssl.cnf" -updatedb \
    -passin "file:$INT_PASS" >/dev/null 2>&1 || \
    fail 'initialized intermediate database is not usable by OpenSSL'
}

assert_missing_db_transaction_rolled_back() {
  local pki=$1 file

  for file in index.txt index.txt.attr serial crlnumber; do
    [[ ! -e $pki/intermediate-ca/$file ]] || \
      fail "failed transaction published missing database file: $file"
  done
  for file in \
    intermediate-ca/openssl.cnf \
    intermediate-ca/private/intermediate-ca.key \
    intermediate-ca/csr/intermediate-ca.csr \
    intermediate-ca/certs/intermediate-ca.crt \
    intermediate-ca/certs/ca-chain.crt; do
    [[ ! -e $pki/$file ]] || fail "failed transaction published intermediate material: $file"
  done
  assert_same_hash "$MISSING_DB_ROOT_INDEX_HASH" "$pki/root-ca/index.txt"
  assert_same_hash "$MISSING_DB_ROOT_SERIAL_HASH" "$pki/root-ca/serial"
  [[ $(find "$pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$MISSING_DB_ROOT_NEWCERTS" ]] || \
    fail 'failed missing-database transaction changed root newcerts'
  assert_no_transaction_residue "$pki/intermediate-ca"
}

run_command "$TOOL" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-intermediate-create --version | -v'
assert_contains "$STDOUT" '--allow-unencrypted-intermediate-key'
assert_empty "$STDERR"

run_command "$TOOL" --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-intermediate-create $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_command "$TOOL" --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_command "$TOOL" --org Test --country PL
assert_status 1
assert_contains "$STDERR" 'missing required flag: --name CN'

run_command "$TOOL" --name Test --org Test --country PL --days zero
assert_status 1
assert_contains "$STDERR" 'Days value must be numeric: zero'

run_command "$TOOL" --name Test --org Test --country PL --days=
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --days='

run_command "$TOOL" --name Test --org Test --country PL \
  --intermediate-pass-file "$INT_PASS" --allow-unencrypted-intermediate-key
assert_status 1
assert_contains "$STDERR" 'conflicting options'

invalid_namespace="$TMP_DIR/invalid"
run_tool "$invalid_namespace" --name $'Invalid\nCN' --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'must not contain newlines'
[[ ! -e $invalid_namespace ]] || fail 'invalid identity created namespace state'

dollar_pki="$TMP_DIR/pki-\$variable"
run_command "$TOOL" --namespace "$TMP_DIR/path-validation" --pki-dir "$dollar_pki" \
  --name Test --org Test --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'PKI directory must not contain OpenSSL variable expansion syntax'
[[ ! -e $dollar_pki ]] || fail 'invalid PKI path created state'

missing_root_namespace="$TMP_DIR/missing-root"
init_namespace "$missing_root_namespace"
missing_root_serial=$(file_hash "$missing_root_namespace/pki/root-ca/serial")
run_tool "$missing_root_namespace" --name Test --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Required file is missing'
assert_same_hash "$missing_root_serial" "$missing_root_namespace/pki/root-ca/serial"
[[ ! -e $missing_root_namespace/pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'missing root prerequisite created an intermediate key'

lock_namespace="$TMP_DIR/intermediate-lock-contention"
init_namespace "$lock_namespace"
create_root "$lock_namespace"
lock_pki="$lock_namespace/pki"
lock_fixture="$lock_pki/intermediate-ca/.platform-pki-intermediate-operation.lock"
mkdir -m 700 "$lock_fixture"
lock_root_index_hash=$(file_hash "$lock_pki/root-ca/index.txt")
lock_root_serial_hash=$(file_hash "$lock_pki/root-ca/serial")
lock_intermediate_serial_hash=$(file_hash "$lock_pki/intermediate-ca/serial")
run_tool "$lock_namespace" --name 'Contended Intermediate' --org Test \
  --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Another intermediate CA operation is in progress'
[[ -d $lock_fixture ]] || fail 'contended intermediate operation lock was removed'
[[ ! -e $lock_pki/root-ca/.platform-pki-root-operation.lock ]] || \
  fail 'root operation lock was not released after intermediate lock contention'
assert_same_hash "$lock_root_index_hash" "$lock_pki/root-ca/index.txt"
assert_same_hash "$lock_root_serial_hash" "$lock_pki/root-ca/serial"
assert_same_hash "$lock_intermediate_serial_hash" "$lock_pki/intermediate-ca/serial"
[[ ! -e $lock_pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'intermediate lock contention allowed material publication'
if compgen -G "$lock_pki/intermediate-ca/.platform-pki-intermediate-create.*" >/dev/null; then
  fail 'intermediate lock contention left command staging or lock residue'
fi
rmdir "$lock_fixture"
assert_no_transaction_residue "$lock_pki/intermediate-ca"

for missing_db_case in index.txt index.txt.attr serial crlnumber all; do
  missing_db_namespace="$TMP_DIR/missing-db-${missing_db_case//./-}"
  init_namespace "$missing_db_namespace"
  create_root "$missing_db_namespace"
  missing_db_dir="$missing_db_namespace/pki/intermediate-ca"
  if [[ $missing_db_case == all ]]; then
    rm "$missing_db_dir/index.txt" "$missing_db_dir/index.txt.attr" \
      "$missing_db_dir/serial" "$missing_db_dir/crlnumber"
  else
    rm "$missing_db_dir/$missing_db_case"
  fi
  preserved_db_files=()
  preserved_db_hashes=()
  for file in index.txt index.txt.attr serial crlnumber; do
    if [[ -e $missing_db_dir/$file ]]; then
      preserved_db_files+=("$missing_db_dir/$file")
      preserved_db_hashes+=("$(file_hash "$missing_db_dir/$file")")
    fi
  done
  create_intermediate "$missing_db_namespace"
  for i in "${!preserved_db_files[@]}"; do
    assert_same_hash "${preserved_db_hashes[i]}" "${preserved_db_files[i]}"
  done
  assert_intermediate_db_defaults "$missing_db_namespace/pki"
done

collision_namespace="$TMP_DIR/serial-collision"
init_namespace "$collision_namespace"
create_root "$collision_namespace"
collision_pki="$collision_namespace/pki"
printf '%s\n' 'serial collision sentinel' >"$collision_pki/root-ca/newcerts/1000.pem"
chmod 600 "$collision_pki/root-ca/newcerts/1000.pem"
collision_index_hash=$(file_hash "$collision_pki/root-ca/index.txt")
collision_serial_hash=$(file_hash "$collision_pki/root-ca/serial")
collision_file_hash=$(file_hash "$collision_pki/root-ca/newcerts/1000.pem")
run_tool "$collision_namespace" --name Collision --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Root CA issued-certificate destination already exists'
assert_same_hash "$collision_index_hash" "$collision_pki/root-ca/index.txt"
assert_same_hash "$collision_serial_hash" "$collision_pki/root-ca/serial"
assert_same_hash "$collision_file_hash" "$collision_pki/root-ca/newcerts/1000.pem"
[[ ! -e $collision_pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'serial collision created intermediate material'
assert_no_transaction_residue "$collision_pki/intermediate-ca"

for serial_case in \
  'lowercase|abcd|ABCD|ABCE|cdef|CDEF' \
  'leading-zero|00ab|AB|AC|00cd|CD'; do
  IFS='|' read -r case_name serial_input issued_serial next_serial \
    collision_serial collision_filename <<<"$serial_case"
  serial_namespace="$TMP_DIR/serial-$case_name"
  init_namespace "$serial_namespace"
  create_root "$serial_namespace"
  serial_pki="$serial_namespace/pki"
  printf '%s\n' "$serial_input" >"$serial_pki/root-ca/serial"
  run_tool "$serial_namespace" --name "Serial $case_name" --org Test \
    --country PL --root-pass-file "$ROOT_PASS" \
    --intermediate-pass-file "$INT_PASS"
  assert_status 0
  serial_cert="$serial_pki/intermediate-ca/certs/intermediate-ca.crt"
  [[ $(openssl x509 -in "$serial_cert" -noout -serial) == "serial=$issued_serial" ]] || \
    fail "$case_name serial was not canonicalized by OpenSSL"
  [[ $(<"$serial_pki/root-ca/serial") == "$next_serial" ]] || \
    fail "$case_name serial did not advance with OpenSSL semantics"
  [[ -f $serial_pki/root-ca/newcerts/$issued_serial.pem ]] || \
    fail "$case_name canonical newcert filename was not published"
  [[ ! -e $serial_pki/root-ca/newcerts/$serial_input.pem || $serial_input == "$issued_serial" ]] || \
    fail "$case_name noncanonical newcert filename was published"

  printf '%s\n' "$collision_serial" >"$serial_pki/root-ca/serial"
  collision_target="$serial_pki/root-ca/newcerts/$collision_filename.pem"
  printf '%s\n' "$case_name collision sentinel" >"$collision_target"
  chmod 600 "$collision_target"
  collision_target_hash=$(file_hash "$collision_target")
  save_state "$serial_pki"
  run_tool "$serial_namespace" --name "$case_name collision" --org Test \
    --country PL --root-pass-file "$ROOT_PASS" \
    --intermediate-pass-file "$INT_PASS" --force
  assert_status 1
  assert_contains "$STDERR" 'Root CA issued-certificate destination already exists'
  assert_same_hash "$collision_target_hash" "$collision_target"
  assert_state_restored "$serial_pki"
done

encrypted_namespace="$TMP_DIR/encrypted"
init_namespace "$encrypted_namespace"
create_root "$encrypted_namespace"
create_intermediate "$encrypted_namespace" --days 5
encrypted_pki="$encrypted_namespace/pki"
int_key="$encrypted_pki/intermediate-ca/private/intermediate-ca.key"
int_cert="$encrypted_pki/intermediate-ca/certs/intermediate-ca.crt"
int_csr="$encrypted_pki/intermediate-ca/csr/intermediate-ca.csr"
int_conf="$encrypted_pki/intermediate-ca/openssl.cnf"
int_chain="$encrypted_pki/intermediate-ca/certs/ca-chain.crt"
root_cert="$encrypted_pki/root-ca/certs/root-ca.crt"
assert_contains "$STDOUT" "[OK] Created intermediate CA certificate: $int_cert"
assert_contains "$STDERR" 'Database updated'
assert_mode 600 "$int_key"
assert_mode 600 "$int_csr"
assert_mode 600 "$int_conf"
assert_mode 644 "$int_cert"
assert_mode 644 "$int_chain"
openssl pkey -in "$int_key" -passin "file:$INT_PASS" -noout >/dev/null 2>&1 || fail 'encrypted intermediate key did not open'
if openssl pkey -in "$int_key" -passin pass:wrong -noout >/dev/null 2>&1; then
  fail 'encrypted intermediate key opened with the wrong passphrase'
fi
subject=$(openssl x509 -in "$int_cert" -noout -subject -nameopt RFC2253)
issuer=$(openssl x509 -in "$int_cert" -noout -issuer -nameopt RFC2253)
[[ $subject == 'subject=CN=Test Intermediate CA,O=Platform Test,C=PL' ]] || fail "unexpected subject: $subject"
[[ $issuer == 'issuer=CN=Test Root CA,O=Platform Test,C=PL' ]] || fail "unexpected issuer: $issuer"
openssl verify -CAfile "$root_cert" "$int_cert" >/dev/null || fail 'intermediate certificate does not verify'
cat "$int_cert" "$root_cert" >"$TMP_DIR/expected-chain"
cmp "$TMP_DIR/expected-chain" "$int_chain" >/dev/null || fail 'CA chain order or content is wrong'
openssl x509 -in "$int_cert" -checkend $((4 * 86400)) -noout >/dev/null || fail 'five-day lifetime was too short'
if openssl x509 -in "$int_cert" -checkend $((6 * 86400)) -noout >/dev/null; then
  fail 'five-day lifetime was too long'
fi
[[ $(wc -l <"$encrypted_pki/root-ca/index.txt") -eq 1 ]] || fail 'root index was not mutated once'
[[ $(<"$encrypted_pki/root-ca/serial") == 1001 ]] || fail 'root serial was not incremented'
[[ -f $encrypted_pki/root-ca/newcerts/1000.pem ]] || fail 'root newcert was not published'

key_hash=$(file_hash "$int_key")
cert_hash=$(file_hash "$int_cert")
index_hash=$(file_hash "$encrypted_pki/root-ca/index.txt")
serial_hash=$(file_hash "$encrypted_pki/root-ca/serial")
run_tool "$encrypted_namespace" --name Replacement --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Intermediate key exists; use --force to overwrite'
assert_same_hash "$key_hash" "$int_key"
assert_same_hash "$cert_hash" "$int_cert"
assert_same_hash "$index_hash" "$encrypted_pki/root-ca/index.txt"
assert_same_hash "$serial_hash" "$encrypted_pki/root-ca/serial"

run_tool "$encrypted_namespace" --name 'Replacement Intermediate' --org Test \
  --country PL --days 7 --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS" --force
assert_status 0
[[ $(file_hash "$int_key") != "$key_hash" ]] || fail '--force did not replace the key'
[[ $(file_hash "$int_cert") != "$cert_hash" ]] || fail '--force did not replace the certificate'
[[ $(wc -l <"$encrypted_pki/root-ca/index.txt") -eq 2 ]] || fail 'forced signing did not append the root index'
[[ $(<"$encrypted_pki/root-ca/serial") == 1002 ]] || fail 'forced signing did not advance the root serial'
[[ -f $encrypted_pki/root-ca/newcerts/1001.pem ]] || fail 'forced signing did not publish the root newcert'

unencrypted_namespace="$TMP_DIR/unencrypted"
init_namespace "$unencrypted_namespace"
create_root "$unencrypted_namespace"
run_tool "$unencrypted_namespace" --name 'Unencrypted Intermediate' --org Test \
  --country PL --root-pass-file "$ROOT_PASS" \
  --allow-unencrypted-intermediate-key
assert_status 0
assert_contains "$STDERR" 'Creating an unencrypted intermediate CA private key'
openssl pkey -in "$unencrypted_namespace/pki/intermediate-ca/private/intermediate-ca.key" \
  -noout >/dev/null 2>&1 || fail 'unencrypted intermediate key requires a passphrase'

env_namespace="$TMP_DIR/environment-days"
init_namespace "$env_namespace"
create_root "$env_namespace"
run_command env PLATFORM_PKI_INTERMEDIATE_DAYS=2 "$TOOL" \
  --namespace "$env_namespace" --name 'Environment Intermediate' --org Test \
  --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS"
assert_status 0
env_cert="$env_namespace/pki/intermediate-ca/certs/intermediate-ca.crt"
openssl x509 -in "$env_cert" -checkend 86400 -noout >/dev/null || fail 'environment lifetime was shorter than one day'
if openssl x509 -in "$env_cert" -checkend 259200 -noout >/dev/null; then
  fail 'PLATFORM_PKI_INTERMEDIATE_DAYS was not used as the lifetime default'
fi

save_state "$encrypted_pki"
mkdir -p "$EXEC_DIR/failing-bin"
REAL_OPENSSL=$(command -v openssl)
cat >"$EXEC_DIR/failing-bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == ca ]]; then
  exit 42
fi
exec "$REAL_OPENSSL" "$@"
EOF
chmod 755 "$EXEC_DIR/failing-bin/openssl"
run_command env PATH="$EXEC_DIR/failing-bin:$PATH" REAL_OPENSSL="$REAL_OPENSSL" \
  "$TOOL" --namespace "$encrypted_namespace" --name 'Failed Signing' \
  --org Test --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS" --force
assert_status 42
assert_state_restored "$encrypted_pki"

missing_db_failure_namespace="$TMP_DIR/missing-db-signing-failure"
init_namespace "$missing_db_failure_namespace"
create_root "$missing_db_failure_namespace"
missing_db_failure_pki="$missing_db_failure_namespace/pki"
rm "$missing_db_failure_pki/intermediate-ca/index.txt" \
  "$missing_db_failure_pki/intermediate-ca/index.txt.attr" \
  "$missing_db_failure_pki/intermediate-ca/serial" \
  "$missing_db_failure_pki/intermediate-ca/crlnumber"
MISSING_DB_ROOT_INDEX_HASH=$(file_hash "$missing_db_failure_pki/root-ca/index.txt")
MISSING_DB_ROOT_SERIAL_HASH=$(file_hash "$missing_db_failure_pki/root-ca/serial")
MISSING_DB_ROOT_NEWCERTS=$(find "$missing_db_failure_pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
run_command env PATH="$EXEC_DIR/failing-bin:$PATH" REAL_OPENSSL="$REAL_OPENSSL" \
  "$TOOL" --namespace "$missing_db_failure_namespace" \
  --name 'Missing DB Signing Failure' --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 42
assert_missing_db_transaction_rolled_back "$missing_db_failure_pki"

mkdir -p "$EXEC_DIR/publication-bin"
REAL_MV=$(command -v mv)
cat >"$EXEC_DIR/publication-bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f $MV_COUNTER ]] || count=$(<"$MV_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" >"$MV_COUNTER"
[[ $count != "$MV_FAIL_AT" ]] || exit 42
if [[ -n ${MV_SIGNAL:-} && $count == "${MV_SIGNAL_AT:-0}" ]]; then
  kill "-$MV_SIGNAL" "$PPID"
  exit 143
fi
if [[ $count == "${MV_REPLACE_AT:-0}" ]]; then
  "$REAL_MV" "$@"
  destination=${!#}
  foreign="${destination}.foreign-fixture"
  printf '%s\n' "$MV_REPLACE_SENTINEL" >"$foreign"
  chmod 600 "$foreign"
  "$REAL_MV" -f -- "$foreign" "$destination"
  exit 0
fi
exec "$REAL_MV" "$@"
EOF
chmod 755 "$EXEC_DIR/publication-bin/mv"
REAL_LN=$(command -v ln)
cat >"$EXEC_DIR/publication-bin/ln" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n ${LN_COUNTER:-} ]]; then
  count=0
  [[ ! -f $LN_COUNTER ]] || count=$(<"$LN_COUNTER")
  count=$((count + 1))
  printf '%s\n' "$count" >"$LN_COUNTER"
  if [[ $count == "${LN_COLLISION_AT:-0}" ]]; then
    destination=${!#}
    printf '%s\n' "$LN_COLLISION_SENTINEL" >"$destination"
    chmod 600 "$destination"
  fi
  [[ $count != "${LN_FAIL_AT:-0}" ]] || exit 42
  if [[ -n ${LN_SIGNAL:-} && $count == "${LN_SIGNAL_AT:-0}" ]]; then
    kill "-$LN_SIGNAL" "$PPID"
    exit 143
  fi
fi
exec "$REAL_LN" "$@"
EOF
chmod 755 "$EXEC_DIR/publication-bin/ln"
save_state "$encrypted_pki"
run_command env PATH="$EXEC_DIR/publication-bin:$PATH" REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" \
  MV_COUNTER="$TMP_DIR/mv.counter" MV_FAIL_AT=7 \
  "$TOOL" --namespace "$encrypted_namespace" --name 'Failed Publication' \
  --org Test --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Failed to publish CA state'
assert_state_restored "$encrypted_pki"

save_state "$encrypted_pki"
foreign_intermediate_sentinel='foreign intermediate publication replacement'
run_command env PATH="$EXEC_DIR/publication-bin:$PATH" \
  REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" \
  MV_COUNTER="$TMP_DIR/intermediate-foreign.counter" \
  MV_REPLACE_AT=1 MV_FAIL_AT=2 \
  MV_REPLACE_SENTINEL="$foreign_intermediate_sentinel" \
  "$TOOL" --namespace "$encrypted_namespace" \
  --name 'Foreign Intermediate Replacement' --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Published CA destination identity changed'
assert_contains "$STDERR" 'preserved staging and locks for recovery'
[[ $(<"${SAVED_PATHS[0]}") == "$foreign_intermediate_sentinel" ]] || \
  fail 'foreign intermediate replacement was not preserved'
for i in "${!SAVED_PATHS[@]}"; do
  [[ $i -eq 0 ]] || assert_same_hash "${SAVED_HASHES[i]}" "${SAVED_PATHS[i]}"
done
[[ $(find "$encrypted_pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$SAVED_NEWCERTS" ]] || \
  fail 'foreign replacement failure changed root newcerts'
[[ -d $encrypted_pki/intermediate-ca/.platform-pki-intermediate-create.lock ]] || \
  fail 'intermediate create lock was not retained for recovery'
[[ -d $encrypted_pki/root-ca/.platform-pki-root-operation.lock ]] || \
  fail 'root operation lock was not retained for intermediate recovery'
[[ -d $encrypted_pki/intermediate-ca/.platform-pki-intermediate-operation.lock ]] || \
  fail 'intermediate operation lock was not retained for recovery'
intermediate_recovery_stage=$(compgen -G "$encrypted_pki/intermediate-ca/.platform-pki-intermediate-create.??????")
[[ -n $intermediate_recovery_stage && -d $intermediate_recovery_stage ]] || \
  fail 'intermediate staging was not retained for recovery'
assert_same_hash "${SAVED_HASHES[0]}" "$intermediate_recovery_stage/backup-0"

# Complete the documented recovery manually inside this disposable namespace.
rm -f -- "${SAVED_PATHS[0]}"
cp -p -- "$intermediate_recovery_stage/backup-0" "${SAVED_PATHS[0]}"
rm -rf -- "$intermediate_recovery_stage"
rmdir "$encrypted_pki/intermediate-ca/.platform-pki-intermediate-create.lock"
rmdir "$encrypted_pki/intermediate-ca/.platform-pki-intermediate-operation.lock"
rmdir "$encrypted_pki/root-ca/.platform-pki-root-operation.lock"
assert_state_restored "$encrypted_pki"

no_clobber_namespace="$TMP_DIR/no-clobber-collision"
init_namespace "$no_clobber_namespace"
create_root "$no_clobber_namespace"
no_clobber_pki="$no_clobber_namespace/pki"
rm "$no_clobber_pki/intermediate-ca/index.txt"
no_clobber_attr_hash=$(file_hash "$no_clobber_pki/intermediate-ca/index.txt.attr")
no_clobber_serial_hash=$(file_hash "$no_clobber_pki/intermediate-ca/serial")
no_clobber_crl_hash=$(file_hash "$no_clobber_pki/intermediate-ca/crlnumber")
MISSING_DB_ROOT_INDEX_HASH=$(file_hash "$no_clobber_pki/root-ca/index.txt")
MISSING_DB_ROOT_SERIAL_HASH=$(file_hash "$no_clobber_pki/root-ca/serial")
MISSING_DB_ROOT_NEWCERTS=$(find "$no_clobber_pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
collision_sentinel='foreign no-clobber sentinel'
run_command env PATH="$EXEC_DIR/publication-bin:$PATH" \
  REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" \
  MV_COUNTER="$TMP_DIR/no-clobber-mv.counter" MV_FAIL_AT=0 \
  LN_COUNTER="$TMP_DIR/no-clobber-ln.counter" LN_FAIL_AT=0 \
  LN_COLLISION_AT=4 LN_COLLISION_SENTINEL="$collision_sentinel" \
  "$TOOL" --namespace "$no_clobber_namespace" \
  --name 'No Clobber Collision' --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Intermediate CA material appeared during creation'
[[ $(<"$no_clobber_pki/intermediate-ca/index.txt") == "$collision_sentinel" ]] || \
  fail 'rollback removed or replaced the foreign no-clobber sentinel'
assert_same_hash "$no_clobber_attr_hash" "$no_clobber_pki/intermediate-ca/index.txt.attr"
assert_same_hash "$no_clobber_serial_hash" "$no_clobber_pki/intermediate-ca/serial"
assert_same_hash "$no_clobber_crl_hash" "$no_clobber_pki/intermediate-ca/crlnumber"
assert_same_hash "$MISSING_DB_ROOT_INDEX_HASH" "$no_clobber_pki/root-ca/index.txt"
assert_same_hash "$MISSING_DB_ROOT_SERIAL_HASH" "$no_clobber_pki/root-ca/serial"
[[ $(find "$no_clobber_pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$MISSING_DB_ROOT_NEWCERTS" ]] || \
  fail 'no-clobber collision changed root newcerts'
for path in \
  intermediate-ca/openssl.cnf \
  intermediate-ca/private/intermediate-ca.key \
  intermediate-ca/csr/intermediate-ca.csr \
  intermediate-ca/certs/intermediate-ca.crt \
  intermediate-ca/certs/ca-chain.crt; do
  [[ ! -e $no_clobber_pki/$path ]] || fail "no-clobber collision left published state: $path"
done
assert_no_transaction_residue "$no_clobber_pki/intermediate-ca"

for missing_db_rollback_case in failure TERM; do
  missing_db_rollback_namespace="$TMP_DIR/missing-db-publication-$missing_db_rollback_case"
  init_namespace "$missing_db_rollback_namespace"
  create_root "$missing_db_rollback_namespace"
  missing_db_rollback_pki="$missing_db_rollback_namespace/pki"
  rm "$missing_db_rollback_pki/intermediate-ca/index.txt" \
    "$missing_db_rollback_pki/intermediate-ca/index.txt.attr" \
    "$missing_db_rollback_pki/intermediate-ca/serial" \
    "$missing_db_rollback_pki/intermediate-ca/crlnumber"
  MISSING_DB_ROOT_INDEX_HASH=$(file_hash "$missing_db_rollback_pki/root-ca/index.txt")
  MISSING_DB_ROOT_SERIAL_HASH=$(file_hash "$missing_db_rollback_pki/root-ca/serial")
  MISSING_DB_ROOT_NEWCERTS=$(find "$missing_db_rollback_pki/root-ca/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
  if [[ $missing_db_rollback_case == failure ]]; then
    run_command env PATH="$EXEC_DIR/publication-bin:$PATH" \
      REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" \
      MV_COUNTER="$TMP_DIR/missing-db-failure-mv.counter" MV_FAIL_AT=0 \
      LN_COUNTER="$TMP_DIR/missing-db-failure-ln.counter" LN_FAIL_AT=5 \
      "$TOOL" --namespace "$missing_db_rollback_namespace" \
      --name 'Missing DB Publication Failure' --org Test --country PL \
      --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
    assert_status 1
    assert_contains "$STDERR" 'Intermediate CA material appeared during creation'
  else
    run_command env PATH="$EXEC_DIR/publication-bin:$PATH" \
      REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" \
      MV_COUNTER="$TMP_DIR/missing-db-TERM-mv.counter" MV_FAIL_AT=0 \
      LN_COUNTER="$TMP_DIR/missing-db-TERM-ln.counter" LN_FAIL_AT=0 \
      LN_SIGNAL=TERM LN_SIGNAL_AT=5 \
      "$TOOL" --namespace "$missing_db_rollback_namespace" \
      --name 'Missing DB Publication Signal' --org Test --country PL \
      --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
    assert_status 143
  fi
  assert_missing_db_transaction_rolled_back "$missing_db_rollback_pki"
done

for signal_case in HUP:129 INT:130 TERM:143; do
  signal=${signal_case%%:*}
  expected_status=${signal_case#*:}
  save_state "$encrypted_pki"
  run_command env PATH="$EXEC_DIR/publication-bin:$PATH" REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" \
    MV_COUNTER="$TMP_DIR/mv-$signal.counter" MV_FAIL_AT=0 \
    MV_SIGNAL="$signal" MV_SIGNAL_AT=7 \
    "$TOOL" --namespace "$encrypted_namespace" --name "Signal $signal" \
    --org Test --country PL --root-pass-file "$ROOT_PASS" \
    --intermediate-pass-file "$INT_PASS" --force
  assert_status "$expected_status"
  assert_state_restored "$encrypted_pki"
done

mkdir -p "$EXEC_DIR/pause-bin"
cat >"$EXEC_DIR/pause-bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == genpkey && -n ${OPENSSL_PAUSE_MARKER:-} ]]; then
  : >"$OPENSSL_PAUSE_MARKER"
  while [[ ! -e $OPENSSL_PAUSE_RELEASE ]]; do
    sleep 0.02
  done
fi
exec "$REAL_OPENSSL" "$@"
EOF
chmod 755 "$EXEC_DIR/pause-bin/openssl"
concurrent_namespace="$TMP_DIR/concurrent-root"
init_namespace "$concurrent_namespace"
create_root "$concurrent_namespace"
concurrent_pki="$concurrent_namespace/pki"
concurrent_index_hash=$(file_hash "$concurrent_pki/root-ca/index.txt")
concurrent_serial_hash=$(file_hash "$concurrent_pki/root-ca/serial")
pause_marker="$TMP_DIR/root-pause.marker"
pause_release="$TMP_DIR/root-pause.release"
env PATH="$EXEC_DIR/pause-bin:$PATH" REAL_OPENSSL="$REAL_OPENSSL" \
  OPENSSL_PAUSE_MARKER="$pause_marker" OPENSSL_PAUSE_RELEASE="$pause_release" \
  "$ROOT_TOOL" --namespace "$concurrent_namespace" --name 'Concurrent Root' \
  --org Test --country PL --root-pass-file "$ROOT_PASS" --force \
  >"$TMP_DIR/concurrent-root.stdout" 2>"$TMP_DIR/concurrent-root.stderr" &
root_pid=$!
for _ in {1..250}; do
  [[ ! -e $pause_marker ]] || break
  sleep 0.02
done
if [[ ! -e $pause_marker ]]; then
  : >"$pause_release"
  wait "$root_pid" || true
  fail 'root-create concurrency fixture did not reach the locked operation'
fi
[[ -d $concurrent_pki/root-ca/.platform-pki-root-operation.lock ]] || \
  fail 'root-create did not hold the shared root operation lock'
run_tool "$concurrent_namespace" --name 'Excluded Intermediate' --org Test \
  --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Another root CA operation is in progress'
assert_same_hash "$concurrent_index_hash" "$concurrent_pki/root-ca/index.txt"
assert_same_hash "$concurrent_serial_hash" "$concurrent_pki/root-ca/serial"
[[ ! -e $concurrent_pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'concurrent root operation allowed intermediate material publication'
: >"$pause_release"
wait "$root_pid" || fail 'paused root-create process failed after release'
assert_no_transaction_residue "$concurrent_pki/intermediate-ca"

symlink_namespace="$TMP_DIR/symlink"
init_namespace "$symlink_namespace"
create_root "$symlink_namespace"
symlink_victim="$TMP_DIR/symlink-victim"
printf '%s\n' 'victim' >"$symlink_victim"
ln -s "$symlink_victim" "$symlink_namespace/pki/intermediate-ca/private/intermediate-ca.key"
run_tool "$symlink_namespace" --name Test --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Intermediate CA key must not be a symlink'
[[ $(<"$symlink_victim") == victim ]] || fail 'symlink victim was modified'

ancestor_target="$TMP_DIR/ancestor-target"
init_namespace "$ancestor_target"
create_root "$ancestor_target"
ancestor_alias="$TMP_DIR/ancestor-alias"
ln -s "$ancestor_target" "$ancestor_alias"
ancestor_serial_hash=$(file_hash "$ancestor_target/pki/root-ca/serial")
run_tool "$ancestor_alias" --name Test --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Namespace path component must not be a symlink'
assert_same_hash "$ancestor_serial_hash" "$ancestor_target/pki/root-ca/serial"
[[ ! -e $ancestor_target/pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'ancestor symlink allowed intermediate mutation'

hardlink_namespace="$TMP_DIR/hardlink"
init_namespace "$hardlink_namespace"
create_root "$hardlink_namespace"
hardlink_key="$hardlink_namespace/pki/intermediate-ca/private/intermediate-ca.key"
printf '%s\n' 'hard-link sentinel' >"$hardlink_key"
chmod 600 "$hardlink_key"
ln "$hardlink_key" "$TMP_DIR/intermediate-hardlink-victim"
run_tool "$hardlink_namespace" --name Test --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Intermediate CA key must not be hard-linked'
[[ $(<"$TMP_DIR/intermediate-hardlink-victim") == 'hard-link sentinel' ]] || \
  fail 'hard-link victim was modified'

writable_namespace="$TMP_DIR/writable-directory"
init_namespace "$writable_namespace"
create_root "$writable_namespace"
chmod 777 "$writable_namespace/pki/intermediate-ca/certs"
run_tool "$writable_namespace" --name Test --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Intermediate CA certificate directory is group- or world-writable'
assert_mode 777 "$writable_namespace/pki/intermediate-ca/certs"
[[ ! -e $writable_namespace/pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'unsafe writable directory allowed intermediate mutation'

owner_namespace="$TMP_DIR/foreign-owner"
init_namespace "$owner_namespace"
create_root "$owner_namespace"
owner_target="$owner_namespace/pki/intermediate-ca/index.txt"
owner_hash=$(file_hash "$owner_target")
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
  STAT_OWNER_TARGET="$owner_target" STAT_FAKE_OWNER=$(( $(id -u) + 1 )) \
  "$TOOL" --namespace "$owner_namespace" --name Test --org Test --country PL \
  --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Intermediate CA index is not owned by the current user'
assert_same_hash "$owner_hash" "$owner_target"
[[ ! -e $owner_namespace/pki/intermediate-ca/private/intermediate-ca.key ]] || \
  fail 'foreign-owned database allowed intermediate mutation'

printf '%s\n' 'test-intermediate-create.sh: ok'
