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
RECOVER_TOOL="$ROOT_DIR/bin/platform-pki-ca-rollover"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0
ROOT_PASS="$TMP_DIR/root.pass"
INT_PASS="$TMP_DIR/intermediate.pass"
ROOT_DB_KEYS=(index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert)
ROOT_DB_OPTIONAL_KEYS=(index_old index_attr_old serial_old crlnumber_old)
declare -A ROOT_DB_FILES=(
  [index]=index.txt [index_attr]=index.txt.attr [serial]=serial [crlnumber]=crlnumber
  [index_old]=index.txt.old [index_attr_old]=index.txt.attr.old [serial_old]=serial.old [crlnumber_old]=crlnumber.old
)
printf '%s\n' 'root-test-passphrase-123' >"$ROOT_PASS"
printf '%s\n' 'intermediate-test-passphrase-123' >"$INT_PASS"
chmod 600 "$ROOT_PASS" "$INT_PASS"

fail() {
  printf 'test-intermediate-create.sh: %s; stderr=%s\n' "$*" "$(<"$STDERR")" >&2
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
  local ca_dir=$1 pki=${1%/authorities/intermediates/g1-i1}
  if compgen -G "$ca_dir/.platform-pki-intermediate-create.*" >/dev/null; then
    fail "intermediate transaction left staging or lock state in $ca_dir"
  fi
  [[ ! -e $pki/authorities/roots/g1/.platform-pki-root-operation.lock ]] || \
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

prepare_complete_root_db_fixture() {
  local namespace=$1 key root="$1/pki/authorities/roots/g1"
  for key in "${ROOT_DB_OPTIONAL_KEYS[@]}"; do
    printf 'pre-transaction-%s\n' "$key" >"$root/${ROOT_DB_FILES[$key]}"
    chmod 600 "$root/${ROOT_DB_FILES[$key]}"
  done
  cp -p "$root/certs/root-ca.crt" "$root/newcerts/0ABC.pem"
}

snapshot_root_db_state() {
  local pki=$1 output=$2 root="$1/authorities/roots/g1" key path name metadata digest
  : >"$output"
  for key in "${ROOT_DB_KEYS[@]}"; do
    [[ $key != newcert ]] || continue
    path="$root/${ROOT_DB_FILES[$key]}"
    if [[ ! -e $path && ! -L $path ]]; then printf 'db|%s|absent\n' "$key" >>"$output"; continue; fi
    [[ -f $path && ! -L $path ]] || fail "root DB snapshot found unsafe state: $path"
    metadata=$(stat -c '%u|%a|%h|%s|%F' "$path"); digest=$(file_hash "$path")
    printf 'db|%s|present|%s|%s\n' "$key" "$metadata" "$digest" >>"$output"
  done
  metadata=$(stat -c '%u|%a|%h|%F' "$root/newcerts")
  printf 'newcerts-dir|%s\n' "$metadata" >>"$output"
  while IFS= read -r -d '' name; do
    path="$root/newcerts/$name"
    [[ -f $path && ! -L $path ]] || fail "root newcert snapshot found unsafe state: $path"
    metadata=$(stat -c '%u|%a|%h|%s|%F' "$path"); digest=$(file_hash "$path")
    printf 'newcert|%s|%s|%s\n' "$name" "$metadata" "$digest" >>"$output"
  done < <(find "$root/newcerts" -mindepth 1 -maxdepth 1 -printf '%f\0' | LC_ALL=C sort -z)
}

assert_root_db_state_restored() {
  local pki=$1 journal=$2 expected=$3 actual="$3.actual" root="$1/authorities/roots/g1" key path current post issued_serial
  snapshot_root_db_state "$pki" "$actual"
  cmp -s "$expected" "$actual" || fail "root CA database/newcert state did not match its pre-transaction snapshot: $(diff -u "$expected" "$actual")"
  issued_serial=$(sed -n 's/^issued_serial=//p' "$journal")
  for key in "${ROOT_DB_KEYS[@]}"; do
    if [[ $key == newcert ]]; then path="$root/newcerts/$issued_serial.pem"
    else path="$root/${ROOT_DB_FILES[$key]}"; fi
    if [[ ! -e $path && ! -L $path ]]; then current=absent
    else current=$(stat -c '%d:%i:%u:%a:%h:%s:%F' "$path"); fi
    post=$(sed -n "s/^root_${key}_post_identity=//p" "$journal")
    [[ -n $post && $current != "$post" ]] || fail "rollback retained the transaction-published root $key identity"
  done
}

save_state() {
  local pki=$1 path
  SAVED_PATHS=(
    "$pki/authorities/intermediates/g1-i1/openssl.cnf"
    "$pki/authorities/intermediates/g1-i1/private/intermediate-ca.key"
    "$pki/authorities/intermediates/g1-i1/csr/intermediate-ca.csr"
    "$pki/authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
    "$pki/authorities/intermediates/g1-i1/certs/ca-chain.crt"
    "$pki/authorities/roots/g1/index.txt" "$pki/authorities/roots/g1/index.txt.attr" "$pki/authorities/roots/g1/serial"
    "$pki/authorities/roots/g1/index.txt.old" "$pki/authorities/roots/g1/index.txt.attr.old" "$pki/authorities/roots/g1/serial.old"
  )
  SAVED_HASHES=()
  for path in "${SAVED_PATHS[@]}"; do
    SAVED_HASHES+=("$(file_hash "$path")")
  done
  SAVED_NEWCERTS=$(find "$pki/authorities/roots/g1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
}

assert_state_restored() {
  local pki=$1 i
  for i in "${!SAVED_PATHS[@]}"; do
    assert_same_hash "${SAVED_HASHES[i]}" "${SAVED_PATHS[i]}"
  done
  [[ $(find "$pki/authorities/roots/g1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$SAVED_NEWCERTS" ]] || \
    fail 'root newcerts changed after failed replacement'
  assert_no_transaction_residue "$pki/authorities/intermediates/g1-i1"
}

assert_intermediate_db_defaults() {
  local pki=$1 db="$1/authorities/intermediates/g1-i1"

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
    [[ ! -e $pki/authorities/intermediates/g1-i1/$file ]] || \
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
  assert_same_hash "$MISSING_DB_ROOT_INDEX_HASH" "$pki/authorities/roots/g1/index.txt"
  assert_same_hash "$MISSING_DB_ROOT_SERIAL_HASH" "$pki/authorities/roots/g1/serial"
  [[ $(find "$pki/authorities/roots/g1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$MISSING_DB_ROOT_NEWCERTS" ]] || \
    fail 'failed missing-database transaction changed root newcerts'
  assert_no_transaction_residue "$pki/authorities/intermediates/g1-i1"
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
run_tool "$missing_root_namespace" --name Test --org Test --country PL --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" "Bootstrap root manifest is missing"

validity_namespace="$TMP_DIR/validity-margin"; init_namespace "$validity_namespace"
run_command "$ROOT_TOOL" --namespace "$validity_namespace" --name 'Short Root' --org Test --country PL --days 2 --root-pass-file "$ROOT_PASS"; assert_status 0
run_tool "$validity_namespace" --name 'Too Long Intermediate' --org Test --country PL --days 2 --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"
assert_status 1; assert_contains "$STDERR" 'exceeds issuer validity safety margin'
[[ ! -e $validity_namespace/pki/authorities/intermediates/g1-i1 && -f $validity_namespace/pki/state/bootstrap-root ]] || fail 'validity rejection published intermediate state'

namespace="$TMP_DIR/primary"
init_namespace "$namespace"
create_root "$namespace"
create_intermediate "$namespace" --days 5
pki="$namespace/pki"
int_key="$pki/authorities/intermediates/g1-i1/private/intermediate-ca.key"
int_cert="$pki/authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
root_cert="$pki/authorities/roots/g1/certs/root-ca.crt"
assert_mode 600 "$int_key"
assert_mode 644 "$int_cert"
openssl verify -CAfile "$root_cert" "$int_cert" >/dev/null || fail "intermediate did not verify"
[[ $(<"$pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "active issuer manifest is invalid"
[[ ! -e $pki/state/bootstrap-root ]] || fail "bootstrap manifest remained"
run_tool "$namespace" --name Replacement --org Test --country PL --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" "active issuer exists"

mkdir -p "$EXEC_DIR/complete-root-db"
REAL_OPENSSL=$(command -v openssl)
cat >"$EXEC_DIR/complete-root-db/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != ca ]]; then exec "$REAL_OPENSSL" "$@"; fi
"$REAL_OPENSSL" "$@"
config=''; previous=''
for argument in "$@"; do
  if [[ $previous == -config ]]; then config=$argument; break; fi
  previous=$argument
done
[[ -n $config ]] || exit 0
ca_dir=''
while IFS= read -r line; do
  if [[ $line == 'dir = '* ]]; then ca_dir=${line#dir = }; break; fi
done <"$config"
[[ -n $ca_dir ]] || exit 0
for file in index.txt.old index.txt.attr.old serial.old crlnumber.old; do
  printf 'post-signing-%s\n' "$file" >"$ca_dir/$file"
  chmod 600 "$ca_dir/$file"
done
EOF
chmod 755 "$EXEC_DIR/complete-root-db/openssl"

bootstrap_seed="$TMP_DIR/bootstrap-seed"; init_namespace "$bootstrap_seed"; create_root "$bootstrap_seed"
for boundary in after-journal after-reservation after-intermediate after-root-db after-reservation-consumed after-active after-bootstrap; do
  fault_namespace="$TMP_DIR/fault-$boundary"; cp -a "$bootstrap_seed" "$fault_namespace"; fault_pki="$fault_namespace/pki"
  root_index_hash=$(file_hash "$fault_pki/authorities/roots/g1/index.txt"); root_serial_hash=$(file_hash "$fault_pki/authorities/roots/g1/serial"); root_newcerts=$(find "$fault_pki/authorities/roots/g1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
  run_command env PLATFORM_PKI_INTERMEDIATE_FAIL_AT="$boundary" "$TOOL" --namespace "$fault_namespace" \
    --name 'Fault Intermediate' --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
  assert_status 1
  [[ ! -e $fault_pki/authorities/intermediates/g1-i1 && ! -e $fault_pki/state/active-issuer && -f $fault_pki/state/bootstrap-root ]] || fail "intermediate state was not rolled back after $boundary"
  assert_same_hash "$root_index_hash" "$fault_pki/authorities/roots/g1/index.txt"; assert_same_hash "$root_serial_hash" "$fault_pki/authorities/roots/g1/serial"
  [[ $(find "$fault_pki/authorities/roots/g1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$root_newcerts" ]] || fail "root newcerts changed after $boundary"
  grep -Fx 'committed=true' "$fault_pki/state/rollover/journal" >/dev/null || fail "intermediate journal was not closed after $boundary"
  if [[ -e $fault_pki/state/generation-reservations/g1-i1 ]]; then grep -Fx 'status=abandoned' "$fault_pki/state/generation-reservations/g1-i1" >/dev/null || fail "intermediate reservation was not abandoned after $boundary"; fi
done

for key in "${ROOT_DB_KEYS[@]}"; do
  for checkpoint in pending 'done'; do
    crash_namespace="$TMP_DIR/root-publication-$key-$checkpoint"; cp -a "$bootstrap_seed" "$crash_namespace"; crash_pki="$crash_namespace/pki"
    prepare_complete_root_db_fixture "$crash_namespace"
    root_snapshot="$TMP_DIR/root-publication-$key-$checkpoint.snapshot"; snapshot_root_db_state "$crash_pki" "$root_snapshot"
    run_command env PATH="$EXEC_DIR/complete-root-db:$PATH" REAL_OPENSSL="$REAL_OPENSSL" PLATFORM_PKI_INTERMEDIATE_CRASH_AT="root-$key-$checkpoint" "$TOOL" --namespace "$crash_namespace" --name Crash --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
    assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$crash_pki/state/rollover/journal")
    pre_identity=$(sed -n "s/^root_${key}_pre_identity=//p" "$crash_pki/state/rollover/journal"); post_identity=$(sed -n "s/^root_${key}_post_identity=//p" "$crash_pki/state/rollover/journal")
    if [[ $key == newcert ]]; then [[ $pre_identity == absent && $post_identity != absent ]] || fail 'newcert publication fixture did not create a new object'
    else [[ $pre_identity != absent && $post_identity != absent && $pre_identity != "$post_identity" ]] || fail "root DB publication fixture did not mutate $key"; fi
    run_command "$RECOVER_TOOL" recover --namespace "$crash_namespace" --transaction "$transaction" --action rollback --yes; assert_status 0
    assert_root_db_state_restored "$crash_pki" "$crash_pki/state/rollover/journal" "$root_snapshot"
  done
done

for boundary in cleanup-pending cleanup-removed cleanup-done; do
  cleanup_namespace="$TMP_DIR/$boundary"; cp -a "$bootstrap_seed" "$cleanup_namespace"; cleanup_pki="$cleanup_namespace/pki"
  run_command env PLATFORM_PKI_INTERMEDIATE_CRASH_AT="$boundary" "$TOOL" --namespace "$cleanup_namespace" --name Cleanup --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
  assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$cleanup_pki/state/rollover/journal"); sensitive_stage=$(sed -n 's/^root_stage=//p' "$cleanup_pki/state/rollover/journal")
  run_command "$RECOVER_TOOL" recover --namespace "$cleanup_namespace" --transaction "$transaction" --action resume --yes; assert_status 0
  [[ ! -e $sensitive_stage && -f $cleanup_pki/state/active-issuer && ! -e $cleanup_pki/state/bootstrap-root ]] || fail "cleanup resume was incomplete after $boundary"
  grep -Fx 'committed=true' "$cleanup_pki/state/rollover/journal" >/dev/null || fail "cleanup resume did not commit after $boundary"
done

cleanup_recovery_namespace="$TMP_DIR/cleanup-recovery-of-recovery"; cp -a "$bootstrap_seed" "$cleanup_recovery_namespace"; cleanup_recovery_pki="$cleanup_recovery_namespace/pki"
run_command env PLATFORM_PKI_INTERMEDIATE_CRASH_AT=cleanup-pending "$TOOL" --namespace "$cleanup_recovery_namespace" --name Cleanup --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$cleanup_recovery_pki/state/rollover/journal")
for checkpoint in cleanup-pending cleanup-done; do run_command env PLATFORM_PKI_RECOVER_CRASH_AT="$checkpoint" "$RECOVER_TOOL" recover --namespace "$cleanup_recovery_namespace" --transaction "$transaction" --action resume --yes; assert_status 137; done
run_command "$RECOVER_TOOL" recover --namespace "$cleanup_recovery_namespace" --transaction "$transaction" --action resume --yes; assert_status 0

recovery_crash_namespace="$TMP_DIR/recovery-of-recovery"; cp -a "$bootstrap_seed" "$recovery_crash_namespace"; recovery_crash_pki="$recovery_crash_namespace/pki"; prepare_complete_root_db_fixture "$recovery_crash_namespace"
recovery_root_snapshot="$TMP_DIR/recovery-of-recovery.snapshot"; snapshot_root_db_state "$recovery_crash_pki" "$recovery_root_snapshot"
run_command env PATH="$EXEC_DIR/complete-root-db:$PATH" REAL_OPENSSL="$REAL_OPENSSL" PLATFORM_PKI_INTERMEDIATE_CRASH_AT=after-bootstrap "$TOOL" --namespace "$recovery_crash_namespace" --name Crash --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$recovery_crash_pki/state/rollover/journal")
for key in "${ROOT_DB_OPTIONAL_KEYS[@]}"; do
  pre_identity=$(sed -n "s/^root_${key}_pre_identity=//p" "$recovery_crash_pki/state/rollover/journal"); post_identity=$(sed -n "s/^root_${key}_post_identity=//p" "$recovery_crash_pki/state/rollover/journal")
  [[ $pre_identity != absent && $post_identity != absent && $pre_identity != "$post_identity" ]] || fail "optional root DB fixture did not mutate $key"
done
recovery_boundaries=(rollback-active-pending rollback-active-done rollback-bootstrap-pending rollback-bootstrap-done)
for key in "${ROOT_DB_KEYS[@]}"; do recovery_boundaries+=("rollback-root-$key-pending" "rollback-root-$key-done"); done
recovery_boundaries+=(rollback-authority-pending rollback-authority-done rollback-stage-pending rollback-stage-done rollback-reservation-pending rollback-reservation-done)
for recovery_boundary in "${recovery_boundaries[@]}"; do
  run_command env PLATFORM_PKI_RECOVER_CRASH_AT="$recovery_boundary" "$RECOVER_TOOL" recover --namespace "$recovery_crash_namespace" --transaction "$transaction" --action rollback --yes
  assert_status 137
done
run_command "$RECOVER_TOOL" recover --namespace "$recovery_crash_namespace" --transaction "$transaction" --action rollback --yes; assert_status 0
assert_root_db_state_restored "$recovery_crash_pki" "$recovery_crash_pki/state/rollover/journal" "$recovery_root_snapshot"
grep -Fx 'status=abandoned' "$recovery_crash_pki/state/generation-reservations/g1-i1" >/dev/null || fail 'recovery-of-recovery lost the intermediate reservation'

hostile_namespace="$TMP_DIR/hostile-generation"; cp -a "$bootstrap_seed" "$hostile_namespace"; mkdir -m 700 "$TMP_DIR/foreign-intermediate"; ln -s "$TMP_DIR/foreign-intermediate" "$hostile_namespace/pki/authorities/intermediates/g1-i1"
run_tool "$hostile_namespace" --name Hostile --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key --force
assert_status 1; [[ -L $hostile_namespace/pki/authorities/intermediates/g1-i1 && -d $TMP_DIR/foreign-intermediate ]] || fail 'intermediate --force altered hostile generation state'

for boundary in after-journal after-reservation after-intermediate after-root-db after-reservation-consumed after-active after-bootstrap; do
  crash_namespace="$TMP_DIR/crash-recovery-$boundary"; cp -a "$bootstrap_seed" "$crash_namespace"; crash_pki="$crash_namespace/pki"
  root_index_hash=$(file_hash "$crash_pki/authorities/roots/g1/index.txt"); root_serial_hash=$(file_hash "$crash_pki/authorities/roots/g1/serial")
  run_command env PLATFORM_PKI_INTERMEDIATE_CRASH_AT="$boundary" "$TOOL" --namespace "$crash_namespace" --name Crash --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
  assert_status 137; transaction=$(sed -n 's/^transaction=//p' "$crash_pki/state/rollover/journal")
  run_command "$RECOVER_TOOL" recover --namespace "$crash_namespace" --transaction "$transaction" --action rollback --yes; assert_status 0
  assert_same_hash "$root_index_hash" "$crash_pki/authorities/roots/g1/index.txt"; assert_same_hash "$root_serial_hash" "$crash_pki/authorities/roots/g1/serial"
  [[ ! -e $crash_pki/authorities/intermediates/g1-i1 && -f $crash_pki/state/bootstrap-root && -f $crash_pki/state/generation-reservations/g1-i1 ]] || fail "intermediate crash recovery did not preserve its abandoned reservation after $boundary"
  grep -Fx 'status=abandoned' "$crash_pki/state/generation-reservations/g1-i1" >/dev/null || fail "intermediate crash recovery did not abandon g1-i1 after $boundary"
  run_tool "$crash_namespace" --name Retry --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key; assert_status 0
  grep -Fx 'intermediate=g1-i2' "$crash_pki/state/active-issuer" >/dev/null || fail "intermediate crash retry reused g1-i1 after $boundary"
done

for category in index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert; do
  hostile_namespace="$TMP_DIR/hostile-root-db-$category"; cp -a "$bootstrap_seed" "$hostile_namespace"; hostile_pki="$hostile_namespace/pki"
  run_command env PLATFORM_PKI_INTERMEDIATE_CRASH_AT=after-root-db "$TOOL" --namespace "$hostile_namespace" --name Hostile --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key; assert_status 137
  transaction=$(sed -n 's/^transaction=//p' "$hostile_pki/state/rollover/journal"); issued_serial=$(sed -n 's/^issued_serial=//p' "$hostile_pki/state/rollover/journal")
  case $category in
    index) hostile_path="$hostile_pki/authorities/roots/g1/index.txt" ;;
    index_attr) hostile_path="$hostile_pki/authorities/roots/g1/index.txt.attr" ;;
    serial) hostile_path="$hostile_pki/authorities/roots/g1/serial" ;;
    crlnumber) hostile_path="$hostile_pki/authorities/roots/g1/crlnumber" ;;
    index_old) hostile_path="$hostile_pki/authorities/roots/g1/index.txt.old" ;;
    index_attr_old) hostile_path="$hostile_pki/authorities/roots/g1/index.txt.attr.old" ;;
    serial_old) hostile_path="$hostile_pki/authorities/roots/g1/serial.old" ;;
    crlnumber_old) hostile_path="$hostile_pki/authorities/roots/g1/crlnumber.old" ;;
    newcert) hostile_path="$hostile_pki/authorities/roots/g1/newcerts/$issued_serial.pem" ;;
  esac
  rm -f -- "$hostile_path"; printf '%s\n' "hostile-$category" >"$hostile_path"; chmod 600 "$hostile_path"
  run_command "$RECOVER_TOOL" recover --namespace "$hostile_namespace" --transaction "$transaction" --action rollback --yes; assert_status 1
  [[ $(<"$hostile_path") == "hostile-$category" ]] || fail "recovery changed hostile root DB replacement: $category"
done

signal_namespace="$TMP_DIR/signal-recovery"; cp -a "$bootstrap_seed" "$signal_namespace"
run_command env PLATFORM_PKI_INTERMEDIATE_SIGNAL_AT=after-root-db "$TOOL" --namespace "$signal_namespace" --name Signal --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
assert_status 143; [[ ! -e $signal_namespace/pki/authorities/intermediates/g1-i1 && -f $signal_namespace/pki/state/bootstrap-root ]] || fail 'intermediate signal rollback left authority state'

openssl_namespace="$TMP_DIR/openssl-failure"; cp -a "$bootstrap_seed" "$openssl_namespace"; mkdir -p "$EXEC_DIR/intermediate-openssl-failure"
REAL_OPENSSL=$(command -v openssl); printf '%s\n' '#!/usr/bin/env bash' '[[ ${1:-} != ca ]] || exit 42' 'exec "$REAL_OPENSSL" "$@"' >"$EXEC_DIR/intermediate-openssl-failure/openssl"; chmod 755 "$EXEC_DIR/intermediate-openssl-failure/openssl"
run_command env PATH="$EXEC_DIR/intermediate-openssl-failure:$PATH" REAL_OPENSSL="$REAL_OPENSSL" "$TOOL" --namespace "$openssl_namespace" --name Failure --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key
assert_status 42; [[ ! -e $openssl_namespace/pki/authorities/intermediates/g1-i1 && -f $openssl_namespace/pki/state/bootstrap-root ]] || fail 'OpenSSL failure published intermediate state'

lock_namespace="$TMP_DIR/lock-contention"; cp -a "$bootstrap_seed" "$lock_namespace"; : >"$lock_namespace/pki/locks/intermediate"; chmod 600 "$lock_namespace/pki/locks/intermediate"; exec {lock_fd}<>"$lock_namespace/pki/locks/intermediate"; flock -n "$lock_fd"
run_tool "$lock_namespace" --name Locked --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key; assert_status 1; assert_contains "$STDERR" 'Another intermediate CA operation is in progress'; flock -u "$lock_fd"; exec {lock_fd}>&-

for hostile_case in key-symlink db-hardlink writable-dir; do
  hostile_namespace="$TMP_DIR/hostile-$hostile_case"; cp -a "$bootstrap_seed" "$hostile_namespace"; hostile_int="$hostile_namespace/pki/authorities/intermediates/g1-i1"; mkdir -m 700 -p "$hostile_int/private" "$hostile_int/certs"
  case $hostile_case in
    key-symlink) printf '%s\n' victim >"$TMP_DIR/intermediate-victim"; ln -s "$TMP_DIR/intermediate-victim" "$hostile_int/private/intermediate-ca.key" ;;
    db-hardlink) printf '%s\n' sentinel >"$hostile_int/serial"; chmod 600 "$hostile_int/serial"; ln "$hostile_int/serial" "$TMP_DIR/intermediate-hardlink" ;;
    writable-dir) chmod 777 "$hostile_int/certs" ;;
  esac
  run_tool "$hostile_namespace" --name Hostile --org Test --country PL --root-pass-file "$ROOT_PASS" --allow-unencrypted-intermediate-key --force; assert_status 1
  [[ -d $hostile_int && ! -L $hostile_int ]] || fail "hostile intermediate state was deleted: $hostile_case"
done

printf '%s\n' 'test-intermediate-create.sh: ok'
