#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-service-issue.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-pki-service-issue-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

INIT_TOOL="$ROOT_DIR/bin/platform-pki-init"
ROOT_TOOL="$ROOT_DIR/bin/platform-pki-root-create"
INT_TOOL="$ROOT_DIR/bin/platform-pki-intermediate-create"
TOOL="$ROOT_DIR/bin/platform-pki-service-issue"
VERSION=$(<"$ROOT_DIR/VERSION")
ROOT_PASS="$TMP_DIR/root.pass"
INT_PASS="$TMP_DIR/intermediate.pass"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0
printf '%s\n' 'root-test-passphrase-123' >"$ROOT_PASS"
printf '%s\n' 'intermediate-test-passphrase-123' >"$INT_PASS"
chmod 600 "$ROOT_PASS" "$INT_PASS"

fail() {
  printf 'test-service-issue.sh: %s\n' "$*" >&2
  exit 1
}

run_command() {
  set +e
  "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

assert_status() {
  [[ $STATUS -eq $1 ]] || fail "expected status $1, got $STATUS; stdout=$(<"$STDOUT"); stderr=$(<"$STDERR")"
}

assert_contains() {
  grep -Fq -- "$2" "$1" || fail "expected '$2' in $(<"$1")"
}

assert_empty() {
  [[ ! -s $1 ]] || fail "expected empty output: $(<"$1")"
}

assert_not_contains() {
  if grep -Fq -- "$2" "$1"; then
    fail "did not expect '$2' in $(<"$1")"
  fi
}

file_hash() {
  local value
  value=$(sha256sum "$1")
  printf '%s\n' "${value%% *}"
}

assert_mode() {
  local actual
  actual=$(stat -c '%a' "$2")
  [[ $actual == "$1" ]] || fail "expected mode $1 for $2, got $actual"
}

assert_no_residue() {
  local pki=$1
  [[ -f $pki/locks/root && -f $pki/locks/intermediate && -f $pki/locks/inventory ]] || fail 'stable lock files are missing'
  if compgen -G "$pki/authorities/intermediates/g1-i1/.platform-pki-service-issue.*" >/dev/null; then
    fail 'service issue staging remained'
  fi
}

assert_no_inventory_temp() {
  if compgen -G "$1/platform-pki-service-issue.*" >/dev/null; then
    fail "inventory staging remained in $1"
  fi
}

replace_config_line() {
  local path=$1 prefix=$2 replacement=$3 line replaced=false tmp
  tmp="${path}.replacement"

  : >"$tmp"
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$prefix"* ]]; then
      printf '%s\n' "$replacement" >>"$tmp"
      replaced=true
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$path"
  [[ $replaced == true ]] || fail "config fixture did not find $prefix"
  chmod 600 "$tmp"
  mv "$tmp" "$path"
}

insert_config_after() {
  local path=$1 prefix=$2 insertion=$3 line inserted=false tmp
  tmp="${path}.insertion"

  : >"$tmp"
  while IFS= read -r line || [[ -n $line ]]; do
    printf '%s\n' "$line" >>"$tmp"
    if [[ $line == "$prefix"* ]]; then
      printf '%s\n' "$insertion" >>"$tmp"
      inserted=true
    fi
  done <"$path"
  [[ $inserted == true ]] || fail "config fixture did not find $prefix"
  chmod 600 "$tmp"
  mv "$tmp" "$path"
}

write_inventory() {
  local pki=$1
  cat >"$pki/inventory/services.yml" <<'EOF'
services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
      - app
    ips:
      - 192.0.2.10
    days: 35
  rotate:
    common_name: rotate.example.internal
    dns:
      - rotate.example.internal
    ips:
      - 192.0.2.11
  failure:
    common_name: failure.example.internal
    dns:
      - failure.example.internal
    ips:
      - 192.0.2.12
EOF
  chmod 600 "$pki/inventory/services.yml"
}

create_ca() {
  local namespace=$1
  run_command "$INIT_TOOL" --namespace "$namespace"
  assert_status 0
  write_inventory "$namespace/pki"
  run_command "$ROOT_TOOL" --namespace "$namespace" --name 'Test Root CA' \
    --org 'Platform Test' --country PL --root-pass-file "$ROOT_PASS"
  assert_status 0
  run_command "$INT_TOOL" --namespace "$namespace" --name 'Test Intermediate CA' \
    --org 'Platform Test' --country PL --root-pass-file "$ROOT_PASS" \
    --intermediate-pass-file "$INT_PASS"
  assert_status 0
}

run_command "$TOOL" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-service-issue --version | -v'
assert_contains "$STDOUT" '--rotate-key'
assert_empty "$STDERR"

run_command "$TOOL" --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-service-issue $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_command "$TOOL" --unknown
assert_status 1
assert_contains "$STDERR" 'invalid option: --unknown'
run_command "$TOOL"
assert_status 1
assert_contains "$STDERR" 'missing required argument: SERVICE'
run_command "$TOOL" app --days nope
assert_status 1
assert_contains "$STDERR" 'Days value must be numeric: nope'
run_command "$TOOL" app --days=
assert_status 1
assert_contains "$STDERR" 'invalid option: --days='

for help_flag in --help -h; do
  run_command "$TOOL" app "$help_flag"
  assert_status 0
  assert_contains "$STDOUT" 'Usage:'
  assert_empty "$STDERR"
done
run_command "$TOOL" app --namespace --help
assert_status 1
assert_empty "$STDOUT"
run_command "$TOOL" app --unknown --help
assert_status 1
assert_empty "$STDOUT"
run_command "$TOOL" app --days= --help
assert_status 1
assert_empty "$STDOUT"

temp_cli_dir="$TMP_DIR/inventory-temp-cli"
mkdir -m 700 "$temp_cli_dir"
run_command env TMPDIR="$temp_cli_dir" "$TOOL" unknown --pki-dir "$TMP_DIR/missing-pki"
assert_status 1
assert_no_inventory_temp "$temp_cli_dir"

namespace="$TMP_DIR/primary"
create_ca "$namespace"
pki="$namespace/pki"
run_command "$TOOL" failure --namespace "$namespace" --days 5000 --intermediate-pass-file "$INT_PASS"
assert_status 1; assert_contains "$STDERR" 'exceeds issuer validity safety margin'
[[ ! -e $pki/services/failure/certs/tls.crt ]] || fail 'validity rejection published service certificate'
run_command "$TOOL" app --namespace "$namespace" --intermediate-pass-file "$INT_PASS"
assert_status 0
assert_contains "$STDOUT" '[OK] Verified service certificate: app'
assert_contains "$STDOUT" "[OK] Issued service certificate: $pki/services/app/certs/tls.crt"
key="$pki/services/app/private/tls.key"
cert="$pki/services/app/certs/tls.crt"
csr="$pki/services/app/csr/tls.csr"
chain="$pki/services/app/chain/ca-chain.crt"
fullchain="$pki/services/app/chain/fullchain.crt"
conf="$pki/services/app/openssl.cnf"
for path in "$key" "$cert" "$csr" "$chain" "$fullchain" "$conf"; do
  [[ -f $path ]] || fail "missing issued artifact: $path"
done
assert_mode 600 "$key"
assert_mode 600 "$csr"
assert_mode 600 "$conf"
assert_mode 644 "$cert"
assert_mode 644 "$chain"
assert_mode 644 "$fullchain"
openssl verify -CAfile "$pki/authorities/roots/g1/certs/root-ca.crt" \
  -untrusted "$pki/authorities/intermediates/g1-i1/certs/intermediate-ca.crt" "$cert" >/dev/null || \
  fail 'real issued certificate did not verify'
openssl x509 -in "$cert" -checkend $((34 * 86400)) -noout >/dev/null || fail 'inventory lifetime was too short'
if openssl x509 -in "$cert" -checkend $((36 * 86400)) -noout >/dev/null; then
  fail 'inventory lifetime was too long'
fi
[[ $(<"$pki/authorities/intermediates/g1-i1/serial") == 1001 ]] || fail 'intermediate serial did not advance'
[[ $(wc -l <"$pki/authorities/intermediates/g1-i1/index.txt") -eq 1 ]] || fail 'intermediate index did not advance once'
[[ -f $pki/authorities/intermediates/g1-i1/newcerts/1000.pem ]] || fail 'intermediate newcert was not published'
assert_no_residue "$pki"

key_hash=$(file_hash "$key")
cert_hash=$(file_hash "$cert")
index_hash=$(file_hash "$pki/authorities/intermediates/g1-i1/index.txt")
serial_hash=$(file_hash "$pki/authorities/intermediates/g1-i1/serial")
run_command "$TOOL" app --namespace "$namespace" --intermediate-pass-file "$INT_PASS" --rotate-key
assert_status 1
assert_contains "$STDERR" 'Service certificate already exists; use platform-pki-service-renew'
[[ $(file_hash "$key") == "$key_hash" ]] || fail 'existing-certificate refusal replaced key'
[[ $(file_hash "$cert") == "$cert_hash" ]] || fail 'existing-certificate refusal replaced certificate'
[[ $(file_hash "$pki/authorities/intermediates/g1-i1/index.txt") == "$index_hash" ]] || fail 'existing-certificate refusal changed index'
[[ $(file_hash "$pki/authorities/intermediates/g1-i1/serial") == "$serial_hash" ]] || fail 'existing-certificate refusal changed serial'

mkdir -m 700 "$pki/services/rotate" "$pki/services/rotate/private"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
  -out "$pki/services/rotate/private/tls.key" >/dev/null 2>&1
chmod 600 "$pki/services/rotate/private/tls.key"
old_rotate_hash=$(file_hash "$pki/services/rotate/private/tls.key")
run_command "$TOOL" rotate --namespace "$namespace" --days 31 \
  --intermediate-pass-file "$INT_PASS"
assert_status 0
[[ $(file_hash "$pki/services/rotate/private/tls.key") == "$old_rotate_hash" ]] || fail 'default issuance did not reuse key'

rm "$pki/services/rotate/certs/tls.crt" "$pki/services/rotate/csr/tls.csr" \
  "$pki/services/rotate/chain/ca-chain.crt" "$pki/services/rotate/chain/fullchain.crt" \
  "$pki/services/rotate/openssl.cnf" "$pki/services/rotate/issuer"
# Reset only the service boundary in this disposable namespace to exercise rotation.
run_command "$TOOL" rotate --namespace "$namespace" --days 31 --rotate-key \
  --intermediate-pass-file "$INT_PASS"
assert_status 0
[[ $(file_hash "$pki/services/rotate/private/tls.key") != "$old_rotate_hash" ]] || fail '--rotate-key did not replace key'
archive_key=$(compgen -G "$pki/services/rotate/archive/*/tls.key")
[[ -f $archive_key ]] || fail 'rotated key was not archived'
[[ $(file_hash "$archive_key") == "$old_rotate_hash" ]] || fail 'archive did not preserve old key'

rollback_namespace="$TMP_DIR/rollback"
create_ca "$rollback_namespace"
rollback_pki="$rollback_namespace/pki"
rollback_index_hash=$(file_hash "$rollback_pki/authorities/intermediates/g1-i1/index.txt")
rollback_serial_hash=$(file_hash "$rollback_pki/authorities/intermediates/g1-i1/serial")
rollback_newcerts=$(find "$rollback_pki/authorities/intermediates/g1-i1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort)
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
  "$TOOL" failure --namespace "$rollback_namespace" --intermediate-pass-file "$INT_PASS"
assert_status 42
[[ ! -e $rollback_pki/services/failure ]] || fail 'signing failure left service state'
[[ $(file_hash "$rollback_pki/authorities/intermediates/g1-i1/index.txt") == "$rollback_index_hash" ]] || fail 'signing failure changed index'
[[ $(file_hash "$rollback_pki/authorities/intermediates/g1-i1/serial") == "$rollback_serial_hash" ]] || fail 'signing failure changed serial'
[[ $(find "$rollback_pki/authorities/intermediates/g1-i1/newcerts" -maxdepth 1 -type f -printf '%f\n' | sort) == "$rollback_newcerts" ]] || fail 'signing failure changed newcerts'
assert_no_residue "$rollback_pki"

for config_case in include database-escape randfile-escape; do
  config_namespace="$TMP_DIR/config-$config_case"
  create_ca "$config_namespace"
  config_pki="$config_namespace/pki"
  config_path="$config_pki/authorities/intermediates/g1-i1/openssl.cnf"
  case $config_case in
    include)
      printf '%s\n' '.include /tmp/external-openssl.cnf' >>"$config_path"
      expected_config_error='must not contain include directives'
      ;;
    database-escape)
      # shellcheck disable=SC2016 # Literal OpenSSL variable expansion syntax.
      replace_config_line "$config_path" 'database =' 'database = $dir/../../external-index.txt'
      expected_config_error="signing path 'database' escapes"
      ;;
    randfile-escape)
      insert_config_after "$config_path" 'dir =' 'RANDFILE = /tmp/external-random-state'
      expected_config_error="signing path 'RANDFILE' escapes"
      ;;
  esac
  config_index_hash=$(file_hash "$config_pki/authorities/intermediates/g1-i1/index.txt")
  config_serial_hash=$(file_hash "$config_pki/authorities/intermediates/g1-i1/serial")
  run_command "$TOOL" failure --namespace "$config_namespace" \
    --intermediate-pass-file "$INT_PASS"
  assert_status 1
  assert_contains "$STDERR" "$expected_config_error"
  [[ $(file_hash "$config_pki/authorities/intermediates/g1-i1/index.txt") == "$config_index_hash" ]] || fail "$config_case changed index"
  [[ $(file_hash "$config_pki/authorities/intermediates/g1-i1/serial") == "$config_serial_hash" ]] || fail "$config_case changed serial"
  [[ ! -e $config_pki/services/failure ]] || fail "$config_case created service state"
  [[ ! -e $config_pki/authorities/roots/g1/.platform-pki-root-operation.lock ]] || fail "$config_case acquired root lock"
  assert_no_residue "$config_pki"
done

inventory_parent_namespace="$TMP_DIR/inventory-parent-symlink"
create_ca "$inventory_parent_namespace"
inventory_parent_pki="$inventory_parent_namespace/pki"
mv "$inventory_parent_pki/inventory" "$inventory_parent_namespace/inventory-real"
ln -s "$inventory_parent_namespace/inventory-real" "$inventory_parent_pki/inventory"
inventory_parent_serial_hash=$(file_hash "$inventory_parent_pki/authorities/intermediates/g1-i1/serial")
run_command "$TOOL" failure --namespace "$inventory_parent_namespace" \
  --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Service inventory ancestor must be a non-symlink directory'
[[ $(file_hash "$inventory_parent_pki/authorities/intermediates/g1-i1/serial") == "$inventory_parent_serial_hash" ]] || fail 'inventory-parent symlink changed serial'
[[ ! -e $inventory_parent_pki/authorities/roots/g1/.platform-pki-root-operation.lock ]] || fail 'inventory-parent symlink acquired root lock'

serial_success_namespace="$TMP_DIR/serial-lowercase"
create_ca "$serial_success_namespace"
serial_success_pki="$serial_success_namespace/pki"
serial_temp_dir="$TMP_DIR/inventory-temp-success"
mkdir -m 700 "$serial_temp_dir"
printf '%s\n' abcd >"$serial_success_pki/authorities/intermediates/g1-i1/serial"
run_command env TMPDIR="$serial_temp_dir" "$TOOL" failure --namespace "$serial_success_namespace" \
  --intermediate-pass-file "$INT_PASS"
assert_status 0
assert_no_inventory_temp "$serial_temp_dir"
[[ $(<"$serial_success_pki/authorities/intermediates/g1-i1/serial") == ABCE ]] || fail 'lowercase serial did not advance canonically'
[[ -f $serial_success_pki/authorities/intermediates/g1-i1/newcerts/ABCD.pem ]] || fail 'lowercase serial did not publish canonical newcert name'

serial_collision_namespace="$TMP_DIR/serial-leading-zero-collision"
create_ca "$serial_collision_namespace"
serial_collision_pki="$serial_collision_namespace/pki"
printf '%s\n' 00ab >"$serial_collision_pki/authorities/intermediates/g1-i1/serial"
printf '%s\n' sentinel >"$serial_collision_pki/authorities/intermediates/g1-i1/newcerts/AB.pem"
chmod 600 "$serial_collision_pki/authorities/intermediates/g1-i1/newcerts/AB.pem"
serial_collision_hash=$(file_hash "$serial_collision_pki/authorities/intermediates/g1-i1/newcerts/AB.pem")
run_command "$TOOL" failure --namespace "$serial_collision_namespace" \
  --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Intermediate CA issued-certificate destination already exists'
[[ $(file_hash "$serial_collision_pki/authorities/intermediates/g1-i1/newcerts/AB.pem") == "$serial_collision_hash" ]] || fail 'canonical serial collision replaced existing newcert'
[[ ! -e $serial_collision_pki/services/failure ]] || fail 'canonical serial collision created service state'

verify_namespace="$TMP_DIR/verify-failure"
create_ca "$verify_namespace"
verify_pki="$verify_namespace/pki"
mkdir -m 700 "$verify_pki/services/failure" "$verify_pki/services/failure/private"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
  -out "$verify_pki/services/failure/private/tls.key" >/dev/null 2>&1
chmod 600 "$verify_pki/services/failure/private/tls.key"
verify_key_hash=$(file_hash "$verify_pki/services/failure/private/tls.key")
verify_index_hash=$(file_hash "$verify_pki/authorities/intermediates/g1-i1/index.txt")
verify_serial_hash=$(file_hash "$verify_pki/authorities/intermediates/g1-i1/serial")
mkdir -p "$EXEC_DIR/verify-lib"
cat >"$EXEC_DIR/verify-lib/platform-pki-common.sh" <<'EOF'
#!/usr/bin/env bash
source "$REAL_COMMON"
pki_verify_service_certificate() { exit 43; }
EOF
run_command env REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" \
  PLATFORM_TOOLS_LIB_DIR="$EXEC_DIR/verify-lib" "$TOOL" failure \
  --namespace "$verify_namespace" --intermediate-pass-file "$INT_PASS" --rotate-key
assert_status 43
[[ $(file_hash "$verify_pki/services/failure/private/tls.key") == "$verify_key_hash" ]] || fail 'verification failure did not restore rotated key'
[[ ! -e $verify_pki/services/failure/certs/tls.crt ]] || fail 'verification failure left certificate state'
[[ ! -e $verify_pki/services/failure/archive ]] || fail 'verification failure left rotated-key archive state'
[[ $(file_hash "$verify_pki/authorities/intermediates/g1-i1/index.txt") == "$verify_index_hash" ]] || fail 'verification failure changed index'
[[ $(file_hash "$verify_pki/authorities/intermediates/g1-i1/serial") == "$verify_serial_hash" ]] || fail 'verification failure changed serial'
assert_no_residue "$verify_pki"

mkdir -p "$EXEC_DIR/publication-bin"
REAL_MV=$(command -v mv)
cat >"$EXEC_DIR/publication-bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f $MV_COUNTER ]] || count=$(<"$MV_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" >"$MV_COUNTER"
if [[ -n ${MV_SIGNAL:-} && $count == "$MV_TRIGGER_AT" ]]; then
  kill "-$MV_SIGNAL" "$PPID"
  exit 143
fi
[[ $count != "$MV_TRIGGER_AT" ]] || exit 42
exec "$REAL_MV" "$@"
EOF
chmod 755 "$EXEC_DIR/publication-bin/mv"
for publication_case in failure:1 HUP:129 TERM:143; do
  case_name=${publication_case%%:*}
  expected_status=${publication_case#*:}
  publication_namespace="$TMP_DIR/publication-$case_name"
  create_ca "$publication_namespace"
  publication_pki="$publication_namespace/pki"
  publication_index_hash=$(file_hash "$publication_pki/authorities/intermediates/g1-i1/index.txt")
  publication_serial_hash=$(file_hash "$publication_pki/authorities/intermediates/g1-i1/serial")
  publication_temp_dir="$TMP_DIR/inventory-temp-$case_name"
  mkdir -m 700 "$publication_temp_dir"
  signal_value=''
  [[ $case_name == failure ]] || signal_value=$case_name
  run_command env PATH="$EXEC_DIR/publication-bin:$PATH" REAL_MV="$REAL_MV" \
    MV_COUNTER="$TMP_DIR/mv-$case_name.counter" MV_TRIGGER_AT=3 MV_SIGNAL="$signal_value" \
    TMPDIR="$publication_temp_dir" \
    "$TOOL" failure --namespace "$publication_namespace" \
    --intermediate-pass-file "$INT_PASS"
  assert_status "$expected_status"
  [[ ! -e $publication_pki/services/failure ]] || fail "$case_name publication left service state"
  [[ $(file_hash "$publication_pki/authorities/intermediates/g1-i1/index.txt") == "$publication_index_hash" ]] || fail "$case_name publication changed index"
  [[ $(file_hash "$publication_pki/authorities/intermediates/g1-i1/serial") == "$publication_serial_hash" ]] || fail "$case_name publication changed serial"
  assert_no_residue "$publication_pki"
  assert_no_inventory_temp "$publication_temp_dir"
done

mkdir -p "$EXEC_DIR/race-bin"
cat >"$EXEC_DIR/race-bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f $RACE_COUNTER ]] || count=$(<"$RACE_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" >"$RACE_COUNTER"
"$REAL_MV" "$@"
if [[ $count == 1 ]]; then
  foreign="${RACE_TARGET}.foreign"
  printf '%s\n' "$RACE_SENTINEL" >"$foreign"
  chmod 600 "$foreign"
  "$REAL_MV" -f -- "$foreign" "$RACE_TARGET"
fi
EOF
chmod 755 "$EXEC_DIR/race-bin/mv"
for race_case in absent inode; do
  race_namespace="$TMP_DIR/race-$race_case"
  create_ca "$race_namespace"
  race_pki="$race_namespace/pki"
  if [[ $race_case == inode ]]; then
    mkdir -m 700 "$race_pki/services/failure" "$race_pki/services/failure/csr"
    printf '%s\n' original >"$race_pki/services/failure/csr/tls.csr"
    chmod 600 "$race_pki/services/failure/csr/tls.csr"
    race_target="$race_pki/services/failure/csr/tls.csr"
    expected_race_error='identity changed after validation'
  else
    race_target="$race_pki/services/failure/certs/tls.crt"
    expected_race_error='appeared after validation'
  fi
  race_sentinel="foreign-$race_case-publication-race"
  run_command env PATH="$EXEC_DIR/race-bin:$PATH" REAL_MV="$REAL_MV" \
    RACE_COUNTER="$TMP_DIR/race-$race_case.counter" RACE_TARGET="$race_target" \
    RACE_SENTINEL="$race_sentinel" "$TOOL" failure \
    --namespace "$race_namespace" --intermediate-pass-file "$INT_PASS"
  assert_status 1
  assert_contains "$STDERR" "$expected_race_error"
  [[ $(<"$race_target") == "$race_sentinel" ]] || fail "$race_case publication race did not preserve foreign state"
  [[ ! -e $race_pki/services/failure/openssl.cnf ]] || fail "$race_case publication race did not roll back prior publication"
  assert_no_residue "$race_pki"
done

cat >"$EXEC_DIR/race-bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f $RACE_COUNTER ]] || count=$(<"$RACE_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" >"$RACE_COUNTER"
[[ $count != 2 ]] || exit 42
"$REAL_MV" "$@"
if [[ $count == 1 ]]; then
  destination=${!#}
  foreign="${destination}.foreign"
  printf '%s\n' "$RACE_SENTINEL" >"$foreign"
  chmod 600 "$foreign"
  "$REAL_MV" -f -- "$foreign" "$destination"
fi
EOF
recovery_namespace="$TMP_DIR/race-recovery"
create_ca "$recovery_namespace"
recovery_pki="$recovery_namespace/pki"
recovery_temp_dir="$TMP_DIR/inventory-temp-recovery"
mkdir -m 700 "$recovery_temp_dir"
run_command env PATH="$EXEC_DIR/race-bin:$PATH" REAL_MV="$REAL_MV" \
  RACE_COUNTER="$TMP_DIR/race-recovery.counter" RACE_SENTINEL='foreign-published-replacement' \
  TMPDIR="$recovery_temp_dir" "$TOOL" failure --namespace "$recovery_namespace" \
  --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Published issuance destination identity changed'
assert_contains "$STDERR" 'preserved staging and locks for recovery'
[[ $(<"$recovery_pki/services/failure/openssl.cnf") == 'foreign-published-replacement' ]] || fail 'recovery race did not preserve foreign replacement'
[[ -f $recovery_pki/locks/root ]] || fail 'recovery race lost stable root lock file'
[[ -f $recovery_pki/locks/intermediate ]] || fail 'recovery race lost stable intermediate lock file'
recovery_stage=$(compgen -G "$recovery_pki/authorities/intermediates/g1-i1/.platform-pki-service-issue.??????")
[[ -n $recovery_stage && -d $recovery_stage ]] || fail 'recovery race did not retain staging'
assert_no_inventory_temp "$recovery_temp_dir"

archive_failure_namespace="$TMP_DIR/archive-failure"
create_ca "$archive_failure_namespace"
archive_failure_pki="$archive_failure_namespace/pki"
mkdir -m 700 "$archive_failure_pki/services/failure" "$archive_failure_pki/services/failure/private"
archive_failure_key="$archive_failure_pki/services/failure/private/tls.key"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
  -out "$archive_failure_key" >/dev/null 2>&1
chmod 600 "$archive_failure_key"
archive_failure_hash=$(file_hash "$archive_failure_key")
archive_failure_metadata=$(stat -c '%a:%Y' "$archive_failure_key")
mkdir -p "$EXEC_DIR/archive-bin"
REAL_LN=$(command -v ln)
cat >"$EXEC_DIR/archive-bin/ln" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
destination=${!#}
[[ $destination != */archive/*/tls.key ]] || exit 42
exec "$REAL_LN" "$@"
EOF
chmod 755 "$EXEC_DIR/archive-bin/ln"
run_command env PATH="$EXEC_DIR/archive-bin:$PATH" REAL_LN="$REAL_LN" \
  "$TOOL" failure --namespace "$archive_failure_namespace" --rotate-key \
  --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_not_contains "$STDERR" 'Archived previous service private key'
[[ $(file_hash "$archive_failure_key") == "$archive_failure_hash" ]] || fail 'archive publication failure did not restore key content'
[[ $(stat -c '%a:%Y' "$archive_failure_key") == "$archive_failure_metadata" ]] || fail 'archive publication failure did not restore key metadata'
[[ ! -e $archive_failure_pki/services/failure/archive ]] || fail 'archive publication failure left archive directories'
[[ ! -e $archive_failure_pki/services/failure/certs/tls.crt ]] || fail 'archive publication failure left certificate'
assert_no_residue "$archive_failure_pki"

for unsafe_case in symlink hardlink mode type inventory; do
  unsafe_namespace="$TMP_DIR/unsafe-$unsafe_case"
  create_ca "$unsafe_namespace"
  unsafe_pki="$unsafe_namespace/pki"
  case $unsafe_case in
    symlink)
      mkdir -p "$unsafe_pki/services/failure/private"
      chmod 700 "$unsafe_pki/services/failure" "$unsafe_pki/services/failure/private"
      ln -s "$TMP_DIR/symlink-victim" "$unsafe_pki/services/failure/private/tls.key"
      expected='Service private key must not be a symlink'
      ;;
    hardlink)
      mkdir -p "$unsafe_pki/services/failure/private"
      chmod 700 "$unsafe_pki/services/failure" "$unsafe_pki/services/failure/private"
      printf '%s\n' sentinel >"$unsafe_pki/services/failure/private/tls.key"
      chmod 600 "$unsafe_pki/services/failure/private/tls.key"
      ln "$unsafe_pki/services/failure/private/tls.key" "$TMP_DIR/hardlink-victim"
      expected='Service private key must not be hard-linked'
      ;;
    mode)
      chmod 777 "$unsafe_pki/authorities/intermediates/g1-i1/newcerts"
      expected='Intermediate CA new-certificates directory is group- or world-writable'
      ;;
    type)
      mkdir -p "$unsafe_pki/services/failure/certs/tls.crt"
      chmod 700 "$unsafe_pki/services/failure" "$unsafe_pki/services/failure/certs" \
        "$unsafe_pki/services/failure/certs/tls.crt"
      expected='Service certificate must be a regular file'
      ;;
    inventory)
      cat >"$unsafe_pki/inventory/services.yml" <<'EOF'
services:
  failure:
    common_name: $ENV::SECRET
    dns:
      - failure.example.internal
    ips:
      - 192.0.2.12
EOF
      chmod 600 "$unsafe_pki/inventory/services.yml"
      expected='must not contain OpenSSL variable expansion syntax'
      ;;
  esac
  unsafe_serial_hash=$(file_hash "$unsafe_pki/authorities/intermediates/g1-i1/serial")
  run_command "$TOOL" failure --namespace "$unsafe_namespace" --intermediate-pass-file "$INT_PASS"
  assert_status 1
  assert_contains "$STDERR" "$expected"
  [[ $(file_hash "$unsafe_pki/authorities/intermediates/g1-i1/serial") == "$unsafe_serial_hash" ]] || fail "$unsafe_case validation changed CA state"
  [[ ! -e $unsafe_pki/authorities/roots/g1/.platform-pki-root-operation.lock ]] || fail "$unsafe_case validation acquired root lock"
done

owner_namespace="$TMP_DIR/unsafe-owner"
create_ca "$owner_namespace"
owner_pki="$owner_namespace/pki"
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
  STAT_OWNER_TARGET="$owner_pki/authorities/intermediates/g1-i1/index.txt" \
  STAT_FAKE_OWNER=$(( $(id -u) + 1 )) "$TOOL" failure \
  --namespace "$owner_namespace" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Intermediate CA index is not owned by the current user'
[[ ! -e $owner_pki/authorities/roots/g1/.platform-pki-root-operation.lock ]] || fail 'owner validation acquired root lock'

lock_namespace="$TMP_DIR/lock"
create_ca "$lock_namespace"
lock_pki="$lock_namespace/pki"
lock_fixture="$lock_pki/locks/intermediate"
exec {lock_fd}<>"$lock_fixture"
flock -n "$lock_fd"
run_command "$TOOL" failure --namespace "$lock_namespace" --intermediate-pass-file "$INT_PASS"
assert_status 1
assert_contains "$STDERR" 'Another intermediate CA operation is in progress'
[[ -f $lock_fixture ]] || fail 'contended stable lock file was removed'
flock -u "$lock_fd"; exec {lock_fd}>&-

mkdir -p "$EXEC_DIR/pause-bin"
cat >"$EXEC_DIR/pause-bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == ca && -n ${OPENSSL_PAUSE_MARKER:-} ]]; then
  : >"$OPENSSL_PAUSE_MARKER"
  while [[ ! -e $OPENSSL_PAUSE_RELEASE ]]; do sleep 0.02; done
fi
exec "$REAL_OPENSSL" "$@"
EOF
chmod 755 "$EXEC_DIR/pause-bin/openssl"
isolation_namespace="$TMP_DIR/isolation"
create_ca "$isolation_namespace"
isolation_pki="$isolation_namespace/pki"
pause_marker="$TMP_DIR/pause.marker"
pause_release="$TMP_DIR/pause.release"
env PATH="$EXEC_DIR/pause-bin:$PATH" REAL_OPENSSL="$REAL_OPENSSL" \
  OPENSSL_PAUSE_MARKER="$pause_marker" OPENSSL_PAUSE_RELEASE="$pause_release" \
  "$TOOL" failure --namespace "$isolation_namespace" \
  --intermediate-pass-file "$INT_PASS" >"$TMP_DIR/pause.stdout" 2>"$TMP_DIR/pause.stderr" &
issue_pid=$!
for _ in {1..250}; do
  [[ ! -e $pause_marker ]] || break
  sleep 0.02
done
if [[ ! -e $pause_marker ]]; then
  : >"$pause_release"
  wait "$issue_pid" || true
  fail 'issuance isolation fixture did not pause under locks'
fi
if flock -n "$isolation_pki/locks/root" true; then fail 'issuance did not hold root lock'; fi
if flock -n "$isolation_pki/locks/intermediate" true; then fail 'issuance did not hold intermediate lock'; fi
run_command "$INT_TOOL" --namespace "$isolation_namespace" --name Replacement \
  --org Test --country PL --root-pass-file "$ROOT_PASS" \
  --intermediate-pass-file "$INT_PASS" --force
assert_status 1
assert_contains "$STDERR" 'Another PKI lifecycle operation is in progress'
: >"$pause_release"
wait "$issue_pid" || fail 'paused real issuance failed after release'
assert_no_residue "$isolation_pki"

printf '%s\n' 'test-service-issue.sh: ok'
