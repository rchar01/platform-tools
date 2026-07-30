#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-service-renew.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-pki-service-renew-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

INIT_TOOL="$ROOT_DIR/bin/platform-pki-init"
ROOT_TOOL="$ROOT_DIR/bin/platform-pki-root-create"
INT_TOOL="$ROOT_DIR/bin/platform-pki-intermediate-create"
ISSUE_TOOL="$ROOT_DIR/bin/platform-pki-service-issue"
TOOL="$ROOT_DIR/bin/platform-pki-service-renew"
VERSION=$(<"$ROOT_DIR/VERSION")
ROOT_PASS="$TMP_DIR/root.pass"
INT_PASS="$TMP_DIR/intermediate.pass"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0
printf '%s\n' 'root-test-passphrase-123' >"$ROOT_PASS"
printf '%s\n' 'intermediate-test-passphrase-123' >"$INT_PASS"
chmod 600 "$ROOT_PASS" "$INT_PASS"

fail() { printf 'test-service-renew.sh: %s\n' "$*" >&2; exit 1; }
run_command() { set +e; "$@" >"$STDOUT" 2>"$STDERR"; STATUS=$?; set -e; }
assert_status() { [[ $STATUS -eq $1 ]] || fail "expected status $1, got $STATUS; stdout=$(<"$STDOUT"); stderr=$(<"$STDERR")"; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "expected '$2' in $(<"$1")"; }
assert_not_contains() { ! grep -Fq -- "$2" "$1" || fail "did not expect '$2' in $(<"$1")"; }
assert_empty() { [[ ! -s $1 ]] || fail "expected empty output: $(<"$1")"; }
file_hash() { local value; value=$(sha256sum "$1"); printf '%s\n' "${value%% *}"; }
assert_no_residue() {
  local pki=$1
  [[ ! -e $pki/authorities/roots/g1/.platform-pki-root-operation.lock ]] || fail 'root operation lock remained'
  [[ ! -e $pki/authorities/intermediates/g1-i1/.platform-pki-intermediate-operation.lock ]] || fail 'intermediate operation lock remained'
  if compgen -G "$pki/authorities/intermediates/g1-i1/.platform-pki-service-renew.*" >/dev/null; then fail 'renewal staging remained'; fi
}
canonical_serial() {
  local serial=${1^^}
  while [[ $serial == 00* && ${#serial} -gt 2 ]]; do serial=${serial#00}; done
  printf '%s\n' "$serial"
}
record_path() {
  local path=$1 metadata hash
  if [[ -L $path ]]; then
    printf '%s|symlink|%s\n' "$path" "$(readlink "$path")"
  elif [[ -f $path ]]; then
    metadata=$(stat -c '%a:%u:%g:%s:%y' "$path"); hash=$(file_hash "$path")
    printf '%s|file|%s|%s\n' "$path" "$metadata" "$hash"
  elif [[ -d $path ]]; then
    printf '%s|dir|%s\n' "$path" "$(stat -c '%a:%u:%g:%y' "$path")"
  elif [[ -e $path ]]; then
    printf '%s|other|%s\n' "$path" "$(stat -c '%F:%a:%u:%g:%y' "$path")"
  else
    printf '%s|absent\n' "$path"
  fi
}
write_state_manifest() {
  local output=$1 service_dir=$2 pki=$3 newcert=$4 path archive_root
  archive_root="$service_dir/archive"
  : >"$output"
  for path in \
    "$service_dir/private/tls.key" "$service_dir/certs/tls.crt" \
    "$service_dir/csr/tls.csr" "$service_dir/openssl.cnf" \
    "$service_dir/chain/ca-chain.crt" "$service_dir/chain/fullchain.crt" \
    "$pki/authorities/intermediates/g1-i1/index.txt" "$pki/authorities/intermediates/g1-i1/index.txt.attr" \
    "$pki/authorities/intermediates/g1-i1/serial" "$pki/authorities/intermediates/g1-i1/crlnumber" \
    "$pki/authorities/intermediates/g1-i1/index.txt.old" "$pki/authorities/intermediates/g1-i1/index.txt.attr.old" \
    "$pki/authorities/intermediates/g1-i1/serial.old" "$newcert" "$archive_root"; do
    record_path "$path" >>"$output"
  done
  if [[ -d $archive_root ]]; then
    while IFS= read -r path; do record_path "$path" >>"$output"; done < <(find "$archive_root" -mindepth 1 -print | sort)
  fi
}
snapshot_state() {
  write_state_manifest "$TMP_DIR/$1.expected" "$2" "$3" "$4"
}
assert_state_restored() {
  local label=$1 service_dir=$2 pki=$3 newcert=$4
  write_state_manifest "$TMP_DIR/$label.actual" "$service_dir" "$pki" "$newcert"
  cmp -s "$TMP_DIR/$label.expected" "$TMP_DIR/$label.actual" || {
    diff -u "$TMP_DIR/$label.expected" "$TMP_DIR/$label.actual" >&2 || true
    fail "$label did not restore complete service, CA, newcert, and archive state"
  }
}
assert_state_restored_except_config() {
  local label=$1 service_dir=$2 pki=$3 newcert=$4 config
  config="$service_dir/openssl.cnf"
  write_state_manifest "$TMP_DIR/$label.actual" "$service_dir" "$pki" "$newcert"
  grep -Fv -- "$config|" "$TMP_DIR/$label.expected" >"$TMP_DIR/$label.expected-filtered"
  grep -Fv -- "$config|" "$TMP_DIR/$label.actual" >"$TMP_DIR/$label.actual-filtered"
  cmp -s "$TMP_DIR/$label.expected-filtered" "$TMP_DIR/$label.actual-filtered" || {
    diff -u "$TMP_DIR/$label.expected-filtered" "$TMP_DIR/$label.actual-filtered" >&2 || true
    fail "$label changed state outside the preserved foreign configuration"
  }
}
write_inventory() {
  cat >"$1/inventory/services.yml" <<'EOF'
services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
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
  keyonly:
    common_name: keyonly.example.internal
    dns:
      - keyonly.example.internal
EOF
  chmod 600 "$1/inventory/services.yml"
}
create_ca() {
  local namespace=$1
  run_command "$INIT_TOOL" --namespace "$namespace"; assert_status 0
  write_inventory "$namespace/pki"
  run_command "$ROOT_TOOL" --namespace "$namespace" --name 'Test Root CA' --org Test --country PL --root-pass-file "$ROOT_PASS"; assert_status 0
  run_command "$INT_TOOL" --namespace "$namespace" --name 'Test Intermediate CA' --org Test --country PL --root-pass-file "$ROOT_PASS" --intermediate-pass-file "$INT_PASS"; assert_status 0
}
issue_service() {
  run_command "$ISSUE_TOOL" "$2" --namespace "$1" --intermediate-pass-file "$INT_PASS"
  assert_status 0
}

run_command "$TOOL" --help; assert_status 0
assert_contains "$STDOUT" 'platform-pki-service-renew --version | -v'
assert_contains "$STDOUT" '--rotate-key'; assert_empty "$STDERR"
run_command "$TOOL" --version; assert_status 0
[[ $(<"$STDOUT") == "platform-pki-service-renew $VERSION" ]] || fail 'unexpected version output'
run_command "$TOOL"; assert_status 1; assert_contains "$STDERR" 'missing required argument: SERVICE'
run_command "$TOOL" app --days nope; assert_status 1; assert_contains "$STDERR" 'Days value must be numeric: nope'
for help_flag in --help -h; do run_command "$TOOL" app "$help_flag"; assert_status 0; assert_contains "$STDOUT" 'Usage:'; assert_empty "$STDERR"; done
run_command "$TOOL" app --namespace --help; assert_status 1; assert_empty "$STDOUT"

namespace="$TMP_DIR/primary"; create_ca "$namespace"; pki="$namespace/pki"
run_command "$TOOL" app --namespace "$namespace" --intermediate-pass-file "$INT_PASS"
assert_status 1; assert_contains "$STDERR" 'Service private key is missing; use platform-pki-service-issue first'
[[ ! -e $pki/services/app ]] || fail 'missing-state renewal created service state'
issue_service "$namespace" app
key="$pki/services/app/private/tls.key"; cert="$pki/services/app/certs/tls.crt"
old_key_hash=$(file_hash "$key"); old_cert_hash=$(file_hash "$cert"); old_serial=$(openssl x509 -in "$cert" -noout -serial)
run_command "$TOOL" app --namespace "$namespace" --intermediate-pass-file "$INT_PASS"
assert_status 0; assert_contains "$STDOUT" '[OK] Verified service certificate: app'; assert_contains "$STDOUT" '[OK] Renewed service certificate:'
[[ $(file_hash "$key") == "$old_key_hash" ]] || fail 'default renewal did not reuse key'
[[ $(file_hash "$cert") != "$old_cert_hash" ]] || fail 'renewal did not replace certificate'
[[ $(openssl x509 -in "$cert" -noout -serial) != "$old_serial" ]] || fail 'renewal did not issue a new serial'
archive=$(compgen -G "$pki/services/app/archive/*")
for name in tls.crt tls.csr ca-chain.crt fullchain.crt openssl.cnf issuer; do [[ -f $archive/$name ]] || fail "archive missing $name"; done
[[ $(file_hash "$archive/tls.crt") == "$old_cert_hash" ]] || fail 'archive did not preserve previous certificate'
openssl verify -CAfile "$pki/authorities/roots/g1/certs/root-ca.crt" -untrusted "$pki/authorities/intermediates/g1-i1/certs/intermediate-ca.crt" "$cert" >/dev/null || fail 'renewed certificate did not verify'
openssl x509 -in "$cert" -checkend $((34 * 86400)) -noout >/dev/null || fail 'inventory lifetime was too short'
if openssl x509 -in "$cert" -checkend $((36 * 86400)) -noout >/dev/null; then fail 'inventory lifetime was too long'; fi
assert_no_residue "$pki"

issue_service "$namespace" keyonly
keyonly_dir="$pki/services/keyonly"
rm "$keyonly_dir/certs/tls.crt" "$keyonly_dir/csr/tls.csr" "$keyonly_dir/chain/ca-chain.crt" "$keyonly_dir/chain/fullchain.crt" "$keyonly_dir/openssl.cnf"
run_command "$TOOL" keyonly --namespace "$namespace" --intermediate-pass-file "$INT_PASS"
assert_status 0
for source in \
  "$keyonly_dir/certs/tls.crt" "$keyonly_dir/csr/tls.csr" \
  "$keyonly_dir/chain/ca-chain.crt" "$keyonly_dir/chain/fullchain.crt" \
  "$keyonly_dir/openssl.cnf"; do
  assert_not_contains "$STDOUT" "Archived $source to "
done
assert_not_contains "$STDOUT" "Archived $keyonly_dir/private/tls.key to "
keyonly_archive=$(compgen -G "$keyonly_dir/archive/*")
[[ -d $keyonly_archive ]] || fail 'key-only renewal did not create archive directory'
[[ -f $keyonly_archive/issuer ]] || fail 'key-only renewal did not archive its prior issuer record'
[[ $(find "$keyonly_archive" -mindepth 1 -maxdepth 1 -type f | wc -l) -eq 1 ]] || fail 'key-only renewal archived unexpected material'

issue_service "$namespace" rotate
rotate_key="$pki/services/rotate/private/tls.key"; rotate_old_hash=$(file_hash "$rotate_key")
run_command "$TOOL" rotate --namespace "$namespace" --days 31 --rotate-key --intermediate-pass-file "$INT_PASS"
assert_status 0
[[ $(file_hash "$rotate_key") != "$rotate_old_hash" ]] || fail '--rotate-key did not replace key'
rotate_archive_key=$(compgen -G "$pki/services/rotate/archive/*/tls.key")
[[ $(file_hash "$rotate_archive_key") == "$rotate_old_hash" ]] || fail 'rotation archive did not preserve old key'

issue_service "$namespace" failure
failure_dir="$pki/services/failure"; failure_key="$failure_dir/private/tls.key"; failure_cert="$failure_dir/certs/tls.crt"
mkdir -m 700 "$failure_dir/archive"
mkdir -m 700 "$failure_dir/archive/previous"
printf '%s\n' 'existing archive sentinel' >"$failure_dir/archive/previous/sentinel"
chmod 600 "$failure_dir/archive/previous/sentinel"
touch -t 202001020304.05 "$failure_dir/archive/previous/sentinel" "$failure_dir/archive/previous" "$failure_dir/archive"
failure_newcert="$pki/authorities/intermediates/g1-i1/newcerts/$(canonical_serial "$(<"$pki/authorities/intermediates/g1-i1/serial")").pem"
mkdir -p "$EXEC_DIR/failing-bin"; REAL_OPENSSL=$(command -v openssl)
cat >"$EXEC_DIR/failing-bin/openssl" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} != ca ]] || exit 42
exec "$REAL_OPENSSL" "$@"
EOF
chmod 755 "$EXEC_DIR/failing-bin/openssl"
snapshot_state signing-failure "$failure_dir" "$pki" "$failure_newcert"
run_command env PATH="$EXEC_DIR/failing-bin:$PATH" REAL_OPENSSL="$REAL_OPENSSL" "$TOOL" failure --namespace "$namespace" --rotate-key --intermediate-pass-file "$INT_PASS"
assert_status 42; assert_state_restored signing-failure "$failure_dir" "$pki" "$failure_newcert"; assert_no_residue "$pki"

mkdir -p "$EXEC_DIR/verify-lib"
cat >"$EXEC_DIR/verify-lib/platform-pki-common.sh" <<'EOF'
#!/usr/bin/env bash
source "$REAL_COMMON"
pki_verify_service_certificate() { exit 43; }
EOF
snapshot_state verification-failure "$failure_dir" "$pki" "$failure_newcert"
run_command env REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" PLATFORM_TOOLS_LIB_DIR="$EXEC_DIR/verify-lib" "$TOOL" failure --namespace "$namespace" --rotate-key --intermediate-pass-file "$INT_PASS"
assert_status 43; assert_state_restored verification-failure "$failure_dir" "$pki" "$failure_newcert"; assert_no_residue "$pki"

[[ $(<"$pki/services/app/issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "renewal issuer record is invalid"
[[ $(<"$archive/issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "archived issuer record is invalid"

printf '%s\n' 'test-service-renew.sh: ok'
