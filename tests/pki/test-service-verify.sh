#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-service-verify.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-pki-service-verify"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-service-verify.sh: %s\n' "$*" >&2
  exit 1
}

run_command() {
  set +e
  "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

run_tool() {
  run_command "$TOOL" "$@"
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

mkdir -p "$TMP_DIR/pki/inventory" \
  "$TMP_DIR/pki/services/platform-example/private" \
  "$TMP_DIR/pki/services/platform-example/certs" \
  "$TMP_DIR/pki/root-ca/certs" \
  "$TMP_DIR/pki/intermediate-ca/certs" \
  "$TMP_DIR/fake-lib" "$TMP_DIR/fake-bin"
cat >"$TMP_DIR/pki/inventory/services.yml" <<'EOF'
services:
  platform-example:
    common_name: platform.example.internal
    dns:
      - platform.example.internal
    ips:
      - 192.0.2.10
EOF
chmod 600 "$TMP_DIR/pki/inventory/services.yml"
touch \
  "$TMP_DIR/pki/services/platform-example/private/tls.key" \
  "$TMP_DIR/pki/services/platform-example/certs/tls.crt" \
  "$TMP_DIR/pki/root-ca/certs/root-ca.crt" \
  "$TMP_DIR/pki/intermediate-ca/certs/intermediate-ca.crt"

cat >"$TMP_DIR/fake-lib/platform-pki-common.sh" <<'EOF'
# shellcheck source=../../../lib/platform-pki-common.sh
source "$REAL_COMMON"

pki_key_matches_cert() { printf '%s\n' key >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != key ]]; }
pki_cert_has_ca_false() { printf '%s\n' ca >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != ca ]]; }
pki_cert_has_server_auth() { printf '%s\n' eku >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != eku ]]; }
pki_cert_has_dns_san() { printf '%s\n' dns >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != dns ]]; }
pki_cert_has_ip_san() { printf '%s\n' ip >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != ip ]]; }
EOF

cat >"$TMP_DIR/fake-bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case $1 in
  verify)
    printf '%s\n' trust >>"$VERIFY_LOG"
    if [[ ${VERIFY_FAILURE:-} == trust ]]; then
      printf '%s\n' 'certificate chain verification failed' >&2
      exit 1
    fi
    ;;
  x509)
    printf '%s\n' lifetime >>"$VERIFY_LOG"
    [[ ${VERIFY_FAILURE:-} != lifetime ]] || exit 1
    ;;
esac
EOF
chmod 755 "$TMP_DIR/fake-bin/openssl"

run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-service-verify --version | -v'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-service-verify $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_tool
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'missing required argument: SERVICE'

run_tool platform-example --min-days nope
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Days value must be numeric: nope'

run_tool 'bad/name' --pki-dir "$TMP_DIR/pki"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Invalid service name: bad/name'

run_verify() {
  local failure=$1
  : >"$TMP_DIR/verify.log"
  run_command env PATH="$TMP_DIR/fake-bin:$PATH" \
    REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" \
    PLATFORM_TOOLS_LIB_DIR="$TMP_DIR/fake-lib" \
    VERIFY_FAILURE="$failure" \
    VERIFY_LOG="$TMP_DIR/verify.log" \
    "$TOOL" platform-example --pki-dir "$TMP_DIR/pki" --min-days 30
}

run_verify none
assert_status 0
assert_empty "$STDERR"
assert_contains "$STDOUT" '[OK] Verified service certificate: platform-example'
[[ $(<"$TMP_DIR/verify.log") == $'trust\nkey\nca\neku\ndns\nip\nlifetime' ]] || \
  fail "unexpected verification order: $(<"$TMP_DIR/verify.log")"

run_verify trust
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'certificate chain verification failed'
[[ $(<"$TMP_DIR/verify.log") == trust ]] || fail 'trust failure did not stop verification'

run_verify key
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Private key does not match certificate'
[[ $(<"$TMP_DIR/verify.log") == $'trust\nkey' ]] || fail 'key failure did not stop verification'

for failure in ca eku dns ip lifetime; do
  run_verify "$failure"
  assert_status 1
  assert_empty "$STDOUT"
  case $failure in
    key) assert_contains "$STDERR" 'Private key does not match certificate' ;;
    ca) assert_contains "$STDERR" 'Certificate is missing CA:false' ;;
    eku) assert_contains "$STDERR" 'Certificate is missing serverAuth EKU' ;;
    dns) assert_contains "$STDERR" "Certificate is missing DNS SAN 'platform.example.internal'" ;;
    ip) assert_contains "$STDERR" "Certificate is missing IP SAN '192.0.2.10'" ;;
    lifetime) assert_contains "$STDERR" 'Certificate has less than 30 days remaining' ;;
  esac
done

: >"$TMP_DIR/verify.log"
run_command env PATH="$TMP_DIR/fake-bin:$PATH" \
  REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" \
  PLATFORM_TOOLS_LIB_DIR="$TMP_DIR/fake-lib" \
  VERIFY_FAILURE=none VERIFY_LOG="$TMP_DIR/verify.log" \
  "$TOOL" unknown-service --pki-dir "$TMP_DIR/pki"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Service is not defined in'
assert_empty "$TMP_DIR/verify.log"

mkdir -p "$TMP_DIR/installed/bin" "$TMP_DIR/installed/share/lib"
cp "$TOOL" "$TMP_DIR/installed/bin/"
cp "$TMP_DIR/fake-lib/platform-pki-common.sh" "$TMP_DIR/installed/share/lib/"
: >"$TMP_DIR/verify.log"
run_command env PATH="$TMP_DIR/fake-bin:$PATH" \
  REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/installed/share" \
  VERIFY_FAILURE=none VERIFY_LOG="$TMP_DIR/verify.log" \
  "$TMP_DIR/installed/bin/platform-pki-service-verify" \
  platform-example --pki-dir "$TMP_DIR/pki"
assert_status 0
assert_empty "$STDERR"
assert_contains "$STDOUT" '[OK] Verified service certificate: platform-example'

mkdir -p "$TMP_DIR/isolated/bin" "$TMP_DIR/isolated/home"
cp "$TOOL" "$TMP_DIR/isolated/bin/"
run_command env HOME="$TMP_DIR/isolated/home" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/isolated/missing" \
  "$TMP_DIR/isolated/bin/platform-pki-service-verify" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_empty "$STDERR"

run_command env HOME="$TMP_DIR/isolated/home" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/isolated/missing" \
  "$TMP_DIR/isolated/bin/platform-pki-service-verify" \
  platform-example --pki-dir "$TMP_DIR/pki"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'platform-pki-common.sh not found'

printf '%s\n' 'test-service-verify.sh: ok'
