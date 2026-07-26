#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-print-cert.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-pki-print-cert"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-print-cert.sh: %s\n' "$*" >&2
  exit 1
}

run_tool() {
  set +e
  "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
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

mkdir -p "$TMP_DIR/fake-bin" "$TMP_DIR/pki/inventory" \
  "$TMP_DIR/pki/services/platform-example/certs"
cat >"$TMP_DIR/pki/inventory/services.yml" <<'EOF'
services:
  platform-example:
    common_name: platform.example.internal
EOF
: >"$TMP_DIR/pki/services/platform-example/certs/tls.crt"

cat >"$TMP_DIR/fake-bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$OPENSSL_LOG"
case $* in
  *'-ext subjectAltName') printf '%s\n' 'X509v3 Subject Alternative Name:' '    DNS:platform.example.internal' ;;
  *'-ext extendedKeyUsage') printf '%s\n' 'X509v3 Extended Key Usage:' '    TLS Web Server Authentication' ;;
  *'-ext keyUsage') printf '%s\n' 'X509v3 Key Usage:' '    Digital Signature' ;;
  *) printf '%s\n' \
    'subject=CN=platform.example.internal' \
    'issuer=CN=Platform Intermediate CA' \
    'serial=1000' \
    'notBefore=Jul 26 00:00:00 2026 GMT' \
    'notAfter=Jul 26 00:00:00 2027 GMT' \
    'sha256 Fingerprint=AA:BB:CC' ;;
esac
EOF
chmod 755 "$TMP_DIR/fake-bin/openssl"

run_tool "$TOOL" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-print-cert --version | -v'
assert_empty "$STDERR"

run_tool "$TOOL" --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-print-cert $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool "$TOOL" --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_tool "$TOOL"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'missing required argument: SERVICE'

run_tool "$TOOL" platform-example extra
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid argument: extra'

mkdir -p "$TMP_DIR/missing-inventory"
run_tool env PATH="$TMP_DIR/fake-bin:$PATH" \
  OPENSSL_LOG="$TMP_DIR/missing-inventory-openssl.log" \
  "$TOOL" platform-example --pki-dir "$TMP_DIR/missing-inventory"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Service inventory is missing or unreadable:'
[[ ! -e $TMP_DIR/missing-inventory-openssl.log ]] || fail 'missing inventory invoked openssl'

run_tool env PATH="$TMP_DIR/fake-bin:$PATH" \
  OPENSSL_LOG="$TMP_DIR/unknown-service-openssl.log" \
  "$TOOL" unknown-service --pki-dir "$TMP_DIR/pki"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Service is not defined in'
[[ ! -e $TMP_DIR/unknown-service-openssl.log ]] || fail 'unknown service invoked openssl'

mkdir -p "$TMP_DIR/missing-cert/inventory"
cat >"$TMP_DIR/missing-cert/inventory/services.yml" <<'EOF'
services:
  platform-example:
    common_name: platform.example.internal
EOF
run_tool env PATH="$TMP_DIR/fake-bin:$PATH" \
  OPENSSL_LOG="$TMP_DIR/missing-cert-openssl.log" \
  "$TOOL" --pki-dir "$TMP_DIR/missing-cert" platform-example
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Required file is missing:'
[[ ! -e $TMP_DIR/missing-cert-openssl.log ]] || fail 'missing certificate invoked openssl'

OPENSSL_LOG="$TMP_DIR/openssl.log" \
  run_tool env PATH="$TMP_DIR/fake-bin:$PATH" OPENSSL_LOG="$TMP_DIR/openssl.log" \
  "$TOOL" --pki-dir "$TMP_DIR/pki" platform-example
assert_status 0
assert_empty "$STDERR"
assert_contains "$STDOUT" 'Service: platform-example'
assert_contains "$STDOUT" 'subject=CN=platform.example.internal'
assert_contains "$STDOUT" 'DNS:platform.example.internal'
assert_contains "$STDOUT" 'Digital Signature'
assert_contains "$STDOUT" 'TLS Web Server Authentication'
[[ $(wc -l <"$TMP_DIR/openssl.log") -eq 4 ]] || fail 'expected four openssl calls'

mkdir -p "$TMP_DIR/explicit/bin" "$TMP_DIR/explicit/lib"
cp "$TOOL" "$TMP_DIR/explicit/bin/"
cp "$ROOT_DIR/lib/platform-pki-common.sh" "$TMP_DIR/explicit/lib/"
run_tool env PATH="$TMP_DIR/fake-bin:$PATH" \
  OPENSSL_LOG="$TMP_DIR/explicit-openssl.log" \
  PLATFORM_TOOLS_LIB_DIR="$TMP_DIR/explicit/lib" \
  "$TMP_DIR/explicit/bin/platform-pki-print-cert" \
  platform-example --pki-dir="$TMP_DIR/pki"
assert_status 0
assert_empty "$STDERR"

mkdir -p "$TMP_DIR/installed/bin" "$TMP_DIR/installed/share/lib"
cp "$TOOL" "$TMP_DIR/installed/bin/"
cp "$ROOT_DIR/lib/platform-pki-common.sh" "$TMP_DIR/installed/share/lib/"
run_tool env PATH="$TMP_DIR/fake-bin:$PATH" \
  OPENSSL_LOG="$TMP_DIR/installed-openssl.log" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/installed/share" \
  "$TMP_DIR/installed/bin/platform-pki-print-cert" \
  --pki-dir "$TMP_DIR/pki" platform-example
assert_status 0
assert_empty "$STDERR"

mkdir -p "$TMP_DIR/isolated/bin" "$TMP_DIR/isolated/home"
cp "$TOOL" "$TMP_DIR/isolated/bin/"
run_tool env HOME="$TMP_DIR/isolated/home" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/isolated/missing" \
  "$TMP_DIR/isolated/bin/platform-pki-print-cert" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_empty "$STDERR"

run_tool env HOME="$TMP_DIR/isolated/home" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/isolated/missing" \
  "$TMP_DIR/isolated/bin/platform-pki-print-cert" \
  platform-example --pki-dir "$TMP_DIR/pki"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'platform-pki-common.sh not found'

printf '%s\n' 'test-print-cert.sh: ok'
