#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-list-expiry.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-pki-list-expiry"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-list-expiry.sh: %s\n' "$*" >&2
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

create_inventory() {
  local pki_dir=$1 service=$2
  mkdir -p "$pki_dir/inventory" "$pki_dir/root-ca" "$pki_dir/intermediate-ca"
  printf 'services:\n  %s:\n    common_name: %s.example.internal\n    dns:\n      - %s.example.internal\n' \
    "$service" "$service" "$service" >"$pki_dir/inventory/services.yml"
  chmod 600 "$pki_dir/inventory/services.yml"
}

create_certificate() {
  local pki_dir=$1 service=$2 days=$3
  mkdir -p "$pki_dir/services/$service/certs"
  openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
    -subj "/CN=$service.example.internal" \
    -keyout "$TMP_DIR/$service.key" \
    -out "$pki_dir/services/$service/certs/tls.crt" >/dev/null 2>&1
}

run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-list-expiry --version | -v'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-list-expiry $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_tool --warn-days nope
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Days value must be numeric: nope'

run_tool --critical-days 0
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Days value must be at least 1: 0'

run_tool --pki-dir "$TMP_DIR/does-not-exist"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory does not exist'

create_inventory "$TMP_DIR/ok" ok-service
create_certificate "$TMP_DIR/ok" ok-service 120
run_tool --pki-dir "$TMP_DIR/ok" --warn-days 90 --critical-days 30
assert_status 0
assert_empty "$STDERR"
assert_contains "$STDOUT" 'SERVICE'
assert_contains "$STDOUT" 'ok-service'
assert_contains "$STDOUT" 'OK'

create_inventory "$TMP_DIR/warn" warn-service
create_certificate "$TMP_DIR/warn" warn-service 60
run_tool --warn-days=90 --pki-dir="$TMP_DIR/warn" --critical-days=30
assert_status 1
assert_empty "$STDERR"
assert_contains "$STDOUT" 'warn-service'
assert_contains "$STDOUT" 'WARN'

create_inventory "$TMP_DIR/critical" critical-service
create_certificate "$TMP_DIR/critical" critical-service 10
run_tool --critical-days 30 --pki-dir "$TMP_DIR/critical" --warn-days 90
assert_status 2
assert_empty "$STDERR"
assert_contains "$STDOUT" 'critical-service'
assert_contains "$STDOUT" 'CRITICAL'

create_inventory "$TMP_DIR/missing" missing-service
run_tool --pki-dir "$TMP_DIR/missing"
assert_status 3
assert_empty "$STDERR"
assert_contains "$STDOUT" 'missing-service'
assert_contains "$STDOUT" 'MISSING'

mkdir -p "$TMP_DIR/fake-lib"
cat >"$TMP_DIR/fake-lib/platform-pki-common.sh" <<'EOF'
# shellcheck source=../../../lib/platform-pki-common.sh
source "$REAL_COMMON"

pki_cert_days_left() {
  case $1 in
    *critical-boundary*) printf '%s\n' '30' ;;
    *warn-boundary*) printf '%s\n' '90' ;;
    *) printf '%s\n' '120' ;;
  esac
}

pki_cert_not_after_iso() {
  printf '%s\n' '2027-07-26T00:00:00Z'
}
EOF

create_mixed_inventory() {
  local pki_dir=$1 first=$2 second=$3
  mkdir -p "$pki_dir/inventory" \
    "$pki_dir/root-ca" "$pki_dir/intermediate-ca" \
    "$pki_dir/services/critical-boundary/certs" \
    "$pki_dir/services/warn-boundary/certs"
  printf 'services:\n  %s:\n    common_name: %s.example.internal\n    dns:\n      - %s.example.internal\n  warn-boundary:\n    common_name: warn.example.internal\n    dns:\n      - warn.example.internal\n  %s:\n    common_name: %s.example.internal\n    dns:\n      - %s.example.internal\n' \
    "$first" "$first" "$first" "$second" "$second" "$second" >"$pki_dir/inventory/services.yml"
  chmod 600 "$pki_dir/inventory/services.yml"
  : >"$pki_dir/services/critical-boundary/certs/tls.crt"
  : >"$pki_dir/services/warn-boundary/certs/tls.crt"
}

create_mixed_inventory "$TMP_DIR/mixed-missing-first" \
  missing-service critical-boundary
run_command env REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" \
  PLATFORM_TOOLS_LIB_DIR="$TMP_DIR/fake-lib" \
  "$TOOL" --pki-dir "$TMP_DIR/mixed-missing-first" \
  --warn-days 90 --critical-days 30
assert_status 3
assert_empty "$STDERR"
assert_contains "$STDOUT" 'critical-boundary'
assert_contains "$STDOUT" 'CRITICAL'
assert_contains "$STDOUT" 'warn-boundary'
assert_contains "$STDOUT" 'WARN'
assert_contains "$STDOUT" 'missing-service'
assert_contains "$STDOUT" 'MISSING'

create_mixed_inventory "$TMP_DIR/mixed-missing-last" \
  critical-boundary missing-service
run_command env REAL_COMMON="$ROOT_DIR/lib/platform-pki-common.sh" \
  PLATFORM_TOOLS_LIB_DIR="$TMP_DIR/fake-lib" \
  "$TOOL" --pki-dir "$TMP_DIR/mixed-missing-last" \
  --warn-days 90 --critical-days 30
assert_status 3
assert_empty "$STDERR"

mkdir -p "$TMP_DIR/installed/bin" "$TMP_DIR/installed/share/lib"
cp "$TOOL" "$TMP_DIR/installed/bin/"
cp "$ROOT_DIR/lib/platform-pki-common.sh" "$TMP_DIR/installed/share/lib/"
run_command env PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/installed/share" \
  "$TMP_DIR/installed/bin/platform-pki-list-expiry" \
  --pki-dir "$TMP_DIR/ok"
assert_status 0
assert_empty "$STDERR"
assert_contains "$STDOUT" 'ok-service'

mkdir -p "$TMP_DIR/isolated/bin" "$TMP_DIR/isolated/home"
cp "$TOOL" "$TMP_DIR/isolated/bin/"
run_command env HOME="$TMP_DIR/isolated/home" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/isolated/missing" \
  "$TMP_DIR/isolated/bin/platform-pki-list-expiry" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_empty "$STDERR"

run_command env HOME="$TMP_DIR/isolated/home" \
  PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/isolated/missing" \
  "$TMP_DIR/isolated/bin/platform-pki-list-expiry" \
  --pki-dir "$TMP_DIR/ok"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'platform-pki-common.sh not found'

printf '%s\n' 'test-list-expiry.sh: ok'
