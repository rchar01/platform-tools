#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-config-init"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-platform-config-init.sh: %s\n' "$*" >&2
  exit 1
}

run_tool() {
  set +e
  "$TOOL" "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

assert_status() {
  [[ $STATUS -eq $1 ]] || fail "expected status $1, got $STATUS"
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

run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-config-init --version | -v'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-config-init $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_tool --config-dir
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" '--config-dir requires an argument'

run_tool --config-dir ''
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'validation error in --config-dir PATH:'
assert_contains "$STDERR" 'must not be empty'

run_tool --config-dir=
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --config-dir='

not_created="$TMP_DIR/help-order"
run_tool --config-dir "$not_created" --help
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --help'
[[ ! -e $not_created ]] || fail 'invalid help ordering executed the command'

custom_dir="$TMP_DIR/custom namespace"
run_tool "--config-dir=$custom_dir"
assert_status 0
assert_empty "$STDERR"
assert_mode 700 "$custom_dir"
assert_mode 700 "$custom_dir/config"
assert_mode 700 "$custom_dir/infra"
assert_mode 700 "$custom_dir/pki"
assert_mode 600 "$custom_dir/README.md"
assert_contains "$custom_dir/README.md" '# Platform Infrastructure Local Config'

printf '%s\n' 'keep this content' >"$custom_dir/README.md"
chmod 644 "$custom_dir/README.md"
chmod 755 "$custom_dir" "$custom_dir/config" "$custom_dir/infra" "$custom_dir/pki"
printf '%s\n' 'legacy content' >"$custom_dir/proxmox.env"
run_tool --config-dir "$custom_dir"
assert_status 0
[[ $(<"$custom_dir/README.md") == 'keep this content' ]] || fail 'existing README.md was overwritten'
assert_mode 600 "$custom_dir/README.md"
assert_mode 700 "$custom_dir"
assert_mode 700 "$custom_dir/config"
assert_mode 700 "$custom_dir/infra"
assert_mode 700 "$custom_dir/pki"
[[ $(<"$custom_dir/proxmox.env") == 'legacy content' ]] || fail 'legacy file was changed'
assert_contains "$STDOUT" '[INFO] Kept existing file:'
assert_contains "$STDERR" '[WARN] Legacy path exists and was left unchanged:'

home_dir="$TMP_DIR/home"
mkdir -p "$home_dir"
set +e
# shellcheck disable=SC2088 # Exercise the tool's literal-tilde expansion.
HOME=$home_dir "$TOOL" --config-dir '~/platform-test' >"$STDOUT" 2>"$STDERR"
STATUS=$?
set -e
assert_status 0
assert_mode 700 "$home_dir/platform-test"

printf '%s\n' 'test-platform-config-init.sh: ok'
