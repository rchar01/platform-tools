#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-vm-env-collect"
SOURCE="$ROOT_DIR/bashly/platform-vm-env-collect/src/root_command.sh"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-vm-env-collect-cli.sh: %s\n' "$*" >&2
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

run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Environment Variables:'
assert_contains "$STDOUT" 'INCLUDE_SENSITIVE'
assert_contains "$STDOUT" 'COLLECT_ENV'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-vm-env-collect $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

set +e
INCLUDE_SENSITIVE=2 "$TOOL" >"$STDOUT" 2>"$STDERR"
STATUS=$?
set -e
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'INCLUDE_SENSITIVE environment variable must be one of: 0, 1'

set +e
COLLECT_ENV=yes "$TOOL" >"$STDOUT" 2>"$STDERR"
STATUS=$?
set -e
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'COLLECT_ENV environment variable must be one of: 0, 1'

grep -Fq 'SCRIPT_VERSION="1.1.0"' "$SOURCE" || fail 'report format version changed'

printf '%s\n' 'test-vm-env-collect-cli.sh: ok'
