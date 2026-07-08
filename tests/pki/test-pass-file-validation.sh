#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

COMMON_LIB="$ROOT_DIR/lib/platform-pki-common.sh"

run_validator() {
  bash -c 'source "$1"; pki_require_pass_file "$2"' _ "$COMMON_LIB" "$1"
}

expect_rejects() {
  local file=$1
  local expected=$2
  local error_out="$TMP_DIR/error.txt"

  if run_validator "$file" >"$error_out" 2>&1; then
    printf '%s\n' "expected passphrase file to be rejected: $file" >&2
    exit 1
  fi
  if ! grep -q "$expected" "$error_out"; then
    printf '%s\n' "expected rejection to mention: $expected" >&2
    printf '%s\n' "actual error:" >&2
    cat "$error_out" >&2
    exit 1
  fi
}

empty_first_line="$TMP_DIR/empty-first-line.pass"
printf '\nthis-second-line-is-long-enough\n' >"$empty_first_line"
chmod 600 "$empty_first_line"
expect_rejects "$empty_first_line" 'first line is empty'

whitespace_only="$TMP_DIR/whitespace-only.pass"
printf '                \n' >"$whitespace_only"
chmod 600 "$whitespace_only"
expect_rejects "$whitespace_only" 'non-whitespace characters'

short_pass="$TMP_DIR/short.pass"
printf 'short-pass\n' >"$short_pass"
chmod 600 "$short_pass"
expect_rejects "$short_pass" 'at least 16 characters'

open_mode="$TMP_DIR/open-mode.pass"
printf 'valid-passphrase-123\n' >"$open_mode"
chmod 644 "$open_mode"
expect_rejects "$open_mode" 'permissions are too open'

valid_pass="$TMP_DIR/valid.pass"
printf 'valid-passphrase-123\n' >"$valid_pass"
chmod 600 "$valid_pass"
run_validator "$valid_pass"

valid_no_newline="$TMP_DIR/valid-no-newline.pass"
printf 'valid-passphrase-456' >"$valid_no_newline"
chmod 600 "$valid_no_newline"
run_validator "$valid_no_newline"

printf '%s\n' 'test-pass-file-validation.sh: ok'
