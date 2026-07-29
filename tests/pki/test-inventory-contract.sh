#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
COMMON="$ROOT_DIR/lib/platform-pki-common.sh"

validate() {
  bash -c 'source "$1"; pki_validate_inventory_file "$2" "$3"' _ "$COMMON" "$1" "$TMP_DIR/canonical"
}

expect_reject() {
  local name=$1 content=$2
  printf '%s' "$content" >"$TMP_DIR/$name.yml"
  if validate "$TMP_DIR/$name.yml" >"$TMP_DIR/out" 2>"$TMP_DIR/err"; then
    printf 'test-inventory-contract.sh: accepted invalid fixture %s\n' "$name" >&2
    exit 1
  fi
}

cat >"$TMP_DIR/valid.yml" <<'EOF'
---
# order is intentionally non-canonical
services:
  api-1:
    ips:
      - '192.0.2.10'
    days: 1
    common_name: "api.example.internal"
  dns_only:
    common_name: dns.example.internal
    dns:
      - dns.example.internal
EOF
validate "$TMP_DIR/valid.yml"
grep -Fq $'api-1\tcommon_name\tapi.example.internal' "$TMP_DIR/canonical"
grep -Fq $'dns_only\tdns\tdns.example.internal' "$TMP_DIR/canonical"

for consumer in \
  platform-pki-service-issue platform-pki-service-renew \
  platform-pki-service-verify platform-pki-list-expiry \
  platform-pki-print-cert platform-pki-export-ansible; do
  count=$(grep -c 'pki_load_inventory_snapshot' "$ROOT_DIR/bashly/$consumer/src/root_command.sh")
  [[ $count -eq 1 ]] || {
    printf 'test-inventory-contract.sh: %s loads %s inventory snapshots\n' "$consumer" "$count" >&2
    exit 1
  }
done

expect_reject no_services $'services:\n'
expect_reject duplicate_service $'services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n'
expect_reject duplicate_field $'services:\n  api:\n    common_name: api.example\n    common_name: other.example\n    dns:\n      - api.example\n'
expect_reject duplicate_san $'services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n      - api.example\n'
expect_reject unknown_field $'services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n    deploy: host\n'
expect_reject bad_indent $'services:\n api:\n    common_name: api.example\n    dns:\n      - api.example\n'
expect_reject tab $'services:\n  api:\n\tcommon_name: api.example\n'
expect_reject inline_comment $'services:\n  api:\n    common_name: api.example # no\n    dns:\n      - api.example\n'
expect_reject empty_list $'services:\n  api:\n    common_name: api.example\n    dns:\n'
expect_reject no_san $'services:\n  api:\n    common_name: api.example\n'
expect_reject bad_ip $'services:\n  api:\n    common_name: api.example\n    ips:\n      - 999.0.2.1\n'
expect_reject duplicate_document $'---\n---\nservices:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n'
expect_reject trailing $'services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\nother:\n'

for location in key scalar list comment structure; do
  case $location in
    key) printf 'serv\0ices:\n' >"$TMP_DIR/nul-$location.yml" ;;
    scalar) printf 'services:\n  api:\n    common_name: api\0.example\n    dns:\n      - api.example\n' >"$TMP_DIR/nul-$location.yml" ;;
    list) printf 'services:\n  api:\n    common_name: api.example\n    dns:\n      - api\0.example\n' >"$TMP_DIR/nul-$location.yml" ;;
    comment) printf '# comment\0hidden\nservices:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n' >"$TMP_DIR/nul-$location.yml" ;;
    structure) printf 'services:\0\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n' >"$TMP_DIR/nul-$location.yml" ;;
  esac
  if validate "$TMP_DIR/nul-$location.yml" >"$TMP_DIR/out" 2>"$TMP_DIR/err"; then
    fail_location=$location
    printf 'test-inventory-contract.sh: accepted NUL fixture %s\n' "$fail_location" >&2
    exit 1
  fi
done

printf '%s\n' 'test-inventory-contract.sh: ok'
