#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

COMMON_LIB="$ROOT_DIR/lib/platform-pki-common.sh"

write_values() {
  local file=$1
  shift

  : >"$file"
  for value in "$@"; do
    printf '%s\n' "$value" >>"$file"
  done
}

run_validator() {
  local common_name=$1
  local dns_file=$2
  local ips_file=$3

  bash -c 'source "$1"; pki_validate_service_inventory_values platform-example "$2" "$3" "$4"' _ "$COMMON_LIB" "$common_name" "$dns_file" "$ips_file"
}

expect_rejects() {
  local expected=$1
  local common_name=$2
  local dns_file=$3
  local ips_file=$4
  local error_out="$TMP_DIR/error.txt"

  if run_validator "$common_name" "$dns_file" "$ips_file" >"$error_out" 2>&1; then
    printf '%s\n' "expected inventory values to be rejected" >&2
    exit 1
  fi
  if ! grep -q "$expected" "$error_out"; then
    printf '%s\n' "expected rejection to mention: $expected" >&2
    printf '%s\n' 'actual error:' >&2
    cat "$error_out" >&2
    exit 1
  fi
}

valid_dns="$TMP_DIR/valid-dns.txt"
valid_ips="$TMP_DIR/valid-ips.txt"
write_values "$valid_dns" app.example.internal app
write_values "$valid_ips" 192.0.2.10
run_validator app.example.internal "$valid_dns" "$valid_ips"

# shellcheck disable=SC2016 # Literal OpenSSL config expansion syntax for regression coverage.
env_expansion='$ENV::AWS_SECRET_ACCESS_KEY'

malicious_common_dns="$TMP_DIR/malicious-common-dns.txt"
malicious_common_ips="$TMP_DIR/malicious-common-ips.txt"
write_values "$malicious_common_dns" app.example.internal
write_values "$malicious_common_ips" 192.0.2.10
expect_rejects 'common_name for service platform-example must not contain OpenSSL variable expansion syntax' "$env_expansion" "$malicious_common_dns" "$malicious_common_ips"

malicious_dns="$TMP_DIR/malicious-dns.txt"
malicious_dns_ips="$TMP_DIR/malicious-dns-ips.txt"
write_values "$malicious_dns" "$env_expansion"
write_values "$malicious_dns_ips" 192.0.2.10
expect_rejects 'DNS SAN for service platform-example must not contain OpenSSL variable expansion syntax' app.example.internal "$malicious_dns" "$malicious_dns_ips"

malicious_ip_dns="$TMP_DIR/malicious-ip-dns.txt"
malicious_ip="$TMP_DIR/malicious-ip.txt"
write_values "$malicious_ip_dns" app.example.internal
write_values "$malicious_ip" "$env_expansion"
expect_rejects 'IP SAN for service platform-example must not contain OpenSSL variable expansion syntax' app.example.internal "$malicious_ip_dns" "$malicious_ip"

bad_dns="$TMP_DIR/bad-dns.txt"
bad_dns_ips="$TMP_DIR/bad-dns-ips.txt"
write_values "$bad_dns" 'bad name.example'
write_values "$bad_dns_ips" 192.0.2.10
expect_rejects 'DNS SAN for service platform-example must be a DNS name' app.example.internal "$bad_dns" "$bad_dns_ips"

bad_ip_dns="$TMP_DIR/bad-ip-dns.txt"
bad_ip="$TMP_DIR/bad-ip.txt"
write_values "$bad_ip_dns" app.example.internal
write_values "$bad_ip" 999.0.2.10
expect_rejects 'IP SAN for service platform-example must be a valid IPv4 address' app.example.internal "$bad_ip_dns" "$bad_ip"

bad_ipv6_dns="$TMP_DIR/bad-ipv6-dns.txt"
bad_ipv6="$TMP_DIR/bad-ipv6.txt"
write_values "$bad_ipv6_dns" app.example.internal
write_values "$bad_ipv6" '1:2:3:4:5:6:7:8:9'
expect_rejects 'IP SAN for service platform-example must be a valid IPv4 address' app.example.internal "$bad_ipv6_dns" "$bad_ipv6"

valid_ipv6_dns="$TMP_DIR/valid-ipv6-dns.txt"
valid_ipv6="$TMP_DIR/valid-ipv6.txt"
write_values "$valid_ipv6_dns" app.example.internal
write_values "$valid_ipv6" '2001:db8::1'
expect_rejects 'IP SAN for service platform-example must be a valid IPv4 address' app.example.internal "$valid_ipv6_dns" "$valid_ipv6"

wildcard_dns="$TMP_DIR/wildcard-dns.txt"
wildcard_ips="$TMP_DIR/wildcard-ips.txt"
write_values "$wildcard_dns" '*.example.internal'
write_values "$wildcard_ips" 192.0.2.10
expect_rejects 'DNS SAN for service platform-example must be a DNS name' app.example.internal "$wildcard_dns" "$wildcard_ips"

whitespace_dns="$TMP_DIR/whitespace-dns.txt"
whitespace_ips="$TMP_DIR/whitespace-ips.txt"
write_values "$whitespace_dns" app.example.internal
write_values "$whitespace_ips" 192.0.2.10
expect_rejects 'common_name for service platform-example must not start or end with whitespace' ' app.example.internal' "$whitespace_dns" "$whitespace_ips"

control_dns="$TMP_DIR/control-dns.txt"
control_ips="$TMP_DIR/control-ips.txt"
write_values "$control_dns" app.example.internal
write_values "$control_ips" $'192.0.2.10\t'
expect_rejects 'IP SAN for service platform-example must not contain control characters' app.example.internal "$control_dns" "$control_ips"

printf '%s\n' 'test-inventory-value-validation.sh: ok'
