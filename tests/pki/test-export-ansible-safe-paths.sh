#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
EXEC_TMP_DIR=$(mktemp -d "$ROOT_DIR/.test-export-ansible.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_TMP_DIR"' EXIT HUP INT TERM

create_generated_pki_tree() {
  local pki_dir=$1
  local service=platform-example

  mkdir -p \
    "$pki_dir/inventory" \
    "$pki_dir/root-ca/certs" \
    "$pki_dir/services/$service/private" \
    "$pki_dir/services/$service/certs" \
    "$pki_dir/services/$service/chain" \
    "$pki_dir/export/ansible"
  chmod 700 "$(dirname -- "$pki_dir")"
  chmod 700 "$pki_dir" "$pki_dir/export" "$pki_dir/export/ansible"
  cat >"$pki_dir/inventory/services.yml" <<'YAML'
services:
  platform-example:
    common_name: platform-example.internal
YAML
  printf '%s\n' 'root certificate' >"$pki_dir/root-ca/certs/root-ca.crt"
  printf '%s\n' 'service certificate' >"$pki_dir/services/$service/certs/tls.crt"
  printf '%s\n' 'service private key' >"$pki_dir/services/$service/private/tls.key"
  printf '%s\n' 'ca chain' >"$pki_dir/services/$service/chain/ca-chain.crt"
  printf '%s\n' 'full chain' >"$pki_dir/services/$service/chain/fullchain.crt"
}

assert_mode() {
  local path=$1
  local expected=$2
  local mode

  mode=$(stat -c '%a' "$path")
  if [[ "$mode" != "$expected" ]]; then
    printf '%s\n' "expected $path to have mode $expected, got $mode" >&2
    exit 1
  fi
}

assert_file_content() {
  local path=$1
  local expected=$2

  if [[ $(cat "$path") != "$expected" ]]; then
    printf '%s\n' "unexpected content in $path" >&2
    exit 1
  fi
}

write_fake_stat() {
  local path=$1

  cat >"$path" <<'SH'
#!/bin/sh
if [ "$1" = '-c' ] && [ "$2" = '%u' ] && [ "${3:-}" = "$UNTRUSTED_COMPONENT" ]; then
  printf '%s\n' "$UNTRUSTED_OWNER"
  exit 0
fi
exec "$REAL_STAT" "$@"
SH
  chmod 755 "$path"
}

pki_dir="$TMP_DIR/default/pki"
create_generated_pki_tree "$pki_dir"
printf '%s\n' 'stale export' >"$pki_dir/export/ansible/stale.txt"

"$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$pki_dir" \
  --force >/dev/null

[[ ! -e "$pki_dir/export/ansible/stale.txt" ]] || { printf '%s\n' 'stale export file survived --force' >&2; exit 1; }
assert_mode "$pki_dir/export/ansible" 700
assert_mode "$pki_dir/export/ansible/ca" 700
assert_mode "$pki_dir/export/ansible/services" 700
assert_mode "$pki_dir/export/ansible/services/platform-example" 700
assert_mode "$pki_dir/export/ansible/services/platform-example/tls.key" 600
assert_mode "$pki_dir/export/ansible/services/platform-example/tls.crt" 644
assert_file_content "$pki_dir/export/ansible/services/platform-example/tls.key" 'service private key'

shared_parent="$TMP_DIR/shared-parent"
shared_pki="$TMP_DIR/shared-pki/pki"
create_generated_pki_tree "$shared_pki"
mkdir -p "$shared_parent"
chmod 777 "$shared_parent"

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$shared_pki" \
  --export-dir "$shared_parent/export" >"$TMP_DIR/shared.out" 2>&1; then
  printf '%s\n' 'export accepted a group/world-writable parent' >&2
  exit 1
fi
grep -q 'Export parent path component is group- or world-writable without sticky bit' "$TMP_DIR/shared.out"

unsafe_ancestor_pki="$TMP_DIR/unsafe-ancestor-pki/pki"
unsafe_ancestor="$TMP_DIR/unsafe-ancestor"
unsafe_child="$unsafe_ancestor/safe-child"
create_generated_pki_tree "$unsafe_ancestor_pki"
mkdir -p "$unsafe_child"
chmod 777 "$unsafe_ancestor"
chmod 700 "$unsafe_child"

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$unsafe_ancestor_pki" \
  --export-dir "$unsafe_child/export" >"$TMP_DIR/unsafe-ancestor.out" 2>&1; then
  printf '%s\n' 'export accepted an unsafe writable ancestor' >&2
  exit 1
fi
grep -q 'Export parent path component is group- or world-writable without sticky bit' "$TMP_DIR/unsafe-ancestor.out"

owner_ancestor_pki="$TMP_DIR/owner-ancestor-pki/pki"
owner_ancestor="$TMP_DIR/owner-ancestor"
owner_child="$owner_ancestor/safe-child"
fake_bin="$EXEC_TMP_DIR/fake-bin"
real_stat=$(command -v stat)
current_uid=$(id -u)
untrusted_owner=99999
if [[ $current_uid -eq $untrusted_owner ]]; then
  untrusted_owner=99998
fi
create_generated_pki_tree "$owner_ancestor_pki"
mkdir -p "$owner_child" "$fake_bin"
chmod 755 "$owner_ancestor"
chmod 700 "$owner_child"
write_fake_stat "$fake_bin/stat"

if REAL_STAT=$real_stat UNTRUSTED_COMPONENT=$owner_ancestor UNTRUSTED_OWNER=$untrusted_owner PATH="$fake_bin:$PATH" "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$owner_ancestor_pki" \
  --export-dir "$owner_child/export" >"$TMP_DIR/owner-ancestor.out" 2>&1; then
  printf '%s\n' 'export accepted an untrusted-owner ancestor' >&2
  exit 1
fi
grep -q 'Export parent path component is not owned by current user or root' "$TMP_DIR/owner-ancestor.out"
[[ ! -e "$owner_child/export/services/platform-example/tls.key" ]] || { printf '%s\n' 'untrusted-owner ancestor export target received private key' >&2; exit 1; }

sticky_owner_ancestor_pki="$TMP_DIR/sticky-owner-ancestor-pki/pki"
sticky_owner_ancestor="$TMP_DIR/sticky-owner-ancestor"
sticky_owner_child="$sticky_owner_ancestor/safe-child"
create_generated_pki_tree "$sticky_owner_ancestor_pki"
mkdir -p "$sticky_owner_child"
chmod 1755 "$sticky_owner_ancestor"
chmod 700 "$sticky_owner_child"

if REAL_STAT=$real_stat UNTRUSTED_COMPONENT=$sticky_owner_ancestor UNTRUSTED_OWNER=$untrusted_owner PATH="$fake_bin:$PATH" "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$sticky_owner_ancestor_pki" \
  --export-dir "$sticky_owner_child/export" >"$TMP_DIR/sticky-owner-ancestor.out" 2>&1; then
  printf '%s\n' 'export accepted a sticky untrusted-owner ancestor' >&2
  exit 1
fi
grep -q 'Export parent path component is not owned by current user or root' "$TMP_DIR/sticky-owner-ancestor.out"
[[ ! -e "$sticky_owner_child/export/services/platform-example/tls.key" ]] || { printf '%s\n' 'sticky untrusted-owner ancestor export target received private key' >&2; exit 1; }

symlink_pki="$TMP_DIR/symlink/pki"
create_generated_pki_tree "$symlink_pki"
symlink_target="$TMP_DIR/symlink-target"
mkdir -p "$symlink_target"
rm -rf "$symlink_pki/export/ansible"
ln -s "$symlink_target" "$symlink_pki/export/ansible"

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$symlink_pki" \
  --force >"$TMP_DIR/symlink.out" 2>&1; then
  printf '%s\n' 'export accepted a symlink export directory' >&2
  exit 1
fi
grep -q 'Export directory must not be a symlink' "$TMP_DIR/symlink.out"
[[ ! -e "$symlink_target/services/platform-example/tls.key" ]] || { printf '%s\n' 'symlink export target received private key' >&2; exit 1; }

ancestor_pki="$TMP_DIR/ancestor/pki"
create_generated_pki_tree "$ancestor_pki"
ancestor_safe_parent="$TMP_DIR/ancestor-safe-parent"
ancestor_target="$TMP_DIR/ancestor-target"
mkdir -p "$ancestor_safe_parent" "$ancestor_target/sub"
chmod 700 "$ancestor_safe_parent" "$ancestor_target" "$ancestor_target/sub"
ln -s "$ancestor_target" "$ancestor_safe_parent/link"

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$ancestor_pki" \
  --export-dir "$ancestor_safe_parent/link/sub/export" >"$TMP_DIR/ancestor.out" 2>&1; then
  printf '%s\n' 'export accepted a symlink ancestor component' >&2
  exit 1
fi
grep -q 'Export parent path component must not be a symlink' "$TMP_DIR/ancestor.out"
[[ ! -e "$ancestor_target/sub/export/services/platform-example/tls.key" ]] || { printf '%s\n' 'symlink ancestor target received private key' >&2; exit 1; }

relative_pki="$TMP_DIR/relative/pki"
create_generated_pki_tree "$relative_pki"
relative_real_cwd="$TMP_DIR/relative-real-cwd"
relative_link_cwd="$TMP_DIR/relative-link-cwd"
mkdir -p "$relative_real_cwd"
ln -s "$relative_real_cwd" "$relative_link_cwd"

if (cd "$relative_link_cwd" && "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$relative_pki" \
  --export-dir relative-export >"$TMP_DIR/relative.out" 2>&1); then
  printf '%s\n' 'export accepted a relative export directory from a symlinked cwd' >&2
  exit 1
fi
grep -q -- '--export-dir must be an absolute path' "$TMP_DIR/relative.out"
[[ ! -e "$relative_real_cwd/relative-export/services/platform-example/tls.key" ]] || { printf '%s\n' 'relative export target received private key' >&2; exit 1; }

target_symlink_pki="$TMP_DIR/target-symlink/pki"
create_generated_pki_tree "$target_symlink_pki"
attacker_file="$TMP_DIR/attacker-file"
printf '%s\n' 'attacker content' >"$attacker_file"
mkdir -p "$target_symlink_pki/export/ansible/services/platform-example"
ln -s "$attacker_file" "$target_symlink_pki/export/ansible/services/platform-example/tls.key"

"$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$target_symlink_pki" \
  --force >/dev/null

assert_file_content "$attacker_file" 'attacker content'
assert_file_content "$target_symlink_pki/export/ansible/services/platform-example/tls.key" 'service private key'

printf '%s\n' 'test-export-ansible-safe-paths.sh: ok'
