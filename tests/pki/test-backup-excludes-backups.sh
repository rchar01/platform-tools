#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

create_pki_tree() {
  local pki_dir=$1

  mkdir -p "$pki_dir/inventory" "$pki_dir/root-ca/private" "$pki_dir/export/ansible"
  printf '%s\n' 'services: {}' >"$pki_dir/inventory/services.yml"
  printf '%s\n' 'root key placeholder' >"$pki_dir/root-ca/private/root-ca.key"
  printf '%s\n' 'export placeholder' >"$pki_dir/export/ansible/README.txt"
}

latest_backup() {
  local backup_dir=$1
  local backups

  shopt -s nullglob
  backups=("$backup_dir"/platform-pki-*.tar.gz)
  shopt -u nullglob
  if (( ${#backups[@]} == 0 )); then
    printf '%s\n' "no backup archive found in $backup_dir" >&2
    exit 1
  fi
  printf '%s\n' "${backups[${#backups[@]} - 1]}"
}

assert_archive_contains() {
  local archive=$1
  local expected=$2
  local entry

  while IFS= read -r entry; do
    if [[ "$entry" == "$expected" ]]; then
      return 0
    fi
  done < <(tar -tzf "$archive")

  printf '%s\n' "expected $archive to contain $expected" >&2
  exit 1
}

assert_archive_excludes_prefix() {
  local archive=$1
  local prefix=$2
  local entry

  while IFS= read -r entry; do
    case $entry in
      "$prefix"|"$prefix"/*)
        printf '%s\n' "expected $archive to exclude $prefix" >&2
        exit 1
        ;;
    esac
  done < <(tar -tzf "$archive")
}

default_pki="$TMP_DIR/default/pki"
create_pki_tree "$default_pki"

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$default_pki" \
  --allow-plain-backup >/dev/null

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$default_pki" \
  --allow-plain-backup >/dev/null

default_archive=$(latest_backup "$default_pki/backups")
assert_archive_contains "$default_archive" 'pki/inventory/services.yml'
assert_archive_excludes_prefix "$default_archive" 'pki/backups'

custom_pki="$TMP_DIR/custom/pki"
custom_backup_dir="$custom_pki/custom-backups"
create_pki_tree "$custom_pki"

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$custom_pki" \
  --backup-dir "$custom_backup_dir" \
  --allow-plain-backup >/dev/null

custom_archive=$(latest_backup "$custom_backup_dir")
assert_archive_contains "$custom_archive" 'pki/inventory/services.yml'
assert_archive_excludes_prefix "$custom_archive" 'pki/custom-backups'

pattern_pki="$TMP_DIR/pattern/pki"
pattern_backup_dir="$pattern_pki/backups[1]"
create_pki_tree "$pattern_pki"

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$pattern_pki" \
  --backup-dir "$pattern_backup_dir" \
  --allow-plain-backup >/dev/null

pattern_archive=$(latest_backup "$pattern_backup_dir")
assert_archive_contains "$pattern_archive" 'pki/inventory/services.yml'
assert_archive_excludes_prefix "$pattern_archive" 'pki/backups[1]'

space_pki="$TMP_DIR/path with spaces/pki"
create_pki_tree "$space_pki"

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$space_pki" \
  --allow-plain-backup >/dev/null

space_archive=$(latest_backup "$space_pki/backups")
assert_archive_contains "$space_archive" 'pki/inventory/services.yml'
assert_archive_excludes_prefix "$space_archive" 'pki/backups'

symlink_pki_real="$TMP_DIR/symlink-pki/real/pki"
symlink_pki_alias="$TMP_DIR/symlink-pki/pki-alias"
create_pki_tree "$symlink_pki_real"
ln -s "$symlink_pki_real" "$symlink_pki_alias"

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$symlink_pki_alias" \
  --allow-plain-backup >/dev/null

symlink_pki_archive=$(latest_backup "$symlink_pki_real/backups")
assert_archive_contains "$symlink_pki_archive" 'pki/inventory/services.yml'
assert_archive_excludes_prefix "$symlink_pki_archive" 'pki/backups'

symlink_backup_pki="$TMP_DIR/symlink-backup/pki"
symlink_backup_real="$symlink_backup_pki/real-backups"
symlink_backup_alias="$symlink_backup_pki/backup-link"
create_pki_tree "$symlink_backup_pki"
mkdir -p "$symlink_backup_real"
ln -s "$symlink_backup_real" "$symlink_backup_alias"

"$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$symlink_backup_pki" \
  --backup-dir "$symlink_backup_alias" \
  --allow-plain-backup >/dev/null

symlink_backup_archive=$(latest_backup "$symlink_backup_real")
assert_archive_contains "$symlink_backup_archive" 'pki/inventory/services.yml'
assert_archive_excludes_prefix "$symlink_backup_archive" 'pki/real-backups'
assert_archive_excludes_prefix "$symlink_backup_archive" 'pki/backup-link'

reject_pki="$TMP_DIR/reject/pki"
create_pki_tree "$reject_pki"

if "$ROOT_DIR/bin/platform-pki-backup" \
  --pki-dir "$reject_pki" \
  --backup-dir "$reject_pki" \
  --allow-plain-backup >"$TMP_DIR/reject.out" 2>&1; then
  printf '%s\n' 'backup accepted the PKI directory as its backup directory' >&2
  exit 1
fi

if ! grep -q 'Backup directory cannot be the PKI directory itself' "$TMP_DIR/reject.out"; then
  printf '%s\n' 'backup-dir rejection did not explain the PKI directory conflict' >&2
  exit 1
fi

printf '%s\n' 'test-backup-excludes-backups.sh: ok'
