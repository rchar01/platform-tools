#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
EXEC_TMP_DIR=$(mktemp -d "$ROOT_DIR/.test-export-ansible.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_TMP_DIR"' EXIT HUP INT TERM
VERSION=$(<"$ROOT_DIR/VERSION")
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=ExportRoot \
  -keyout "$TMP_DIR/root.key" -out "$TMP_DIR/root.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=ExportIntermediate \
  -keyout "$TMP_DIR/intermediate.key" -out "$TMP_DIR/intermediate.csr" >/dev/null 2>&1
openssl x509 -req -in "$TMP_DIR/intermediate.csr" -CA "$TMP_DIR/root.crt" -CAkey "$TMP_DIR/root.key" \
  -CAcreateserial -days 300 -out "$TMP_DIR/intermediate.crt" >/dev/null 2>&1

if ! "$ROOT_DIR/bin/platform-pki-export-ansible" --help \
  >"$TMP_DIR/help.out" 2>"$TMP_DIR/help.err"; then
  printf '%s\n' 'export help failed' >&2
  exit 1
fi
grep -q 'Usage:' "$TMP_DIR/help.out"
grep -q 'platform-pki-export-ansible --version | -v' "$TMP_DIR/help.out"
[[ ! -s $TMP_DIR/help.err ]] || { printf '%s\n' 'export help wrote stderr' >&2; exit 1; }

if [[ $("$ROOT_DIR/bin/platform-pki-export-ansible" --version) != \
  "platform-pki-export-ansible $VERSION" ]]; then
  printf '%s\n' 'unexpected export version output' >&2
  exit 1
fi

literal_service="platform-\$(touch $TMP_DIR/eval-injected)"
if "$ROOT_DIR/bin/platform-pki-export-ansible" "$literal_service" \
  >"$TMP_DIR/literal.out" 2>&1; then
  printf '%s\n' 'export accepted an invalid literal service' >&2
  exit 1
fi
grep -q 'Invalid service name:' "$TMP_DIR/literal.out"
[[ ! -e $TMP_DIR/eval-injected ]] || { printf '%s\n' 'service value executed shell content' >&2; exit 1; }

create_generated_pki_tree() {
  local pki_dir=$1
  local service

  mkdir -p \
    "$pki_dir/inventory" \
    "$pki_dir/authorities/roots/g1/certs" \
    "$pki_dir/authorities/intermediates/g1-i1/certs" \
    "$pki_dir/locks" "$pki_dir/state/rollover" \
    "$pki_dir/export/ansible"
  chmod 700 "$(dirname -- "$pki_dir")"
  find "$pki_dir" -type d -exec chmod 700 {} +
  cat >"$pki_dir/inventory/services.yml" <<'YAML'
services:
  platform-example:
    common_name: platform-example.internal
    dns:
      - platform-example.internal
  platform-second:
    common_name: platform-second.internal
    dns:
      - platform-second.internal
YAML
  chmod 600 "$pki_dir/inventory/services.yml"
  cp "$TMP_DIR/root.crt" "$pki_dir/authorities/roots/g1/certs/root-ca.crt"
  cp "$TMP_DIR/intermediate.crt" "$pki_dir/authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
  printf 'root=g1\nintermediate=g1-i1\n' >"$pki_dir/state/active-issuer"
  chmod 600 "$pki_dir/state/active-issuer"
  for service in platform-example platform-second; do
    mkdir -p "$pki_dir/services/$service/private" \
      "$pki_dir/services/$service/certs" \
      "$pki_dir/services/$service/chain"
    printf '%s\n' "$service certificate" >"$pki_dir/services/$service/certs/tls.crt"
    printf '%s\n' "$service private key" >"$pki_dir/services/$service/private/tls.key"
    printf '%s\n' "$service ca chain" >"$pki_dir/services/$service/chain/ca-chain.crt"
    printf '%s\n' "$service full chain" >"$pki_dir/services/$service/chain/fullchain.crt"
    printf 'root=g1\nintermediate=g1-i1\n' >"$pki_dir/services/$service/issuer"
    chmod 600 "$pki_dir/services/$service/issuer"
  done
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
assert_file_content "$pki_dir/export/ansible/services/platform-example/tls.key" 'platform-example private key'
[[ -f $pki_dir/export/ansible/services/platform-second/tls.key ]] || { printf '%s\n' 'default export omitted generated second service' >&2; exit 1; }

selected_export="$pki_dir/export/selected"
"$ROOT_DIR/bin/platform-pki-export-ansible" \
  platform-example platform-second \
  --pki-dir "$pki_dir" --export-dir "$selected_export" >/dev/null
[[ -f $selected_export/services/platform-example/tls.key ]] || { printf '%s\n' 'explicit export omitted first service' >&2; exit 1; }
[[ -f $selected_export/services/platform-second/tls.key ]] || { printf '%s\n' 'explicit export omitted second service' >&2; exit 1; }
"$ROOT_DIR/bin/platform-pki-export-ansible" \
  platform-example platform-second --pki-dir "$pki_dir" \
  --export-dir "$selected_export" --force >/dev/null

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$pki_dir" --export-dir "$pki_dir" --force \
  >"$TMP_DIR/equal-scope.out" 2>&1; then
  printf '%s\n' 'export accepted the PKI directory as replacement scope' >&2
  exit 1
fi
grep -q 'Export directory must not equal or contain the PKI directory' \
  "$TMP_DIR/equal-scope.out"
[[ -f $pki_dir/inventory/services.yml ]] || { printf '%s\n' 'equal-scope check deleted PKI state' >&2; exit 1; }

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$pki_dir" --export-dir "$(dirname -- "$pki_dir")" --force \
  >"$TMP_DIR/ancestor-scope.out" 2>&1; then
  printf '%s\n' 'export accepted a PKI ancestor as replacement scope' >&2
  exit 1
fi
grep -q 'Export directory must not equal or contain the PKI directory' \
  "$TMP_DIR/ancestor-scope.out"
[[ -f $pki_dir/inventory/services.yml ]] || { printf '%s\n' 'ancestor-scope check deleted PKI state' >&2; exit 1; }

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$pki_dir" --export-dir "$pki_dir/services" --force \
  >"$TMP_DIR/source-scope.out" 2>&1; then
  printf '%s\n' 'export accepted a PKI source directory as replacement scope' >&2
  exit 1
fi
grep -q 'Export directory inside the PKI tree must be under its export directory' \
  "$TMP_DIR/source-scope.out"
[[ -f $pki_dir/services/platform-example/private/tls.key ]] || { printf '%s\n' 'source-scope check deleted private key' >&2; exit 1; }

if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$pki_dir" --export-dir "$pki_dir/export" --force \
  >"$TMP_DIR/export-root.out" 2>&1; then
  printf '%s\n' 'export accepted the structural PKI export root' >&2
  exit 1
fi
grep -q 'Export directory must be below the PKI export directory' \
  "$TMP_DIR/export-root.out"
[[ -f $selected_export/services/platform-example/tls.key ]] || { printf '%s\n' 'export-root check deleted nested export' >&2; exit 1; }

unmarked_export="$pki_dir/export/unmarked"
mkdir -m 700 "$unmarked_export"
printf '%s\n' 'unmarked sentinel' >"$unmarked_export/sentinel"
if "$ROOT_DIR/bin/platform-pki-export-ansible" \
  --pki-dir "$pki_dir" --export-dir "$unmarked_export" --force \
  >"$TMP_DIR/unmarked.out" 2>&1; then
  printf '%s\n' 'export replaced an unmarked custom directory' >&2
  exit 1
fi
grep -q 'Refusing to replace unmarked custom export directory' "$TMP_DIR/unmarked.out"
assert_file_content "$unmarked_export/sentinel" 'unmarked sentinel'

zero_pki="$TMP_DIR/zero-generated/pki"
mkdir -p "$zero_pki/inventory" "$zero_pki/authorities/roots/g1/certs" \
  "$zero_pki/authorities/intermediates/g1-i1/certs" "$zero_pki/export/ansible" \
  "$zero_pki/locks" "$zero_pki/state/rollover"
chmod 700 "$TMP_DIR/zero-generated"
find "$zero_pki" -type d -exec chmod 700 {} +
cat >"$zero_pki/inventory/services.yml" <<'YAML'
services:
  missing-service:
    common_name: missing.internal
    dns:
      - missing.internal
YAML
chmod 600 "$zero_pki/inventory/services.yml"
cp "$TMP_DIR/root.crt" "$zero_pki/authorities/roots/g1/certs/root-ca.crt"
cp "$TMP_DIR/intermediate.crt" "$zero_pki/authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
printf 'root=g1\nintermediate=g1-i1\n' >"$zero_pki/state/active-issuer"
chmod 600 "$zero_pki/state/active-issuer"
printf '%s\n' 'zero sentinel' >"$zero_pki/export/ansible/sentinel"
if "$ROOT_DIR/bin/platform-pki-export-ansible" --pki-dir "$zero_pki" --force \
  >"$TMP_DIR/zero.out" 2>&1; then
  printf '%s\n' 'export accepted an inventory without generated services' >&2
  exit 1
fi
grep -q 'No generated service certificates found to export' "$TMP_DIR/zero.out"
assert_file_content "$zero_pki/export/ansible/sentinel" 'zero sentinel'

copy_fail_bin="$EXEC_TMP_DIR/copy-fail-bin"
mkdir -p "$copy_fail_bin"
real_cp=$(command -v cp)
cat >"$copy_fail_bin/cp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == */private/tls.key ]]; then
  printf '%s\n' 'partial private key' >"$2"
  exit 1
fi
exec "$REAL_CP" "$@"
EOF
chmod 755 "$copy_fail_bin/cp"
copy_fail_export="$pki_dir/export/copy-fail"
if REAL_CP=$real_cp PATH="$copy_fail_bin:$PATH" \
  "$ROOT_DIR/bin/platform-pki-export-ansible" platform-example \
  --pki-dir "$pki_dir" --export-dir "$copy_fail_export" \
  >"$TMP_DIR/copy-fail.out" 2>&1; then
  printf '%s\n' 'export succeeded after private-key copy failure' >&2
  exit 1
fi
grep -q 'Failed to publish export file without overwriting' \
  "$TMP_DIR/copy-fail.out"
if find "$copy_fail_export" -name '.tls.key.tmp.*' -print -quit | grep -q .; then
  printf '%s\n' 'failed private-key copy left a temporary file' >&2
  exit 1
fi
[[ ! -e $copy_fail_export/services/platform-example/tls.key ]] || { printf '%s\n' 'failed copy published a private key' >&2; exit 1; }

race_bin="$EXEC_TMP_DIR/race-bin"
mkdir -p "$race_bin"
real_ln=$(command -v ln)
cat >"$race_bin/ln" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if { [[ ${RACE_TARGET_KIND:-payload} == payload && $target == */ca/root-ca.crt ]] ||
  [[ ${RACE_TARGET_KIND:-payload} == marker && $target == */.platform-pki-ansible-export ]]; } &&
  [[ ! -e $RACE_MARKER ]]; then
  case ${RACE_KIND:-file} in
    file) printf '%s\n' 'attacker target' >"$target" ;;
    directory) mkdir "$target" ;;
    symlink)
      [[ -e $RACE_VICTIM ]] || mkdir "$RACE_VICTIM"
      "$REAL_LN" -s "$RACE_VICTIM" "$target"
      ;;
  esac
  : >"$RACE_MARKER"
fi
exec "$REAL_LN" "$@"
EOF
chmod 755 "$race_bin/ln"
race_export="$pki_dir/export/race"
if REAL_LN=$real_ln RACE_MARKER="$TMP_DIR/race-marker" \
  PATH="$race_bin:$PATH" "$ROOT_DIR/bin/platform-pki-export-ansible" \
  platform-example --pki-dir "$pki_dir" --export-dir "$race_export" \
  >"$TMP_DIR/race.out" 2>&1; then
  printf '%s\n' 'export overwrote a target that appeared during copy' >&2
  exit 1
fi
assert_file_content "$race_export/ca/root-ca.crt" 'attacker target'
if find "$race_export" -name '.root-ca.crt.tmp.*' -print -quit | grep -q .; then
  printf '%s\n' 'target race left a temporary file' >&2
  exit 1
fi

directory_race_export="$pki_dir/export/directory-race"
if REAL_LN=$real_ln RACE_MARKER="$TMP_DIR/directory-race-marker" \
  RACE_KIND=directory PATH="$race_bin:$PATH" \
  "$ROOT_DIR/bin/platform-pki-export-ansible" platform-example \
  --pki-dir "$pki_dir" --export-dir "$directory_race_export" \
  >"$TMP_DIR/directory-race.out" 2>&1; then
  printf '%s\n' 'export published into a raced-in target directory' >&2
  exit 1
fi
[[ -d $directory_race_export/ca/root-ca.crt ]] || { printf '%s\n' 'directory race target disappeared' >&2; exit 1; }
[[ -z $(find "$directory_race_export/ca/root-ca.crt" -mindepth 1 -print -quit) ]] || { printf '%s\n' 'directory race received exported content' >&2; exit 1; }

symlink_race_export="$pki_dir/export/symlink-race"
if REAL_LN=$real_ln RACE_MARKER="$TMP_DIR/symlink-race-marker" \
  RACE_KIND=symlink RACE_VICTIM="$TMP_DIR/symlink-race-victim" \
  PATH="$race_bin:$PATH" "$ROOT_DIR/bin/platform-pki-export-ansible" \
  platform-example --pki-dir "$pki_dir" --export-dir "$symlink_race_export" \
  >"$TMP_DIR/symlink-race.out" 2>&1; then
  printf '%s\n' 'export published through a raced-in target symlink' >&2
  exit 1
fi
[[ -L $symlink_race_export/ca/root-ca.crt ]] || { printf '%s\n' 'symlink race target disappeared' >&2; exit 1; }
[[ -z $(find "$TMP_DIR/symlink-race-victim" -mindepth 1 -print -quit) ]] || { printf '%s\n' 'symlink race victim received exported content' >&2; exit 1; }

marker_race_export="$pki_dir/export/marker-race"
printf '%s\n' 'marker victim sentinel' >"$TMP_DIR/marker-race-victim"
if REAL_LN=$real_ln RACE_MARKER="$TMP_DIR/marker-target-race-marker" \
  RACE_TARGET_KIND=marker RACE_KIND=symlink \
  RACE_VICTIM="$TMP_DIR/marker-race-victim" PATH="$race_bin:$PATH" \
  "$ROOT_DIR/bin/platform-pki-export-ansible" platform-example \
  --pki-dir "$pki_dir" --export-dir "$marker_race_export" \
  >"$TMP_DIR/marker-race.out" 2>&1; then
  printf '%s\n' 'export overwrote a raced-in marker symlink' >&2
  exit 1
fi
assert_file_content "$TMP_DIR/marker-race-victim" 'marker victim sentinel'

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
assert_file_content "$target_symlink_pki/export/ansible/services/platform-example/tls.key" 'platform-example private key'

printf '%s\n' 'test-export-ansible-safe-paths.sh: ok'
