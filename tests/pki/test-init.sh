#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-init.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-pki-init-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-pki-init"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-init.sh: %s\n' "$*" >&2
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

assert_mode() {
  local expected=$1 path=$2 actual
  actual=$(stat -c '%a' "$path")
  [[ $actual == "$expected" ]] || fail "expected mode $expected for $path, got $actual"
}

assert_content() {
  local expected=$1 path=$2 actual
  actual=$(<"$path")
  [[ $actual == "$expected" ]] || fail "unexpected content in $path: $actual"
}

run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-init --version | -v'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-init $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_tool --namespace ''
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'must not be empty'

namespace="$TMP_DIR/namespace"
pki_dir="$namespace/pki"
run_tool --namespace "$namespace"
assert_status 0
assert_empty "$STDERR"
assert_contains "$STDOUT" "[OK] PKI directory ready: $pki_dir"

for dir in \
  "$namespace" "$pki_dir" "$pki_dir/inventory" \
  "$pki_dir/root-ca" "$pki_dir/root-ca/certs" \
  "$pki_dir/root-ca/private" "$pki_dir/root-ca/crl" \
  "$pki_dir/root-ca/newcerts" "$pki_dir/intermediate-ca" \
  "$pki_dir/intermediate-ca/certs" "$pki_dir/intermediate-ca/csr" \
  "$pki_dir/intermediate-ca/private" "$pki_dir/intermediate-ca/crl" \
  "$pki_dir/intermediate-ca/newcerts" "$pki_dir/services" \
  "$pki_dir/export" "$pki_dir/export/ansible" "$pki_dir/backups"; do
  [[ -d $dir ]] || fail "missing directory: $dir"
  assert_mode 700 "$dir"
done

for file in \
  "$pki_dir/inventory/services.yml.example" \
  "$pki_dir/root-ca/index.txt" "$pki_dir/root-ca/index.txt.attr" \
  "$pki_dir/root-ca/serial" "$pki_dir/root-ca/crlnumber" \
  "$pki_dir/intermediate-ca/index.txt" \
  "$pki_dir/intermediate-ca/index.txt.attr" \
  "$pki_dir/intermediate-ca/serial" \
  "$pki_dir/intermediate-ca/crlnumber"; do
  [[ -f $file ]] || fail "missing file: $file"
  assert_mode 600 "$file"
done

printf '%s\n' 'custom inventory' >"$pki_dir/inventory/services.yml"
printf '%s\n' 'custom example' >"$pki_dir/inventory/services.yml.example"
printf '%s\n' 'custom index' >"$pki_dir/root-ca/index.txt"
printf '%s\n' 'custom serial' >"$pki_dir/intermediate-ca/serial"
printf '%s\n' 'private key sentinel' >"$pki_dir/root-ca/private/root-ca.key"
printf '%s\n' 'certificate sentinel' >"$pki_dir/root-ca/certs/root-ca.crt"
chmod 600 "$pki_dir/root-ca/private/root-ca.key"

run_tool --namespace "$namespace"
assert_status 0
assert_empty "$STDERR"
assert_content 'custom inventory' "$pki_dir/inventory/services.yml"
assert_content 'custom example' "$pki_dir/inventory/services.yml.example"

run_tool --namespace "$namespace" --force
assert_status 0
assert_empty "$STDERR"
cmp "$ROOT_DIR/templates/pki/services.yml.example" \
  "$pki_dir/inventory/services.yml.example" >/dev/null || fail 'force did not refresh inventory example'
assert_content 'custom inventory' "$pki_dir/inventory/services.yml"
assert_content 'custom index' "$pki_dir/root-ca/index.txt"
assert_content 'custom serial' "$pki_dir/intermediate-ca/serial"
assert_content 'private key sentinel' "$pki_dir/root-ca/private/root-ca.key"
assert_content 'certificate sentinel' "$pki_dir/root-ca/certs/root-ca.crt"
assert_mode 600 "$pki_dir/root-ca/private/root-ca.key"

run_tool --namespace /
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Namespace must not be the filesystem root'

run_tool --namespace relative/path
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Namespace must be an absolute path'

run_tool --namespace "$TMP_DIR/trailing-slash/"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Namespace must not end with a slash'

run_tool --namespace "$TMP_DIR/equal-path" --pki-dir "$TMP_DIR/equal-path"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory must not equal or contain the namespace'
[[ ! -e $TMP_DIR/equal-path ]] || fail 'equal namespace and PKI path created state'

run_tool --namespace "$TMP_DIR/overlap/pki.env/namespace" \
  --pki-dir "$TMP_DIR/overlap"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory must not equal or contain the namespace'
[[ ! -e $TMP_DIR/overlap ]] || fail 'overlapping paths created state'

mkdir -p "$TMP_DIR/symlink-victim"
chmod 755 "$TMP_DIR/symlink-victim"
ln -s "$TMP_DIR/symlink-victim" "$TMP_DIR/symlink-namespace"
run_tool --namespace "$TMP_DIR/symlink-namespace"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Namespace path component must not be a symlink'
assert_mode 755 "$TMP_DIR/symlink-victim"

mkdir -p "$EXEC_DIR/race-bin" "$TMP_DIR/race-victim"
chmod 755 "$TMP_DIR/race-victim"
cat >"$EXEC_DIR/race-bin/mkdir" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if [[ $target == "$RACE_TARGET" ]]; then
  ln -s "$RACE_VICTIM" "$target"
  exit 1
fi
exec "$REAL_MKDIR" "$@"
EOF
chmod 755 "$EXEC_DIR/race-bin/mkdir"
real_mkdir=$(command -v mkdir)
run_command env PATH="$EXEC_DIR/race-bin:$PATH" \
  RACE_TARGET="$TMP_DIR/race-namespace" \
  RACE_VICTIM="$TMP_DIR/race-victim" REAL_MKDIR="$real_mkdir" \
  "$TOOL" --namespace "$TMP_DIR/race-namespace"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Cannot create Namespace path component'
assert_mode 755 "$TMP_DIR/race-victim"
[[ ! -e $TMP_DIR/race-victim/pki ]] || \
  fail 'path creation race mutated the symlink victim'

mkdir -p "$TMP_DIR/nested-link-namespace/pki" "$TMP_DIR/nested-link-victim"
chmod 755 "$TMP_DIR/nested-link-namespace" \
  "$TMP_DIR/nested-link-namespace/pki" "$TMP_DIR/nested-link-victim"
ln -s "$TMP_DIR/nested-link-victim" \
  "$TMP_DIR/nested-link-namespace/pki/root-ca"
run_tool --namespace "$TMP_DIR/nested-link-namespace"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Existing PKI state must not contain symlinks'
assert_mode 755 "$TMP_DIR/nested-link-namespace"
assert_mode 755 "$TMP_DIR/nested-link-namespace/pki"
assert_mode 755 "$TMP_DIR/nested-link-victim"

run_tool --namespace "$TMP_DIR/hard-link-namespace"
assert_status 0
hard_link_pki="$TMP_DIR/hard-link-namespace/pki"
printf '%s\n' 'hard link key sentinel' \
  >"$hard_link_pki/root-ca/private/root-ca.key"
rm "$hard_link_pki/inventory/services.yml.example"
ln "$hard_link_pki/root-ca/private/root-ca.key" "$hard_link_pki/inventory/services.yml.example"
run_tool --namespace "$TMP_DIR/hard-link-namespace" --force
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Existing PKI state must not contain hard-linked files'
assert_content 'hard link key sentinel' \
  "$hard_link_pki/root-ca/private/root-ca.key"

run_tool --namespace "$TMP_DIR/template-link-namespace"
assert_status 0
template_link_pki="$TMP_DIR/template-link-namespace/pki"
printf '%s\n' 'symlink key sentinel' \
  >"$template_link_pki/root-ca/private/root-ca.key"
rm "$template_link_pki/inventory/services.yml.example"
ln -s "$template_link_pki/root-ca/private/root-ca.key" \
  "$template_link_pki/inventory/services.yml.example"
run_tool --namespace "$TMP_DIR/template-link-namespace" --force
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Existing PKI state must not contain symlinks'
assert_content 'symlink key sentinel' \
  "$template_link_pki/root-ca/private/root-ca.key"

mkdir -p "$TMP_DIR/directory-collision/pki/root-ca/index.txt"
chmod 755 "$TMP_DIR/directory-collision" \
  "$TMP_DIR/directory-collision/pki" \
  "$TMP_DIR/directory-collision/pki/root-ca"
run_tool --namespace "$TMP_DIR/directory-collision"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI file destination must be a non-symlink regular file'
assert_mode 755 "$TMP_DIR/directory-collision"
assert_mode 755 "$TMP_DIR/directory-collision/pki"
[[ ! -e $TMP_DIR/directory-collision/pki/inventory ]] || \
  fail 'directory collision allowed partial initialization'

mkdir -p "$TMP_DIR/fifo-collision/pki/intermediate-ca"
chmod 755 "$TMP_DIR/fifo-collision" "$TMP_DIR/fifo-collision/pki" \
  "$TMP_DIR/fifo-collision/pki/intermediate-ca"
mkfifo "$TMP_DIR/fifo-collision/pki/intermediate-ca/serial"
run_tool --namespace "$TMP_DIR/fifo-collision"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI file destination must be a non-symlink regular file'
assert_mode 755 "$TMP_DIR/fifo-collision/pki"
[[ ! -e $TMP_DIR/fifo-collision/pki/root-ca ]] || \
  fail 'FIFO collision allowed partial initialization'

mkdir -p "$TMP_DIR/file-collision/pki"
chmod 755 "$TMP_DIR/file-collision" "$TMP_DIR/file-collision/pki"
printf '%s\n' 'not a directory' >"$TMP_DIR/file-collision/pki/services"
run_tool --namespace "$TMP_DIR/file-collision"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory destination must be a non-symlink directory'
assert_mode 755 "$TMP_DIR/file-collision/pki"
[[ ! -e $TMP_DIR/file-collision/pki/root-ca ]] || \
  fail 'file collision allowed partial initialization'

mkdir -p "$TMP_DIR/unsafe-mode/pki/root-ca"
chmod 755 "$TMP_DIR/unsafe-mode" "$TMP_DIR/unsafe-mode/pki"
chmod 777 "$TMP_DIR/unsafe-mode/pki/root-ca"
run_tool --namespace "$TMP_DIR/unsafe-mode"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI directory destination is group- or world-writable'
assert_mode 755 "$TMP_DIR/unsafe-mode"
assert_mode 755 "$TMP_DIR/unsafe-mode/pki"
assert_mode 777 "$TMP_DIR/unsafe-mode/pki/root-ca"
[[ ! -e $TMP_DIR/unsafe-mode/pki/inventory ]] || \
  fail 'unsafe late directory allowed partial initialization'

run_tool --namespace "$TMP_DIR/writable-file"
assert_status 0
writable_file_pki="$TMP_DIR/writable-file/pki"
chmod 666 "$writable_file_pki/inventory/services.yml.example"
printf '%s\n' 'database sentinel' >"$writable_file_pki/root-ca/index.txt"
run_tool --namespace "$TMP_DIR/writable-file"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI file destination is group- or world-writable'
assert_mode 666 "$writable_file_pki/inventory/services.yml.example"
assert_content 'database sentinel' "$writable_file_pki/root-ca/index.txt"

run_tool --namespace "$TMP_DIR/writable-private"
assert_status 0
writable_private_pki="$TMP_DIR/writable-private/pki"
mkdir -p "$writable_private_pki/services/custom/private"
chmod 777 "$writable_private_pki/services/custom/private"
run_tool --namespace "$TMP_DIR/writable-private"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Private directory is group- or world-writable'
assert_mode 777 "$writable_private_pki/services/custom/private"

run_tool --namespace "$TMP_DIR/open-key"
assert_status 0
open_key_pki="$TMP_DIR/open-key/pki"
mkdir -p "$open_key_pki/services/custom/private"
chmod 700 "$open_key_pki/services/custom/private"
printf '%s\n' 'open key sentinel' \
  >"$open_key_pki/services/custom/private/tls.key"
chmod 644 "$open_key_pki/services/custom/private/tls.key"
run_tool --namespace "$TMP_DIR/open-key"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Private key permissions are too open'
assert_mode 644 "$open_key_pki/services/custom/private/tls.key"

mkdir -p "$TMP_DIR/custom-templates/pki"
cp "$ROOT_DIR"/templates/pki/* "$TMP_DIR/custom-templates/pki/"
printf '%s\n' 'custom template source' \
  >"$TMP_DIR/custom-templates/pki/services.yml.example"
mkdir -p "$EXEC_DIR/explicit/bin" "$TMP_DIR/explicit/lib"
cp "$TOOL" "$EXEC_DIR/explicit/bin/"
cp "$ROOT_DIR/lib/platform-pki-common.sh" "$TMP_DIR/explicit/lib/"
run_command env PLATFORM_TOOLS_LIB_DIR="$TMP_DIR/explicit/lib" \
  PLATFORM_TOOLS_TEMPLATE_DIR="$TMP_DIR/custom-templates" \
  "$EXEC_DIR/explicit/bin/platform-pki-init" \
  --namespace "$TMP_DIR/custom-namespace" \
  --pki-dir "$TMP_DIR/custom-pki"
assert_status 0
assert_empty "$STDERR"
assert_content 'custom template source' "$TMP_DIR/custom-pki/inventory/services.yml.example"

mkdir -p "$TMP_DIR/incomplete-templates/pki"
cp "$ROOT_DIR"/templates/pki/* "$TMP_DIR/incomplete-templates/pki/"
rm "$TMP_DIR/incomplete-templates/pki/services.yml.example"
run_command env PLATFORM_TOOLS_TEMPLATE_DIR="$TMP_DIR/incomplete-templates" \
  "$TOOL" --namespace "$TMP_DIR/incomplete-namespace"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Required PKI template is missing or unsafe'
[[ ! -e $TMP_DIR/incomplete-namespace ]] || \
  fail 'incomplete templates created namespace state'

mkdir -p "$EXEC_DIR/failing-bin"
cat >"$EXEC_DIR/failing-bin/mv" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod 755 "$EXEC_DIR/failing-bin/mv"
run_command env PATH="$EXEC_DIR/failing-bin:$PATH" \
  "$TOOL" --namespace "$TMP_DIR/rename-failure"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'Failed to replace template:'
if find "$TMP_DIR/rename-failure" -name '.platform-pki-init.*' -print -quit | \
  grep -q .; then
  fail 'failed template replacement left a temporary file'
fi

mkdir -p "$EXEC_DIR/installed/bin" "$TMP_DIR/installed/share/lib" \
  "$TMP_DIR/installed/share/templates/pki"
cp "$TOOL" "$EXEC_DIR/installed/bin/"
cp "$ROOT_DIR/lib/platform-pki-common.sh" "$TMP_DIR/installed/share/lib/"
cp "$ROOT_DIR"/templates/pki/* "$TMP_DIR/installed/share/templates/pki/"
run_command env PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/installed/share" \
  "$EXEC_DIR/installed/bin/platform-pki-init" \
  --namespace "$TMP_DIR/installed-namespace"
assert_status 0
assert_empty "$STDERR"
[[ -f $TMP_DIR/installed-namespace/pki/inventory/services.yml.example ]] || \
  fail 'installed layout did not initialize inventory example'
[[ ! -e $TMP_DIR/installed-namespace/pki/inventory/services.yml ]] || \
  fail 'installed layout created active inventory'

mkdir -p "$EXEC_DIR/missing/bin" "$TMP_DIR/missing/share/lib"
cp "$TOOL" "$EXEC_DIR/missing/bin/"
cp "$ROOT_DIR/lib/platform-pki-common.sh" "$TMP_DIR/missing/share/lib/"
run_command env PLATFORM_TOOLS_SHARE_DIR="$TMP_DIR/missing/share" \
  "$EXEC_DIR/missing/bin/platform-pki-init" \
  --namespace "$TMP_DIR/missing-namespace"
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'PKI templates not found'
[[ ! -e $TMP_DIR/missing-namespace ]] || fail 'missing templates created namespace state'

printf '%s\n' 'test-init.sh: ok'
