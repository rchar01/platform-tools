#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-backup-cli.XXXXXX)
EXEC_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-backup-cli-exec.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$EXEC_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-pki-backup"
VERSION=$(<"$ROOT_DIR/VERSION")
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
STATUS=0

fail() {
  printf 'test-backup-cli.sh: %s\n' "$*" >&2
  exit 1
}

run_command() {
  set +e
  "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
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

latest_encrypted_backup() {
  local backup_dir=$1
  local -a backups

  shopt -s nullglob
  backups=("$backup_dir"/platform-pki-*.tar.gz.age)
  shopt -u nullglob
  (( ${#backups[@]} > 0 )) || fail "no encrypted backup in $backup_dir"
  printf '%s\n' "${backups[${#backups[@]} - 1]}"
}

latest_plain_backup() {
  local backup_dir=$1
  local -a backups

  shopt -s nullglob
  backups=("$backup_dir"/platform-pki-*.tar.gz)
  shopt -u nullglob
  (( ${#backups[@]} > 0 )) || fail "no plain backup in $backup_dir"
  printf '%s\n' "${backups[${#backups[@]} - 1]}"
}

run_command "$TOOL" --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-pki-backup --version | -v'
assert_empty "$STDERR"

run_command "$TOOL" --version
assert_status 0
[[ $(<"$STDOUT") == "platform-pki-backup $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_command "$TOOL" --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_command "$TOOL" --backup-dir ''
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'must not be empty'

run_command "$TOOL" --namespace "$TMP_DIR/order" --help
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --help'

mkdir -p "$TMP_DIR/pki/inventory" "$EXEC_DIR/fake-bin"
printf '%s\n' 'services: {}' >"$TMP_DIR/pki/inventory/services.yml"
printf '%s\n' 'private state sentinel' >"$TMP_DIR/pki/private-state"

cat >"$EXEC_DIR/fake-bin/age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output=''
input=''
for arg in "$@"; do
  printf '<%s>\n' "$arg" >>"$AGE_LOG"
done
while [[ $# -gt 0 ]]; do
  case $1 in
    -r) shift 2 ;;
    -o) output=$2; shift 2 ;;
    -p) shift ;;
    *) input=$1; shift ;;
  esac
done
[[ -n $output && -n $input ]]
cp "$input" "$output"
if [[ ${AGE_FAIL:-0} == 1 ]]; then
  printf '%s\n' 'partial encrypted output' >"$output"
  exit 1
fi
EOF
chmod 755 "$EXEC_DIR/fake-bin/age"

recipient_backup="$TMP_DIR/recipient-backups"
literal_recipient="age1\$(touch $TMP_DIR/injected)"
: >"$TMP_DIR/recipient-age.log"
run_command env PATH="$EXEC_DIR/fake-bin:$PATH" \
  AGE_LOG="$TMP_DIR/recipient-age.log" \
  "$TOOL" --namespace "$TMP_DIR/namespace" --pki-dir "$TMP_DIR/pki" \
  --backup-dir "$recipient_backup" \
  --age-recipient age1first --age-recipient "$literal_recipient"
assert_status 0
assert_contains "$STDOUT" '[OK] Created encrypted PKI backup:'
assert_contains "$STDERR" 'PKI backup contains secrets'
assert_contains "$TMP_DIR/recipient-age.log" '<-r>'
assert_contains "$TMP_DIR/recipient-age.log" '<age1first>'
assert_contains "$TMP_DIR/recipient-age.log" "<$literal_recipient>"
[[ ! -e $TMP_DIR/injected ]] || fail 'recipient value executed shell content'
recipient_archive=$(latest_encrypted_backup "$recipient_backup")
[[ $(stat -c '%a' "$recipient_archive") == 600 ]] || fail 'encrypted backup mode is not 600'
tar -tzf "$recipient_archive" | grep -F 'pki/private-state' >/dev/null || \
  fail 'encrypted backup input did not contain PKI state'

passphrase_backup="$TMP_DIR/passphrase-backups"
: >"$TMP_DIR/passphrase-age.log"
run_command env PATH="$EXEC_DIR/fake-bin:$PATH" \
  AGE_LOG="$TMP_DIR/passphrase-age.log" \
  "$TOOL" --namespace "$TMP_DIR/namespace" --pki-dir "$TMP_DIR/pki" \
  --backup-dir "$passphrase_backup"
assert_status 0
assert_contains "$TMP_DIR/passphrase-age.log" '<-p>'
passphrase_archive=$(latest_encrypted_backup "$passphrase_backup")
[[ $(stat -c '%a' "$passphrase_archive") == 600 ]] || fail 'passphrase backup mode is not 600'

plain_backup="$TMP_DIR/plain-backups"
run_command "$TOOL" --namespace "$TMP_DIR/namespace" \
  --pki-dir "$TMP_DIR/pki" --backup-dir "$plain_backup" \
  --allow-plain-backup
assert_status 0
assert_contains "$STDERR" 'Created unencrypted PKI backup'
plain_archive=$(latest_plain_backup "$plain_backup")
[[ $(stat -c '%a' "$plain_archive") == 600 ]] || fail 'plain backup mode is not 600'

failure_backup="$TMP_DIR/failure-backups"
: >"$TMP_DIR/failure-age.log"
run_command env PATH="$EXEC_DIR/fake-bin:$PATH" AGE_FAIL=1 \
  AGE_LOG="$TMP_DIR/failure-age.log" \
  "$TOOL" --namespace "$TMP_DIR/namespace" --pki-dir "$TMP_DIR/pki" \
  --backup-dir "$failure_backup" --age-recipient age1failure
assert_status 1
assert_empty "$STDOUT"
if [[ -d $failure_backup ]] && \
  find "$failure_backup" -mindepth 1 -print -quit | grep -q .; then
  fail 'failed age command left temporary plaintext or encrypted output'
fi

mkdir -p "$EXEC_DIR/collision-bin"
cp "$EXEC_DIR/fake-bin/age" "$EXEC_DIR/collision-bin/age"
cat >"$EXEC_DIR/collision-bin/date" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '20260726-120000'
EOF
cat >"$EXEC_DIR/collision-bin/ln" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if [[ ! -e $COLLISION_MARKER ]]; then
  printf '%s\n' 'concurrent backup sentinel' >"$target"
  : >"$COLLISION_MARKER"
  exit 1
fi
exec "$REAL_LN" "$@"
EOF
chmod 755 "$EXEC_DIR/collision-bin/date" "$EXEC_DIR/collision-bin/ln"
collision_backup="$TMP_DIR/collision-backups"
mkdir -p "$collision_backup"
: >"$TMP_DIR/collision-age.log"
real_ln=$(command -v ln)
run_command env PATH="$EXEC_DIR/collision-bin:$PATH" \
  AGE_LOG="$TMP_DIR/collision-age.log" \
  COLLISION_MARKER="$TMP_DIR/collision-marker" REAL_LN="$real_ln" \
  "$TOOL" --namespace "$TMP_DIR/namespace" --pki-dir "$TMP_DIR/pki" \
  --backup-dir "$collision_backup" --age-recipient age1collision
assert_status 0
[[ $(<"$collision_backup/platform-pki-20260726-120000.tar.gz.age") == \
  'concurrent backup sentinel' ]] || fail 'concurrent backup was overwritten'
[[ -f $collision_backup/platform-pki-20260726-120000-01.tar.gz.age ]] || \
  fail 'colliding backup was not published with a distinct name'
[[ $(stat -c '%a' "$collision_backup/platform-pki-20260726-120000-01.tar.gz.age") == 600 ]] || \
  fail 'collision backup mode is not 600'

printf '%s\n' 'test-backup-cli.sh: ok'
