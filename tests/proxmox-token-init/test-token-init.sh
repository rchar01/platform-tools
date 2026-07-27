#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TOOL="$ROOT_DIR/bin/platform-proxmox-token-init"
VERSION=$(<"$ROOT_DIR/VERSION")
SOURCE_FAKE_BIN="$ROOT_DIR/tests/proxmox-token-init/fake-bin"
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/platform-proxmox-token-init.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

HOME_DIR="$TMP_DIR/home"
FAKE_BIN="$TMP_DIR/fake-bin"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
PVEUM_LOG="$TMP_DIR/pveum.log"
JQ_LOG="$TMP_DIR/jq.log"
SSH_LOG="$TMP_DIR/ssh.log"
LN_LOG="$TMP_DIR/ln.log"
MV_LOG="$TMP_DIR/mv.log"
SEQUENCE_LOG="$TMP_DIR/publication-sequence.log"
REAL_JQ=$(command -v jq)
REAL_LN=$(command -v ln)
REAL_MV=$(command -v mv)
REAL_STAT=$(command -v stat)
RUN_PATH=$FAKE_BIN
MISSING_PVEUM_BIN="$TMP_DIR/missing-pveum-bin"
STATUS=0

mkdir -p "$HOME_DIR" "$FAKE_BIN" "$MISSING_PVEUM_BIN"
chmod 700 "$HOME_DIR"
cp "$SOURCE_FAKE_BIN"/* "$FAKE_BIN/"
chmod 755 "$FAKE_BIN"/*
for command_name in awk bash basename cat chmod dirname mkdir mktemp rm; do
  "$REAL_LN" -s -- "$(command -v -- "$command_name")" "$FAKE_BIN/$command_name"
done
"$REAL_LN" -s -- "$(command -v -- bash)" "$MISSING_PVEUM_BIN/bash"

fail() {
  printf 'test-token-init.sh: %s\n' "$*" >&2
  exit 1
}

reset_fakes() {
  : >"$PVEUM_LOG"
  : >"$JQ_LOG"
  : >"$SSH_LOG"
  : >"$LN_LOG"
  : >"$MV_LOG"
  : >"$SEQUENCE_LOG"
}

run_tool() {
  : >"$STDOUT"
  : >"$STDERR"
  set +e
  HOME=$HOME_DIR PATH=$RUN_PATH \
    FAKE_PVEUM_LOG=$PVEUM_LOG FAKE_JQ_LOG=$JQ_LOG FAKE_SSH_LOG=$SSH_LOG \
    FAKE_LN_LOG=$LN_LOG FAKE_MV_LOG=$MV_LOG FAKE_SEQUENCE_LOG=$SEQUENCE_LOG \
    REAL_JQ=$REAL_JQ REAL_LN=$REAL_LN REAL_MV=$REAL_MV REAL_STAT=$REAL_STAT \
    FAKE_USER_EXISTS=${FAKE_USER_EXISTS:-0} \
    FAKE_TOKEN_EXISTS=${FAKE_TOKEN_EXISTS:-0} \
    FAKE_EXPECTED_USER=${FAKE_EXPECTED_USER:-tofu@pve} \
    FAKE_EXPECTED_TOKEN_ID=${FAKE_EXPECTED_TOKEN_ID:-platform} \
    FAKE_FULL_TOKEN=${FAKE_FULL_TOKEN:-} \
    FAKE_TOKEN_SECRET=${FAKE_TOKEN_SECRET:-12345678-1234-1234-1234-123456789abc} \
    FAKE_INVALID_JSON=${FAKE_INVALID_JSON:-0} \
    FAKE_TOKEN_ADD_FAIL=${FAKE_TOKEN_ADD_FAIL:-0} \
    FAKE_TOKEN_RACE_PATH=${FAKE_TOKEN_RACE_PATH:-} \
    FAKE_TOKEN_RACE_EMPTY=${FAKE_TOKEN_RACE_EMPTY:-0} \
    FAKE_TOKEN_RACE_SYMLINK_TARGET=${FAKE_TOKEN_RACE_SYMLINK_TARGET:-} \
    FAKE_TOKEN_REPLACE_PATH=${FAKE_TOKEN_REPLACE_PATH:-} \
    FAKE_ACL_FAIL=${FAKE_ACL_FAIL:-0} \
    FAKE_REMOTE_CHECK_STATUS=${FAKE_REMOTE_CHECK_STATUS:-0} \
    FAKE_REMOTE_CHECK_ERROR=${FAKE_REMOTE_CHECK_ERROR:-} \
    FAKE_SSH_PROTOCOL_FAIL=${FAKE_SSH_PROTOCOL_FAIL:-0} \
    FAKE_MV_FAIL=${FAKE_MV_FAIL:-0} \
    FAKE_MV_FAIL_PATH=${FAKE_MV_FAIL_PATH:-} \
    FAKE_SEQUENCE_PATH=${FAKE_SEQUENCE_PATH:-} \
    "$TOOL" "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

run_tool_without_pveum() {
  : >"$STDOUT"
  : >"$STDERR"
  set +e
  HOME=$HOME_DIR PATH=$MISSING_PVEUM_BIN "$TOOL" "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

assert_status() {
  [[ $STATUS -eq $1 ]] || fail "line ${BASH_LINENO[0]}: expected status $1, got $STATUS; stdout: $(<"$STDOUT"); stderr: $(<"$STDERR")"
}

assert_empty() {
  [[ ! -s $1 ]] || fail "expected empty output in $1: $(<"$1")"
}

assert_contains() {
  grep -Fq -- "$2" "$1" || fail "expected '$2' in $1: $(<"$1")"
}

assert_not_contains() {
  ! grep -Fq -- "$2" "$1" || fail "did not expect '$2' in $1: $(<"$1")"
}

assert_mode() {
  local actual
  actual=$(stat -c '%a' "$2")
  [[ $actual == "$1" ]] || fail "expected mode $1 for $2, got $actual"
}

assert_no_temp() {
  local path=$1 dir base
  dir=$(dirname -- "$path")
  base=$(basename -- "$path")
  ! compgen -G "$dir/.${base}.tmp.*" >/dev/null || fail "temporary token file remains beside $path"
}

reset_fakes
run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-proxmox-token-init --version | -v'
assert_contains "$STDOUT" '--proxmox-user, --user USERID'
assert_not_contains "$STDOUT" '--emit-token-line'
assert_empty "$STDERR"
assert_empty "$PVEUM_LOG"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-proxmox-token-init $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

# Bashly handles help/version only as leading global parser actions.
run_tool --help --unknown
assert_status 0
assert_contains "$STDOUT" 'Usage:'
run_tool --unknown --help
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'
run_tool --version --unknown
assert_status 0

run_tool --ssh
assert_status 1
assert_contains "$STDERR" '--ssh requires an argument'
run_tool --token-id=
assert_status 1
assert_contains "$STDERR" 'invalid option: --token-id='
run_tool --proxmox-user ''
assert_status 1
assert_contains "$STDERR" 'must not be empty'
run_tool positional
assert_status 1
assert_contains "$STDERR" 'invalid argument: positional'
assert_empty "$PVEUM_LOG"

run_tool_without_pveum
assert_status 1
assert_contains "$STDERR" 'pveum is required; run this on a Proxmox host, or use --ssh'

run_tool_without_pveum --check
assert_status 1
assert_contains "$STDERR" 'Local Proxmox marker missing: /etc/pve'
assert_contains "$STDERR" 'Local command missing: pveum'
assert_contains "$STDERR" 'One or more Proxmox token prerequisites are missing'

marker="$TMP_DIR/injected"
run_tool --ssh=-oProxyCommand=touch-bad --check
assert_status 1
assert_contains "$STDERR" '--ssh must not start with -'
assert_empty "$SSH_LOG"
run_tool --ssh "root@pve;touch $marker" --check
assert_status 0
assert_contains "$SSH_LOG" "ARG=root@pve\\;touch\\ $marker"
[[ ! -e $marker ]] || fail 'SSH destination content executed as shell code'
run_tool --comment $'safe\nunsafe' --check
assert_status 1
assert_contains "$STDERR" '--comment must not contain control characters'

# Local creation preserves exact pveum operand boundaries and last-value precedence.
reset_fakes
FAKE_EXPECTED_USER='second@pve'
FAKE_EXPECTED_TOKEN_ID='second-token'
run_tool --user first@pve --proxmox-user second@pve \
  --token-id first-token --token-id second-token \
  --role 'Custom Role' --path '/pool/a;still-one-arg' \
  --comment "automation; touch $marker"
assert_status 0
assert_contains "$PVEUM_LOG" 'ARG=second@pve'
assert_contains "$PVEUM_LOG" 'ARG=second-token'
assert_contains "$PVEUM_LOG" 'ARG=Custom\ Role'
assert_contains "$PVEUM_LOG" 'ARG=/pool/a\;still-one-arg'
assert_contains "$PVEUM_LOG" "ARG=automation\;\ touch\ $marker"
assert_contains "$STDOUT" 'second@pve!second-token=12345678-1234-1234-1234-123456789abc'
[[ ! -e $marker ]] || fail 'pveum argument content executed as shell code'

# jq is optional for manual output; pveum emits its one-time output directly.
NO_JQ_BIN="$TMP_DIR/no-jq-bin"
mkdir "$NO_JQ_BIN"
ln -s "$FAKE_BIN/pveum" "$NO_JQ_BIN/pveum"
for command_name in awk bash cat; do
  ln -s "$(command -v "$command_name")" "$NO_JQ_BIN/$command_name"
done
reset_fakes
RUN_PATH=$NO_JQ_BIN
FAKE_EXPECTED_USER='tofu@pve'
FAKE_EXPECTED_TOKEN_ID='platform'
run_tool
RUN_PATH=$FAKE_BIN
assert_status 0
assert_empty "$JQ_LOG"
assert_contains "$STDOUT" '"full-tokenid":"tofu@pve!platform"'
assert_contains "$STDERR" 'Install jq before running this helper if you want it to write the token file automatically.'

# Existing identities are not recreated, but the exact ACL is still ensured.
reset_fakes
FAKE_EXPECTED_USER='tofu@pve'
FAKE_EXPECTED_TOKEN_ID='platform'
FAKE_USER_EXISTS=1
FAKE_TOKEN_EXISTS=1
run_tool
assert_status 0
assert_contains "$STDOUT" '[OK] User already exists: tofu@pve'
assert_contains "$STDERR" 'already exists. Proxmox cannot show the existing secret'
assert_not_contains "$PVEUM_LOG" 'ARG=add'
assert_contains "$PVEUM_LOG" 'ARG=aclmod'
FAKE_USER_EXISTS=0
FAKE_TOKEN_EXISTS=0

# Automatic local file output is private, mode-correct, and atomic.
reset_fakes
token_file="$HOME_DIR/tokens/proxmox.token"
run_tool --write-token-file "$token_file"
assert_status 0
[[ $(<"$token_file") == 'tofu@pve!platform=12345678-1234-1234-1234-123456789abc' ]] || fail 'unexpected token file content'
assert_mode 700 "$(dirname "$token_file")"
assert_mode 600 "$token_file"
assert_contains "$LN_LOG" 'SOURCE_MODE=600'
assert_contains "$LN_LOG" "DESTINATION=$token_file"
assert_empty "$MV_LOG"
assert_not_contains "$STDOUT" '12345678-1234-1234-1234-123456789abc'
assert_not_contains "$STDERR" '12345678-1234-1234-1234-123456789abc'
assert_no_temp "$token_file"

printf '%s\n' 'keep existing' >"$token_file"
reset_fakes
run_tool --write-token-file "$token_file"
assert_status 1
assert_contains "$STDERR" 'Refusing to overwrite non-empty token file before creating'
[[ $(<"$token_file") == 'keep existing' ]] || fail 'non-empty token file changed without --force'
assert_empty "$PVEUM_LOG"

reset_fakes
FAKE_SEQUENCE_PATH=$token_file
run_tool --write-token-file "$token_file" --force
FAKE_SEQUENCE_PATH=''
assert_status 0
[[ $(<"$token_file") == 'tofu@pve!platform=12345678-1234-1234-1234-123456789abc' ]] || fail '--force did not replace token file'
assert_mode 600 "$token_file"
assert_contains "$MV_LOG" 'SOURCE_MODE=600'
assert_contains "$MV_LOG" "DESTINATION=$token_file"
mapfile -t publication_sequence <"$SEQUENCE_LOG"
sequence_count=${#publication_sequence[@]}
((sequence_count >= 2)) || fail 'forced publication sequence did not record final stat and mv'
[[ ${publication_sequence[sequence_count - 2]} == "STAT $token_file" ]] || fail 'destination identity recheck was not immediately before mv'
[[ ${publication_sequence[sequence_count - 1]} == "MV $token_file" ]] || fail 'mv did not immediately follow destination identity recheck'

race_file="$HOME_DIR/tokens/race.token"
reset_fakes
FAKE_TOKEN_RACE_PATH=$race_file
run_tool --write-token-file "$race_file"
FAKE_TOKEN_RACE_PATH=''
assert_status 1
[[ $(<"$race_file") == 'concurrent token file' ]] || fail 'concurrent token file was overwritten'
assert_contains "$STDERR" 'Refusing to replace token file created concurrently'
assert_contains "$LN_LOG" 'SOURCE_MODE=600'
assert_empty "$MV_LOG"
assert_no_temp "$race_file"

empty_race_file="$HOME_DIR/tokens/empty-race.token"
reset_fakes
FAKE_TOKEN_RACE_PATH=$empty_race_file
FAKE_TOKEN_RACE_EMPTY=1
run_tool --write-token-file "$empty_race_file"
FAKE_TOKEN_RACE_PATH=''
FAKE_TOKEN_RACE_EMPTY=0
assert_status 1
[[ -f $empty_race_file && ! -s $empty_race_file ]] || fail 'concurrent empty token file was changed'
assert_contains "$STDERR" 'Refusing to replace token file created concurrently'
assert_contains "$LN_LOG" 'SOURCE_MODE=600'
assert_empty "$MV_LOG"
assert_no_temp "$empty_race_file"

force_race_file="$HOME_DIR/tokens/force-race.token"
reset_fakes
FAKE_TOKEN_RACE_PATH=$force_race_file
run_tool --write-token-file "$force_race_file" --force
FAKE_TOKEN_RACE_PATH=''
assert_status 1
[[ $(<"$force_race_file") == 'concurrent token file' ]] || fail '--force overwrote a concurrent non-empty token file absent at preflight'
assert_contains "$STDERR" 'Refusing to replace token file created concurrently'
assert_contains "$LN_LOG" 'SOURCE_MODE=600'
assert_empty "$MV_LOG"
assert_not_contains "$STDOUT" '12345678-1234-1234-1234-123456789abc'
assert_not_contains "$STDERR" '12345678-1234-1234-1234-123456789abc'
assert_no_temp "$force_race_file"

force_empty_race_file="$HOME_DIR/tokens/force-empty-race.token"
reset_fakes
FAKE_TOKEN_RACE_PATH=$force_empty_race_file
FAKE_TOKEN_RACE_EMPTY=1
run_tool --write-token-file "$force_empty_race_file" --force
FAKE_TOKEN_RACE_PATH=''
FAKE_TOKEN_RACE_EMPTY=0
assert_status 1
[[ -f $force_empty_race_file && ! -s $force_empty_race_file ]] || fail '--force changed a concurrent empty token file absent at preflight'
assert_contains "$STDERR" 'Refusing to replace token file created concurrently'
assert_contains "$LN_LOG" 'SOURCE_MODE=600'
assert_empty "$MV_LOG"
assert_no_temp "$force_empty_race_file"

force_symlink_target="$HOME_DIR/tokens/force-symlink-target"
force_symlink_race_file="$HOME_DIR/tokens/force-symlink-race.token"
printf '%s\n' 'foreign symlink target' >"$force_symlink_target"
reset_fakes
FAKE_TOKEN_RACE_PATH=$force_symlink_race_file
FAKE_TOKEN_RACE_SYMLINK_TARGET=$force_symlink_target
run_tool --write-token-file "$force_symlink_race_file" --force
FAKE_TOKEN_RACE_PATH=''
FAKE_TOKEN_RACE_SYMLINK_TARGET=''
assert_status 1
[[ -L $force_symlink_race_file ]] || fail '--force replaced a concurrent symlink absent at preflight'
[[ $(<"$force_symlink_target") == 'foreign symlink target' ]] || fail '--force changed a concurrent symlink target'
assert_contains "$STDERR" 'Refusing to replace token file created concurrently'
assert_contains "$LN_LOG" 'SOURCE_MODE=600'
assert_empty "$MV_LOG"
assert_no_temp "$force_symlink_race_file"

forced_identity_file="$HOME_DIR/tokens/forced-identity.token"
printf '%s\n' 'original forced file' >"$forced_identity_file"
reset_fakes
FAKE_TOKEN_REPLACE_PATH=$forced_identity_file
run_tool --write-token-file "$forced_identity_file" --force
FAKE_TOKEN_REPLACE_PATH=''
assert_status 1
[[ $(<"$forced_identity_file") == 'foreign replacement' ]] || fail 'foreign forced-file transition was overwritten'
assert_contains "$STDERR" 'Token file changed after preflight; refusing to replace it'
assert_empty "$MV_LOG"
assert_not_contains "$STDOUT" '12345678-1234-1234-1234-123456789abc'
assert_not_contains "$STDERR" '12345678-1234-1234-1234-123456789abc'
assert_no_temp "$forced_identity_file"

printf '%s\n' 'original token file' >"$token_file"
reset_fakes
FAKE_MV_FAIL=1
FAKE_MV_FAIL_PATH=$token_file
run_tool --write-token-file "$token_file" --force
FAKE_MV_FAIL=0
FAKE_MV_FAIL_PATH=''
assert_status 1
[[ $(<"$token_file") == 'original token file' ]] || fail 'failed atomic publication lost the original token file'
assert_contains "$STDERR" 'Failed to publish token file'
assert_no_temp "$token_file"

link_target="$HOME_DIR/tokens/link-target"
printf '%s\n' 'link target' >"$link_target"
ln -s "$link_target" "$HOME_DIR/tokens/link.token"
reset_fakes
run_tool --write-token-file "$HOME_DIR/tokens/link.token" --force
assert_status 1
assert_contains "$STDERR" 'Token file must not be a symbolic link'
[[ $(<"$link_target") == 'link target' ]] || fail 'token symlink target was modified'
assert_empty "$PVEUM_LOG"

# Invalid or failed JSON token creation never prints the one-time secret.
secret='abcdefab-cdef-abcd-efab-cdefabcdefab'
FAKE_TOKEN_SECRET=$secret
FAKE_INVALID_JSON=1
reset_fakes
run_tool --write-token-file "$HOME_DIR/tokens/invalid-json.token"
assert_status 0
assert_not_contains "$STDOUT" "$secret"
assert_not_contains "$STDERR" "$secret"
assert_contains "$STDERR" 'Refusing to print raw pveum output'
[[ ! -e $HOME_DIR/tokens/invalid-json.token ]] || fail 'invalid JSON produced a token file'
assert_contains "$PVEUM_LOG" 'ARG=aclmod'
FAKE_INVALID_JSON=0

FAKE_TOKEN_ADD_FAIL=1
reset_fakes
run_tool --write-token-file "$HOME_DIR/tokens/failed-token.token"
assert_status 1
assert_not_contains "$STDOUT" "$secret"
assert_not_contains "$STDERR" "$secret"
assert_contains "$STDERR" 'Refusing to print failed pveum JSON output'
assert_not_contains "$PVEUM_LOG" 'ARG=aclmod'
FAKE_TOKEN_ADD_FAIL=0

FAKE_FULL_TOKEN='other@pve!platform'
reset_fakes
run_tool --write-token-file "$HOME_DIR/tokens/mismatch.token"
assert_status 1
assert_contains "$STDERR" 'Generated Proxmox token ID mismatch'
assert_not_contains "$STDERR" "$secret"
assert_not_contains "$PVEUM_LOG" 'ARG=aclmod'
FAKE_FULL_TOKEN=''
FAKE_TOKEN_SECRET='12345678-1234-1234-1234-123456789abc'

# SSH check mode requires remote jq only for automatic token capture.
unsafe_parent="$HOME_DIR/unsafe-check-parent"
mkdir "$unsafe_parent"
chmod 720 "$unsafe_parent"
reset_fakes
run_tool --ssh root@pve.example --write-token-file "$unsafe_parent/token" --check
assert_status 1
assert_contains "$STDERR" 'Token file directory must not be writable by group or other users'
[[ ! -e $unsafe_parent/token ]] || fail '--check created a token under an unsafe parent'

unsafe_operation_parent="$HOME_DIR/unsafe-operation-parent"
mkdir "$unsafe_operation_parent"
chmod 720 "$unsafe_operation_parent"
reset_fakes
run_tool --write-token-file "$unsafe_operation_parent/token"
assert_status 1
assert_contains "$STDERR" 'Token file directory must not be writable by group or other users'
assert_empty "$PVEUM_LOG"

check_parent_target="$HOME_DIR/check-parent-target"
mkdir "$check_parent_target"
chmod 700 "$check_parent_target"
ln -s "$check_parent_target" "$HOME_DIR/check-parent-link"
reset_fakes
run_tool --ssh root@pve.example --write-token-file "$HOME_DIR/check-parent-link/token" --check
assert_status 1
assert_contains "$STDERR" 'Token file directory must not be a symbolic link'

printf '%s\n' 'not a directory' >"$HOME_DIR/check-parent-file"
reset_fakes
run_tool --ssh root@pve.example --write-token-file "$HOME_DIR/check-parent-file/token" --check
assert_status 1
assert_contains "$STDERR" 'Token file directory is not a directory'

reset_fakes
run_tool --ssh root@pve.example --check
assert_status 0
assert_contains "$SSH_LOG" 'REQUIRE_JQ=false'
assert_not_contains "$STDOUT" 'Remote command available: jq'

run_tool --ssh root@pve.example --write-token-file "$HOME_DIR/tokens/check.token" --check
assert_status 0
assert_contains "$SSH_LOG" 'REQUIRE_JQ=true'
assert_contains "$STDOUT" 'Remote command available: jq'
[[ ! -e $HOME_DIR/tokens/check.token ]] || fail '--check created a token file'
assert_empty "$PVEUM_LOG"

FAKE_REMOTE_CHECK_STATUS=1
FAKE_REMOTE_CHECK_ERROR='[ERROR] Remote command missing: pveum'
run_tool --ssh root@pve.example --check
assert_status 1
assert_contains "$STDERR" 'Remote command missing: pveum'
assert_contains "$STDERR" 'One or more Proxmox token prerequisites are missing'

FAKE_REMOTE_CHECK_ERROR='[ERROR] Remote command missing: jq'
run_tool --ssh root@pve.example --write-token-file "$HOME_DIR/tokens/check.token" --check
assert_status 1
assert_contains "$STDERR" 'Remote command missing: jq'
FAKE_REMOTE_CHECK_STATUS=0
FAKE_REMOTE_CHECK_ERROR=''

# The generated executable self-streams, and remote shell metacharacters stay in operands.
reset_fakes
remote_file="$HOME_DIR/tokens/remote.token"
remote_marker="$TMP_DIR/remote-injected"
run_tool --ssh root@pve.example --write-token-file "$remote_file" \
  --role 'Remote Role' --path '/remote;path' --comment "remote; touch $remote_marker"
assert_status 0
[[ $(<"$remote_file") == 'tofu@pve!platform=12345678-1234-1234-1234-123456789abc' ]] || fail 'remote token was not written locally'
assert_mode 600 "$remote_file"
assert_contains "$SSH_LOG" 'ARG=bash\ -s\ --'
assert_contains "$PVEUM_LOG" 'ARG=Remote\ Role'
assert_contains "$PVEUM_LOG" 'ARG=/remote\;path'
assert_contains "$PVEUM_LOG" "ARG=remote\;\ touch\ $remote_marker"
assert_not_contains "$STDOUT" '12345678-1234-1234-1234-123456789abc'
[[ ! -e $remote_marker ]] || fail 'remote argument content executed as shell code'

FAKE_SSH_PROTOCOL_FAIL=1
reset_fakes
run_tool --ssh root@pve.example --write-token-file "$HOME_DIR/tokens/remote-fail.token"
assert_status 1
assert_contains "$STDERR" 'PLATFORM_PROXMOX_TOKEN_LINE=<redacted>'
assert_not_contains "$STDERR" '12345678-1234-1234-1234-123456789abc'
assert_contains "$STDERR" 'Remote Proxmox token bootstrap failed'
[[ ! -e $HOME_DIR/tokens/remote-fail.token ]] || fail 'remote failure created a token file'
FAKE_SSH_PROTOCOL_FAIL=0

printf '%s\n' 'test-token-init.sh: ok'
