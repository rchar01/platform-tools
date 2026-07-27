#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TOOL="$ROOT_DIR/bin/platform-proxmox-vm-cleanup"
VERSION=$(<"$ROOT_DIR/VERSION")
SOURCE_FAKE_BIN="$ROOT_DIR/tests/proxmox-vm-cleanup/fake-bin"
PTY_RUNNER="$ROOT_DIR/tests/proxmox-vm-cleanup/pty-runner.py"
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/platform-proxmox-vm-cleanup.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

FAKE_BIN="$TMP_DIR/fake-bin"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
QM_LOG="$TMP_DIR/qm.log"
QM_OPERATION_LOG="$TMP_DIR/qm-operations.log"
SSH_LOG="$TMP_DIR/ssh.log"
AUTH_DIR="$TMP_DIR/authorizations"
REAL_MV=$(command -v mv)
REAL_LN=$(command -v ln)
REAL_RM=$(command -v rm)
REAL_BASH=$(command -v bash)
REAL_STAT=$(command -v stat)
REMOTE_CHILD_ARGV_LOG="$TMP_DIR/remote-child-argv.log"
FD_LOG="$TMP_DIR/fd.log"
STATUS=0
mkdir "$FAKE_BIN"
cp "$SOURCE_FAKE_BIN"/* "$FAKE_BIN/"
chmod 755 "$FAKE_BIN"/*

fail() {
  printf 'test-cleanup.sh: %s\n' "$*" >&2
  exit 1
}

reset_fakes() {
  : >"$QM_LOG"
  : >"$QM_OPERATION_LOG"
  : >"$SSH_LOG"
  : >"$REMOTE_CHILD_ARGV_LOG"
  : >"$FD_LOG"
}

run_tool() {
  : >"$STDOUT"
  : >"$STDERR"
  TOKEN_FD_INPUT="$TMP_DIR/token-fd-input"
  if [[ ${PRIVATE_AUTH_RAW_SET:-0} == 1 ]]; then
    printf '%s' "${PRIVATE_AUTH_RAW_PAYLOAD:-}" >"$TOKEN_FD_INPUT"
  else
    printf '%s\n' "${PRIVATE_AUTH_TOKEN:-}" >"$TOKEN_FD_INPUT"
  fi
  set +e
  PATH="$FAKE_BIN:$PATH" FAKE_QM_LOG="$QM_LOG" FAKE_QM_OPERATION_LOG="$QM_OPERATION_LOG" \
    FAKE_SSH_LOG="$SSH_LOG" FAKE_VM_EXISTS=${FAKE_VM_EXISTS:-1} \
    FAKE_VM_MISSING_AT=${FAKE_VM_MISSING_AT:-} FAKE_VM_STATUS=${FAKE_VM_STATUS:-stopped} \
    FAKE_QM_STATUS_OUTPUT=${FAKE_QM_STATUS_OUTPUT:-} \
    FAKE_QM_STATUS_OUTPUT_AT_2=${FAKE_QM_STATUS_OUTPUT_AT_2:-} \
    FAKE_QM_STATUS_OUTPUT_AT_3=${FAKE_QM_STATUS_OUTPUT_AT_3:-} \
    FAKE_QM_STATUS_OUTPUT_AT_4=${FAKE_QM_STATUS_OUTPUT_AT_4:-} \
    FAKE_QM_STATUS_ERROR_AT=${FAKE_QM_STATUS_ERROR_AT:-} \
    FAKE_QM_STATUS_ERROR=${FAKE_QM_STATUS_ERROR:-} \
    FAKE_VM_NAME=${FAKE_VM_NAME:-fixture-vm} FAKE_VM_NAME_AT_2=${FAKE_VM_NAME_AT_2:-} \
    FAKE_VM_NAME_AT_3=${FAKE_VM_NAME_AT_3:-} FAKE_VM_NAME_AT_4=${FAKE_VM_NAME_AT_4:-} \
    FAKE_CONFIG_MEMORY_AT_3=${FAKE_CONFIG_MEMORY_AT_3:-} \
    FAKE_POST_STOP_STATUS=${FAKE_POST_STOP_STATUS:-stopped} \
    FAKE_CONFIG_HAS_NAME=${FAKE_CONFIG_HAS_NAME:-1} \
    FAKE_CONFIG_DUPLICATE_NAME=${FAKE_CONFIG_DUPLICATE_NAME:-0} \
    FAKE_QM_CONFIG_ERROR_AT=${FAKE_QM_CONFIG_ERROR_AT:-} \
    FAKE_QM_CONFIG_ERROR=${FAKE_QM_CONFIG_ERROR:-} \
    FAKE_DESTROY_SUPPORTS_UNREFERENCED=${FAKE_DESTROY_SUPPORTS_UNREFERENCED:-1} \
    FAKE_DESTROY_PROBE_INVALID=${FAKE_DESTROY_PROBE_INVALID:-0} \
    FAKE_QM_FAIL_OPERATION=${FAKE_QM_FAIL_OPERATION:-} \
    FAKE_QM_FAIL_TARGET_DESTROY=${FAKE_QM_FAIL_TARGET_DESTROY:-0} \
    FAKE_QM_FAIL_STATUS=${FAKE_QM_FAIL_STATUS:-42} \
    FAKE_SSH_FAIL_INSPECT=${FAKE_SSH_FAIL_INSPECT:-0} \
    FAKE_SSH_FAIL_DESTROY=${FAKE_SSH_FAIL_DESTROY:-0} \
    FAKE_AUTH_REPLACE_ON_MV=${FAKE_AUTH_REPLACE_ON_MV:-0} REAL_MV="$REAL_MV" \
    FAKE_AUTH_INTERRUPT_AFTER_LINK=${FAKE_AUTH_INTERRUPT_AFTER_LINK:-0} \
    FAKE_AUTH_INTERRUPT_AFTER_UNLINK=${FAKE_AUTH_INTERRUPT_AFTER_UNLINK:-0} \
    FAKE_AUTH_INTERRUPT_AFTER_MV=${FAKE_AUTH_INTERRUPT_AFTER_MV:-0} \
    REAL_LN="$REAL_LN" REAL_RM="$REAL_RM" REAL_BASH="$REAL_BASH" \
    REAL_STAT="$REAL_STAT" FAKE_REQUIRE_FD3_CLOSED=${FAKE_REQUIRE_FD3_CLOSED:-0} \
    FAKE_FD_LOG="$FD_LOG" \
    FAKE_REMOTE_CHILD_ARGV_LOG="$REMOTE_CHILD_ARGV_LOG" \
    PLATFORM_VM_CLEANUP_AUTH_DIR="$AUTH_DIR" \
    "$TOOL" "$@" 3<"$TOKEN_FD_INPUT" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

run_tool_tty() {
  : >"$STDOUT"
  : >"$STDERR"
  set +e
  PATH="$FAKE_BIN:$PATH" FAKE_QM_LOG="$QM_LOG" FAKE_QM_OPERATION_LOG="$QM_OPERATION_LOG" \
    FAKE_SSH_LOG="$SSH_LOG" FAKE_VM_EXISTS=${FAKE_VM_EXISTS:-1} \
    FAKE_VM_STATUS=${FAKE_VM_STATUS:-stopped} FAKE_VM_NAME=${FAKE_VM_NAME:-fixture-vm} \
    FAKE_DESTROY_SUPPORTS_UNREFERENCED=${FAKE_DESTROY_SUPPORTS_UNREFERENCED:-1} \
    REAL_MV="$REAL_MV" REAL_LN="$REAL_LN" REAL_RM="$REAL_RM" REAL_BASH="$REAL_BASH" \
    REAL_STAT="$REAL_STAT" FAKE_REQUIRE_FD3_CLOSED=${FAKE_REQUIRE_FD3_CLOSED:-0} \
    FAKE_FD_LOG="$FD_LOG" \
    FAKE_REMOTE_CHILD_ARGV_LOG="$REMOTE_CHILD_ARGV_LOG" PLATFORM_VM_CLEANUP_AUTH_DIR="$AUTH_DIR" \
    PTY_INPUT=${PTY_INPUT-} PTY_EOF=${PTY_EOF:-0} \
    python3 "$PTY_RUNNER" "$TOOL" "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

assert_status() {
  [[ $STATUS -eq $1 ]] || fail "line ${BASH_LINENO[0]}: expected status $1, got $STATUS; stdout: $(<"$STDOUT"); stderr: $(<"$STDERR")"
}

assert_contains() {
  grep -Fq -- "$2" "$1" || fail "expected '$2' in $1: $(<"$1")"
}

assert_not_contains() {
  ! grep -Fq -- "$2" "$1" || fail "did not expect '$2' in $1: $(<"$1")"
}

assert_empty() {
  [[ ! -s $1 ]] || fail "expected empty $1: $(<"$1")"
}

assert_operations() {
  local expected=$1 actual
  actual=$(paste -sd ' ' "$QM_OPERATION_LOG")
  [[ $actual == "$expected" ]] || fail "expected qm operations '$expected', got '$actual'"
}

assert_no_mutation() {
  assert_not_contains "$QM_OPERATION_LOG" 'stop'
  target_destroy_count=$(grep -c '^ARG=101$' "$QM_LOG" || true)
  ! grep -A2 '^ARG=destroy$' "$QM_LOG" | grep -Fqx 'ARG=101' ||
    fail "unexpected VM-targeted destroy call: $(<"$QM_LOG")"
  : "$target_destroy_count"
}

authorization_token() {
  local line
  while IFS= read -r line; do
    case $line in PLATFORM_VM_CLEANUP_AUTHORIZATION=*) printf '%s\n' "${line#*=}"; return 0 ;; esac
  done <"$STDOUT"
  return 1
}

reset_fakes
run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-proxmox-vm-cleanup --version | -v'
assert_not_contains "$STDOUT" '--remote-inspect'
assert_not_contains "$STDOUT" '--remote-destroy'
assert_not_contains "$STDOUT" '--remote-cancel'
assert_not_contains "$STDOUT" '--authorization-token'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-proxmox-vm-cleanup $VERSION" ]] || fail 'unexpected version output'

# Leading global actions retain Bashly precedence; legacy interspersed help is
# accepted only when every preceding token is valid.
run_tool --help --unknown
assert_status 0
run_tool --unknown --help
assert_status 1
assert_contains "$STDERR" 'invalid option: --unknown'
run_tool --vmid 101 --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
run_tool --yes --ssh pve.example -h
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_empty "$SSH_LOG"
run_tool --vmid abc --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
run_tool --vmid --help
assert_status 1
assert_contains "$STDERR" 'must be numeric'
run_tool --unknown --vmid 101 --help
assert_status 1
assert_contains "$STDERR" 'invalid option: --unknown'
run_tool --ssh --help --vmid 101
assert_status 1
assert_contains "$STDERR" '--ssh must use host or user@host syntax'

reset_fakes
run_tool
assert_status 1
assert_contains "$STDERR" 'missing required flag: --vmid VMID'
run_tool --vmid=
assert_status 1
assert_contains "$STDERR" 'invalid option: --vmid='
run_tool --vmid 101 positional --yes
assert_status 1
assert_contains "$STDERR" 'invalid argument: positional'
assert_empty "$QM_LOG"

# Equals forms and duplicate scalar options retain last-value precedence.
reset_fakes
FAKE_VM_NAME=second run_tool --vmid=100 --vmid 101 --name=first --name second --yes
assert_status 0
assert_not_contains "$QM_LOG" 'ARG=100'
assert_contains "$STDOUT" 'name: second'

# SSH destinations accept only shell-safe host or user@host forms. IPv6 is not
# documented or accepted by this helper.
for unsafe_target in \
  '-oProxyCommand=touch-bad' 'root@pve.example extra' 'root@pve.example;touch-bad' \
  'root@@pve.example' 'root@' '@pve.example' 'bad_user!@pve.example' '[::1]'; do
  reset_fakes
  run_tool --ssh "$unsafe_target" --vmid 101 --yes
  assert_status 1
  assert_contains "$STDERR" '--ssh must use host or user@host syntax'
  assert_empty "$SSH_LOG"
  assert_empty "$QM_LOG"
done
reset_fakes
run_tool --ssh $'root@pve.example\n-oProxyCommand=bad' --vmid 101 --yes
assert_status 1
assert_empty "$SSH_LOG"
assert_empty "$QM_LOG"
marker="$TMP_DIR/ssh-injection-marker"
reset_fakes
run_tool --ssh="root@pve.example;touch $marker" --vmid 101 --yes
assert_status 1
[[ ! -e $marker ]] || fail 'hostile SSH destination executed shell content'
assert_empty "$SSH_LOG"
assert_empty "$QM_LOG"

reset_fakes
run_tool --ssh pve.example --vmid 101 --yes
assert_status 0
assert_contains "$SSH_LOG" 'ARG=pve.example'
reset_fakes
run_tool --ssh operator_1@pve-1.example --vmid 101 --yes
assert_status 0
assert_contains "$SSH_LOG" 'ARG=operator_1@pve-1.example'
reset_fakes
run_tool --ssh root@192.0.2.10 --vmid 101 --yes
assert_status 0
assert_contains "$SSH_LOG" 'ARG=root@192.0.2.10'

# qm status must be exactly running or stopped. Missing evidence is separated
# from diagnostics and exit status for other qm failures.
for status_output in 'status: paused' 'garbage' $'status: running\nextra'; do
  reset_fakes
  FAKE_QM_STATUS_OUTPUT=$status_output run_tool --vmid 101 --yes
  assert_status 1
  assert_contains "$STDERR" 'malformed or unsupported qm status'
  assert_operations 'status'
done

reset_fakes
FAKE_VM_EXISTS=0 run_tool --vmid 404 --yes
assert_status 1
assert_contains "$STDERR" 'VMID 404 does not exist'
assert_not_contains "$STDERR" 'permission denied'
assert_operations 'status'

reset_fakes
FAKE_QM_STATUS_ERROR_AT=1 FAKE_QM_STATUS_ERROR='permission denied by fake qm' run_tool --vmid 101 --yes
assert_status 42
assert_contains "$STDERR" 'permission denied by fake qm'
assert_not_contains "$STDERR" 'does not exist'
assert_operations 'status'

reset_fakes
FAKE_QM_CONFIG_ERROR_AT=1 run_tool --vmid 101 --yes
assert_status 42
assert_contains "$STDERR" 'simulated qm config failure'
assert_operations 'status config'

reset_fakes
FAKE_CONFIG_HAS_NAME=0 run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'no unique non-empty name'
assert_no_mutation
reset_fakes
FAKE_CONFIG_DUPLICATE_NAME=1 run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'no unique non-empty name'
assert_no_mutation

# Refused confirmation never performs the fresh inspection or destroy probe.
reset_fakes
run_tool --vmid 101 </dev/null
assert_status 1
assert_contains "$STDERR" 'Interactive confirmation requires a TTY'
assert_operations 'status config'
assert_no_mutation

reset_fakes
PTY_INPUT=wrong run_tool_tty --vmid 101
assert_status 1
assert_contains "$STDOUT" 'Confirmation did not match'
assert_operations 'status config'

reset_fakes
unset PTY_INPUT
PTY_EOF=1 run_tool_tty --vmid 101
assert_status 1
assert_contains "$STDOUT" 'Confirmation input unavailable; cleanup aborted'
assert_operations 'status config'
unset PTY_EOF

reset_fakes
PTY_INPUT=101 run_tool_tty --vmid 101
assert_status 0
assert_contains "$STDOUT" 'Type VMID 101 to destroy:'
assert_operations 'status config status config destroy status config destroy'

# State is re-inspected after confirmation. Drift or a fresh inspection error
# aborts before probing supported destroy argv or mutating the VM.
reset_fakes
FAKE_VM_NAME_AT_2=renamed-vm run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'name changed after inspection'
assert_operations 'status config status config'
assert_no_mutation

reset_fakes
FAKE_QM_STATUS_OUTPUT_AT_2='status: running' run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'status changed after inspection'
assert_operations 'status config status config'
assert_no_mutation

reset_fakes
FAKE_VM_MISSING_AT=2 run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'VMID 101 does not exist'
assert_operations 'status config status'
assert_no_mutation

reset_fakes
FAKE_QM_STATUS_ERROR_AT=2 FAKE_QM_STATUS_ERROR='second status permission failure' run_tool --vmid 101 --yes
assert_status 42
assert_contains "$STDERR" 'second status permission failure'
assert_operations 'status config status'
assert_no_mutation

# Capability probing is followed by another exact state/config check.
reset_fakes
FAKE_VM_NAME_AT_3=probe-window-rename run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'name changed after inspection'
assert_operations 'status config status config destroy status config'
assert_no_mutation

reset_fakes
FAKE_CONFIG_MEMORY_AT_3=4096 run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'configuration changed after inspection'
assert_operations 'status config status config destroy status config'
assert_no_mutation

# The complete supported destroy command is resolved before stop. The fake
# validates every target destroy operand and the operation log proves ordering.
reset_fakes
FAKE_VM_STATUS=stopped run_tool --vmid 101 --yes
assert_status 0
assert_operations 'status config status config destroy status config destroy'
assert_contains "$QM_LOG" 'ARG=--destroy-unreferenced-disks'

reset_fakes
FAKE_VM_STATUS=running run_tool --vmid 101 --yes
assert_status 0
assert_operations 'status config status config destroy status config stop status config destroy'

reset_fakes
FAKE_VM_STATUS=running FAKE_QM_STATUS_OUTPUT_AT_4='status: running' run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" "expected 'stopped', got 'running'"
assert_operations 'status config status config destroy status config stop status config'
assert_not_contains "$QM_LOG" 'ARG=--purge'

reset_fakes
FAKE_VM_STATUS=running FAKE_VM_NAME_AT_4=post-stop-rename run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'name changed after inspection'
assert_operations 'status config status config destroy status config stop status config'

reset_fakes
FAKE_VM_STATUS=running FAKE_DESTROY_SUPPORTS_UNREFERENCED=0 run_tool --vmid 101 --yes
assert_status 0
assert_operations 'status config status config destroy status config stop status config destroy'
assert_not_contains "$QM_LOG" 'ARG=--destroy-unreferenced-disks'

reset_fakes
FAKE_VM_STATUS=running FAKE_DESTROY_PROBE_INVALID=1 run_tool --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'Could not verify qm destroy --purge support'
assert_operations 'status config status config destroy'
assert_no_mutation

reset_fakes
FAKE_VM_STATUS=running FAKE_QM_FAIL_OPERATION=stop run_tool --vmid 101 --yes
assert_status 42
assert_operations 'status config status config destroy status config stop'
reset_fakes
FAKE_QM_FAIL_TARGET_DESTROY=1 run_tool --vmid 101 --yes
assert_status 42
assert_contains "$STDERR" 'simulated qm destroy failure'

# Inspection persists owner-only authorization on the Proxmox side and returns
# only a strong nonce. Destruction atomically consumes that server-side record.
rm -rf "$AUTH_DIR"
reset_fakes
run_tool --vmid 101 --remote-inspect
assert_status 0
token=$(authorization_token) || fail 'private inspection did not emit an authorization token'
[[ $token =~ ^[a-f0-9]{64}$ ]] || fail 'authorization token is not 256-bit hexadecimal'
auth_path="$AUTH_DIR/$token"
[[ $(stat -c '%a:%h' "$AUTH_DIR") == '700:2' ]] || fail 'authorization directory metadata is unsafe'
[[ $(stat -c '%a:%h' "$auth_path") == '600:1' ]] || fail 'authorization state metadata is unsafe'
assert_operations 'status config'

reset_fakes
run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'authorization input has an invalid shape'
assert_empty "$QM_LOG"
reset_fakes
PRIVATE_AUTH_TOKEN="${token}"$'\nextra' run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'must contain exactly one line'
assert_empty "$QM_LOG"

# Raw framing requires one newline-terminated token and clean EOF. A partial
# second line at EOF must not be mistaken for clean one-line framing.
reset_fakes
PRIVATE_AUTH_RAW_SET=1 PRIVATE_AUTH_RAW_PAYLOAD='' run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'unavailable or not newline-terminated'
assert_empty "$QM_LOG"
assert_empty "$FD_LOG"
reset_fakes
PRIVATE_AUTH_RAW_SET=1 PRIVATE_AUTH_RAW_PAYLOAD="$token" run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'unavailable or not newline-terminated'
assert_empty "$QM_LOG"
assert_empty "$FD_LOG"
reset_fakes
PRIVATE_AUTH_RAW_SET=1 PRIVATE_AUTH_RAW_PAYLOAD="${token}"$'\nextra' run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'trailing unterminated data'
assert_empty "$QM_LOG"
assert_empty "$FD_LOG"

run_tool --vmid 101 --remote-inspect
raw_valid_token=$(authorization_token)
reset_fakes
FAKE_REQUIRE_FD3_CLOSED=1 PRIVATE_AUTH_RAW_SET=1 \
  PRIVATE_AUTH_RAW_PAYLOAD="${raw_valid_token}"$'\n' run_tool --vmid 101 --remote-destroy
assert_status 0
assert_contains "$FD_LOG" 'stat FD3=closed'
assert_contains "$FD_LOG" 'mv FD3=closed'
assert_contains "$FD_LOG" 'qm FD3=closed'
assert_not_contains "$STDOUT" "$raw_valid_token"
assert_not_contains "$STDERR" "$raw_valid_token"

reset_fakes
PRIVATE_AUTH_TOKEN=$(printf '%064d' 0) run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'was not found or was already consumed'
assert_not_contains "$STDOUT" "$(printf '%064d' 0)"
assert_not_contains "$STDERR" "$(printf '%064d' 0)"
assert_empty "$QM_LOG"

# FD 3 is closed in the generated process before authorization stat/mv or qm.
run_tool --vmid 101 --remote-inspect
fd_token=$(authorization_token)
reset_fakes
FAKE_REQUIRE_FD3_CLOSED=1 PRIVATE_AUTH_TOKEN=$fd_token run_tool --vmid 101 --remote-destroy
assert_status 0
assert_contains "$FD_LOG" 'stat FD3=closed'
assert_contains "$FD_LOG" 'mv FD3=closed'
assert_contains "$FD_LOG" 'qm FD3=closed'
assert_not_contains "$STDOUT" "$fd_token"
assert_not_contains "$STDERR" "$fd_token"

# A hardlink invalidates exact nlink=1 authorization metadata.
ln "$auth_path" "$AUTH_DIR/hardlink-copy"
reset_fakes
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'mode 600 with one link'
assert_empty "$QM_LOG"
rm "$AUTH_DIR/hardlink-copy"
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-cancel
assert_status 0

# Copying state under a forged nonce cannot forge the nonce bound in content.
run_tool --vmid 101 --remote-inspect
assert_status 0
token=$(authorization_token)
auth_path="$AUTH_DIR/$token"
forged=$(printf 'f%.0s' {1..64})
cp "$auth_path" "$AUTH_DIR/$forged"
chmod 600 "$AUTH_DIR/$forged"
reset_fakes
PRIVATE_AUTH_TOKEN=$forged run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'nonce does not match its server-side state'
assert_empty "$QM_LOG"
[[ -f $auth_path ]] || fail 'forged authorization consumed the genuine state'
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-cancel
assert_status 0

# Exact mode, bounded age, and replacement identity are enforced.
run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
auth_path="$AUTH_DIR/$token"
chmod 640 "$auth_path"
reset_fakes
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'mode 600 with one link'
chmod 600 "$auth_path"
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-cancel

run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
auth_path="$AUTH_DIR/$token"
sed -i 's/^created=.*/created=1/' "$auth_path"
chmod 600 "$auth_path"
reset_fakes
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'has expired'
assert_empty "$QM_LOG"

# A later inspection removes expired valid records but preserves its current
# authorization until explicit cancellation or consume.
run_tool --vmid 101 --remote-inspect
stale_token=$(authorization_token)
stale_path="$AUTH_DIR/$stale_token"
sed -i 's/^created=.*/created=1/' "$stale_path"
chmod 600 "$stale_path"
run_tool --vmid 101 --remote-inspect
current_token=$(authorization_token)
[[ ! -e $stale_path ]] || fail 'expired authorization was not cleaned'
[[ -f $AUTH_DIR/$current_token ]] || fail 'current authorization was removed during stale cleanup'
PRIVATE_AUTH_TOKEN=$current_token run_tool --vmid 101 --remote-cancel
assert_status 0

run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
reset_fakes
FAKE_AUTH_REPLACE_ON_MV=1 PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'changed during consumption'
assert_empty "$QM_LOG"

# Interrupted publish link/unlink pairs remain current initially, then are
# reaped only after aging with exact nlink and inode-pair checks.
for interruption in LINK UNLINK; do
  reset_fakes
  if [[ $interruption == LINK ]]; then
    FAKE_AUTH_INTERRUPT_AFTER_LINK=1 run_tool --vmid 101 --remote-inspect
  else
    FAKE_AUTH_INTERRUPT_AFTER_UNLINK=1 run_tool --vmid 101 --remote-inspect
  fi
  assert_status 1
  pair_tmp=$(compgen -G "$AUTH_DIR/.tmp.*") || fail "missing interrupted $interruption temp artifact"
  pair_name=${pair_tmp##*/}
  pair_token=${pair_name#.tmp.}
  pair_token=${pair_token%%.*}
  pair_final="$AUTH_DIR/$pair_token"
  [[ $(stat -c '%a:%h:%d:%i' "$pair_tmp") == "600:2:$(stat -c '%d:%i' "$pair_tmp")" ]] ||
    fail "unsafe interrupted $interruption temp artifact"
  [[ $(stat -c '%d:%i' "$pair_tmp") == "$(stat -c '%d:%i' "$pair_final")" ]] ||
    fail "interrupted $interruption publish pair does not share identity"

  run_tool --vmid 101 --remote-inspect
  current_token=$(authorization_token)
  [[ -f $pair_tmp && -f $pair_final ]] || fail "current interrupted $interruption pair was reaped early"
  PRIVATE_AUTH_TOKEN=$current_token run_tool --vmid 101 --remote-cancel
  touch -d @1 "$pair_tmp" "$pair_final"
  run_tool --vmid 101 --remote-inspect
  current_token=$(authorization_token)
  [[ ! -e $pair_tmp && ! -e $pair_final ]] || fail "aged interrupted $interruption pair was not reaped"
  PRIVATE_AUTH_TOKEN=$current_token run_tool --vmid 101 --remote-cancel
done

# A consume rename interrupted after the atomic move leaves no reusable nonce;
# its owner-only consumed artifact is removed only after aging.
run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
reset_fakes
FAKE_AUTH_INTERRUPT_AFTER_MV=1 PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_empty "$QM_LOG"
[[ ! -e $AUTH_DIR/$token ]] || fail 'interrupted consume left reusable authorization state'
consumed_path=$(compgen -G "$AUTH_DIR/.consumed.${token}.*") || fail 'interrupted consume artifact missing'
[[ $(stat -c '%a:%h' "$consumed_path") == 600:1 ]] || fail 'interrupted consume artifact metadata is unsafe'
touch -d @1 "$consumed_path"
run_tool --vmid 101 --remote-inspect
current_token=$(authorization_token)
[[ ! -e $consumed_path ]] || fail 'aged consumed artifact was not reaped'
PRIVATE_AUTH_TOKEN=$current_token run_tool --vmid 101 --remote-cancel

# Aged foreign symlinks and metadata-incompatible regular files are untouched.
foreign_target="$TMP_DIR/foreign-authorization-target"
printf '%s\n' foreign >"$foreign_target"
foreign_nonce=$(printf 'e%.0s' {1..64})
foreign_link="$AUTH_DIR/.tmp.${foreign_nonce}.999"
ln -s "$foreign_target" "$foreign_link"
foreign_file="$AUTH_DIR/.consumed.${foreign_nonce}.999.1"
printf '%s\n' foreign >"$foreign_file"
chmod 640 "$foreign_file"
touch -d @1 "$foreign_file"
run_tool --vmid 101 --remote-inspect
current_token=$(authorization_token)
[[ -L $foreign_link && -f $foreign_file ]] || fail 'foreign authorization artifacts were removed'
PRIVATE_AUTH_TOKEN=$current_token run_tool --vmid 101 --remote-cancel
rm "$foreign_link" "$foreign_file"

# Conflicting arguments and stale inspected state fail after consume but before
# the capability probe or mutation.
run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
reset_fakes
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 102 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'conflicts with --vmid'
assert_empty "$QM_LOG"

run_tool --vmid 101 --name fixture-vm --remote-inspect
token=$(authorization_token)
reset_fakes
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --name other-name --remote-destroy
assert_status 1
assert_contains "$STDERR" 'conflicts with --name'
assert_empty "$QM_LOG"

run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
reset_fakes
FAKE_VM_NAME=renamed-vm PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'name changed after inspection'
assert_operations 'status config'
assert_no_mutation

run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
reset_fakes
FAKE_VM_STATUS=running PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'status changed after inspection'
assert_operations 'status config'
assert_no_mutation

# One consumer succeeds; a concurrent/replayed consumer cannot reuse the nonce.
run_tool --vmid 101 --remote-inspect
token=$(authorization_token)
reset_fakes
set +e
PATH="$FAKE_BIN:$PATH" PLATFORM_VM_CLEANUP_AUTH_DIR="$AUTH_DIR" REAL_MV="$REAL_MV" \
  REAL_LN="$REAL_LN" REAL_RM="$REAL_RM" REAL_BASH="$REAL_BASH" REAL_STAT="$REAL_STAT" \
  FAKE_QM_LOG="$QM_LOG" FAKE_QM_OPERATION_LOG="$QM_OPERATION_LOG" \
  "$TOOL" --vmid 101 --remote-destroy 3<<<"$token" >"$TMP_DIR/concurrent-1.out" 2>"$TMP_DIR/concurrent-1.err" &
pid_one=$!
PATH="$FAKE_BIN:$PATH" PLATFORM_VM_CLEANUP_AUTH_DIR="$AUTH_DIR" REAL_MV="$REAL_MV" \
  REAL_LN="$REAL_LN" REAL_RM="$REAL_RM" REAL_BASH="$REAL_BASH" REAL_STAT="$REAL_STAT" \
  FAKE_QM_LOG="$QM_LOG" FAKE_QM_OPERATION_LOG="$QM_OPERATION_LOG" \
  "$TOOL" --vmid 101 --remote-destroy 3<<<"$token" >"$TMP_DIR/concurrent-2.out" 2>"$TMP_DIR/concurrent-2.err" &
pid_two=$!
wait "$pid_one"; status_one=$?
wait "$pid_two"; status_two=$?
set -e
[[ ( $status_one -eq 0 && $status_two -ne 0 ) || ( $status_two -eq 0 && $status_one -ne 0 ) ]] ||
  fail "concurrent authorization results were $status_one and $status_two"
[[ $(grep -hF '[OK] Destroyed VMID 101' "$TMP_DIR"/concurrent-*.out | wc -l) -eq 1 ]] ||
  fail 'concurrent authorization mutated more or less than once'

reset_fakes
PRIVATE_AUTH_TOKEN=$token run_tool --vmid 101 --remote-destroy
assert_status 1
assert_contains "$STDERR" 'was not found or was already consumed'
assert_empty "$QM_LOG"

# Public SSH carries only line-framed data through a fixed command parsed by a
# POSIX login shell. Authorization state remains persisted on the remote side.
identity="$TMP_DIR/id_ed25519"
printf '%s\n' 'synthetic test identity' >"$identity"
reset_fakes
FAKE_VM_NAME='fixture;still-one-name' FAKE_REQUIRE_FD3_CLOSED=1 run_tool --ssh root@pve.example \
  --identity-file "$identity" --vmid 101 --name 'fixture;still-one-name' --yes
assert_status 0
assert_contains "$SSH_LOG" 'ARG=-i'
assert_contains "$SSH_LOG" 'ARG=IdentitiesOnly=yes'
assert_contains "$SSH_LOG" 'MODE=inspect'
assert_contains "$SSH_LOG" 'MODE=destroy'
assert_contains "$SSH_LOG" 'LOGIN_SHELL=sh'
assert_not_contains "$SSH_LOG" 'fixture;still-one-name'
assert_not_contains "$STDOUT" 'PLATFORM_VM_CLEANUP_AUTHORIZATION='
assert_not_contains "$STDERR" 'PLATFORM_VM_CLEANUP_AUTHORIZATION='
! grep -Eq '[a-f0-9]{64}' "$SSH_LOG" || fail 'authorization token leaked to SSH arguments or logs'
assert_contains "$REMOTE_CHILD_ARGV_LOG" 'CAPTURED_ARGV'
assert_contains "$REMOTE_CHILD_ARGV_LOG" 'ARG=--remote-destroy'
assert_not_contains "$REMOTE_CHILD_ARGV_LOG" 'authorization-token'
! grep -Eq '[a-f0-9]{64}' "$REMOTE_CHILD_ARGV_LOG" || fail 'authorization token leaked to remote child argv or proc cmdline'
assert_contains "$FD_LOG" 'stat FD3=closed'
assert_contains "$FD_LOG" 'mv FD3=closed'
assert_contains "$FD_LOG" 'qm FD3=closed'
assert_operations 'status config status config destroy status config destroy'

reset_fakes
FAKE_VM_NAME_AT_2=remote-renamed run_tool --ssh root@pve.example --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'name changed after inspection'
assert_operations 'status config status config'
assert_no_mutation

reset_fakes
FAKE_QM_STATUS_OUTPUT_AT_2='status: running' run_tool --ssh root@pve.example --vmid 101 --yes
assert_status 1
assert_contains "$STDERR" 'status changed after inspection'
assert_operations 'status config status config'
assert_no_mutation

reset_fakes
FAKE_VM_EXISTS=0 run_tool --ssh root@pve.example --vmid 404 --yes
assert_status 1
assert_contains "$STDERR" 'VMID 404 does not exist'
assert_not_contains "$SSH_LOG" 'MODE=destroy'
assert_operations 'status'

reset_fakes
FAKE_QM_STATUS_ERROR_AT=1 FAKE_QM_STATUS_ERROR='remote permission denied' \
  run_tool --ssh root@pve.example --vmid 101 --yes
assert_status 42
assert_contains "$STDERR" 'remote permission denied'
assert_not_contains "$STDERR" 'does not exist'
assert_not_contains "$SSH_LOG" 'MODE=destroy'

reset_fakes
FAKE_SSH_FAIL_INSPECT=1 run_tool --ssh root@pve.example --vmid 101 --yes
assert_status 43
assert_not_contains "$SSH_LOG" 'MODE=destroy'
assert_empty "$QM_LOG"
reset_fakes
FAKE_SSH_FAIL_DESTROY=1 run_tool --ssh root@pve.example --vmid 101 --yes
assert_status 44
assert_contains "$SSH_LOG" 'MODE=inspect'
assert_contains "$SSH_LOG" 'MODE=destroy'
assert_contains "$SSH_LOG" 'MODE=cancel'
assert_operations 'status config'
assert_no_mutation

reset_fakes
run_tool --ssh root@pve.example --vmid 101 </dev/null
assert_status 1
assert_contains "$STDERR" 'Interactive confirmation requires a TTY'
assert_not_contains "$SSH_LOG" 'MODE=destroy'
assert_contains "$SSH_LOG" 'MODE=cancel'
assert_operations 'status config'
! compgen -G "$AUTH_DIR/[a-f0-9]*" >/dev/null || fail 'cancelled remote authorization remains persisted'

printf '%s\n' 'test-cleanup.sh: ok'
