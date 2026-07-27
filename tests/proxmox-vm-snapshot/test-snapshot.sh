#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
FIXTURE_DIR="$ROOT_DIR/tests/proxmox-vm-snapshot/fixtures"
FAKE_BIN="$ROOT_DIR/tests/proxmox-vm-snapshot/fake-bin"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-proxmox-vm-snapshot"
VERSION=$(<"$ROOT_DIR/VERSION")
PTY_RUNNER="$ROOT_DIR/tests/proxmox-vm-snapshot/pty-runner.py"
STATE="$TMP_DIR/state"
OUTPUT=''
STATUS=0
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"

fail() {
  printf 'test-snapshot.sh: %s\n' "$*" >&2
  exit 1
}

assert_success() {
  [[ $STATUS -eq 0 ]] || fail "expected success, got $STATUS: $OUTPUT"
}

assert_failure() {
  [[ $STATUS -ne 0 ]] || fail "expected failure: $OUTPUT"
}

assert_contains() {
  local haystack=$1 needle=$2
  [[ "$haystack" == *"$needle"* ]] || fail "expected output to contain '$needle': $haystack"
}

assert_not_contains() {
  local haystack=$1 needle=$2
  [[ "$haystack" != *"$needle"* ]] || fail "expected output not to contain '$needle': $haystack"
}

assert_before() {
  local haystack=$1 first=$2 second=$3 before after
  before=${haystack%%"$first"*}
  [[ "$before" != "$haystack" ]] || fail "missing '$first': $haystack"
  after=${haystack#*"$first"}
  [[ "$after" == *"$second"* ]] || fail "expected '$first' before '$second': $haystack"
}

create_state() {
  rm -rf "$STATE"
  mkdir -p "$STATE/configs" "$STATE/status" "$STATE/snapshots"
  cp "$FIXTURE_DIR/nodes.single.json" "$STATE/nodes.json"
  cp "$FIXTURE_DIR/inventory.json" "$STATE/inventory.json"
  cp "$FIXTURE_DIR/config-101.json" "$STATE/configs/101.json"
  cp "$FIXTURE_DIR/config-102.json" "$STATE/configs/102.json"
  cp "$FIXTURE_DIR/config-103.json" "$STATE/configs/103.json"
  cp "$FIXTURE_DIR/config-9000.json" "$STATE/configs/9000.json"
  cp "$FIXTURE_DIR/status-running.json" "$STATE/status/101.json"
  cp "$FIXTURE_DIR/status-stopped.json" "$STATE/status/102.json"
  cp "$FIXTURE_DIR/status-stopped.json" "$STATE/status/103.json"
  cp "$FIXTURE_DIR/status-stopped.json" "$STATE/status/9000.json"
  cp "$FIXTURE_DIR/snapshots.current.json" "$STATE/snapshots/101.json"
  cp "$FIXTURE_DIR/snapshots.current.json" "$STATE/snapshots/102.json"
  cp "$FIXTURE_DIR/snapshots.current.json" "$STATE/snapshots/103.json"
  cp "$FIXTURE_DIR/snapshots.current.json" "$STATE/snapshots/9000.json"
  : >"$STATE/pvesh.log"
  : >"$STATE/qm.log"
  : >"$STATE/qm-order.log"
  : >"$STATE/ssh.log"
}

run_tool() {
  set +e
  OUTPUT=$(PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" "$TOOL" "$@" 2>&1)
  STATUS=$?
  set -e
}

run_tool_split() {
  : >"$STDOUT"
  : >"$STDERR"
  set +e
  PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" "$TOOL" "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

run_tool_with_env() {
  local drift_at=$1 drift_kind=$2 fail_operation=$3 fail_vmid=$4
  shift 4
  set +e
  OUTPUT=$(PATH="$FAKE_BIN:$PATH" \
    FAKE_PVE_STATE="$STATE" \
    FAKE_PVESH_DRIFT_AT="$drift_at" \
    FAKE_PVESH_DRIFT_KIND="$drift_kind" \
    FAKE_QM_FAIL_OPERATION="$fail_operation" \
    FAKE_QM_FAIL_VMID="$fail_vmid" \
    "$TOOL" "$@" 2>&1)
  STATUS=$?
  set -e
}

run_tool_with_input() {
  local input=$1
  shift
  set +e
  OUTPUT=$(PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" PTY_INPUT="$input" \
    python3 "$PTY_RUNNER" "$TOOL" "$@" 2>&1)
  STATUS=$?
  set -e
}

qm_log() {
  printf '%s' "$(<"$STATE/qm.log")"
}

ssh_log() {
  printf '%s' "$(<"$STATE/ssh.log")"
}

assert_duplicate_rejected() {
  create_state
  run_tool "$@"
  assert_failure
  assert_contains "$OUTPUT" 'may be specified only once'
  assert_not_contains "$(<"$STATE/pvesh.log")" 'CALL pvesh'
}

capture_create_manifest() {
  local destination=$1
  shift
  run_tool_split create "$@" --internal-preflight
  [[ $STATUS -eq 0 ]] || fail "could not capture create manifest: $(<"$STDERR")"
  cp "$STDOUT" "$destination"
  chmod 600 "$destination"
}

create_state
run_tool
assert_failure
assert_contains "$OUTPUT" 'platform-proxmox-vm-snapshot COMMAND'

run_tool_split --help
assert_success
assert_contains "$(<"$STDOUT")" 'Commands:'
assert_contains "$(<"$STDOUT")" 'create'
assert_contains "$(<"$STDOUT")" 'rollback'
assert_not_contains "$(<"$STDOUT")" '--internal-preflight'
assert_not_contains "$(<"$STDOUT")" '--expected-targets-file'
[[ ! -s $STDERR ]] || fail "expected empty help stderr: $(<"$STDERR")"

run_tool create --help
assert_success
assert_contains "$OUTPUT" 'platform-proxmox-vm-snapshot create [OPTIONS]'
assert_contains "$OUTPUT" '--include-memory'
assert_not_contains "$OUTPUT" '--start-after-rollback'
assert_not_contains "$OUTPUT" '--internal-action'

run_tool_split --version
assert_success
[[ $(<"$STDOUT") == "platform-proxmox-vm-snapshot $VERSION" ]] || fail "unexpected version output: $(<"$STDOUT")"
[[ ! -s $STDERR ]] || fail "expected empty version stderr: $(<"$STDERR")"

run_tool_split create --unknown
assert_failure
[[ ! -s $STDOUT ]] || fail "expected empty parser-error stdout: $(<"$STDOUT")"
assert_contains "$(<"$STDERR")" 'invalid option: --unknown'

run_tool create --vmid 101 --snapshot-name valid-name --start-after-rollback
assert_failure
assert_contains "$OUTPUT" 'invalid option: --start-after-rollback'

run_tool rollback --vmid 101 --snapshot-name valid-name --description invalid
assert_failure
assert_contains "$OUTPUT" 'invalid option: --description'

# Every selector pair is rejected before discovery, as is an absent selector.
while IFS='|' read -r first first_value second second_value; do
  create_state
  run_tool list "$first" "$first_value" "$second" "$second_value"
  assert_failure
  assert_contains "$OUTPUT" 'Exactly one of --vmid, --vm-name, or --environment is required'
  assert_not_contains "$(<"$STATE/pvesh.log")" 'CALL pvesh'
done <<'SELECTOR_PAIRS'
--vmid|101|--vm-name|fixture-app
--vmid|101|--environment|dev
--vm-name|fixture-app|--environment|dev
SELECTOR_PAIRS
create_state
run_tool list
assert_failure
assert_contains "$OUTPUT" 'Exactly one of --vmid, --vm-name, or --environment is required'

# Duplicate rejection covers selector, operation, transport, public boolean,
# and private protocol options without relying on Bashly's last-value behavior.
for duplicate_option in \
  --vmid --vm-name --environment --snapshot-name --description --ssh \
  --identity-file --expected-targets-file; do
  assert_duplicate_rejected create --vmid 101 --snapshot-name valid-name \
    "$duplicate_option" first "$duplicate_option" second
done
for duplicate_option in \
  --include-memory --dry-run --yes --internal-preflight --internal-action; do
  assert_duplicate_rejected create --vmid 101 --snapshot-name valid-name \
    "$duplicate_option" "$duplicate_option"
done
assert_duplicate_rejected rollback --vmid 101 --snapshot-name valid-name \
  --start-after-rollback --start-after-rollback

create_state
run_tool list --vmid=101
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app)'

create_state
run_tool list --vmid=
assert_failure
assert_contains "$OUTPUT" 'invalid option: --vmid='
assert_not_contains "$(<"$STATE/pvesh.log")" 'CALL pvesh'

create_state
run_tool create --vmid=101 --vmid 102 --snapshot-name valid-name
assert_failure
assert_contains "$OUTPUT" '--vmid may be specified only once'

create_state
run_tool create --vmid 101 --snapshot-name valid-name --dry-run=true
assert_failure
assert_contains "$OUTPUT" 'invalid argument: true'

create_state
run_tool create --vmid 101 --snapshot-name valid-name --dry-run=true --dry-run
assert_failure
assert_contains "$OUTPUT" 'invalid argument: true'
assert_not_contains "$OUTPUT" 'may be specified only once'

create_state
run_tool create --vmid 101 --snapshot-name valid-name --dry-run=
assert_failure
assert_contains "$OUTPUT" 'invalid option: --dry-run='

# Scalar values consume the next token even when it resembles an option.
create_state
run_tool create --vmid --help --snapshot-name valid-name
assert_failure
assert_contains "$OUTPUT" '--vmid must be an integer'
assert_not_contains "$OUTPUT" 'Create a temporary VM snapshot'

create_state
run_tool create --vmid 101 --snapshot-name option-value \
  --description --include-memory --dry-run
assert_success
assert_contains "$OUTPUT" 'qm snapshot 101 option-value --description --include-memory'
assert_not_contains "$OUTPUT" '--vmstate'

create_state
run_tool create --description --yes --yes --help
assert_success
assert_contains "$OUTPUT" 'platform-proxmox-vm-snapshot create [OPTIONS]'
assert_not_contains "$OUTPUT" 'may be specified only once'

# Interspersed help keeps legacy precedence without hiding earlier parser errors.
create_state
run_tool create --vmid 101 --help --unknown
assert_success
assert_contains "$OUTPUT" 'platform-proxmox-vm-snapshot create [OPTIONS]'

create_state
run_tool create --unknown --help
assert_failure
assert_contains "$OUTPUT" 'invalid option: --unknown'

create_state
run_tool create --vmid 101 --vmid 102 --help
assert_failure
assert_contains "$OUTPUT" '--vmid may be specified only once'

create_state
run_tool create --vmid= --help
assert_failure
assert_contains "$OUTPUT" 'invalid option: --vmid='

run_tool create --vmid 101 --snapshot-name a
assert_failure
assert_contains "$OUTPUT" '2-40 characters'

run_tool create --vmid
assert_failure
assert_contains "$OUTPUT" '--vmid requires an argument'

run_tool create --vmid 101 --snapshot-name current
assert_failure
assert_contains "$OUTPUT" 'Reserved snapshot name: current'

run_tool create --vmid 101 --snapshot-name PENDING
assert_failure
assert_contains "$OUTPUT" 'Reserved snapshot name: PENDING'

run_tool list --environment managed-by-tofu
assert_failure
assert_contains "$OUTPUT" 'Reserved environment selector'

run_tool list --environment all
assert_failure
assert_contains "$OUTPUT" 'Reserved environment selector: all'

run_tool list --environment '*'
assert_failure
assert_contains "$OUTPUT" 'valid exact Proxmox tag'

run_tool list --vmid 101 --yes
assert_failure
assert_contains "$OUTPUT" 'invalid option: --yes'

run_tool create --vmid 101 --snapshot-name valid-name --yes --dry-run
assert_failure
assert_contains "$OUTPUT" '--yes cannot be combined with --dry-run'

hostile_marker="$TMP_DIR/ssh-injection"
hostile_ssh_values=(
  '-oProxyCommand=touch-bad'
  "root@pve-a;touch $hostile_marker"
  "root@\$(touch $hostile_marker)"
  "root@\`touch $hostile_marker\`"
  "root@pve-a'quoted"
)
for hostile_ssh in "${hostile_ssh_values[@]}"; do
  create_state
  run_tool create --ssh "$hostile_ssh" --vmid 101 --snapshot-name valid-name --yes
  assert_failure
  assert_contains "$OUTPUT" '--ssh must use user@host'
  assert_not_contains "$(ssh_log)" 'CALL ssh'
  [[ ! -e $hostile_marker ]] || fail "hostile SSH value caused a side effect: $hostile_ssh"
done

run_tool create --identity-file "$TMP_DIR/missing-key" --vmid 101 --snapshot-name valid-name --yes
assert_failure
assert_contains "$OUTPUT" '--identity-file requires --ssh'

run_tool create --vmid 101 --snapshot-name valid-name --description $'line one\nline two' --yes
assert_failure
assert_contains "$OUTPUT" '--description must not contain control characters'

run_tool list --vmid 101
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app) on pve-a'
assert_contains "$OUTPUT" 'current state'
assert_not_contains "$(qm_log)" 'CALL qm'

run_tool list --vm-name fixture-db
assert_success
assert_contains "$OUTPUT" 'VMID 102 (fixture-db)'

run_tool list --vm-name fixture
assert_failure
assert_contains "$OUTPUT" "No VM has exact name 'fixture'"

run_tool list --environment dev
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app)'
assert_contains "$OUTPUT" 'VMID 102 (fixture-db)'
assert_not_contains "$OUTPUT" 'fixture-other'
assert_not_contains "$OUTPUT" 'fixture-template'
assert_before "$OUTPUT" 'VMID 101' 'VMID 102'

run_tool list --environment Dev
assert_failure
assert_contains "$OUTPUT" 'No non-template VMs have exact tags'

cp "$FIXTURE_DIR/nodes.multi.json" "$STATE/nodes.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Exactly one Proxmox node is required; discovered: 2'

create_state
printf '%s\n' '[]' >"$STATE/nodes.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Exactly one Proxmox node is required; discovered: 0'

create_state
printf '%s\n' '[{"node":"pve-a"},{"node":"pve-a"}]' >"$STATE/nodes.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Exactly one Proxmox node is required; discovered: 2'

create_state
printf '%s\n' '{not-json' >"$STATE/nodes.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid JSON returned by pvesh node discovery'

create_state
run_tool list --vmid 9000
assert_failure
assert_contains "$OUTPUT" 'is a template'

create_state
printf '%s\n' '{not-json' >"$STATE/inventory.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid QEMU inventory JSON'

create_state
jq '. + [.[0]]' "$STATE/inventory.json" >"$STATE/inventory.tmp"
mv "$STATE/inventory.tmp" "$STATE/inventory.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid QEMU inventory JSON'

create_state
printf '%s\n' '{not-json' >"$STATE/configs/101.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid current config JSON for VMID 101'

create_state
jq 'del(.digest)' "$STATE/configs/101.json" >"$STATE/configs/101.tmp"
mv "$STATE/configs/101.tmp" "$STATE/configs/101.json"
run_tool create --vmid 101 --snapshot-name missing-digest --dry-run
assert_failure
assert_contains "$OUTPUT" 'current config has no valid digest'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
printf '%s\n' '{}' >"$STATE/status/101.json"
run_tool create --vmid 101 --snapshot-name invalid-status --dry-run
assert_failure
assert_contains "$OUTPUT" 'Invalid current status JSON for VMID 101'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
printf '%s\n' '[{"description":"missing name"},{"name":"current"}]' >"$STATE/snapshots/101.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid snapshot JSON for VMID 101'

create_state
printf '%s\n' '[{"name":"duplicate"},{"name":"duplicate"},{"name":"current"}]' >"$STATE/snapshots/101.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid snapshot JSON for VMID 101'

create_state
printf '%s\n' '{not-json' >"$STATE/snapshots/101.json"
run_tool list --vmid 101
assert_failure
assert_contains "$OUTPUT" 'Invalid snapshot JSON'

create_state
jq '.lock = "snapshot"' "$STATE/configs/101.json" >"$STATE/configs/101.tmp"
mv "$STATE/configs/101.tmp" "$STATE/configs/101.json"
run_tool create --vmid 101 --snapshot-name before-change --dry-run
assert_failure
assert_contains "$OUTPUT" "has Proxmox lock 'snapshot'"
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
jq '.lock = "backup"' "$STATE/configs/101.json" >"$STATE/configs/101.tmp"
mv "$STATE/configs/101.tmp" "$STATE/configs/101.json"
run_tool create --vmid 101 --snapshot-name before-change --dry-run
assert_failure
assert_contains "$OUTPUT" "has Proxmox lock 'backup'"
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool create --vmid 101 --snapshot-name before-change --dry-run
assert_success
assert_contains "$OUTPUT" '[PLAN] Would run:'
assert_contains "$OUTPUT" 'qm snapshot 101 before-change'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool create --vmid 101 --snapshot-name before-change --yes
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_contains "$(qm_log)" 'ARG=snapshot'
assert_contains "$(qm_log)" 'ARG=Created\ by\ platform-proxmox-vm-snapshot\ for\ VMID\ 101'
assert_not_contains "$(qm_log)" 'ARG=--vmstate'
jq -e 'any(.[]; .name == "before-change")' >/dev/null "$STATE/snapshots/101.json"

create_state
run_tool_with_input y create --vmid 101 --snapshot-name interactive-create
assert_success
assert_contains "$OUTPUT" 'Create snapshot interactive-create for 1 VM(s)?'
assert_contains "$(qm_log)" 'ARG=snapshot'

create_state
run_tool create --vmid 101 --snapshot-name memory-check --description 'Before app upgrade' --include-memory --yes
assert_success
assert_contains "$(qm_log)" 'ARG=Before\ app\ upgrade'
assert_contains "$(qm_log)" 'ARG=--vmstate'
assert_contains "$(qm_log)" 'ARG=1'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/102.json"
run_tool create --environment dev --snapshot-name before-change --yes
assert_failure
assert_contains "$OUTPUT" "VMID 102 already has snapshot 'before-change'"
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool rollback --vmid 101 --snapshot-name before-change --start-after-rollback --yes
assert_success
assert_contains "$(qm_log)" 'ARG=rollback'
assert_contains "$(qm_log)" 'ARG=--start'
[[ $(jq -r '.status' "$STATE/status/101.json") == running ]] || fail 'rollback did not produce running fake status'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool_with_input '101 before-change' rollback --vmid 101 --snapshot-name before-change
assert_success
assert_not_contains "$(qm_log)" 'ARG=--start'
[[ $(jq -r '.status' "$STATE/status/101.json") == stopped ]] || fail 'rollback did not produce stopped fake status'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool_with_input 'wrong confirmation' rollback --vmid 101 --snapshot-name before-change
assert_failure
assert_contains "$OUTPUT" 'Confirmation did not match'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
set +e
OUTPUT=$(PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" \
  "$TOOL" create --vmid 101 --snapshot-name no-input </dev/null 2>&1)
STATUS=$?
set -e
assert_failure
assert_contains "$OUTPUT" 'Interactive confirmation requires a TTY'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool rollback --vmid 101 --snapshot-name before-change
assert_failure
assert_contains "$OUTPUT" 'Interactive confirmation requires a TTY'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool delete --vmid 101 --snapshot-name before-change
assert_failure
assert_contains "$OUTPUT" 'Interactive confirmation requires a TTY'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool rollback --vmid 101 --snapshot-name before --yes
assert_failure
assert_contains "$OUTPUT" "does not have snapshot 'before'"
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
set +e
OUTPUT=$(PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" FAKE_QM_SUPPRESS_STATUS_UPDATE=1 \
  "$TOOL" rollback --vmid 101 --snapshot-name before-change --yes 2>&1)
STATUS=$?
set -e
assert_failure
assert_contains "$OUTPUT" "did not reach Proxmox state 'stopped'"
assert_contains "$OUTPUT" 'rollback command or postcondition failed'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
set +e
OUTPUT=$(PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" FAKE_QM_NOOP_ROLLBACK=1 \
  "$TOOL" rollback --vmid 101 --snapshot-name before-change --yes 2>&1)
STATUS=$?
set -e
assert_failure
assert_contains "$OUTPUT" "current snapshot parent is not 'before-change'"

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool delete --vmid 101 --snapshot-name before-change --yes
assert_success
assert_contains "$(qm_log)" 'ARG=delsnapshot'
assert_not_contains "$(qm_log)" 'ARG=--force'
jq -e 'all(.[]; .name != "before-change")' >/dev/null "$STATE/snapshots/101.json"

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool_with_input 'wrong confirmation' delete --vmid 101 --snapshot-name before-change
assert_failure
assert_contains "$OUTPUT" 'Confirmation did not match; delete aborted'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool_with_input '101 before-change' delete --vmid 101 --snapshot-name before-change
assert_success
assert_contains "$(qm_log)" 'ARG=delsnapshot'

create_state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool rollback --environment dev --snapshot-name before-change --yes
assert_failure
assert_contains "$OUTPUT" "VMID 102 does not have snapshot 'before-change'"
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
jq '.tags = "managed-by-tofu;dev"' "$STATE/configs/103.json" >"$STATE/configs/103.tmp"
mv "$STATE/configs/103.tmp" "$STATE/configs/103.json"
run_tool_with_env '' '' snapshot 102 create --environment dev --snapshot-name partial-check --yes
assert_failure
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_contains "$OUTPUT" 'VMID 102 (fixture-db): failed'
assert_contains "$OUTPUT" 'VMID 103 (fixture-other): not attempted'
assert_contains "$OUTPUT" 'simulated qm failure'
assert_before "$OUTPUT" 'VMID 101 (fixture-app): succeeded' 'VMID 102 (fixture-db): failed'
assert_before "$OUTPUT" 'VMID 102 (fixture-db): failed' 'VMID 103 (fixture-other): not attempted'
[[ $(<"$STATE/qm-order.log") == $'snapshot:101\nsnapshot:102' ]] || \
  fail "unexpected three-target mutation order: $(<"$STATE/qm-order.log")"

create_state
run_tool_with_env 2 rename-101 '' '' create --vmid 101 --snapshot-name drift-check --yes
assert_failure
assert_contains "$OUTPUT" 'Target set changed after preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool_with_env 2 disk-101 '' '' create --vmid 101 --snapshot-name config-drift --yes
assert_failure
assert_contains "$OUTPUT" 'Config, status, lock, or snapshot state changed after preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
jq '.[] |= if .vmid == 103 then .name = "fixture-app" else . end' "$STATE/inventory.json" >"$STATE/inventory.tmp"
mv "$STATE/inventory.tmp" "$STATE/inventory.json"
jq '.name = "fixture-app"' "$STATE/configs/103.json" >"$STATE/configs/103.tmp"
mv "$STATE/configs/103.tmp" "$STATE/configs/103.json"
run_tool list --vm-name fixture-app
assert_failure
assert_contains "$OUTPUT" 'is not unique; matching VMIDs: 101, 103'

create_state
manifest_file="$TMP_DIR/expected-targets.json"
run_tool create --vmid 101 --snapshot-name internal-check --yes \
  --internal-action --expected-targets-file "$TMP_DIR/missing-manifest.json"
assert_failure
assert_contains "$OUTPUT" 'Expected target manifest must be a regular non-symlink file with valid metadata'

mkdir "$TMP_DIR/manifest-directory"
run_tool create --vmid 101 --snapshot-name internal-check --yes \
  --internal-action --expected-targets-file "$TMP_DIR/manifest-directory"
assert_failure
assert_contains "$OUTPUT" 'Expected target manifest must be a regular non-symlink file with valid metadata'

printf '%s\n' '{}' >"$manifest_file"
chmod 600 "$manifest_file"
ln -s "$manifest_file" "$TMP_DIR/manifest-link.json"
run_tool create --vmid 101 --snapshot-name internal-check --yes \
  --internal-action --expected-targets-file "$TMP_DIR/manifest-link.json"
assert_failure
assert_contains "$OUTPUT" 'Expected target manifest must be a regular non-symlink file with valid metadata'

ln "$manifest_file" "$TMP_DIR/manifest-hardlink.json"
run_tool create --vmid 101 --snapshot-name internal-check --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Expected target manifest must have exactly one hard link'
rm "$TMP_DIR/manifest-hardlink.json"

FAKE_STAT_TARGET="$manifest_file" FAKE_STAT_OWNER="$((EUID + 1))" \
  run_tool create --vmid 101 --snapshot-name internal-check --yes \
    --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Expected target manifest must be owned by the current user'

for unsafe_mode in 640 604; do
  chmod "$unsafe_mode" "$manifest_file"
  run_tool create --vmid 101 --snapshot-name internal-check --yes \
    --internal-action --expected-targets-file "$manifest_file"
  assert_failure
  assert_contains "$OUTPUT" 'Expected target manifest must have exact mode 600'
done
chmod 600 "$manifest_file"

original_manifest=$(<"$manifest_file")
mkdir "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest"
chmod 750 "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest"
run_tool create --vmid 101 --snapshot-name internal-check --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Expected manifest consumption directory must be current-user-owned with exact mode 700'
[[ $(<"$manifest_file") == "$original_manifest" ]] || fail 'unsafe consumption directory changed the source manifest'
rmdir "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest"

FAKE_MV_SWAP_SOURCE="$manifest_file" FAKE_MV_SWAP_KIND=file \
  run_tool create --vmid 101 --snapshot-name internal-check --yes \
    --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Could not inspect consumed expected target manifest identity'
[[ -f $manifest_file && ! -L $manifest_file && $(<"$manifest_file") == "$original_manifest" ]] ||
  fail 'path-swap rejection did not preserve the original expected manifest'
[[ ! -e $TMP_DIR/.platform-proxmox-vm-snapshot-manifest ]] ||
  fail 'path-swap rejection left consumed manifest state'
assert_not_contains "$(qm_log)" 'CALL qm'

FAKE_MV_SWAP_SOURCE="$manifest_file" FAKE_MV_SWAP_KIND=symlink \
  run_tool create --vmid 101 --snapshot-name internal-check --yes \
    --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Could not inspect consumed expected target manifest identity'
[[ -f $manifest_file && ! -L $manifest_file && $(<"$manifest_file") == "$original_manifest" ]] ||
  fail 'symlink-swap rejection did not preserve the original expected manifest'
[[ ! -e $TMP_DIR/.platform-proxmox-vm-snapshot-manifest ]] ||
  fail 'symlink-swap rejection left consumed manifest state'
assert_not_contains "$(qm_log)" 'CALL qm'

mkdir "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest"
chmod 700 "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest"
printf '%s\n' 'foreign collision' >"$TMP_DIR/.platform-proxmox-vm-snapshot-manifest/expected-targets.consumed"
run_tool create --vmid 101 --snapshot-name internal-check --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Expected manifest consumed-state path already exists'
[[ $(<"$manifest_file") == "$original_manifest" ]] || fail 'consumed collision changed the source manifest'
[[ $(<"$TMP_DIR/.platform-proxmox-vm-snapshot-manifest/expected-targets.consumed") == 'foreign collision' ]] ||
  fail 'consumed collision replaced foreign state'
assert_not_contains "$(qm_log)" 'CALL qm'
rm "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest/expected-targets.consumed"
rmdir "$TMP_DIR/.platform-proxmox-vm-snapshot-manifest"

run_tool create --vmid 101 --snapshot-name internal-check --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Internal action requires --yes'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool create --vmid 101 --snapshot-name internal-check --yes --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Invalid expected operation-state manifest'
[[ ! -e $manifest_file && ! -L $manifest_file ]] || fail 'malformed authorization was not consumed'

create_state
capture_create_manifest "$manifest_file" --vmid 101 --snapshot-name signal-cleanup
FAKE_STAT_SIGNAL_DESCRIPTOR=1 \
  run_tool create --vmid 101 --snapshot-name signal-cleanup --yes \
    --internal-action --expected-targets-file "$manifest_file"
assert_failure
[[ ! -e $manifest_file && ! -L $manifest_file ]] || fail 'signal path left the original authorization reusable'
[[ ! -e $TMP_DIR/.platform-proxmox-vm-snapshot-manifest ]] ||
  fail 'signal path left consumed manifest state'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
capture_create_manifest "$manifest_file" --environment dev --snapshot-name target-drift
jq '.tags = "managed-by-tofu;dev"' "$STATE/configs/103.json" >"$STATE/configs/103.tmp"
mv "$STATE/configs/103.tmp" "$STATE/configs/103.json"
run_tool create --environment dev --snapshot-name target-drift --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Target set changed after remote preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
capture_create_manifest "$manifest_file" --vmid 101 --snapshot-name name-drift
jq '.name = "fixture-app-renamed"' "$STATE/configs/101.json" >"$STATE/configs/101.tmp"
mv "$STATE/configs/101.tmp" "$STATE/configs/101.json"
run_tool create --vmid 101 --snapshot-name name-drift --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Target set changed after remote preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
capture_create_manifest "$manifest_file" --vmid 101 --snapshot-name status-drift
jq '.status = "stopped" | .qmpstatus = "stopped"' "$STATE/status/101.json" >"$STATE/status/101.tmp"
mv "$STATE/status/101.tmp" "$STATE/status/101.json"
run_tool create --vmid 101 --snapshot-name status-drift --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Config, status, lock, or snapshot state changed after remote preflight'
[[ ! -e $manifest_file && ! -L $manifest_file ]] || fail 'stale authorization remained reusable after consumption'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
capture_create_manifest "$manifest_file" --vmid 101 --snapshot-name config-drift
jq '.scsi0 = "fixture-storage:vm-101-disk-0,size=24G" | .digest = "4123456789abcdef0123456789abcdef01234567"' \
  "$STATE/configs/101.json" >"$STATE/configs/101.tmp"
mv "$STATE/configs/101.tmp" "$STATE/configs/101.json"
run_tool create --vmid 101 --snapshot-name config-drift --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Config, status, lock, or snapshot state changed after remote preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
capture_create_manifest "$manifest_file" --vmid 101 --snapshot-name stale-state
cp "$FIXTURE_DIR/snapshots.checkpoint.json" "$STATE/snapshots/101.json"
run_tool create --vmid 101 --snapshot-name stale-state --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Config, status, lock, or snapshot state changed after remote preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
capture_create_manifest "$manifest_file" --vmid 101 --snapshot-name replay-check
FAKE_FORBID_CONSUMED_MANIFEST_FD=1 \
  run_tool create --vmid 101 --snapshot-name replay-check --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_success
[[ ! -e $manifest_file && ! -L $manifest_file ]] || fail 'successful action did not consume its authorization'
run_tool create --vmid 101 --snapshot-name replay-check --yes \
  --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Expected target manifest must be a regular non-symlink file with valid metadata'
[[ $(<"$STATE/qm-order.log") == 'snapshot:101' ]] || \
  fail "replayed manifest caused another mutation: $(<"$STATE/qm-order.log")"

create_state
run_tool_with_env 4 rename-102 '' '' create --environment dev --snapshot-name serial-drift --yes
assert_failure
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_contains "$OUTPUT" 'VMID 102 (fixture-db): failed'
assert_contains "$OUTPUT" 'target set changed before mutation'

create_state
run_tool_with_env 4 lock-102 '' '' create --environment dev --snapshot-name state-drift --yes
assert_failure
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_contains "$OUTPUT" 'VMID 102 (fixture-db): failed - operation state changed before mutation'

create_state
identity="$TMP_DIR/id_ed25519"
printf '%s\n' 'synthetic test identity' >"$identity"
chmod 600 "$identity"
run_tool create --ssh root@pve-a --identity-file "$identity" --vmid 101 --snapshot-name remote-check --description 'Remote description; still one argument' --yes
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_contains "$(ssh_log)" 'ARG=-i'
assert_contains "$(ssh_log)" 'ARG=-o'
assert_contains "$(ssh_log)" 'ARG=IdentitiesOnly=yes'
assert_not_contains "$(ssh_log)" 'fixture-storage'
assert_contains "$(qm_log)" 'ARG=Remote\ description\;\ still\ one\ argument'

create_state
run_tool_with_env 2 rename-101 '' '' create --ssh root@pve-a --vmid 101 --snapshot-name remote-drift --yes
assert_failure
assert_contains "$OUTPUT" 'Target set changed after remote preflight'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool list --ssh root@pve-a --environment dev
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app)'
assert_contains "$OUTPUT" 'VMID 102 (fixture-db)'

create_state
{
  printf '%s' '[{"name":"history","description":"'
  printf '%140000s' '' | tr ' ' x
  printf '%s\n' '","snaptime":1700004000,"vmstate":0},{"name":"current","parent":"history"}]'
} >"$STATE/snapshots/101.json"
run_tool create --ssh root@pve-a --vmid 101 --snapshot-name large-transport --yes
assert_success
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_not_contains "$(ssh_log)" 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

printf '%s\n' 'test-snapshot.sh: ok'
