#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
FIXTURE_DIR="$ROOT_DIR/tests/proxmox-vm-snapshot/fixtures"
FAKE_BIN="$ROOT_DIR/tests/proxmox-vm-snapshot/fake-bin"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-proxmox-vm-snapshot"
STATE="$TMP_DIR/state"
OUTPUT=''
STATUS=0

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
  : >"$STATE/ssh.log"
}

run_tool() {
  set +e
  OUTPUT=$(PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" "$TOOL" "$@" 2>&1)
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
  OUTPUT=$(printf '%s\n' "$input" | PATH="$FAKE_BIN:$PATH" FAKE_PVE_STATE="$STATE" "$TOOL" "$@" 2>&1)
  STATUS=$?
  set -e
}

qm_log() {
  printf '%s' "$(<"$STATE/qm.log")"
}

ssh_log() {
  printf '%s' "$(<"$STATE/ssh.log")"
}

create_state
run_tool
assert_failure
assert_contains "$OUTPUT" 'Usage: platform-proxmox-vm-snapshot'

run_tool create --vmid 101 --snapshot-name a
assert_failure
assert_contains "$OUTPUT" '2-40 characters'

run_tool create --vmid 101 --vmid 102 --snapshot-name valid-name
assert_failure
assert_contains "$OUTPUT" 'may be specified only once'

run_tool list --environment managed-by-tofu
assert_failure
assert_contains "$OUTPUT" 'Reserved environment selector'

run_tool list --environment '*'
assert_failure
assert_contains "$OUTPUT" 'valid exact Proxmox tag'

run_tool list --vmid 101 --yes
assert_failure
assert_contains "$OUTPUT" '--yes is not valid for list'

run_tool create --vmid 101 --snapshot-name valid-name --yes --dry-run
assert_failure
assert_contains "$OUTPUT" '--yes cannot be combined with --dry-run'

run_tool create --ssh '-oProxyCommand=touch-bad' --vmid 101 --snapshot-name valid-name --yes
assert_failure
assert_contains "$OUTPUT" '--ssh must use user@host'
assert_not_contains "$(ssh_log)" 'CALL ssh'

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
run_tool list --vmid 9000
assert_failure
assert_contains "$OUTPUT" 'is a template'

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
assert_contains "$OUTPUT" 'Confirmation input unavailable'
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
run_tool rollback --environment dev --snapshot-name before-change --yes
assert_failure
assert_contains "$OUTPUT" "VMID 102 does not have snapshot 'before-change'"
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool_with_env '' '' snapshot 102 create --environment dev --snapshot-name partial-check --yes
assert_failure
assert_contains "$OUTPUT" 'VMID 101 (fixture-app): succeeded'
assert_contains "$OUTPUT" 'VMID 102 (fixture-db): failed'
assert_contains "$OUTPUT" 'simulated qm failure'

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
manifest_file="$TMP_DIR/invalid-manifest.json"
printf '%s\n' '{}' >"$manifest_file"
chmod 600 "$manifest_file"
run_tool create --vmid 101 --snapshot-name internal-check --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Internal action requires --yes'
assert_not_contains "$(qm_log)" 'CALL qm'

create_state
run_tool create --vmid 101 --snapshot-name internal-check --yes --internal-action --expected-targets-file "$manifest_file"
assert_failure
assert_contains "$OUTPUT" 'Invalid expected operation-state manifest'

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
