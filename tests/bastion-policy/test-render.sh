#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

VALID_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.valid.yaml"
INVALID_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.invalid-missing-user-group.yaml"
INVALID_NEWLINE_GROUP_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.invalid-newline-group.yaml"
INVALID_NEWLINE_USER_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.invalid-newline-user.yaml"
INVALID_EMBEDDED_NEWLINE_USER_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.invalid-embedded-newline-user.yaml"
EXPECTED_CONFIGMAP="$ROOT_DIR/examples/bastion-policy/bastion-csr-policy.configmap.example.yaml"
HOST_OUT="$TMP_DIR/access-policy.yaml"
CONFIGMAP_OUT="$TMP_DIR/bastion-csr-policy.configmap.yaml"
ERROR_OUT="$TMP_DIR/error.txt"

assert_mode_600() {
  mode=$(stat -c '%a' "$1")
  if [ "$mode" != "600" ]; then
    printf '%s\n' "expected $1 to have mode 600, got $mode" >&2
    exit 1
  fi
}

expect_validation_rejects() {
  policy=$1
  expected=$2

  if "$ROOT_DIR/bin/platform-bastion-policy" validate --input "$policy" >"$ERROR_OUT" 2>&1; then
    printf '%s\n' "invalid policy unexpectedly passed validation: $policy" >&2
    exit 1
  fi

  if ! grep -q "$expected" "$ERROR_OUT"; then
    printf '%s\n' "invalid policy error did not mention: $expected" >&2
    exit 1
  fi
}

"$ROOT_DIR/bin/platform-bastion-policy" validate --input "$VALID_POLICY"

"$ROOT_DIR/bin/platform-bastion-policy" render-host \
  --input "$VALID_POLICY" \
  --output "$HOST_OUT"

assert_mode_600 "$HOST_OUT"

python3 - "$VALID_POLICY" "$HOST_OUT" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    expected = yaml.safe_load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    actual = yaml.safe_load(handle)

if actual != expected:
    raise SystemExit("host render did not preserve full source policy")
PY

"$ROOT_DIR/bin/platform-bastion-policy" render-csr-configmap \
  --input "$VALID_POLICY" \
  --name bastion-csr-policy \
  --namespace bastion-system \
  --output "$CONFIGMAP_OUT"

assert_mode_600 "$CONFIGMAP_OUT"

cmp "$EXPECTED_CONFIGMAP" "$CONFIGMAP_OUT"

python3 - "$CONFIGMAP_OUT" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    configmap = yaml.safe_load(handle)

policy = yaml.safe_load(configmap["data"]["policy.yaml"])

for host_only in ("cluster", "daemon", "bootstrap"):
    if host_only in policy:
        raise SystemExit(f"ConfigMap projection includes host-only field {host_only}")
if "renewal" in policy["csr"]:
    raise SystemExit("ConfigMap projection includes host-only field csr.renewal")

assert policy["apiVersion"] == "bastion.csr-policy/v1"
assert policy["csr"]["signerName"] == "example.com/client"
assert policy["csr"]["groupPrefix"] == "k8s-"
assert policy["csr"]["ttl"] == {
    "minSeconds": 3600,
    "defaultSeconds": 28800,
    "maxSeconds": 86400,
}
assert policy["csr"]["cleanup"]["retentionSeconds"] == 1209600
assert set(policy["groups"]) == {"k8s-admins", "k8s-viewers"}
assert set(policy["users"]) == {"alice", "bob"}
PY

expect_validation_rejects "$INVALID_POLICY" "k8s-missing"
expect_validation_rejects "$INVALID_NEWLINE_GROUP_POLICY" "group name"
expect_validation_rejects "$INVALID_NEWLINE_USER_POLICY" "user name"
expect_validation_rejects "$INVALID_EMBEDDED_NEWLINE_USER_POLICY" "user name"

EXISTING_OUT="$TMP_DIR/existing-output.yaml"
printf '%s\n' 'keep' > "$EXISTING_OUT"

if "$ROOT_DIR/bin/platform-bastion-policy" render-host \
  --input "$VALID_POLICY" \
  --output "$EXISTING_OUT" >"$ERROR_OUT" 2>&1; then
  printf '%s\n' "existing output path was overwritten" >&2
  exit 1
fi

if [ "$(cat "$EXISTING_OUT")" != "keep" ]; then
  printf '%s\n' "existing output file content changed" >&2
  exit 1
fi

if ! grep -q "refusing to overwrite existing output" "$ERROR_OUT"; then
  printf '%s\n' "existing output error did not mention overwrite refusal" >&2
  exit 1
fi

SYMLINK_OUT="$TMP_DIR/symlink-output.yaml"
SYMLINK_TARGET="$TMP_DIR/symlink-target.yaml"
ln -s "$SYMLINK_TARGET" "$SYMLINK_OUT"

if "$ROOT_DIR/bin/platform-bastion-policy" render-host \
  --input "$VALID_POLICY" \
  --output "$SYMLINK_OUT" >"$ERROR_OUT" 2>&1; then
  printf '%s\n' "symlink output path was followed" >&2
  exit 1
fi

if [ -e "$SYMLINK_TARGET" ]; then
  printf '%s\n' "symlink output target was created" >&2
  exit 1
fi

printf '%s\n' "test-render.sh: ok"
