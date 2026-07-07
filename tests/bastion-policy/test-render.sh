#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

VALID_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.valid.yaml"
INVALID_POLICY="$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.invalid-missing-user-group.yaml"
EXPECTED_CONFIGMAP="$ROOT_DIR/examples/bastion-policy/bastion-csr-policy.configmap.example.yaml"
HOST_OUT="$TMP_DIR/access-policy.yaml"
CONFIGMAP_OUT="$TMP_DIR/bastion-csr-policy.configmap.yaml"
ERROR_OUT="$TMP_DIR/error.txt"

"$ROOT_DIR/bin/platform-bastion-policy" validate --input "$VALID_POLICY"

"$ROOT_DIR/bin/platform-bastion-policy" render-host \
  --input "$VALID_POLICY" \
  --output "$HOST_OUT"

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

if "$ROOT_DIR/bin/platform-bastion-policy" validate --input "$INVALID_POLICY" >"$ERROR_OUT" 2>&1; then
  printf '%s\n' "invalid policy unexpectedly passed validation" >&2
  exit 1
fi

if ! grep -q "k8s-missing" "$ERROR_OUT"; then
  printf '%s\n' "invalid policy error did not mention missing group" >&2
  exit 1
fi

printf '%s\n' "test-render.sh: ok"
