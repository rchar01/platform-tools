#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
INIT="$ROOT_DIR/bin/platform-pki-init"
TOOL="$ROOT_DIR/bin/platform-pki-inventory-install"
NAMESPACE="$TMP_DIR/namespace"
PKI="$NAMESPACE/pki"
PRIVATE="$TMP_DIR/platform-private"
OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

fail() { printf 'test-inventory-install.sh: %s\n' "$*" >&2; exit 1; }
run() { set +e; "$@" >"$OUT" 2>"$ERR"; STATUS=$?; set -e; }
assert_ok() { [[ $STATUS -eq 0 ]] || fail "expected success; stderr=$(<"$ERR")"; }
assert_fail() { [[ $STATUS -eq 1 ]] || fail "expected failure, got $STATUS"; }

"$INIT" --namespace "$NAMESPACE" >/dev/null
mkdir -p "$PRIVATE/pki"
chmod 700 "$PRIVATE" "$PRIVATE/pki"
cat >"$PRIVATE/pki/services.yml" <<'EOF'
services:
  api:
    common_name: api.example.internal
    dns:
      - api.example.internal
EOF
chmod 600 "$PRIVATE/pki/services.yml"

run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_ok
grep -Fq 'Inventory installed:' "$OUT"
cmp "$PRIVATE/pki/services.yml" "$PKI/inventory/services.yml" || fail 'installed bytes differ'
[[ $(stat -c '%a' "$PKI/inventory/services.yml") == 600 ]] || fail 'installed mode is not 600'

inode=$(stat -c '%i' "$PKI/inventory/services.yml")
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_ok
grep -Fq 'Inventory already current:' "$OUT"
[[ $(stat -c '%i' "$PKI/inventory/services.yml") == "$inode" ]] || fail 'no-op replaced destination'

chmod 400 "$PKI/inventory/services.yml"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_ok
grep -Fq 'Inventory normalized:' "$OUT"
[[ $(stat -c '%a' "$PKI/inventory/services.yml") == 600 ]] || fail 'normalization did not set mode 600'

REAL_CP=$(command -v cp)
REAL_MKDIR=$(command -v mkdir)
REAL_MV=$(command -v mv)
REAL_RM=$(command -v rm)
REAL_LN=$(command -v ln)
RACE_ENV="$TMP_DIR/race-env.sh"

cat >"$RACE_ENV" <<'EOF'
if [[ ${RACE_MODE:-} == source ]]; then
  cp() {
    "$REAL_RM" -f -- "$RACE_SOURCE"
    "$REAL_LN" -s -- "$RACE_TARGET" "$RACE_SOURCE"
    "$REAL_CP" "$@"
  }
elif [[ ${RACE_MODE:-} == parent ]]; then
  mkdir() {
    "$REAL_MKDIR" "$@"
    local last=${!#}
    if [[ ${last##*/} == "$RACE_LOCK_NAME" ]]; then
      "$REAL_MV" -- "$RACE_PARENT" "$RACE_OLD_PARENT"
      "$REAL_MKDIR" -m 700 -- "$RACE_PARENT"
      "$REAL_MKDIR" -m 700 -- "$RACE_PARENT/$RACE_LOCK_NAME"
    fi
  }
elif [[ ${RACE_MODE:-} == publication ]]; then
  mv() {
    if [[ $* == *'--exchange'* && ${RACE_TRIGGERED:-false} == false ]]; then
      RACE_TRIGGERED=true
      "$REAL_MV" -T -- "$RACE_DESTINATION" "$RACE_SAVED_DESTINATION"
      printf '%s\n' 'foreign inventory' >"$RACE_DESTINATION"
      chmod 600 "$RACE_DESTINATION"
    fi
    "$REAL_MV" "$@"
  }
elif [[ ${RACE_MODE:-} == post_exchange ]]; then
  mv() {
    "$REAL_MV" "$@"
    if [[ $* == *'--exchange'* && ${RACE_TRIGGERED:-false} == false ]]; then
      RACE_TRIGGERED=true
      local exchanged_source=${@: -2:1}
      "$REAL_RM" -f -- "$exchanged_source"
    fi
  }
fi
EOF
chmod 600 "$RACE_ENV"

before=$(sha256sum "$PKI/inventory/services.yml")
printf '%s\n' 'not inventory' >"$TMP_DIR/race-target"
run env BASH_ENV="$RACE_ENV" RACE_MODE=source REAL_CP="$REAL_CP" REAL_RM="$REAL_RM" REAL_LN="$REAL_LN" \
  RACE_SOURCE="$PRIVATE/pki/services.yml" RACE_TARGET="$TMP_DIR/race-target" \
  "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
[[ -L $PRIVATE/pki/services.yml ]] || fail 'source replacement race was not triggered'
[[ $(sha256sum "$PKI/inventory/services.yml") == "$before" ]] || fail 'source replacement race changed destination'
rm "$PRIVATE/pki/services.yml"
cp "$PKI/inventory/services.yml" "$PRIVATE/pki/services.yml"
chmod 600 "$PRIVATE/pki/services.yml"

before=$(sha256sum "$PKI/inventory/services.yml")
before=${before%% *}
run env BASH_ENV="$RACE_ENV" RACE_MODE=parent REAL_MKDIR="$REAL_MKDIR" REAL_MV="$REAL_MV" \
  RACE_LOCK_NAME=.platform-pki-inventory-operation.lock \
  RACE_PARENT="$PKI/inventory" RACE_OLD_PARENT="$PKI/inventory-raced" \
  "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
[[ -d $PKI/inventory-raced ]] || fail 'parent replacement race was not triggered'
after=$(sha256sum "$PKI/inventory-raced/services.yml")
[[ ${after%% *} == "$before" ]] || fail 'parent replacement race changed original destination'
rm -rf "$PKI/inventory"
rmdir "$PKI/inventory-raced/.platform-pki-inventory-operation.lock" 2>/dev/null || true
mv "$PKI/inventory-raced" "$PKI/inventory"

cat >"$PRIVATE/pki/services.yml" <<'EOF'
services:
  api:
    common_name: api.example.internal
    dns:
      - api.example.internal
    days: 2
EOF
chmod 600 "$PRIVATE/pki/services.yml"
before=$(sha256sum "$PKI/inventory/services.yml")
before=${before%% *}
run env BASH_ENV="$RACE_ENV" RACE_MODE=publication REAL_MV="$REAL_MV" \
  RACE_DESTINATION="$PKI/inventory/services.yml" RACE_SAVED_DESTINATION="$TMP_DIR/raced-original.yml" \
  "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
[[ $(<"$PKI/inventory/services.yml") == 'foreign inventory' ]] || fail 'publication race did not preserve foreign destination'
after=$(sha256sum "$TMP_DIR/raced-original.yml")
[[ ${after%% *} == "$before" ]] || fail 'publication race did not preserve validated destination'
rm "$PKI/inventory/services.yml"
mv "$TMP_DIR/raced-original.yml" "$PKI/inventory/services.yml"

run env BASH_ENV="$RACE_ENV" RACE_MODE=post_exchange REAL_MV="$REAL_MV" REAL_RM="$REAL_RM" \
  "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
grep -Fq 'requires recovery; retained locks:' "$ERR" || fail 'post-exchange failure did not report retained locks'
[[ -d $PKI/root-ca/.platform-pki-root-operation.lock ]] || fail 'post-exchange failure did not retain root lock'
[[ -d $PKI/intermediate-ca/.platform-pki-intermediate-operation.lock ]] || fail 'post-exchange failure did not retain intermediate lock'
[[ -d $PKI/inventory/.platform-pki-inventory-operation.lock ]] || fail 'post-exchange failure did not retain inventory lock'
guards=("$PKI"/inventory/.platform-pki-inventory-guard.*.link)
[[ -f ${guards[0]} ]] || fail 'post-exchange failure did not preserve old inventory guard'
[[ $(sha256sum "${guards[0]}") == "$before  ${guards[0]}" ]] || fail 'preserved guard does not contain old inventory'
rm "$PKI/inventory/services.yml"
mv "${guards[0]}" "$PKI/inventory/services.yml"
rm -f "${guards[0]%.link}"
rmdir "$PKI/inventory/.platform-pki-inventory-operation.lock"
rmdir "$PKI/intermediate-ca/.platform-pki-intermediate-operation.lock"
rmdir "$PKI/root-ca/.platform-pki-root-operation.lock"

before=$(sha256sum "$PKI/inventory/services.yml")
printf '%s\n' 'services: {}' >"$PRIVATE/pki/services.yml"
chmod 600 "$PRIVATE/pki/services.yml"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
[[ $(sha256sum "$PKI/inventory/services.yml") == "$before" ]] || fail 'invalid source changed destination'

rm "$PRIVATE/pki/services.yml"
ln -s "$PKI/inventory/services.yml" "$PRIVATE/pki/services.yml"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
rm "$PRIVATE/pki/services.yml"
cp "$PKI/inventory/services.yml" "$PRIVATE/pki/services.yml"
ln "$PRIVATE/pki/services.yml" "$PRIVATE/pki/services.link"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
rm "$PRIVATE/pki/services.link"
chmod 622 "$PRIVATE/pki/services.yml"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
chmod 600 "$PRIVATE/pki/services.yml"

mv "$PKI/inventory/services.yml" "$PKI/inventory/services.real"
ln -s "$PKI/inventory/services.real" "$PKI/inventory/services.yml"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
[[ -L $PKI/inventory/services.yml ]] || fail 'unsafe destination was replaced'
rm "$PKI/inventory/services.yml"
mv "$PKI/inventory/services.real" "$PKI/inventory/services.yml"

chmod 777 "$PKI/inventory"
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE"
assert_fail
[[ $(stat -c '%a' "$PKI/inventory") == 777 ]] || fail 'unsafe destination directory was changed'
chmod 700 "$PKI/inventory"

mkdir -p "$TMP_DIR/default/platform-tools" "$TMP_DIR/default/platform-private/pki"
cp "$PRIVATE/pki/services.yml" "$TMP_DIR/default/platform-private/pki/services.yml"
chmod 700 "$TMP_DIR/default" "$TMP_DIR/default/platform-tools" "$TMP_DIR/default/platform-private" "$TMP_DIR/default/platform-private/pki"
chmod 600 "$TMP_DIR/default/platform-private/pki/services.yml"
run bash -c 'cd "$1" && exec "$2" --namespace "$3"' _ "$TMP_DIR/default/platform-tools" "$TOOL" "$NAMESPACE"
assert_ok

run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PKI"
assert_fail
run "$TOOL" --namespace "$NAMESPACE" --private-repo ''
assert_fail
run "$TOOL" --namespace "$NAMESPACE" --private-repo "$PRIVATE" --private-repo "$PRIVATE"
assert_fail

printf '%s\n' 'test-inventory-install.sh: ok'
