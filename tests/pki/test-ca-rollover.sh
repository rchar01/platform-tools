#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d /tmp/platform-tools-test-pki-ca-rollover.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
INIT="$ROOT_DIR/bin/platform-pki-init"; ROOT="$ROOT_DIR/bin/platform-pki-root-create"
INTERMEDIATE="$ROOT_DIR/bin/platform-pki-intermediate-create"; ISSUE="$ROOT_DIR/bin/platform-pki-service-issue"
BACKUP="$ROOT_DIR/bin/platform-pki-backup"; ROLLOVER="$ROOT_DIR/bin/platform-pki-ca-rollover"
PASS="$TMP_DIR/pass"; printf '%s\n' 'phase-five-test-passphrase' >"$PASS"; chmod 600 "$PASS"

fail() { printf 'test-ca-rollover.sh: %s\n' "$*" >&2; exit 1; }

write_inventory() {
  local destination=$1
  mkdir -p "$(dirname -- "$destination")"
  cat >"$destination" <<'EOF'
services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
EOF
  chmod 600 "$destination"
}

create_generation_fixture() {
  local base=$1 ns="$1/ns" pki="$1/ns/pki"
  mkdir -m 700 "$base/private" "$base/private/pki"
  "$INIT" --namespace "$ns" >/dev/null
  write_inventory "$pki/inventory/services.yml"
  write_inventory "$base/private/pki/services.yml"
  "$ROOT" --namespace "$ns" --name 'Test Root' --org Test --country PL --root-pass-file "$PASS" >/dev/null
  [[ -f $pki/state/bootstrap-root && ! -e $pki/state/active-issuer ]] || fail 'root bootstrap manifest contract failed'
  "$INTERMEDIATE" --namespace "$ns" --name 'Test Intermediate' --org Test --country PL \
    --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null
  [[ $(<"$pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail 'active issuer manifest is invalid'
  "$ISSUE" app --namespace "$ns" --intermediate-pass-file "$PASS" >/dev/null
  [[ $(<"$pki/services/app/issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail 'service issuer record is invalid'
}

convert_to_legacy() {
  local base=$1 pki="$1/ns/pki" path old new line tmp
  mv "$pki/authorities/roots/g1" "$pki/root-ca"
  mv "$pki/authorities/intermediates/g1-i1" "$pki/intermediate-ca"
  for path in "$pki/root-ca/openssl.cnf" "$pki/intermediate-ca/openssl.cnf"; do
    if [[ $path == */root-ca/* ]]; then old="$pki/authorities/roots/g1"; new="$pki/root-ca"
    else old="$pki/authorities/intermediates/g1-i1"; new="$pki/intermediate-ca"; fi
    tmp="$path.tmp"; : >"$tmp"
    while IFS= read -r line || [[ -n $line ]]; do
      if [[ $line == 'dir = '* ]]; then printf 'dir = %s\n' "$new" >>"$tmp"; else printf '%s\n' "${line//$old/$new}" >>"$tmp"; fi
    done <"$path"
    chmod 600 "$tmp"; mv "$tmp" "$path"
  done
  rm -f "$pki/state/active-issuer" "$pki/state/generation-reservations/g1" \
    "$pki/state/generation-reservations/g1-i1" "$pki/services/app/issuer"
}

backup_legacy() {
  local base=$1
  "$BACKUP" --namespace "$base/ns" --backup-dir "$base/backups" --allow-plain-backup >/dev/null 2>&1
  RECEIPT=$(printf '%s\n' "$base"/backups/*.receipt)
  ROOT_FP=$(openssl x509 -in "$base/ns/pki/root-ca/certs/root-ca.crt" -noout -fingerprint -sha256); ROOT_FP=${ROOT_FP#*=}; ROOT_FP=${ROOT_FP//:/}
  INT_FP=$(openssl x509 -in "$base/ns/pki/intermediate-ca/certs/intermediate-ca.crt" -noout -fingerprint -sha256); INT_FP=${INT_FP#*=}; INT_FP=${INT_FP//:/}
}

migrate() {
  local base=$1
  "$ROLLOVER" migrate --namespace "$base/ns" --private-repo "$base/private" \
    --backup-receipt "$RECEIPT" --yes --expected-root-sha256 "$ROOT_FP" \
    --expected-intermediate-sha256 "$INT_FP"
}

seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"

"$ROLLOVER" --help >"$TMP_DIR/help"
grep -Fq 'migration/bootstrap recovery' "$TMP_DIR/help" || fail 'rollover help footer is stale'
if grep -Fq 'rollback, recovery, retirement' "$TMP_DIR/help"; then fail 'rollover help still advertises implemented recovery as deferred'; fi

metadata_case="$TMP_DIR/private-metadata"; cp -a "$seed" "$metadata_case"; convert_to_legacy "$metadata_case"; backup_legacy "$metadata_case"; touch "$metadata_case/ns/pki/root-ca/private/root-ca.key"
if migrate "$metadata_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'migration accepted changed private metadata'; fi
grep -Fq 'private metadata differs' "$TMP_DIR/stderr" || fail 'private metadata mismatch was not reported'

for private_case in passphrase quarantine; do
  case_dir="$TMP_DIR/private-$private_case"; cp -a "$seed" "$case_dir"; convert_to_legacy "$case_dir"; if [[ $private_case == passphrase ]]; then private_dir="$case_dir/ns/pki/operator-private"; private_file="$private_dir/secret-passphrase"; else private_dir="$case_dir/ns/pki/quarantine"; private_file="$private_dir/private-secret"; fi; mkdir -m 700 "$private_dir"; printf '%s\n' private-sentinel >"$private_file"; chmod 600 "$private_file"; backup_legacy "$case_dir"; touch "$private_file"
  if migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "migration accepted changed $private_case private metadata"; fi
  grep -Fq 'private metadata differs' "$TMP_DIR/stderr" || fail "$private_case private metadata mismatch was not reported"
done

extra_case="$TMP_DIR/extra-service"; cp -a "$seed" "$extra_case"; convert_to_legacy "$extra_case"; mkdir -m 700 "$extra_case/ns/pki/services/not-in-inventory"; backup_legacy "$extra_case"
if migrate "$extra_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'migration accepted an extra service directory'; fi
grep -Fq 'absent from inventory' "$TMP_DIR/stderr" || fail 'extra service mismatch was not reported'

foreign_case="$TMP_DIR/foreign-recovery"; cp -a "$seed" "$foreign_case"; convert_to_legacy "$foreign_case"; backup_legacy "$foreign_case"
PLATFORM_PKI_MIGRATE_FAIL_AT=after-reservations migrate "$foreign_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr" || true
foreign_pki="$foreign_case/ns/pki"; foreign_transaction=$(sed -n 's/^transaction=//p' "$foreign_pki/state/rollover/journal"); printf '%s\n' foreign >>"$foreign_pki/state/rollover/$foreign_transaction/services"
if "$ROLLOVER" recover --namespace "$foreign_case/ns" --transaction "$foreign_transaction" --action rollback --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'recovery accepted replaced transaction evidence'; fi
grep -Fq 'service set changed' "$TMP_DIR/stderr" || fail 'foreign recovery evidence was not rejected'

for boundary in after-reservations after-root-rename after-intermediate-rename after-configs after-issuers after-quarantine after-active; do
  for action in rollback resume; do
    case_dir="$TMP_DIR/${boundary}-${action}"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"
    convert_to_legacy "$case_dir"; backup_legacy "$case_dir"
    if PLATFORM_PKI_MIGRATE_FAIL_AT=$boundary migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "fault injection unexpectedly succeeded at $boundary"; fi
    transaction=$(sed -n 's/^transaction=//p' "$pki/state/rollover/journal")
    [[ -n $transaction ]] || fail "missing transaction after $boundary"
    set +e; "$ROLLOVER" status --namespace "$case_dir/ns" >"$TMP_DIR/recovery-status"; status=$?; set -e
    [[ $status -eq 2 ]] || fail "status did not require recovery after $boundary"
    "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >/dev/null
    if [[ $action == rollback ]]; then
      [[ -d $pki/root-ca && -d $pki/intermediate-ca && ! -e $pki/state/active-issuer && ! -e $pki/services/app/issuer ]] || fail "rollback did not restore legacy state after $boundary"
    else
      [[ -d $pki/authorities/roots/g1 && -d $pki/authorities/intermediates/g1-i1 && -f $pki/state/active-issuer && -f $pki/services/app/issuer ]] || fail "resume did not complete generation state after $boundary"
    fi
    grep -Fx 'committed=true' "$pki/state/rollover/journal" >/dev/null || fail "recovery did not commit after $boundary/$action"
  done
done

unresolved_case="$TMP_DIR/unresolved-failure"; cp -a "$seed" "$unresolved_case"; unresolved_pki="$unresolved_case/ns/pki"; convert_to_legacy "$unresolved_case"; backup_legacy "$unresolved_case"
if PLATFORM_PKI_MIGRATE_FAIL_AT=after-reservations migrate "$unresolved_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'injected migration failure unexpectedly succeeded'; fi
grep -Fx 'committed=false' "$unresolved_pki/state/rollover/journal" >/dev/null || fail 'migration failure automatically closed its journal'
[[ -f $unresolved_pki/state/rollover/recovery-required ]] || fail 'migration failure did not publish a recovery marker'
if "$ROLLOVER" status --namespace "$unresolved_case/ns" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'normal status ignored an unresolved migration'; fi
transaction=$(sed -n 's/^transaction=//p' "$unresolved_pki/state/rollover/journal")
"$ROLLOVER" recover --namespace "$unresolved_case/ns" --transaction "$transaction" --action rollback --yes >/dev/null

for category in manifest readme quarantine; do
  case_dir="$TMP_DIR/provenance-$category"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; printf '%s\n' private-sentinel >"$pki/pki.env"; chmod 600 "$pki/pki.env"; backup_legacy "$case_dir"
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=after-journal migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "provenance fixture crash failed for $category"
  journal="$pki/state/rollover/journal"; transaction=$(sed -n 's/^transaction=//p' "$journal"); provenance=$(sed -n 's/^provenance_stage=//p' "$journal")
  grep -Fq '|quarantine/pki.env|' "$provenance/provenance-manifest" || fail 'provenance manifest omitted quarantined material'
  grep -F '|quarantine/pki.env|' "$provenance/provenance-manifest" | grep -Fq '|secret' || fail 'provenance manifest hashed potentially private quarantine content'
  case $category in manifest) printf '%s\n' tampered >>"$provenance/provenance-manifest" ;; readme) printf '%s\n' tampered >>"$provenance/README" ;; quarantine) printf '%s\n' tampered >>"$provenance/quarantine/pki.env" ;; esac
  if "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action resume --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted tampered provenance $category"; fi
done

for action in rollback resume; do
  case_dir="$TMP_DIR/recovery-of-recovery-$action"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; printf '%s\n' legacy-config >"$pki/pki.env"; chmod 600 "$pki/pki.env"; backup_legacy "$case_dir"
  if [[ $action == rollback ]]; then migration_boundary=after-active; recovery_boundaries=(rollback-active rollback-issuer-app rollback-quarantine-pki.env rollback-config-root rollback-config-intermediate rollback-intermediate-rename rollback-root-rename rollback-reservation-root rollback-reservation-intermediate rollback-backup-session rollback-provenance)
  else migration_boundary=after-journal; recovery_boundaries=(resume-backup-session resume-reservation-root resume-reservation-intermediate resume-root-rename resume-intermediate-rename resume-config-root resume-config-intermediate resume-issuer-app resume-quarantine-pki.env resume-consume-root resume-consume-intermediate resume-active resume-provenance); fi
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=$migration_boundary migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "migration recovery-of-recovery fixture failed for $action"
  transaction=$(sed -n 's/^transaction=//p' "$pki/state/rollover/journal")
  for recovery_boundary in "${recovery_boundaries[@]}"; do
    for checkpoint in pending done; do
      set +e; PLATFORM_PKI_RECOVER_CRASH_AT="$recovery_boundary-$checkpoint" "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
      [[ $crash_status -eq 137 ]] || fail "recovery SIGKILL status at $recovery_boundary-$checkpoint/$action was $crash_status: $(<"$TMP_DIR/stderr")"
    done
  done
  "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >/dev/null
  grep -Fx 'committed=true' "$pki/state/rollover/journal" >/dev/null || fail "recovery-of-recovery did not commit for $action"
  if [[ $action == resume ]]; then [[ -f $pki/legacy/$transaction/README && $(<"$pki/legacy/$transaction/quarantine/pki.env") == legacy-config ]] || fail 'resume did not publish complete migration provenance'
  else [[ ! -e $pki/legacy/$transaction && ! -e $pki/legacy/.$transaction.publish ]] || fail 'rollback retained uncommitted migration provenance'; fi
done

for boundary in after-reservations after-root-rename after-intermediate-rename after-configs after-issuers after-quarantine after-active; do
  case_dir="$TMP_DIR/crash-$boundary"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; backup_legacy "$case_dir"
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=$boundary migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "migration SIGKILL status at $boundary was $crash_status"
  transaction=$(sed -n 's/^transaction=//p' "$pki/state/rollover/journal")
  "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action rollback --yes >/dev/null
  [[ -d $pki/root-ca && -d $pki/intermediate-ca ]] || fail "SIGKILL rollback did not restore legacy state after $boundary"
  migrate "$case_dir" >/dev/null || fail "migration retry failed after SIGKILL rollback at $boundary"
done

for category in backup-session root-reservation intermediate-reservation root-config-original root-config-published intermediate-config-published issuer quarantine active dual-root dual-intermediate; do
  case_dir="$TMP_DIR/hostile-$category"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"
  printf '%s\n' legacy-config >"$pki/pki.env"; chmod 600 "$pki/pki.env"; backup_legacy "$case_dir"
  case $category in
    backup-session|root-reservation|intermediate-reservation|root-config-original) boundary=after-reservations ;;
    root-config-published|intermediate-config-published) boundary=after-configs ;;
    issuer) boundary=after-issuers ;;
    quarantine) boundary=after-quarantine ;;
    active) boundary=after-active ;;
    dual-root) boundary=after-root-rename ;;
    dual-intermediate) boundary=after-intermediate-rename ;;
  esac
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=$boundary migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "hostile fixture crash failed for $category"
  journal="$pki/state/rollover/journal"; transaction=$(sed -n 's/^transaction=//p' "$journal")
  case $category in
    backup-session) hostile_path=$(sed -n 's/^backup_session=//p' "$journal") ;;
    root-reservation) hostile_path="$pki/state/generation-reservations/g1" ;;
    intermediate-reservation) hostile_path="$pki/state/generation-reservations/g1-i1" ;;
    root-config-original) hostile_path="$pki/root-ca/openssl.cnf" ;;
    root-config-published) hostile_path="$pki/authorities/roots/g1/openssl.cnf" ;;
    intermediate-config-published) hostile_path="$pki/authorities/intermediates/g1-i1/openssl.cnf" ;;
    issuer) hostile_path="$pki/services/app/issuer" ;;
    quarantine) hostile_path="$pki/state/rollover/$transaction/quarantine/pki.env" ;;
    active) hostile_path="$pki/state/active-issuer" ;;
    dual-root) mkdir -m 700 "$pki/root-ca"; hostile_path="$pki/root-ca" ;;
    dual-intermediate) mkdir -m 700 "$pki/intermediate-ca"; hostile_path="$pki/intermediate-ca" ;;
  esac
  if [[ $category != dual-root && $category != dual-intermediate ]]; then rm -f -- "$hostile_path"; printf '%s\n' "hostile-$category" >"$hostile_path"; chmod 600 "$hostile_path"; fi
  if "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action rollback --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted hostile $category replacement"; fi
  if [[ $category == dual-root ]]; then [[ -d $pki/root-ca && -d $pki/authorities/roots/g1 ]] || fail 'dual root paths were nested or removed'
  elif [[ $category == dual-intermediate ]]; then [[ -d $pki/intermediate-ca && -d $pki/authorities/intermediates/g1-i1 ]] || fail 'dual intermediate paths were nested or removed'
  else [[ $(<"$hostile_path") == "hostile-$category" ]] || fail "recovery changed hostile $category replacement"; fi
done

for dual in root intermediate; do
  case_dir="$TMP_DIR/preflight-dual-$dual"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; backup_legacy "$case_dir"
  if [[ $dual == root ]]; then mkdir -m 700 "$pki/authorities/roots/g1"; else mkdir -m 700 "$pki/authorities/intermediates/g1-i1"; fi
  if migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "migration accepted simultaneous legacy/generation $dual paths"; fi
  grep -Eq 'incomplete or ambiguous|partial' "$TMP_DIR/stderr" || fail "dual $dual layout rejection was not reported"
done

primary="$TMP_DIR/primary"; cp -a "$seed" "$primary"; pki="$primary/ns/pki"
root_key_inode=$(stat -c '%d:%i' "$pki/authorities/roots/g1/private/root-ca.key"); int_key_inode=$(stat -c '%d:%i' "$pki/authorities/intermediates/g1-i1/private/intermediate-ca.key")
convert_to_legacy "$primary"; backup_legacy "$primary"; migrate "$primary" >/dev/null
[[ $(stat -c '%d:%i' "$pki/authorities/roots/g1/private/root-ca.key") == "$root_key_inode" ]] || fail 'root key inode changed during migration'
[[ $(stat -c '%d:%i' "$pki/authorities/intermediates/g1-i1/private/intermediate-ca.key") == "$int_key_inode" ]] || fail 'intermediate key inode changed during migration'
[[ $(<"$pki/services/app/issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail 'migrated issuer record is invalid'
migrate "$primary" >"$TMP_DIR/noop"
grep -Fq 'already complete' "$TMP_DIR/noop" || fail 'idempotent migration did not report no-op'

cat >"$pki/state/rollover/journal" <<'EOF'
schema=2
operation=legacy-migrate
transaction=migrate-20260730-000000-1
phase=root-renamed
committed=false
EOF
chmod 600 "$pki/state/rollover/journal"
set +e
"$ROLLOVER" status --namespace "$primary/ns" >"$TMP_DIR/recovery-status"
status=$?
set -e
[[ $status -eq 2 ]] || fail "recovery-required status was $status instead of 2"
grep -Fq 'status=recovery-required' "$TMP_DIR/recovery-status" || fail 'status did not report recovery-required'

printf '%s\n' 'test-ca-rollover.sh: ok'
