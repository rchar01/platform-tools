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
assert_fails_with() {
  local label=$1 expected=$2
  shift 2
  if "$@" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "$label unexpectedly succeeded"; fi
  grep -Fq "$expected" "$TMP_DIR/stderr" || fail "$label did not report: $expected; stdout=$(<"$TMP_DIR/stdout"); stderr=$(<"$TMP_DIR/stderr")"
}
assert_fails() {
  local label=$1
  shift
  if "$@" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "$label unexpectedly succeeded"; fi
}
test_progress() {
  local status=$1 scenario=$2
  [[ ${PLATFORM_PKI_TEST_PROGRESS:-0} == 1 ]] || return 0
  printf 'test-ca-rollover.sh: progress elapsed=%ss status=%s scenario=%s\n' "$SECONDS" "$status" "$scenario" >&2
}

without_option() {
  local rejected=$1 option skip=false
  shift
  OPTION_RESULT=()
  for option in "$@"; do
    if [[ $skip == true ]]; then skip=false; continue; fi
    if [[ $option == "$rejected" ]]; then skip=true; continue; fi
    OPTION_RESULT+=("$option")
  done
}

crash_recovery_at() {
  local namespace=$1 transaction=$2 action=$3 checkpoint=$4 status
  test_progress start "recover:$action:$checkpoint"
  set +e
  PLATFORM_PKI_RECOVER_CRASH_AT=$checkpoint "$ROLLOVER" recover --namespace "$namespace" --transaction "$transaction" --action "$action" --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  status=$?
  set -e
  [[ $status -eq 137 ]] || fail "recovery SIGKILL status at $checkpoint/$action was $status: $(<"$TMP_DIR/stderr")"
  test_progress pass "recover:$action:$checkpoint"
}

write_inventory() {
  local destination=$1
  mkdir -p "$(dirname -- "$destination")"
  cat >"$destination" <<'EOF'
services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
  next:
    common_name: next.example.internal
    dns:
      - next.example.internal
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

backup_generation() {
  local base=$1
  mkdir -m 700 -p "$base/backups"
  "$BACKUP" --namespace "$base/ns" --backup-dir "$base/backups" --allow-plain-backup >/dev/null
  PREPARE_RECEIPT=$(printf '%s\n' "$base"/backups/*.receipt)
}

write_trust_consumers() {
  local destination=$1
  mkdir -p "$(dirname -- "$destination")"
  cat >"$destination" <<'EOF'
consumers:
  managed-cluster:
    kind: managed
  firewall.manual:
    kind: manual
EOF
  chmod 600 "$destination"
}

crash_prepare_fixture() {
  local case_dir=$1 type=$2 boundary=$3
  test_progress start "prepare:$type:$boundary"
  cp -a "$seed" "$case_dir"
  [[ $type != root ]] || write_trust_consumers "$case_dir/private/pki/trust-consumers.yml"
  backup_generation "$case_dir"
  set +e
  if [[ $type == root ]]; then
    PLATFORM_PKI_PREPARE_CRASH_AT=$boundary "$ROLLOVER" prepare --namespace "$case_dir/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$case_dir/private" >/dev/null 2>"$TMP_DIR/stderr"
  else
    PLATFORM_PKI_PREPARE_CRASH_AT=$boundary "$ROLLOVER" prepare --namespace "$case_dir/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null 2>"$TMP_DIR/stderr"
  fi
  crash_status=$?
  set -e
  [[ $crash_status -eq 137 ]] || fail "hostile fixture crash at $type/$boundary returned $crash_status: $(<"$TMP_DIR/stderr")"
  CRASH_JOURNAL="$case_dir/ns/pki/state/rollover/journal"
  CRASH_TRANSACTION=$(sed -n 's/^transaction=//p' "$CRASH_JOURNAL")
  CRASH_TRANSACTION_DIR="$case_dir/ns/pki/state/rollover/$CRASH_TRANSACTION"
  test_progress pass "prepare:$type:$boundary"
}

assert_hostile_prepare_boundary() {
  local type=$1 boundary=$2 relative=$3 object_type=$4 case_dir hostile original
  case_dir="$TMP_DIR/hostile-prepare-$type-$boundary"
  crash_prepare_fixture "$case_dir" "$type" "$boundary"
  hostile="$CRASH_TRANSACTION_DIR/$relative"; mkdir -p "$(dirname -- "$hostile")"
  if [[ -e $hostile || -L $hostile ]]; then original="$case_dir/original-$boundary"; mv -- "$hostile" "$original"; fi
  if [[ $object_type == directory ]]; then mkdir -m 700 "$hostile"; printf '%s\n' hostile >"$hostile/sentinel"; chmod 600 "$hostile/sentinel"
  else printf '%s\n' "hostile-$boundary" >"$hostile"; chmod 600 "$hostile"; fi
  test_progress start "hostile-recovery:$type:$boundary:$object_type"
  if "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$CRASH_TRANSACTION" --action rollback --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted hostile replacement at $type/$boundary"; fi
  if [[ $object_type == directory ]]; then [[ $(<"$hostile/sentinel") == hostile ]] || fail "recovery changed hostile directory at $type/$boundary"
  else [[ $(<"$hostile") == "hostile-$boundary" ]] || fail "recovery changed hostile file at $type/$boundary"; fi
  [[ $(<"$case_dir/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "hostile recovery changed active state at $type/$boundary"
  test_progress pass "hostile-recovery:$type:$boundary:$object_type"
}

rewrite_same_inode_same_size() {
  local path=$1
  [[ -s $path ]] || fail "same-inode rewrite fixture is empty: $path"
  printf '\000' | dd of="$path" bs=1 count=1 conv=notrunc status=none
}

wait_for_path() {
  local path=$1 count
  for ((count = 0; count < 10000; count++)); do [[ -e $path ]] && return 0; sleep 0.01; done
  fail "timed out waiting for test hook: $path"
}

migrate() {
  local base=$1
  "$ROLLOVER" migrate --namespace "$base/ns" --private-repo "$base/private" \
    --backup-receipt "$RECEIPT" --yes --expected-root-sha256 "$ROOT_FP" \
    --expected-intermediate-sha256 "$INT_FP"
}

run_parser_tests() {
  local option spec value parser_other="$TMP_DIR/parser-other" parser_private="$TMP_DIR/parser-private" parser_unused="$TMP_DIR/parser-unused"
  local -a prepare_cli recover_cli

  "$ROLLOVER" --help >"$TMP_DIR/help"
  grep -Fq 'candidate preparation, recovery, and status' "$TMP_DIR/help" || fail 'rollover help footer is stale'
  grep -Fq 'activate, acknowledge, rollback, retire, and complete remain unavailable' "$TMP_DIR/help" || fail 'rollover help does not identify unavailable transitions'
  assert_fails_with 'repeated status format' 'Option must not be repeated: --format' "$ROLLOVER" status --format text --format json

  prepare_cli=(prepare --namespace "$parser_unused" --pki-dir "$parser_unused/pki" --type intermediate --backup-receipt "$parser_unused.receipt" --intermediate-name Test --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --issuer-safety-days 1)
  for spec in "--namespace:$parser_other" "--pki-dir:$parser_other" '--type:root' "--backup-receipt:$parser_other" '--intermediate-name:Other' '--org:Other' '--country:PL' "--root-pass-file:$parser_other" "--intermediate-pass-file:$parser_other" '--issuer-safety-days:2'; do
    option=${spec%%:*}; value=${spec#*:}; assert_fails_with "repeated prepare $option" 'Option must not be repeated' "$ROLLOVER" "${prepare_cli[@]}" "$option" "$value"
  done
  for spec in '--root-name:Root' '--root-days:2' '--intermediate-days:2' "--private-repo:$parser_private"; do option=${spec%%:*}; value=${spec#*:}; assert_fails_with "repeated prepare $option" 'Option must not be repeated' "$ROLLOVER" "${prepare_cli[@]}" "$option" "$value" "$option" "$value"; done

  recover_cli=(recover --namespace "$parser_unused" --pki-dir "$parser_unused/pki" --transaction prepare-root-20260730-000000-1 --action rollback --yes)
  for spec in "--namespace:$parser_other" "--pki-dir:$parser_other" '--transaction:prepare-root-20260730-000000-2' '--action:resume'; do option=${spec%%:*}; value=${spec#*:}; assert_fails_with "repeated recover $option" 'Option must not be repeated' "$ROLLOVER" "${recover_cli[@]}" "$option" "$value"; done
  assert_fails_with 'repeated recover --yes' 'Option must not be repeated' "$ROLLOVER" "${recover_cli[@]}" --yes

  for option in --namespace --pki-dir --type --backup-receipt --intermediate-name --org --country --root-pass-file --intermediate-pass-file --issuer-safety-days; do without_option "$option" "${prepare_cli[@]:1}"; assert_fails "empty prepare $option" "$ROLLOVER" prepare "${OPTION_RESULT[@]}" "$option" ''; done
  without_option --issuer-safety-days "${prepare_cli[@]:1}"
  assert_fails_with 'empty equals prepare --issuer-safety-days' 'invalid option: --issuer-safety-days=' "$ROLLOVER" prepare "${OPTION_RESULT[@]}" '--issuer-safety-days='
  assert_fails_with 'empty equals shared helper' 'Option must not be empty: --issuer-safety-days' bash -c 'source "$1"; command_line_args=(--issuer-safety-days=); pki_reject_explicit_empty_options --issuer-safety-days' _ "$ROOT_DIR/lib/platform-pki-common.sh"
  for option in --root-name --root-days --intermediate-days --private-repo; do assert_fails "empty prepare $option" "$ROLLOVER" "${prepare_cli[@]}" "$option" ''; done
  for option in --namespace --pki-dir --transaction --action; do without_option "$option" "${recover_cli[@]:1}"; assert_fails "empty recover $option" "$ROLLOVER" recover "${OPTION_RESULT[@]}" "$option" ''; done
  assert_fails 'prepare positional argument' "$ROLLOVER" "${prepare_cli[@]}" unexpected
  assert_fails 'recover positional argument' "$ROLLOVER" "${recover_cli[@]}" unexpected
  for spec in '--root-name:Root' '--root-days:2' "--private-repo:$parser_private"; do option=${spec%%:*}; value=${spec#*:}; assert_fails_with "forbidden intermediate $option" 'forbidden for intermediate preparation' "$ROLLOVER" "${prepare_cli[@]}" "$option" "$value"; done
  for option in --backup-receipt --type --root-name --intermediate-name --org --country --root-days --intermediate-days --root-pass-file --intermediate-pass-file --issuer-safety-days --private-repo; do assert_fails "forbidden recover $option" "$ROLLOVER" "${recover_cli[@]}" "$option" value; done
  for option in --transaction --action --yes; do assert_fails "forbidden prepare $option" "$ROLLOVER" "${prepare_cli[@]}" "$option" value; done
  [[ ! -e $parser_unused && ! -e $parser_unused.receipt && ! -e $parser_other && ! -e $parser_private ]] || fail 'parser tests created PKI operand paths'
}

declare -a STATUS_ENV=()
STATUS_NAMESPACE=''; STATUS_PKI=''

configure_status_environment() {
  local base=$1
  mkdir -m 700 "$base/environment" "$base/environment/home" \
    "$base/environment/config" "$base/environment/tmp"
  STATUS_NAMESPACE="$base/ns"; STATUS_PKI="$base/ns/pki"
  STATUS_ENV=(env -i HOME="$base/environment/home" XDG_CONFIG_HOME="$base/environment/config" TMPDIR="$base/environment/tmp" LC_ALL=C NO_COLOR=1 PATH=/usr/local/bin:/usr/bin:/bin)
}

create_status_control_fixture() {
  local base=$1 lock
  mkdir -m 700 "$base" "$base/ns" "$base/ns/pki" "$base/ns/pki/locks" \
    "$base/ns/pki/state" "$base/ns/pki/state/rollover" \
    "$base/ns/pki/state/rollovers" "$base/ns/pki/state/generation-reservations"
  for lock in lifecycle root intermediate inventory export; do
    (umask 077; : >"$base/ns/pki/locks/$lock")
  done
  configure_status_environment "$base"
}

status_control_manifest() {
  local root=$1 path relative metadata detail
  while IFS= read -r -d '' path; do
    relative=${path#"$root"}; relative=${relative#/}; relative=${relative:-.}
    metadata=$(stat -c '%F\t%a\t%d:%i:%h\t%s\t%y' "$path")
    if [[ -f $path && ! -L $path ]]; then
      detail=$(sha256sum "$path"); detail=${detail%% *}
    elif [[ -d $path && ! -L $path ]]; then detail=directory
    else detail=other
    fi
    printf '%s\t%s\t%s\n' "$relative" "$metadata" "$detail"
  done < <(find "$root" -print0 | LC_ALL=C sort -z)
}

run_invalid_terminal_marker_test() {
  local invalid_terminal="$TMP_DIR/invalid-terminal-marker" marker status control_before control_after
  create_status_control_fixture "$invalid_terminal"
  marker="$STATUS_PKI/state/rollover/recovery-required"
  (umask 077; : >"$marker")
  cat >"$marker" <<'EOF'
transaction=prepare-root-20260730-000000-1
operation=rollover-prepare
terminal_outcome=invalid
EOF
  control_before=$(status_control_manifest "$STATUS_PKI")
  set +e
  "${STATUS_ENV[@]}" "$ROLLOVER" status --namespace "$STATUS_NAMESPACE" --format json >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  status=$?
  set -e
  [[ $status -eq 1 ]] || fail "invalid terminal marker status was $status instead of 1"
  [[ ! -s $TMP_DIR/stdout ]] || fail 'invalid terminal marker status wrote stdout'
  [[ $(<"$TMP_DIR/stderr") == '[ERROR] PKI recovery marker has invalid terminal preparation state' ]] || fail "invalid terminal marker status stderr was unexpected: $(<"$TMP_DIR/stderr")"
  [[ $(<"$marker") == $'transaction=prepare-root-20260730-000000-1\noperation=rollover-prepare\nterminal_outcome=invalid' ]] || fail 'invalid terminal marker status changed the marker'
  control_after=$(status_control_manifest "$STATUS_PKI")
  [[ $control_after == "$control_before" ]] || fail 'invalid terminal marker status changed the control tree'
}

run_unresolved_migration_journal_test() {
  local base="$TMP_DIR/unresolved-migration-journal" journal status control_before control_after
  create_status_control_fixture "$base"
  journal="$STATUS_PKI/state/rollover/journal"
  (umask 077; : >"$journal")
  cat >"$journal" <<'EOF'
schema=2
operation=legacy-migrate
transaction=migrate-20260730-000000-1
phase=root-renamed
committed=false
EOF
  control_before=$(status_control_manifest "$STATUS_PKI")
  set +e
  "${STATUS_ENV[@]}" "$ROLLOVER" status --namespace "$STATUS_NAMESPACE" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "unresolved migration journal status was $status instead of 2"
  [[ ! -s $TMP_DIR/stderr ]] || fail "unresolved migration journal wrote stderr: $(<"$TMP_DIR/stderr")"
  [[ $(<"$TMP_DIR/stdout") == $'status=recovery-required\nrecovery_required=true\ntransaction=migrate-20260730-000000-1\noperation=legacy-migrate\nphase=root-renamed\nterminal_outcome=none\nrequired_action=rollback\naction=run platform-pki-ca-rollover recover --transaction migrate-20260730-000000-1 --action rollback' ]] || fail "unresolved migration journal stdout was unexpected: $(<"$TMP_DIR/stdout")"
  control_after=$(status_control_manifest "$STATUS_PKI")
  [[ $control_after == "$control_before" ]] || fail 'unresolved migration journal status changed the control tree'
}

run_missing_service_issuer_test() {
  local source=$1 base="$TMP_DIR/missing-service-issuer" issuer status pass_mode state_before state_after locks_before locks_after
  cp -a "$source" "$base"
  configure_status_environment "$base"
  mkdir -m 700 "$STATUS_PKI/state/rollovers"
  for lock in lifecycle root intermediate inventory export; do
    [[ -e $STATUS_PKI/locks/$lock ]] || (umask 077; : >"$STATUS_PKI/locks/$lock")
  done
  issuer="$STATUS_PKI/services/app/issuer"; rm -f "$issuer"
  chmod 000 "$STATUS_PKI/authorities/roots/g1/private/root-ca.key" \
    "$STATUS_PKI/authorities/intermediates/g1-i1/private/intermediate-ca.key"
  chmod 000 "$PASS"
  state_before=$(status_control_manifest "$STATUS_PKI/state")
  locks_before=$(status_control_manifest "$STATUS_PKI/locks")
  set +e
  "${STATUS_ENV[@]}" "$ROLLOVER" status --namespace "$STATUS_NAMESPACE" --format json >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  status=$?
  pass_mode=$(stat -c %a "$PASS")
  chmod 600 "$PASS"
  set -e
  [[ $status -eq 1 ]] || fail "missing service issuer status was $status instead of 1"
  [[ ! -s $TMP_DIR/stdout ]] || fail 'missing service issuer status wrote stdout'
  [[ $(<"$TMP_DIR/stderr") == '[ERROR] Service app issuer manifest is missing or unsafe' ]] || fail "missing service issuer stderr was unexpected: $(<"$TMP_DIR/stderr")"
  [[ ! -e $issuer && ! -L $issuer ]] || fail 'missing service issuer status recreated the issuer manifest'
  [[ $pass_mode == 0 ]] || fail 'missing service issuer status changed the passphrase mode'
  state_after=$(status_control_manifest "$STATUS_PKI/state")
  locks_after=$(status_control_manifest "$STATUS_PKI/locks")
  [[ $state_after == "$state_before" && $locks_after == "$locks_before" ]] || fail 'missing service issuer status changed public control state'
}

run_ready_status_test() {
  local source=$1 base="$TMP_DIR/ready-status" status pass_mode state_before state_after locks_before locks_after
  local root_fp root_end root_expiry int_fp int_end int_expiry expected actual
  cp -a "$source" "$base"
  configure_status_environment "$base"
  mkdir -m 700 "$STATUS_PKI/state/rollovers"
  for lock in lifecycle root intermediate inventory export; do
    [[ -e $STATUS_PKI/locks/$lock ]] || (umask 077; : >"$STATUS_PKI/locks/$lock")
  done
  chmod 000 "$STATUS_PKI/authorities/roots/g1/private/root-ca.key" \
    "$STATUS_PKI/authorities/intermediates/g1-i1/private/intermediate-ca.key" "$PASS"
  root_fp=$(openssl x509 -in "$STATUS_PKI/authorities/roots/g1/certs/root-ca.crt" -noout -fingerprint -sha256); root_fp=${root_fp#*=}; root_fp=${root_fp//:/}
  root_end=$(openssl x509 -in "$STATUS_PKI/authorities/roots/g1/certs/root-ca.crt" -noout -enddate); root_expiry=$(date -u -d "${root_end#notAfter=}" '+%Y-%m-%dT%H:%M:%SZ')
  int_fp=$(openssl x509 -in "$STATUS_PKI/authorities/intermediates/g1-i1/certs/intermediate-ca.crt" -noout -fingerprint -sha256); int_fp=${int_fp#*=}; int_fp=${int_fp//:/}
  int_end=$(openssl x509 -in "$STATUS_PKI/authorities/intermediates/g1-i1/certs/intermediate-ca.crt" -noout -enddate); int_expiry=$(date -u -d "${int_end#notAfter=}" '+%Y-%m-%dT%H:%M:%SZ')
  state_before=$(status_control_manifest "$STATUS_PKI/state")
  locks_before=$(status_control_manifest "$STATUS_PKI/locks")
  set +e
  "${STATUS_ENV[@]}" "$ROLLOVER" status --namespace "$STATUS_NAMESPACE" --format json >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  status=$?
  pass_mode=$(stat -c %a "$PASS")
  chmod 600 "$PASS"
  set -e
  [[ $status -eq 0 ]] || fail "ready status was $status instead of 0: $(<"$TMP_DIR/stderr")"
  [[ ! -s $TMP_DIR/stderr ]] || fail "ready status wrote stderr: $(<"$TMP_DIR/stderr")"
  expected=$(jq -cn --arg root_fp "$root_fp" --arg root_expiry "$root_expiry" --arg int_fp "$int_fp" --arg int_expiry "$int_expiry" '{schema:1,status:"ready",recovery_required:false,phase:"idle",active:{root:{generation:"g1",fingerprint_sha256:$root_fp,expires_at:$root_expiry},intermediate:{generation:"g1-i1",fingerprint_sha256:$int_fp,expires_at:$int_expiry}},candidate:null,retired:[],trust_snapshot_sha256:null,services_on_old_issuer:[],required_action:null}')
  actual=$(jq -Sc . <"$TMP_DIR/stdout")
  expected=$(jq -Sc . <<<"$expected")
  [[ $actual == "$expected" ]] || fail "ready status JSON was unexpected: $actual"
  [[ $pass_mode == 0 ]] || fail 'ready status changed the passphrase mode'
  state_after=$(status_control_manifest "$STATUS_PKI/state")
  locks_after=$(status_control_manifest "$STATUS_PKI/locks")
  [[ $state_after == "$state_before" && $locks_after == "$locks_before" ]] || fail 'ready status changed public control state'
  [[ $(stat -c %a "$STATUS_PKI/authorities/roots/g1/private/root-ca.key") == 0 && $(stat -c %a "$STATUS_PKI/authorities/intermediates/g1-i1/private/intermediate-ca.key") == 0 ]] || fail 'ready status changed private-key modes'
}

run_ca_profile_noncritical_basic_constraints_test() {
  local profile_dir="$TMP_DIR/certificate-profiles"
  mkdir -m 700 "$profile_dir"
  openssl req -new -x509 -newkey rsa:2048 -nodes -subj /CN=bad-basic -days 1 -keyout "$profile_dir/basic.key" -out "$profile_dir/basic.crt" -addext 'basicConstraints=CA:true,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
  assert_fails_with 'noncritical CA constraints' 'critical CA:TRUE Basic Constraints' bash -c 'source "$1"; pki_require_ca_certificate_profile "$2" 1 Test' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$profile_dir/basic.crt"
}

run_ca_profile_extra_key_usage_test() {
  local profile_dir="$TMP_DIR/certificate-profiles"
  mkdir -m 700 -p "$profile_dir"
  openssl req -new -x509 -newkey rsa:2048 -nodes -subj /CN=bad-usage -days 1 -keyout "$profile_dir/usage.key" -out "$profile_dir/usage.crt" -addext 'basicConstraints=critical,CA:true,pathlen:1' -addext 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign' >/dev/null 2>&1
  assert_fails_with 'extra CA key usage' 'Key Usage only' bash -c 'source "$1"; pki_require_ca_certificate_profile "$2" 1 Test' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$profile_dir/usage.crt"
}

run_ca_self_signature_corruption_test() {
  local source=$1 profile_dir="$TMP_DIR/certificate-profiles"
  mkdir -m 700 -p "$profile_dir"
  openssl x509 -in "$source" -badsig -out "$profile_dir/bad-self-signature.crt"
  openssl x509 -in "$profile_dir/bad-self-signature.crt" -noout >/dev/null || fail 'corrupted self-signature fixture is not parseable'
  assert_fails 'corrupted root self-signature' openssl verify -check_ss_sig -CAfile "$profile_dir/bad-self-signature.crt" "$profile_dir/bad-self-signature.crt"
  assert_fails_with 'application root self-signature validation' 'Candidate root self-signature is invalid' bash -c 'source "$1"; pki_require_ca_self_signature "$2" "Candidate root"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$profile_dir/bad-self-signature.crt"
}

run_ca_self_signature_selector_test() {
  local profile_dir="$TMP_DIR/certificate-profiles" source="$TMP_DIR/certificate-profiles/root.crt"
  mkdir -m 700 -p "$profile_dir"
  openssl req -new -x509 -newkey rsa:2048 -nodes -subj /CN=valid-root -days 1 -keyout "$profile_dir/root.key" -out "$source" >/dev/null 2>&1
  run_ca_self_signature_corruption_test "$source"
}

IDENTITY_CASE=''; IDENTITY_AFTER=''

run_file_identity_rewrite_test() {
  local identity_before
  IDENTITY_CASE="$TMP_DIR/nanosecond-identity"
  mkdir -m 700 "$IDENTITY_CASE"
  printf '%s' first >"$IDENTITY_CASE/key"; chmod 600 "$IDENTITY_CASE/key"
  identity_before=$(bash -c 'source "$1"; pki_file_identity "$2"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$IDENTITY_CASE/key")
  printf '%s' other >"$IDENTITY_CASE/key"
  IDENTITY_AFTER=$(bash -c 'source "$1"; pki_file_identity "$2"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$IDENTITY_CASE/key")
  [[ $identity_before != "$IDENTITY_AFTER" ]] || fail 'same-size same-second rewrite retained its file identity'
}

run_state_record_identity_test() {
  bash -c 'source "$1"; pki_atomic_write "$2" "identity=$3
"; pki_read_state_record "$2" Identity; [[ ${PKI_RECORD[identity]} == "$3" ]]' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$IDENTITY_CASE/state" "$IDENTITY_AFTER" || fail 'state parser did not preserve a nanosecond identity'
}

run_manifested_tree_rewrite_test() {
  local manifest_case="$TMP_DIR/manifest-removal" manifest_identity manifest_digest tree_identity
  mkdir -m 700 "$manifest_case" "$manifest_case/tree"; printf '%s' first >"$manifest_case/tree/key"; chmod 600 "$manifest_case/tree/key"
  bash -c 'source "$1"; pki_tree_manifest "$2"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$manifest_case/tree" >"$manifest_case/manifest"; chmod 600 "$manifest_case/manifest"
  manifest_identity=$(bash -c 'source "$1"; pki_file_identity "$2"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$manifest_case/manifest"); manifest_digest=$(sha256sum "$manifest_case/manifest"); manifest_digest=${manifest_digest%% *}; tree_identity=$(bash -c 'source "$1"; pki_dir_identity "$2"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$manifest_case/tree")
  printf '%s' other >"$manifest_case/tree/key"
  if bash -c 'source "$1"; pki_remove_manifested_tree "$2" "$3" "$4" "$5" "$6" "$7"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$manifest_case/tree" "$tree_identity" "$manifest_case" "$manifest_case/manifest" "$manifest_identity" "$manifest_digest"; then fail 'manifest cleanup accepted a hostile same-size replacement'; fi
  [[ $(<"$manifest_case/tree/key") == other ]] || fail 'manifest cleanup modified a hostile replacement'
}

JOURNAL_CASE=''

run_committed_prepare_journal_test() {
  JOURNAL_CASE="$TMP_DIR/journal-gating"
  mkdir -m 700 "$JOURNAL_CASE" "$JOURNAL_CASE/state" "$JOURNAL_CASE/state/rollover"
  cat >"$JOURNAL_CASE/state/rollover/journal" <<'EOF'
operation=rollover-prepare
committed=true
EOF
  chmod 600 "$JOURNAL_CASE/state/rollover/journal"
  assert_fails_with 'committed preparation journal gating' 'PKI recovery is required' bash -c 'source "$1"; PKI_DIR=$2; pki_require_no_unresolved_journal' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$JOURNAL_CASE"
}

run_committed_migration_journal_test() {
  JOURNAL_CASE="$TMP_DIR/journal-gating"
  mkdir -m 700 -p "$JOURNAL_CASE/state/rollover"
  cat >"$JOURNAL_CASE/state/rollover/journal" <<'EOF'
operation=legacy-migrate
committed=true
EOF
  chmod 600 "$JOURNAL_CASE/state/rollover/journal"
  bash -c 'source "$1"; PKI_DIR=$2; pki_require_no_unresolved_journal' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$JOURNAL_CASE" || fail 'committed migration journal no longer preserves Phase 5 behavior'
}

run_intermediate_ambiguous_generation_name_test() {
  local case_dir=$1
  assert_fails_with 'ambiguous generation name' 'must identify its new generation ID' "$ROLLOVER" prepare --namespace "$case_dir/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I20 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS"
}

run_intermediate_lifetime_root_margin_test() {
  local case_dir=$1
  assert_fails_with 'invalid intermediate lifetime' 'exceeds the active root validity safety margin' "$ROLLOVER" prepare --namespace "$case_dir/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --intermediate-days 3650 --root-pass-file "$PASS" --intermediate-pass-file "$PASS"
}

run_root_symlinked_private_repository_test() {
  local case_dir=$1
  ln -s "$case_dir/private" "$case_dir/private-link"
  assert_fails_with 'symlinked private repository' 'symlink' "$ROLLOVER" prepare --namespace "$case_dir/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$case_dir/private-link"
  rm -f "$case_dir/private-link"
}

run_root_invalid_trust_consumer_grammar_test() {
  local case_dir=$1
  cat >"$case_dir/private/pki/trust-consumers.yml" <<'EOF'
consumers:
  invalid:
    unknown: manual
EOF
  assert_fails_with 'invalid trust checklist' 'Unsupported trust consumer grammar' "$ROLLOVER" prepare --namespace "$case_dir/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$case_dir/private"
}

run_root_duplicate_yaml_document_marker_test() {
  local case_dir=$1
  cat >"$case_dir/private/pki/trust-consumers.yml" <<'EOF'
---
---
consumers:
  invalid:
    kind: manual
EOF
  assert_fails_with 'duplicate trust document marker' 'document marker is duplicate' "$ROLLOVER" prepare --namespace "$case_dir/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$case_dir/private"
}

run_migration_dual_layout_preflight_test() {
  local dual case_dir pki
  for dual in root intermediate; do
    case_dir="$TMP_DIR/preflight-dual-$dual"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; backup_legacy "$case_dir"
    if [[ $dual == root ]]; then mkdir -m 700 "$pki/authorities/roots/g1"; else mkdir -m 700 "$pki/authorities/intermediates/g1-i1"; fi
    if migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "migration accepted simultaneous legacy/generation $dual paths"; fi
    grep -Eq 'incomplete or ambiguous|partial' "$TMP_DIR/stderr" || fail "dual $dual layout rejection was not reported"
  done
}

run_migration_changed_ca_private_metadata_test() {
  local metadata_case="$TMP_DIR/private-metadata"
  cp -a "$seed" "$metadata_case"; convert_to_legacy "$metadata_case"; backup_legacy "$metadata_case"; touch "$metadata_case/ns/pki/root-ca/private/root-ca.key"
  if migrate "$metadata_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'migration accepted changed private metadata'; fi
  grep -Fq 'private metadata differs' "$TMP_DIR/stderr" || fail 'private metadata mismatch was not reported'
}

run_migration_changed_additional_private_metadata_test() {
  local private_case case_dir private_dir private_file
  for private_case in passphrase quarantine; do
    case_dir="$TMP_DIR/private-$private_case"; cp -a "$seed" "$case_dir"; convert_to_legacy "$case_dir"; if [[ $private_case == passphrase ]]; then private_dir="$case_dir/ns/pki/operator-private"; private_file="$private_dir/secret-passphrase"; else private_dir="$case_dir/ns/pki/quarantine"; private_file="$private_dir/private-secret"; fi; mkdir -m 700 "$private_dir"; printf '%s\n' private-sentinel >"$private_file"; chmod 600 "$private_file"; backup_legacy "$case_dir"; touch "$private_file"
    if migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "migration accepted changed $private_case private metadata"; fi
    grep -Fq 'private metadata differs' "$TMP_DIR/stderr" || fail "$private_case private metadata mismatch was not reported"
  done
}

run_migration_extra_service_directory_test() {
  local extra_case="$TMP_DIR/extra-service"
  cp -a "$seed" "$extra_case"; convert_to_legacy "$extra_case"; mkdir -m 700 "$extra_case/ns/pki/services/not-in-inventory"; backup_legacy "$extra_case"
  if migrate "$extra_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'migration accepted an extra service directory'; fi
  grep -Fq 'absent from inventory' "$TMP_DIR/stderr" || fail 'extra service mismatch was not reported'
}

run_migration_success_preserves_key_inodes_test() {
  local pki root_key_inode int_key_inode
  primary="$TMP_DIR/primary"
  cp -a "$seed" "$primary"; pki="$primary/ns/pki"
  root_key_inode=$(stat -c '%d:%i' "$pki/authorities/roots/g1/private/root-ca.key"); int_key_inode=$(stat -c '%d:%i' "$pki/authorities/intermediates/g1-i1/private/intermediate-ca.key")
  convert_to_legacy "$primary"; backup_legacy "$primary"; migrate "$primary" >/dev/null
  [[ $(stat -c '%d:%i' "$pki/authorities/roots/g1/private/root-ca.key") == "$root_key_inode" ]] || fail 'root key inode changed during migration'
  [[ $(stat -c '%d:%i' "$pki/authorities/intermediates/g1-i1/private/intermediate-ca.key") == "$int_key_inode" ]] || fail 'intermediate key inode changed during migration'
  [[ $(<"$pki/services/app/issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail 'migrated issuer record is invalid'
}

run_migration_completed_layout_idempotence_test() {
  local case_dir=$1
  migrate "$case_dir" >"$TMP_DIR/noop"
  grep -Fq 'already complete' "$TMP_DIR/noop" || fail 'idempotent migration did not report no-op'
}

run_intermediate_prepare_publication_test() {
  local case_dir=$1 active_before prepare_status intermediate_transaction intermediate_manifest
  active_before=$(<"$case_dir/ns/pki/state/active-issuer")
  "$ROLLOVER" prepare --namespace "$case_dir/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null
  [[ $(<"$case_dir/ns/pki/state/active-issuer") == "$active_before" ]] || fail 'intermediate preparation changed the active issuer'
  [[ -d $case_dir/ns/pki/authorities/intermediates/g1-i2 ]] || fail 'intermediate preparation did not publish g1-i2'
  [[ -f $case_dir/ns/pki/state/active-rollover && ! -L $case_dir/ns/pki/state/active-rollover ]] || fail 'intermediate preparation did not publish active-rollover'
  "$ISSUE" next --namespace "$case_dir/ns" --intermediate-pass-file "$PASS" >/dev/null
  openssl verify -CAfile "$case_dir/ns/pki/authorities/roots/g1/certs/root-ca.crt" -untrusted "$case_dir/ns/pki/authorities/intermediates/g1-i1/certs/intermediate-ca.crt" "$case_dir/ns/pki/services/next/certs/tls.crt" >/dev/null || fail 'issuance after intermediate preparation did not use the old active issuer'
  set +e; "$ROLLOVER" status --namespace "$case_dir/ns" --format json >"$case_dir/status.json"; prepare_status=$?; set -e
  [[ $prepare_status -eq 1 ]] || fail "intermediate prepared status returned $prepare_status instead of 1"
  jq -e '.schema == 1 and .status == "prepared" and .type == "intermediate" and .candidate.intermediate.generation == "g1-i2" and (.services_on_old_issuer | sort) == ["app", "next"]' "$case_dir/status.json" >/dev/null || fail 'intermediate preparation JSON status is incorrect'
  intermediate_transaction=$(sed -n 's/^transaction=//p' "$case_dir/ns/pki/state/active-rollover"); intermediate_manifest="$case_dir/ns/pki/state/rollovers/$intermediate_transaction/candidate-intermediate-tree.manifest"
  [[ $(wc -l <"$intermediate_manifest") -eq $(find "$case_dir/ns/pki/authorities/intermediates/g1-i2" -mindepth 1 -xdev -print | wc -l) ]] || fail 'candidate intermediate manifest omitted a tree entry'
  grep -F '|private/intermediate-ca.key|' "$intermediate_manifest" | grep -Fq '|secret' || fail 'candidate intermediate manifest exposed a private-key digest'
  if grep -Fq 'phase-five-test-passphrase' "$intermediate_manifest"; then fail 'candidate intermediate manifest exposed passphrase content'; fi
}

run_overlapping_active_rollover_test() {
  local case_dir=$1
  assert_fails_with 'overlapping preparation' 'An active rollover already exists' "$ROLLOVER" prepare --namespace "$case_dir/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I3 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS"
}

run_root_prepare_publication_test() {
  local case_dir=$1 active_before prepare_status root_transaction root_state
  active_before=$(<"$case_dir/ns/pki/state/active-issuer")
  write_trust_consumers "$case_dir/private/pki/trust-consumers.yml"
  "$ROLLOVER" prepare --namespace "$case_dir/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-days 3650 --intermediate-days 1825 --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$case_dir/private" >/dev/null
  [[ $(<"$case_dir/ns/pki/state/active-issuer") == "$active_before" ]] || fail 'root preparation changed the active issuer'
  [[ -d $case_dir/ns/pki/authorities/roots/g2 && -d $case_dir/ns/pki/authorities/intermediates/g2-i1 ]] || fail 'root preparation did not publish both candidates'
  openssl verify -CAfile "$case_dir/ns/pki/authorities/roots/g2/certs/root-ca.crt" "$case_dir/ns/pki/authorities/intermediates/g2-i1/certs/intermediate-ca.crt" >/dev/null || fail 'root preparation candidate chain is invalid'
  set +e; "$ROLLOVER" status --namespace "$case_dir/ns" --format json >"$case_dir/status.json"; prepare_status=$?; set -e
  [[ $prepare_status -eq 1 ]] || fail "root prepared status returned $prepare_status instead of 1"
  jq -e '.schema == 1 and .status == "prepared" and .type == "root" and .candidate.root.generation == "g2" and .candidate.intermediate.generation == "g2-i1"' "$case_dir/status.json" >/dev/null || fail 'root preparation JSON status is incorrect'
  root_transaction=$(sed -n 's/^transaction=//p' "$case_dir/ns/pki/state/active-rollover"); root_state="$case_dir/ns/pki/state/rollovers/$root_transaction"
  [[ $(wc -l <"$root_state/candidate-root-tree.manifest") -eq $(find "$case_dir/ns/pki/authorities/roots/g2" -mindepth 1 -xdev -print | wc -l) ]] || fail 'candidate root manifest omitted a tree entry'
  [[ $(wc -l <"$root_state/candidate-intermediate-tree.manifest") -eq $(find "$case_dir/ns/pki/authorities/intermediates/g2-i1" -mindepth 1 -xdev -print | wc -l) ]] || fail 'root rollover intermediate manifest omitted a tree entry'
  grep -F '|private/root-ca.key|' "$root_state/candidate-root-tree.manifest" | grep -Fq '|secret' || fail 'candidate root manifest exposed a private-key digest'
  grep -F '|private/intermediate-ca.key|' "$root_state/candidate-intermediate-tree.manifest" | grep -Fq '|secret' || fail 'root rollover intermediate manifest exposed a private-key digest'
  if grep -Fq 'phase-five-test-passphrase' "$root_state"/*.manifest; then fail 'root rollover manifests exposed passphrase content'; fi
}

setup_child_kill_wrappers() {
  wrapper_dir="$TMP_DIR/child-wrappers"; mkdir -m 700 "$wrapper_dir"; real_cp=$(command -v cp); real_openssl=$(command -v openssl)
  cat >"$wrapper_dir/cp" <<'EOF'
#!/usr/bin/env bash
"$REAL_CP" "$@" || exit $?
destination=${!#}
[[ $destination != */state/rollover/* ]] || kill -KILL "$$"
EOF
  cat >"$wrapper_dir/openssl" <<'EOF'
#!/usr/bin/env bash
subcommand=${1:-}
"$REAL_OPENSSL" "$@" || exit $?
[[ $subcommand != "${KILL_OPENSSL_SUBCOMMAND:-}" ]] || kill -KILL "$$"
EOF
  chmod 700 "$wrapper_dir/cp" "$wrapper_dir/openssl"
}

run_child_kill_test() {
  local child=$1 child_case child_type child_active child_status child_journal child_transaction
  test_progress start "child-kill:$child"
  child_case="$TMP_DIR/child-kill-$child"; cp -a "$seed" "$child_case"; child_type=intermediate
  if [[ $child == req ]]; then child_type=root; write_trust_consumers "$child_case/private/pki/trust-consumers.yml"; fi
  backup_generation "$child_case"; child_active=$(<"$child_case/ns/pki/state/active-issuer")
  set +e
  if [[ $child_type == root ]]; then
    env REAL_CP="$real_cp" REAL_OPENSSL="$real_openssl" PLATFORM_PKI_PREPARE_CP="$wrapper_dir/cp" PLATFORM_PKI_PREPARE_OPENSSL="$wrapper_dir/openssl" KILL_OPENSSL_SUBCOMMAND="$child" "$ROLLOVER" prepare --namespace "$child_case/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$child_case/private" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  else
    env REAL_CP="$real_cp" REAL_OPENSSL="$real_openssl" PLATFORM_PKI_PREPARE_CP="$wrapper_dir/cp" PLATFORM_PKI_PREPARE_OPENSSL="$wrapper_dir/openssl" KILL_OPENSSL_SUBCOMMAND="$child" "$ROLLOVER" prepare --namespace "$child_case/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"
  fi
  child_status=$?; set -e
  [[ $child_status -ne 0 ]] || fail "$child child-kill preparation unexpectedly succeeded"
  child_journal="$child_case/ns/pki/state/rollover/journal"; child_transaction=$(sed -n 's/^transaction=//p' "$child_journal")
  [[ -n $child_transaction && -f $child_case/ns/pki/state/rollover/recovery-required ]] || fail "$child child-kill did not retain recovery evidence"
  [[ $(<"$child_case/ns/pki/state/active-issuer") == "$child_active" ]] || fail "$child child-kill changed active state"
  assert_fails_with "$child child-kill resume" 'recover with rollback' "$ROLLOVER" recover --namespace "$child_case/ns" --transaction "$child_transaction" --action resume --yes
  "$ROLLOVER" recover --namespace "$child_case/ns" --transaction "$child_transaction" --action rollback --yes >/dev/null
  [[ $(<"$child_case/ns/pki/state/active-issuer") == "$child_active" && ! -e $child_case/ns/pki/state/rollover/journal ]] || fail "$child child-kill rollback was incomplete"
  test_progress pass "child-kill:$child"
}

run_child_kill_matrix() {
  local child
  setup_child_kill_wrappers
  for child in cp genpkey req ca; do run_child_kill_test "$child"; done
}

run_transaction_manifest_publication_crash_tests() {
  local boundary manifest_case
  for boundary in transaction-manifest-staged transaction-manifest-published; do
    test_progress start "transaction-manifest-recovery:$boundary"
    manifest_case="$TMP_DIR/$boundary"; crash_prepare_fixture "$manifest_case" intermediate "$boundary"
    grep -Fx 'transaction_tree_manifest_pending_identity=none' "$CRASH_JOURNAL" >/dev/null && fail "$boundary did not retain pending immutable-manifest evidence"
    "$ROLLOVER" recover --namespace "$manifest_case/ns" --transaction "$CRASH_TRANSACTION" --action rollback --yes >/dev/null
    [[ $(<"$manifest_case/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "$boundary recovery changed active state"
    test_progress pass "transaction-manifest-recovery:$boundary"
  done
}

run_intermediate_early_checkpoint_rollback_tests() {
  local early_case=$1 boundary max path generation next crash_status transaction
  local -a generation_paths
  for boundary in transaction-dir-pending transaction-dir-done long-stage-pending long-stage-done backup-session-pending backup-session-done reserve-intermediate-pending reserve-intermediate-done stage-dir-pending stage-dir-done sensitive-stage-pending sensitive-root-stage-pending sensitive-root-stage-done sensitive-root-private-pending sensitive-root-private-done sensitive-intermediate-stage-pending sensitive-intermediate-stage-done sensitive-intermediate-private-pending sensitive-intermediate-private-done copied-root-key-pending copied-root-key-done sensitive-stage-done intermediate-stage-config-pending intermediate-stage-config-done intermediate-key-pending intermediate-key-done intermediate-csr-pending intermediate-csr-done intermediate-signing-pending intermediate-signing-done chain-pending chain-done evidence-stage-pending evidence-stage-done; do
    test_progress start "prepare:intermediate:$boundary"
    max=1; shopt -s nullglob; generation_paths=("$early_case/ns/pki/state/generation-reservations/g1-i"* "$early_case/ns/pki/authorities/intermediates/g1-i"*); shopt -u nullglob
    for path in "${generation_paths[@]}"; do generation=${path##*g1-i}; [[ $generation =~ ^[0-9]+$ ]] && (( 10#$generation > max )) && max=$((10#$generation)); done
    next=$((max + 1))
    set +e; PLATFORM_PKI_PREPARE_CRASH_AT=$boundary "$ROLLOVER" prepare --namespace "$early_case/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name "Test G1-I$next Intermediate CA" --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
    [[ $crash_status -eq 137 ]] || fail "early preparation SIGKILL status at $boundary was $crash_status: $(<"$TMP_DIR/stderr")"
    transaction=$(sed -n 's/^transaction=//p' "$early_case/ns/pki/state/rollover/journal")
    "$ROLLOVER" recover --namespace "$early_case/ns" --transaction "$transaction" --action rollback --yes >/dev/null
    [[ ! -e $early_case/ns/pki/state/rollover/journal && ! -e $early_case/ns/pki/state/rollover/recovery-required ]] || fail "early rollback retained recovery state after $boundary"
    test_progress pass "prepare:intermediate:$boundary"
  done
}

run_root_crypto_checkpoint_rollback_tests() {
  local early_root=$1 boundary max path generation next crash_status transaction
  local -a generation_paths
  for boundary in candidate-root-stage-pending candidate-root-directory-pending candidate-root-directory-done candidate-root-private-pending candidate-root-private-done candidate-intermediate-directory-pending candidate-intermediate-directory-done candidate-intermediate-private-pending candidate-intermediate-private-done candidate-root-stage-done root-key-pending root-key-done root-certificate-pending root-certificate-done; do
    test_progress start "prepare:root:$boundary"
    max=1; shopt -s nullglob; generation_paths=("$early_root/ns/pki/state/generation-reservations/g"* "$early_root/ns/pki/authorities/roots/g"*); shopt -u nullglob
    for path in "${generation_paths[@]}"; do generation=${path##*/g}; [[ $generation =~ ^[0-9]+$ ]] && (( 10#$generation > max )) && max=$((10#$generation)); done
    next=$((max + 1))
    set +e; PLATFORM_PKI_PREPARE_CRASH_AT=$boundary "$ROLLOVER" prepare --namespace "$early_root/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name "Test G$next Root CA" --intermediate-name "Test G$next-I1 Intermediate CA" --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$early_root/private" >/dev/null 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
    [[ $crash_status -eq 137 ]] || fail "root crypto SIGKILL status at $boundary was $crash_status: $(<"$TMP_DIR/stderr")"
    transaction=$(sed -n 's/^transaction=//p' "$early_root/ns/pki/state/rollover/journal")
    "$ROLLOVER" recover --namespace "$early_root/ns" --transaction "$transaction" --action rollback --yes >/dev/null
    test_progress pass "prepare:root:$boundary"
  done
}

run_hostile_prepare_spec() {
  local spec=$1 hostile_type hostile_boundary hostile_relative hostile_object_type
  IFS=: read -r hostile_type hostile_boundary hostile_relative hostile_object_type <<<"$spec"
  assert_hostile_prepare_boundary "$hostile_type" "$hostile_boundary" "$hostile_relative" "$hostile_object_type"
}

run_intermediate_hostile_staged_directory_tests() {
  local spec
  for spec in \
    'intermediate:sensitive-stage-pending:stage/root:directory' \
    'intermediate:sensitive-stage-done:stage/root:directory' \
    'intermediate:sensitive-root-stage-pending:stage/root:directory' \
    'intermediate:sensitive-root-stage-done:stage/root:directory' \
    'intermediate:sensitive-root-private-pending:stage/root/private:directory' \
    'intermediate:sensitive-root-private-done:stage/root/private:directory' \
    'intermediate:sensitive-intermediate-stage-pending:stage/intermediate:directory' \
    'intermediate:sensitive-intermediate-stage-done:stage/intermediate:directory' \
    'intermediate:sensitive-intermediate-private-pending:stage/intermediate/private:directory' \
    'intermediate:sensitive-intermediate-private-done:stage/intermediate/private:directory'; do
    run_hostile_prepare_spec "$spec"
  done
}

run_intermediate_hostile_staged_file_tests() {
  local spec
  for spec in \
    'intermediate:copied-root-key-pending:stage/root/private/root-ca.key:file' \
    'intermediate:copied-root-key-done:stage/root/private/root-ca.key:file' \
    'intermediate:intermediate-key-pending:stage/intermediate/private/intermediate-ca.key:file' \
    'intermediate:intermediate-key-done:stage/intermediate/private/intermediate-ca.key:file' \
    'intermediate:intermediate-signing-pending:stage/intermediate/certs/intermediate-ca.crt:file' \
    'intermediate:intermediate-signing-done:stage/intermediate/certs/intermediate-ca.crt:file'; do
    run_hostile_prepare_spec "$spec"
  done
}

run_root_hostile_staged_directory_tests() {
  local spec
  for spec in \
    'root:candidate-root-stage-pending:stage/root:directory' \
    'root:candidate-root-stage-done:stage/root:directory' \
    'root:candidate-root-directory-pending:stage/root:directory' \
    'root:candidate-root-directory-done:stage/root:directory' \
    'root:candidate-root-private-pending:stage/root/private:directory' \
    'root:candidate-root-private-done:stage/root/private:directory' \
    'root:candidate-intermediate-directory-pending:stage/intermediate:directory' \
    'root:candidate-intermediate-directory-done:stage/intermediate:directory' \
    'root:candidate-intermediate-private-pending:stage/intermediate/private:directory' \
    'root:candidate-intermediate-private-done:stage/intermediate/private:directory'; do
    run_hostile_prepare_spec "$spec"
  done
}

run_root_hostile_staged_file_tests() {
  local spec
  for spec in \
    'root:root-key-pending:stage/root/private/root-ca.key:file' \
    'root:root-key-done:stage/root/private/root-ca.key:file' \
    'root:intermediate-key-pending:stage/intermediate/private/intermediate-ca.key:file' \
    'root:intermediate-key-done:stage/intermediate/private/intermediate-ca.key:file' \
    'root:intermediate-signing-pending:stage/intermediate/certs/intermediate-ca.crt:file' \
    'root:intermediate-signing-done:stage/intermediate/certs/intermediate-ca.crt:file'; do
    run_hostile_prepare_spec "$spec"
  done
}

run_all_hostile_staged_replacement_tests() {
  run_intermediate_hostile_staged_directory_tests
  run_intermediate_hostile_staged_file_tests
  run_root_hostile_staged_directory_tests
  run_root_hostile_staged_file_tests
}

run_staged_rewrite_spec() {
  local spec=$1 rewrite_type rewrite_boundary rewrite_relative rewrite_case rewrite_path rewrite_inode rewrite_size
  IFS=: read -r rewrite_type rewrite_boundary rewrite_relative <<<"$spec"
  test_progress start "staged-rewrite:$rewrite_type:$rewrite_boundary"
  rewrite_case="$TMP_DIR/rewrite-$rewrite_type-$rewrite_boundary"; crash_prepare_fixture "$rewrite_case" "$rewrite_type" "$rewrite_boundary"
  rewrite_path="$CRASH_TRANSACTION_DIR/$rewrite_relative"; rewrite_inode=$(stat -c '%d:%i' "$rewrite_path"); rewrite_size=$(stat -c '%s' "$rewrite_path")
  rewrite_same_inode_same_size "$rewrite_path"
  [[ $(stat -c '%d:%i:%s' "$rewrite_path") == "$rewrite_inode:$rewrite_size" ]] || fail "rewrite fixture did not preserve inode and size at $rewrite_type/$rewrite_boundary"
  if "$ROLLOVER" recover --namespace "$rewrite_case/ns" --transaction "$CRASH_TRANSACTION" --action rollback --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted same-inode rewrite at $rewrite_type/$rewrite_boundary"; fi
  [[ $(stat -c '%d:%i:%s' "$rewrite_path") == "$rewrite_inode:$rewrite_size" ]] || fail "recovery deleted same-inode rewrite at $rewrite_type/$rewrite_boundary"
  [[ $(<"$rewrite_case/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "same-inode rewrite recovery changed active state at $rewrite_type/$rewrite_boundary"
  test_progress pass "staged-rewrite:$rewrite_type:$rewrite_boundary"
}

run_intermediate_same_inode_staged_rewrite_tests() {
  local spec
  for spec in \
    'intermediate:copied-root-key-done:stage/root/private/root-ca.key' \
    'intermediate:intermediate-key-done:stage/intermediate/private/intermediate-ca.key' \
    'intermediate:intermediate-csr-done:stage/intermediate/csr/intermediate-ca.csr' \
    'intermediate:intermediate-signing-done:stage/intermediate/certs/intermediate-ca.crt' \
    'intermediate:chain-done:stage/intermediate/certs/ca-chain.crt'; do
    run_staged_rewrite_spec "$spec"
  done
}

run_root_same_inode_staged_rewrite_tests() {
  local spec
  for spec in \
    'root:root-key-done:stage/root/private/root-ca.key' \
    'root:root-certificate-done:stage/root/certs/root-ca.crt'; do
    run_staged_rewrite_spec "$spec"
  done
}

root_db_relative() {
  local key=$1 issued=$2
  case $key in
    index) ROOT_DB_RELATIVE=index.txt ;;
    index_attr) ROOT_DB_RELATIVE=index.txt.attr ;;
    serial) ROOT_DB_RELATIVE=serial ;;
    crlnumber) ROOT_DB_RELATIVE=crlnumber ;;
    index_old) ROOT_DB_RELATIVE=index.txt.old ;;
    index_attr_old) ROOT_DB_RELATIVE=index.txt.attr.old ;;
    serial_old) ROOT_DB_RELATIVE=serial.old ;;
    crlnumber_old) ROOT_DB_RELATIVE=crlnumber.old ;;
    newcert) ROOT_DB_RELATIVE="newcerts/$issued.pem" ;;
    *) fail "unknown staged root DB key: $key" ;;
  esac
}

discover_staged_root_db_keys() {
  local db_probe=$1 key source_identity
  db_probe="$TMP_DIR/$db_probe"; crash_prepare_fixture "$db_probe" intermediate after-staged
  root_db_keys=(index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert); staged_root_db_keys=()
  for key in "${root_db_keys[@]}"; do
    source_identity=$(sed -n "s/^root_${key}_source_identity=//p" "$CRASH_JOURNAL")
    [[ $source_identity == absent ]] || staged_root_db_keys+=("$key")
  done
}

run_staged_root_db_source_identities_test() {
  local db_probe="$TMP_DIR/root-db-source-probe" key source_identity issued actual_identity
  test_progress start root-db-source-identities
  discover_staged_root_db_keys root-db-source-probe
  for key in "${staged_root_db_keys[@]}"; do
    source_identity=$(sed -n "s/^root_${key}_source_identity=//p" "$CRASH_JOURNAL")
    issued=$(sed -n 's/^issued_serial=//p' "$CRASH_JOURNAL"); root_db_relative "$key" "$issued"
    actual_identity=$(bash -c 'source "$1"; pki_file_identity "$2"' _ "$ROOT_DIR/lib/platform-pki-common.sh" "$CRASH_TRANSACTION_DIR/stage/root/$ROOT_DB_RELATIVE")
    [[ $source_identity == "$actual_identity" ]] || fail "staged root DB source lacks full nanosecond identity: $key"
  done
  "$ROLLOVER" recover --namespace "$db_probe/ns" --transaction "$CRASH_TRANSACTION" --action rollback --yes >/dev/null
  test_progress pass root-db-source-identities
}

run_replaced_staged_root_db_source_tests() {
  local key case_dir issued hostile
  for key in "${staged_root_db_keys[@]}"; do
    test_progress start "root-db-hostile:$key"
    case_dir="$TMP_DIR/hostile-root-db-source-$key"; crash_prepare_fixture "$case_dir" intermediate after-staged
    issued=$(sed -n 's/^issued_serial=//p' "$CRASH_JOURNAL"); root_db_relative "$key" "$issued"
    hostile="$CRASH_TRANSACTION_DIR/stage/root/$ROOT_DB_RELATIVE"; mv -- "$hostile" "$case_dir/original-$key"; printf '%s\n' "hostile-$key" >"$hostile"; chmod 600 "$hostile"
    if "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$CRASH_TRANSACTION" --action resume --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted hostile staged root DB source: $key"; fi
    [[ $(<"$hostile") == "hostile-$key" ]] || fail "recovery changed hostile staged root DB source: $key"
    [[ $(<"$case_dir/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "hostile root DB source changed active state: $key"
    test_progress pass "root-db-hostile:$key"
  done
}

run_same_inode_root_db_rewrite_tests() {
  local key case_dir issued rewrite_path rewrite_inode rewrite_size
  for key in "${staged_root_db_keys[@]}"; do
    test_progress start "root-db-rewrite:$key"
    case_dir="$TMP_DIR/rewrite-root-db-source-$key"; crash_prepare_fixture "$case_dir" intermediate after-staged
    issued=$(sed -n 's/^issued_serial=//p' "$CRASH_JOURNAL"); root_db_relative "$key" "$issued"
    rewrite_path="$CRASH_TRANSACTION_DIR/stage/root/$ROOT_DB_RELATIVE"; rewrite_inode=$(stat -c '%d:%i' "$rewrite_path"); rewrite_size=$(stat -c '%s' "$rewrite_path")
    rewrite_same_inode_same_size "$rewrite_path"
    if "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$CRASH_TRANSACTION" --action resume --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted same-inode staged root DB rewrite: $key"; fi
    [[ $(stat -c '%d:%i:%s' "$rewrite_path") == "$rewrite_inode:$rewrite_size" ]] || fail "recovery deleted same-inode staged root DB rewrite: $key"
    [[ $(<"$case_dir/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail "same-inode root DB rewrite changed active state: $key"
    test_progress pass "root-db-rewrite:$key"
  done
}

run_intermediate_major_boundary_spec() {
  local boundary=$1 action=$2 case_dir crash_status transaction key source_identity pre_identity post_identity recovery_boundary checkpoint
  local -a recovery_boundaries
  case_dir="$TMP_DIR/prepare-intermediate-$boundary"; cp -a "$seed" "$case_dir"; backup_generation "$case_dir"
  test_progress start "prepare-recover:intermediate:$boundary:$action"
  set +e; PLATFORM_PKI_PREPARE_CRASH_AT=$boundary "$ROLLOVER" prepare --namespace "$case_dir/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "intermediate preparation crash at $boundary returned $crash_status instead of 137"
  transaction=$(sed -n 's/^transaction=//p' "$case_dir/ns/pki/state/rollover/journal")
  if [[ $boundary == after-staged ]]; then
    recovery_boundaries=(resume-publish-intermediate)
    for key in index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert; do source_identity=$(sed -n "s/^root_${key}_source_identity=//p" "$case_dir/ns/pki/state/rollover/journal"); pre_identity=$(sed -n "s/^root_${key}_pre_identity=//p" "$case_dir/ns/pki/state/rollover/journal"); post_identity=$(sed -n "s/^root_${key}_post_identity=//p" "$case_dir/ns/pki/state/rollover/journal"); [[ $source_identity == absent || $pre_identity == "$post_identity" ]] || recovery_boundaries+=("resume-root-db-$key"); done
    recovery_boundaries+=(resume-consume-intermediate resume-cleanup-root-stage resume-publish-state resume-publish-pointer terminal-transaction terminal-journal)
    for recovery_boundary in "${recovery_boundaries[@]}"; do for checkpoint in pending done; do crash_recovery_at "$case_dir/ns" "$transaction" "$action" "$recovery_boundary-$checkpoint"; done; done
  fi
  "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >/dev/null
  [[ ! -e $case_dir/ns/pki/state/rollover/journal ]] || fail "intermediate recovery left a journal after $boundary"
  if [[ $action == resume ]]; then [[ -d $case_dir/ns/pki/authorities/intermediates/g1-i2 && -f $case_dir/ns/pki/state/active-rollover ]] || fail "intermediate resume did not publish state after $boundary"; else [[ ! -e $case_dir/ns/pki/authorities/intermediates/g1-i2 && ! -e $case_dir/ns/pki/state/active-rollover ]] || fail "intermediate rollback did not restore state after $boundary"; fi
  test_progress pass "prepare-recover:intermediate:$boundary:$action"
}

run_intermediate_major_boundary_rollback_tests() {
  local boundary
  for boundary in after-journal after-root-db after-state; do run_intermediate_major_boundary_spec "$boundary" rollback; done
}

run_intermediate_major_boundary_resume_tests() {
  local boundary
  for boundary in after-intermediate-candidate after-consumed cleanup-root-stage-removed after-pointer; do run_intermediate_major_boundary_spec "$boundary" resume; done
}

run_all_intermediate_major_boundary_tests() {
  local scenario boundary action
  for scenario in after-journal:rollback after-staged:resume after-intermediate-candidate:resume after-root-db:rollback after-consumed:resume cleanup-root-stage-removed:resume after-state:rollback after-pointer:resume; do
    boundary=${scenario%%:*}; action=${scenario#*:}
    run_intermediate_major_boundary_spec "$boundary" "$action"
  done
}

case ${1:-all} in
  all) run_parser_tests; run_invalid_terminal_marker_test; run_unresolved_migration_journal_test ;;
  parser) run_parser_tests; exit 0 ;;
  invalid-terminal-marker) run_invalid_terminal_marker_test; exit 0 ;;
  unresolved-migration-journal) run_unresolved_migration_journal_test; exit 0 ;;
  missing-service-issuer)
    selector_seed="$TMP_DIR/selector-seed"; mkdir -m 700 "$selector_seed"; create_generation_fixture "$selector_seed"
    run_missing_service_issuer_test "$selector_seed"; exit 0
    ;;
  ready-status)
    selector_seed="$TMP_DIR/selector-seed"; mkdir -m 700 "$selector_seed"; create_generation_fixture "$selector_seed"
    run_ready_status_test "$selector_seed"; exit 0
    ;;
  ca-profile-noncritical-basic-constraints) run_ca_profile_noncritical_basic_constraints_test; exit 0 ;;
  ca-profile-extra-key-usage) run_ca_profile_extra_key_usage_test; exit 0 ;;
  ca-self-signature-corruption) run_ca_self_signature_selector_test; exit 0 ;;
  file-identity-rewrite) run_file_identity_rewrite_test; exit 0 ;;
  state-record-nanosecond-identity) run_file_identity_rewrite_test; run_state_record_identity_test; exit 0 ;;
  manifested-tree-rewrite) run_manifested_tree_rewrite_test; exit 0 ;;
  committed-prepare-journal) run_committed_prepare_journal_test; exit 0 ;;
  committed-migration-journal) run_committed_migration_journal_test; exit 0 ;;
  intermediate-ambiguous-generation-name)
    selector_case="$TMP_DIR/intermediate-prepare"; mkdir -m 700 "$selector_case"; create_generation_fixture "$selector_case"; backup_generation "$selector_case"
    run_intermediate_ambiguous_generation_name_test "$selector_case"; exit 0
    ;;
  intermediate-lifetime-root-margin)
    selector_case="$TMP_DIR/intermediate-prepare"; mkdir -m 700 "$selector_case"; create_generation_fixture "$selector_case"; backup_generation "$selector_case"
    run_intermediate_lifetime_root_margin_test "$selector_case"; exit 0
    ;;
  root-symlinked-private-repository|root-invalid-trust-consumer-grammar|root-duplicate-yaml-document-marker)
    selector_case="$TMP_DIR/root-prepare"; mkdir -m 700 "$selector_case"; create_generation_fixture "$selector_case"; write_trust_consumers "$selector_case/private/pki/trust-consumers.yml"; backup_generation "$selector_case"
    case $1 in
      root-symlinked-private-repository) run_root_symlinked_private_repository_test "$selector_case" ;;
      root-invalid-trust-consumer-grammar) run_root_invalid_trust_consumer_grammar_test "$selector_case" ;;
      root-duplicate-yaml-document-marker) run_root_duplicate_yaml_document_marker_test "$selector_case" ;;
    esac
    exit 0
    ;;
  progress-probe)
    test_progress start progress-probe
    test_progress pass progress-probe
    exit 0
    ;;
  migration-dual-layout-preflight)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_migration_dual_layout_preflight_test; exit 0
    ;;
  migration-changed-ca-private-metadata)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_migration_changed_ca_private_metadata_test; exit 0
    ;;
  migration-changed-additional-private-metadata)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_migration_changed_additional_private_metadata_test; exit 0
    ;;
  migration-extra-service-directory)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_migration_extra_service_directory_test; exit 0
    ;;
  migration-success-preserves-key-inodes)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_migration_success_preserves_key_inodes_test
    [[ $primary == "$TMP_DIR/primary" ]] || fail 'successful migration case path was not retained for idempotence testing'
    exit 0
    ;;
  migration-completed-layout-idempotence)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_migration_success_preserves_key_inodes_test
    run_migration_completed_layout_idempotence_test "$primary"
    exit 0
    ;;
  intermediate-prepare-publication)
    selector_case="$TMP_DIR/intermediate-prepare"; mkdir -m 700 "$selector_case"; create_generation_fixture "$selector_case"; backup_generation "$selector_case"
    run_intermediate_prepare_publication_test "$selector_case"; exit 0
    ;;
  overlapping-active-rollover)
    selector_case="$TMP_DIR/overlapping-active-rollover"; mkdir -m 700 "$selector_case"; create_generation_fixture "$selector_case"; backup_generation "$selector_case"
    "$ROLLOVER" prepare --namespace "$selector_case/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null
    run_overlapping_active_rollover_test "$selector_case"; exit 0
    ;;
  root-prepare-publication)
    root_prepare="$TMP_DIR/root-prepare"; mkdir -m 700 "$root_prepare"; create_generation_fixture "$root_prepare"; write_trust_consumers "$root_prepare/private/pki/trust-consumers.yml"; backup_generation "$root_prepare"
    run_root_prepare_publication_test "$root_prepare"; exit 0
    ;;
  intermediate-child-kill-cp|intermediate-child-kill-openssl|root-child-kill-req)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"; setup_child_kill_wrappers
    case $1 in
      intermediate-child-kill-cp) run_child_kill_test cp ;;
      intermediate-child-kill-openssl) run_child_kill_test genpkey; run_child_kill_test ca ;;
      root-child-kill-req) run_child_kill_test req ;;
    esac
    exit 0
    ;;
  transaction-manifest-publication-crash)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_transaction_manifest_publication_crash_tests; exit 0
    ;;
  intermediate-early-checkpoint-rollback)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    selector_case="$TMP_DIR/prepare-early-boundaries"; cp -a "$seed" "$selector_case"; backup_generation "$selector_case"
    run_intermediate_early_checkpoint_rollback_tests "$selector_case"; exit 0
    ;;
  root-crypto-checkpoint-rollback)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    selector_case="$TMP_DIR/prepare-root-crypto-boundaries"; cp -a "$seed" "$selector_case"; write_trust_consumers "$selector_case/private/pki/trust-consumers.yml"; backup_generation "$selector_case"
    run_root_crypto_checkpoint_rollback_tests "$selector_case"; exit 0
    ;;
  intermediate-hostile-staged-directory)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_intermediate_hostile_staged_directory_tests; exit 0
    ;;
  intermediate-hostile-staged-file|root-hostile-staged-directory|root-hostile-staged-file)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    case $1 in
      intermediate-hostile-staged-file) run_intermediate_hostile_staged_file_tests ;;
      root-hostile-staged-directory) run_root_hostile_staged_directory_tests ;;
      root-hostile-staged-file) run_root_hostile_staged_file_tests ;;
    esac
    exit 0
    ;;
  intermediate-same-inode-staged-rewrite|root-same-inode-staged-rewrite)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    case $1 in
      intermediate-same-inode-staged-rewrite) run_intermediate_same_inode_staged_rewrite_tests ;;
      root-same-inode-staged-rewrite) run_root_same_inode_staged_rewrite_tests ;;
    esac
    exit 0
    ;;
  staged-root-db-source-identities)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    run_staged_root_db_source_identities_test; exit 0
    ;;
  replaced-staged-root-db-source|same-inode-root-db-rewrite)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    discover_staged_root_db_keys selector-root-db-key-discovery
    "$ROLLOVER" recover --namespace "$TMP_DIR/selector-root-db-key-discovery/ns" --transaction "$CRASH_TRANSACTION" --action rollback --yes >/dev/null
    case $1 in
      replaced-staged-root-db-source) run_replaced_staged_root_db_source_tests ;;
      same-inode-root-db-rewrite) run_same_inode_root_db_rewrite_tests ;;
    esac
    exit 0
    ;;
  intermediate-major-boundary-rollback|intermediate-major-boundary-resume)
    seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
    case $1 in
      intermediate-major-boundary-rollback) run_intermediate_major_boundary_rollback_tests ;;
      intermediate-major-boundary-resume) run_intermediate_major_boundary_resume_tests ;;
    esac
    exit 0
    ;;
  *) fail "unknown test group: $1" ;;
esac

seed="$TMP_DIR/seed"; mkdir -m 700 "$seed"; create_generation_fixture "$seed"
run_missing_service_issuer_test "$seed"
run_ready_status_test "$seed"

run_file_identity_rewrite_test
run_state_record_identity_test

run_manifested_tree_rewrite_test

run_committed_prepare_journal_test
run_committed_migration_journal_test

intermediate_prepare="$TMP_DIR/intermediate-prepare"; mkdir -m 700 "$intermediate_prepare"; create_generation_fixture "$intermediate_prepare"; backup_generation "$intermediate_prepare"
run_intermediate_ambiguous_generation_name_test "$intermediate_prepare"
run_intermediate_lifetime_root_margin_test "$intermediate_prepare"
run_intermediate_prepare_publication_test "$intermediate_prepare"
run_overlapping_active_rollover_test "$intermediate_prepare"

root_prepare="$TMP_DIR/root-prepare"; mkdir -m 700 "$root_prepare"; create_generation_fixture "$root_prepare"; write_trust_consumers "$root_prepare/private/pki/trust-consumers.yml"; backup_generation "$root_prepare"
run_root_symlinked_private_repository_test "$root_prepare"
run_root_invalid_trust_consumer_grammar_test "$root_prepare"
run_root_duplicate_yaml_document_marker_test "$root_prepare"
run_root_prepare_publication_test "$root_prepare"

run_child_kill_matrix

run_transaction_manifest_publication_crash_tests

run_ca_profile_noncritical_basic_constraints_test
run_ca_profile_extra_key_usage_test
run_ca_self_signature_corruption_test "$root_prepare/ns/pki/authorities/roots/g2/certs/root-ca.crt"

early_case="$TMP_DIR/prepare-early-boundaries"; cp -a "$seed" "$early_case"; backup_generation "$early_case"
run_intermediate_early_checkpoint_rollback_tests "$early_case"

early_root="$TMP_DIR/prepare-root-crypto-boundaries"; cp -a "$seed" "$early_root"; write_trust_consumers "$early_root/private/pki/trust-consumers.yml"; backup_generation "$early_root"
run_root_crypto_checkpoint_rollback_tests "$early_root"

run_all_hostile_staged_replacement_tests

run_intermediate_same_inode_staged_rewrite_tests
run_root_same_inode_staged_rewrite_tests

run_staged_root_db_source_identities_test
run_replaced_staged_root_db_source_tests
run_same_inode_root_db_rewrite_tests

run_all_intermediate_major_boundary_tests

test_progress start unexpected-candidate-tree-entry
tree_case="$TMP_DIR/prepare-tree-extra"; cp -a "$seed" "$tree_case"; backup_generation "$tree_case"
set +e; PLATFORM_PKI_PREPARE_CRASH_AT=after-staged "$ROLLOVER" prepare --namespace "$tree_case/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
[[ $crash_status -eq 137 ]] || fail 'tree-manifest fixture did not crash'
transaction=$(sed -n 's/^transaction=//p' "$tree_case/ns/pki/state/rollover/journal"); printf '%s\n' hostile >"$tree_case/ns/pki/state/rollover/$transaction/stage/intermediate/unexpected"; chmod 600 "$tree_case/ns/pki/state/rollover/$transaction/stage/intermediate/unexpected"
assert_fails_with 'unexpected candidate tree entry' 'tree contents do not match' "$ROLLOVER" recover --namespace "$tree_case/ns" --transaction "$transaction" --action resume --yes
test_progress pass unexpected-candidate-tree-entry

terminal_case="$TMP_DIR/prepare-terminal-cleanup"; cp -a "$seed" "$terminal_case"; backup_generation "$terminal_case"
set +e; PLATFORM_PKI_PREPARE_CRASH_AT=after-staged "$ROLLOVER" prepare --namespace "$terminal_case/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >/dev/null 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
[[ $crash_status -eq 137 ]] || fail 'terminal-cleanup fixture did not crash'
transaction=$(sed -n 's/^transaction=//p' "$terminal_case/ns/pki/state/rollover/journal")
for checkpoint in terminal-transaction-pending terminal-transaction-done terminal-journal-pending terminal-journal-done; do
  test_progress start "terminal-status:resume:$checkpoint"
  crash_recovery_at "$terminal_case/ns" "$transaction" resume "$checkpoint"
  set +e; "$ROLLOVER" status --namespace "$terminal_case/ns" --format json >"$terminal_case/status.json"; terminal_status=$?; set -e
  [[ $terminal_status -eq 2 ]] || fail "status ignored interrupted terminal cleanup at $checkpoint"
  jq -e '.schema == 2 and .status == "recovery-required" and .terminal_outcome == "resumed" and .required_action == "resume"' "$terminal_case/status.json" >/dev/null || fail "terminal cleanup JSON was incomplete at $checkpoint"
  set +e; "$ROLLOVER" status --namespace "$terminal_case/ns" --format text >"$terminal_case/status.txt"; terminal_status=$?; set -e
  [[ $terminal_status -eq 2 ]] || fail "text status ignored interrupted terminal cleanup at $checkpoint"
  grep -Fx 'status=recovery-required' "$terminal_case/status.txt" >/dev/null && grep -Fx 'terminal_outcome=resumed' "$terminal_case/status.txt" >/dev/null && grep -Fx 'required_action=resume' "$terminal_case/status.txt" >/dev/null && grep -Fx "action=run platform-pki-ca-rollover recover --transaction $transaction --action resume" "$terminal_case/status.txt" >/dev/null || fail "terminal cleanup text was incomplete at $checkpoint"
  test_progress pass "terminal-status:resume:$checkpoint"
done
"$ROLLOVER" recover --namespace "$terminal_case/ns" --transaction "$transaction" --action resume --yes >/dev/null
[[ ! -e $terminal_case/ns/pki/state/rollover/journal && ! -e $terminal_case/ns/pki/state/rollover/recovery-required ]] || fail 'terminal cleanup retained recovery control state'

rollback_terminal="$TMP_DIR/prepare-rollback-terminal-cleanup"; crash_prepare_fixture "$rollback_terminal" root after-pointer; transaction=$CRASH_TRANSACTION
for checkpoint in terminal-transaction-pending terminal-transaction-done terminal-journal-pending terminal-journal-done; do
  test_progress start "terminal-status:rollback:$checkpoint"
  crash_recovery_at "$rollback_terminal/ns" "$transaction" rollback "$checkpoint"
  set +e; "$ROLLOVER" status --namespace "$rollback_terminal/ns" --format json >"$rollback_terminal/status.json"; terminal_status=$?; set -e
  [[ $terminal_status -eq 2 ]] || fail "status ignored interrupted rollback cleanup at $checkpoint"
  jq -e '.schema == 2 and .status == "recovery-required" and .terminal_outcome == "rolled-back" and .required_action == "rollback"' "$rollback_terminal/status.json" >/dev/null || fail "rollback cleanup JSON was incomplete at $checkpoint"
  set +e; "$ROLLOVER" status --namespace "$rollback_terminal/ns" --format text >"$rollback_terminal/status.txt"; terminal_status=$?; set -e
  [[ $terminal_status -eq 2 ]] || fail "text status ignored interrupted rollback cleanup at $checkpoint"
  grep -Fx 'terminal_outcome=rolled-back' "$rollback_terminal/status.txt" >/dev/null && grep -Fx 'required_action=rollback' "$rollback_terminal/status.txt" >/dev/null && grep -Fx "action=run platform-pki-ca-rollover recover --transaction $transaction --action rollback" "$rollback_terminal/status.txt" >/dev/null || fail "rollback cleanup text was incomplete at $checkpoint"
  test_progress pass "terminal-status:rollback:$checkpoint"
done
"$ROLLOVER" recover --namespace "$rollback_terminal/ns" --transaction "$transaction" --action rollback --yes >/dev/null

test_progress start prepare-terminal-journal-unlink-race
prepare_unlink="$TMP_DIR/prepare-unlink-race"; cp -a "$seed" "$prepare_unlink"; backup_generation "$prepare_unlink"
pause_marker="$TMP_DIR/prepare-unlink.pause"; pause_release="$TMP_DIR/prepare-unlink.release"
PLATFORM_PKI_UNLINK_PAUSE_AT=terminal-journal PLATFORM_PKI_UNLINK_PAUSE_MARKER="$pause_marker" PLATFORM_PKI_UNLINK_PAUSE_RELEASE="$pause_release" "$ROLLOVER" prepare --namespace "$prepare_unlink/ns" --type intermediate --backup-receipt "$PREPARE_RECEIPT" --intermediate-name 'Test G1-I2 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr" &
unlink_pid=$!; wait_for_path "$pause_marker"; unlink_journal="$prepare_unlink/ns/pki/state/rollover/journal"; mv "$unlink_journal" "$unlink_journal.original"; printf '%s\n' hostile-journal >"$unlink_journal"; chmod 600 "$unlink_journal"; touch "$pause_release"
set +e; wait "$unlink_pid"; unlink_status=$?; set -e
[[ $unlink_status -ne 0 && $(<"$unlink_journal") == hostile-journal ]] || fail 'prepare terminal journal unlink deleted a concurrent replacement'
[[ $(<"$prepare_unlink/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail 'prepare terminal unlink race changed active state'
test_progress pass prepare-terminal-journal-unlink-race

test_progress start recover-terminal-marker-unlink-race
recover_unlink="$TMP_DIR/recover-unlink-race"; crash_prepare_fixture "$recover_unlink" intermediate after-staged
pause_marker="$TMP_DIR/recover-unlink.pause"; pause_release="$TMP_DIR/recover-unlink.release"
PLATFORM_PKI_UNLINK_PAUSE_AT=terminal-marker PLATFORM_PKI_UNLINK_PAUSE_MARKER="$pause_marker" PLATFORM_PKI_UNLINK_PAUSE_RELEASE="$pause_release" "$ROLLOVER" recover --namespace "$recover_unlink/ns" --transaction "$CRASH_TRANSACTION" --action resume --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr" &
unlink_pid=$!; wait_for_path "$pause_marker"; unlink_marker="$recover_unlink/ns/pki/state/rollover/recovery-required"; mv "$unlink_marker" "$unlink_marker.original"; printf '%s\n' hostile-marker >"$unlink_marker"; chmod 600 "$unlink_marker"; touch "$pause_release"
set +e; wait "$unlink_pid"; unlink_status=$?; set -e
[[ $unlink_status -ne 0 && $(<"$unlink_marker") == hostile-marker && ! -e $recover_unlink/ns/pki/state/rollover/journal ]] || fail 'recover terminal marker unlink deleted a concurrent replacement'
[[ $(<"$recover_unlink/ns/pki/state/active-issuer") == $'root=g1\nintermediate=g1-i1' ]] || fail 'recover terminal unlink race changed active state'
test_progress pass recover-terminal-marker-unlink-race

for scenario in after-journal:rollback after-staged:resume after-root-candidate:rollback after-intermediate-candidate:resume after-consumed:rollback after-state:resume after-pointer:rollback; do
  boundary=${scenario%%:*}; action=${scenario#*:}; case_dir="$TMP_DIR/prepare-root-$boundary"; cp -a "$seed" "$case_dir"; write_trust_consumers "$case_dir/private/pki/trust-consumers.yml"; backup_generation "$case_dir"
  test_progress start "prepare-recover:root:$boundary:$action"
  set +e; PLATFORM_PKI_PREPARE_CRASH_AT=$boundary "$ROLLOVER" prepare --namespace "$case_dir/ns" --type root --backup-receipt "$PREPARE_RECEIPT" --root-name 'Test G2 Root CA' --intermediate-name 'Test G2-I1 Intermediate CA' --org Test --country US --root-pass-file "$PASS" --intermediate-pass-file "$PASS" --private-repo "$case_dir/private" >/dev/null 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "root preparation crash at $boundary returned $crash_status instead of 137"
  transaction=$(sed -n 's/^transaction=//p' "$case_dir/ns/pki/state/rollover/journal")
  if [[ $boundary == after-root-candidate ]]; then
    printf '%s\n' hostile-candidate >"$case_dir/ns/pki/authorities/roots/g2/certs/root-ca.crt"
    assert_fails_with 'replaced root candidate recovery' 'Candidate root certificate' "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes
    [[ $(<"$case_dir/ns/pki/authorities/roots/g2/certs/root-ca.crt") == hostile-candidate ]] || fail 'recovery changed a hostile root candidate replacement'
    test_progress pass "prepare-recover:root:$boundary:$action"
    continue
  fi
  if [[ $boundary == after-staged ]]; then
    for recovery_boundary in resume-publish-root resume-publish-intermediate resume-consume-root resume-consume-intermediate resume-publish-state resume-publish-pointer terminal-transaction terminal-journal; do for checkpoint in pending done; do crash_recovery_at "$case_dir/ns" "$transaction" "$action" "$recovery_boundary-$checkpoint"; done; done
  elif [[ $boundary == after-pointer ]]; then
    for recovery_boundary in rollback-pointer rollback-intermediate rollback-root rollback-state rollback-stage rollback-reservation-intermediate rollback-reservation-root rollback-backup-session terminal-transaction terminal-journal; do for checkpoint in pending done; do crash_recovery_at "$case_dir/ns" "$transaction" "$action" "$recovery_boundary-$checkpoint"; done; done
  fi
  "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >/dev/null
  [[ ! -e $case_dir/ns/pki/state/rollover/journal ]] || fail "root recovery left a journal after $boundary"
  if [[ $action == resume ]]; then [[ -d $case_dir/ns/pki/authorities/roots/g2 && -d $case_dir/ns/pki/authorities/intermediates/g2-i1 && -f $case_dir/ns/pki/state/active-rollover ]] || fail "root resume did not publish state after $boundary"; else [[ ! -e $case_dir/ns/pki/authorities/roots/g2 && ! -e $case_dir/ns/pki/authorities/intermediates/g2-i1 && ! -e $case_dir/ns/pki/state/active-rollover ]] || fail "root rollback did not restore state after $boundary"; fi
  test_progress pass "prepare-recover:root:$boundary:$action"
done

run_migration_changed_ca_private_metadata_test

run_migration_changed_additional_private_metadata_test

run_migration_extra_service_directory_test

foreign_case="$TMP_DIR/foreign-recovery"; cp -a "$seed" "$foreign_case"; convert_to_legacy "$foreign_case"; backup_legacy "$foreign_case"
PLATFORM_PKI_MIGRATE_FAIL_AT=after-reservations migrate "$foreign_case" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr" || true
foreign_pki="$foreign_case/ns/pki"; foreign_transaction=$(sed -n 's/^transaction=//p' "$foreign_pki/state/rollover/journal"); printf '%s\n' foreign >>"$foreign_pki/state/rollover/$foreign_transaction/services"
if "$ROLLOVER" recover --namespace "$foreign_case/ns" --transaction "$foreign_transaction" --action rollback --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail 'recovery accepted replaced transaction evidence'; fi
grep -Fq 'service set changed' "$TMP_DIR/stderr" || fail 'foreign recovery evidence was not rejected'

for boundary in after-reservations after-root-rename after-intermediate-rename after-configs after-issuers after-quarantine after-active; do
  for action in rollback resume; do
    test_progress start "migrate-recover:$boundary:$action"
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
    test_progress pass "migrate-recover:$boundary:$action"
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
  test_progress start "migration-provenance:$category"
  case_dir="$TMP_DIR/provenance-$category"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; printf '%s\n' private-sentinel >"$pki/pki.env"; chmod 600 "$pki/pki.env"; backup_legacy "$case_dir"
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=after-journal migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "provenance fixture crash failed for $category"
  journal="$pki/state/rollover/journal"; transaction=$(sed -n 's/^transaction=//p' "$journal"); provenance=$(sed -n 's/^provenance_stage=//p' "$journal")
  grep -Fq '|quarantine/pki.env|' "$provenance/provenance-manifest" || fail 'provenance manifest omitted quarantined material'
  grep -F '|quarantine/pki.env|' "$provenance/provenance-manifest" | grep -Fq '|secret' || fail 'provenance manifest hashed potentially private quarantine content'
  case $category in manifest) printf '%s\n' tampered >>"$provenance/provenance-manifest" ;; readme) printf '%s\n' tampered >>"$provenance/README" ;; quarantine) printf '%s\n' tampered >>"$provenance/quarantine/pki.env" ;; esac
  if "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action resume --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; then fail "recovery accepted tampered provenance $category"; fi
  test_progress pass "migration-provenance:$category"
done

for action in rollback resume; do
  test_progress start "migration-recovery-of-recovery:$action"
  case_dir="$TMP_DIR/recovery-of-recovery-$action"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; printf '%s\n' legacy-config >"$pki/pki.env"; chmod 600 "$pki/pki.env"; backup_legacy "$case_dir"
  if [[ $action == rollback ]]; then migration_boundary=after-active; recovery_boundaries=(rollback-active rollback-issuer-app rollback-quarantine-pki.env rollback-config-root rollback-config-intermediate rollback-intermediate-rename rollback-root-rename rollback-reservation-root rollback-reservation-intermediate rollback-backup-session rollback-provenance)
  else migration_boundary=after-journal; recovery_boundaries=(resume-backup-session resume-reservation-root resume-reservation-intermediate resume-root-rename resume-intermediate-rename resume-config-root resume-config-intermediate resume-issuer-app resume-quarantine-pki.env resume-consume-root resume-consume-intermediate resume-active resume-provenance); fi
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=$migration_boundary migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "migration recovery-of-recovery fixture failed for $action"
  transaction=$(sed -n 's/^transaction=//p' "$pki/state/rollover/journal")
  for recovery_boundary in "${recovery_boundaries[@]}"; do
    for checkpoint in pending done; do
      test_progress start "migration-recover:$action:$recovery_boundary-$checkpoint"
      set +e; PLATFORM_PKI_RECOVER_CRASH_AT="$recovery_boundary-$checkpoint" "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
      [[ $crash_status -eq 137 ]] || fail "recovery SIGKILL status at $recovery_boundary-$checkpoint/$action was $crash_status: $(<"$TMP_DIR/stderr")"
      test_progress pass "migration-recover:$action:$recovery_boundary-$checkpoint"
    done
  done
  "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action "$action" --yes >/dev/null
  grep -Fx 'committed=true' "$pki/state/rollover/journal" >/dev/null || fail "recovery-of-recovery did not commit for $action"
  if [[ $action == resume ]]; then [[ -f $pki/legacy/$transaction/README && $(<"$pki/legacy/$transaction/quarantine/pki.env") == legacy-config ]] || fail 'resume did not publish complete migration provenance'
  else [[ ! -e $pki/legacy/$transaction && ! -e $pki/legacy/.$transaction.publish ]] || fail 'rollback retained uncommitted migration provenance'; fi
  test_progress pass "migration-recovery-of-recovery:$action"
done

for boundary in after-reservations after-root-rename after-intermediate-rename after-configs after-issuers after-quarantine after-active; do
  test_progress start "migration-sigkill-retry:$boundary"
  case_dir="$TMP_DIR/crash-$boundary"; cp -a "$seed" "$case_dir"; pki="$case_dir/ns/pki"; convert_to_legacy "$case_dir"; backup_legacy "$case_dir"
  set +e; PLATFORM_PKI_MIGRATE_CRASH_AT=$boundary migrate "$case_dir" >"$TMP_DIR/stdout" 2>"$TMP_DIR/stderr"; crash_status=$?; set -e
  [[ $crash_status -eq 137 ]] || fail "migration SIGKILL status at $boundary was $crash_status"
  transaction=$(sed -n 's/^transaction=//p' "$pki/state/rollover/journal")
  "$ROLLOVER" recover --namespace "$case_dir/ns" --transaction "$transaction" --action rollback --yes >/dev/null
  [[ -d $pki/root-ca && -d $pki/intermediate-ca ]] || fail "SIGKILL rollback did not restore legacy state after $boundary"
  migrate "$case_dir" >/dev/null || fail "migration retry failed after SIGKILL rollback at $boundary"
  test_progress pass "migration-sigkill-retry:$boundary"
done

for category in backup-session root-reservation intermediate-reservation root-config-original root-config-published intermediate-config-published issuer quarantine active dual-root dual-intermediate; do
  test_progress start "migration-hostile:$category"
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
  test_progress pass "migration-hostile:$category"
done

run_migration_dual_layout_preflight_test

run_migration_success_preserves_key_inodes_test
run_migration_completed_layout_idempotence_test "$primary"

printf '%s\n' 'test-ca-rollover.sh: ok'
