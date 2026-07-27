#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-command-contract.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
VERSION=$(cat "$ROOT_DIR/VERSION")

fail() {
  printf 'test-command-contract.sh: %s\n' "$*" >&2
  exit 1
}

run_command() {
  set +e
  HOME="$TMP_DIR/home" XDG_CONFIG_HOME="$TMP_DIR/config" \
    XDG_DATA_HOME="$TMP_DIR/data" "$@" >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

assert_success_stdout() {
  [ "$STATUS" -eq 0 ] || fail "expected status 0 for $*; got $STATUS; stderr=$(cat "$STDERR")"
  [ -s "$STDOUT" ] || fail "expected stdout for $*"
  [ ! -s "$STDERR" ] || fail "expected empty stderr for $*: $(cat "$STDERR")"
}

assert_parser_error() {
  [ "$STATUS" -eq 1 ] || fail "expected parser status 1 for $*; got $STATUS"
  [ ! -s "$STDOUT" ] || fail "expected empty parser-error stdout for $*: $(cat "$STDOUT")"
  [ -s "$STDERR" ] || fail "expected parser-error stderr for $*"
}

mkdir -p "$TMP_DIR/home" "$TMP_DIR/config" "$TMP_DIR/data"

for tool in $SHELL_TOOLS; do
  case " $BASHLY_TOOLS " in
    *" $tool "*) ;;
    *) fail "$tool is in SHELL_TOOLS but not BASHLY_TOOLS" ;;
  esac
  [ -f "$ROOT_DIR/bashly/$tool/settings.yml" ] || fail "missing Bashly settings for $tool"
  [ -f "$ROOT_DIR/bashly/$tool/src/bashly.yml" ] || fail "missing Bashly configuration for $tool"
  [ -x "$ROOT_DIR/bin/$tool" ] || fail "missing generated executable for $tool"
done

for tool in $BASHLY_TOOLS; do
  case " $SHELL_TOOLS " in
    *" $tool "*) ;;
    *) fail "$tool is in BASHLY_TOOLS but not SHELL_TOOLS" ;;
  esac
done

for tool in $SHELL_TOOLS $PYTHON_TOOLS; do
  command="$ROOT_DIR/bin/$tool"
  for flag in --help -h; do
    run_command "$command" "$flag"
    assert_success_stdout "$tool $flag"
  done
  for flag in --version -v; do
    run_command "$command" "$flag"
    assert_success_stdout "$tool $flag"
    [ "$(cat "$STDOUT")" = "$tool $VERSION" ] || \
      fail "unexpected version output for $tool $flag: $(cat "$STDOUT")"
  done

  run_command "$command" --help --contract-invalid-option
  assert_success_stdout "$tool leading --help precedence"
  run_command "$command" --version --contract-invalid-option
  assert_success_stdout "$tool leading --version precedence"
  [ "$(cat "$STDOUT")" = "$tool $VERSION" ] || \
    fail "unexpected precedence version output for $tool"

  run_command "$command" --contract-invalid-option
  assert_parser_error "$tool invalid option"
  run_command "$command" --contract-invalid-option --help
  assert_parser_error "$tool invalid option before --help"
  run_command "$command" --contract-invalid-option --version
  assert_parser_error "$tool invalid option before --version"
done

for subcommand in create list rollback delete; do
  for flag in --help -h; do
    run_command "$ROOT_DIR/bin/platform-proxmox-vm-snapshot" "$subcommand" "$flag"
    assert_success_stdout "platform-proxmox-vm-snapshot $subcommand $flag"
  done
  for action in --help --version; do
    run_command "$ROOT_DIR/bin/platform-proxmox-vm-snapshot" \
      "$subcommand" --contract-invalid-option "$action"
    assert_parser_error "platform-proxmox-vm-snapshot $subcommand invalid option before $action"
  done
done
run_command "$ROOT_DIR/bin/platform-proxmox-vm-snapshot" create --contract-invalid-option
assert_parser_error 'platform-proxmox-vm-snapshot create invalid option'

for subcommand in validate render-host render-csr-configmap; do
  for flag in --help -h; do
    run_command "$ROOT_DIR/bin/platform-bastion-policy" "$subcommand" "$flag"
    assert_success_stdout "platform-bastion-policy $subcommand $flag"
  done
  for action in --help --version; do
    run_command "$ROOT_DIR/bin/platform-bastion-policy" \
      "$subcommand" --contract-invalid-option "$action"
    assert_parser_error "platform-bastion-policy $subcommand invalid option before $action"
  done

  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --inp "$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.valid.yaml"
  assert_parser_error "platform-bastion-policy $subcommand abbreviated option"

  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --inp value --help
  assert_parser_error "platform-bastion-policy $subcommand abbreviation before --help"
  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --help --inp value
  assert_success_stdout "platform-bastion-policy $subcommand abbreviation after --help"

  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --inp value --version
  assert_parser_error "platform-bastion-policy $subcommand abbreviation before --version"
  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --version --inp value
  assert_parser_error "platform-bastion-policy $subcommand abbreviation after --version"

  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --input "$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.valid.yaml" --help
  assert_success_stdout "platform-bastion-policy $subcommand valid option before --help"
  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --input "$ROOT_DIR/tests/bastion-policy/fixtures/access-policy.valid.yaml" --version
  assert_parser_error "platform-bastion-policy $subcommand valid option before --version"

  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --help --contract-invalid-option
  assert_success_stdout "platform-bastion-policy $subcommand invalid option after --help"
  run_command "$ROOT_DIR/bin/platform-bastion-policy" \
    "$subcommand" --version --contract-invalid-option
  assert_parser_error "platform-bastion-policy $subcommand invalid option after --version"
done
run_command "$ROOT_DIR/bin/platform-bastion-policy" validate --contract-invalid-option
assert_parser_error 'platform-bastion-policy validate invalid option'

for abbreviation in --hel --ver; do
  run_command "$ROOT_DIR/bin/platform-bastion-policy" "$abbreviation"
  assert_parser_error "platform-bastion-policy abbreviated root option $abbreviation"
done
run_command "$ROOT_DIR/bin/platform-bastion-policy" --help --ver
assert_success_stdout 'platform-bastion-policy root abbreviation after --help'
run_command "$ROOT_DIR/bin/platform-bastion-policy" --version --hel
assert_success_stdout 'platform-bastion-policy root abbreviation after --version'

if find "$TMP_DIR/home" "$TMP_DIR/config" "$TMP_DIR/data" -mindepth 1 -print -quit | grep -q .; then
  fail 'help, version, or parser errors created state'
fi

printf '%s\n' 'test-command-contract.sh: ok'
