#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/test-installed-tools.XXXXXX")
STATE_PARENT=${XDG_CACHE_HOME:-$HOME/.cache}
mkdir -p "$STATE_PARENT"
STATE_DIR=$(mktemp -d "$STATE_PARENT/platform-tools-installed.XXXXXX")
trap 'rm -rf "$TMP_DIR" "$STATE_DIR"' EXIT HUP INT TERM

STAGED_INSTALL_DIR="$TMP_DIR/install/bin"
STAGED_SHARE_DIR="$TMP_DIR/install/share/platform-tools"
INSTALL_DIR="$STATE_DIR/install/bin"
SHARE_DIR="$STATE_DIR/xdg-data/platform-tools"
RUNTIME_DIR="$STATE_DIR/runtime-bin"
HOME_DIR="$STATE_DIR/home"
XDG_CONFIG_DIR="$STATE_DIR/xdg-config"
XDG_DATA_DIR="$STATE_DIR/xdg-data"
STDOUT="$STATE_DIR/stdout"
STDERR="$STATE_DIR/stderr"
VERSION=$(cat "$ROOT_DIR/VERSION")

fail() {
  printf 'test-installed-tools.sh: %s\n' "$*" >&2
  exit 1
}

run_clean() {
  set +e
  (
    cd "$STATE_DIR"
    /usr/bin/env -i \
      HOME="$HOME_DIR" \
      XDG_CONFIG_HOME="$XDG_CONFIG_DIR" \
      XDG_DATA_HOME="$XDG_DATA_DIR" \
      PATH="$RUNTIME_DIR" \
      "$@"
  ) >"$STDOUT" 2>"$STDERR"
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

/usr/bin/env -i HOME="$HOME" PATH="$PATH" "$(command -v make)" -C "$ROOT_DIR" install \
  INSTALL_DIR="$STAGED_INSTALL_DIR" SHARE_DIR="$STAGED_SHARE_DIR" >/dev/null
/usr/bin/env -i HOME="$HOME" PATH="$PATH" "$(command -v make)" -C "$ROOT_DIR" install \
  INSTALL_DIR="$INSTALL_DIR" SHARE_DIR="$SHARE_DIR" >/dev/null
mkdir -p "$RUNTIME_DIR" "$HOME_DIR" "$XDG_CONFIG_DIR"

for command in bash python3 dirname mkdir chmod id stat find mktemp cp mv rm pwd; do
  source_path=$(command -v "$command") || fail "required smoke dependency not found: $command"
  ln -s "$source_path" "$RUNTIME_DIR/$command"
done

for tool in $TOOLS; do
  [ -x "$STAGED_INSTALL_DIR/$tool" ] || fail "staged command is missing: $tool"
  [ -x "$INSTALL_DIR/$tool" ] || fail "installed command is missing: $tool"
  ln -s "$INSTALL_DIR/$tool" "$RUNTIME_DIR/$tool"

  for flag in --help -h; do
    run_clean "$RUNTIME_DIR/$tool" "$flag"
    assert_success_stdout "$tool $flag"
  done
  for flag in --version -v; do
    run_clean "$RUNTIME_DIR/$tool" "$flag"
    assert_success_stdout "$tool $flag"
    [ "$(cat "$STDOUT")" = "$tool $VERSION" ] || \
      fail "unexpected installed version for $tool $flag: $(cat "$STDOUT")"
  done

  run_clean "$RUNTIME_DIR/$tool" --contract-invalid-option
  assert_parser_error "$tool invalid option"
done

case $RUNTIME_DIR in
  "$ROOT_DIR"/*) fail 'runtime PATH is inside the checkout' ;;
esac
case "$INSTALL_DIR:$SHARE_DIR:$HOME_DIR:$XDG_CONFIG_DIR:$XDG_DATA_DIR" in
  *"$ROOT_DIR"*) fail 'runtime installation or state exposes a checkout path' ;;
esac
[ "$(pwd -P)" != "$STATE_DIR" ] || fail 'test driver unexpectedly changed its working directory'
[ ! -e "$RUNTIME_DIR/ruby" ] || fail 'runtime PATH unexpectedly contains Ruby'
[ ! -e "$RUNTIME_DIR/bashly" ] || fail 'runtime PATH unexpectedly contains Bashly'
[ ! -e "$INSTALL_DIR/../lib/platform-pki-common.sh" ] || \
  fail 'installed PKI command has an unintended adjacent library fallback'

NAMESPACE="$STATE_DIR/pki-namespace"
run_clean "$RUNTIME_DIR/platform-pki-init" --namespace "$NAMESPACE"
[ "$STATUS" -eq 0 ] || fail "installed PKI initialization failed: $(cat "$STDERR")"
[ ! -s "$STDERR" ] || fail "installed PKI initialization wrote stderr: $(cat "$STDERR")"
[ -f "$NAMESPACE/pki/inventory/services.yml.example" ] || fail 'installed PKI template lookup failed'
[ ! -e "$NAMESPACE/pki/inventory/services.yml" ] || fail 'initializer created active inventory'
cmp "$SHARE_DIR/templates/pki/services.yml.example" \
  "$NAMESPACE/pki/inventory/services.yml.example" || fail 'installed PKI template content differs from SHARE_DIR'

printf '%s\n' 'test-installed-tools.sh: ok'
