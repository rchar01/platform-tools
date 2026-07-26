#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$ROOT_DIR/.tmp"
TMP_DIR=$(mktemp -d "$ROOT_DIR/.tmp/platform-ssh-init.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-ssh-init"
VERSION=$(<"$ROOT_DIR/VERSION")
HOME_DIR="$TMP_DIR/home"
FAKE_BIN="$TMP_DIR/fake-bin"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
SSH_KEYGEN_LOG="$TMP_DIR/ssh-keygen.log"
SSH_LOG="$TMP_DIR/ssh.log"
SYSTEM_PATH=$PATH
RUN_PATH=$SYSTEM_PATH
RUN_CWD=$ROOT_DIR
STATUS=0
SSH_KEYGEN_DERIVE_FAIL=0
SSH_KEYGEN_DERIVE_RACE_PATH=''
SSH_FAIL_STATUS=0

mkdir -p "$HOME_DIR" "$FAKE_BIN"
chmod 700 "$HOME_DIR"

fail() {
  printf 'test-platform-ssh-init.sh: %s\n' "$*" >&2
  exit 1
}

run_tool() {
  : >"$STDOUT"
  : >"$STDERR"
  set +e
  (
    cd "$RUN_CWD"
    HOME=$HOME_DIR PATH=$RUN_PATH SSH_KEYGEN_LOG=$SSH_KEYGEN_LOG SSH_LOG=$SSH_LOG \
      SSH_KEYGEN_DERIVE_FAIL=$SSH_KEYGEN_DERIVE_FAIL \
      SSH_KEYGEN_DERIVE_RACE_PATH=$SSH_KEYGEN_DERIVE_RACE_PATH \
      SSH_FAIL_STATUS=$SSH_FAIL_STATUS \
      "$TOOL" "$@"
  ) >"$STDOUT" 2>"$STDERR"
  STATUS=$?
  set -e
}

assert_status() {
  [[ $STATUS -eq $1 ]] || fail "expected status $1, got $STATUS: $(<"$STDERR")"
}

assert_empty() {
  [[ ! -s $1 ]] || fail "expected empty output: $(<"$1")"
}

assert_contains() {
  local file=$1 expected=$2
  grep -Fq -- "$expected" "$file" || fail "expected '$expected' in $(<"$file")"
}

assert_not_contains() {
  local file=$1 unexpected=$2
  ! grep -Fq -- "$unexpected" "$file" || fail "did not expect '$unexpected' in $(<"$file")"
}

assert_mode() {
  local expected=$1 path=$2 actual
  actual=$(stat -c '%a' "$path")
  [[ $actual == "$expected" ]] || fail "expected mode $expected for $path, got $actual"
}

assert_not_exists() {
  [[ ! -e $1 && ! -L $1 ]] || fail "expected path not to exist: $1"
}

cat >"$FAKE_BIN/ssh-keygen" <<'FAKE_KEYGEN'
#!/usr/bin/env bash
set -euo pipefail

key_path=''
derive=false
while [[ $# -gt 0 ]]; do
  printf '<%s>\n' "$1" >>"$SSH_KEYGEN_LOG"
  case $1 in
    -f)
      key_path=$2
      printf '<%s>\n' "$2" >>"$SSH_KEYGEN_LOG"
      shift 2
      ;;
    -y)
      derive=true
      shift
      ;;
    *) shift ;;
  esac
done

if [[ $derive == true ]]; then
  if [[ $SSH_KEYGEN_DERIVE_FAIL == 1 ]]; then
    printf '%s\n' 'partial public key'
    exit 42
  fi
  if [[ -n $SSH_KEYGEN_DERIVE_RACE_PATH ]]; then
    printf '%s\n' 'race winner' >"$SSH_KEYGEN_DERIVE_RACE_PATH"
  fi
  printf '%s\n' 'ssh-ed25519 AAAAC3NzaFakeReconstructed'
else
  : >"$key_path"
  printf '%s\n' 'ssh-ed25519 AAAAC3NzaFakeGenerated fake-comment' >"${key_path}.pub"
fi
FAKE_KEYGEN

cat >"$FAKE_BIN/ssh" <<'FAKE_SSH'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  printf '<%s>\n' "$arg" >>"$SSH_LOG"
done
[[ $SSH_FAIL_STATUS == 0 ]] || exit "$SSH_FAIL_STATUS"
FAKE_SSH
chmod 755 "$FAKE_BIN/ssh-keygen" "$FAKE_BIN/ssh"

run_tool --help
assert_status 0
assert_contains "$STDOUT" 'Usage:'
assert_contains "$STDOUT" 'platform-ssh-init --version | -v'
assert_contains "$STDOUT" 'CONFIG_FILE'
assert_empty "$STDERR"

run_tool --version
assert_status 0
[[ $(<"$STDOUT") == "platform-ssh-init $VERSION" ]] || fail 'unexpected version output'
assert_empty "$STDERR"

run_tool --unknown
assert_status 1
assert_empty "$STDOUT"
assert_contains "$STDERR" 'invalid option: --unknown'

run_tool --key-path
assert_status 1
assert_contains "$STDERR" '--key-path requires an argument'

run_tool --key-path ''
assert_status 1
assert_contains "$STDERR" 'validation error in --key-path PATH:'
assert_contains "$STDERR" 'must not be empty'
[[ ! -e $HOME_DIR/.ssh ]] || fail 'parser error caused a filesystem side effect'

run_tool one.env two.env
assert_status 1
assert_contains "$STDERR" 'invalid argument: two.env'

# Exercise real OpenSSH key creation only under the disposable HOME.
real_key="$HOME_DIR/real/id_ed25519"
RUN_PATH=$SYSTEM_PATH
run_tool --key-path "$real_key" --empty-passphrase --print-public-key
assert_status 0
[[ -f $real_key && -f ${real_key}.pub ]] || fail 'real ssh-keygen did not create a keypair'
assert_mode 700 "$(dirname "$real_key")"
assert_mode 600 "$real_key"
assert_mode 644 "${real_key}.pub"
ssh-keygen -y -f "$real_key" >"$TMP_DIR/derived-real.pub"
assert_contains "$STDOUT" "$(<"$TMP_DIR/derived-real.pub")"

RUN_PATH="$FAKE_BIN:$SYSTEM_PATH"

# Key targets are validated before keygen, chmod, or public-key publication.
mkdir -p "$HOME_DIR/unsafe-targets"
printf '%s\n' 'target' >"$HOME_DIR/unsafe-targets/target"
chmod 644 "$HOME_DIR/unsafe-targets/target"
for private_link in private-link private-dangling; do
  private_path="$HOME_DIR/unsafe-targets/$private_link"
  if [[ $private_link == private-link ]]; then
    ln -s "$HOME_DIR/unsafe-targets/target" "$private_path"
  else
    ln -s "$HOME_DIR/unsafe-targets/missing" "$private_path"
  fi
  run_tool --key-path "$private_path"
  assert_status 1
  assert_contains "$STDERR" 'SSH private key path must not be a symbolic link'
  rm "$private_path"
done
assert_mode 644 "$HOME_DIR/unsafe-targets/target"

chmod 600 "$HOME_DIR/unsafe-targets/target"
for public_link in public-link public-dangling; do
  linked_key="$HOME_DIR/unsafe-targets/$public_link-key"
  if [[ $public_link == public-link ]]; then
    ln -s "$HOME_DIR/unsafe-targets/target" "${linked_key}.pub"
  else
    ln -s "$HOME_DIR/unsafe-targets/missing" "${linked_key}.pub"
  fi
  run_tool --key-path "$linked_key"
  assert_status 1
  assert_contains "$STDERR" 'SSH public key path must not be a symbolic link'
  assert_not_exists "$linked_key"
  rm "${linked_key}.pub"
done
assert_mode 600 "$HOME_DIR/unsafe-targets/target"

nonregular_private="$HOME_DIR/unsafe-targets/private-directory"
mkdir "$nonregular_private"
run_tool --key-path "$nonregular_private"
assert_status 1
assert_contains "$STDERR" 'SSH private key path is not a regular file'

nonregular_public_key="$HOME_DIR/unsafe-targets/public-fifo-key"
mkfifo "${nonregular_public_key}.pub"
run_tool --key-path "$nonregular_public_key"
assert_status 1
assert_contains "$STDERR" 'SSH public key path is not a regular file'
assert_not_exists "$nonregular_public_key"
rm "${nonregular_public_key}.pub"

# Key-directory ancestry is validated before mkdir or chmod.
mkdir "$HOME_DIR/key-dir-target"
chmod 700 "$HOME_DIR/key-dir-target"
ln -s "$HOME_DIR/key-dir-target" "$HOME_DIR/key-dir-link"
run_tool --key-path "$HOME_DIR/key-dir-link/id_ed25519"
assert_status 1
assert_contains "$STDERR" 'SSH key directory component must not be a symbolic link'
assert_not_exists "$HOME_DIR/key-dir-target/id_ed25519"
rm "$HOME_DIR/key-dir-link"

printf '%s\n' 'not a directory' >"$HOME_DIR/key-dir-file"
run_tool --key-path "$HOME_DIR/key-dir-file/nested/id_ed25519"
assert_status 1
assert_contains "$STDERR" 'SSH key directory component is not a directory'

mkdir "$HOME_DIR/group-writable-key-dir"
chmod 720 "$HOME_DIR/group-writable-key-dir"
run_tool --key-path "$HOME_DIR/group-writable-key-dir/id_ed25519"
assert_status 1
assert_contains "$STDERR" 'SSH key directory component must not be writable by group or other users'
assert_not_exists "$HOME_DIR/group-writable-key-dir/id_ed25519"

relative_cwd="$TMP_DIR/relative-cwd"
mkdir "$relative_cwd"
chmod 700 "$relative_cwd"
RUN_CWD=$relative_cwd
run_tool --key-path 'relative keys/id_ed25519'
assert_status 0
[[ -f "$relative_cwd/relative keys/id_ed25519" ]] || fail 'safe relative key path was not created'
assert_mode 700 "$relative_cwd/relative keys"

mkdir "$relative_cwd/relative-target"
chmod 700 "$relative_cwd/relative-target"
ln -s "$relative_cwd/relative-target" "$relative_cwd/relative-link"
run_tool --key-path 'relative-link/id_ed25519'
assert_status 1
assert_contains "$STDERR" 'SSH key directory component must not be a symbolic link'
assert_not_exists "$relative_cwd/relative-target/id_ed25519"
RUN_CWD=$ROOT_DIR

: >"$SSH_KEYGEN_LOG"
fake_key="$HOME_DIR/fake/key"
run_tool --key-path "$fake_key" --empty-passphrase
assert_status 0
assert_contains "$SSH_KEYGEN_LOG" '<-t>'
assert_contains "$SSH_KEYGEN_LOG" '<ed25519>'
assert_contains "$SSH_KEYGEN_LOG" '<-N>'
assert_contains "$SSH_KEYGEN_LOG" '<>'

: >"$SSH_KEYGEN_LOG"
run_tool --key-path "$HOME_DIR/fake/encrypted-default"
assert_status 0
assert_not_contains "$SSH_KEYGEN_LOG" '<-N>'

# Reuse an existing private key, correct modes, and reconstruct its public key.
reuse_key="$HOME_DIR/reuse/id_ed25519"
mkdir -p "$(dirname "$reuse_key")"
printf '%s\n' 'controlled private fixture' >"$reuse_key"
chmod 644 "$reuse_key"
: >"$SSH_KEYGEN_LOG"
run_tool --key-path "$reuse_key" --print-public-key
assert_status 0
assert_contains "$STDOUT" '[OK] SSH key already exists:'
assert_contains "$STDOUT" 'ssh-ed25519 AAAAC3NzaFakeReconstructed'
assert_contains "$SSH_KEYGEN_LOG" '<-y>'
assert_not_contains "$SSH_KEYGEN_LOG" '<-t>'
assert_mode 600 "$reuse_key"
assert_mode 644 "${reuse_key}.pub"

# Failed derivation leaves neither a partial destination nor temporary files.
derive_failure_key="$HOME_DIR/derive-failure/id_ed25519"
mkdir -p "$(dirname "$derive_failure_key")"
printf '%s\n' 'controlled private fixture' >"$derive_failure_key"
chmod 600 "$derive_failure_key"
SSH_KEYGEN_DERIVE_FAIL=1
run_tool --key-path "$derive_failure_key"
SSH_KEYGEN_DERIVE_FAIL=0
assert_status 1
assert_contains "$STDERR" 'Failed to derive public key'
assert_not_exists "${derive_failure_key}.pub"
! compgen -G "${derive_failure_key}.pub.tmp.*" >/dev/null || fail 'failed derivation left a temporary file'

# Atomic hard-link publication refuses a destination created during derivation.
derive_race_key="$HOME_DIR/derive-race/id_ed25519"
mkdir -p "$(dirname "$derive_race_key")"
printf '%s\n' 'controlled private fixture' >"$derive_race_key"
chmod 600 "$derive_race_key"
SSH_KEYGEN_DERIVE_RACE_PATH="${derive_race_key}.pub"
run_tool --key-path "$derive_race_key"
SSH_KEYGEN_DERIVE_RACE_PATH=''
assert_status 1
assert_contains "$STDERR" 'Refusing to replace public key path'
[[ $(<"${derive_race_key}.pub") == 'race winner' ]] || fail 'concurrent public key was overwritten'
! compgen -G "${derive_race_key}.pub.tmp.*" >/dev/null || fail 'publication race left a temporary file'

# Config is data, HOME forms expand, and interspersed CLI values win.
config_file="$TMP_DIR/ssh.env"
cat >"$config_file" <<'CONFIG'
export SSH_KEY_PATH="${HOME}/from-config/id_ed25519"
SSH_KEY_COMMENT="config comment"
SSH_HOST="config.example"
SSH_USER="config-user"
SSH_ALIAS="config-alias"
SSH_TEST_COMMAND="config command"
CONFIG
# shellcheck disable=SC2088 # Exercise literal-tilde expansion in the tool.
cli_key='~/from-cli/id_ed25519'
run_tool --host cli.example "$config_file" --key-path "$cli_key" --comment 'cli comment' --alias cli-alias
assert_status 0
[[ -f $HOME_DIR/from-cli/id_ed25519 ]] || fail 'CLI key path did not override config'
[[ ! -e $HOME_DIR/from-config ]] || fail 'overridden config key path was used'
assert_contains "$STDOUT" 'Host cli-alias'
assert_contains "$STDOUT" '  HostName cli.example'
assert_contains "$STDOUT" '  IdentityFile "~/from-cli/id_ed25519"'
assert_contains "$SSH_KEYGEN_LOG" '<cli comment>'

marker="$TMP_DIR/command-substitution-ran"
unsafe_config="$TMP_DIR/unsafe.env"
# shellcheck disable=SC2016 # Keep command substitution literal in the fixture.
printf 'SSH_KEY_PATH=%s\nSSH_KEY_COMMENT=$(touch %s)\n' "$HOME_DIR/unsafe/key" "$marker" >"$unsafe_config"
run_tool "$unsafe_config"
assert_status 1
assert_contains "$STDERR" 'Config values must not contain command substitution'
[[ ! -e $marker && ! -e $HOME_DIR/unsafe ]] || fail 'unsafe config was evaluated or caused key creation'

# Directive and destination values must remain one safe token.
injection_key="$HOME_DIR/injection/id_ed25519"
run_tool --key-path "$injection_key" --host $'safe.example\nProxyCommand bad'
assert_status 1
assert_contains "$STDERR" 'SSH_HOST must not contain control characters'
assert_not_exists "$injection_key"

run_tool --key-path "$injection_key" --host safe.example --alias $'safe\nMatch all'
assert_status 1
assert_contains "$STDERR" 'SSH_ALIAS must not contain control characters'
assert_not_exists "$injection_key"

run_tool --key-path "$injection_key" --user $'deploy\nProxyCommand bad'
assert_status 1
assert_contains "$STDERR" 'SSH_USER must not contain control characters'
assert_not_exists "$injection_key"

run_tool --key-path "$injection_key" --comment $'comment\nssh-rsa injected'
assert_status 1
assert_contains "$STDERR" 'SSH_KEY_COMMENT must not contain control characters'
assert_not_exists "$injection_key"

control_path=$'control-path\nIdentityFile injected'
run_tool --key-path "$HOME_DIR/$control_path"
assert_status 1
assert_contains "$STDERR" 'SSH_KEY_PATH must not contain control characters'
assert_not_exists "$HOME_DIR/$control_path"

run_tool --key-path "$injection_key" --host=-oProxyCommand=bad
assert_status 1
assert_contains "$STDERR" 'SSH_HOST must not start with -'
assert_not_exists "$injection_key"

run_tool --key-path "$injection_key" --user=-oProxyCommand=bad
assert_status 1
assert_contains "$STDERR" 'SSH_USER must not start with -'
assert_not_exists "$injection_key"

alias_only_key="$HOME_DIR/alias-only/id_ed25519"
run_tool --key-path "$alias_only_key" --alias alias-only
assert_status 1
assert_contains "$STDERR" 'SSH_ALIAS requires SSH_HOST'
assert_not_exists "$alias_only_key"
assert_not_exists "$(dirname "$alias_only_key")"

# --write-config preflights predictable path and mode failures before keygen.
preflight_key="$HOME_DIR/preflight/id_ed25519"
ln -s "$HOME_DIR/missing-ssh-dir" "$HOME_DIR/.ssh"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH directory must not be a symbolic link'
assert_not_exists "$preflight_key"
rm "$HOME_DIR/.ssh"

mkdir "$HOME_DIR/linked-ssh-dir"
chmod 700 "$HOME_DIR/linked-ssh-dir"
ln -s "$HOME_DIR/linked-ssh-dir" "$HOME_DIR/.ssh"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH directory must not be a symbolic link'
assert_not_exists "$preflight_key"
assert_not_exists "$HOME_DIR/linked-ssh-dir/config"
rm "$HOME_DIR/.ssh"

printf '%s\n' 'not a directory' >"$HOME_DIR/.ssh"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH directory is not a directory'
assert_not_exists "$preflight_key"
rm "$HOME_DIR/.ssh"

mkdir "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"
ln -s "$HOME_DIR/missing-config" "$HOME_DIR/.ssh/config"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH config must not be a symbolic link'
assert_not_exists "$preflight_key"
rm "$HOME_DIR/.ssh/config"

printf '%s\n' 'target config' >"$HOME_DIR/config-target"
chmod 644 "$HOME_DIR/config-target"
ln -s "$HOME_DIR/config-target" "$HOME_DIR/.ssh/config"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH config must not be a symbolic link'
assert_not_exists "$preflight_key"
[[ $(<"$HOME_DIR/config-target") == 'target config' ]] || fail 'SSH config symlink target was changed'
assert_mode 644 "$HOME_DIR/config-target"
rm "$HOME_DIR/.ssh/config"

mkdir "$HOME_DIR/.ssh/config"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH config is not a regular file'
assert_not_exists "$preflight_key"
rmdir "$HOME_DIR/.ssh/config"

chmod 720 "$HOME_DIR/.ssh"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH directory must not be writable by group or other users'
assert_not_exists "$preflight_key"
chmod 700 "$HOME_DIR/.ssh"

printf '%s\n' 'Host existing' >"$HOME_DIR/.ssh/config"
chmod 400 "$HOME_DIR/.ssh/config"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH config must be readable and writable by its owner'
assert_not_exists "$preflight_key"
chmod 600 "$HOME_DIR/.ssh/config"

chmod 620 "$HOME_DIR/.ssh/config"
run_tool --key-path "$preflight_key" --host safe.example --alias safe --write-config
assert_status 1
assert_contains "$STDERR" 'SSH config must not be writable by group or other users'
assert_not_exists "$preflight_key"
chmod 600 "$HOME_DIR/.ssh/config"

# Reject duplicate aliases for any Host directive keyword case before key creation.
for host_keyword in Host host hOsT; do
  printf '%s\n' "$host_keyword duplicate" '  HostName existing.example' >"$HOME_DIR/.ssh/config"
  before_config=$(<"$HOME_DIR/.ssh/config")
  duplicate_key="$HOME_DIR/duplicate-${host_keyword}/id_ed25519"
  run_tool --key-path "$duplicate_key" --host new.example --alias duplicate --write-config
  assert_status 1
  assert_contains "$STDERR" 'SSH config already contains Host duplicate'
  assert_not_exists "$duplicate_key"
  assert_not_exists "$(dirname "$duplicate_key")"
  [[ $(<"$HOME_DIR/.ssh/config") == "$before_config" ]] || fail 'duplicate alias changed SSH config'
done

write_key="$HOME_DIR/write path/id_ed25519"
run_tool --key-path "$write_key" --host write.example --user deploy --alias write-alias --write-config
assert_status 0
assert_contains "$HOME_DIR/.ssh/config" 'Host write-alias'
assert_contains "$HOME_DIR/.ssh/config" "  IdentityFile \"$write_key\""
assert_mode 700 "$HOME_DIR/.ssh"
assert_mode 600 "$HOME_DIR/.ssh/config"

# A controlled fake proves each SSH operand, including the command, stays separate.
: >"$SSH_LOG"
test_command="printf \"%s %s\" one two; touch $TMP_DIR/should-not-run-locally"
run_tool --key-path "$write_key" --host test.example --user tester --test-command "$test_command" --test
assert_status 0
mapfile -t ssh_args <"$SSH_LOG"
[[ ${#ssh_args[@]} -eq 6 ]] || fail "expected 6 SSH arguments, got ${#ssh_args[@]}"
[[ ${ssh_args[0]} == '<-i>' ]] || fail 'unexpected SSH identity flag boundary'
[[ ${ssh_args[1]} == "<$write_key>" ]] || fail 'unexpected SSH key boundary'
[[ ${ssh_args[2]} == '<-o>' && ${ssh_args[3]} == '<IdentitiesOnly=yes>' ]] || fail 'unexpected SSH option boundaries'
[[ ${ssh_args[4]} == '<tester@test.example>' ]] || fail 'unexpected SSH destination boundary'
[[ ${ssh_args[5]} == "<$test_command>" ]] || fail 'test command was split or evaluated locally'
[[ ! -e $TMP_DIR/should-not-run-locally ]] || fail 'test command executed locally'

SSH_FAIL_STATUS=23
run_tool --key-path "$write_key" --host test.example --user tester --test
SSH_FAIL_STATUS=0
assert_status 23
assert_not_contains "$STDOUT" '[OK] SSH access test succeeded'

missing_host_key="$HOME_DIR/missing-host/id_ed25519"
run_tool --key-path "$missing_host_key" --test
assert_status 1
assert_contains "$STDERR" 'Required config variable SSH_HOST is missing or empty'
[[ ! -e $missing_host_key ]] || fail 'invalid --test invocation created a key'

printf '%s\n' 'test-platform-ssh-init.sh: ok'
