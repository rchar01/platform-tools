info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

validate_not_empty() {
  [[ -n $1 ]] || printf '%s\n' 'must not be empty'
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

expand_path() {
  case $1 in
    \~) printf '%s\n' "$HOME" ;;
    \~/*) printf '%s/%s\n' "$HOME" "${1:2}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

require_no_control() {
  local name=$1 value=$2
  [[ ! $value =~ [[:cntrl:]] ]] || die "${name} must not contain control characters"
}

validate_inputs() {
  require_no_control '--proxmox-user' "$PROXMOX_USER"
  require_no_control '--token-id' "$TOKEN_ID"
  require_no_control '--role' "$ROLE"
  require_no_control '--path' "$ACL_PATH"
  require_no_control '--comment' "$COMMENT"

  if [[ -n $SSH_TARGET ]]; then
    require_no_control '--ssh' "$SSH_TARGET"
    [[ $SSH_TARGET != -* ]] || die '--ssh must not start with -'
  fi

  if [[ -n $WRITE_TOKEN_FILE ]]; then
    require_no_control '--write-token-file' "$WRITE_TOKEN_FILE"
  fi
}

resolve_self_path() {
  case ${BASH_SOURCE[0]} in
    */*)
      [[ -r ${BASH_SOURCE[0]} ]] || return 1
      printf '%s\n' "${BASH_SOURCE[0]}"
      ;;
    *) command -v -- "${BASH_SOURCE[0]}" 2>/dev/null || return 1 ;;
  esac
}

quote_remote_command() {
  printf '%q ' "$@"
}

sanitize_remote_output() {
  local line
  while IFS= read -r line; do
    case $line in
      PLATFORM_PROXMOX_TOKEN_LINE=*) printf '%s\n' 'PLATFORM_PROXMOX_TOKEN_LINE=<redacted>' ;;
      *) printf '%s\n' "$line" ;;
    esac
  done
}

extract_token_line() {
  local line
  while IFS= read -r line; do
    case $line in
      PLATFORM_PROXMOX_TOKEN_LINE=*)
        printf '%s\n' "${line#PLATFORM_PROXMOX_TOKEN_LINE=}"
        return 0
        ;;
    esac
  done
  return 1
}

validate_token_target() {
  local path=$1
  if [[ -e $path || -L $path ]]; then
    [[ ! -L $path ]] || die "Token file must not be a symbolic link: $path"
    [[ -f $path ]] || die "Token file is not a regular file: $path"
  fi
}

token_parent_validation_error() {
  local dir=$1 owner mode
  [[ ! -L $dir ]] || { printf 'Token file directory must not be a symbolic link: %s\n' "$dir"; return; }
  [[ -d $dir ]] || { printf 'Token file directory is not a directory: %s\n' "$dir"; return; }
  owner=$(stat -c '%u' -- "$dir") || { printf 'Cannot inspect token file directory owner: %s\n' "$dir"; return; }
  mode=$(stat -c '%a' -- "$dir") || { printf 'Cannot inspect token file directory mode: %s\n' "$dir"; return; }
  [[ $owner == "$EUID" ]] || { printf 'Token file directory is not owned by the current user: %s\n' "$dir"; return; }
  [[ $mode =~ ^[0-7]+$ ]] || { printf 'Cannot parse token file directory mode: %s\n' "$dir"; return; }
  (( (8#$mode & 0700) == 0700 )) || { printf 'Token file directory must be readable, writable, and searchable by its owner: %s\n' "$dir"; return; }
  (( (8#$mode & 0022) == 0 )) || { printf 'Token file directory must not be writable by group or other users: %s\n' "$dir"; return; }
  [[ -w $dir && -x $dir ]] || { printf 'Token file directory is not writable and searchable: %s\n' "$dir"; return; }
}

prepare_token_parent() {
  local path=$1 dir validation_error mode
  dir=$(dirname -- "$path")
  if [[ ! -e $dir && ! -L $dir ]]; then
    mkdir -p -- "$dir"
  fi
  validation_error=$(token_parent_validation_error "$dir")
  [[ -z $validation_error ]] || die "$validation_error"
  if [[ $dir != '.' ]]; then
    chmod 700 -- "$dir"
    mode=$(stat -c '%a' -- "$dir") || die "Cannot verify token file directory mode: $dir"
    [[ $mode == 700 ]] || die "Token file directory mode is not 700 after preparation: $dir"
  fi
}

preflight_token_file() {
  local path identity
  path=$(expand_path "$1")
  validate_token_target "$path"
  if [[ -s $path && $FORCE != true ]]; then
    die "Refusing to overwrite non-empty token file before creating a new Proxmox token: $path. Use --force to replace it."
  fi
  prepare_token_parent "$path"
  validate_token_target "$path"
  TOKEN_FILE_PREFLIGHT_PATH=$path
  if [[ -e $path ]]; then
    identity=$(stat -c '%d:%i' -- "$path") || die "Cannot snapshot token file identity: $path"
    TOKEN_FILE_PREFLIGHT_STATE="present:${identity}"
  else
    TOKEN_FILE_PREFLIGHT_STATE=absent
  fi
}

recheck_token_target_identity() {
  local path=$1 expected_identity=$2 current_identity
  if [[ ! -f $path || -L $path ]]; then
    die "Token file changed after preflight; refusing to replace it: $path"
  fi
  current_identity=$(stat -c '%d:%i' -- "$path") ||
    die "Cannot recheck token file identity: $path"
  [[ $current_identity == "$expected_identity" ]] ||
    die "Token file changed after preflight; refusing to replace it: $path"
}

write_token_file() {
  local path token_line dir base staged_mode expected_identity
  path=$(expand_path "$1")
  token_line=$2
  dir=$(dirname -- "$path")
  base=$(basename -- "$path")

  [[ $TOKEN_FILE_PREFLIGHT_PATH == "$path" && -n $TOKEN_FILE_PREFLIGHT_STATE ]] ||
    die "Token file publication has no matching preflight state: $path"
  prepare_token_parent "$path"

  TOKEN_FILE_TEMP=$(umask 077; mktemp -- "$dir/.${base}.tmp.XXXXXX") ||
    die "Cannot create temporary token file beside $path"
  trap 'rm -f -- "${TOKEN_FILE_TEMP:-}"' EXIT
  trap 'exit 1' HUP INT TERM
  printf '%s\n' "$token_line" >"$TOKEN_FILE_TEMP"
  chmod 600 -- "$TOKEN_FILE_TEMP"
  staged_mode=$(stat -c '%a' -- "$TOKEN_FILE_TEMP") ||
    die "Cannot verify temporary token file mode beside $path"
  [[ $staged_mode == 600 ]] || die "Temporary token file mode is not 600 beside $path"

  if [[ $TOKEN_FILE_PREFLIGHT_STATE == absent ]]; then
    ln -- "$TOKEN_FILE_TEMP" "$path" ||
      die "Refusing to replace token file created concurrently: $path"
    rm -f -- "$TOKEN_FILE_TEMP"
  else
    if [[ $TOKEN_FILE_PREFLIGHT_STATE == present:* ]]; then
      if [[ $FORCE != true && -s $path ]]; then
        die "Refusing to overwrite non-empty token file: $path. Use --force to replace it."
      fi
      expected_identity=${TOKEN_FILE_PREFLIGHT_STATE#present:}
      recheck_token_target_identity "$path" "$expected_identity"
    fi
    mv -- "$TOKEN_FILE_TEMP" "$path" || die "Failed to publish token file: $path"
  fi

  TOKEN_FILE_TEMP=''
  trap - EXIT HUP INT TERM
  ok "Wrote token to $path"
}

validate_generated_token() {
  local full_token=$1 secret=$2 expected_token="${PROXMOX_USER}!${TOKEN_ID}"
  [[ $full_token == "$expected_token" ]] ||
    die "Generated Proxmox token ID mismatch; expected ${expected_token}, got ${full_token}"
  [[ $secret =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] ||
    die "Generated Proxmox token secret has unexpected shape; refusing to use it. Expected UUID-shaped secret with 36 characters; actual length: ${#secret} characters."
}

check_error() {
  printf '[ERROR] %s\n' "$*" >&2
  MISSING=1
}

check_local_command() {
  if command_exists "$1"; then
    ok "Local command available: $1"
  else
    check_error "Local command missing: $1"
  fi
}

check_local_token_file() {
  local path dir existing_dir validation_error
  path=$(expand_path "$1")
  dir=$(dirname -- "$path")

  if [[ -L $path || (-e $path && ! -f $path) ]]; then
    check_error "Local token file is not a regular file: $path"
    return
  fi
  if [[ -s $path && $FORCE != true ]]; then
    check_error "Local token file is non-empty and would not be overwritten without --force: $path"
    return
  fi
  if [[ -e $dir || -L $dir ]]; then
    validation_error=$(token_parent_validation_error "$dir")
    if [[ -n $validation_error ]]; then
      check_error "$validation_error"
      return
    fi
    ok "Local token file target is writable: $path"
    return
  fi

  existing_dir=$dir
  while [[ ! -d $existing_dir && ! -L $existing_dir && $existing_dir != / && $existing_dir != . ]]; do
    existing_dir=$(dirname -- "$existing_dir")
  done
  if [[ -L $existing_dir || ! -d $existing_dir ]]; then
    check_error "Local token file parent is not a directory: $path"
  elif [[ -w $existing_dir && -x $existing_dir ]]; then
    ok "Local token file target is writable: $path"
  else
    check_error "Local token file parent is not writable: $path"
  fi
}

check_local_proxmox_requirements() {
  if [[ -d /etc/pve ]]; then
    ok 'Local Proxmox marker found: /etc/pve'
  else
    check_error 'Local Proxmox marker missing: /etc/pve'
  fi
  check_local_command pveum
  [[ -z $WRITE_TOKEN_FILE ]] || check_local_command jq
}

check_remote_proxmox_requirements() {
  local require_jq=false remote_cmd
  command_exists ssh || die 'ssh is required for --ssh'
  [[ -z $WRITE_TOKEN_FILE ]] || require_jq=true
  info "Checking SSH access and Proxmox prerequisites on $SSH_TARGET"
  remote_cmd=$(quote_remote_command bash -s -- "$require_jq")

  # remote_cmd is assembled and shell-quoted on the client side.
  # shellcheck disable=SC2029
  if ssh "$SSH_TARGET" "$remote_cmd" <<'REMOTE_CHECK'
set -u
require_jq=${1:-false}
missing=0
ok() { printf '[OK] Remote %s\n' "$*"; }
error() { printf '[ERROR] Remote %s\n' "$*" >&2; missing=1; }
check_command() {
  if command -v "$1" >/dev/null 2>&1; then ok "command available: $1"; else error "command missing: $1"; fi
}
if test -d /etc/pve; then ok 'Proxmox marker found: /etc/pve'; else error 'Proxmox marker missing: /etc/pve'; fi
check_command bash
check_command pveum
if [ "$require_jq" = true ]; then check_command jq; fi
exit "$missing"
REMOTE_CHECK
  then
    ok "Remote prerequisite check passed on $SSH_TARGET"
  else
    check_error "Remote prerequisite check failed on $SSH_TARGET"
  fi
}

run_checks() {
  MISSING=0
  if [[ -n $WRITE_TOKEN_FILE ]]; then
    info 'Check mode: automatic token-file workflow'
    info 'Remote jq is required because --write-token-file needs parsed pveum JSON output'
    check_local_token_file "$WRITE_TOKEN_FILE"
  else
    info 'Check mode: manual token output workflow'
    info 'Remote jq is optional because the generated token can be copied from pveum output'
  fi

  if [[ -n $SSH_TARGET ]]; then
    check_local_command ssh
    check_remote_proxmox_requirements
  else
    check_local_proxmox_requirements
  fi
  [[ $MISSING -eq 0 ]] || die 'One or more Proxmox token prerequisites are missing'
  ok 'Proxmox token prerequisite check complete'
}

run_over_ssh() {
  local self_path remote_cmd remote_output status token_line
  local -a remote_args
  command_exists ssh || die 'ssh is required for --ssh'
  self_path=$(resolve_self_path) || die 'Could not locate this script to stream it over SSH'
  remote_args=(
    --proxmox-user "$PROXMOX_USER"
    --token-id "$TOKEN_ID"
    --role "$ROLE"
    --path "$ACL_PATH"
    --comment "$COMMENT"
  )
  if [[ -n $WRITE_TOKEN_FILE ]]; then
    preflight_token_file "$WRITE_TOKEN_FILE"
    remote_args+=(--emit-token-line)
  fi
  remote_cmd=$(quote_remote_command bash -s -- "${remote_args[@]}")
  info "Running Proxmox token bootstrap over SSH: $SSH_TARGET"

  if [[ -z $WRITE_TOKEN_FILE ]]; then
    # remote_cmd is assembled and shell-quoted on the client side.
    # shellcheck disable=SC2029
    ssh "$SSH_TARGET" "$remote_cmd" <"$self_path"
    return
  fi

  set +e
  # remote_cmd is assembled and shell-quoted on the client side.
  # shellcheck disable=SC2029
  remote_output=$(ssh "$SSH_TARGET" "$remote_cmd" <"$self_path" 2>&1)
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    printf '%s\n' "$remote_output" | sanitize_remote_output >&2
    die "Remote Proxmox token bootstrap failed on $SSH_TARGET"
  fi
  token_line=$(printf '%s\n' "$remote_output" | extract_token_line || true)
  if [[ -z $token_line ]]; then
    printf '%s\n' "$remote_output" | sanitize_remote_output
    warn "Nothing was written to $WRITE_TOKEN_FILE. The token may already exist, or the remote host could not emit the generated secret."
    return
  fi
  write_token_file "$WRITE_TOKEN_FILE" "$token_line"
}

user_exists() {
  local output
  if command_exists jq && output=$(pveum user list --output-format json 2>/dev/null); then
    if printf '%s\n' "$output" | jq -e --arg user "$PROXMOX_USER" '.[] | select(.userid == $user)' >/dev/null 2>&1; then
      return 0
    fi
  fi
  output=$(pveum user list 2>/dev/null || true)
  awk -v user="$PROXMOX_USER" 'index($0, user) { found = 1 } END { exit found ? 0 : 1 }' <<<"$output"
}

token_exists() {
  local output
  if command_exists jq && output=$(pveum user token list "$PROXMOX_USER" --output-format json 2>/dev/null); then
    if printf '%s\n' "$output" | jq -e --arg token "$TOKEN_ID" '.[] | select((.tokenid? == $token) or (.id? == $token) or (."token-id"? == $token))' >/dev/null 2>&1; then
      return 0
    fi
  fi
  output=$(pveum user token list "$PROXMOX_USER" 2>/dev/null || true)
  awk -v token="$TOKEN_ID" 'index($0, token) { found = 1 } END { exit found ? 0 : 1 }' <<<"$output"
}

ensure_user() {
  if user_exists; then
    ok "User already exists: $PROXMOX_USER"
  else
    info "Creating Proxmox user: $PROXMOX_USER"
    pveum user add "$PROXMOX_USER" --comment "$COMMENT"
    ok "Created user: $PROXMOX_USER"
  fi
}

create_token() {
  local output full_token value
  info "Creating Proxmox token: ${PROXMOX_USER}!${TOKEN_ID}"
  if ! command_exists jq; then
    if [[ $EMIT_TOKEN_LINE == true || -n $WRITE_TOKEN_FILE ]]; then
      die 'jq is required when capturing the generated token line automatically'
    fi
    pveum user token add "$PROXMOX_USER" "$TOKEN_ID" --privsep "$PRIVSEP"
    ok "Created token: ${PROXMOX_USER}!${TOKEN_ID}"
    warn 'Install jq before running this helper if you want it to write the token file automatically.'
    return
  fi

  if ! output=$(pveum user token add "$PROXMOX_USER" "$TOKEN_ID" --privsep "$PRIVSEP" --output-format json 2>&1); then
    warn 'Refusing to print failed pveum JSON output because it may contain the one-time token secret.'
    die "Failed to create token: ${PROXMOX_USER}!${TOKEN_ID}"
  fi
  full_token=$(printf '%s\n' "$output" | jq -r '."full-tokenid" // empty' 2>/dev/null || true)
  value=$(printf '%s\n' "$output" | jq -r '.value // empty' 2>/dev/null || true)
  if [[ -z $full_token || -z $value ]]; then
    warn 'Created the token, but could not parse the generated secret from pveum JSON output.'
    warn 'Refusing to print raw pveum output because it may contain the one-time token secret.'
    return
  fi
  validate_generated_token "$full_token" "$value"
  GENERATED_TOKEN_LINE="${full_token}=${value}"
  ok "Created token: $full_token"
  if [[ $EMIT_TOKEN_LINE == true ]]; then
    printf 'PLATFORM_PROXMOX_TOKEN_LINE=%s\n' "$GENERATED_TOKEN_LINE"
  elif [[ -z $WRITE_TOKEN_FILE ]]; then
    printf '\nGenerated token line:\n\n  %s\n' "$GENERATED_TOKEN_LINE"
  fi
}

ensure_acl() {
  info "Granting ${ROLE} on ${ACL_PATH} to ${PROXMOX_USER}"
  pveum aclmod "$ACL_PATH" -user "$PROXMOX_USER" -role "$ROLE"
  ok "Granted ${ROLE} on ${ACL_PATH} to ${PROXMOX_USER}"
}
