die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

validate_evidence_scalar() {
  [[ -n $1 ]] || {
    printf '%s\n' 'must not be empty'
    return
  }
  [[ $1 != *$'\n'* && $1 != *$'\r'* && $1 != *$'\t'* ]] ||
    printf '%s\n' 'must not contain tabs or line breaks'
}

validate_evidence_path() {
  validate_evidence_scalar "$1"
}

encode_value() {
  local value=$1
  local byte code index
  local LC_ALL=C
  for ((index = 0; index < ${#value}; index++)); do
    byte=${value:index:1}
    printf -v code '%d' "'$byte"
    if [[ $byte == '%' || $code -lt 32 || $code -eq 127 ]]; then
      printf '%%%02X' "$code"
    else
      printf '%s' "$byte"
    fi
  done
}

emit() {
  printf '%s=' "$1"
  encode_value "$2"
  printf '\n'
}

emit_encoded() {
  printf '%s=%s\n' "$1" "$2"
}

first_line() {
  local value=$1
  value=${value%%$'\n'*}
  printf '%s' "$value"
}

command_path() {
  type -P -- "$1" 2>/dev/null || true
}

resolved_command_path() {
  local path
  path=$(command_path "$1")
  [[ -n $path ]] || {
    printf 'absent'
    return
  }
  if type -P readlink >/dev/null 2>&1; then
    command readlink -f -- "$path" 2>/dev/null || printf '%s' "$path"
  else
    printf '%s' "$path"
  fi
}

path_state() {
  local path=$1
  if [[ -L $path ]]; then
    if [[ -e $path ]]; then printf 'symlink'; else printf 'dangling-symlink'; fi
  elif [[ -f $path ]]; then
    printf 'regular-file'
  elif [[ -d $path ]]; then
    printf 'directory'
  elif [[ -e $path ]]; then
    printf 'other'
  else
    printf 'absent'
  fi
}

read_os_release_value() {
  local wanted=$1
  local name value
  local source=''
  if [[ -f /etc/os-release && ! -L /etc/os-release ]]; then
    source=/etc/os-release
  elif [[ -f /usr/lib/os-release && ! -L /usr/lib/os-release ]]; then
    source=/usr/lib/os-release
  fi
  [[ -n $source ]] || {
    printf 'unknown'
    return
  }
  while IFS='=' read -r name value; do
    [[ $name == "$wanted" ]] || continue
    if [[ $value == \"*\" && $value == *\" ]]; then
      value=${value:1:${#value}-2}
    fi
    printf '%s' "$value"
    return
  done < "$source"
  printf 'unknown'
}

tool_version() {
  local name=$1
  local path=$2
  local output=''
  case $name in
    openssl) output=$("$path" version 2>/dev/null || true) ;;
    ssh-keygen)
      local ssh_path
      ssh_path=$(command_path ssh)
      [[ -z $ssh_path ]] || {
        output=$("$ssh_path" -V 2>&1 || true)
        [[ -z $output ]] || output="suite-via-${ssh_path}: ${output}"
      }
      ;;
    age) output=$("$path" --version 2>/dev/null || true) ;;
    *) output=$("$path" --version 2>/dev/null || true) ;;
  esac
  [[ -n $output ]] || output=unavailable
  first_line "$output"
}

emit_tool() {
  local name=$1
  local key=${name//-/_}
  local path
  path=$(resolved_command_path "$name")
  emit "tool.${key}.path" "$path"
  if [[ $path == absent ]]; then
    emit "tool.${key}.version" unavailable
  else
    emit "tool.${key}.version" "$(tool_version "$name" "$path")"
  fi
}

cleanup_probe_workspace() {
  if [[ -z ${PROBE_WORKSPACE:-} ]]; then
    exec 8<&- 7<&-
    return 0
  fi
  local current_id directory_id entry
  if [[ -z ${PROBE_WORKSPACE_ID:-} ]]; then
    if [[ -n ${PROBE_WORKSPACE_NAME:-} && -d /proc/self/fd/8 ]]; then
      current_id=$(command stat -Lc '%d:%i' -- "/proc/self/fd/7/$PROBE_WORKSPACE_NAME" 2>/dev/null) || true
      directory_id=$(command stat -Lc '%d:%i' -- /proc/self/fd/8 2>/dev/null) || true
      if [[ -n $current_id && $current_id == "$directory_id" ]]; then
        PROBE_WORKSPACE_ID=$current_id
      fi
    fi
  fi
  if [[ -z ${PROBE_WORKSPACE_ID:-} ]]; then
    printf '[ERROR] Capability-probe directory retained after uncertain setup: %s\n' \
      "$PROBE_WORKSPACE" >&2
    exec 8<&- 7<&-
    return 1
  fi
  for entry in linked lock; do
    probe_workspace_owned || {
      printf '[ERROR] Capability-probe directory retained after identity change: %s\n' \
        "$PROBE_WORKSPACE" >&2
      exec 8<&- 7<&-
      return 1
    }
    command rm -f -- "/proc/self/fd/8/$entry" || return 1
  done
  probe_workspace_owned || {
    printf '[ERROR] Capability-probe directory retained after identity change: %s\n' \
      "$PROBE_WORKSPACE" >&2
    exec 8<&- 7<&-
    return 1
  }
  # The validated parent prevents untrusted replacement between this identity
  # check and descriptor-relative removal (sticky directories protect our name).
  command rmdir -- "/proc/self/fd/7/$PROBE_WORKSPACE_NAME" || {
    printf '[ERROR] Capability-probe directory retained after uncertain cleanup: %s\n' \
      "$PROBE_WORKSPACE" >&2
    exec 8<&- 7<&-
    return 1
  }
  exec 8<&- 7<&-
  PROBE_WORKSPACE=''
  PROBE_WORKSPACE_NAME=''
  PROBE_WORKSPACE_ID=''
}

probe_workspace_owned() {
  local current_id directory_id
  [[ -n ${PROBE_WORKSPACE_ID:-} && -n ${PROBE_WORKSPACE_NAME:-} ]] || return 1
  [[ -d /proc/self/fd/8 && ! -L /proc/self/fd/7/$PROBE_WORKSPACE_NAME ]] || return 1
  current_id=$(command stat -Lc '%d:%i' -- "/proc/self/fd/7/$PROBE_WORKSPACE_NAME" 2>/dev/null) || return 1
  directory_id=$(command stat -Lc '%d:%i' -- /proc/self/fd/8 2>/dev/null) || return 1
  [[ $current_id == "$PROBE_WORKSPACE_ID" && $directory_id == "$PROBE_WORKSPACE_ID" ]]
}

probe_parent_protects_owned_names() {
  local mode owner path_id
  [[ -d $PROBE_WORKSPACE_PARENT && ! -L $PROBE_WORKSPACE_PARENT ]] || return 1
  PROBE_PARENT_ID=$(command stat -Lc '%d:%i' -- /proc/self/fd/7 2>/dev/null) || return 1
  path_id=$(command stat -c '%d:%i' -- "$PROBE_WORKSPACE_PARENT" 2>/dev/null) || return 1
  [[ $path_id == "$PROBE_PARENT_ID" ]] || return 1
  mode=$(command stat -Lc '%a' -- /proc/self/fd/7 2>/dev/null) || return 1
  owner=$(command stat -Lc '%u' -- /proc/self/fd/7 2>/dev/null) || return 1
  [[ $mode =~ ^[0-7]+$ ]] || return 1
  [[ $owner =~ ^[0-9]+$ ]] || return 1
  mode=$((8#$mode))
  (( (owner == EUID || owner == 0) && ((mode & 0022) == 0 || (mode & 01000) != 0) ))
}

probe_filesystem_features() {
  local probe_base=$1
  local python_path=$2
  local python_result='otmpfile=unknown proc_fd_link=unknown'
  local lock_result=unknown
  local value

  PROBE_WORKSPACE_PARENT=$probe_base
  exec 7< "$probe_base" || die 'Could not open the capability-probe parent directory'
  trap cleanup_probe_workspace EXIT
  probe_parent_protects_owned_names ||
    die 'Capability-probe parent must be an identity-stable protected directory'
  PROBE_WORKSPACE=$(command mktemp -d "/proc/self/fd/7/.platform-runtime-evidence.XXXXXX") ||
    die 'Could not create the owned capability-probe directory'
  PROBE_WORKSPACE_NAME=${PROBE_WORKSPACE##*/}
  PROBE_WORKSPACE="$probe_base/$PROBE_WORKSPACE_NAME"
  exec 8< "/proc/self/fd/7/$PROBE_WORKSPACE_NAME" ||
    die 'Could not open the capability-probe directory'
  PROBE_WORKSPACE_ID=$(command stat -Lc '%d:%i' -- /proc/self/fd/8) ||
    die 'Could not identify the capability-probe directory'
  probe_workspace_owned || die 'Capability-probe directory identity changed during setup'
  command chmod 700 "/proc/self/fd/8" ||
    die 'Could not protect the capability-probe directory'

  if [[ $python_path != absent ]]; then
    python_result=$("$python_path" -c '
import os
import sys

directory = sys.argv[1]
descriptor = None
linked = os.path.join(directory, "linked")
otmpfile = "no"
proc_fd_link = "no"
try:
    flag = getattr(os, "O_TMPFILE", None)
    if flag is not None:
        descriptor = os.open(directory, os.O_RDWR | flag, 0o600)
        otmpfile = "yes"
        try:
            os.link(f"/proc/self/fd/{descriptor}", linked)
            proc_fd_link = "yes"
        except OSError:
            pass
finally:
    if descriptor is not None:
        os.close(descriptor)
    try:
        os.unlink(linked)
    except FileNotFoundError:
        pass
print(f"otmpfile={otmpfile} proc_fd_link={proc_fd_link}")
' /proc/self/fd/8 2>/dev/null || printf 'otmpfile=no proc_fd_link=no')
  fi

  local flock_path
  flock_path=$(command_path flock)
  if [[ -n $flock_path ]]; then
    : > /proc/self/fd/8/lock
    exec 9>/proc/self/fd/8/lock
    if "$flock_path" -n 9; then
      lock_result=yes
      "$flock_path" -u 9 || lock_result=no
    else
      lock_result=no
    fi
    exec 9>&-
  fi

  value=${python_result#*otmpfile=}
  emit feature.o_tmpfile "${value%% *}"
  value=${python_result#*proc_fd_link=}
  emit feature.proc_self_fd_link "${value%% *}"
  emit feature.advisory_lock "$lock_result"

  cleanup_probe_workspace
  trap - EXIT
}

LEGACY_PKI_ALIASES=(
  platform-pki-init
  platform-pki-inventory-install
  platform-pki-print-cert
  platform-pki-list-expiry
  platform-pki-service-verify
  platform-pki-export-ansible
  platform-pki-backup
  platform-pki-custody-report
  platform-pki-ca-passphrase-verify
  platform-pki-root-create
  platform-pki-intermediate-create
  platform-pki-csr-recover
  platform-pki-service-issue
  platform-pki-service-renew
  platform-pki-csr-trust-install
  platform-pki-certificate-export
  platform-pki-csr-candidate
  platform-pki-ca-rollover
)
