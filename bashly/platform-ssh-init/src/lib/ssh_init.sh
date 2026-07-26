info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
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

trim_space() {
  local value=$1

  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  printf '%s\n' "$value"
}

expand_config_value() {
  local value=$1

  value=${value//\$\{HOME\}/$HOME}
  value=${value//\$HOME/$HOME}
  case $value in
    \~) value=$HOME ;;
    \~/*) value=${HOME}/${value:2} ;;
  esac
  printf '%s\n' "$value"
}

parse_config_value() {
  local value=$1
  local first last
  local dollar_substitution=$'\x24\x28'
  local backtick_substitution=$'\x60'

  value=$(trim_space "$value")
  [[ $value != *"$dollar_substitution"* && $value != *"$backtick_substitution"* ]] || die 'Config values must not contain command substitution'

  first=${value:0:1}
  last=${value: -1}
  if [[ $first == '"' || $first == "'" ]]; then
    [[ $last == "$first" ]] || die 'Config value has an unmatched quote'
    value=${value:1:${#value}-2}
  elif [[ $last == '"' || $last == "'" ]]; then
    die 'Config value has an unmatched quote'
  fi

  expand_config_value "$value"
}

set_config_var() {
  local name=$1
  local value=$2

  case $name in
    SSH_KEY_PATH | SSH_KEY_COMMENT | SSH_HOST | SSH_USER | SSH_ALIAS | SSH_TEST_COMMAND)
      printf -v "$name" '%s' "$value"
      ;;
    *)
      die "Unsupported config variable in ${CONFIG_FILE}: ${name}"
      ;;
  esac
}

load_config_file() {
  local line_number=0
  local line name value

  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1))
    line=${line%$'\r'}
    line=$(trim_space "$line")

    [[ -z $line ]] && continue
    [[ ${line:0:1} == '#' ]] && continue

    case $line in
      export[[:space:]]*) line=$(trim_space "${line#export}") ;;
    esac

    [[ $line == *=* ]] || die "Invalid config line ${line_number} in ${CONFIG_FILE}: expected NAME=value"
    name=$(trim_space "${line%%=*}")
    value=${line#*=}
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "Invalid config variable name on line ${line_number} in ${CONFIG_FILE}: ${name}"
    value=$(parse_config_value "$value") || exit 1
    set_config_var "$name" "$value"
  done <"$CONFIG_FILE"
}

require_var() {
  local name=$1
  [[ -n ${!name:-} ]] || die "Required config variable ${name} is missing or empty"
}

require_no_control() {
  local name=$1
  local value=$2

  [[ ! $value =~ [[:cntrl:]] ]] || die "${name} must not contain control characters"
}

validate_connection_values() {
  require_no_control SSH_KEY_PATH "$SSH_KEY_PATH"
  require_no_control SSH_KEY_COMMENT "$SSH_KEY_COMMENT"
  require_no_control SSH_USER "$SSH_USER"

  [[ $SSH_USER != -* ]] || die 'SSH_USER must not start with -'
  [[ $SSH_USER =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || die 'SSH_USER contains unsupported characters'

  if [[ -n ${SSH_HOST:-} ]]; then
    require_no_control SSH_HOST "$SSH_HOST"
    [[ $SSH_HOST != -* ]] || die 'SSH_HOST must not start with -'
    [[ $SSH_HOST =~ ^[A-Za-z0-9_.:%-]+$ || $SSH_HOST =~ ^\[[A-Fa-f0-9:.%]+\]$ ]] || die 'SSH_HOST contains unsupported characters'
  fi

  if [[ -n ${SSH_ALIAS:-} ]]; then
    require_no_control SSH_ALIAS "$SSH_ALIAS"
    [[ $SSH_ALIAS != -* ]] || die 'SSH_ALIAS must not start with -'
    [[ $SSH_ALIAS =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || die 'SSH_ALIAS contains unsupported characters'
  fi
}

validate_owned_regular_file() {
  local path=$1
  local description=$2
  local owner

  [[ ! -L $path ]] || die "${description} must not be a symbolic link: ${path}"
  [[ -f $path ]] || die "${description} is not a regular file: ${path}"
  owner=$(stat -c '%u' -- "$path") || die "Cannot inspect ${description}: ${path}"
  [[ $owner == "$EUID" ]] || die "${description} is not owned by the current user: ${path}"
}

validate_key_targets() {
  if [[ -e $KEY_PATH || -L $KEY_PATH ]]; then
    validate_owned_regular_file "$KEY_PATH" 'SSH private key path'
  fi

  if [[ -e ${KEY_PATH}.pub || -L ${KEY_PATH}.pub ]]; then
    validate_owned_regular_file "${KEY_PATH}.pub" 'SSH public key path'
  fi
}

normalize_absolute_path() {
  local path=$1
  local component normalized=''
  local -a input_parts=() output_parts=()

  IFS='/' read -r -a input_parts <<<"$path"
  for component in "${input_parts[@]}"; do
    case $component in
      '' | .) ;;
      ..)
        if ((${#output_parts[@]} > 1)); then
          output_parts=("${output_parts[@]:0:${#output_parts[@]}-1}")
        else
          output_parts=()
        fi
        ;;
      *) output_parts+=("$component") ;;
    esac
  done

  for component in "${output_parts[@]}"; do
    normalized=${normalized}/${component}
  done
  printf '%s\n' "${normalized:-/}"
}

validate_key_directory_component() {
  local path=$1
  local require_writable=$2
  local owner mode

  [[ ! -L $path ]] || die "SSH key directory component must not be a symbolic link: ${path}"
  [[ -d $path ]] || die "SSH key directory component is not a directory: ${path}"
  owner=$(stat -c '%u' -- "$path") || die "Cannot inspect SSH key directory component: ${path}"
  mode=$(stat -c '%a' -- "$path") || die "Cannot inspect SSH key directory component: ${path}"
  [[ $owner == "$EUID" || $owner == 0 ]] || die "SSH key directory component has untrusted ownership: ${path}"
  (( (8#$mode & 0002) == 0 )) || die "SSH key directory component must not be writable by other users: ${path}"
  if [[ $owner != "$EUID" ]]; then
    (( (8#$mode & 0020) == 0 )) || die "Trusted SSH key directory component must not be group-writable: ${path}"
  fi
  [[ -x $path ]] || die "SSH key directory component is not searchable: ${path}"

  if [[ $require_writable == true ]]; then
    [[ $owner == "$EUID" ]] || die "Writable SSH key directory component is not owned by the current user: ${path}"
    (( (8#$mode & 0700) == 0700 )) || die "SSH key directory component must be readable, writable, and searchable by its owner: ${path}"
    (( (8#$mode & 0020) == 0 )) || die "SSH key directory component must not be writable by group or other users: ${path}"
    [[ -w $path ]] || die "SSH key directory component is not writable: ${path}"
  fi
}

preflight_key_directory() {
  local absolute_dir current=/ candidate component
  local -a components=() key_dir_parts=()
  local i

  IFS='/' read -r -a key_dir_parts <<<"$KEY_DIR"
  for component in "${key_dir_parts[@]}"; do
    [[ $component != .. ]] || die "SSH key directory must not contain parent traversal: ${KEY_DIR}"
  done

  if [[ $KEY_DIR == /* ]]; then
    absolute_dir=$(normalize_absolute_path "$KEY_DIR")
  else
    absolute_dir=$(normalize_absolute_path "$(pwd -P)/${KEY_DIR}")
  fi

  IFS='/' read -r -a components <<<"${absolute_dir#/}"
  if [[ $absolute_dir == / ]]; then
    validate_key_directory_component / true
    return
  fi

  validate_key_directory_component / false
  for ((i = 0; i < ${#components[@]}; i++)); do
    component=${components[i]}
    candidate=${current%/}/${component}
    if [[ -e $candidate || -L $candidate ]]; then
      if ((i == ${#components[@]} - 1)); then
        validate_key_directory_component "$candidate" true
      else
        validate_key_directory_component "$candidate" false
      fi
    else
      validate_key_directory_component "$current" true
      return
    fi
    current=$candidate
  done
}

validate_owned_safe_directory() {
  local path=$1
  local description=$2
  local owner mode

  [[ ! -L $path ]] || die "${description} must not be a symbolic link: ${path}"
  [[ -d $path ]] || die "${description} is not a directory: ${path}"
  owner=$(stat -c '%u' -- "$path") || die "Cannot inspect ${description}: ${path}"
  mode=$(stat -c '%a' -- "$path") || die "Cannot inspect ${description}: ${path}"
  [[ $owner == "$EUID" ]] || die "${description} is not owned by the current user: ${path}"
  (( (8#$mode & 0700) == 0700 )) || die "${description} must be readable, writable, and searchable by its owner: ${path}"
  (( (8#$mode & 0022) == 0 )) || die "${description} must not be writable by group or other users: ${path}"
  [[ -w $path && -x $path ]] || die "${description} is not writable and searchable: ${path}"
}

validate_owned_safe_config() {
  local path=$1
  local owner mode

  validate_owned_regular_file "$path" 'SSH config'
  owner=$(stat -c '%u' -- "$path") || die "Cannot inspect SSH config: ${path}"
  mode=$(stat -c '%a' -- "$path") || die "Cannot inspect SSH config: ${path}"
  [[ $owner == "$EUID" ]] || die "SSH config is not owned by the current user: ${path}"
  (( (8#$mode & 0600) == 0600 )) || die "SSH config must be readable and writable by its owner: ${path}"
  (( (8#$mode & 0022) == 0 )) || die "SSH config must not be writable by group or other users: ${path}"
  [[ -r $path && -w $path ]] || die "SSH config is not readable and writable: ${path}"
}

has_host_config() {
  [[ -n ${SSH_HOST:-} && -n ${SSH_ALIAS:-} ]]
}

print_ssh_config() {
  local identity_file

  require_var SSH_HOST
  require_var SSH_ALIAS

  identity_file=${SSH_KEY_PATH//\/\\}
  identity_file=${identity_file//\"/\\\"}

  printf 'Host %s\n' "$SSH_ALIAS"
  printf '  HostName %s\n' "$SSH_HOST"
  printf '  User %s\n' "$SSH_USER"
  printf '  IdentityFile "%s"\n' "$identity_file"
  printf '  IdentitiesOnly yes\n'
}

host_alias_exists() {
  local config_file=$1
  local alias=$2

  [[ -f $config_file ]] || return 1
  awk -v alias="$alias" '
    tolower($1) == "host" {
      for (i = 2; i <= NF; i++) {
        if ($i == alias) found = 1
      }
    }
    END { exit found ? 0 : 1 }
  ' "$config_file"
}

preflight_ssh_config_write() {
  local ssh_dir=$1
  local config_file=$2

  if [[ -e $ssh_dir || -L $ssh_dir ]]; then
    validate_owned_safe_directory "$ssh_dir" 'SSH directory'
  else
    validate_owned_safe_directory "$HOME" 'HOME directory'
    return
  fi

  if [[ -e $config_file || -L $config_file ]]; then
    validate_owned_safe_config "$config_file"
    if host_alias_exists "$config_file" "$SSH_ALIAS"; then
      die "SSH config already contains Host ${SSH_ALIAS}; edit ${config_file} manually or choose another SSH_ALIAS"
    fi
  fi
}

validate_actions() {
  if [[ -n ${SSH_ALIAS:-} && -z ${SSH_HOST:-} ]]; then
    die 'SSH_ALIAS requires SSH_HOST from the config file or CLI flags'
  fi

  if [[ $WRITE_CONFIG == true ]]; then
    has_host_config || die '--write-config requires SSH_HOST and SSH_ALIAS from the config file or CLI flags'
    preflight_ssh_config_write "$SSH_DIR" "$SSH_CONFIG_FILE"
  fi

  if [[ $RUN_TEST == true ]]; then
    require_var SSH_HOST
    command_exists ssh || die 'ssh is required for --test'
  fi
}

write_ssh_config() {
  local ssh_dir=$1
  local config_file=$2

  preflight_ssh_config_write "$ssh_dir" "$config_file"
  mkdir -p -- "$ssh_dir"
  preflight_ssh_config_write "$ssh_dir" "$config_file"
  chmod 700 -- "$ssh_dir"

  if [[ ! -e $config_file && ! -L $config_file ]]; then
    (umask 077; set -o noclobber; : >"$config_file") || die "Refusing to replace SSH config path: ${config_file}"
  fi
  preflight_ssh_config_write "$ssh_dir" "$config_file"
  chmod 600 -- "$config_file"

  {
    printf '\n'
    print_ssh_config
  } >>"$config_file"
  ok "Wrote SSH config alias ${SSH_ALIAS} to ${config_file}"
}

derive_public_key() {
  local public_key=${KEY_PATH}.pub

  PUBLIC_KEY_TEMP=$(umask 077; mktemp -- "${public_key}.tmp.XXXXXX") || die "Cannot create temporary public key beside ${public_key}"
  trap 'rm -f -- "${PUBLIC_KEY_TEMP:-}"' EXIT
  trap 'exit 1' HUP INT TERM

  if ! ssh-keygen -y -f "$KEY_PATH" >"$PUBLIC_KEY_TEMP"; then
    die "Failed to derive public key from ${KEY_PATH}"
  fi
  if [[ ! -s $PUBLIC_KEY_TEMP ]]; then
    die "Derived public key is empty for ${KEY_PATH}"
  fi
  if ! chmod 644 -- "$PUBLIC_KEY_TEMP" || ! ln -- "$PUBLIC_KEY_TEMP" "$public_key"; then
    die "Refusing to replace public key path: ${public_key}"
  fi
  rm -f -- "$PUBLIC_KEY_TEMP"
  PUBLIC_KEY_TEMP=''
  trap - EXIT HUP INT TERM
}

test_connection() {
  local test_command=${SSH_TEST_COMMAND:-hostname}

  info "Testing SSH access to ${SSH_USER}@${SSH_HOST}"
  ssh -i "$KEY_PATH" -o IdentitiesOnly=yes "${SSH_USER}@${SSH_HOST}" "$test_command"
  ok 'SSH access test succeeded'
}
