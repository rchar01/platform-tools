CONFIG_FILE=${args[config_file]:-}

if [[ -n $CONFIG_FILE ]]; then
  [[ -f $CONFIG_FILE ]] || die "Config file not found: ${CONFIG_FILE}"
  load_config_file
fi

[[ ! -v args[--key-path] ]] || SSH_KEY_PATH=${args[--key-path]}
[[ ! -v args[--comment] ]] || SSH_KEY_COMMENT=${args[--comment]}
[[ ! -v args[--host] ]] || SSH_HOST=${args[--host]}
[[ ! -v args[--user] ]] || SSH_USER=${args[--user]}
[[ ! -v args[--alias] ]] || SSH_ALIAS=${args[--alias]}
[[ ! -v args[--test-command] ]] || SSH_TEST_COMMAND=${args[--test-command]}

EMPTY_PASSPHRASE=false
WRITE_CONFIG=false
RUN_TEST=false
PRINT_PUBLIC_KEY=false
[[ ! -v args[--empty-passphrase] ]] || EMPTY_PASSPHRASE=true
[[ ! -v args[--write-config] ]] || WRITE_CONFIG=true
[[ ! -v args[--test] ]] || RUN_TEST=true
[[ ! -v args[--print-public-key] ]] || PRINT_PUBLIC_KEY=true

require_var SSH_KEY_PATH
SSH_USER=${SSH_USER:-$(id -un)}
SSH_KEY_COMMENT=${SSH_KEY_COMMENT:-platform-ssh-init}

KEY_PATH=$(expand_path "$SSH_KEY_PATH")
KEY_DIR=$(dirname -- "$KEY_PATH")
SSH_DIR=${HOME}/.ssh
SSH_CONFIG_FILE=${HOME}/.ssh/config

command_exists ssh-keygen || die 'ssh-keygen is required'
validate_connection_values
validate_actions
preflight_key_directory
validate_key_targets

umask 077
mkdir -p -- "$KEY_DIR"
preflight_key_directory
chmod 700 -- "$KEY_DIR"

if [[ -e $KEY_PATH ]]; then
  chmod 600 -- "$KEY_PATH"
  ok "SSH key already exists: ${KEY_PATH}"
else
  info "Creating dedicated ed25519 SSH key: ${KEY_PATH}"
  if [[ $EMPTY_PASSPHRASE == true ]]; then
    ssh-keygen -t ed25519 -a 100 -N '' -f "$KEY_PATH" -C "$SSH_KEY_COMMENT"
  else
    ssh-keygen -t ed25519 -a 100 -f "$KEY_PATH" -C "$SSH_KEY_COMMENT"
  fi
  validate_owned_regular_file "$KEY_PATH" 'SSH private key path'
  chmod 600 -- "$KEY_PATH"
  ok "Created SSH key: ${KEY_PATH}"
fi

if [[ ! -e ${KEY_PATH}.pub && ! -L ${KEY_PATH}.pub ]]; then
  info "Creating missing public key: ${KEY_PATH}.pub"
  derive_public_key
  ok "Created public key: ${KEY_PATH}.pub"
else
  validate_owned_regular_file "${KEY_PATH}.pub" 'SSH public key path'
  chmod 644 -- "${KEY_PATH}.pub"
fi

if has_host_config; then
  printf '\nSSH config block:\n\n'
  print_ssh_config
  printf '\nInstall the public key on the remote host if needed:\n\n'
  printf 'ssh-copy-id -i '
  printf '%q' "${SSH_KEY_PATH}.pub"
  printf ' %s@%s\n' "$SSH_USER" "$SSH_HOST"
fi

if [[ $WRITE_CONFIG == true ]]; then
  write_ssh_config "$SSH_DIR" "$SSH_CONFIG_FILE"
elif has_host_config; then
  printf '\nRun again with --write-config to append this Host block to %s.\n' "$SSH_CONFIG_FILE"
fi

if [[ $PRINT_PUBLIC_KEY == true ]]; then
  printf '\nPublic key:\n\n'
  sed -n '1p' -- "${KEY_PATH}.pub"
fi

if [[ $RUN_TEST == true ]]; then
  test_connection
elif [[ -n ${SSH_HOST:-} ]]; then
  printf '\nAfter installing the public key, test access with:\n\n'
  printf 'ssh -i '
  printf '%q' "$KEY_PATH"
  printf ' -o IdentitiesOnly=yes %s@%s ' "$SSH_USER" "$SSH_HOST"
  printf '%q\n' "${SSH_TEST_COMMAND:-hostname}"
fi
