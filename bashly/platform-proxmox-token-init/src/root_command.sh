PROXMOX_USER=${args[--proxmox-user]-tofu@pve}
TOKEN_ID=${args[--token-id]-platform}
ROLE=${args[--role]-Administrator}
ACL_PATH=${args[--path]-/}
COMMENT=${args[--comment]-OpenTofu automation user}
PRIVSEP=0
SSH_TARGET=${args[--ssh]:-}
WRITE_TOKEN_FILE=${args[--write-token-file]:-}
FORCE=false
CHECK_ONLY=false
EMIT_TOKEN_LINE=false
GENERATED_TOKEN_LINE=''
TOKEN_FILE_TEMP=''
TOKEN_FILE_PREFLIGHT_PATH=''
TOKEN_FILE_PREFLIGHT_STATE=''
[[ ! -v args[--force] ]] || FORCE=true
[[ ! -v args[--check] ]] || CHECK_ONLY=true
[[ ! -v args[--emit-token-line] ]] || EMIT_TOKEN_LINE=true

validate_inputs

if [[ $CHECK_ONLY == true ]]; then
  run_checks
  exit 0
fi

if [[ -n $SSH_TARGET ]]; then
  run_over_ssh
  exit 0
fi

[[ -z $WRITE_TOKEN_FILE ]] || preflight_token_file "$WRITE_TOKEN_FILE"
command_exists pveum || die 'pveum is required; run this on a Proxmox host, or use --ssh from an operator workstation'

ensure_user
if token_exists; then
  warn "Token ${PROXMOX_USER}!${TOKEN_ID} already exists. Proxmox cannot show the existing secret."
  warn 'Delete and recreate the token if you lost the token secret.'
else
  create_token
fi
ensure_acl

if [[ -n $WRITE_TOKEN_FILE ]]; then
  if [[ -n $GENERATED_TOKEN_LINE ]]; then
    write_token_file "$WRITE_TOKEN_FILE" "$GENERATED_TOKEN_LINE"
  else
    warn "Nothing was written to $WRITE_TOKEN_FILE. Proxmox did not provide a newly generated token secret."
  fi
else
  cat <<EOF

Next step:

  Copy the generated token line into:

    ~/.config/platform-infrastructure/infra/proxmox.token

The file should contain one raw line like:

  ${PROXMOX_USER}!${TOKEN_ID}=TOKEN_SECRET

EOF
fi
