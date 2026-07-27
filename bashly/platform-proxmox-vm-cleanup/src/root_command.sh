VMID=${args[--vmid]}
SSH_TARGET=${args[--ssh]:-}
IDENTITY_FILE=${args[--identity-file]:-}
EXPECTED_NAME=${args[--name]:-}
ASSUME_YES=false
REMOTE_INSPECT=false
REMOTE_DESTROY=false
REMOTE_CANCEL=false
AUTHORIZATION_TOKEN=''
[[ ! -v args[--yes] ]] || ASSUME_YES=true
[[ ! -v args[--remote-inspect] ]] || REMOTE_INSPECT=true
if [[ -v args[--remote-destroy] ]]; then
  REMOTE_DESTROY=true
  ASSUME_YES=true
fi
[[ ! -v args[--remote-cancel] ]] || REMOTE_CANCEL=true

validate_inputs

if [[ $REMOTE_INSPECT == true || $REMOTE_DESTROY == true || $REMOTE_CANCEL == true ]]; then
  [[ -z $SSH_TARGET ]] || die '--ssh cannot be combined with internal remote modes'
  run_local
  exit 0
fi

if [[ -n $SSH_TARGET ]]; then
  run_over_ssh
else
  run_local
fi
