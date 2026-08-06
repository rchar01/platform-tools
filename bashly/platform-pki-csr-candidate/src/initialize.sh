enable_auto_colors

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then
  COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then
  COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else
  COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh
fi
[[ -r $COMMON_PATH ]] || { printf '[ERROR] platform-pki-common.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"
CSR_COMMON_PATH=$(dirname -- "$COMMON_PATH")/platform-pki-csr-sign.sh
CANDIDATE_COMMON_PATH=$(dirname -- "$COMMON_PATH")/platform-pki-csr-candidate.sh
[[ -r $CSR_COMMON_PATH && -r $CANDIDATE_COMMON_PATH ]] || { printf '[ERROR] PKI CSR shared libraries not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-csr-sign.sh disable=SC1091
source "$CSR_COMMON_PATH"
# shellcheck source=../../../../lib/platform-pki-csr-candidate.sh disable=SC1091
source "$CANDIDATE_COMMON_PATH"

candidate_confirm() {
  local action=$1 service=${args[service]} request_id=${args[--request-id]}
  [[ -v args[--yes] ]] && return 0
  [[ -t 0 ]] || pki_die "CSR candidate $action requires a TTY or --yes"
  printf 'Type %s %s %s to continue: ' "$action" "$service" "$request_id" >&2
  IFS= read -r confirmation
  [[ $confirmation == "$action $service $request_id" ]] || pki_die "CSR candidate $action confirmation did not match"
}
