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
[[ -r $CSR_COMMON_PATH ]] || { printf '[ERROR] platform-pki-csr-sign.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-csr-sign.sh disable=SC1091
source "$CSR_COMMON_PATH"

pki_reject_repeated_options --transaction --response-key --namespace --pki-dir --yes
TRANSACTION=${args[--transaction]}
[[ $TRANSACTION =~ ^csr-[0-9a-f]{32}$ ]] || pki_die 'CSR recovery transaction ID is invalid'
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
if [[ ! -v args[--yes] ]]; then
  [[ -t 0 ]] || pki_die 'CSR recovery requires a TTY or --yes'
  printf 'Type recover %s to continue: ' "$TRANSACTION" >&2
  IFS= read -r confirmation
  [[ $confirmation == "recover $TRANSACTION" ]] || pki_die 'CSR recovery confirmation did not match'
fi
pki_csr_recover "${args[--response-key]:-}"
