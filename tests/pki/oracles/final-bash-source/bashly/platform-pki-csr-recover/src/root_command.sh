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
CANDIDATE_COMMON_PATH=$(dirname -- "$COMMON_PATH")/platform-pki-csr-candidate.sh
[[ -r $CANDIDATE_COMMON_PATH ]] || { printf '[ERROR] platform-pki-csr-candidate.sh not found\n' >&2; exit 1; }
# shellcheck source=../../../../lib/platform-pki-csr-candidate.sh disable=SC1091
source "$CANDIDATE_COMMON_PATH"

pki_reject_repeated_options --transaction --response-key --namespace --pki-dir --yes
TRANSACTION=${args[--transaction]:-}
[[ -z $TRANSACTION || $TRANSACTION =~ ^csr-[0-9a-f]{32}$ ]] || pki_die 'CSR recovery transaction ID is invalid'
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")
FINALIZATION_JOURNAL=$(pki_csr_finalization_recovery_journal)
if [[ -e $FINALIZATION_JOURNAL || -L $FINALIZATION_JOURNAL ]]; then
  [[ -z ${args[--response-key]:-} ]] || pki_die '--response-key is not accepted for candidate finalization recovery'
  RECOVERY_DESCRIPTION='candidate finalization'
else
  [[ -n $TRANSACTION ]] || pki_die '--transaction is required for CSR signing recovery'
  RECOVERY_DESCRIPTION=$TRANSACTION
fi
if [[ ! -v args[--yes] ]]; then
  [[ -t 0 ]] || pki_die 'CSR recovery requires a TTY or --yes'
  printf 'Type recover %s to continue: ' "$RECOVERY_DESCRIPTION" >&2
  IFS= read -r confirmation
  [[ $confirmation == "recover $RECOVERY_DESCRIPTION" ]] || pki_die 'CSR recovery confirmation did not match'
fi
if [[ -e $FINALIZATION_JOURNAL || -L $FINALIZATION_JOURNAL ]]; then pki_candidate_recover; else pki_csr_recover "${args[--response-key]:-}"; fi
