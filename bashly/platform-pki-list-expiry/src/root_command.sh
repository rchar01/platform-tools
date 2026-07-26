SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
COMMON_PATH=${PLATFORM_TOOLS_LIB_DIR:-}
if [[ -n $COMMON_PATH ]]; then
  COMMON_PATH=${COMMON_PATH}/platform-pki-common.sh
elif [[ -r ${SCRIPT_DIR}/../lib/platform-pki-common.sh ]]; then
  COMMON_PATH=${SCRIPT_DIR}/../lib/platform-pki-common.sh
else
  COMMON_PATH=${PLATFORM_TOOLS_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/platform-tools}/lib/platform-pki-common.sh
fi
[[ -r $COMMON_PATH ]] || {
  printf '[ERROR] platform-pki-common.sh not found\n' >&2
  exit 1
}
# shellcheck source=../../../../lib/platform-pki-common.sh disable=SC1091
source "$COMMON_PATH"

NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}
WARN_DAYS=${args[--warn-days]:-90}
CRITICAL_DAYS=${args[--critical-days]:-30}

pki_validate_days "$WARN_DAYS"
pki_validate_days "$CRITICAL_DAYS"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")

pki_require_cmd openssl
pki_require_pki_dir
pki_require_inventory

printf '%-24s %-22s %-10s %s\n' 'SERVICE' 'EXPIRES' 'DAYS_LEFT' 'STATUS'
EXIT_CODE=0

while IFS= read -r service || [[ -n $service ]]; do
  [[ -n $service ]] || continue
  cert=$(pki_service_cert "$service")
  if [[ ! -f $cert ]]; then
    printf '%-24s %-22s %-10s %s\n' "$service" '-' '-' 'MISSING'
    EXIT_CODE=3
    continue
  fi

  days_left=$(pki_cert_days_left "$cert")
  expires=$(pki_cert_not_after_iso "$cert")
  status=OK
  if (( days_left <= CRITICAL_DAYS )); then
    status=CRITICAL
    if (( EXIT_CODE < 2 )); then
      EXIT_CODE=2
    fi
  elif (( days_left <= WARN_DAYS )); then
    status=WARN
    if (( EXIT_CODE < 1 )); then
      EXIT_CODE=1
    fi
  fi

  printf '%-24s %-22s %-10s %s\n' "$service" "$expires" "$days_left" "$status"
done < <(pki_inventory_services)

exit "$EXIT_CODE"
