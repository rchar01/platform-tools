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

SERVICE=${args[service]}
NAMESPACE=${args[--namespace]:-$(pki_default_namespace)}
PKI_DIR=${args[--pki-dir]:-}

pki_validate_service_name "$SERVICE"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")

pki_require_cmd openssl
pki_require_pki_dir
pki_require_service_in_inventory "$SERVICE"
CERT=$(pki_service_cert "$SERVICE")
pki_require_file "$CERT"

printf 'Service: %s\n' "$SERVICE"
openssl x509 -in "$CERT" -noout \
  -subject \
  -issuer \
  -serial \
  -startdate \
  -enddate \
  -fingerprint -sha256
openssl x509 -in "$CERT" -noout -ext subjectAltName || true
openssl x509 -in "$CERT" -noout -ext keyUsage || true
openssl x509 -in "$CERT" -noout -ext extendedKeyUsage || true
