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
MIN_DAYS=${args[--min-days]:-30}

pki_validate_service_name "$SERVICE"
pki_validate_days "$MIN_DAYS"
NAMESPACE=$(pki_expand_path "$NAMESPACE")
PKI_DIR=${PKI_DIR:-${NAMESPACE}/pki}
PKI_DIR=$(pki_expand_path "$PKI_DIR")

pki_require_cmd openssl
pki_require_pki_dir
pki_require_service_in_inventory "$SERVICE"

KEY=$(pki_service_key "$SERVICE")
CERT=$(pki_service_cert "$SERVICE")
ROOT_CERT=$(pki_root_cert)
INT_CERT=$(pki_intermediate_cert)
pki_require_file "$KEY"
pki_require_file "$CERT"
pki_require_file "$ROOT_CERT"
pki_require_file "$INT_CERT"

openssl verify -CAfile "$ROOT_CERT" -untrusted "$INT_CERT" "$CERT" >/dev/null
pki_key_matches_cert "$KEY" "$CERT" || pki_die "Private key does not match certificate for service: $SERVICE"
pki_cert_has_ca_false "$CERT" || pki_die "Certificate is missing CA:false: $CERT"
pki_cert_has_server_auth "$CERT" || pki_die "Certificate is missing serverAuth EKU: $CERT"

while IFS= read -r dns || [[ -n $dns ]]; do
  [[ -n $dns ]] || continue
  pki_cert_has_dns_san "$CERT" "$dns" || pki_die "Certificate is missing DNS SAN '${dns}': $CERT"
done < <(pki_inventory_array "$SERVICE" dns)

while IFS= read -r ip || [[ -n $ip ]]; do
  [[ -n $ip ]] || continue
  pki_cert_has_ip_san "$CERT" "$ip" || pki_die "Certificate is missing IP SAN '${ip}': $CERT"
done < <(pki_inventory_array "$SERVICE" ips)

SECONDS_LEFT=$(( MIN_DAYS * 86400 ))
openssl x509 -in "$CERT" -checkend "$SECONDS_LEFT" -noout >/dev/null || pki_die "Certificate has less than ${MIN_DAYS} days remaining: $CERT"

pki_ok "Verified service certificate: $SERVICE"
