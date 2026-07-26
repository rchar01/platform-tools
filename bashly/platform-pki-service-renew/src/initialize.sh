# Preserve the handwritten command's post-service help without changing Bashly's
# handling of leading global help/version options or option arguments.
service_seen=false
skip_value=false
legacy_help_compatible=true
for argument in "${command_line_args[@]}"; do
  if [[ $skip_value == true ]]; then
    skip_value=false
    continue
  fi
  case $argument in
    --namespace|--pki-dir|--days|--intermediate-pass-file)
      skip_value=true
      ;;
    --namespace=?*|--pki-dir=?*|--days=?*|--intermediate-pass-file=?*|--rotate-key)
      ;;
    -*)
      if [[ $legacy_help_compatible == true && $service_seen == true && ( $argument == -h || $argument == --help ) ]]; then
        long_usage=yes
        platform_pki_service_renew_usage
        exit 0
      fi
      legacy_help_compatible=false
      ;;
    *)
      if [[ $service_seen == true ]]; then
        legacy_help_compatible=false
      else
        service_seen=true
      fi
      ;;
  esac
done
