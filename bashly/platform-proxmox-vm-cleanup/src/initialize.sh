# Preserve the handwritten parser's interspersed help behavior while allowing
# any earlier parser or validation error to take precedence.
legacy_help_compatible=true
index=0
while ((index < ${#command_line_args[@]})); do
  argument=${command_line_args[index]}
  case $argument in
    --help|-h)
      if [[ $legacy_help_compatible == true ]]; then
        long_usage=yes
        platform_proxmox_vm_cleanup_usage
        exit 0
      fi
      ;;
    --vmid|--ssh|--identity-file|--name)
      ((index += 1))
      if ((index >= ${#command_line_args[@]})); then
        legacy_help_compatible=false
      fi
      ;;
    --vmid=?*|--ssh=?*|--identity-file=?*|--name=?*|--yes|--remote-inspect|--remote-destroy|--remote-cancel)
      ;;
    *) legacy_help_compatible=false ;;
  esac
  ((index += 1))
done
