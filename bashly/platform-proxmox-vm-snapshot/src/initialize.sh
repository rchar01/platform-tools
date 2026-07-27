declare -A snapshot_seen_options=()
snapshot_command=${command_line_args[0]:-}
snapshot_index=1
while ((snapshot_index < ${#command_line_args[@]})); do
  snapshot_argument=${command_line_args[snapshot_index]}
  snapshot_option=${snapshot_argument%%=*}
  snapshot_kind=''

  case $snapshot_command:$snapshot_option in
    create:--vmid|create:--vm-name|create:--environment|create:--snapshot-name|create:--description|create:--ssh|create:--identity-file|create:--expected-targets-file|\
    list:--vmid|list:--vm-name|list:--environment|list:--ssh|list:--identity-file|\
    rollback:--vmid|rollback:--vm-name|rollback:--environment|rollback:--snapshot-name|rollback:--ssh|rollback:--identity-file|rollback:--expected-targets-file|\
    delete:--vmid|delete:--vm-name|delete:--environment|delete:--snapshot-name|delete:--ssh|delete:--identity-file|delete:--expected-targets-file)
      snapshot_kind=scalar
      ;;
    create:--include-memory|create:--dry-run|create:--yes|create:--internal-preflight|create:--internal-action|\
    list:--dry-run|\
    rollback:--start-after-rollback|rollback:--dry-run|rollback:--yes|rollback:--internal-preflight|rollback:--internal-action|\
    delete:--dry-run|delete:--yes|delete:--internal-preflight|delete:--internal-action)
      snapshot_kind=boolean
      ;;
    create:--help|create:-h|list:--help|list:-h|rollback:--help|rollback:-h|delete:--help|delete:-h)
      long_usage=yes
      case $snapshot_command in
        create) platform_proxmox_vm_snapshot_create_usage ;;
        list) platform_proxmox_vm_snapshot_list_usage ;;
        rollback) platform_proxmox_vm_snapshot_rollback_usage ;;
        delete) platform_proxmox_vm_snapshot_delete_usage ;;
      esac
      exit 0
      ;;
    *) break ;;
  esac

  # Bashly accepts equals syntax only for scalar options. Let its parser retain
  # precedence for boolean equals forms instead of reporting a later duplicate.
  if [[ $snapshot_kind == boolean && $snapshot_argument == *=* ]]; then
    break
  fi

  if [[ -v snapshot_seen_options[$snapshot_option] ]]; then
    printf '[ERROR] %s may be specified only once\n' "$snapshot_option" >&2
    exit 1
  fi
  snapshot_seen_options[$snapshot_option]=1

  if [[ $snapshot_kind == scalar && $snapshot_argument != *=* ]]; then
    ((snapshot_index += 1))
    ((snapshot_index < ${#command_line_args[@]})) || break
  elif [[ $snapshot_kind == scalar && $snapshot_argument == *= ]]; then
    break
  fi
  ((snapshot_index += 1))
done
unset snapshot_argument snapshot_command snapshot_index snapshot_kind snapshot_option snapshot_seen_options
