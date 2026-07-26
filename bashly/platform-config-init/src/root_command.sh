config_dir=${args[--config-dir]:-$(default_config_dir)}
config_dir=$(expand_path "$config_dir")

mkdir -p "$config_dir"
chmod 700 "$config_dir"
ok "Config directory ready: $config_dir"

ensure_secret_dir "$config_dir/config"
ensure_secret_dir "$config_dir/infra"
ensure_secret_dir "$config_dir/pki"

write_if_missing "$config_dir/README.md" content_readme

for legacy_path in \
  "$config_dir/proxmox-token" \
  "$config_dir/codeberg.env" \
  "$config_dir/ansible.env" \
  "$config_dir/backup.env" \
  "$config_dir/proxmox.env"; do
  if [[ -e "$legacy_path" ]]; then
    warn "Legacy path exists and was left unchanged: $legacy_path"
  fi
done

cat <<EOF

Next steps:

  1. Let each downstream project/helper create its own files under:

        $config_dir

  2. Write the Proxmox token through the Proxmox helper when needed:

        platform-proxmox-token-init --write-token-file "$config_dir/infra/proxmox.token" --ssh root@<proxmox-ip>

  3. Run the downstream platform command, for example:

       tofu plan -var-file=../../../platform-private/infra/production.tfvars

EOF
