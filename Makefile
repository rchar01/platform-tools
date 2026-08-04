SHELL := /bin/sh
.DEFAULT_GOAL := help

INSTALL_DIR ?= $(HOME)/.local/bin
SHARE_DIR ?= $(HOME)/.local/share/platform-tools
SHELL_TOOLS := platform-ssh-init platform-vm-env-collect platform-config-init platform-proxmox-token-init platform-proxmox-vm-cleanup platform-proxmox-vm-snapshot platform-pki-init platform-pki-inventory-install platform-pki-root-create platform-pki-intermediate-create platform-pki-service-issue platform-pki-service-renew platform-pki-service-verify platform-pki-list-expiry platform-pki-print-cert platform-pki-export-ansible platform-pki-backup platform-pki-ca-rollover
PYTHON_TOOLS := platform-bastion-policy
TOOLS := $(SHELL_TOOLS) $(PYTHON_TOOLS)
LIBS := lib/platform-pki-common.sh
DEV_SCRIPTS := scripts/check scripts/devshell scripts/generate scripts/in-container scripts/verify-generated
BASHLY_TOOLS := platform-config-init platform-vm-env-collect platform-pki-print-cert platform-pki-list-expiry platform-pki-service-verify platform-pki-init platform-pki-inventory-install platform-pki-backup platform-pki-export-ansible platform-pki-root-create platform-pki-intermediate-create platform-pki-service-issue platform-pki-service-renew platform-pki-ca-rollover platform-ssh-init platform-proxmox-token-init platform-proxmox-vm-cleanup platform-proxmox-vm-snapshot

.PHONY: help shell container-check generate verify-generated install verify test test-python-infrastructure test-python-pki-rollover test-python-pki-rollover-parallel test-command-contract test-installed-tools test-platform-config-init test-platform-ssh-init test-vm-env-collect-cli test-vm-env-collect-archive test-bastion-policy test-proxmox-token-init test-proxmox-vm-cleanup test-proxmox-vm-snapshot test-pki-init test-pki-root-create test-pki-intermediate-create test-pki-service-issue test-pki-service-renew test-pki-print-cert test-pki-list-expiry test-pki-service-verify test-pki-pass-file test-pki-legacy-gating test-pki-backup test-pki-export test-pki-inventory test-pki-inventory-install test-pki-ca-rollover test-pki-ca-rollover-parser shellcheck

## Show available commands
help:
	@printf '%s\n' 'Available targets:'
	@awk '\
		/^## / { help = substr($$0, 4); next } \
		/^[a-zA-Z0-9_.-]+:/ { \
			if (help != "") { \
				target = $$1; \
				sub(/:.*/, "", target); \
				printf "  %-24s %s\n", target, help; \
				help = ""; \
			} \
		} \
	' $(MAKEFILE_LIST) | sort

## Open a shell in the Podman development container
shell:
	./scripts/devshell

## Run all maintained checks in the development container
container-check:
	./scripts/in-container ./scripts/check

## Generate committed Bash CLI artifacts
generate:
	./scripts/generate $(BASHLY_TOOLS)

## Verify committed Bash CLI artifacts are current
verify-generated:
	./scripts/verify-generated $(BASHLY_TOOLS)

## Install platform tools into INSTALL_DIR
install:
	mkdir -p "$(INSTALL_DIR)"
	mkdir -p "$(SHARE_DIR)/lib" "$(SHARE_DIR)/templates/pki"
	@for tool in $(TOOLS); do \
		cp "bin/$$tool" "$(INSTALL_DIR)/$$tool"; \
		chmod 755 "$(INSTALL_DIR)/$$tool"; \
		printf '%s\n' "Installed $$tool to $(INSTALL_DIR)/$$tool"; \
	done
	cp $(LIBS) "$(SHARE_DIR)/lib/"
	cp templates/pki/* "$(SHARE_DIR)/templates/pki/"
	chmod 644 "$(SHARE_DIR)/lib/platform-pki-common.sh" "$(SHARE_DIR)"/templates/pki/*
	@printf '%s\n' "Installed shared assets to $(SHARE_DIR)"

## Run syntax checks for maintained tool scripts
verify:
	@for tool in $(SHELL_TOOLS); do \
		bash -n "bin/$$tool"; \
	done
	@for lib in $(LIBS); do \
		bash -n "$$lib"; \
	done
	@for script in $(DEV_SCRIPTS); do \
		bash -n "$$script"; \
	done
	@for tool in $(PYTHON_TOOLS); do \
		python3 -m py_compile "bin/$$tool"; \
	done

## Run maintained tests
test: test-python-infrastructure test-command-contract test-installed-tools test-platform-config-init test-platform-ssh-init test-vm-env-collect-cli test-bastion-policy test-proxmox-token-init test-proxmox-vm-cleanup test-proxmox-vm-snapshot test-pki-init test-pki-root-create test-pki-intermediate-create test-pki-service-issue test-pki-service-renew test-pki-print-cert test-pki-list-expiry test-pki-service-verify test-pki-pass-file test-pki-legacy-gating test-pki-backup test-pki-export test-pki-inventory test-pki-inventory-install test-pki-ca-rollover

## Run generic Python test-harness contract tests
test-python-infrastructure:
	python3 -m pytest -m infrastructure tests/test_harness.py

## Run authoritative PKI rollover pytest scenarios directly
test-python-pki-rollover:
	python3 -m pytest -m pki tests/pki/test_ca_rollover_*.py

## Run authoritative PKI rollover pytest scenarios with bounded parallel workers
test-python-pki-rollover-parallel:
	@python3 -c 'import xdist' >/dev/null 2>&1 || { \
		printf '%s\n' 'pytest-xdist is required; run in make shell or use ./scripts/in-container' >&2; \
		exit 2; \
	}
	@workers=$${PKI_PYTEST_WORKERS:-4}; \
	case "$$workers" in \
		1|2|3|4) ;; \
		*) printf '%s\n' 'PKI_PYTEST_WORKERS must be an integer from 1 through 4' >&2; exit 2 ;; \
	esac; \
	python3 -m pytest -n "$$workers" -m pki tests/pki/test_ca_rollover_*.py

## Run the maintained cross-command CLI contract tests
test-command-contract:
	python3 -m pytest tests/test_command_contract.py

## Smoke test all commands and PKI assets from a disposable install
test-installed-tools:
	python3 -m pytest tests/test_installed_tools.py

## Run platform config initializer behavior tests
test-platform-config-init:
	python3 -m pytest tests/test_platform_config_init.py

## Run SSH identity initializer behavior tests
test-platform-ssh-init:
	python3 -m pytest tests/test_platform_ssh_init.py

## Run VM environment collector CLI tests
test-vm-env-collect-cli:
	python3 -m pytest tests/test_vm_env_collect_cli.py

## Run VM collector archive smoke tests in the dev container
test-vm-env-collect-archive:
	python3 -m pytest tests/test_vm_env_collect_archive.py

## Run bastion policy render tests
test-bastion-policy:
	python3 -m pytest tests/test_bastion_policy_render.py

## Run Proxmox token initializer behavior tests
test-proxmox-token-init:
	python3 -m pytest tests/test_proxmox_token_init.py

## Run Proxmox VM cleanup behavior tests
test-proxmox-vm-cleanup:
	python3 -m pytest tests/test_proxmox_vm_cleanup.py

## Run Proxmox VM snapshot behavior tests
test-proxmox-vm-snapshot:
	python3 -m pytest tests/test_proxmox_vm_snapshot.py

## Run PKI namespace initialization behavior tests
test-pki-init:
	python3 -m pytest tests/pki/test_init.py

## Run PKI root CA creation behavior tests
test-pki-root-create:
	python3 -m pytest tests/pki/test_root_create.py

## Run PKI intermediate CA creation behavior tests
test-pki-intermediate-create:
	python3 -m pytest tests/pki/test_intermediate_create.py

## Run PKI service certificate issuance behavior tests
test-pki-service-issue:
	python3 -m pytest tests/pki/test_service_issue.py

## Run PKI service certificate renewal behavior tests
test-pki-service-renew:
	python3 -m pytest tests/pki/test_service_renew.py

## Run PKI certificate printing behavior tests
test-pki-print-cert:
	python3 -m pytest tests/pki/test_print_cert.py

## Run PKI certificate expiry behavior tests
test-pki-list-expiry:
	python3 -m pytest tests/pki/test_list_expiry.py

## Run PKI service certificate verification tests
test-pki-service-verify:
	python3 -m pytest tests/pki/test_service_verify.py

## Run PKI passphrase file validation tests
test-pki-pass-file:
	python3 -m pytest tests/pki/test_pass_file_validation.py

## Run PKI legacy-layout migration gating tests
test-pki-legacy-gating:
	python3 -m pytest tests/pki/test_legacy_command_gating.py

## Run PKI backup archive exclusion tests
test-pki-backup:
	python3 -m pytest tests/pki/test_backup_excludes_backups.py tests/pki/test_backup_cli.py

## Run PKI Ansible export path safety tests
test-pki-export:
	python3 -m pytest tests/pki/test_export_ansible_safe_paths.py

## Run PKI inventory value validation tests
test-pki-inventory:
	python3 -m pytest tests/pki/test_inventory_value_validation.py tests/pki/test_inventory_contract.py

## Run PKI inventory installation tests
test-pki-inventory-install:
	python3 -m pytest tests/pki/test_inventory_install.py

## Run authoritative generation-aware CA rollover tests
test-pki-ca-rollover: test-python-pki-rollover-parallel

## Run authoritative rollover parser contract tests
test-pki-ca-rollover-parser:
	python3 -m pytest -m pki tests/pki/test_ca_rollover_parser.py

## Run ShellCheck for maintained tool scripts
shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { printf '%s\n' 'shellcheck not found; install ShellCheck or skip this target' >&2; exit 1; }
	shellcheck $(addprefix bin/,$(SHELL_TOOLS)) $(LIBS) $(DEV_SCRIPTS)
