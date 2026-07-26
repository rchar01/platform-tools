SHELL := /bin/sh
.DEFAULT_GOAL := help

INSTALL_DIR ?= $(HOME)/.local/bin
SHARE_DIR ?= $(HOME)/.local/share/platform-tools
SHELL_TOOLS := platform-ssh-init platform-vm-env-collect platform-config-init platform-proxmox-token-init platform-proxmox-vm-cleanup platform-proxmox-vm-snapshot platform-pki-init platform-pki-root-create platform-pki-intermediate-create platform-pki-service-issue platform-pki-service-renew platform-pki-service-verify platform-pki-list-expiry platform-pki-print-cert platform-pki-export-ansible platform-pki-backup
PYTHON_TOOLS := platform-bastion-policy
TOOLS := $(SHELL_TOOLS) $(PYTHON_TOOLS)
LIBS := lib/platform-pki-common.sh
DEV_SCRIPTS := scripts/check scripts/devshell scripts/generate scripts/in-container scripts/verify-generated
BASHLY_TOOLS := platform-config-init platform-vm-env-collect platform-pki-print-cert platform-pki-list-expiry platform-pki-service-verify platform-pki-init platform-pki-backup platform-pki-export-ansible platform-pki-root-create platform-ssh-init

.PHONY: help shell container-check generate verify-generated install verify test test-platform-config-init test-platform-ssh-init test-vm-env-collect-cli test-vm-env-collect-archive test-bastion-policy test-proxmox-vm-snapshot test-pki-init test-pki-root-create test-pki-print-cert test-pki-list-expiry test-pki-service-verify test-pki-pass-file test-pki-backup test-pki-export test-pki-inventory shellcheck

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
test: test-platform-config-init test-platform-ssh-init test-vm-env-collect-cli test-bastion-policy test-proxmox-vm-snapshot test-pki-init test-pki-root-create test-pki-print-cert test-pki-list-expiry test-pki-service-verify test-pki-pass-file test-pki-backup test-pki-export test-pki-inventory

## Run platform config initializer behavior tests
test-platform-config-init:
	./tests/cli/test-platform-config-init.sh

## Run SSH identity initializer behavior tests
test-platform-ssh-init:
	./tests/cli/test-platform-ssh-init.sh

## Run VM environment collector CLI tests
test-vm-env-collect-cli:
	./tests/cli/test-vm-env-collect-cli.sh

## Run VM collector archive smoke tests in the dev container
test-vm-env-collect-archive:
	./tests/cli/test-vm-env-collect-archive.sh

## Run bastion policy render tests
test-bastion-policy:
	./tests/bastion-policy/test-render.sh

## Run Proxmox VM snapshot behavior tests
test-proxmox-vm-snapshot:
	./tests/proxmox-vm-snapshot/test-snapshot.sh

## Run PKI namespace initialization behavior tests
test-pki-init:
	./tests/pki/test-init.sh

## Run PKI root CA creation behavior tests
test-pki-root-create:
	./tests/pki/test-root-create.sh

## Run PKI certificate printing behavior tests
test-pki-print-cert:
	./tests/pki/test-print-cert.sh

## Run PKI certificate expiry behavior tests
test-pki-list-expiry:
	./tests/pki/test-list-expiry.sh

## Run PKI service certificate verification tests
test-pki-service-verify:
	./tests/pki/test-service-verify.sh

## Run PKI passphrase file validation tests
test-pki-pass-file:
	./tests/pki/test-pass-file-validation.sh

## Run PKI backup archive exclusion tests
test-pki-backup:
	./tests/pki/test-backup-excludes-backups.sh
	./tests/pki/test-backup-cli.sh

## Run PKI Ansible export path safety tests
test-pki-export:
	./tests/pki/test-export-ansible-safe-paths.sh

## Run PKI inventory value validation tests
test-pki-inventory:
	./tests/pki/test-inventory-value-validation.sh

## Run ShellCheck for maintained tool scripts
shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { printf '%s\n' 'shellcheck not found; install ShellCheck or skip this target' >&2; exit 1; }
	shellcheck $(addprefix bin/,$(SHELL_TOOLS)) $(LIBS) $(DEV_SCRIPTS)
