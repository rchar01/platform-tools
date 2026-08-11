SHELL := /bin/sh
.DEFAULT_GOAL := help

INSTALL_DIR ?= $(HOME)/.local/bin
SHARE_DIR ?= $(HOME)/.local/share/platform-tools
TEST_MAKE_JOBS ?= 2
PKI_PYTEST_WORKERS ?= 4
export TEST_MAKE_JOBS PKI_PYTEST_WORKERS
SHELL_TOOLS := platform-ssh-init platform-vm-env-collect platform-config-init platform-proxmox-token-init platform-proxmox-vm-cleanup platform-proxmox-vm-snapshot platform-pki-csr-trust-install platform-pki-certificate-export platform-pki-csr-candidate platform-pki-service-issue platform-pki-service-renew platform-pki-ca-rollover
PYTHON_SOURCE_TOOLS := platform-bastion-policy
PYTHON_ZIPAPPS := platform-pki platform-pki-init platform-pki-inventory-install platform-pki-print-cert platform-pki-list-expiry platform-pki-service-verify platform-pki-export-ansible platform-pki-backup platform-pki-custody-report platform-pki-ca-passphrase-verify platform-pki-root-create platform-pki-intermediate-create platform-pki-csr-recover
PYTHON_TOOLS := $(PYTHON_SOURCE_TOOLS) $(PYTHON_ZIPAPPS)
PYTHON_SOURCES := scripts/build-platform-pki-zipapp.py $(wildcard src/platform_pki/*.py)
TOOLS := $(SHELL_TOOLS) $(PYTHON_TOOLS)
LIBS := lib/platform-pki-common.sh lib/platform-pki-csr-sign.sh lib/platform-pki-csr-candidate.sh
MAINTAINED_SCRIPTS := scripts/check scripts/devshell scripts/generate scripts/in-container scripts/in-test-container scripts/verify-generated
BASHLY_TOOLS := platform-config-init platform-vm-env-collect platform-pki-csr-trust-install platform-pki-certificate-export platform-pki-csr-candidate platform-pki-service-issue platform-pki-service-renew platform-pki-ca-rollover platform-ssh-init platform-proxmox-token-init platform-proxmox-vm-cleanup platform-proxmox-vm-snapshot
NON_ROLLOVER_TEST_TARGETS := test-python-infrastructure test-command-contract test-installed-tools test-platform-pki-foundation test-platform-config-init test-platform-ssh-init test-vm-env-collect-cli test-bastion-policy test-proxmox-token-init test-proxmox-vm-cleanup test-proxmox-vm-snapshot test-pki-init test-pki-root-create test-pki-intermediate-create test-pki-service-issue test-pki-service-issue-writer test-pki-service-writer test-pki-service-renew test-pki-service-recover test-pki-print-cert test-pki-list-expiry test-pki-service-verify test-pki-pass-file test-pki-legacy-gating test-pki-backup test-pki-custody-report test-pki-ca-passphrase-verify test-pki-export test-pki-certificate-export test-pki-csr-candidate test-pki-inventory test-pki-inventory-install test-pki-csr-trust-install test-pki-csr-signing

.PHONY: help shell container-check generate generate-python verify-generated verify-python-generated install verify test test-non-rollover test-python-infrastructure test-python-pki-rollover test-python-pki-rollover-parallel test-command-contract test-installed-tools test-platform-pki-foundation test-platform-pki-service-transaction-foundation test-platform-pki-publication test-platform-config-init test-platform-ssh-init test-vm-env-collect-cli test-vm-env-collect-archive test-bastion-policy test-proxmox-token-init test-proxmox-vm-cleanup test-proxmox-vm-snapshot test-pki-init test-pki-root-create test-pki-intermediate-create test-pki-service-issue test-pki-service-issue-writer test-pki-service-writer test-pki-service-renew test-pki-service-recover test-pki-print-cert test-pki-list-expiry test-pki-service-verify test-pki-pass-file test-pki-legacy-gating test-pki-backup test-pki-custody-report test-pki-ca-passphrase-verify test-pki-export test-pki-certificate-export test-pki-csr-candidate test-pki-inventory test-pki-inventory-install test-pki-csr-trust-install test-pki-csr-signing test-pki-ca-rollover test-pki-ca-rollover-python-recover test-pki-ca-rollover-parser shellcheck

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

## Run all maintained checks in pinned containers
container-check:
	./scripts/in-container make verify-generated shellcheck
	./scripts/in-test-container ./scripts/check

## Generate committed Bash CLI artifacts
generate:
	./scripts/generate $(BASHLY_TOOLS)

## Generate the committed Python PKI zipapp
generate-python:
	@for tool in $(PYTHON_ZIPAPPS); do \
		python3 scripts/build-platform-pki-zipapp.py --output "bin/$$tool"; \
	done

## Verify committed Bash CLI artifacts are current
verify-generated:
	./scripts/verify-generated $(BASHLY_TOOLS)

## Verify the committed Python PKI zipapp is deterministic and current
verify-python-generated:
	@for tool in $(PYTHON_ZIPAPPS); do \
		python3 scripts/build-platform-pki-zipapp.py --verify --output "bin/$$tool"; \
	done

## Install platform tools into INSTALL_DIR
install: verify-python-generated
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
verify: verify-python-generated
	@for tool in $(SHELL_TOOLS); do \
		bash -n "bin/$$tool"; \
	done
	@for lib in $(LIBS); do \
		bash -n "$$lib"; \
	done
	@for script in $(MAINTAINED_SCRIPTS); do \
		bash -n "$$script"; \
	done
	@for tool in $(PYTHON_SOURCE_TOOLS); do \
		python3 -m py_compile "bin/$$tool"; \
	done
	python3 -m py_compile $(PYTHON_SOURCES)

## Run maintained tests
test:
	+@case "$$TEST_MAKE_JOBS" in \
		1|2|3|4) ;; \
		*) printf '%s\n' 'TEST_MAKE_JOBS must be an integer from 1 through 4' >&2; exit 2 ;; \
	esac; \
	case "$$PKI_PYTEST_WORKERS" in \
		1|2|3|4) ;; \
		*) printf '%s\n' 'PKI_PYTEST_WORKERS must be an integer from 1 through 4' >&2; exit 2 ;; \
	esac; \
	$(MAKE) --no-print-directory --jobs="$$TEST_MAKE_JOBS" --output-sync=target test-non-rollover && \
	$(MAKE) --no-print-directory test-pki-ca-rollover

test-non-rollover: $(NON_ROLLOVER_TEST_TARGETS)

## Run generic Python test-harness contract tests
test-python-infrastructure:
	python3 -m pytest -m infrastructure \
		tests/test_harness.py \
		tests/test_make_orchestration.py \
		tests/pki/test_migration_contract.py \
		tests/pki/test_migration_harness.py \
		tests/pki/test_rollover_wrapper.py

## Run authoritative PKI rollover pytest scenarios directly
test-python-pki-rollover:
	python3 -m pytest -m pki tests/pki/test_ca_rollover_*.py

## Run authoritative PKI rollover pytest scenarios with bounded parallel workers
test-python-pki-rollover-parallel:
	@workers=$${PKI_PYTEST_WORKERS-}; \
	case "$$workers" in \
		1|2|3|4) ;; \
		*) printf '%s\n' 'PKI_PYTEST_WORKERS must be an integer from 1 through 4' >&2; exit 2 ;; \
	esac; \
	python3 -c 'import xdist' >/dev/null 2>&1 || { \
		printf '%s\n' 'pytest-xdist is required; use ./scripts/in-test-container' >&2; \
		exit 2; \
	}; \
	python3 -m pytest -n "$$workers" -m pki tests/pki/test_ca_rollover_*.py

## Run the maintained cross-command CLI contract tests
test-command-contract:
	python3 -m pytest tests/test_command_contract.py

## Smoke test all commands and PKI assets from a disposable install
test-installed-tools:
	python3 -m pytest tests/test_installed_tools.py

## Run deterministic Python PKI foundation and primitive tests
test-platform-pki-foundation:
	python3 -m pytest \
		tests/test_platform_pki_foundation.py \
		tests/test_platform_pki_parser.py \
		tests/test_platform_pki_records.py \
		tests/test_platform_pki_recovery_foundation.py \
		tests/test_platform_pki_csr_recovery_foundation.py \
		tests/test_platform_pki_service_transaction_foundation.py \
		tests/test_platform_pki_recovery_semantics.py \
		tests/test_platform_pki_tree_manifests.py \
		tests/test_platform_pki_inventory.py \
		tests/test_platform_pki_subprocesses.py \
		tests/test_platform_pki_paths.py \
		tests/test_platform_pki_filesystem.py \
		tests/test_platform_pki_publication.py \
		tests/test_platform_pki_locks.py \
		tests/test_platform_pki_faults.py

## Run focused managed service transaction model tests
test-platform-pki-service-transaction-foundation:
	python3 -m pytest tests/test_platform_pki_service_transaction_foundation.py

## Run focused Python PKI durable-publication primitive tests
test-platform-pki-publication:
	python3 -m pytest tests/test_platform_pki_publication.py

## Run platform config initializer behavior tests
test-platform-config-init:
	python3 -m pytest tests/test_platform_config_init.py

## Run SSH identity initializer behavior tests
test-platform-ssh-init:
	python3 -m pytest tests/test_platform_ssh_init.py

## Run VM environment collector CLI tests
test-vm-env-collect-cli:
	python3 -m pytest tests/test_vm_env_collect_cli.py

## Run VM collector archive smoke tests in the test container
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

## Run non-public managed service issue orchestration tests
test-pki-service-issue-writer:
	python3 -m pytest --durations=20 tests/pki/test_service_issue_writer.py

## Run non-public managed service writer tests
test-pki-service-writer:
	python3 -m pytest tests/pki/test_service_writer.py

## Run PKI service certificate renewal behavior tests
test-pki-service-renew:
	python3 -m pytest tests/pki/test_service_renew.py

## Run non-public managed service transaction recovery tests
test-pki-service-recover:
	python3 -m pytest tests/pki/test_service_recover.py

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

## Run PKI custody report behavior tests
test-pki-custody-report:
	python3 -m pytest tests/pki/test_custody_report.py

## Run active CA passphrase verification tests
test-pki-ca-passphrase-verify:
	python3 -m pytest tests/pki/test_ca_passphrase_verify.py

## Run atomic PKI Ansible export compatibility and safety tests
test-pki-export:
	python3 -m pytest tests/pki/test_export_ansible_safe_paths.py

## Run immutable certificate-only export tests
test-pki-certificate-export:
	python3 -m pytest tests/pki/test_certificate_export.py

## Run authenticated CSR candidate decision and recovery tests
test-pki-csr-candidate:
	python3 -m pytest tests/pki/test_csr_candidate.py tests/pki/test_csr_finalization_recover.py

## Run PKI inventory value validation tests
test-pki-inventory:
	python3 -m pytest tests/pki/test_inventory_value_validation.py tests/pki/test_inventory_contract.py

## Run PKI inventory installation tests
test-pki-inventory-install:
	python3 -m pytest tests/pki/test_inventory_install.py

## Run host-local CSR trust installation tests
test-pki-csr-trust-install:
	python3 -m pytest tests/pki/test_csr_trust_install.py

## Run authenticated host-local CSR signing and recovery tests
test-pki-csr-signing:
	python3 -m pytest tests/pki/test_csr_signing.py tests/pki/test_csr_signing_recover.py tests/pki/test_csr_recover_cli.py

## Run authoritative generation-aware CA rollover tests
test-pki-ca-rollover: test-python-pki-rollover-parallel

## Run authoritative rollover tests with unified Python recovery
test-pki-ca-rollover-python-recover: export PLATFORM_PKI_TEST_PYTHON_RECOVER = 1
test-pki-ca-rollover-python-recover: test-python-pki-rollover-parallel

## Run authoritative rollover parser contract tests
test-pki-ca-rollover-parser:
	python3 -m pytest -m pki tests/pki/test_ca_rollover_parser.py

## Run ShellCheck for maintained tool scripts
shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { printf '%s\n' 'shellcheck not found; install ShellCheck or skip this target' >&2; exit 1; }
	shellcheck $(addprefix bin/,$(SHELL_TOOLS)) $(LIBS) $(MAINTAINED_SCRIPTS)
