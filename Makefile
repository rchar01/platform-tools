SHELL := /bin/sh
.DEFAULT_GOAL := help

INSTALL_DIR ?= $(HOME)/.local/bin
SHARE_DIR ?= $(HOME)/.local/share/platform-tools
TOOLS := platform-ssh-init vm-env-collect platform-config-init platform-proxmox-token-init platform-proxmox-vm-cleanup platform-pki-init platform-pki-root-create platform-pki-intermediate-create platform-pki-service-issue platform-pki-service-verify platform-pki-list-expiry
LIBS := lib/platform-pki-common.sh

.PHONY: help install verify shellcheck

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
	@for tool in $(TOOLS); do \
		bash -n "bin/$$tool"; \
	done
	@for lib in $(LIBS); do \
		bash -n "$$lib"; \
	done

## Run ShellCheck for maintained tool scripts
shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { printf '%s\n' 'shellcheck not found; install ShellCheck or skip this target' >&2; exit 1; }
	shellcheck $(addprefix bin/,$(TOOLS)) $(LIBS)
