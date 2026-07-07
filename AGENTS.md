# Agent Notes

## Agent Workflow Expectations

- Read relevant code before editing.
- Prefer minimal changes that match existing patterns.
- Keep `README.md`, `AGENTS.md`, and skill docs current when repository behavior changes.
- If your runtime provides specialized tools or subagents for codebase exploration, use them when the repository structure, ownership boundaries, or relevant files are unclear.
- If your runtime provides specialized tools or subagents for verification, use them for non-trivial test runs, runtime-backed checks, or command-heavy validation.
- If your runtime provides specialized tools or subagents for review, use them after substantial edits to catch regressions, missing updates, or doc/code drift.
- If your runtime provides specialized tools or subagents for research, use them when behavior depends on external tooling or upstream docs.
- Prefer local repository docs, scripts, and configuration first; use web research when local sources are insufficient or freshness matters.
- Summarize any specialist-tool or subagent findings you rely on.
- Do not revert unrelated worktree changes.

## Repository Shape

- This repo is a collection of maintained Bash and Python helper tools in `bin/`; `Makefile` is the source of truth for supported tools and local targets.
- PKI commands share logic in `lib/platform-pki-common.sh` and install templates from `templates/pki/`; keep all three areas aligned when changing PKI behavior.
- `platform-bastion-policy` is a Python helper for public bastion access-policy validation and rendering; real policy data belongs in `platform-private`.
- User-facing behavior is documented in `README.md` and topic docs under `docs/`; update both the command help text and docs when changing flags, defaults, paths, or safety rules.
- `platform-tools` owns reusable bootstrap/operator helpers only. Real secret values and generated PKI state live outside Git under `~/.config/platform-infrastructure/`.

## Verification

- Run `make verify` after tool changes; it runs `bash -n` over maintained Bash files and `python3 -m py_compile` over maintained Python tools.
- Run `make test` after behavior changes; it runs maintained repository tests such as bastion policy rendering checks.
- Run `make shellcheck` when ShellCheck is available; it lint-checks maintained shell tools and libraries.
- There is no repo test suite or CI workflow in this tree. For behavior changes, run focused smoke commands in `/tmp/opencode` or another temporary namespace instead of the default `~/.config/platform-infrastructure/` paths.
- For PKI smoke tests, use `platform-pki-init --namespace <temp-dir>` and pass `--namespace <temp-dir>` to every following PKI command so real CA material is never touched.

## Security And Generated Files

- Never commit generated archives, VM reports, SSH keys, token files, PKI CA material, service private keys, PKI exports, PKI backups, or copied private config.
- `reports/*` is ignored except `reports/.gitkeep`; use `reports/platform-vm-env-collect/` only for local analysis copies.
- PKI passphrase files are plaintext secrets; keep them outside Git, mode `600` or stricter, and prefer temporary secret-manager mounts such as `/run/secrets`.
- PKI backups are encrypted with `age` by default; plain `.tar.gz` backups require the explicit `--allow-plain-backup` flag and still contain secrets.

## Tooling Notes

- `make install` copies scripts to `INSTALL_DIR` and PKI shared assets to `SHARE_DIR`; custom installs commonly use `make install INSTALL_DIR="$PWD/.tools/bin" SHARE_DIR="$PWD/.tools/share/platform-tools"`.
- Installed PKI scripts find shared assets through `PLATFORM_TOOLS_LIB_DIR`, checkout-relative `../lib`, or `PLATFORM_TOOLS_SHARE_DIR`/`~/.local/share/platform-tools`; preserve this lookup behavior when editing wrappers.
- Proxmox helpers can stream themselves over SSH; remote prerequisites are `pveum` for token bootstrap, `qm` for VM cleanup, and remote `jq` only when `platform-proxmox-token-init --write-token-file` parses JSON output.
- The VM collector usually needs `sudo`; `COLLECT_ENV=1` and `INCLUDE_SENSITIVE=1` intentionally create more sensitive reports.

## Release And Commit Notes

- Update `NEWS.md` and `CHANGELOG.md` for release-facing behavior changes; this repo currently records dated releases such as `v1.2.0 - 2026-05-25`.
- Local commit hooks require `gitleaks` for staged secret scanning and a `git-tools` commit-msg validator.
- Commit messages should follow `.gitmessage`: Conventional Commit style, header max 68 characters, subject max 50 characters, imperative mood, no trailing period.
