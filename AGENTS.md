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

- This repo is a collection of maintained Bash and Python helper tools in `bin/`; `Makefile` is the source of truth for supported tools and local targets. Every maintained shell tool is Bashly-backed: source lives under `bashly/<tool>/`, while its generated and committed executable lives under `bin/`.
- Bashly workspaces use the standard colors library and `usage_colors` for TTY-only generated help. Preserve automatic pipe/redirect suppression and nonempty `NO_COLOR` support; this does not apply to application logs.
- PKI commands share logic in `lib/platform-pki-common.sh` and install templates from `templates/pki/`; keep all three areas aligned when changing PKI behavior.
- PKI inventory may set only `key_custody: host-local`; absence means the existing managed-key workflow. Authenticated host-local issue, migration, renewal, signed response publication, replay state, and deterministic signer recovery are available. Signer-side candidate verification, deployment finalization, and explicit Ansible export remain fail closed.
- `platform-pki-csr-trust-install` installs only the reviewed public protocol trust from `platform-private`; preserve exact policy fields, no-options Ed25519 signer validation, source-race checks, atomic whole-directory publication, and the rule that installation itself performs no signing.
- Host-local CSR signing uses strict ordered request and approval records, dedicated OpenSSH signature namespaces, inventory-authoritative profiles, permanently consumed replay records, certificate-only pending candidates, and `state/csr/recovery-journal`. Pre-commit recovery restores exact CA state without reusing the request; post-commit recovery never rolls back or re-signs and resumes exact response publication.
- `platform-pki-custody-report` is an operationally read-only managed-layout audit: preserve identity-checked first-line-only PEM/age inspection, secret-free output, explicit unknown operational controls, and the standard PKI lock boundary.
- `platform-pki-ca-passphrase-verify` is a point-in-time active-generation check: keep passphrases off argv, environment, and output; pass them through a minimal inherited-descriptor boundary; suppress raw OpenSSL diagnostics; match each opened key to its active certificate; and never persist validation receipts.
- `platform-bastion-policy` is a Python helper for public bastion access-policy validation and rendering; real policy data belongs in `platform-private`.
- User-facing behavior is documented in `README.md` and topic docs under `docs/`; update both the command help text and docs when changing flags, defaults, paths, or safety rules.
- `platform-tools` owns reusable bootstrap/operator helpers only. Real secret values and generated PKI state live outside Git under `~/.config/platform-infrastructure/`.

## Verification

- Use `make shell` for interactive development in the rootless Podman container, or `make container-check` to run all maintained checks in a one-shot container. Do not mount host SSH keys, private config, PKI state, or the Podman socket into routine development containers.
- Run `make generate` after changing Bashly source and `make verify-generated` to prove committed executables are deterministic and current. Never edit a Bashly-generated `bin/` file directly.
- Run `make verify` after tool changes; it runs `bash -n` over maintained Bash files and `python3 -m py_compile` over maintained Python tools.
- All maintained tests are pytest-orchestrated. They must preserve real generated commands, external tools, executable fakes, PTYs, inherited descriptors, and SSH transport as subprocess boundaries rather than replacing them with in-process mocks.
- Run focused Make targets or pytest modules while developing. Reserve `make container-check`, which owns one complete `make test` execution in the pinned image, for final acceptance; do not run a separate full `make test` immediately before it.
- Run `make test-python-infrastructure` after changing pytest fixtures or process helpers. Keep subprocesses argv-only with `shell=False`, isolated process groups, bounded descendant cleanup, and shell-style signal statuses. PTY and escaped-descendant supervision requires Linux procfs and pidfds.
- Run `make test-pki-ca-rollover` after changing authoritative rollover scenarios; it uses four bounded pytest workers by default. Use `make test-python-pki-rollover` for explicit serial diagnostics.
- Run `make test-pki-ca-rollover-parser` for the authoritative Python parser contract.
- Run `make test-command-contract` after command inventory or parser changes, and `make test-installed-tools` after installation or shared-asset changes. The latter uses a disposable `.tmp` install and an isolated runtime `PATH`.
- Run `make shellcheck` when ShellCheck is available; it lint-checks maintained shell tools and libraries.
- There is no CI workflow in this tree. For behavior not covered by maintained tests, run focused smoke commands in `/tmp/opencode` or another temporary namespace instead of the default `~/.config/platform-infrastructure/` paths.
- For PKI smoke tests, use `platform-pki-init --namespace <temp-dir>` and pass `--namespace <temp-dir>` to every following PKI command so real CA material is never touched.

## Security And Generated Files

- Never commit generated archives, VM reports, SSH keys, token files, PKI CA material, service private keys, PKI exports, PKI backups, or copied private config.
- `reports/*` is ignored except `reports/.gitkeep`; use `reports/platform-vm-env-collect/` only for local analysis copies.
- PKI passphrase files are plaintext secrets; keep them outside Git, mode `600` or stricter, first-line passphrase length at least 16 characters with non-whitespace content, and prefer temporary secret-manager mounts such as `/run/secrets`.
- PKI rollover preparation requires a fresh generation-layout backup receipt, leaves `state/active-issuer` unchanged, and publishes immutable candidates plus public state under `state/rollovers/`. Root preparation also snapshots the reviewed private `pki/trust-consumers.yml`; deterministic candidate/state tree manifests record metadata and non-secret digests but never private-key or passphrase content. Keep pre-created child destinations, immutable write-ahead transaction manifests, identity-checked superseded/final manifest cleanup, full staged-source identities, backup-session rollback, and receipt-bound terminal unlink aligned; activation and later lifecycle transitions remain unavailable.
- PKI backups are encrypted with `age` by default; plain `.tar.gz` backups require the explicit `--allow-plain-backup` flag and still contain secrets.
- PKI operations use persistent shared lock files under `pki/locks/`. Acquire lifecycle before root, intermediate, inventory, and export locks as needed, release in reverse order, and hold locks across protected reads, mutations, and publication. After locking, normal commands must reject unresolved migration or rollover journals before reading operational snapshots.
- Legacy PKI state may prepare missing private control directories before locking, but only inventory installation, protected backup, and rollover status/migration may proceed. Under the full migration lock matrix, migration may also prepare missing empty private authority destination parents from older initializers and must revalidate the legacy layout before receipt-bound state checks or transaction creation. Normal CA and service commands must reject legacy or mixed authority layouts before operational reads or mutations.
- Service signing must reject OpenSSL include/global directives and signing paths outside staged CA state; snapshot validated publication destinations under lock and recheck identity immediately before each replacement.

## Tooling Notes

- `Containerfile.dev` uses a digest-pinned Debian 13 Ruby base, an immutable Debian snapshot with exact direct package versions, checksum-verified ShellCheck/shfmt binaries for `amd64` and `arm64`, and the locked Bashly bundle in `Gemfile.lock`. Refresh these inputs together and verify with a reviewed `podman build --no-cache -f Containerfile.dev .`.
- `make install` copies scripts to `INSTALL_DIR` and PKI shared assets to `SHARE_DIR`; custom installs commonly use `make install INSTALL_DIR="$PWD/.tools/bin" SHARE_DIR="$PWD/.tools/share/platform-tools"`.
- Installed PKI scripts find shared assets through `PLATFORM_TOOLS_LIB_DIR`, checkout-relative `../lib`, or `PLATFORM_TOOLS_SHARE_DIR`/`~/.local/share/platform-tools`; preserve this lookup behavior when editing wrappers.
- Proxmox helpers can stream themselves over SSH; remote prerequisites are `pveum` for token bootstrap, `qm` for VM cleanup, and remote `jq` only when `platform-proxmox-token-init --write-token-file` parses JSON output.
- `platform-proxmox-vm-cleanup` requires an interactive TTY and exact VMID confirmation unless `--yes` is supplied, rechecks exact VM identity/state before mutation, and authorizes streamed destruction with owner-only, bounded-lifetime state persisted on the Proxmox host; bearer nonces travel through framed stdin and protected FD 3, never SSH or child argv. Run `make test-proxmox-vm-cleanup` for fake-backed local and self-streamed SSH coverage.
- `platform-proxmox-vm-snapshot` uses generated create/list/rollback/delete subcommands, targets single-node Proxmox VE 9, and requires remote `pvesh`, `jq`, and Linux procfs at `/proc`, plus `qm` for mutations and local `jq` with `--ssh`; private action manifests are consumed before use and their descriptor is closed before operational children run. Create, rollback, and delete require a TTY unless `--yes` is supplied. Run `make test-proxmox-vm-snapshot` for fake-backed behavior checks.
- Real snapshot create, rollback, or deletion tests require explicit authorization and a disposable development VM. Keep environment mutations gated until `platform-infra` tags are reconciled and a dry-run target set is verified manually.
- The VM collector usually needs `sudo`; `COLLECT_ENV=1` and `INCLUDE_SENSITIVE=1` intentionally create more sensitive reports.

## Release And Commit Notes

- Update `NEWS.md` and `CHANGELOG.md` for release-facing behavior changes; this repo currently records dated releases such as `v1.2.0 - 2026-05-25`.
- Local commit hooks require `gitleaks` for staged secret scanning and a `git-tools` commit-msg validator.
- Commit messages should follow `.gitmessage`: Conventional Commit style, header max 68 characters, subject max 50 characters, imperative mood, no trailing period.
