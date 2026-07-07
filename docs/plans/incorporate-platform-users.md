# Plan: Incorporate platform-users Into platform-tools

## Goal

Move the public bastion access-policy validation and rendering workflow from `platform-users` into `platform-tools` as maintained helper tooling.

## Scope

- Add a `platform-bastion-policy` command to `platform-tools`.
- Port public examples, schema documentation, and render tests.
- Update `platform-tools` verification to handle Bash and Python helpers.
- Update cross-repository docs that describe the bastion policy flow.
- Deprecate `platform-users` after the replacement command is available.

## Non-Goals

- Do not move real access policies, kubeconfigs, tokens, private keys, or environment-specific values into public repositories.
- Do not make `platform-k8s-bastion` responsible for rendering or applying policy.
- Do not make `platform-tools` apply host files or Kubernetes resources.
- Do not preserve old `platform-users` import internals unless compatibility wrappers are explicitly needed later.

## Current Context

- `platform-users` currently contains one shared Python module, three thin wrapper scripts, public examples, schema docs, and shell tests.
- `platform-users/scripts/__pycache__/bastion_policy.cpython-313.pyc` is tracked and must be removed during deprecation.
- `platform-tools` currently documents itself as Bash helper tooling, so the repo contract must expand to Bash and Python helper tools.
- `platform-config` consumes a final rendered `k8s_bastion_policy_src`; rendering remains outside Ansible apply logic.
- `platform-k8s-bastion` owns runtime behavior and consumes `/etc/bastion/access-policy.yaml`.

## Assumptions

- The migrated command should be a single self-contained Python CLI named `platform-bastion-policy`.
- `PyYAML` is an optional dependency required only for bastion policy tooling.
- Cross-repository changes should be committed separately per repository.

## Open Questions

- [ ] Decide later whether old `platform-users/scripts/...` compatibility wrappers are needed for external users.
- [ ] Decide later whether to archive `platform-users` after publishing its deprecation notice.

## Phase 1: Record Plan

Goal: Create a durable plan file that tracks implementation and verification evidence.

Tasks:

- [x] Create this plan at `docs/plans/incorporate-platform-users.md`.
- [x] Commit the plan before code changes.

Validation gate:

- [x] `git status --short` in `platform-tools` shows only the staged plan before commit.

## Phase 2: Add Tooling To platform-tools

Goal: Port the policy validator/renderer into `platform-tools` with tests and install support.

Tasks:

- [x] Add `bin/platform-bastion-policy` with `validate`, `render-host`, and `render-csr-configmap` subcommands.
- [x] Add public examples under `examples/bastion-policy/`.
- [x] Add render tests under `tests/bastion-policy/`.
- [x] Update `Makefile` to install the Python helper, syntax-check it, and run tests.
- [x] Update `.gitignore` to exclude Python caches.

Validation gate:

- [x] Run `make verify` in `platform-tools`.
- [x] Run `make test` in `platform-tools`.
- [x] Run `make shellcheck` in `platform-tools`.
- [x] Run `gitleaks detect --source . --verbose` in `platform-tools`.

## Phase 3: Document platform-tools Migration

Goal: Make the new command discoverable and update repository guidance for mixed Bash/Python helpers.

Tasks:

- [x] Update `README.md` tool list, requirements, and quick usage.
- [x] Add `docs/bastion-policy.md` with schema, ownership, examples, and rendering flow.
- [x] Update `docs/README.md` to link the new documentation.
- [x] Update `AGENTS.md` for maintained Bash and Python helper tools.
- [x] Update `NEWS.md` and `CHANGELOG.md` under `Unreleased`.

Validation gate:

- [x] Re-run `make verify`, `make test`, `make shellcheck`, and `gitleaks detect --source . --verbose` in `platform-tools`.

## Phase 4: Update Consuming Repository Docs

Goal: Point consumers at the new `platform-tools` command without moving ownership boundaries.

Tasks:

- [x] Update `platform-config/docs/k8s-bastion.md` to mention rendering with `platform-bastion-policy`.
- [x] Update `platform-config/docs/private-workflow.md` with validate/render examples.
- [x] Update `platform-k8s-bastion` docs to mention optional external policy tooling while preserving runtime-only ownership.

Validation gate:

- [x] Review diffs carefully because these repositories already had unrelated local changes.
- [x] Run each repository's available lightweight verification target if one exists.

## Phase 5: Deprecate platform-users

Goal: Remove the bad cached Python artifact and redirect users to the new command.

Tasks:

- [x] Remove tracked `scripts/__pycache__/bastion_policy.cpython-313.pyc`.
- [x] Add `__pycache__/` and `*.pyc` to `.gitignore`.
- [x] Update `README.md` with a deprecation notice pointing to `platform-tools`.
- [x] Update docs if needed to avoid presenting `platform-users` as the primary workflow.

Validation gate:

- [x] Run `make test` in `platform-users` if the legacy tests remain runnable.
- [x] Run `gitleaks detect --source . --verbose` in `platform-users`.

## Phase 6: Final Verification

Goal: Confirm all affected repositories are consistent and public-safe.

Tasks:

- [ ] Confirm each repository has only intended changes.
- [ ] Confirm commits were created per phase/repository.
- [ ] Summarize commit hashes and any skipped validation.

## Progress Log

| Date | Update | Evidence |
| --- | --- | --- |
| 2026-07-07 | Plan created. | User requested phase-by-phase implementation with commits and tracked progress. |
| 2026-07-07 | Phase 1 committed. | Commit `ca67e0d` added `docs/plans/incorporate-platform-users.md`. |
| 2026-07-07 | Phase 2 tooling port completed. | Added `bin/platform-bastion-policy`, examples, tests, Makefile support, and Python cache ignores; `make verify`, `make test`, `make shellcheck`, and `gitleaks detect --source . --verbose` passed. |
| 2026-07-07 | Phase 3 documentation completed. | Updated `README.md`, `AGENTS.md`, `docs/README.md`, `docs/bastion-policy.md`, `NEWS.md`, and `CHANGELOG.md`; `make verify`, `make test`, `make shellcheck`, and `gitleaks detect --source . --verbose` passed. |
| 2026-07-07 | Phase 4 consuming docs completed. | `platform-config` commit `68abd4c` updated bastion docs; `platform-k8s-bastion` commit `3a3746f` updated runtime boundary docs. `platform-k8s-bastion` `make test` and staged `gitleaks protect --staged --verbose` passed. |
| 2026-07-07 | Phase 5 `platform-users` deprecation completed. | `platform-users` commit `414cd0a` added `.gitignore`, removed tracked `.pyc`, and pointed users at `platform-bastion-policy`; `make test`, `git diff --check`, and `gitleaks detect --source . --verbose` passed. |

## Decision Log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-07-07 | Use one `platform-bastion-policy` command. | Existing `platform-users` wrappers only dispatch into one shared module, so one CLI reduces install and import-path complexity. |
| 2026-07-07 | Keep applying rendered resources out of `platform-tools`. | `platform-config` owns host/Kubernetes apply workflows and `platform-k8s-bastion` owns runtime behavior. |
