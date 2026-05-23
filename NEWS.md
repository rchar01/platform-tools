# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

No unreleased changes.

## v1.0.0 - 2026-05-23

Initial public release of `platform-tools`.

Highlights:

- Shared operator helpers are now centralized in one repository: SSH identity setup, Rocky VM fact collection, local secret namespace initialization, Proxmox API token bootstrap, and safe single-VM cleanup.
- Local secrets now use the outside-Git namespace `~/.config/platform-infrastructure/` with major directories `infra/` and `config/`.
- The documented Proxmox token path is `~/.config/platform-infrastructure/infra/proxmox.token`.
- SSH config parsing, token output handling, file modes, and VM collector defaults were hardened for safer operator use.
- Downstream ownership of concrete config paths is documented in `docs/handoffs/config-namespace-handoff.md`.
