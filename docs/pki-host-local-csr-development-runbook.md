# Development Host-Local Registry PKI Runbook

The original direct SSH/SFTP design on this page has been superseded. Target
request generation, response intake, transactional Zot activation and recovery,
runner validation, deployment evidence, terminal signer-outcome import, and
status handling are now implemented by `platform-config`.

Use the canonical cross-repository procedure:

- [Host-Local Registry PKI Workflow](https://codeberg.org/rch/platform-config/src/branch/main/docs/registry-host-local-pki-workflow.md)

That runbook covers every implemented phase from prerequisite trust and backup
through request collection, controlled-media approval and signing, certificate
export, activation, evidence export, candidate finalization, authenticated
outcome export/import, terminal status, recovery, and isolated restore
validation.

Signer command and schema details remain canonical in:

- [OpenSSL PKI Helpers](pki-openssl.md)
- [Host-Local PKI CSR Handoff](handoffs/pki-host-local-csr-handoff.md)

`platform-config` implements host-key-pinned direct SSH for exact package
movement across the target boundary. GitLab provides the normal durable online
exchange; protected local custody is the fallback. Controlled media separates
the online transfer station from the offline approver and signer. Transport
success never replaces canonical signatures, frozen trust, or digest pins. The
target leaf private key never leaves the target.
