# Final Bash Source Evidence

This directory contains immutable, test-only extracts from the retired PKI
Bash implementation. The files were relocated byte-for-byte from production
source at commit `94f123d31558018ec4fd0b9426abafcdf2651e3c`; command-specific
cutover commits and complete executable oracles are recorded in
`docs/plans/platform-pki-python-migration.md` and sibling oracle directories.

Only source declarations and command/library fragments still used by contract
tests are retained here. Their paths mirror the former production `bashly/`
and `lib/` layout so historical contract labels remain readable.

These files are not generated, installed, linted as maintained production
code, or loaded by Python PKI commands. Do not edit them. `SHA256SUMS` and the
migration-contract tests enforce the exact retained file set and bytes.
