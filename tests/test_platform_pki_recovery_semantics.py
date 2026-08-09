from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from src.platform_pki import ca_rollover_recovery as recovery
from src.platform_pki.filesystem import FileIdentity
from src.platform_pki.ca_rollover_recovery import (
    IntermediateBootstrapRecoveryRecord,
    LegacyMigrationRecoveryRecord,
    PreparationTerminalOutcome,
    RecoveryAction,
    RecoveryIdentityPlaceholder,
    RecoveryRecordError,
    RootBootstrapRecoveryRecord,
    RolloverPrepareRecoveryRecord,
    parse_preparation_terminal_marker,
    parse_preparation_terminal_receipt,
    parse_recovery_semantics,
    validate_preparation_terminal_records,
    validate_recovery_action,
)
from src.platform_pki.persisted_identity import IdentitySentinel, parse_file_identity


PKI_DIR = "/srv/platform/pki"
DIRECTORY_IDENTITY = "1:2:1000:700:directory"
FILE_IDENTITY = (
    "1:3:1000:600:1:1:2026-08-09 12:00:00.000000000 +0000:"
    "2026-08-09 12:00:01.000000000 +0000:regular file"
)
OBJECT_IDENTITY = "1:4:1000:600:1:1:regular file"
DIGEST = "0" * 64
FINGERPRINT = "A" * 64


def _payload(fields: tuple[str, ...], values: dict[str, str]) -> bytes:
    return b"".join(f"{field}={values[field]}\n".encode() for field in fields)


def _root_values() -> dict[str, str]:
    transaction = "root-bootstrap-20260809-120000-10"
    values = {field: "none" for field in recovery.ROOT_BOOTSTRAP_WRITER_FIELDS}
    values.update(
        schema="3",
        operation="root-bootstrap",
        transaction=transaction,
        phase="prepared",
        generation="g2",
        authority_dir=f"{PKI_DIR}/authorities/roots/g2",
        authority_identity="none",
        stage_dir="none",
        stage_identity="none",
        transaction_dir=f"{PKI_DIR}/state/rollover/{transaction}",
        transaction_identity=DIRECTORY_IDENTITY,
        reservation=f"{PKI_DIR}/state/generation-reservations/g2",
        reservation_identity="absent",
        reservation_reserved_identity=OBJECT_IDENTITY,
        reservation_consumed_identity="absent",
        reservation_abandoned_identity=OBJECT_IDENTITY,
        bootstrap_identity="absent",
        recovery_action="none",
        recovery_step="none",
        committed="false",
    )
    return values


def _intermediate_values() -> dict[str, str]:
    transaction = "intermediate-bootstrap-20260809-120000-11"
    values = {
        field: "pending"
        if field in recovery.INTERMEDIATE_BOOTSTRAP_DB_FIELDS
        else "none"
        for field in recovery.INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS
    }
    values.update(
        schema="3",
        operation="intermediate-bootstrap",
        transaction=transaction,
        phase="prepared",
        root_generation="g1",
        intermediate_generation="g1-i2",
        root_dir=f"{PKI_DIR}/authorities/roots/g1",
        intermediate_dir=f"{PKI_DIR}/authorities/intermediates/g1-i2",
        intermediate_identity="none",
        stage_dir="none",
        stage_identity="none",
        root_stage="none",
        root_stage_identity="none",
        transaction_dir=f"{PKI_DIR}/state/rollover/{transaction}",
        transaction_identity=DIRECTORY_IDENTITY,
        bootstrap_fingerprint="none",
        issued_serial="none",
        reservation=f"{PKI_DIR}/state/generation-reservations/g1-i2",
        reservation_identity="absent",
        reservation_reserved_identity=OBJECT_IDENTITY,
        reservation_consumed_identity="absent",
        reservation_abandoned_identity=OBJECT_IDENTITY,
        active_identity="absent",
        bootstrap_identity="absent",
        bootstrap_rollback_identity=OBJECT_IDENTITY,
        root_mutated="false",
        recovery_action="none",
        recovery_step="none",
        committed="false",
    )
    return values


def _legacy_values(*, checkpoint: bool = False) -> dict[str, str]:
    fields = (
        recovery.LEGACY_MIGRATION_CHECKPOINT_FIELDS
        if checkpoint
        else recovery.LEGACY_MIGRATION_WRITER_FIELDS
    )
    transaction = "migrate-20260809-120000-12"
    transaction_dir = f"{PKI_DIR}/state/rollover/{transaction}"
    values = {field: "none" for field in fields}
    values.update(
        schema="2",
        operation="legacy-migrate",
        transaction=transaction,
        phase="pre-mutation",
        legacy_root=f"{PKI_DIR}/root-ca",
        legacy_intermediate=f"{PKI_DIR}/intermediate-ca",
        new_root=f"{PKI_DIR}/authorities/roots/g1",
        new_intermediate=f"{PKI_DIR}/authorities/intermediates/g1-i1",
        root_source_identity="1:20",
        intermediate_source_identity="1:21",
        root_sha256=FINGERPRINT,
        intermediate_sha256=FINGERPRINT,
        transaction_dir=transaction_dir,
        transaction_identity=DIRECTORY_IDENTITY,
        provenance_stage=f"{PKI_DIR}/legacy/.{transaction}.publish",
        provenance_dir=f"{PKI_DIR}/legacy/{transaction}",
        provenance_identity=DIRECTORY_IDENTITY,
        provenance_manifest=(
            f"{PKI_DIR}/legacy/.{transaction}.publish/provenance-manifest"
        ),
        provenance_manifest_identity=FILE_IDENTITY,
        provenance_manifest_sha256=DIGEST,
        receipt_identity=FILE_IDENTITY,
        services_sha256=DIGEST,
        services_identity=FILE_IDENTITY,
        backup_receipt="/var/backups/pki.receipt",
        private_repo="/srv/platform-private",
        backup_session=f"{PKI_DIR}/state/rollover/backup-session-{'a' * 32}",
        backup_session_original_identity="absent",
        backup_session_published_identity=OBJECT_IDENTITY,
        root_reservation=f"{PKI_DIR}/state/generation-reservations/g1",
        intermediate_reservation=(
            f"{PKI_DIR}/state/generation-reservations/g1-i1"
        ),
        issuer_ledger=f"{transaction_dir}/issuer-identities",
        issuer_ledger_identity=FILE_IDENTITY,
        issuer_ledger_sha256=DIGEST,
        quarantine_ledger=f"{transaction_dir}/quarantine-identities",
        quarantine_ledger_identity=FILE_IDENTITY,
        quarantine_ledger_sha256=DIGEST,
        active_manifest=f"{PKI_DIR}/state/active-issuer",
        committed="false",
    )
    for prefix in ("root_reservation", "intermediate_reservation"):
        values[f"{prefix}_original_identity"] = "absent"
        values[f"{prefix}_reserved_identity"] = OBJECT_IDENTITY
        values[f"{prefix}_consumed_identity"] = OBJECT_IDENTITY
        values[f"{prefix}_rollback_identity"] = OBJECT_IDENTITY
    for prefix in ("root_config", "intermediate_config"):
        values[f"{prefix}_original_identity"] = OBJECT_IDENTITY
        values[f"{prefix}_published_identity"] = OBJECT_IDENTITY
        values[f"{prefix}_rollback_identity"] = OBJECT_IDENTITY
        values[f"{prefix}_backup_identity"] = OBJECT_IDENTITY
    values["active_original_identity"] = "absent"
    values["active_published_identity"] = OBJECT_IDENTITY
    if checkpoint:
        values["recovery_action"] = "resume"
        values["recovery_step"] = "resume-root-rename-pending"
    return values


def _rollover_values(kind: str = "root") -> dict[str, str]:
    transaction = f"prepare-{kind}-20260809-120000-13"
    candidate_root = "g2" if kind == "root" else "g1"
    candidate_intermediate = f"{candidate_root}-i2"
    transaction_dir = f"{PKI_DIR}/state/rollover/{transaction}"
    values = {field: "none" for field in recovery.ROLLOVER_PREPARE_DECLARED_FIELDS}
    values.update(
        schema="5",
        operation="rollover-prepare",
        transaction=transaction,
        type=kind,
        phase="planned",
        committed="false",
        recovery_action="none",
        recovery_step="none",
        terminal_outcome="none",
        active_root="g1",
        active_intermediate="g1-i1",
        active_manifest=f"{PKI_DIR}/state/active-issuer",
        active_identity=FILE_IDENTITY,
        candidate_root=candidate_root,
        candidate_intermediate=candidate_intermediate,
        candidate_root_dir=f"{PKI_DIR}/authorities/roots/{candidate_root}",
        candidate_intermediate_dir=(
            f"{PKI_DIR}/authorities/intermediates/{candidate_intermediate}"
        ),
        transaction_dir=transaction_dir,
        transaction_identity="none",
        stage_dir="none",
        stage_identity="none",
        root_stage="none",
        root_stage_identity="none",
        root_stage_private_identity="none",
        root_stage_key_identity="none",
        intermediate_stage_identity="none",
        intermediate_stage_private_identity="none",
        long_stage=f"{transaction_dir}/rollover-state",
        long_dir=f"{PKI_DIR}/state/rollovers/{transaction}",
        long_identity="none",
        pointer=f"{PKI_DIR}/state/active-rollover",
        pointer_identity="absent",
        backup_receipt="/var/backups/pki.receipt",
        receipt_identity=FILE_IDENTITY,
        backup_session=f"{PKI_DIR}/state/rollover/backup-session-{'b' * 32}",
        backup_session_original_identity="absent",
        backup_session_identity="absent",
        root_reservation=(
            f"{PKI_DIR}/state/generation-reservations/{candidate_root}"
        ),
        intermediate_reservation=(
            f"{PKI_DIR}/state/generation-reservations/{candidate_intermediate}"
        ),
        root_mutated="false",
        transaction_tree_manifest_sequence="0",
    )
    for prefix in ("root_reservation", "intermediate_reservation"):
        for suffix in ("reserved", "consumed", "abandoned"):
            values[f"{prefix}_{suffix}_identity"] = "absent"
    for key in recovery.ROOT_DB_KEYS:
        values[f"root_{key}_pre_identity"] = "pending"
        values[f"root_{key}_post_identity"] = "pending"
        values[f"root_{key}_backup_identity"] = "absent"
        values[f"root_{key}_rollback_identity"] = "absent"
        values[f"root_{key}_source_identity"] = "absent"
        values[f"signing_{key}_pre_identity"] = "none"
        values[f"signing_{key}_partial_identity"] = "none"
        values[f"signing_{key}_was_absent"] = "false"
    if kind == "root":
        values["trust_source"] = "/srv/platform-private/pki/trust-consumers.yml"
        values["trust_source_identity"] = FILE_IDENTITY
        values["trust_snapshot_sha256"] = DIGEST
    else:
        values["trust_source"] = "none"
        values["trust_source_identity"] = "none"
        values["trust_snapshot_sha256"] = "none"
    return values


def test_root_bootstrap_writer_and_sorted_recovery_are_semantically_typed() -> None:
    values = _root_values()
    for fields in (
        recovery.ROOT_BOOTSTRAP_WRITER_FIELDS,
        recovery.ROOT_BOOTSTRAP_RECOVERY_FIELDS,
    ):
        record = parse_recovery_semantics(
            _payload(fields, values), pki_dir=PKI_DIR, action="rollback"
        )
        assert isinstance(record, RootBootstrapRecoveryRecord)
        assert record.generation == "g2"
        transaction_path = record.path("transaction_dir")
        assert transaction_path is not None
        assert transaction_path.endswith(record["transaction"])
        assert record.identity("stage_identity") is IdentitySentinel.NONE
        with pytest.raises(FrozenInstanceError):
            record.generation = "g3"  # type: ignore[misc]


def test_bootstrap_semantics_reject_path_escape_and_malformed_identity() -> None:
    values = _root_values()
    values["authority_dir"] = "/tmp/g2"
    with pytest.raises(RecoveryRecordError, match="authority_dir"):
        parse_recovery_semantics(
            _payload(recovery.ROOT_BOOTSTRAP_WRITER_FIELDS, values),
            pki_dir=PKI_DIR,
        )
    values = _root_values()
    values["transaction_identity"] = "1:2"
    with pytest.raises(RecoveryRecordError, match="transaction_identity"):
        parse_recovery_semantics(
            _payload(recovery.ROOT_BOOTSTRAP_WRITER_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_intermediate_cleanup_resume_preserves_final_bash_rollback_quirk() -> None:
    values = _intermediate_values()
    values.update(
        phase="recovering",
        recovery_action="rollback",
        recovery_step="cleanup-pending",
    )
    record = parse_recovery_semantics(
        _payload(recovery.INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS, values),
        pki_dir=PKI_DIR,
        action="resume",
    )
    assert isinstance(record, IntermediateBootstrapRecoveryRecord)
    assert record.recovery_action is RecoveryAction.ROLLBACK
    assert validate_recovery_action(record, RecoveryAction.RESUME) is RecoveryAction.RESUME
    values["recovery_step"] = "rollback-active-pending"
    with pytest.raises(RecoveryRecordError, match="limited to cleanup"):
        parse_recovery_semantics(
            _payload(recovery.INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS, values),
            pki_dir=PKI_DIR,
            action="resume",
        )
    values["recovery_step"] = "cleanup-pending"
    values["recovery_action"] = "resume"
    with pytest.raises(RecoveryRecordError, match="persists rollback"):
        parse_recovery_semantics(
            _payload(recovery.INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_intermediate_mutation_requires_resolved_database_identities() -> None:
    values = _intermediate_values()
    values["root_mutated"] = "true"
    with pytest.raises(RecoveryRecordError, match="pending root identity"):
        parse_recovery_semantics(
            _payload(recovery.INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_legacy_writer_and_checkpoint_validate_exact_paths_and_source_identity() -> None:
    writer = parse_recovery_semantics(
        _payload(
            recovery.LEGACY_MIGRATION_WRITER_FIELDS, _legacy_values()
        ),
        pki_dir=PKI_DIR,
        action="rollback",
    )
    checkpoint = parse_recovery_semantics(
        _payload(
            recovery.LEGACY_MIGRATION_CHECKPOINT_FIELDS,
            _legacy_values(checkpoint=True),
        ),
        pki_dir=PKI_DIR,
        action="resume",
    )
    assert isinstance(writer, LegacyMigrationRecoveryRecord)
    assert isinstance(checkpoint, LegacyMigrationRecoveryRecord)
    assert writer.root_source_identity == (1, 20)
    assert checkpoint.recovery_action is RecoveryAction.RESUME

    changed = _legacy_values()
    changed["provenance_manifest"] = f"{PKI_DIR}/legacy/provenance-manifest"
    with pytest.raises(RecoveryRecordError, match="provenance_manifest"):
        parse_recovery_semantics(
            _payload(recovery.LEGACY_MIGRATION_WRITER_FIELDS, changed),
            pki_dir=PKI_DIR,
        )


def test_rollover_declared_and_cumulative_runtime_shapes_are_typed() -> None:
    root_values = _rollover_values()
    root = parse_recovery_semantics(
        _payload(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS, root_values),
        pki_dir=PKI_DIR,
        action="rollback",
    )
    assert isinstance(root, RolloverPrepareRecoveryRecord)
    assert len(root) == 206
    assert root.runtime_identity_fields == ()
    assert root.identity("root_index_pre_identity") is RecoveryIdentityPlaceholder.PENDING

    intermediate_values = _rollover_values("intermediate")
    runtime_field = "root_stage_cert_identity"
    intermediate_values["root_stage_cert_pre_identity"] = FILE_IDENTITY
    intermediate_values[runtime_field] = FILE_IDENTITY
    fields = tuple(sorted((*recovery.ROLLOVER_PREPARE_DECLARED_FIELDS, runtime_field)))
    intermediate = parse_recovery_semantics(
        _payload(fields, intermediate_values), pki_dir=PKI_DIR
    )
    assert isinstance(intermediate, RolloverPrepareRecoveryRecord)
    assert len(intermediate) == 207
    assert intermediate.runtime_identity_fields == (runtime_field,)


def test_rollover_rejects_non_cumulative_runtime_and_manifest_mismatch() -> None:
    values = _rollover_values("intermediate")
    runtime_field = "root_stage_index_identity"
    values["root_stage_index_pre_identity"] = FILE_IDENTITY
    values[runtime_field] = FILE_IDENTITY
    fields = tuple(sorted((*recovery.ROLLOVER_PREPARE_DECLARED_FIELDS, runtime_field)))
    with pytest.raises(RecoveryRecordError, match="not cumulative"):
        parse_recovery_semantics(_payload(fields, values), pki_dir=PKI_DIR)

    values = _rollover_values()
    values["transaction_tree_manifest_sequence"] = "1"
    with pytest.raises(RecoveryRecordError, match="sequence has no manifest"):
        parse_recovery_semantics(
            _payload(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_committed_rollover_binds_terminal_outcome_action_and_phase() -> None:
    values = _rollover_values()
    values.update(
        committed="true",
        phase="terminal-cleanup",
        recovery_action="resume",
        recovery_step="terminal-journal-pending",
        terminal_outcome="resumed",
    )
    record = parse_recovery_semantics(
        _payload(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS, values),
        pki_dir=PKI_DIR,
        action="resume",
    )
    assert isinstance(record, RolloverPrepareRecoveryRecord)
    assert record.terminal_outcome is PreparationTerminalOutcome.RESUMED
    with pytest.raises(RecoveryRecordError, match="does not match"):
        validate_recovery_action(record, "rollback")

    values["recovery_action"] = "rollback"
    with pytest.raises(RecoveryRecordError, match="outcome and recovery action"):
        parse_recovery_semantics(
            _payload(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_terminal_marker_and_receipt_are_typed_and_bound() -> None:
    transaction = "prepare-root-20260809-120000-13"
    marker = parse_preparation_terminal_marker(
        (
            f"transaction={transaction}\n"
            "operation=rollover-prepare\n"
            "terminal_outcome=rolled-back\n"
        ).encode()
    )
    receipt = parse_preparation_terminal_receipt(
        (
            f"transaction={transaction}\n"
            "operation=rollover-prepare\n"
            "terminal_outcome=rolled-back\n"
            f"journal_identity={FILE_IDENTITY}\n"
            f"marker_identity={FILE_IDENTITY}\n"
        ).encode()
    )
    assert (
        validate_preparation_terminal_records(
            marker,
            receipt,
            marker_identity=receipt.marker_identity,
            journal_identity=receipt.journal_identity,
            transaction=transaction,
            action="rollback",
        )
        is PreparationTerminalOutcome.ROLLED_BACK
    )
    with pytest.raises(RecoveryRecordError, match="does not match"):
        validate_preparation_terminal_records(
            marker,
            receipt,
            marker_identity=receipt.marker_identity,
            action="resume",
        )

    changed_identity = parse_file_identity(FILE_IDENTITY.replace("1:3:", "1:30:", 1))
    assert isinstance(changed_identity, FileIdentity)
    with pytest.raises(RecoveryRecordError, match="marker identity"):
        validate_preparation_terminal_records(
            marker,
            receipt,
            marker_identity=changed_identity,
        )


def test_terminal_receipt_accepts_writer_and_c_sorted_field_orders() -> None:
    values = {
        "transaction": "prepare-root-20260809-120000-13",
        "operation": "rollover-prepare",
        "terminal_outcome": "resumed",
        "journal_identity": FILE_IDENTITY,
        "marker_identity": FILE_IDENTITY,
    }
    writer = parse_preparation_terminal_receipt(
        _payload(
            (
                "transaction",
                "operation",
                "terminal_outcome",
                "journal_identity",
                "marker_identity",
            ),
            values,
        )
    )
    sorted_record = parse_preparation_terminal_receipt(
        _payload(tuple(sorted(values)), values)
    )
    assert writer.transaction == sorted_record.transaction


def test_terminal_receipt_rejects_altered_field_set() -> None:
    values = {
        "transaction": "prepare-root-20260809-120000-13",
        "operation": "rollover-prepare",
        "terminal_outcome": "resumed",
        "journal_identity": FILE_IDENTITY,
        "extra": "value",
    }
    with pytest.raises(RecoveryRecordError, match="fields are invalid"):
        parse_preparation_terminal_receipt(_payload(tuple(values), values))
