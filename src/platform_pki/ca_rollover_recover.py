"""Operational recovery for final-Bash CA rollover transactions."""

from __future__ import annotations

import hashlib
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn

from .ca_rollover_recovery import (
    MAX_RECOVERY_RECORD_BYTES,
    ROOT_DB_KEYS,
    IntermediateBootstrapRecoveryRecord,
    LegacyMigrationRecoveryRecord,
    PreparationTerminalOutcome,
    RecoveryAction,
    RecoveryIdentityPlaceholder,
    RecoveryRecordError,
    RootBootstrapRecoveryRecord,
    RolloverPreparationType,
    RolloverPrepareRecoveryRecord,
    TypedRecoveryRecord,
    parse_preparation_terminal_marker,
    parse_preparation_terminal_receipt,
    parse_recovery_semantics,
    serialize_typed_recovery_rewrite,
    validate_preparation_terminal_records,
)
from .errors import ApplicationError
from .faults import DEFAULT_FAULT_HOOK, FaultHook, PauseHook
from .filesystem import (
    ABSENT,
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FileObjectState,
    FilePolicy,
    FilesystemAbsentError,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_at,
)
from .operational import (
    acquire_operational_locks,
    prepare_control_state,
    require_pki_directory,
    resolve_paths,
)
from .parser import ParseResult
from .persisted_identity import (
    IdentitySentinel,
    PersistedIdentityError,
    parse_file_object_state,
    serialize_file_identity,
)
from .publication import (
    PublicationAmbiguousError,
    PublicationError,
    atomic_write_bytes,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    replace_exact,
    unlink_exact,
)
from .tree_manifests import (
    TreeManifestError,
    remove_manifested_tree,
    validate_provenance_manifest,
    validate_tree_manifest,
)


_TRANSACTION = re.compile(
    r"(?:migrate|root-bootstrap|intermediate-bootstrap|prepare-root|"
    r"prepare-intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+",
    re.ASCII,
)
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_QUARANTINE_NAMES = frozenset(
    (
        "pki.env",
        "openssl-root.cnf.tpl",
        "openssl-intermediate.cnf.tpl",
        "openssl-service.cnf.tpl",
    )
)
_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _matches(
    actual: FileIdentity | object,
    expected: FileIdentity | FileObjectState | DirectoryIdentity | IdentitySentinel,
) -> bool:
    if expected is IdentitySentinel.ABSENT:
        return actual is ABSENT
    if actual is ABSENT or not isinstance(actual, FileIdentity):
        return False
    if isinstance(expected, FileIdentity):
        return actual == expected
    if isinstance(expected, FileObjectState):
        return actual.state == expected
    if isinstance(expected, DirectoryIdentity):
        return actual.kind == "directory" and actual.directory == expected
    return False


def _relocated_state(
    expected: FileIdentity | FileObjectState,
) -> FileObjectState:
    return expected.state if isinstance(expected, FileIdentity) else expected


def _publication_identity(result: object) -> FileIdentity:
    identity = getattr(result, "destination_identity", None)
    if identity is None:
        identity = getattr(result, "identity", None)
    if not isinstance(identity, FileIdentity):
        raise TypeError("publication result has no destination identity")
    return identity


def _actual(path: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemAbsentError:
        return ABSENT
    except FilesystemError:
        _die("Recovery filesystem state could not be inspected")


def _require_state(
    path: str,
    expected: FileIdentity | FileObjectState | DirectoryIdentity | IdentitySentinel,
    label: str,
) -> FileIdentity | object:
    current = _actual(path)
    if not _matches(current, expected):
        _die(f"{label} identity changed: {path}")
    return current


def _allowed_state(
    path: str,
    label: str,
    *expected: FileIdentity | FileObjectState | DirectoryIdentity | IdentitySentinel,
) -> FileIdentity | object:
    current = _actual(path)
    if not any(_matches(current, value) for value in expected):
        _die(f"{label} is not in a journaled identity state")
    return current


def _opened_file(
    path: str,
    expected: FileIdentity | FileObjectState | None = None,
    *,
    max_bytes: int = _MAX_EVIDENCE_BYTES,
) -> OpenedFile:
    return OpenedFile(
        path,
        policy=FilePolicy(owner=os.geteuid(), links=1, max_size=max_bytes),
        expected_identity=expected,
    )


def _verify_file(
    path: str,
    expected: FileIdentity | FileObjectState,
    digest: str | None,
    label: str,
    *,
    max_bytes: int = _MAX_EVIDENCE_BYTES,
    changed_message: str | None = None,
) -> bytes:
    try:
        with _opened_file(path, expected, max_bytes=max_bytes) as opened:
            data = opened.read(max_bytes)
    except FilesystemError:
        _die(changed_message or f"{label} identity changed: {path}")
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        _die(changed_message or f"{label} digest changed")
    return data


def _parent(path: str) -> tuple[OpenedDirectory, str]:
    parent_path, name = os.path.split(path)
    try:
        return OpenedDirectory(parent_path), name
    except FilesystemError:
        _die("Recovery publication parent is unsafe")


def _publish_file(
    source: str,
    destination: str,
    expected_source: FileIdentity | FileObjectState,
    *expected_destinations: FileIdentity | FileObjectState | IdentitySentinel,
) -> FileIdentity:
    if not expected_destinations:
        raise TypeError("at least one expected destination state is required")
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
    try:
        try:
            with source_parent.open_file(
                source_name,
                policy=FilePolicy(owner=os.geteuid(), links=1),
                expected_identity=expected_source,
            ) as opened:
                source_identity = opened.identity
            current = destination_parent.identity_at(destination_name)
            if not any(_matches(current, expected) for expected in expected_destinations):
                _die("Recovery publication destination is not in a journaled identity state")
            if current is ABSENT:
                result = publish_no_clobber(
                    source_parent,
                    source_name,
                    source_identity,
                    destination_parent,
                    destination_name,
                )
                return _publication_identity(result)
            if not isinstance(current, FileIdentity) or current.kind != "regular":
                _die("Recovery publication destination is unsafe")
            result = replace_exact(
                source_parent,
                source_name,
                source_identity,
                destination_parent,
                destination_name,
                current,
            )
            return _publication_identity(result)
        except PublicationAmbiguousError:
            raise
        except (FilesystemError, PublicationError):
            _die("Recovery staged-file publication failed")
    finally:
        destination_parent.close()
        source_parent.close()


def _move_file(
    source: str,
    destination: str,
    expected: FileIdentity | FileObjectState,
) -> FileIdentity:
    if _actual(destination) is not ABSENT:
        _die("Recovery publication destination appeared")
    return _publish_file(source, destination, expected, IdentitySentinel.ABSENT)


def _move_tree(
    source: str,
    destination: str,
    expected: DirectoryIdentity,
) -> None:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
    try:
        try:
            with source_parent.open_directory(
                source_name, expected_identity=expected
            ) as root:
                readiness = fsync_tree(root, source_parent, source_name)
                source_identity = root.identity
            publish_no_clobber(
                source_parent,
                source_name,
                source_identity,
                destination_parent,
                destination_name,
                readiness=readiness,
            )
        except (FilesystemError, PublicationError):
            _die("Recovery directory publication failed")
    finally:
        destination_parent.close()
        source_parent.close()


def _remove_file(
    path: str,
    expected: FileIdentity | FileObjectState,
    label: str,
    pause: PauseHook | None = None,
    pause_point: str | None = None,
    changed_message: str | None = None,
) -> None:
    parent, name = _parent(path)
    try:
        try:
            with parent.open_file(name, expected_identity=expected) as opened:
                identity = opened.identity
            if pause is not None:
                pause(pause_point or label)
            unlink_exact(parent, name, identity)
        except (FilesystemError, PublicationError):
            _die(changed_message or f"{label} changed before terminal unlink")
    finally:
        parent.close()


def _remove_tree(path: str, expected: DirectoryIdentity, label: str) -> None:
    parent, name = _parent(path)
    try:
        try:
            with parent.open_directory(name, expected_identity=expected) as root:
                readiness = fsync_tree(root, parent, name)
                identity = root.identity
            remove_exact_tree(parent, name, identity, readiness)
        except (FilesystemError, PublicationError):
            _die(label)
    finally:
        parent.close()


def _manifested_tree(
    root_path: str,
    root_identity: DirectoryIdentity,
    manifest_path: str,
    manifest_identity: FileIdentity | FileObjectState,
    manifest_digest: str,
    label: str,
    *,
    excluded: str | None = None,
    remove: bool = False,
) -> None:
    parent, name = _parent(root_path)
    try:
        try:
            manifest = _opened_file(manifest_path, manifest_identity)
            try:
                if remove:
                    remove_manifested_tree(
                        parent,
                        name,
                        root_identity,
                        manifest,
                        manifest_identity,
                        manifest_digest,
                        excluded,
                    )
                else:
                    with parent.open_directory(
                        name, expected_identity=root_identity
                    ) as root:
                        validate_tree_manifest(
                            root,
                            parent,
                            name,
                            manifest,
                            manifest_identity,
                            manifest_digest,
                            excluded,
                        )
            finally:
                manifest.close()
        except FilesystemError:
            manifest_label = (
                "PKI cleanup tree manifest"
                if remove
                else "PKI tree manifest"
            )
            _die(f"{manifest_label} identity changed")
        except TreeManifestError as error:
            detail = str(error)
            if detail == "tree manifest identity changed":
                manifest_label = (
                    "PKI cleanup tree manifest"
                    if remove
                    else "PKI tree manifest"
                )
                _die(f"{manifest_label} identity changed")
            if not remove and detail == "tree manifest digest changed":
                _die("PKI tree manifest digest changed")
            if not remove:
                _die(
                    "PKI tree contents do not match their manifest: "
                    f"{root_path}"
                )
            _die(label)
        except PublicationError:
            _die(label)
    finally:
        parent.close()


def _read_pair(path: str, expected: FileIdentity) -> tuple[str, str]:
    data = _verify_file(path, expected, None, "Active issuer manifest", max_bytes=4096)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        _die("Active issuer manifest is invalid")
    lines = text.splitlines()
    if (
        len(lines) != 2
        or not lines[0].startswith("root=")
        or not lines[1].startswith("intermediate=")
    ):
        _die("Active issuer manifest is invalid")
    return lines[0][5:], lines[1][13:]


def _marker_cleanup_quirk(path: str) -> None:
    """Preserve final Bash's unbound ``rm -f`` for schema-2/3 completion."""

    parent, name = _parent(path)
    try:
        try:
            os.unlink(name, dir_fd=parent.fileno())
        except FileNotFoundError:
            pass
        except OSError:
            _die("Recovery marker could not be removed")
        try:
            os.fsync(parent.fileno())
        except OSError:
            _die("Recovery marker removal is not durable")
    finally:
        parent.close()


@dataclass(slots=True)
class _Journal:
    pki_dir: str
    path: str
    values: dict[str, str]
    identity: FileIdentity

    def write(self, phase: str, *, committed: bool = False) -> TypedRecoveryRecord:
        self.values["phase"] = phase
        self.values["committed"] = "true" if committed else "false"
        try:
            data = serialize_typed_recovery_rewrite(
                self.values,
                pki_dir=self.pki_dir,
            )
            parent, name = _parent(self.path)
            try:
                result = atomic_write_bytes(
                    parent,
                    name,
                    data,
                    expected_destination=self.identity,
                )
                self.identity = _publication_identity(result)
            finally:
                parent.close()
            return parse_recovery_semantics(data, pki_dir=self.pki_dir)
        except (RecoveryRecordError, FilesystemError, PublicationError):
            _die("Recovery journal could not be rewritten safely")

    def checkpoint(
        self,
        step: str,
        fault: FaultHook,
        *,
        action: RecoveryAction | None = None,
    ) -> None:
        if action is not None:
            self.values["recovery_action"] = action.value
        self.values["recovery_step"] = step
        self.write("recovering")
        fault(step)


def _load_journal(path: str, pki_dir: str, action: RecoveryAction) -> tuple[_Journal, TypedRecoveryRecord]:
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=MAX_RECOVERY_RECORD_BYTES
            ),
        ) as opened:
            data = opened.read(MAX_RECOVERY_RECORD_BYTES)
            identity = opened.identity
        record = parse_recovery_semantics(data, pki_dir=pki_dir, action=action)
    except (FilesystemError, RecoveryRecordError) as error:
        _die(str(error))
    return _Journal(pki_dir, path, dict(record.items()), identity), record


def _write_control(path: str, data: bytes) -> FileIdentity:
    parent, name = _parent(path)
    try:
        try:
            current = parent.identity_at(name)
            expected = current if isinstance(current, FileIdentity) else ABSENT
            result = atomic_write_bytes(
                parent,
                name,
                data,
                expected_destination=expected,
            )
        except (FilesystemError, PublicationError):
            _die("Recovery control record could not be published")
        return _publication_identity(result)
    finally:
        parent.close()


def _terminal_pause(environment: Mapping[str, str]) -> PauseHook:
    return PauseHook(
        pause_at=environment.get("PLATFORM_PKI_UNLINK_PAUSE_AT"),
        marker=environment.get("PLATFORM_PKI_UNLINK_PAUSE_MARKER"),
        release=environment.get("PLATFORM_PKI_UNLINK_PAUSE_RELEASE"),
    )


def _no_journal_terminal(
    pki_dir: str,
    transaction: str,
    action: RecoveryAction,
    marker_path: str,
    environment: Mapping[str, str],
) -> None:
    receipt_path = f"{pki_dir}/state/rollover/terminal-{transaction}"
    try:
        with _opened_file(marker_path, max_bytes=MAX_RECOVERY_RECORD_BYTES) as marker_file:
            marker_data = marker_file.read(MAX_RECOVERY_RECORD_BYTES)
            marker_identity = marker_file.identity
        with _opened_file(receipt_path, max_bytes=MAX_RECOVERY_RECORD_BYTES) as receipt_file:
            receipt_data = receipt_file.read(MAX_RECOVERY_RECORD_BYTES)
        marker = parse_preparation_terminal_marker(marker_data)
        receipt = parse_preparation_terminal_receipt(receipt_data)
        validate_preparation_terminal_records(
            marker,
            receipt,
            marker_identity=marker_identity,
            transaction=transaction,
            action=action,
        )
    except (FilesystemError, RecoveryRecordError):
        _die("Preparation terminal receipt does not match the recovery marker")
    _remove_file(
        marker_path,
        marker_identity,
        "Recovery marker",
        _terminal_pause(environment),
        "terminal-marker",
    )


def _finish_preparation(
    journal: _Journal,
    record: RolloverPrepareRecoveryRecord,
    action: RecoveryAction,
    outcome: PreparationTerminalOutcome,
    marker_path: str,
    fault: FaultHook,
    environment: Mapping[str, str],
) -> None:
    if action is not outcome.action:
        _die("Recovery action does not match the terminal preparation outcome")
    transaction = record["transaction"]
    transaction_dir = record.path("transaction_dir")
    assert transaction_dir is not None
    journal.values.update(
        recovery_action=action.value,
        terminal_outcome=outcome.value,
        recovery_step="terminal-transaction-pending",
    )
    journal.write("terminal-cleanup", committed=True)
    marker_identity = _write_control(
        marker_path,
        (
            f"transaction={transaction}\noperation=rollover-prepare\n"
            f"terminal_outcome={outcome.value}\n"
        ).encode("ascii"),
    )
    fault("terminal-transaction-pending")

    transaction_manifest = journal.values["transaction_tree_manifest"]
    current_transaction = _actual(transaction_dir)
    if current_transaction is not ABSENT:
        expected_transaction = record.identity("transaction_identity")
        if not isinstance(expected_transaction, DirectoryIdentity):
            _die("Incomplete preparation transaction has no exact cleanup manifest")
        if transaction_manifest != "none":
            manifest_identity = record.identity("transaction_tree_manifest_identity")
            assert isinstance(manifest_identity, FileIdentity)
            _manifested_tree(
                transaction_dir,
                expected_transaction,
                transaction_manifest,
                manifest_identity,
                journal.values["transaction_tree_manifest_sha256"],
                "Cannot remove preparation transaction staging",
                remove=True,
            )
        else:
            parent, name = _parent(transaction_dir)
            try:
                try:
                    with parent.open_directory(
                        name, expected_identity=expected_transaction
                    ) as directory:
                        if os.listdir(directory.fileno()):
                            _die("Incomplete preparation transaction has no exact cleanup manifest")
                        identity = directory.identity
                        readiness = fsync_tree(directory, parent, name)
                    remove_exact_tree(parent, name, identity, readiness)
                except (FilesystemError, PublicationError):
                    _die("Cannot remove empty incomplete preparation transaction staging")
            finally:
                parent.close()
    if transaction_manifest != "none" and _actual(transaction_manifest) is not ABSENT:
        identity = record.identity("transaction_tree_manifest_identity")
        assert isinstance(identity, FileIdentity)
        _remove_file(
            transaction_manifest,
            identity,
            "Preparation transaction manifest",
            changed_message="Preparation transaction manifest changed before cleanup",
        )

    journal.values["recovery_step"] = "terminal-transaction-done"
    journal.write("terminal-cleanup", committed=True)
    fault("terminal-transaction-done")
    journal.values["recovery_step"] = "terminal-journal-pending"
    journal.write("terminal-cleanup", committed=True)
    fault("terminal-journal-pending")

    journal_identity = journal.identity
    marker_current = _actual(marker_path)
    if not isinstance(marker_current, FileIdentity) or marker_current != marker_identity:
        _die("Recovery marker changed before terminal receipt")
    receipt_path = f"{journal.pki_dir}/state/rollover/terminal-{transaction}"
    _write_control(
        receipt_path,
        (
            f"transaction={transaction}\noperation=rollover-prepare\n"
            f"terminal_outcome={outcome.value}\n"
            f"journal_identity={serialize_file_identity(journal_identity)}\n"
            f"marker_identity={serialize_file_identity(marker_identity)}\n"
        ).encode("ascii"),
    )
    pause = _terminal_pause(environment)
    _remove_file(
        journal.path,
        journal_identity,
        "Recovery journal",
        pause,
        "terminal-journal",
    )
    fault("terminal-journal-done")
    _remove_file(
        marker_path,
        marker_identity,
        "Recovery marker",
        pause,
        "terminal-marker",
    )


def _remove_manifest_path(record: RolloverPrepareRecoveryRecord) -> None:
    path = record.path("transaction_tree_manifest")
    if path is None or _actual(path) is ABSENT:
        return
    identity = record.identity("transaction_tree_manifest_identity")
    assert isinstance(identity, FileIdentity)
    _remove_file(
        path,
        identity,
        "Preparation transaction manifest",
        changed_message="Preparation transaction manifest changed before cleanup",
    )


def _promote_pending_manifest(
    journal: _Journal,
    record: RolloverPrepareRecoveryRecord,
) -> RolloverPrepareRecoveryRecord:
    pending = record.path("transaction_tree_manifest_pending")
    if pending is None:
        return record
    identity = record.identity("transaction_tree_manifest_pending_identity")
    assert isinstance(identity, FileIdentity)
    _verify_file(
        pending,
        identity,
        record["transaction_tree_manifest_pending_sha256"],
        "Pending transaction manifest",
    )
    _remove_manifest_path(record)
    journal.values.update(
        transaction_tree_manifest=record[
            "transaction_tree_manifest_pending_destination"
        ],
        transaction_tree_manifest_identity=record[
            "transaction_tree_manifest_pending_identity"
        ],
        transaction_tree_manifest_sha256=record[
            "transaction_tree_manifest_pending_sha256"
        ],
        transaction_tree_manifest_sequence=str(
            record.transaction_manifest_sequence + 1
        ),
        transaction_tree_manifest_pending="none",
        transaction_tree_manifest_pending_destination="none",
        transaction_tree_manifest_pending_identity="none",
        transaction_tree_manifest_pending_sha256="none",
    )
    rewritten = journal.write(record.phase, committed=record.committed)
    assert isinstance(rewritten, RolloverPrepareRecoveryRecord)
    return rewritten


def _tree_identity(record: TypedRecoveryRecord, field: str) -> DirectoryIdentity:
    value = record.identity(field)
    if not isinstance(value, DirectoryIdentity):
        _die(f"Recovery directory identity {field} is unavailable")
    return value


def _file_identity(
    record: TypedRecoveryRecord, field: str
) -> FileIdentity | FileObjectState:
    value = record.identity(field)
    if not isinstance(value, (FileIdentity, FileObjectState)):
        _die(f"Recovery file identity {field} is unavailable")
    return value


def _state_identity(
    record: TypedRecoveryRecord, field: str
) -> FileIdentity | FileObjectState | IdentitySentinel:
    value = record.identity(field)
    if not isinstance(value, (FileIdentity, FileObjectState, IdentitySentinel)):
        _die(f"Recovery file identity {field} is unresolved")
    return value


def _preparation_state_allowed(record: RolloverPrepareRecoveryRecord) -> dict[str, object]:
    values: dict[str, object] = {}
    for field, label, allowed in (
        (
            "backup_session",
            "Preparation backup session",
            ("backup_session_original_identity", "backup_session_identity"),
        ),
        (
            "intermediate_reservation",
            "intermediate reservation",
            (
                None,
                "intermediate_reservation_reserved_identity",
                "intermediate_reservation_consumed_identity",
                "intermediate_reservation_abandoned_identity",
            ),
        ),
    ):
        path = record.path(field)
        assert path is not None
        identities = tuple(
            IdentitySentinel.ABSENT if name is None else record.identity(name)
            for name in allowed
        )
        values[field] = _allowed_state(path, label, *identities)
    if record.preparation_type is RolloverPreparationType.ROOT:
        path = record.path("root_reservation")
        assert path is not None
        values["root_reservation"] = _allowed_state(
            path,
            "root reservation",
            IdentitySentinel.ABSENT,
            record.identity("root_reservation_reserved_identity"),
            record.identity("root_reservation_consumed_identity"),
            record.identity("root_reservation_abandoned_identity"),
        )
    return values


def _validate_preparation_committed(record: RolloverPrepareRecoveryRecord) -> None:
    active = record.path("active_manifest")
    assert active is not None
    _require_state(active, _file_identity(record, "active_identity"), "Active issuer manifest")
    pointer = record.path("pointer")
    long_dir = record.path("long_dir")
    root_dir = record.path("candidate_root_dir")
    intermediate_dir = record.path("candidate_intermediate_dir")
    assert pointer and long_dir and root_dir and intermediate_dir
    assert record.terminal_outcome is not None
    if record.terminal_outcome is PreparationTerminalOutcome.RESUMED:
        _require_state(pointer, _file_identity(record, "pointer_identity"), "Active rollover pointer")
        long_identity = _tree_identity(record, "long_identity")
        _manifested_tree(
            long_dir,
            long_identity,
            f"{long_dir}/tree.manifest",
            _file_identity(record, "long_tree_manifest_identity"),
            record["long_tree_manifest_sha256"],
            "Prepared rollover state identity changed",
            excluded="tree.manifest",
        )
        _manifested_tree(
            intermediate_dir,
            _tree_identity(record, "candidate_intermediate_identity"),
            f"{long_dir}/candidate-intermediate-tree.manifest",
            _file_identity(record, "candidate_intermediate_tree_manifest_identity"),
            record["candidate_intermediate_tree_manifest_sha256"],
            "Candidate intermediate tree changed",
        )
        if record.preparation_type is RolloverPreparationType.ROOT:
            _manifested_tree(
                root_dir,
                _tree_identity(record, "candidate_root_identity"),
                f"{long_dir}/candidate-root-tree.manifest",
                _file_identity(record, "candidate_root_tree_manifest_identity"),
                record["candidate_root_tree_manifest_sha256"],
                "Candidate root tree changed",
            )
        return
    _require_state(pointer, IdentitySentinel.ABSENT, "Active rollover pointer")
    for path, label in (
        (long_dir, "Rolled-back preparation retained rollover state"),
        (intermediate_dir, "Rolled-back preparation retained a candidate intermediate"),
    ):
        if _actual(path) is not ABSENT:
            _die(label)
    if record.preparation_type is RolloverPreparationType.ROOT:
        if _actual(root_dir) is not ABSENT:
            _die("Rolled-back preparation retained a candidate root")
    else:
        _require_state(
            root_dir,
            _tree_identity(record, "candidate_root_identity"),
            "Active root",
        )
    backup_session = record.path("backup_session")
    intermediate_reservation = record.path("intermediate_reservation")
    assert backup_session and intermediate_reservation
    _require_state(
        backup_session,
        record.identity("backup_session_original_identity"),
        "Preparation backup session",
    )
    _require_state(
        intermediate_reservation,
        record.identity("intermediate_reservation_abandoned_identity"),
        "Abandoned intermediate reservation",
    )
    if record.preparation_type is RolloverPreparationType.ROOT:
        root_reservation = record.path("root_reservation")
        assert root_reservation
        _require_state(
            root_reservation,
            record.identity("root_reservation_abandoned_identity"),
            "Abandoned root reservation",
        )


def _recover_preparation(
    journal: _Journal,
    initial: RolloverPrepareRecoveryRecord,
    action: RecoveryAction,
    marker_path: str,
    fault: FaultHook,
    environment: Mapping[str, str],
) -> str:
    record = _promote_pending_manifest(journal, initial)
    transaction = record["transaction"]
    transaction_dir = record.path("transaction_dir")
    active = record.path("active_manifest")
    backup_receipt = record.path("backup_receipt")
    root_dir = record.path("candidate_root_dir")
    intermediate_dir = record.path("candidate_intermediate_dir")
    long_stage = record.path("long_stage")
    long_dir = record.path("long_dir")
    pointer = record.path("pointer")
    root_reservation = record.path("root_reservation")
    intermediate_reservation = record.path("intermediate_reservation")
    backup_session = record.path("backup_session")
    assert all(
        value is not None
        for value in (
            transaction_dir,
            active,
            backup_receipt,
            root_dir,
            intermediate_dir,
            long_stage,
            long_dir,
            pointer,
            root_reservation,
            intermediate_reservation,
            backup_session,
        )
    )
    if record.committed:
        _validate_preparation_committed(record)
        assert record.terminal_outcome is not None
        _finish_preparation(
            journal,
            record,
            action,
            record.terminal_outcome,
            marker_path,
            fault,
            environment,
        )
        return f"Completed terminal cleanup for {transaction}"

    active_identity = _file_identity(record, "active_identity")
    active_root, active_intermediate = _read_pair(active, active_identity)  # type: ignore[arg-type]
    if (active_root, active_intermediate) != (
        record.active_root,
        record.active_intermediate,
    ):
        _die("Active issuer changed during preparation recovery")
    _require_state(
        backup_receipt,
        _file_identity(record, "receipt_identity"),
        "Preparation backup receipt",
    )

    transaction_identity = record.identity("transaction_identity")
    if transaction_identity is IdentitySentinel.NONE:
        if action is not RecoveryAction.ROLLBACK:
            _die("Planned preparation can only be rolled back before transaction staging")
        current = _actual(transaction_dir)
        if current is not ABSENT:
            if record.recovery_step != "transaction-dir-pending" or not isinstance(
                current, FileIdentity
            ) or current.kind != "directory" or current.uid != os.geteuid() or current.permissions != 0o700:
                _die("Planned preparation transaction path is ambiguous")
            try:
                with OpenedDirectory(transaction_dir, expected_identity=current) as directory:
                    if os.listdir(directory.fileno()):
                        _die("Pending preparation transaction directory is not safely empty")
            except FilesystemError:
                _die("Pending preparation transaction directory is not safely empty")
            journal.values["transaction_identity"] = (
                f"{current.dev}:{current.ino}:{current.uid}:{current.permissions:o}:directory"
            )
            record = parse_recovery_semantics(
                serialize_typed_recovery_rewrite(journal.values, pki_dir=journal.pki_dir),
                pki_dir=journal.pki_dir,
            )
            assert isinstance(record, RolloverPrepareRecoveryRecord)
        if record.preparation_type is RolloverPreparationType.ROOT and _actual(root_dir) is not ABSENT:
            _die("Unjournaled candidate root state exists")
        if any(_actual(path) is not ABSENT for path in (intermediate_dir, long_dir, pointer)):
            _die("Unjournaled preparation state exists")
        _finish_preparation(
            journal,
            record,
            action,
            PreparationTerminalOutcome.ROLLED_BACK,
            marker_path,
            fault,
            environment,
        )
        return f"Rolled back planned preparation transaction: {transaction}"

    transaction_directory_identity = _tree_identity(record, "transaction_identity")
    _require_state(
        transaction_dir,
        transaction_directory_identity,
        "Preparation transaction directory",
    )
    _preparation_state_allowed(record)

    abandoned_intermediate = record.identity(
        "intermediate_reservation_abandoned_identity"
    )
    current_intermediate_reservation = _actual(intermediate_reservation)
    if not _matches(current_intermediate_reservation, abandoned_intermediate):
        if abandoned_intermediate is IdentitySentinel.ABSENT:
            _die("Intermediate reservation lacks rollback evidence")
        _require_state(
            f"{transaction_dir}/intermediate-abandoned",
            abandoned_intermediate,
            "Intermediate abandoned reservation stage",
        )
    if record.preparation_type is RolloverPreparationType.ROOT:
        abandoned_root = record.identity("root_reservation_abandoned_identity")
        if not _matches(_actual(root_reservation), abandoned_root):
            if abandoned_root is IdentitySentinel.ABSENT:
                _die("Root reservation lacks rollback evidence")
            _require_state(
                f"{transaction_dir}/root-abandoned",
                abandoned_root,
                "Root abandoned reservation stage",
            )

    if record.identity("candidate_intermediate_identity") is IdentitySentinel.NONE:
        if action is not RecoveryAction.ROLLBACK:
            _die("Preparation interrupted before candidate staging completed; recover with rollback")
        if any(_actual(path) is not ABSENT for path in (intermediate_dir, long_dir, pointer)):
            _die("Unjournaled preparation publication exists")
        if record.preparation_type is RolloverPreparationType.ROOT and _actual(root_dir) is not ABSENT:
            _die("Unjournaled candidate root exists")
        if abandoned_intermediate is not IdentitySentinel.ABSENT and not _matches(
            _actual(intermediate_reservation), abandoned_intermediate
        ):
            journal.checkpoint("rollback-reservation-intermediate-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/intermediate-abandoned",
                intermediate_reservation,
                _file_identity(record, "intermediate_reservation_abandoned_identity"),
                IdentitySentinel.ABSENT,
                _state_identity(record, "intermediate_reservation_reserved_identity"),
                _state_identity(record, "intermediate_reservation_consumed_identity"),
            )
            journal.checkpoint("rollback-reservation-intermediate-done", fault, action=action)
        if record.preparation_type is RolloverPreparationType.ROOT:
            abandoned_root = record.identity("root_reservation_abandoned_identity")
            if abandoned_root is not IdentitySentinel.ABSENT and not _matches(
                _actual(root_reservation), abandoned_root
            ):
                journal.checkpoint("rollback-reservation-root-pending", fault, action=action)
                _publish_file(
                    f"{transaction_dir}/root-abandoned",
                    root_reservation,
                    _file_identity(record, "root_reservation_abandoned_identity"),
                    IdentitySentinel.ABSENT,
                    _state_identity(record, "root_reservation_reserved_identity"),
                    _state_identity(record, "root_reservation_consumed_identity"),
                )
                journal.checkpoint("rollback-reservation-root-done", fault, action=action)
        current_backup = _actual(backup_session)
        if _matches(current_backup, record.identity("backup_session_identity")) and isinstance(current_backup, FileIdentity):
            journal.checkpoint("rollback-backup-session-pending", fault, action=action)
            _remove_file(backup_session, current_backup, "Preparation backup session")
            journal.checkpoint("rollback-backup-session-done", fault, action=action)
        _finish_preparation(
            journal,
            record,
            action,
            PreparationTerminalOutcome.ROLLED_BACK,
            marker_path,
            fault,
            environment,
        )
        return f"Rolled back incomplete preparation transaction: {transaction}"

    stage_dir = record.path("stage_dir")
    if stage_dir is None:
        _die("Preparation staging directory identity changed")
    stage_root = f"{stage_dir}/root"
    stage_intermediate = f"{stage_dir}/intermediate"
    rollback_progress = action is RecoveryAction.ROLLBACK and record.recovery_action is action
    step = record.recovery_step or ""
    intermediate_removed = rollback_progress and step.startswith(
        ("rollback-intermediate-", "rollback-root-", "rollback-state-", "rollback-stage-", "rollback-reservation-", "rollback-backup-session-", "terminal-")
    )
    root_removed = rollback_progress and step.startswith(
        ("rollback-root-", "rollback-state-", "rollback-stage-", "rollback-reservation-", "rollback-backup-session-", "terminal-")
    )
    state_removed = rollback_progress and step.startswith(
        ("rollback-state-", "rollback-stage-", "rollback-reservation-", "rollback-backup-session-", "terminal-")
    )
    stage_current = _actual(stage_dir)
    if stage_current is not ABSENT and not _matches(stage_current, record.identity("stage_identity")):
        _die("Preparation staging directory identity changed")

    root_identity = _tree_identity(record, "candidate_root_identity")
    intermediate_identity = _tree_identity(record, "candidate_intermediate_identity")
    if record.preparation_type is RolloverPreparationType.ROOT:
        root_at_stage = _matches(_actual(stage_root), root_identity)
        root_at_final = _matches(_actual(root_dir), root_identity)
        if not ((root_at_stage != root_at_final) or (root_removed and not root_at_stage and not root_at_final)):
            _die("Candidate root location is ambiguous or replaced")
    else:
        _require_state(root_dir, root_identity, "Active root")
    intermediate_at_stage = _matches(_actual(stage_intermediate), intermediate_identity)
    intermediate_at_final = _matches(_actual(intermediate_dir), intermediate_identity)
    if not (
        (intermediate_at_stage != intermediate_at_final)
        or (intermediate_removed and not intermediate_at_stage and not intermediate_at_final)
    ):
        _die("Candidate intermediate location is ambiguous or replaced")

    root_location = root_dir if _actual(root_dir) is not ABSENT else stage_root
    intermediate_location = (
        intermediate_dir if _actual(intermediate_dir) is not ABSENT else stage_intermediate
    )
    if _actual(root_location) is not ABSENT:
        _require_state(
            f"{root_location}/private/root-ca.key",
            _file_identity(record, "candidate_root_key_identity"),
            "Candidate root key",
        )
        _verify_file(
            f"{root_location}/certs/root-ca.crt",
            _file_identity(record, "candidate_root_cert_identity"),
            record["candidate_root_cert_sha256"],
            "Candidate root certificate",
        )
    if _actual(intermediate_location) is not ABSENT:
        _require_state(
            f"{intermediate_location}/private/intermediate-ca.key",
            _file_identity(record, "candidate_intermediate_key_identity"),
            "Candidate intermediate key",
        )
        for relative, identity_field, digest_field, label in (
            ("certs/intermediate-ca.crt", "candidate_intermediate_cert_identity", "candidate_intermediate_cert_sha256", "Candidate intermediate certificate"),
            ("certs/ca-chain.crt", "candidate_chain_identity", "candidate_chain_sha256", "Candidate CA chain"),
        ):
            _verify_file(
                f"{intermediate_location}/{relative}",
                _file_identity(record, identity_field),
                record[digest_field],
                label,
            )
    long_identity = _tree_identity(record, "long_identity")
    state_at_stage = _matches(_actual(long_stage), long_identity)
    state_at_final = _matches(_actual(long_dir), long_identity)
    if not (
        (state_at_stage != state_at_final)
        or (state_removed and not state_at_stage and not state_at_final)
    ):
        _die("Long-lived rollover state is ambiguous or replaced")
    state_location = long_dir if state_at_final else long_stage
    if _actual(state_location) is not ABSENT:
        _verify_file(
            f"{state_location}/manifest",
            _file_identity(record, "long_manifest_identity"),
            record["long_manifest_sha256"],
            "Rollover manifest",
        )
        _manifested_tree(
            state_location,
            long_identity,
            f"{state_location}/tree.manifest",
            _file_identity(record, "long_tree_manifest_identity"),
            record["long_tree_manifest_sha256"],
            "Rollover state tree changed",
            excluded="tree.manifest",
        )
        if record.preparation_type is RolloverPreparationType.ROOT:
            _verify_file(
                f"{state_location}/trust-consumers.yml",
                _file_identity(record, "trust_snapshot_identity"),
                record["trust_snapshot_sha256"],
                "Trust consumer snapshot",
            )
            if _actual(root_location) is not ABSENT:
                _manifested_tree(
                    root_location,
                    root_identity,
                    f"{state_location}/candidate-root-tree.manifest",
                    _file_identity(record, "candidate_root_tree_manifest_identity"),
                    record["candidate_root_tree_manifest_sha256"],
                    "Candidate root tree changed",
                )
        if _actual(intermediate_location) is not ABSENT:
            _manifested_tree(
                intermediate_location,
                intermediate_identity,
                f"{state_location}/candidate-intermediate-tree.manifest",
                _file_identity(record, "candidate_intermediate_tree_manifest_identity"),
                record["candidate_intermediate_tree_manifest_sha256"],
                "Candidate intermediate tree changed",
            )
    _allowed_state(
        pointer,
        "Active rollover pointer",
        IdentitySentinel.ABSENT,
        record.identity("pointer_identity"),
    )

    db_paths: dict[str, str] = {}
    db_backups: dict[str, str] = {}
    if record.preparation_type is RolloverPreparationType.INTERMEDIATE:
        issued = record["issued_serial"]
        relatives = {
            "index": "index.txt",
            "index_attr": "index.txt.attr",
            "serial": "serial",
            "crlnumber": "crlnumber",
            "index_old": "index.txt.old",
            "index_attr_old": "index.txt.attr.old",
            "serial_old": "serial.old",
            "crlnumber_old": "crlnumber.old",
            "newcert": f"newcerts/{issued}.pem",
        }
        backups = {
            **{key: f"{stage_dir}/root-backup/{relative}" for key, relative in relatives.items()},
            "newcert": "none",
        }
        for key, relative in relatives.items():
            path = f"{root_dir}/{relative}"
            db_paths[key] = path
            db_backups[key] = backups[key]
            pre = _state_identity(record, f"root_{key}_pre_identity")
            post = _state_identity(record, f"root_{key}_post_identity")
            rollback = _state_identity(record, f"root_{key}_rollback_identity")
            source = _state_identity(record, f"root_{key}_source_identity")
            backup = _state_identity(record, f"root_{key}_backup_identity")
            allowed = [pre, post, rollback]
            resume_window = (
                action is RecoveryAction.RESUME
                and record.recovery_action is action
                and record.recovery_step == f"resume-root-db-{key}-pending"
                and isinstance(source, (FileIdentity, FileObjectState))
            )
            rollback_window = (
                action is RecoveryAction.ROLLBACK
                and record.recovery_action is action
                and record.recovery_step == f"rollback-root-db-{key}-pending"
                and isinstance(backup, (FileIdentity, FileObjectState))
            )
            if resume_window:
                allowed.append(_relocated_state(source))
            if rollback_window:
                allowed.append(_relocated_state(backup))
            current = _allowed_state(
                path,
                f"Root {key}",
                *allowed,
            )
            if _matches(current, post) and pre is not IdentitySentinel.ABSENT:
                _require_state(backups[key], record.identity(f"root_{key}_backup_identity"), f"Root {key} rollback copy")
            if _matches(current, pre) and source is not IdentitySentinel.ABSENT:
                _require_state(f"{stage_root}/{relative}", source, f"Staged root {key} publication source")
            if resume_window and _matches(current, _relocated_state(source)):
                _require_state(
                    f"{stage_root}/{relative}",
                    IdentitySentinel.ABSENT,
                    f"Consumed staged root {key} publication source",
                )
            if rollback_window and _matches(current, _relocated_state(backup)):
                _require_state(
                    backups[key],
                    IdentitySentinel.ABSENT,
                    f"Consumed root {key} rollback copy",
                )
        root_stage = record.path("root_stage")
        if root_stage is not None and _actual(root_stage) is not ABSENT:
            _require_state(root_stage, _tree_identity(record, "root_stage_identity"), "Sensitive root stage")
            _require_state(
                f"{root_stage}/private/root-ca.key",
                _file_identity(record, "root_stage_key_identity"),
                "Copied root signing key",
            )

    journal.values["recovery_action"] = action.value
    if action is RecoveryAction.ROLLBACK:
        current_pointer = _actual(pointer)
        if _matches(current_pointer, record.identity("pointer_identity")) and isinstance(current_pointer, FileIdentity):
            journal.checkpoint("rollback-pointer-pending", fault, action=action)
            _remove_file(pointer, current_pointer, "Active rollover pointer")
            journal.checkpoint("rollback-pointer-done", fault, action=action)
        for key in ROOT_DB_KEYS if db_paths else ():
            current = _actual(db_paths[key])
            pre = _state_identity(record, f"root_{key}_pre_identity")
            post = _state_identity(record, f"root_{key}_post_identity")
            backup = _state_identity(record, f"root_{key}_backup_identity")
            if (
                backup is not IdentitySentinel.ABSENT
                and isinstance(current, FileIdentity)
                and isinstance(backup, (FileIdentity, FileObjectState))
                and _matches(current, _relocated_state(backup))
                and record.recovery_step == f"rollback-root-db-{key}-pending"
            ):
                journal.values[f"root_{key}_rollback_identity"] = (
                    serialize_file_identity(current)
                )
                journal.checkpoint(
                    f"rollback-root-db-{key}-done", fault, action=action
                )
                continue
            if _matches(current, post) and pre != post:
                journal.checkpoint(f"rollback-root-db-{key}-pending", fault, action=action)
                if pre is IdentitySentinel.ABSENT:
                    assert isinstance(current, FileIdentity)
                    _remove_file(db_paths[key], current, f"Root {key}")
                else:
                    published = _publish_file(
                        db_backups[key],
                        db_paths[key],
                        _file_identity(record, f"root_{key}_backup_identity"),
                        _file_identity(record, f"root_{key}_post_identity"),
                    )
                    journal.values[f"root_{key}_rollback_identity"] = serialize_file_identity(published)
                journal.checkpoint(f"rollback-root-db-{key}-done", fault, action=action)
        if _actual(intermediate_dir) is not ABSENT:
            journal.checkpoint("rollback-intermediate-pending", fault, action=action)
            _manifested_tree(
                intermediate_dir,
                intermediate_identity,
                f"{state_location}/candidate-intermediate-tree.manifest",
                _file_identity(record, "candidate_intermediate_tree_manifest_identity"),
                record["candidate_intermediate_tree_manifest_sha256"],
                "Cannot remove candidate intermediate",
                remove=True,
            )
            journal.checkpoint("rollback-intermediate-done", fault, action=action)
        if record.preparation_type is RolloverPreparationType.ROOT and _actual(root_dir) is not ABSENT:
            journal.checkpoint("rollback-root-pending", fault, action=action)
            _manifested_tree(
                root_dir,
                root_identity,
                f"{state_location}/candidate-root-tree.manifest",
                _file_identity(record, "candidate_root_tree_manifest_identity"),
                record["candidate_root_tree_manifest_sha256"],
                "Cannot remove candidate root",
                remove=True,
            )
            journal.checkpoint("rollback-root-done", fault, action=action)
        state_remove = long_dir if _actual(long_dir) is not ABSENT else long_stage
        if _actual(state_remove) is not ABSENT:
            journal.checkpoint("rollback-state-pending", fault, action=action)
            _manifested_tree(
                state_remove,
                long_identity,
                f"{state_remove}/tree.manifest",
                _file_identity(record, "long_tree_manifest_identity"),
                record["long_tree_manifest_sha256"],
                "Cannot remove rollover state",
                excluded="tree.manifest",
                remove=True,
            )
            journal.checkpoint("rollback-state-done", fault, action=action)
        if _actual(stage_dir) is not ABSENT:
            journal.checkpoint("rollback-stage-pending", fault, action=action)
            manifest_path = record.path("stage_tree_manifest")
            assert manifest_path is not None
            _manifested_tree(
                stage_dir,
                _tree_identity(record, "stage_identity"),
                manifest_path,
                _file_identity(record, "stage_tree_manifest_identity"),
                record["stage_tree_manifest_sha256"],
                "Cannot remove preparation staging",
                remove=True,
            )
            journal.checkpoint("rollback-stage-done", fault, action=action)
        for kind, path, identity_field, stage_name in (
            ("intermediate", intermediate_reservation, "intermediate_reservation_abandoned_identity", "intermediate-abandoned"),
            ("root", root_reservation, "root_reservation_abandoned_identity", "root-abandoned"),
        ):
            if kind == "root" and record.preparation_type is not RolloverPreparationType.ROOT:
                continue
            expected = record.identity(identity_field)
            if not _matches(_actual(path), expected):
                journal.checkpoint(f"rollback-reservation-{kind}-pending", fault, action=action)
                _publish_file(
                    f"{transaction_dir}/{stage_name}",
                    path,
                    _file_identity(record, identity_field),
                    IdentitySentinel.ABSENT,
                    _state_identity(record, f"{kind}_reservation_reserved_identity"),
                    _state_identity(record, f"{kind}_reservation_consumed_identity"),
                )
                journal.checkpoint(f"rollback-reservation-{kind}-done", fault, action=action)
        current_backup = _actual(backup_session)
        if _matches(current_backup, record.identity("backup_session_identity")) and isinstance(current_backup, FileIdentity):
            journal.checkpoint("rollback-backup-session-pending", fault, action=action)
            _remove_file(backup_session, current_backup, "Preparation backup session")
            journal.checkpoint("rollback-backup-session-done", fault, action=action)
        _finish_preparation(
            journal,
            record,
            action,
            PreparationTerminalOutcome.ROLLED_BACK,
            marker_path,
            fault,
            environment,
        )
        return f"Rolled back preparation transaction: {transaction}"

    if _actual(backup_session) is ABSENT:
        journal.checkpoint("resume-backup-session-pending", fault, action=action)
        _publish_file(
            f"{transaction_dir}/backup-session.publish",
            backup_session,
            _file_identity(record, "backup_session_identity"),
            IdentitySentinel.ABSENT,
        )
        journal.checkpoint("resume-backup-session-done", fault, action=action)
    for kind, path, identity_field, stage_name in (
        ("root", root_reservation, "root_reservation_reserved_identity", "root-reserved"),
        ("intermediate", intermediate_reservation, "intermediate_reservation_reserved_identity", "intermediate-reserved"),
    ):
        if kind == "root" and record.preparation_type is not RolloverPreparationType.ROOT:
            continue
        if _actual(path) is ABSENT:
            checkpoint = f"resume-reserve-{kind}"
            journal.checkpoint(f"{checkpoint}-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/{stage_name}",
                path,
                _file_identity(record, identity_field),
                IdentitySentinel.ABSENT,
            )
            journal.checkpoint(f"{checkpoint}-done", fault, action=action)
    if record.preparation_type is RolloverPreparationType.ROOT and _actual(stage_root) is not ABSENT:
        journal.checkpoint("resume-publish-root-pending", fault, action=action)
        _move_tree(stage_root, root_dir, root_identity)
        journal.checkpoint("resume-publish-root-done", fault, action=action)
    if _actual(stage_intermediate) is not ABSENT:
        journal.checkpoint("resume-publish-intermediate-pending", fault, action=action)
        _move_tree(stage_intermediate, intermediate_dir, intermediate_identity)
        journal.checkpoint("resume-publish-intermediate-done", fault, action=action)
    for key in ROOT_DB_KEYS if db_paths else ():
        pre = _state_identity(record, f"root_{key}_pre_identity")
        post = _state_identity(record, f"root_{key}_post_identity")
        source = _state_identity(record, f"root_{key}_source_identity")
        current = _actual(db_paths[key])
        if (
            source is not IdentitySentinel.ABSENT
            and isinstance(current, FileIdentity)
            and isinstance(source, (FileIdentity, FileObjectState))
            and _matches(current, _relocated_state(source))
            and record.recovery_step == f"resume-root-db-{key}-pending"
        ):
            journal.values[f"root_{key}_post_identity"] = serialize_file_identity(
                current
            )
            journal.checkpoint(f"resume-root-db-{key}-done", fault, action=action)
            continue
        if _matches(current, pre) and pre != post:
            relative = db_paths[key].removeprefix(f"{root_dir}/")
            journal.checkpoint(f"resume-root-db-{key}-pending", fault, action=action)
            published = _publish_file(
                f"{stage_root}/{relative}",
                db_paths[key],
                _file_identity(record, f"root_{key}_source_identity"),
                _state_identity(record, f"root_{key}_pre_identity"),
            )
            journal.values[f"root_{key}_post_identity"] = serialize_file_identity(published)
            journal.checkpoint(f"resume-root-db-{key}-done", fault, action=action)
    for kind, path, reserved_field, consumed_field, stage_name in (
        ("root", root_reservation, "root_reservation_reserved_identity", "root_reservation_consumed_identity", "root-consumed"),
        ("intermediate", intermediate_reservation, "intermediate_reservation_reserved_identity", "intermediate_reservation_consumed_identity", "intermediate-consumed"),
    ):
        if kind == "root" and record.preparation_type is not RolloverPreparationType.ROOT:
            continue
        if _matches(_actual(path), record.identity(reserved_field)):
            journal.checkpoint(f"resume-consume-{kind}-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/{stage_name}",
                path,
                _file_identity(record, consumed_field),
                _file_identity(record, reserved_field),
            )
            journal.checkpoint(f"resume-consume-{kind}-done", fault, action=action)
    root_stage = record.path("root_stage")
    if record.preparation_type is RolloverPreparationType.INTERMEDIATE and root_stage is not None and _actual(root_stage) is not ABSENT:
        journal.checkpoint("resume-cleanup-root-stage-pending", fault, action=action)
        _manifested_tree(
            root_stage,
            _tree_identity(record, "root_stage_identity"),
            f"{state_location}/root-signing-stage-tree.manifest",
            _file_identity(record, "root_stage_tree_manifest_identity"),
            record["root_stage_tree_manifest_sha256"],
            "Cannot remove copied root signing stage",
            remove=True,
        )
        journal.checkpoint("resume-cleanup-root-stage-done", fault, action=action)
    if _actual(long_stage) is not ABSENT:
        journal.checkpoint("resume-publish-state-pending", fault, action=action)
        _move_tree(long_stage, long_dir, long_identity)
        journal.checkpoint("resume-publish-state-done", fault, action=action)
    if _actual(pointer) is ABSENT:
        journal.checkpoint("resume-publish-pointer-pending", fault, action=action)
        _publish_file(
            f"{transaction_dir}/active-rollover.publish",
            pointer,
            _file_identity(record, "pointer_identity"),
            IdentitySentinel.ABSENT,
        )
        journal.checkpoint("resume-publish-pointer-done", fault, action=action)
    _finish_preparation(
        journal,
        record,
        action,
        PreparationTerminalOutcome.RESUMED,
        marker_path,
        fault,
        environment,
    )
    return f"Resumed preparation transaction: {transaction}"


def _bootstrap_db_paths(
    record: IntermediateBootstrapRecoveryRecord,
) -> tuple[dict[str, str], dict[str, str]]:
    root_dir = record.path("root_dir")
    stage = record.path("stage_dir")
    assert root_dir is not None and stage is not None
    issued = record["issued_serial"]
    relatives = {
        "index": "index.txt",
        "index_attr": "index.txt.attr",
        "serial": "serial",
        "crlnumber": "crlnumber",
        "index_old": "index.txt.old",
        "index_attr_old": "index.txt.attr.old",
        "serial_old": "serial.old",
        "crlnumber_old": "crlnumber.old",
        "newcert": f"newcerts/{issued}.pem",
    }
    paths = {key: f"{root_dir}/{relative}" for key, relative in relatives.items()}
    backups = {
        key: f"{stage}/root-backup/{relative}" for key, relative in relatives.items()
    }
    backups["newcert"] = "none"
    return paths, backups


def _recover_bootstrap(
    journal: _Journal,
    record: RootBootstrapRecoveryRecord | IntermediateBootstrapRecoveryRecord,
    action: RecoveryAction,
    marker_path: str,
    fault: FaultHook,
) -> str:
    transaction = record["transaction"]
    transaction_dir = record.path("transaction_dir")
    reservation = record.path("reservation")
    stage = record.path("stage_dir")
    assert transaction_dir is not None and reservation is not None
    _require_state(
        transaction_dir,
        _tree_identity(record, "transaction_identity"),
        "Bootstrap recovery transaction directory",
    )
    _allowed_state(
        reservation,
        "Bootstrap reservation",
        IdentitySentinel.ABSENT,
        _state_identity(record, "reservation_reserved_identity"),
        _state_identity(record, "reservation_consumed_identity"),
        _state_identity(record, "reservation_abandoned_identity"),
    )
    abandoned = _state_identity(record, "reservation_abandoned_identity")
    abandoned_stage = f"{transaction_dir}/reservation-abandoned"
    if not _matches(_actual(reservation), abandoned):
        if abandoned is IdentitySentinel.ABSENT:
            _die("Abandoned bootstrap reservation stage is missing")
        _require_state(abandoned_stage, abandoned, "Abandoned bootstrap reservation stage")
    if stage is not None:
        current_stage = _actual(stage)
        if current_stage is not ABSENT and not _matches(
            current_stage, record.identity("stage_identity")
        ):
            _die("Bootstrap staging identity changed")
    journal.values["recovery_action"] = RecoveryAction.ROLLBACK.value

    authority: str
    authority_identity: DirectoryIdentity | IdentitySentinel
    db_paths: dict[str, str] = {}
    db_backups: dict[str, str] = {}
    if isinstance(record, RootBootstrapRecoveryRecord):
        authority = record.path("authority_dir") or ""
        authority_identity = record.identity("authority_identity")  # type: ignore[assignment]
        current_authority = _actual(authority)
        if current_authority is not ABSENT and (
            authority_identity is IdentitySentinel.NONE
            or not _matches(current_authority, authority_identity)
        ):
            _die("Root bootstrap authority identity changed")
        bootstrap = f"{journal.pki_dir}/state/bootstrap-root"
        bootstrap_identity = _state_identity(record, "bootstrap_identity")
        current_bootstrap = _allowed_state(
            bootstrap,
            "Bootstrap root manifest",
            IdentitySentinel.ABSENT,
            bootstrap_identity,
        )
        if current_bootstrap is not ABSENT:
            assert isinstance(current_bootstrap, FileIdentity)
            journal.checkpoint(
                "rollback-bootstrap-pending", fault, action=RecoveryAction.ROLLBACK
            )
            _remove_file(bootstrap, current_bootstrap, "Bootstrap root manifest")
            journal.checkpoint(
                "rollback-bootstrap-done", fault, action=RecoveryAction.ROLLBACK
            )
    else:
        authority = record.path("intermediate_dir") or ""
        authority_identity = record.identity("intermediate_identity")  # type: ignore[assignment]
        root_stage = record.path("root_stage")
        if root_stage is not None:
            current_root_stage = _actual(root_stage)
            if current_root_stage is not ABSENT and not _matches(
                current_root_stage, record.identity("root_stage_identity")
            ):
                _die("Sensitive root signing stage identity changed")
        current_authority = _actual(authority)
        if current_authority is not ABSENT and (
            authority_identity is IdentitySentinel.NONE
            or not _matches(current_authority, authority_identity)
        ):
            _die("Intermediate bootstrap authority identity changed")
        active = f"{journal.pki_dir}/state/active-issuer"
        bootstrap = f"{journal.pki_dir}/state/bootstrap-root"
        active_identity = _state_identity(record, "active_identity")
        bootstrap_identity = _state_identity(record, "bootstrap_identity")
        rollback_identity = _state_identity(record, "bootstrap_rollback_identity")
        _allowed_state(
            active,
            "Active issuer manifest",
            IdentitySentinel.ABSENT,
            active_identity,
        )
        _allowed_state(
            bootstrap,
            "Bootstrap root manifest",
            IdentitySentinel.ABSENT,
            bootstrap_identity,
            rollback_identity,
        )
        bootstrap_stage = f"{transaction_dir}/bootstrap-rollback"
        if _actual(bootstrap) is ABSENT:
            _require_state(
                bootstrap_stage, rollback_identity, "Bootstrap rollback stage"
            )
        if record.root_mutated:
            db_paths, db_backups = _bootstrap_db_paths(record)
            for key in ROOT_DB_KEYS:
                current = _allowed_state(
                    db_paths[key],
                    f"Root {key} state",
                    _state_identity(record, f"root_{key}_pre_identity"),
                    _state_identity(record, f"root_{key}_post_identity"),
                    _state_identity(record, f"root_{key}_backup_identity"),
                )
                pre = _state_identity(record, f"root_{key}_pre_identity")
                post = _state_identity(record, f"root_{key}_post_identity")
                if _matches(current, post) and pre is not IdentitySentinel.ABSENT:
                    _require_state(
                        db_backups[key],
                        _state_identity(record, f"root_{key}_backup_identity"),
                        f"Root {key} rollback copy",
                    )
        if action is RecoveryAction.RESUME:
            if authority_identity is IdentitySentinel.NONE:
                _die("Published intermediate authority is not complete")
            _require_state(authority, authority_identity, "Published intermediate authority")
            _require_state(active, active_identity, "Active issuer manifest")
            _require_state(bootstrap, IdentitySentinel.ABSENT, "Bootstrap root manifest")
            _require_state(
                reservation,
                _state_identity(record, "reservation_consumed_identity"),
                "Consumed intermediate reservation",
            )
            for key in ROOT_DB_KEYS if db_paths else ():
                _require_state(
                    db_paths[key],
                    _state_identity(record, f"root_{key}_post_identity"),
                    f"Published root {key} state",
                )
            if root_stage is not None and _actual(root_stage) is not ABSENT:
                journal.checkpoint("cleanup-pending", fault)
                _remove_tree(
                    root_stage,
                    _tree_identity(record, "root_stage_identity"),
                    "Cannot remove sensitive root signing stage",
                )
            journal.values["recovery_step"] = "cleanup-done"
            journal.write("recovering")
            fault("cleanup-done")
            journal.write("complete", committed=True)
            _marker_cleanup_quirk(marker_path)
            if stage is not None and _actual(stage) is not ABSENT:
                _remove_tree(
                    stage,
                    _tree_identity(record, "stage_identity"),
                    "Cannot remove intermediate bootstrap staging",
                )
            return (
                "Completed sensitive-stage cleanup for intermediate bootstrap "
                f"transaction: {transaction}"
            )

        current_active = _actual(active)
        if current_active is not ABSENT:
            if not isinstance(current_active, FileIdentity):
                _die("Active issuer manifest identity changed")
            journal.checkpoint(
                "rollback-active-pending", fault, action=RecoveryAction.ROLLBACK
            )
            _remove_file(active, active_identity, "Active issuer manifest")  # type: ignore[arg-type]
            journal.checkpoint(
                "rollback-active-done", fault, action=RecoveryAction.ROLLBACK
            )
        if _actual(bootstrap) is ABSENT:
            journal.checkpoint(
                "rollback-bootstrap-pending", fault, action=RecoveryAction.ROLLBACK
            )
            _publish_file(
                bootstrap_stage,
                bootstrap,
                rollback_identity,  # type: ignore[arg-type]
                IdentitySentinel.ABSENT,
            )
            journal.checkpoint(
                "rollback-bootstrap-done", fault, action=RecoveryAction.ROLLBACK
            )
        for key in ROOT_DB_KEYS if db_paths else ():
            current = _actual(db_paths[key])
            pre = _state_identity(record, f"root_{key}_pre_identity")
            post = _state_identity(record, f"root_{key}_post_identity")
            if _matches(current, post) and pre != post:
                journal.checkpoint(
                    f"rollback-root-{key}-pending",
                    fault,
                    action=RecoveryAction.ROLLBACK,
                )
                if pre is IdentitySentinel.ABSENT:
                    assert isinstance(current, FileIdentity)
                    _remove_file(db_paths[key], current, f"Root {key}")
                else:
                    _publish_file(
                        db_backups[key],
                        db_paths[key],
                        _file_identity(record, f"root_{key}_backup_identity"),
                        _file_identity(record, f"root_{key}_post_identity"),
                    )
                journal.checkpoint(
                    f"rollback-root-{key}-done",
                    fault,
                    action=RecoveryAction.ROLLBACK,
                )

    if _actual(authority) is not ABSENT:
        if authority_identity is IdentitySentinel.NONE:
            _die("Journaled bootstrap authority identity is missing")
        journal.checkpoint(
            "rollback-authority-pending", fault, action=RecoveryAction.ROLLBACK
        )
        _remove_tree(
            authority,
            authority_identity,
            "Cannot remove journaled bootstrap authority",
        )
        journal.checkpoint(
            "rollback-authority-done", fault, action=RecoveryAction.ROLLBACK
        )
    if stage is not None and _actual(stage) is not ABSENT:
        journal.checkpoint(
            "rollback-stage-pending", fault, action=RecoveryAction.ROLLBACK
        )
        _remove_tree(
            stage,
            _tree_identity(record, "stage_identity"),
            "Cannot remove journaled bootstrap staging",
        )
        journal.checkpoint(
            "rollback-stage-done", fault, action=RecoveryAction.ROLLBACK
        )
    if not _matches(_actual(reservation), abandoned):
        journal.checkpoint(
            "rollback-reservation-pending", fault, action=RecoveryAction.ROLLBACK
        )
        assert isinstance(abandoned, (FileIdentity, FileObjectState))
        _publish_file(
            abandoned_stage,
            reservation,
            abandoned,
            IdentitySentinel.ABSENT,
            _state_identity(record, "reservation_reserved_identity"),
            _state_identity(record, "reservation_consumed_identity"),
        )
        journal.checkpoint(
            "rollback-reservation-done", fault, action=RecoveryAction.ROLLBACK
        )
    journal.values["reservation_identity"] = record[
        "reservation_abandoned_identity"
    ]
    journal.values["recovery_step"] = "complete"
    journal.write("rolled-back", committed=True)
    _marker_cleanup_quirk(marker_path)
    return f"Rolled back bootstrap transaction: {transaction}"


def _ledger_state(value: str) -> FileObjectState | IdentitySentinel:
    try:
        parsed = parse_file_object_state(
            value,
            allowed_sentinels=frozenset((IdentitySentinel.ABSENT,)),
        )
    except PersistedIdentityError:
        _die("Migration ledger contains an invalid identity")
    assert isinstance(parsed, (FileObjectState, IdentitySentinel))
    return parsed


def _issuer_ledger(data: bytes) -> tuple[tuple[str, FileObjectState | IdentitySentinel, FileObjectState], ...]:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Migration issuer ledger has invalid content")
    records = []
    for line in lines:
        fields = line.split("|")
        if len(fields) != 3 or _SERVICE.fullmatch(fields[0]) is None:
            _die("Migration issuer ledger has invalid content")
        original = _ledger_state(fields[1])
        published = _ledger_state(fields[2])
        if not isinstance(published, FileObjectState):
            _die("Migration issuer ledger has invalid content")
        records.append((fields[0], original, published))
    return tuple(records)


def _quarantine_ledger(data: bytes) -> tuple[tuple[str, FileObjectState], ...]:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Migration quarantine ledger has invalid content")
    records = []
    for line in lines:
        fields = line.split("|")
        if len(fields) != 2 or fields[0] not in _QUARANTINE_NAMES:
            _die("Migration quarantine ledger has invalid content")
        identity = _ledger_state(fields[1])
        if not isinstance(identity, FileObjectState):
            _die("Migration quarantine ledger has invalid content")
        records.append((fields[0], identity))
    return tuple(records)


def _authority_location(
    legacy: str,
    generation: str,
    source_identity: tuple[int, int],
    label: str,
) -> tuple[str, DirectoryIdentity]:
    legacy_state = _actual(legacy)
    generation_state = _actual(generation)
    if (legacy_state is ABSENT) == (generation_state is ABSENT):
        _die(f"{label} paths are simultaneously present or absent")
    current = legacy_state if legacy_state is not ABSENT else generation_state
    location = legacy if legacy_state is not ABSENT else generation
    if (
        not isinstance(current, FileIdentity)
        or current.kind != "directory"
        or (current.dev, current.ino) != source_identity
    ):
        suffix = "legacy" if location == legacy else "generation"
        _die(f"{label} {suffix} identity changed")
    return location, current.directory


def _validate_provenance(
    root_path: str,
    root_identity: DirectoryIdentity,
    manifest_path: str,
    manifest_identity: FileIdentity,
    manifest_digest: str,
) -> None:
    parent, name = _parent(root_path)
    try:
        try:
            root = parent.open_directory(name, expected_identity=root_identity)
            try:
                manifest = _opened_file(manifest_path, manifest_identity)
                try:
                    validate_provenance_manifest(
                        root,
                        parent,
                        name,
                        manifest,
                        manifest_identity,
                        manifest_digest,
                    )
                finally:
                    manifest.close()
            finally:
                root.close()
        except FilesystemError:
            _die("Migration provenance manifest identity changed")
        except TreeManifestError as error:
            if str(error) in {
                "tree manifest identity changed",
                "tree manifest digest changed",
            }:
                _die("Migration provenance manifest identity changed")
            _die("Migration provenance contents do not match their manifest")
        except PublicationError:
            _die("Migration provenance contents do not match their manifest")
    finally:
        parent.close()


def _recover_legacy(
    journal: _Journal,
    record: LegacyMigrationRecoveryRecord,
    action: RecoveryAction,
    marker_path: str,
    fault: FaultHook,
) -> str:
    transaction = record["transaction"]
    transaction_dir = record.path("transaction_dir")
    provenance_stage = record.path("provenance_stage")
    provenance_dir = record.path("provenance_dir")
    backup_receipt = record.path("backup_receipt")
    backup_session = record.path("backup_session")
    root_reservation = record.path("root_reservation")
    intermediate_reservation = record.path("intermediate_reservation")
    active = record.path("active_manifest")
    issuer_ledger_path = record.path("issuer_ledger")
    quarantine_ledger_path = record.path("quarantine_ledger")
    legacy_root = record.path("legacy_root")
    legacy_intermediate = record.path("legacy_intermediate")
    new_root = record.path("new_root")
    new_intermediate = record.path("new_intermediate")
    assert all(
        value is not None
        for value in (
            transaction_dir,
            provenance_stage,
            provenance_dir,
            backup_receipt,
            backup_session,
            root_reservation,
            intermediate_reservation,
            active,
            issuer_ledger_path,
            quarantine_ledger_path,
            legacy_root,
            legacy_intermediate,
            new_root,
            new_intermediate,
        )
    )
    try:
        with OpenedDirectory(
            transaction_dir,
            policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700),
            expected_identity=_tree_identity(record, "transaction_identity"),
        ):
            pass
    except FilesystemError:
        _die("Recovery transaction directory is missing, replaced, or unsafe")
    provenance_identity = _tree_identity(record, "provenance_identity")
    stage_exists = _matches(_actual(provenance_stage), provenance_identity)
    final_exists = _matches(_actual(provenance_dir), provenance_identity)
    provenance_removed = (
        record.recovery_action is RecoveryAction.ROLLBACK
        and (record.recovery_step or "").startswith("rollback-provenance-")
        and _actual(provenance_stage) is ABSENT
        and _actual(provenance_dir) is ABSENT
    )
    if not ((stage_exists != final_exists) or provenance_removed):
        _die("Migration provenance is missing, replaced, or ambiguous")
    if stage_exists:
        provenance_location = provenance_stage
        provenance_manifest = record.path("provenance_manifest")
    elif final_exists:
        provenance_location = provenance_dir
        provenance_manifest = f"{provenance_dir}/provenance-manifest"
    else:
        provenance_location = provenance_manifest = None
    if provenance_location is not None:
        assert provenance_manifest is not None
        _validate_provenance(
            provenance_location,
            provenance_identity,
            provenance_manifest,
            _file_identity(record, "provenance_manifest_identity"),  # type: ignore[arg-type]
            record["provenance_manifest_sha256"],
        )
    _require_state(
        backup_receipt,
        _file_identity(record, "receipt_identity"),
        "Migration backup receipt",
    )
    issuer_data = _verify_file(
        issuer_ledger_path,
        _file_identity(record, "issuer_ledger_identity"),
        record["issuer_ledger_sha256"],
        "Migration issuer ledger",
    )
    quarantine_data = _verify_file(
        quarantine_ledger_path,
        _file_identity(record, "quarantine_ledger_identity"),
        record["quarantine_ledger_sha256"],
        "Migration quarantine ledger",
    )
    services_path = f"{transaction_dir}/services"
    _verify_file(
        services_path,
        _file_identity(record, "services_identity"),
        record["services_sha256"],
        "Recovery service set",
        changed_message="Recovery service set changed",
    )
    issuers = _issuer_ledger(issuer_data)
    quarantine = _quarantine_ledger(quarantine_data)

    root_location, root_directory_identity = _authority_location(
        legacy_root,
        new_root,
        record.root_source_identity,
        "Root authority",
    )
    intermediate_location, intermediate_directory_identity = _authority_location(
        legacy_intermediate,
        new_intermediate,
        record.intermediate_source_identity,
        "Intermediate authority",
    )
    root_config = f"{root_location}/openssl.cnf"
    intermediate_config = f"{intermediate_location}/openssl.cnf"
    for path, label, prefix in (
        (root_config, "Root OpenSSL configuration", "root_config"),
        (
            intermediate_config,
            "Intermediate OpenSSL configuration",
            "intermediate_config",
        ),
    ):
        _allowed_state(
            path,
            label,
            _state_identity(record, f"{prefix}_original_identity"),
            _state_identity(record, f"{prefix}_published_identity"),
            _state_identity(record, f"{prefix}_rollback_identity"),
        )
    for path, label, prefix in (
        (root_reservation, "Root reservation", "root_reservation"),
        (
            intermediate_reservation,
            "Intermediate reservation",
            "intermediate_reservation",
        ),
    ):
        _allowed_state(
            path,
            label,
            _state_identity(record, f"{prefix}_original_identity"),
            _state_identity(record, f"{prefix}_reserved_identity"),
            _state_identity(record, f"{prefix}_consumed_identity"),
            _state_identity(record, f"{prefix}_rollback_identity"),
        )
    _allowed_state(
        backup_session,
        "Backup session record",
        _state_identity(record, "backup_session_original_identity"),
        _state_identity(record, "backup_session_published_identity"),
    )
    _allowed_state(
        active,
        "Active issuer manifest",
        _state_identity(record, "active_original_identity"),
        _state_identity(record, "active_published_identity"),
    )
    for service, original, published in issuers:
        _allowed_state(
            f"{journal.pki_dir}/services/{service}/issuer",
            f"Service {service} issuer",
            original,
            published,
        )
    for basename, identity in quarantine:
        source = f"{journal.pki_dir}/{basename}"
        destination = f"{transaction_dir}/quarantine/{basename}"
        if not (
            (_matches(_actual(source), identity) and _actual(destination) is ABSENT)
            or (_actual(source) is ABSENT and _matches(_actual(destination), identity))
        ):
            _die(f"Quarantine entry is ambiguous or replaced: {basename}")

    if action is RecoveryAction.ROLLBACK:
        if _matches(
            _actual(root_config),
            _state_identity(record, "root_config_published_identity"),
        ):
            _require_state(
                f"{transaction_dir}/root-openssl.rollback",
                _state_identity(record, "root_config_rollback_identity"),
                "Root OpenSSL rollback stage",
            )
        if _matches(
            _actual(intermediate_config),
            _state_identity(record, "intermediate_config_published_identity"),
        ):
            _require_state(
                f"{transaction_dir}/intermediate-openssl.rollback",
                _state_identity(record, "intermediate_config_rollback_identity"),
                "Intermediate OpenSSL rollback stage",
            )
        for path, prefix, stage_name, label in (
            (root_reservation, "root_reservation", "root-abandoned.publish", "Root abandoned reservation stage"),
            (intermediate_reservation, "intermediate_reservation", "intermediate-abandoned.publish", "Intermediate abandoned reservation stage"),
        ):
            rollback = _state_identity(record, f"{prefix}_rollback_identity")
            if not _matches(_actual(path), rollback):
                _require_state(f"{transaction_dir}/{stage_name}", rollback, label)
    else:
        if _matches(
            _actual(backup_session),
            _state_identity(record, "backup_session_original_identity"),
        ):
            _require_state(
                f"{transaction_dir}/backup-session.publish",
                _state_identity(record, "backup_session_published_identity"),
                "Staged backup session",
            )
        for prefix, path, reserved_stage, consumed_stage in (
            ("root_reservation", root_reservation, "root-reserved.publish", "root-consumed.publish"),
            ("intermediate_reservation", intermediate_reservation, "intermediate-reserved.publish", "intermediate-consumed.publish"),
        ):
            original = _state_identity(record, f"{prefix}_original_identity")
            consumed = _state_identity(record, f"{prefix}_consumed_identity")
            if _matches(_actual(path), original):
                _require_state(
                    f"{transaction_dir}/{reserved_stage}",
                    _state_identity(record, f"{prefix}_reserved_identity"),
                    "Staged reserved generation",
                )
            if not _matches(_actual(path), consumed):
                _require_state(
                    f"{transaction_dir}/{consumed_stage}",
                    consumed,
                    "Staged consumed generation",
                )
        for path, prefix, stage_name, label in (
            (root_config, "root_config", "root-openssl.new", "Staged root generation configuration"),
            (intermediate_config, "intermediate_config", "intermediate-openssl.new", "Staged intermediate generation configuration"),
        ):
            if _matches(
                _actual(path), _state_identity(record, f"{prefix}_original_identity")
            ):
                _require_state(
                    f"{transaction_dir}/{stage_name}",
                    _state_identity(record, f"{prefix}_published_identity"),
                    label,
                )
        for service, original, published in issuers:
            if _matches(
                _actual(f"{journal.pki_dir}/services/{service}/issuer"), original
            ):
                _require_state(
                    f"{transaction_dir}/issuer-stage/{service}",
                    published,
                    f"Staged issuer {service}",
                )
        if _matches(
            _actual(active), _state_identity(record, "active_original_identity")
        ):
            _require_state(
                f"{transaction_dir}/active.publish",
                _state_identity(record, "active_published_identity"),
                "Staged active issuer",
            )

    journal.values.update(
        recovery_action=action.value,
        recovery_step=record.recovery_step or "none",
    )
    if action is RecoveryAction.ROLLBACK:
        current_active = _actual(active)
        if _matches(
            current_active, _state_identity(record, "active_published_identity")
        ):
            assert isinstance(current_active, FileIdentity)
            journal.checkpoint("rollback-active-pending", fault, action=action)
            _remove_file(active, current_active, "Active issuer manifest")
            journal.checkpoint("rollback-active-done", fault, action=action)
        for service, _original, published in issuers:
            issuer = f"{journal.pki_dir}/services/{service}/issuer"
            current = _actual(issuer)
            if _matches(current, published):
                assert isinstance(current, FileIdentity)
                journal.checkpoint(f"rollback-issuer-{service}-pending", fault, action=action)
                _remove_file(issuer, current, f"Journaled issuer {service}")
                journal.checkpoint(f"rollback-issuer-{service}-done", fault, action=action)
        for basename, identity in quarantine:
            source = f"{journal.pki_dir}/{basename}"
            destination = f"{transaction_dir}/quarantine/{basename}"
            if _matches(_actual(destination), identity):
                journal.checkpoint(f"rollback-quarantine-{basename}-pending", fault, action=action)
                _move_file(destination, source, identity)
                journal.checkpoint(f"rollback-quarantine-{basename}-done", fault, action=action)
        for location, label, prefix, stage_name in (
            (root_location, "root", "root_config", "root-openssl.rollback"),
            (intermediate_location, "intermediate", "intermediate_config", "intermediate-openssl.rollback"),
        ):
            path = f"{location}/openssl.cnf"
            if _matches(
                _actual(path), _state_identity(record, f"{prefix}_published_identity")
            ):
                journal.checkpoint(f"rollback-config-{label}-pending", fault, action=action)
                _publish_file(
                    f"{transaction_dir}/{stage_name}",
                    path,
                    _file_identity(record, f"{prefix}_rollback_identity"),
                    _file_identity(record, f"{prefix}_published_identity"),
                )
                journal.checkpoint(f"rollback-config-{label}-done", fault, action=action)
        intermediate_location, intermediate_directory_identity = _authority_location(
            legacy_intermediate,
            new_intermediate,
            record.intermediate_source_identity,
            "Intermediate authority",
        )
        if intermediate_location == new_intermediate:
            journal.checkpoint("rollback-intermediate-rename-pending", fault, action=action)
            _move_tree(new_intermediate, legacy_intermediate, intermediate_directory_identity)
            journal.checkpoint("rollback-intermediate-rename-done", fault, action=action)
        root_location, root_directory_identity = _authority_location(
            legacy_root, new_root, record.root_source_identity, "Root authority"
        )
        if root_location == new_root:
            journal.checkpoint("rollback-root-rename-pending", fault, action=action)
            _move_tree(new_root, legacy_root, root_directory_identity)
            journal.checkpoint("rollback-root-rename-done", fault, action=action)
        for kind, path, prefix, stage_name in (
            ("root", root_reservation, "root_reservation", "root-abandoned.publish"),
            ("intermediate", intermediate_reservation, "intermediate_reservation", "intermediate-abandoned.publish"),
        ):
            rollback = _state_identity(record, f"{prefix}_rollback_identity")
            if not _matches(_actual(path), rollback):
                journal.checkpoint(f"rollback-reservation-{kind}-pending", fault, action=action)
                _publish_file(
                    f"{transaction_dir}/{stage_name}",
                    path,
                    _file_identity(record, f"{prefix}_rollback_identity"),
                    _state_identity(record, f"{prefix}_original_identity"),
                    _state_identity(record, f"{prefix}_reserved_identity"),
                    _state_identity(record, f"{prefix}_consumed_identity"),
                )
                journal.checkpoint(f"rollback-reservation-{kind}-done", fault, action=action)
        current_backup = _actual(backup_session)
        if _matches(
            current_backup,
            _state_identity(record, "backup_session_published_identity"),
        ):
            assert isinstance(current_backup, FileIdentity)
            journal.checkpoint("rollback-backup-session-pending", fault, action=action)
            _remove_file(backup_session, current_backup, "Backup session record")
            journal.checkpoint("rollback-backup-session-done", fault, action=action)
        provenance_remove = provenance_stage if _actual(provenance_stage) is not ABSENT else provenance_dir
        if _actual(provenance_remove) is not ABSENT:
            journal.checkpoint("rollback-provenance-pending", fault, action=action)
            _remove_tree(
                provenance_remove,
                provenance_identity,
                "Cannot remove migration provenance",
            )
            journal.checkpoint("rollback-provenance-done", fault, action=action)
        journal.write("rolled-back", committed=True)
        _marker_cleanup_quirk(marker_path)
        return f"Rolled back migration transaction: {transaction}"

    if _matches(
        _actual(backup_session),
        _state_identity(record, "backup_session_original_identity"),
    ):
        journal.checkpoint("resume-backup-session-pending", fault, action=action)
        _publish_file(
            f"{transaction_dir}/backup-session.publish",
            backup_session,
            _file_identity(record, "backup_session_published_identity"),
            _state_identity(record, "backup_session_original_identity"),
        )
        journal.checkpoint("resume-backup-session-done", fault, action=action)
    for kind, path, prefix, stage_name in (
        ("root", root_reservation, "root_reservation", "root-reserved.publish"),
        ("intermediate", intermediate_reservation, "intermediate_reservation", "intermediate-reserved.publish"),
    ):
        if _matches(
            _actual(path), _state_identity(record, f"{prefix}_original_identity")
        ):
            journal.checkpoint(f"resume-reservation-{kind}-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/{stage_name}",
                path,
                _file_identity(record, f"{prefix}_reserved_identity"),
                _state_identity(record, f"{prefix}_original_identity"),
            )
            journal.checkpoint(f"resume-reservation-{kind}-done", fault, action=action)
    journal.write("reserved")
    root_location, root_directory_identity = _authority_location(
        legacy_root, new_root, record.root_source_identity, "Root authority"
    )
    if root_location == legacy_root:
        journal.checkpoint("resume-root-rename-pending", fault, action=action)
        _move_tree(legacy_root, new_root, root_directory_identity)
        journal.checkpoint("resume-root-rename-done", fault, action=action)
    journal.write("root-renamed")
    intermediate_location, intermediate_directory_identity = _authority_location(
        legacy_intermediate,
        new_intermediate,
        record.intermediate_source_identity,
        "Intermediate authority",
    )
    if intermediate_location == legacy_intermediate:
        journal.checkpoint("resume-intermediate-rename-pending", fault, action=action)
        _move_tree(legacy_intermediate, new_intermediate, intermediate_directory_identity)
        journal.checkpoint("resume-intermediate-rename-done", fault, action=action)
    journal.write("intermediate-renamed")
    for path, label, prefix, stage_name in (
        (f"{new_root}/openssl.cnf", "root", "root_config", "root-openssl.new"),
        (f"{new_intermediate}/openssl.cnf", "intermediate", "intermediate_config", "intermediate-openssl.new"),
    ):
        current = _actual(path)
        original = _state_identity(record, f"{prefix}_original_identity")
        published = _state_identity(record, f"{prefix}_published_identity")
        if _matches(current, original):
            journal.checkpoint(f"resume-config-{label}-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/{stage_name}",
                path,
                _file_identity(record, f"{prefix}_published_identity"),
                _state_identity(record, f"{prefix}_original_identity"),
            )
            journal.checkpoint(f"resume-config-{label}-done", fault, action=action)
        elif not _matches(current, published):
            _die("Generation configuration cannot be resumed from its current identity")
    journal.write("configs-published")
    for service, original, published in issuers:
        issuer = f"{journal.pki_dir}/services/{service}/issuer"
        current = _actual(issuer)
        if _matches(current, original):
            journal.checkpoint(f"resume-issuer-{service}-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/issuer-stage/{service}",
                issuer,
                published,
                original,
            )
            journal.checkpoint(f"resume-issuer-{service}-done", fault, action=action)
        elif not _matches(current, published):
            _die(f"Issuer cannot be resumed from its current identity: {service}")
    journal.write("issuers-published")
    for basename, identity in quarantine:
        source = f"{journal.pki_dir}/{basename}"
        destination = f"{transaction_dir}/quarantine/{basename}"
        if _matches(_actual(source), identity):
            journal.checkpoint(f"resume-quarantine-{basename}-pending", fault, action=action)
            _move_file(source, destination, identity)
            journal.checkpoint(f"resume-quarantine-{basename}-done", fault, action=action)
        elif not _matches(_actual(destination), identity):
            _die(f"Quarantine entry cannot be resumed: {basename}")
    journal.write("quarantined")
    for kind, path, prefix, stage_name in (
        ("root", root_reservation, "root_reservation", "root-consumed.publish"),
        ("intermediate", intermediate_reservation, "intermediate_reservation", "intermediate-consumed.publish"),
    ):
        reserved = _state_identity(record, f"{prefix}_reserved_identity")
        consumed = _state_identity(record, f"{prefix}_consumed_identity")
        if _matches(_actual(path), reserved):
            journal.checkpoint(f"resume-consume-{kind}-pending", fault, action=action)
            _publish_file(
                f"{transaction_dir}/{stage_name}",
                path,
                _file_identity(record, f"{prefix}_consumed_identity"),
                reserved,
            )
            journal.checkpoint(f"resume-consume-{kind}-done", fault, action=action)
        elif not _matches(_actual(path), consumed):
            _die("Reservation cannot be consumed from its current identity")
    journal.write("active-pending")
    active_original = _state_identity(record, "active_original_identity")
    active_published = _state_identity(record, "active_published_identity")
    if _matches(_actual(active), active_original):
        journal.checkpoint("resume-active-pending", fault, action=action)
        _publish_file(
            f"{transaction_dir}/active.publish",
            active,
            _file_identity(record, "active_published_identity"),
            active_original,
        )
        journal.checkpoint("resume-active-done", fault, action=action)
    elif not _matches(_actual(active), active_published):
        _die("Active issuer cannot be resumed from its current identity")
    if _actual(provenance_stage) is not ABSENT:
        journal.checkpoint("resume-provenance-pending", fault, action=action)
        _move_tree(provenance_stage, provenance_dir, provenance_identity)
        journal.checkpoint("resume-provenance-done", fault, action=action)
    journal.write("complete", committed=True)
    _marker_cleanup_quirk(marker_path)
    _remove_tree(
        transaction_dir,
        _tree_identity(record, "transaction_identity"),
        "Cannot remove committed migration transaction staging",
    )
    return f"Resumed migration transaction: {transaction}"


def recover_ca_rollover(
    arguments: ParseResult,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Recover one exact final-Bash CA transaction under the full lock profile."""

    if not isinstance(arguments, ParseResult):
        raise TypeError("arguments must be a ParseResult")
    environment = os.environ if environment is None else environment
    transaction = arguments.values["--transaction"]
    action_text = arguments.values["--action"]
    if not isinstance(transaction, str) or _TRANSACTION.fullmatch(transaction) is None:
        _die("Recovery transaction ID is invalid")
    try:
        action = RecoveryAction(action_text)
    except ValueError:
        _die("Recovery action is invalid")
    if "--yes" not in arguments.provided:
        if not sys.stdin.isatty():
            _die("Recovery requires a TTY or --yes")
        print(
            f"Type recover {transaction} {action.value} to continue: ",
            file=sys.stderr,
            end="",
            flush=True,
        )
        confirmation = sys.stdin.readline().rstrip("\n")
        if confirmation != f"recover {transaction} {action.value}":
            _die("Recovery confirmation did not match")
    paths = resolve_paths(arguments.values, environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    fault = FaultHook(crash_at=environment.get("PLATFORM_PKI_RECOVER_CRASH_AT"))
    journal_path = f"{paths.pki_dir}/state/rollover/journal"
    marker_path = f"{paths.pki_dir}/state/rollover/recovery-required"
    with acquire_operational_locks(paths.pki_dir, "export"):
        if _actual(journal_path) is ABSENT:
            _no_journal_terminal(
                paths.pki_dir,
                transaction,
                action,
                marker_path,
                environment,
            )
            message = f"Completed terminal cleanup for {transaction}"
        else:
            journal, record = _load_journal(
                journal_path, paths.pki_dir, action
            )
            if record["transaction"] != transaction:
                _die("Recovery journal does not describe the requested transaction")
            if isinstance(record, RolloverPrepareRecoveryRecord):
                message = _recover_preparation(
                    journal,
                    record,
                    action,
                    marker_path,
                    fault,
                    environment,
                )
            elif isinstance(
                record,
                (RootBootstrapRecoveryRecord, IntermediateBootstrapRecoveryRecord),
            ):
                message = _recover_bootstrap(
                    journal,
                    record,
                    action,
                    marker_path,
                    fault,
                )
            else:
                assert isinstance(record, LegacyMigrationRecoveryRecord)
                message = _recover_legacy(
                    journal,
                    record,
                    action,
                    marker_path,
                    fault,
                )
    print(f"[OK] {message}")
    return 0
