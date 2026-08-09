"""Structural and semantic models for final Bash CA recovery records."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

from .filesystem import (
    DirectoryIdentity,
    FileIdentity,
    FileObjectState,
    FilePolicy,
    OpenedFile,
)
from .persisted_identity import (
    IdentitySentinel,
    PersistedIdentityError,
    parse_directory_identity,
    parse_file_identity,
    parse_file_object_state,
)


MAX_RECOVERY_RECORD_BYTES = 256 * 1024
ROOT_DB_KEYS = (
    "index",
    "index_attr",
    "serial",
    "crlnumber",
    "index_old",
    "index_attr_old",
    "serial_old",
    "crlnumber_old",
    "newcert",
)


def _fields(value: str) -> tuple[str, ...]:
    return tuple(value.split())


ROOT_BOOTSTRAP_WRITER_FIELDS = _fields("""
schema operation transaction phase generation authority_dir authority_identity
stage_dir stage_identity transaction_dir transaction_identity reservation
reservation_identity reservation_reserved_identity reservation_consumed_identity
reservation_abandoned_identity bootstrap_identity recovery_action recovery_step
committed
""")
ROOT_BOOTSTRAP_RECOVERY_FIELDS = tuple(sorted(ROOT_BOOTSTRAP_WRITER_FIELDS))
INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS = _fields("""
schema operation transaction phase root_generation intermediate_generation
root_dir intermediate_dir intermediate_identity stage_dir stage_identity
root_stage root_stage_identity transaction_dir transaction_identity
bootstrap_fingerprint issued_serial reservation reservation_identity
reservation_reserved_identity reservation_consumed_identity
reservation_abandoned_identity active_identity bootstrap_identity
bootstrap_rollback_identity root_mutated recovery_action recovery_step
""")
INTERMEDIATE_BOOTSTRAP_DB_FIELDS = tuple(
    f"root_{key}_{suffix}"
    for key in ROOT_DB_KEYS
    for suffix in ("pre_identity", "post_identity", "backup_identity")
)
INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS = (
    INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS
    + INTERMEDIATE_BOOTSTRAP_DB_FIELDS
    + ("committed",)
)
INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS = tuple(
    sorted(INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS)
)
LEGACY_MIGRATION_WRITER_FIELDS = _fields("""
schema operation transaction phase legacy_root legacy_intermediate new_root
new_intermediate root_source_identity intermediate_source_identity root_sha256
intermediate_sha256 transaction_dir transaction_identity provenance_stage
provenance_dir provenance_identity provenance_manifest
provenance_manifest_identity provenance_manifest_sha256 receipt_identity
services_sha256 services_identity backup_receipt private_repo backup_session
backup_session_original_identity backup_session_published_identity
root_reservation root_reservation_original_identity
root_reservation_reserved_identity root_reservation_consumed_identity
root_reservation_rollback_identity intermediate_reservation
intermediate_reservation_original_identity
intermediate_reservation_reserved_identity
intermediate_reservation_consumed_identity
intermediate_reservation_rollback_identity root_config_original_identity
root_config_published_identity root_config_rollback_identity
root_config_backup_identity intermediate_config_original_identity
intermediate_config_published_identity intermediate_config_rollback_identity
intermediate_config_backup_identity issuer_ledger issuer_ledger_identity
issuer_ledger_sha256 quarantine_ledger quarantine_ledger_identity
quarantine_ledger_sha256 active_manifest active_original_identity
active_published_identity committed
""")
LEGACY_MIGRATION_RECOVERY_FIELDS = tuple(sorted(LEGACY_MIGRATION_WRITER_FIELDS))
LEGACY_MIGRATION_CHECKPOINT_FIELDS = tuple(
    sorted((*LEGACY_MIGRATION_WRITER_FIELDS, "recovery_action", "recovery_step"))
)
ROLLOVER_PREPARE_BASE_FIELDS = _fields("""
schema operation transaction type phase committed recovery_action recovery_step
terminal_outcome active_root active_intermediate active_manifest active_identity
candidate_root candidate_intermediate candidate_root_dir
candidate_intermediate_dir candidate_root_identity
candidate_intermediate_identity candidate_root_key_identity
candidate_root_cert_identity candidate_root_cert_sha256
candidate_intermediate_key_identity candidate_intermediate_csr_identity
candidate_intermediate_cert_identity candidate_intermediate_cert_sha256
candidate_chain_identity candidate_chain_sha256 candidate_root_tree_manifest
candidate_root_tree_manifest_identity candidate_root_tree_manifest_sha256
candidate_intermediate_tree_manifest candidate_intermediate_tree_manifest_identity
candidate_intermediate_tree_manifest_sha256 root_stage_tree_manifest
root_stage_tree_manifest_identity root_stage_tree_manifest_sha256
stage_tree_manifest stage_tree_manifest_identity stage_tree_manifest_sha256
transaction_tree_manifest transaction_tree_manifest_identity
transaction_tree_manifest_sha256 transaction_tree_manifest_sequence
transaction_tree_manifest_pending transaction_tree_manifest_pending_destination
transaction_tree_manifest_pending_identity transaction_tree_manifest_pending_sha256
transaction_dir transaction_identity stage_dir stage_identity root_stage
root_stage_identity root_stage_private_identity root_stage_key_identity
intermediate_stage_identity intermediate_stage_private_identity long_stage
long_dir long_identity long_manifest_identity long_manifest_sha256
long_tree_manifest long_tree_manifest_identity long_tree_manifest_sha256
trust_snapshot_identity pointer pointer_identity backup_receipt receipt_identity
backup_session backup_session_original_identity backup_session_identity
root_reservation root_reservation_reserved_identity
root_reservation_consumed_identity root_reservation_abandoned_identity
intermediate_reservation intermediate_reservation_reserved_identity
intermediate_reservation_consumed_identity
intermediate_reservation_abandoned_identity root_fingerprint
intermediate_fingerprint root_expiry intermediate_expiry trust_bundle_sha256
trust_snapshot_sha256 trust_source trust_source_identity issued_serial root_mutated
""")
ROLLOVER_PREPARE_ROOT_DB_FIELDS = tuple(
    field
    for key in ROOT_DB_KEYS
    for field in (
        f"root_{key}_pre_identity",
        f"root_{key}_post_identity",
        f"root_{key}_backup_identity",
        f"root_{key}_rollback_identity",
        f"root_{key}_source_identity",
        f"signing_{key}_pre_identity",
        f"signing_{key}_partial_identity",
        f"signing_{key}_was_absent",
    )
)
ROLLOVER_PREPARE_PREPARTIAL_NAMES = _fields("""
trust_snapshot root_stage_key root_stage_cert root_stage_index
root_stage_index_backup root_stage_index_attr root_stage_index_attr_backup
root_stage_serial root_stage_serial_backup root_stage_crlnumber
root_stage_crlnumber_backup root_stage_index_old_backup
root_stage_index_attr_old_backup root_stage_serial_old_backup
root_stage_crlnumber_old_backup candidate_root_key candidate_root_cert
candidate_intermediate_key candidate_intermediate_csr
candidate_intermediate_cert candidate_chain
""")
ROLLOVER_PREPARE_PREPARTIAL_FIELDS = tuple(
    f"{name}_{suffix}"
    for name in ROLLOVER_PREPARE_PREPARTIAL_NAMES
    for suffix in ("pre_identity", "partial_identity")
)
ROLLOVER_PREPARE_DECLARED_FIELDS = tuple(
    sorted(
        ROLLOVER_PREPARE_BASE_FIELDS
        + ROLLOVER_PREPARE_ROOT_DB_FIELDS
        + ROLLOVER_PREPARE_PREPARTIAL_FIELDS
    )
)
# prepare_copy_file adds these keys only after successful copies. Their optional,
# cumulative presence means schema 5 does not have one exact fixed field set.
ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS = tuple(
    sorted(
        f"{name}_identity"
        for name in ROLLOVER_PREPARE_PREPARTIAL_NAMES
        if f"{name}_identity" not in ROLLOVER_PREPARE_DECLARED_FIELDS
    )
)


class RecoveryRecordError(ValueError):
    """A recovery record does not match the frozen final-Bash contract."""


class RecoveryOperation(Enum):
    LEGACY_MIGRATE = "legacy-migrate"
    ROOT_BOOTSTRAP = "root-bootstrap"
    INTERMEDIATE_BOOTSTRAP = "intermediate-bootstrap"
    ROLLOVER_PREPARE = "rollover-prepare"


class RecoveryAction(Enum):
    RESUME = "resume"
    ROLLBACK = "rollback"


class RecoveryRecordOrder(Enum):
    WRITER = "writer"
    C_LOCALE = "c-locale"


class RolloverPreparationType(Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"


class PreparationTerminalOutcome(Enum):
    RESUMED = "resumed"
    ROLLED_BACK = "rolled-back"

    @property
    def action(self) -> RecoveryAction:
        if self is PreparationTerminalOutcome.RESUMED:
            return RecoveryAction.RESUME
        return RecoveryAction.ROLLBACK


class RecoveryIdentityPlaceholder(Enum):
    PENDING = "pending"


ParsedRecoveryIdentity: TypeAlias = (
    DirectoryIdentity
    | FileIdentity
    | FileObjectState
    | IdentitySentinel
    | RecoveryIdentityPlaceholder
)


@dataclass(frozen=True, slots=True)
class GenericRecoveryRecord(Mapping[str, str]):
    _pairs: tuple[tuple[str, str], ...]

    def __getitem__(self, key: str) -> str:
        for field, value in self._pairs:
            if field == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (field for field, _value in self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(field for field, _value in self._pairs)


@dataclass(frozen=True, slots=True)
class RecoveryRecord(GenericRecoveryRecord):
    operation: RecoveryOperation
    schema: int
    order: RecoveryRecordOrder
    recovery_action: RecoveryAction | None

    def to_recovery_bytes(self) -> bytes:
        """Serialize a future recovery rewrite in final Bash C-locale order."""

        data = _serialize_pairs(tuple(sorted(self._pairs)))
        if self.operation is RecoveryOperation.ROLLOVER_PREPARE:
            _parse_rollover_prepare_record(data)
        else:
            parse_recovery_record(data)
        return data


@dataclass(frozen=True, slots=True)
class SemanticRecoveryRecord(Mapping[str, str]):
    """Immutable, filesystem-independent view of a validated recovery journal."""

    record: RecoveryRecord
    pki_dir: str
    committed: bool
    phase: str
    recovery_step: str | None
    identities: tuple[tuple[str, ParsedRecoveryIdentity], ...]
    paths: tuple[tuple[str, str | None], ...]

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)

    @property
    def operation(self) -> RecoveryOperation:
        return self.record.operation

    @property
    def schema(self) -> int:
        return self.record.schema

    @property
    def order(self) -> RecoveryRecordOrder:
        return self.record.order

    @property
    def recovery_action(self) -> RecoveryAction | None:
        return self.record.recovery_action

    def identity(self, field: str) -> ParsedRecoveryIdentity:
        for name, identity in self.identities:
            if name == field:
                return identity
        raise KeyError(field)

    def path(self, field: str) -> str | None:
        for name, path in self.paths:
            if name == field:
                return path
        raise KeyError(field)


@dataclass(frozen=True, slots=True)
class RootBootstrapRecoveryRecord(SemanticRecoveryRecord):
    generation: str


@dataclass(frozen=True, slots=True)
class IntermediateBootstrapRecoveryRecord(SemanticRecoveryRecord):
    root_generation: str
    intermediate_generation: str
    root_mutated: bool


@dataclass(frozen=True, slots=True)
class LegacyMigrationRecoveryRecord(SemanticRecoveryRecord):
    root_source_identity: tuple[int, int]
    intermediate_source_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class RolloverPrepareRecoveryRecord(SemanticRecoveryRecord):
    preparation_type: RolloverPreparationType
    terminal_outcome: PreparationTerminalOutcome | None
    active_root: str
    active_intermediate: str
    candidate_root: str
    candidate_intermediate: str
    transaction_manifest_sequence: int
    runtime_identity_fields: tuple[str, ...]


TypedRecoveryRecord: TypeAlias = (
    RootBootstrapRecoveryRecord
    | IntermediateBootstrapRecoveryRecord
    | LegacyMigrationRecoveryRecord
    | RolloverPrepareRecoveryRecord
)


@dataclass(frozen=True, slots=True)
class PreparationTerminalMarker(Mapping[str, str]):
    record: GenericRecoveryRecord
    transaction: str
    outcome: PreparationTerminalOutcome

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)


@dataclass(frozen=True, slots=True)
class PreparationTerminalReceipt(Mapping[str, str]):
    record: GenericRecoveryRecord
    transaction: str
    outcome: PreparationTerminalOutcome
    journal_identity: FileIdentity
    marker_identity: FileIdentity

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)


_KEY = re.compile(rb"[a-z0-9_]+", re.ASCII)
_TRANSACTIONS = {
    RecoveryOperation.LEGACY_MIGRATE: re.compile(
        r"migrate-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII
    ),
    RecoveryOperation.ROOT_BOOTSTRAP: re.compile(
        r"root-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII
    ),
    RecoveryOperation.INTERMEDIATE_BOOTSTRAP: re.compile(
        r"intermediate-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII
    ),
    RecoveryOperation.ROLLOVER_PREPARE: re.compile(
        r"prepare-(?:root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII
    ),
}
_SCHEMAS = {
    RecoveryOperation.LEGACY_MIGRATE: 2,
    RecoveryOperation.ROOT_BOOTSTRAP: 3,
    RecoveryOperation.INTERMEDIATE_BOOTSTRAP: 3,
    RecoveryOperation.ROLLOVER_PREPARE: 5,
}
_ALLOWED_ACTIONS = {
    RecoveryOperation.LEGACY_MIGRATE: frozenset(RecoveryAction),
    RecoveryOperation.ROOT_BOOTSTRAP: frozenset((RecoveryAction.ROLLBACK,)),
    RecoveryOperation.INTERMEDIATE_BOOTSTRAP: frozenset(RecoveryAction),
    RecoveryOperation.ROLLOVER_PREPARE: frozenset(RecoveryAction),
}
_FIELD_ORDERS = {
    RecoveryOperation.LEGACY_MIGRATE: (
        (LEGACY_MIGRATION_WRITER_FIELDS, RecoveryRecordOrder.WRITER),
        (LEGACY_MIGRATION_RECOVERY_FIELDS, RecoveryRecordOrder.C_LOCALE),
        (LEGACY_MIGRATION_CHECKPOINT_FIELDS, RecoveryRecordOrder.C_LOCALE),
    ),
    RecoveryOperation.ROOT_BOOTSTRAP: (
        (ROOT_BOOTSTRAP_WRITER_FIELDS, RecoveryRecordOrder.WRITER),
        (ROOT_BOOTSTRAP_RECOVERY_FIELDS, RecoveryRecordOrder.C_LOCALE),
    ),
    RecoveryOperation.INTERMEDIATE_BOOTSTRAP: (
        (INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS, RecoveryRecordOrder.WRITER),
        (INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS, RecoveryRecordOrder.C_LOCALE),
    ),
}


def _parse_generic(data: bytes) -> GenericRecoveryRecord:
    if not isinstance(data, bytes):
        raise TypeError("recovery record input must be bytes")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise RecoveryRecordError("recovery record must end with exactly one newline")
    pairs: list[tuple[str, str]] = []
    seen: set[bytes] = set()
    for line in data[:-1].split(b"\n"):
        if b"=" not in line:
            raise RecoveryRecordError("recovery record contains a malformed field")
        key, value = line.split(b"=", 1)
        if _KEY.fullmatch(key) is None:
            raise RecoveryRecordError("recovery record contains an invalid field key")
        if key in seen:
            raise RecoveryRecordError("recovery record contains a duplicate field")
        seen.add(key)
        if not value:
            raise RecoveryRecordError("recovery record contains an empty field")
        if any(byte < 0x20 or byte > 0x7E for byte in value):
            raise RecoveryRecordError("recovery record contains a non-canonical value")
        pairs.append((key.decode("ascii"), value.decode("ascii")))
    return GenericRecoveryRecord(tuple(pairs))


def _operation(record: GenericRecoveryRecord) -> RecoveryOperation:
    try:
        raw = record["operation"]
    except KeyError:
        raise RecoveryRecordError("recovery record is missing operation") from None
    try:
        return RecoveryOperation(raw)
    except ValueError:
        raise RecoveryRecordError("recovery record operation is unsupported") from None


def _schema(record: GenericRecoveryRecord) -> int:
    try:
        raw = record["schema"]
    except KeyError:
        raise RecoveryRecordError("recovery record is missing schema") from None
    if (
        re.fullmatch(r"[1-9][0-9]*", raw, re.ASCII) is None
        or len(raw) > 10
        or (len(raw) == 10 and raw > "2147483647")
    ):
        raise RecoveryRecordError("recovery record schema is not canonical")
    return int(raw)


def parse_recovery_action(
    operation: RecoveryOperation,
    value: str,
) -> RecoveryAction:
    if not isinstance(operation, RecoveryOperation):
        raise TypeError("operation must be a RecoveryOperation")
    try:
        action = RecoveryAction(value)
    except (TypeError, ValueError):
        raise RecoveryRecordError("recovery action is unsupported") from None
    if action not in _ALLOWED_ACTIONS[operation]:
        raise RecoveryRecordError("recovery action is invalid for the operation")
    return action


def _record_action(
    record: GenericRecoveryRecord,
    operation: RecoveryOperation,
) -> RecoveryAction | None:
    raw = dict(record._pairs).get("recovery_action")
    if raw is None or raw == "none":
        return None
    return parse_recovery_action(operation, raw)


def parse_recovery_record(data: bytes) -> RecoveryRecord:
    """Parse strict schema-2/3 structure before state-machine validation."""

    generic = _parse_generic(data)
    operation = _operation(generic)
    schema = _schema(generic)
    if operation is RecoveryOperation.ROLLOVER_PREPARE:
        raise RecoveryRecordError("schema-5 typed semantic validation is not implemented")
    if schema != _SCHEMAS[operation]:
        raise RecoveryRecordError("recovery record schema does not match its operation")
    keys = generic.fields
    selected_order = None
    for fields, order in _FIELD_ORDERS[operation]:
        if keys == fields:
            selected_order = order
            break
    if selected_order is None:
        allowed_sets = {
            frozenset(fields) for fields, _order in _FIELD_ORDERS[operation]
        }
        actual = frozenset(keys)
        if actual not in allowed_sets:
            union = frozenset().union(*allowed_sets)
            if actual - union:
                raise RecoveryRecordError("recovery record contains an unexpected field")
            raise RecoveryRecordError("recovery record is missing a required field")
        raise RecoveryRecordError("recovery record fields are not in an accepted order")
    if generic["committed"] not in {"false", "true"}:
        raise RecoveryRecordError("recovery record committed value is invalid")
    if (
        operation is RecoveryOperation.INTERMEDIATE_BOOTSTRAP
        and generic["root_mutated"] not in {"false", "true"}
    ):
        raise RecoveryRecordError("intermediate root_mutated value is invalid")
    if _TRANSACTIONS[operation].fullmatch(generic["transaction"]) is None:
        raise RecoveryRecordError("recovery record transaction is invalid")
    action = _record_action(generic, operation)
    if operation is RecoveryOperation.LEGACY_MIGRATE:
        has_checkpoint_fields = "recovery_action" in generic
        if has_checkpoint_fields != (action is not None):
            raise RecoveryRecordError("legacy recovery checkpoint action is invalid")
    elif action is None and generic["recovery_step"] != "none":
        raise RecoveryRecordError("bootstrap recovery step has no recovery action")
    return RecoveryRecord(generic._pairs, operation, schema, selected_order, action)


def parse_rollover_prepare_structure(data: bytes) -> GenericRecoveryRecord:
    """Parse only the strict generic structure currently safe for schema 5."""

    record = _parse_generic(data)
    operation = _operation(record)
    if operation is not RecoveryOperation.ROLLOVER_PREPARE or _schema(record) != 5:
        raise RecoveryRecordError("record is not a schema-5 rollover preparation journal")
    if record.fields != tuple(sorted(record.fields)):
        raise RecoveryRecordError("schema-5 fields are not in C-locale order")
    try:
        transaction = record["transaction"]
    except KeyError:
        raise RecoveryRecordError("recovery record is missing transaction") from None
    if _TRANSACTIONS[operation].fullmatch(transaction) is None:
        raise RecoveryRecordError("recovery record transaction is invalid")
    return record


def _semantic_error(message: str) -> RecoveryRecordError:
    return RecoveryRecordError(message)


def _canonical_pki_dir(path: os.PathLike[str] | str) -> str:
    value = os.fspath(path)
    if isinstance(value, bytes):
        raise TypeError("pki_dir must be a text path")
    if (
        not value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or "\x00" in value
    ):
        raise RecoveryRecordError("pki_dir must be a canonical absolute path")
    return value


def _path(value: str, field: str, *, optional: bool = False) -> str | None:
    if optional and value == "none":
        return None
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise _semantic_error(f"recovery path {field} is not canonical and absolute")
    return value


def _expect_path(value: str, expected: str, field: str) -> str:
    path = _path(value, field)
    assert path is not None
    if path != expected:
        raise _semantic_error(f"recovery path {field} is outside its contract")
    return path


def _generation(value: str, field: str, *, intermediate: bool = False) -> str:
    pattern = (
        r"g[1-9][0-9]*-i[1-9][0-9]*" if intermediate else r"g[1-9][0-9]*"
    )
    if re.fullmatch(pattern, value, re.ASCII) is None:
        raise _semantic_error(f"recovery generation {field} is invalid")
    return value


def _intermediate_for_root(intermediate: str, root: str, field: str) -> None:
    if not intermediate.startswith(f"{root}-i"):
        raise _semantic_error(f"recovery generation {field} does not belong to {root}")


def _boolean(value: str, field: str) -> bool:
    if value not in {"false", "true"}:
        raise _semantic_error(f"recovery field {field} is not boolean")
    return value == "true"


def _identity(
    value: str,
    field: str,
    kind: str,
    *,
    sentinels: frozenset[IdentitySentinel] = frozenset(),
    pending: bool = False,
) -> ParsedRecoveryIdentity:
    if pending and value == RecoveryIdentityPlaceholder.PENDING.value:
        return RecoveryIdentityPlaceholder.PENDING
    try:
        if kind == "directory":
            return parse_directory_identity(value, allowed_sentinels=sentinels)
        if kind == "file":
            return parse_file_identity(value, allowed_sentinels=sentinels)
        if kind == "object":
            return parse_file_object_state(value, allowed_sentinels=sentinels)
    except PersistedIdentityError as error:
        raise _semantic_error(f"recovery identity {field} is invalid: {error}") from None
    raise AssertionError(f"unsupported recovery identity kind: {kind}")


def _source_identity(value: str, field: str) -> tuple[int, int]:
    match = re.fullmatch(r"(0|[1-9][0-9]*):([1-9][0-9]*)", value, re.ASCII)
    if match is None:
        raise _semantic_error(f"recovery source identity {field} is invalid")
    device, inode = (int(part) for part in match.groups())
    if device > (1 << 64) - 1 or inode > (1 << 64) - 1:
        raise _semantic_error(f"recovery source identity {field} is outside its range")
    return device, inode


def _digest(value: str, field: str, *, allow_none: bool = False) -> None:
    if allow_none and value == "none":
        return
    if re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
        raise _semantic_error(f"recovery digest {field} is invalid")


def _fingerprint(value: str, field: str, *, allow_none: bool = False) -> None:
    if allow_none and value == "none":
        return
    if re.fullmatch(r"[0-9A-F]{64}", value, re.ASCII) is None:
        raise _semantic_error(f"recovery fingerprint {field} is invalid")


def _semantic_base(
    record: RecoveryRecord,
    pki_dir: str,
    identities: dict[str, ParsedRecoveryIdentity],
    paths: dict[str, str | None],
) -> tuple[RecoveryRecord, str, bool, str, str | None, tuple, tuple]:
    step = dict(record._pairs).get("recovery_step", "none")
    return (
        record,
        pki_dir,
        _boolean(record["committed"], "committed"),
        record["phase"],
        None if step == "none" else step,
        tuple(sorted(identities.items())),
        tuple(sorted(paths.items())),
    )


def _validate_root_bootstrap(
    record: RecoveryRecord, pki_dir: str
) -> RootBootstrapRecoveryRecord:
    generation = _generation(record["generation"], "generation")
    transaction = record["transaction"]
    expected_root_parent = os.path.join(pki_dir, "authorities", "roots")
    paths: dict[str, str | None] = {
        "authority_dir": _expect_path(
            record["authority_dir"],
            os.path.join(expected_root_parent, generation),
            "authority_dir",
        ),
        "transaction_dir": _expect_path(
            record["transaction_dir"],
            os.path.join(pki_dir, "state", "rollover", transaction),
            "transaction_dir",
        ),
        "reservation": _expect_path(
            record["reservation"],
            os.path.join(pki_dir, "state", "generation-reservations", generation),
            "reservation",
        ),
    }
    stage = _path(record["stage_dir"], "stage_dir", optional=True)
    paths["stage_dir"] = stage
    both = frozenset((IdentitySentinel.ABSENT, IdentitySentinel.NONE))
    identities = {
        "authority_identity": _identity(
            record["authority_identity"],
            "authority_identity",
            "directory",
            sentinels=frozenset((IdentitySentinel.NONE,)),
        ),
        "stage_identity": _identity(
            record["stage_identity"],
            "stage_identity",
            "directory",
            sentinels=frozenset((IdentitySentinel.NONE,)),
        ),
        "transaction_identity": _identity(
            record["transaction_identity"], "transaction_identity", "directory"
        ),
        "reservation_identity": _identity(
            record["reservation_identity"],
            "reservation_identity",
            "object",
            sentinels=frozenset((IdentitySentinel.ABSENT,)),
        ),
        "reservation_reserved_identity": _identity(
            record["reservation_reserved_identity"],
            "reservation_reserved_identity",
            "object",
        ),
        "reservation_consumed_identity": _identity(
            record["reservation_consumed_identity"],
            "reservation_consumed_identity",
            "object",
            sentinels=frozenset((IdentitySentinel.ABSENT,)),
        ),
        "reservation_abandoned_identity": _identity(
            record["reservation_abandoned_identity"],
            "reservation_abandoned_identity",
            "object",
        ),
        "bootstrap_identity": _identity(
            record["bootstrap_identity"],
            "bootstrap_identity",
            "file",
            sentinels=both,
        ),
    }
    if stage is None and identities["stage_identity"] is not IdentitySentinel.NONE:
        raise _semantic_error("root bootstrap stage identity has no stage path")
    return RootBootstrapRecoveryRecord(
        *_semantic_base(record, pki_dir, identities, paths), generation
    )


def _validate_intermediate_bootstrap(
    record: RecoveryRecord, pki_dir: str
) -> IntermediateBootstrapRecoveryRecord:
    if record.recovery_action is RecoveryAction.RESUME:
        raise _semantic_error(
            "intermediate cleanup persists rollback rather than resume action"
        )
    root = _generation(record["root_generation"], "root_generation")
    intermediate = _generation(
        record["intermediate_generation"],
        "intermediate_generation",
        intermediate=True,
    )
    _intermediate_for_root(intermediate, root, "intermediate_generation")
    transaction = record["transaction"]
    parent = os.path.join(pki_dir, "authorities", "intermediates")
    paths: dict[str, str | None] = {
        "root_dir": _expect_path(
            record["root_dir"],
            os.path.join(pki_dir, "authorities", "roots", root),
            "root_dir",
        ),
        "intermediate_dir": _expect_path(
            record["intermediate_dir"],
            os.path.join(parent, intermediate),
            "intermediate_dir",
        ),
        "transaction_dir": _expect_path(
            record["transaction_dir"],
            os.path.join(pki_dir, "state", "rollover", transaction),
            "transaction_dir",
        ),
        "reservation": _expect_path(
            record["reservation"],
            os.path.join(pki_dir, "state", "generation-reservations", intermediate),
            "reservation",
        ),
    }
    stage = _path(record["stage_dir"], "stage_dir", optional=True)
    paths["stage_dir"] = stage
    root_stage = _path(record["root_stage"], "root_stage", optional=True)
    if root_stage is not None and (stage is None or root_stage != f"{stage}/root"):
        raise _semantic_error("recovery path root_stage is outside its contract")
    paths["root_stage"] = root_stage
    none = frozenset((IdentitySentinel.NONE,))
    absent = frozenset((IdentitySentinel.ABSENT,))
    identities: dict[str, ParsedRecoveryIdentity] = {
        "intermediate_identity": _identity(
            record["intermediate_identity"],
            "intermediate_identity",
            "directory",
            sentinels=none,
        ),
        "stage_identity": _identity(
            record["stage_identity"], "stage_identity", "directory", sentinels=none
        ),
        "root_stage_identity": _identity(
            record["root_stage_identity"],
            "root_stage_identity",
            "directory",
            sentinels=none,
        ),
        "transaction_identity": _identity(
            record["transaction_identity"], "transaction_identity", "directory"
        ),
        "reservation_identity": _identity(
            record["reservation_identity"],
            "reservation_identity",
            "object",
            sentinels=absent,
        ),
        "reservation_reserved_identity": _identity(
            record["reservation_reserved_identity"],
            "reservation_reserved_identity",
            "object",
        ),
        "reservation_consumed_identity": _identity(
            record["reservation_consumed_identity"],
            "reservation_consumed_identity",
            "object",
            sentinels=absent,
        ),
        "reservation_abandoned_identity": _identity(
            record["reservation_abandoned_identity"],
            "reservation_abandoned_identity",
            "object",
        ),
        "active_identity": _identity(
            record["active_identity"],
            "active_identity",
            "file",
            sentinels=absent,
        ),
        "bootstrap_identity": _identity(
            record["bootstrap_identity"],
            "bootstrap_identity",
            "file",
            sentinels=absent,
        ),
        "bootstrap_rollback_identity": _identity(
            record["bootstrap_rollback_identity"],
            "bootstrap_rollback_identity",
            "object",
        ),
    }
    root_mutated = _boolean(record["root_mutated"], "root_mutated")
    for field in INTERMEDIATE_BOOTSTRAP_DB_FIELDS:
        identities[field] = _identity(
            record[field],
            field,
            "object",
            sentinels=absent,
            pending=True,
        )
        if root_mutated and identities[field] is RecoveryIdentityPlaceholder.PENDING:
            raise _semantic_error("mutated intermediate bootstrap has pending root identity")
    if stage is None and identities["stage_identity"] is not IdentitySentinel.NONE:
        raise _semantic_error("intermediate bootstrap stage identity has no stage path")
    if root_stage is None and identities["root_stage_identity"] is not IdentitySentinel.NONE:
        raise _semantic_error("intermediate bootstrap root-stage identity has no path")
    return IntermediateBootstrapRecoveryRecord(
        *_semantic_base(record, pki_dir, identities, paths),
        root,
        intermediate,
        root_mutated,
    )


def _validate_legacy_migration(
    record: RecoveryRecord, pki_dir: str
) -> LegacyMigrationRecoveryRecord:
    transaction = record["transaction"]
    transaction_dir = os.path.join(pki_dir, "state", "rollover", transaction)
    provenance_stage = os.path.join(pki_dir, "legacy", f".{transaction}.publish")
    paths: dict[str, str | None] = {}
    expected = {
        "legacy_root": os.path.join(pki_dir, "root-ca"),
        "legacy_intermediate": os.path.join(pki_dir, "intermediate-ca"),
        "new_root": os.path.join(pki_dir, "authorities", "roots", "g1"),
        "new_intermediate": os.path.join(
            pki_dir, "authorities", "intermediates", "g1-i1"
        ),
        "transaction_dir": transaction_dir,
        "provenance_stage": provenance_stage,
        "provenance_dir": os.path.join(pki_dir, "legacy", transaction),
        "provenance_manifest": os.path.join(
            provenance_stage, "provenance-manifest"
        ),
        "root_reservation": os.path.join(
            pki_dir, "state", "generation-reservations", "g1"
        ),
        "intermediate_reservation": os.path.join(
            pki_dir, "state", "generation-reservations", "g1-i1"
        ),
        "issuer_ledger": os.path.join(transaction_dir, "issuer-identities"),
        "quarantine_ledger": os.path.join(
            transaction_dir, "quarantine-identities"
        ),
        "active_manifest": os.path.join(pki_dir, "state", "active-issuer"),
    }
    for field, value in expected.items():
        paths[field] = _expect_path(record[field], value, field)
    for field in ("backup_receipt", "private_repo"):
        paths[field] = _path(record[field], field)
    backup_session = _path(record["backup_session"], "backup_session")
    prefix = os.path.join(pki_dir, "state", "rollover", "backup-session-")
    if backup_session is None or re.fullmatch(
        re.escape(prefix) + r"[0-9a-f]{32}", backup_session, re.ASCII
    ) is None:
        raise _semantic_error("recovery path backup_session is outside its contract")
    paths["backup_session"] = backup_session
    root_source = _source_identity(
        record["root_source_identity"], "root_source_identity"
    )
    intermediate_source = _source_identity(
        record["intermediate_source_identity"], "intermediate_source_identity"
    )
    _fingerprint(record["root_sha256"], "root_sha256")
    _fingerprint(record["intermediate_sha256"], "intermediate_sha256")
    for field in (
        "provenance_manifest_sha256",
        "services_sha256",
        "issuer_ledger_sha256",
        "quarantine_ledger_sha256",
    ):
        _digest(record[field], field)
    absent = frozenset((IdentitySentinel.ABSENT,))
    identities: dict[str, ParsedRecoveryIdentity] = {
        "transaction_identity": _identity(
            record["transaction_identity"], "transaction_identity", "directory"
        ),
        "provenance_identity": _identity(
            record["provenance_identity"], "provenance_identity", "directory"
        ),
    }
    full_fields = (
        "provenance_manifest_identity",
        "receipt_identity",
        "services_identity",
        "issuer_ledger_identity",
        "quarantine_ledger_identity",
    )
    for field in full_fields:
        identities[field] = _identity(record[field], field, "file")
    object_fields = (
        "backup_session_original_identity",
        "backup_session_published_identity",
        "root_reservation_original_identity",
        "root_reservation_reserved_identity",
        "root_reservation_consumed_identity",
        "root_reservation_rollback_identity",
        "intermediate_reservation_original_identity",
        "intermediate_reservation_reserved_identity",
        "intermediate_reservation_consumed_identity",
        "intermediate_reservation_rollback_identity",
        "root_config_original_identity",
        "root_config_published_identity",
        "root_config_rollback_identity",
        "root_config_backup_identity",
        "intermediate_config_original_identity",
        "intermediate_config_published_identity",
        "intermediate_config_rollback_identity",
        "intermediate_config_backup_identity",
        "active_original_identity",
        "active_published_identity",
    )
    for field in object_fields:
        identities[field] = _identity(
            record[field], field, "object", sentinels=absent
        )
    for field in (
        "backup_session_published_identity",
        "root_reservation_reserved_identity",
        "root_reservation_consumed_identity",
        "root_reservation_rollback_identity",
        "intermediate_reservation_reserved_identity",
        "intermediate_reservation_consumed_identity",
        "intermediate_reservation_rollback_identity",
        "root_config_original_identity",
        "root_config_published_identity",
        "root_config_rollback_identity",
        "root_config_backup_identity",
        "intermediate_config_original_identity",
        "intermediate_config_published_identity",
        "intermediate_config_rollback_identity",
        "intermediate_config_backup_identity",
        "active_published_identity",
    ):
        if identities[field] is IdentitySentinel.ABSENT:
            raise _semantic_error(f"legacy migration identity {field} is missing")
    return LegacyMigrationRecoveryRecord(
        *_semantic_base(record, pki_dir, identities, paths),
        root_source,
        intermediate_source,
    )


_ROLLOVER_DIRECTORY_IDENTITIES = frozenset(
    (
        "candidate_root_identity",
        "candidate_intermediate_identity",
        "transaction_identity",
        "stage_identity",
        "root_stage_identity",
        "root_stage_private_identity",
        "intermediate_stage_identity",
        "intermediate_stage_private_identity",
        "long_identity",
    )
)
_ROLLOVER_OBJECT_IDENTITIES = frozenset(
    (
        "pointer_identity",
        "backup_session_original_identity",
        "backup_session_identity",
        "root_reservation_reserved_identity",
        "root_reservation_consumed_identity",
        "root_reservation_abandoned_identity",
        "intermediate_reservation_reserved_identity",
        "intermediate_reservation_consumed_identity",
        "intermediate_reservation_abandoned_identity",
    )
)
_ROLLOVER_ROOT_DB_IDENTITY_FIELDS = frozenset(
    f"root_{key}_{suffix}_identity"
    for key in ROOT_DB_KEYS
    for suffix in ("pre", "post", "backup", "rollback", "source")
)
_ROLLOVER_NONE_FILE_IDENTITIES = frozenset(ROLLOVER_PREPARE_PREPARTIAL_FIELDS)


def _parse_rollover_prepare_record(data: bytes) -> RecoveryRecord:
    generic = parse_rollover_prepare_structure(data)
    actual = frozenset(generic.fields)
    declared = frozenset(ROLLOVER_PREPARE_DECLARED_FIELDS)
    runtime = frozenset(ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS)
    if actual - declared - runtime:
        raise _semantic_error("schema-5 recovery record contains an unexpected field")
    if not declared <= actual:
        raise _semantic_error("schema-5 recovery record is missing a required field")
    action = _record_action(generic, RecoveryOperation.ROLLOVER_PREPARE)
    return RecoveryRecord(
        generic._pairs,
        RecoveryOperation.ROLLOVER_PREPARE,
        5,
        RecoveryRecordOrder.C_LOCALE,
        action,
    )


def _manifest_triple(
    record: RecoveryRecord,
    path_field: str,
    identity_field: str,
    digest_field: str,
    identities: dict[str, ParsedRecoveryIdentity],
) -> None:
    path = record[path_field]
    identity = record[identity_field]
    digest = record[digest_field]
    if path == "none":
        if identity != "none" or digest != "none":
            raise _semantic_error(f"recovery manifest {path_field} has partial evidence")
        return
    if identity == "none" or digest == "none":
        raise _semantic_error(f"recovery manifest {path_field} has partial evidence")
    identities[identity_field] = _identity(identity, identity_field, "file")
    _digest(digest, digest_field)


def _validate_rollover_prepare(
    record: RecoveryRecord, pki_dir: str
) -> RolloverPrepareRecoveryRecord:
    try:
        preparation_type = RolloverPreparationType(record["type"])
    except ValueError:
        raise _semantic_error("rollover preparation type is invalid") from None
    transaction = record["transaction"]
    expected_transaction_prefix = f"prepare-{preparation_type.value}-"
    if not transaction.startswith(expected_transaction_prefix):
        raise _semantic_error("rollover preparation type does not match its transaction")
    active_root = _generation(record["active_root"], "active_root")
    active_intermediate = _generation(
        record["active_intermediate"], "active_intermediate", intermediate=True
    )
    candidate_root = _generation(record["candidate_root"], "candidate_root")
    candidate_intermediate = _generation(
        record["candidate_intermediate"],
        "candidate_intermediate",
        intermediate=True,
    )
    _intermediate_for_root(active_intermediate, active_root, "active_intermediate")
    _intermediate_for_root(
        candidate_intermediate, candidate_root, "candidate_intermediate"
    )
    if (
        preparation_type is RolloverPreparationType.INTERMEDIATE
        and candidate_root != active_root
    ):
        raise _semantic_error("intermediate rollover candidate root is not active")
    if (
        preparation_type is RolloverPreparationType.ROOT
        and candidate_root == active_root
    ):
        raise _semantic_error("root rollover candidate root is not new")

    transaction_dir = os.path.join(pki_dir, "state", "rollover", transaction)
    long_stage = os.path.join(transaction_dir, "rollover-state")
    stage_dir = _path(record["stage_dir"], "stage_dir", optional=True)
    root_stage = _path(record["root_stage"], "root_stage", optional=True)
    paths: dict[str, str | None] = {
        "active_manifest": _expect_path(
            record["active_manifest"],
            os.path.join(pki_dir, "state", "active-issuer"),
            "active_manifest",
        ),
        "candidate_root_dir": _expect_path(
            record["candidate_root_dir"],
            os.path.join(pki_dir, "authorities", "roots", candidate_root),
            "candidate_root_dir",
        ),
        "candidate_intermediate_dir": _expect_path(
            record["candidate_intermediate_dir"],
            os.path.join(
                pki_dir, "authorities", "intermediates", candidate_intermediate
            ),
            "candidate_intermediate_dir",
        ),
        "transaction_dir": _expect_path(
            record["transaction_dir"], transaction_dir, "transaction_dir"
        ),
        "long_stage": _expect_path(record["long_stage"], long_stage, "long_stage"),
        "long_dir": _expect_path(
            record["long_dir"],
            os.path.join(pki_dir, "state", "rollovers", transaction),
            "long_dir",
        ),
        "pointer": _expect_path(
            record["pointer"],
            os.path.join(pki_dir, "state", "active-rollover"),
            "pointer",
        ),
        "root_reservation": _expect_path(
            record["root_reservation"],
            os.path.join(
                pki_dir, "state", "generation-reservations", candidate_root
            ),
            "root_reservation",
        ),
        "intermediate_reservation": _expect_path(
            record["intermediate_reservation"],
            os.path.join(
                pki_dir,
                "state",
                "generation-reservations",
                candidate_intermediate,
            ),
            "intermediate_reservation",
        ),
        "stage_dir": stage_dir,
        "root_stage": root_stage,
    }
    if stage_dir is not None and stage_dir != os.path.join(transaction_dir, "stage"):
        raise _semantic_error("recovery path stage_dir is outside its contract")
    if root_stage is not None and (
        stage_dir is None or root_stage != os.path.join(stage_dir, "root")
    ):
        raise _semantic_error("recovery path root_stage is outside its contract")
    for field in ("backup_receipt",):
        paths[field] = _path(record[field], field)
    backup_session = _path(record["backup_session"], "backup_session")
    backup_prefix = os.path.join(
        pki_dir, "state", "rollover", "backup-session-"
    )
    if backup_session is None or re.fullmatch(
        re.escape(backup_prefix) + r"[0-9a-f]{32}", backup_session, re.ASCII
    ) is None:
        raise _semantic_error("recovery path backup_session is outside its contract")
    paths["backup_session"] = backup_session

    trust_source = _path(record["trust_source"], "trust_source", optional=True)
    if preparation_type is RolloverPreparationType.INTERMEDIATE:
        if trust_source is not None or record["trust_source_identity"] != "none":
            raise _semantic_error("intermediate rollover has root trust-source evidence")
    elif trust_source is None or record["trust_source_identity"] == "none":
        raise _semantic_error("root rollover lacks trust-source evidence")
    paths["trust_source"] = trust_source

    none = frozenset((IdentitySentinel.NONE,))
    identities: dict[str, ParsedRecoveryIdentity] = {}
    for field in record.fields:
        if field != "active_identity" and not field.endswith("_identity"):
            continue
        if field in _ROLLOVER_DIRECTORY_IDENTITIES:
            identities[field] = _identity(
                record[field], field, "directory", sentinels=none
            )
        elif field in _ROLLOVER_OBJECT_IDENTITIES:
            identities[field] = _identity(
                record[field],
                field,
                "object",
                sentinels=frozenset((IdentitySentinel.ABSENT,)),
            )
        elif field in _ROLLOVER_ROOT_DB_IDENTITY_FIELDS:
            identities[field] = _identity(
                record[field],
                field,
                "file",
                sentinels=frozenset((IdentitySentinel.ABSENT,)),
                pending=True,
            )
        elif field in _ROLLOVER_NONE_FILE_IDENTITIES:
            identities[field] = _identity(
                record[field], field, "file", sentinels=none
            )
        elif field in ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS:
            identities[field] = _identity(record[field], field, "file")
        else:
            identities[field] = _identity(
                record[field], field, "file", sentinels=none
            )
    if identities["active_identity"] is IdentitySentinel.NONE:
        raise _semantic_error("rollover preparation active identity is missing")
    if identities["receipt_identity"] is IdentitySentinel.NONE:
        raise _semantic_error("rollover preparation receipt identity is missing")
    if (
        preparation_type is RolloverPreparationType.ROOT
        and identities["trust_source_identity"] is IdentitySentinel.NONE
    ):
        raise _semantic_error("root rollover trust-source identity is missing")
    if stage_dir is None and identities["stage_identity"] is not IdentitySentinel.NONE:
        raise _semantic_error("rollover stage identity has no stage path")
    if root_stage is None and identities["root_stage_identity"] is not IdentitySentinel.NONE:
        raise _semantic_error("rollover root-stage identity has no path")

    root_mutated = _boolean(record["root_mutated"], "root_mutated")
    for key in ROOT_DB_KEYS:
        _boolean(record[f"signing_{key}_was_absent"], f"signing_{key}_was_absent")
        if root_mutated:
            for suffix in ("pre", "post", "backup", "rollback", "source"):
                if (
                    identities[f"root_{key}_{suffix}_identity"]
                    is RecoveryIdentityPlaceholder.PENDING
                ):
                    raise _semantic_error(
                        "mutated rollover preparation has pending root identity"
                    )

    manifest_paths = {
        "candidate_root_tree_manifest": os.path.join(
            long_stage, "candidate-root-tree.manifest"
        ),
        "candidate_intermediate_tree_manifest": os.path.join(
            long_stage, "candidate-intermediate-tree.manifest"
        ),
        "root_stage_tree_manifest": os.path.join(
            long_stage, "root-signing-stage-tree.manifest"
        ),
        "stage_tree_manifest": os.path.join(transaction_dir, "stage-tree.manifest"),
        "long_tree_manifest": os.path.join(long_stage, "tree.manifest"),
    }
    for field, expected in manifest_paths.items():
        value = _path(record[field], field, optional=True)
        if value is not None and value != expected:
            raise _semantic_error(f"recovery path {field} is outside its contract")
        paths[field] = value
        _manifest_triple(
            record, field, f"{field}_identity", f"{field}_sha256", identities
        )
    if preparation_type is RolloverPreparationType.ROOT:
        if record["root_stage_tree_manifest"] != "none":
            raise _semantic_error("root rollover has a root signing-stage manifest")
    elif record["candidate_root_tree_manifest"] != "none":
        raise _semantic_error("intermediate rollover has a candidate-root manifest")
    if (record["long_manifest_identity"] == "none") != (
        record["long_manifest_sha256"] == "none"
    ):
        raise _semantic_error("rollover long manifest has partial evidence")
    _digest(
        record["long_manifest_sha256"], "long_manifest_sha256", allow_none=True
    )

    sequence_raw = record["transaction_tree_manifest_sequence"]
    if re.fullmatch(r"0|[1-9][0-9]*", sequence_raw, re.ASCII) is None:
        raise _semantic_error("transaction manifest sequence is invalid")
    sequence = int(sequence_raw)
    manifest = _path(
        record["transaction_tree_manifest"],
        "transaction_tree_manifest",
        optional=True,
    )
    if manifest is None:
        if sequence != 0:
            raise _semantic_error("transaction manifest sequence has no manifest")
        if (
            record["transaction_tree_manifest_identity"] != "none"
            or record["transaction_tree_manifest_sha256"] != "none"
        ):
            raise _semantic_error("transaction manifest has partial evidence")
    else:
        match = re.fullmatch(
            re.escape(os.path.dirname(transaction_dir))
            + re.escape(f"/.{transaction}.transaction-tree.")
            + r"([1-9][0-9]*)",
            manifest,
            re.ASCII,
        )
        if match is None or int(match[1]) != sequence:
            raise _semantic_error("transaction manifest path and sequence disagree")
        _digest(
            record["transaction_tree_manifest_sha256"],
            "transaction_tree_manifest_sha256",
        )
        if identities["transaction_tree_manifest_identity"] is IdentitySentinel.NONE:
            raise _semantic_error("transaction manifest identity is missing")
    paths["transaction_tree_manifest"] = manifest
    pending = _path(
        record["transaction_tree_manifest_pending"],
        "transaction_tree_manifest_pending",
        optional=True,
    )
    pending_destination = _path(
        record["transaction_tree_manifest_pending_destination"],
        "transaction_tree_manifest_pending_destination",
        optional=True,
    )
    if pending is None:
        if pending_destination is not None or any(
            record[field] != "none"
            for field in (
                "transaction_tree_manifest_pending_identity",
                "transaction_tree_manifest_pending_sha256",
            )
        ):
            raise _semantic_error("pending transaction manifest has partial evidence")
    else:
        pending_match = re.fullmatch(
            re.escape(os.path.dirname(transaction_dir))
            + re.escape(f"/.{transaction}.transaction-tree.")
            + r"([1-9][0-9]*)",
            pending,
            re.ASCII,
        )
        if pending_match is None or pending_destination != pending:
            raise _semantic_error("pending transaction manifest paths disagree")
        if int(pending_match[1]) != sequence + 1:
            raise _semantic_error("pending transaction manifest sequence is not next")
        _digest(
            record["transaction_tree_manifest_pending_sha256"],
            "transaction_tree_manifest_pending_sha256",
        )
        if (
            identities["transaction_tree_manifest_pending_identity"]
            is IdentitySentinel.NONE
        ):
            raise _semantic_error("pending transaction manifest identity is missing")
    paths["transaction_tree_manifest_pending"] = pending
    paths["transaction_tree_manifest_pending_destination"] = pending_destination

    for field in (
        "candidate_root_cert_sha256",
        "candidate_intermediate_cert_sha256",
        "candidate_chain_sha256",
        "trust_bundle_sha256",
        "trust_snapshot_sha256",
    ):
        _digest(record[field], field, allow_none=True)
    for identity_field, digest_field in (
        ("candidate_root_cert_identity", "candidate_root_cert_sha256"),
        (
            "candidate_intermediate_cert_identity",
            "candidate_intermediate_cert_sha256",
        ),
        ("candidate_chain_identity", "candidate_chain_sha256"),
    ):
        if (record[identity_field] == "none") != (record[digest_field] == "none"):
            raise _semantic_error(f"rollover evidence {identity_field} is partial")
    for field in ("root_fingerprint", "intermediate_fingerprint"):
        _fingerprint(record[field], field, allow_none=True)
    for field in ("root_expiry", "intermediate_expiry"):
        if record[field] != "none" and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            record[field],
            re.ASCII,
        ) is None:
            raise _semantic_error(f"rollover preparation expiry {field} is invalid")

    runtime_fields = tuple(
        field
        for field in ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS
        if field in record
    )
    if preparation_type is RolloverPreparationType.ROOT and runtime_fields:
        raise _semantic_error("root rollover has intermediate copy identities")
    runtime_execution_order = (
        "root_stage_cert_identity",
        "root_stage_index_identity",
        "root_stage_index_backup_identity",
        "root_stage_index_attr_identity",
        "root_stage_index_attr_backup_identity",
        "root_stage_serial_identity",
        "root_stage_serial_backup_identity",
        "root_stage_crlnumber_identity",
        "root_stage_crlnumber_backup_identity",
    )
    present_runtime = frozenset(runtime_fields)
    latest_mandatory = max(
        (
            index
            for index, field in enumerate(runtime_execution_order)
            if field in present_runtime
        ),
        default=-1,
    )
    if any(
        field not in present_runtime
        for field in runtime_execution_order[: latest_mandatory + 1]
    ):
        raise _semantic_error("rollover runtime copy identities are not cumulative")
    optional_runtime = present_runtime - frozenset(runtime_execution_order)
    if optional_runtime and not frozenset(runtime_execution_order) <= present_runtime:
        raise _semantic_error("rollover optional copy identity precedes required copies")
    for field in runtime_fields:
        prefix = field.removesuffix("_identity")
        pre = identities[f"{prefix}_pre_identity"]
        if pre is IdentitySentinel.NONE or pre is RecoveryIdentityPlaceholder.PENDING:
            raise _semantic_error("rollover copied identity lacks pre-copy evidence")

    raw_outcome = record["terminal_outcome"]
    if raw_outcome == "none":
        outcome = None
    else:
        try:
            outcome = PreparationTerminalOutcome(raw_outcome)
        except ValueError:
            raise _semantic_error("rollover terminal outcome is invalid") from None
    committed = _boolean(record["committed"], "committed")
    if committed:
        if outcome is None or record.recovery_action is not outcome.action:
            raise _semantic_error(
                "committed rollover outcome and recovery action do not match"
            )
        if record["phase"] != "terminal-cleanup" or not record[
            "recovery_step"
        ].startswith("terminal-"):
            raise _semantic_error("committed rollover is not in terminal cleanup")
    elif outcome is not None:
        raise _semantic_error("uncommitted rollover has a terminal outcome")
    return RolloverPrepareRecoveryRecord(
        *_semantic_base(record, pki_dir, identities, paths),
        preparation_type,
        outcome,
        active_root,
        active_intermediate,
        candidate_root,
        candidate_intermediate,
        sequence,
        runtime_fields,
    )


def parse_recovery_semantics(
    data: bytes,
    *,
    pki_dir: os.PathLike[str] | str,
    action: RecoveryAction | str | None = None,
) -> TypedRecoveryRecord:
    """Validate one final-Bash journal without reading or changing PKI state."""

    canonical_pki_dir = _canonical_pki_dir(pki_dir)
    generic = _parse_generic(data)
    operation = _operation(generic)
    if operation is RecoveryOperation.ROLLOVER_PREPARE:
        structural = _parse_rollover_prepare_record(data)
        typed: TypedRecoveryRecord = _validate_rollover_prepare(
            structural, canonical_pki_dir
        )
    else:
        structural = parse_recovery_record(data)
        if operation is RecoveryOperation.ROOT_BOOTSTRAP:
            typed = _validate_root_bootstrap(structural, canonical_pki_dir)
        elif operation is RecoveryOperation.INTERMEDIATE_BOOTSTRAP:
            typed = _validate_intermediate_bootstrap(structural, canonical_pki_dir)
        else:
            typed = _validate_legacy_migration(structural, canonical_pki_dir)
    if action is not None:
        validate_recovery_action(typed, action)
    return typed


def validate_recovery_action(
    record: TypedRecoveryRecord, action: RecoveryAction | str
) -> RecoveryAction:
    """Validate a requested final-Bash action against semantic journal state."""

    if not isinstance(record, SemanticRecoveryRecord):
        raise TypeError("record must be a typed semantic recovery record")
    if isinstance(action, str):
        try:
            action = RecoveryAction(action)
        except ValueError:
            raise _semantic_error("recovery action is unsupported") from None
    if not isinstance(action, RecoveryAction):
        raise TypeError("action must be a RecoveryAction or text")
    parse_recovery_action(record.operation, action.value)
    if record.committed and not isinstance(record, RolloverPrepareRecoveryRecord):
        raise _semantic_error("committed recovery journal is not actionable")
    if isinstance(record, IntermediateBootstrapRecoveryRecord) and action is RecoveryAction.RESUME:
        if not (
            record.phase.startswith("cleanup-")
            or (record.recovery_step or "").startswith("cleanup-")
        ):
            raise _semantic_error(
                "intermediate bootstrap resume is limited to cleanup"
            )
    if isinstance(record, RolloverPrepareRecoveryRecord) and record.committed:
        assert record.terminal_outcome is not None
        if action is not record.terminal_outcome.action:
            raise _semantic_error(
                "recovery action does not match the terminal preparation outcome"
            )
    return action


_TERMINAL_MARKER_FIELDS = ("transaction", "operation", "terminal_outcome")
_TERMINAL_RECEIPT_FIELDS = (
    "transaction",
    "operation",
    "terminal_outcome",
    "journal_identity",
    "marker_identity",
)


def _terminal_header(
    record: GenericRecoveryRecord, fields: tuple[str, ...], label: str
) -> tuple[str, PreparationTerminalOutcome]:
    if len(record.fields) != len(fields) or frozenset(record.fields) != frozenset(fields):
        raise _semantic_error(f"preparation terminal {label} fields are invalid")
    if record["operation"] != RecoveryOperation.ROLLOVER_PREPARE.value:
        raise _semantic_error(f"preparation terminal {label} operation is invalid")
    transaction = record["transaction"]
    if _TRANSACTIONS[RecoveryOperation.ROLLOVER_PREPARE].fullmatch(transaction) is None:
        raise _semantic_error(f"preparation terminal {label} transaction is invalid")
    try:
        outcome = PreparationTerminalOutcome(record["terminal_outcome"])
    except ValueError:
        raise _semantic_error(f"preparation terminal {label} outcome is invalid") from None
    return transaction, outcome


def parse_preparation_terminal_marker(data: bytes) -> PreparationTerminalMarker:
    record = _parse_generic(data)
    transaction, outcome = _terminal_header(
        record, _TERMINAL_MARKER_FIELDS, "marker"
    )
    return PreparationTerminalMarker(record, transaction, outcome)


def parse_preparation_terminal_receipt(data: bytes) -> PreparationTerminalReceipt:
    record = _parse_generic(data)
    transaction, outcome = _terminal_header(
        record, _TERMINAL_RECEIPT_FIELDS, "receipt"
    )
    journal = _identity(record["journal_identity"], "journal_identity", "file")
    marker = _identity(record["marker_identity"], "marker_identity", "file")
    assert isinstance(journal, FileIdentity)
    assert isinstance(marker, FileIdentity)
    return PreparationTerminalReceipt(record, transaction, outcome, journal, marker)


def validate_preparation_terminal_records(
    marker: PreparationTerminalMarker,
    receipt: PreparationTerminalReceipt,
    *,
    marker_identity: FileIdentity,
    journal_identity: FileIdentity | None = None,
    transaction: str | None = None,
    action: RecoveryAction | str | None = None,
) -> PreparationTerminalOutcome:
    """Bind terminal marker and receipt values before a later unlink handler."""

    if not isinstance(marker, PreparationTerminalMarker):
        raise TypeError("marker must be a PreparationTerminalMarker")
    if not isinstance(receipt, PreparationTerminalReceipt):
        raise TypeError("receipt must be a PreparationTerminalReceipt")
    if not isinstance(marker_identity, FileIdentity):
        raise TypeError("marker_identity must be a FileIdentity")
    if journal_identity is not None and not isinstance(journal_identity, FileIdentity):
        raise TypeError("journal_identity must be a FileIdentity or None")
    if marker.transaction != receipt.transaction or marker.outcome is not receipt.outcome:
        raise _semantic_error("preparation terminal marker and receipt do not match")
    if receipt.marker_identity != marker_identity:
        raise _semantic_error("preparation terminal marker identity does not match")
    if journal_identity is not None and receipt.journal_identity != journal_identity:
        raise _semantic_error("preparation terminal journal identity does not match")
    if transaction is not None and transaction != marker.transaction:
        raise _semantic_error("preparation terminal transaction does not match")
    if action is not None:
        if isinstance(action, str):
            try:
                action = RecoveryAction(action)
            except ValueError:
                raise _semantic_error("recovery action is unsupported") from None
        if action is not marker.outcome.action:
            raise _semantic_error(
                "recovery action does not match the terminal preparation outcome"
            )
    return marker.outcome


def _serialize_pairs(pairs: tuple[tuple[str, str], ...]) -> bytes:
    return b"".join(f"{key}={value}\n".encode("ascii") for key, value in pairs)


def serialize_recovery_rewrite(values: Mapping[str, str]) -> bytes:
    """Validate and serialize one schema-2/3 rewrite in C-locale key order."""

    if not isinstance(values, Mapping):
        raise TypeError("recovery rewrite values must be a mapping")
    pairs: list[tuple[str, str]] = []
    for key, value in values.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise RecoveryRecordError("recovery rewrite fields must be text")
        pairs.append((key, value))
    try:
        data = _serialize_pairs(tuple(sorted(pairs)))
    except UnicodeEncodeError:
        raise RecoveryRecordError("recovery rewrite contains a non-canonical value") from None
    parse_recovery_record(data)
    return data


def load_recovery_record(
    path: os.PathLike[str] | str,
    *,
    max_bytes: int = MAX_RECOVERY_RECORD_BYTES,
) -> RecoveryRecord:
    """Identity-open and bounded-read one private schema-2/3 recovery journal."""

    data = b""
    with OpenedFile(
        path,
        policy=FilePolicy(
            owner=os.geteuid(),
            mode=0o600,
            links=1,
            max_size=max_bytes,
        ),
    ) as opened:
        data = opened.read(max_bytes)
    return parse_recovery_record(data)


def load_rollover_prepare_structure(
    path: os.PathLike[str] | str,
    *,
    max_bytes: int = MAX_RECOVERY_RECORD_BYTES,
) -> GenericRecoveryRecord:
    """Identity-open and bounded-read schema 5 without claiming typed semantics."""

    data = b""
    with OpenedFile(
        path,
        policy=FilePolicy(
            owner=os.geteuid(),
            mode=0o600,
            links=1,
            max_size=max_bytes,
        ),
    ) as opened:
        data = opened.read(max_bytes)
    return parse_rollover_prepare_structure(data)


def load_recovery_semantics(
    path: os.PathLike[str] | str,
    *,
    pki_dir: os.PathLike[str] | str,
    action: RecoveryAction | str | None = None,
    max_bytes: int = MAX_RECOVERY_RECORD_BYTES,
) -> TypedRecoveryRecord:
    """Identity-open and semantically validate one private recovery journal."""

    data = b""
    with OpenedFile(
        path,
        policy=FilePolicy(
            owner=os.geteuid(),
            mode=0o600,
            links=1,
            max_size=max_bytes,
        ),
    ) as opened:
        data = opened.read(max_bytes)
    return parse_recovery_semantics(data, pki_dir=pki_dir, action=action)
