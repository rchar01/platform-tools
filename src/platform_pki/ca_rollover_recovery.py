"""Behavior-neutral parsing foundation for final Bash CA recovery journals."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum

from .filesystem import FilePolicy, OpenedFile


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
        parse_recovery_record(data)
        return data


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
