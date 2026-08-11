"""Pure schema-1 model for future managed service issue/renew transactions.

This module deliberately performs no filesystem access or mutation.  The schema
is Python-only and forward-only: retained Bash service writers and recovery
tools are not expected to understand a journal emitted from this contract.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import TypeAlias

from .filesystem import DirectoryIdentity, FileIdentity, FileObjectState
from .persisted_identity import (
    IdentitySentinel,
    PersistedIdentityError,
    parse_directory_identity,
    parse_file_identity,
    parse_file_object_state,
)
from .records import OrderedRecord, RecordError, RecordSpec


SERVICE_TRANSACTION_LOCK_PROFILE = (
    "lifecycle",
    "root",
    "intermediate",
    "inventory",
)
SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH = "state/service/recovery-journal"
SERVICE_TRANSACTION_TREE_RELATIVE_PATH = "state/service/transactions"
SERVICE_TRANSACTION_DIRECTORY_MODE = 0o700
SERVICE_TRANSACTION_FILE_MODE = 0o600
SERVICE_TRANSACTION_LINKS = 1
SERVICE_CLEANUP_OWNED_KEYS = ("archive-marker", "stage", "backup")

SERVICE_CONTAINER_ORDER = (
    "service_root",
    "service_private_dir",
    "service_csr_dir",
    "service_certs_dir",
    "service_chain_dir",
)
SERVICE_CA_PUBLICATION_ORDER = (
    "service_config",
    "service_csr",
    "service_certificate",
    "service_chain",
    "service_fullchain",
    "service_issuer",
    "ca_index",
    "ca_index_attr",
    "ca_serial",
    "ca_index_old",
    "ca_index_attr_old",
    "ca_serial_old",
    "ca_newcert",
)
MANAGED_ISSUE_PUBLICATION_ORDER = SERVICE_CA_PUBLICATION_ORDER
MANAGED_RENEW_PUBLICATION_ORDER = SERVICE_CA_PUBLICATION_ORDER
MANAGED_ISSUE_ARCHIVE_MEMBER_ORDER = ("tls.key",)
MANAGED_RENEW_ARCHIVE_MEMBER_ORDER = (
    ".platform-pki-renew-archive",
    "tls.crt",
    "tls.csr",
    "ca-chain.crt",
    "fullchain.crt",
    "openssl.cnf",
    "issuer",
    "tls.key",
)
SERVICE_ISSUE_REPLACE_POLICY = (
    True,
    True,
    False,
    True,
    True,
    False,
    True,
    True,
    True,
    True,
    True,
    True,
    False,
)
SERVICE_RENEW_REPLACE_POLICY = (
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    False,
)

_FILE_MUTATION_KEYS = (
    *SERVICE_CA_PUBLICATION_ORDER,
    "service_key",
    "archive_marker",
    "archive_certificate",
    "archive_csr",
    "archive_chain",
    "archive_fullchain",
    "archive_config",
    "archive_issuer",
    "archive_key",
)
_FILE_MUTATION_SUFFIXES = (
    "destination",
    "pre_identity",
    "pre_sha256",
    "stage",
    "stage_identity",
    "stage_object",
    "stage_sha256",
    "backup",
    "backup_identity",
    "backup_object",
    "backup_sha256",
    "post_identity",
    "post_sha256",
    "rollback_identity",
    "rollback_sha256",
)
_DIRECTORY_MUTATION_KEYS = (
    *SERVICE_CONTAINER_ORDER,
    "archive_root",
    "archive_dir",
)
_DIRECTORY_MUTATION_SUFFIXES = (
    "destination",
    "pre_identity",
    "post_identity",
    "rollback_identity",
)
_MUTATION_KEYS = (*_DIRECTORY_MUTATION_KEYS, *_FILE_MUTATION_KEYS)
SERVICE_CONTINUITY_KEYS = _MUTATION_KEYS
_ARCHIVE_MUTATION_KEYS = (
    "archive_marker",
    "archive_certificate",
    "archive_csr",
    "archive_chain",
    "archive_fullchain",
    "archive_config",
    "archive_issuer",
    "archive_key",
)
_ARCHIVE_EVIDENCE_SUFFIXES = (
    "source",
    "source_identity",
    "source_sha256",
)
SERVICE_SIGNING_INPUT_KEYS = (
    "signing_inventory",
    "signing_root_certificate",
    "signing_ca_key",
    "signing_ca_certificate",
    "signing_ca_config",
    "signing_ca_crlnumber",
    "signing_service_key",
)
_SIGNING_INPUT_SUFFIXES = (
    "source",
    "source_identity",
    "source_sha256",
    "stage",
    "stage_identity",
    "stage_object",
    "stage_sha256",
)
SERVICE_TRANSACTION_PREFIX_FIELDS = (
    "schema",
    "operation",
    "transaction",
    "phase",
    "checkpoint",
    "mutation",
    "committed",
    "recovery_mode",
    "outcome",
    "service",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "key_action",
    "current_key_identity",
    "current_key_sha256",
    "archive_state",
    "archive_name",
    "archive_members",
    "owner",
    "created_epoch",
    "staged_count",
    "backed_up_count",
    "published_count",
    "rollback_count",
    "rollback_completion_count",
    "rollback_completion_path",
    "rollback_completion_identity",
    "rollback_completion_sha256",
    "journal_path",
    "journal_identity",
    "transaction_dir",
    "transaction_identity",
    "transaction_record_path",
    "transaction_record_identity",
    "transaction_record_sha256",
    "stage_dir",
    "stage_dir_identity",
    "inputs_dir",
    "inputs_dir_identity",
    "backup_dir",
    "backup_dir_identity",
    "archive_root_snapshot_identity",
    "archive_root_reference_path",
    "archive_root_reference_identity",
    "archive_root_reference_sha256",
    "archive_root_restored",
    "archive_root_restored_identity",
    "archive_marker_removed",
    "stage_removed",
    "backup_removed",
    "terminal_path",
    "terminal_identity",
    "terminal_sha256",
)
SERVICE_TRANSACTION_FIELDS = SERVICE_TRANSACTION_PREFIX_FIELDS + tuple(
    f"{key}_{suffix}"
    for key in _DIRECTORY_MUTATION_KEYS
    for suffix in _DIRECTORY_MUTATION_SUFFIXES
) + tuple(
    f"{key}_{suffix}"
    for key in _FILE_MUTATION_KEYS
    for suffix in _FILE_MUTATION_SUFFIXES
) + tuple(
    f"{key}_{suffix}"
    for key in _ARCHIVE_MUTATION_KEYS
    for suffix in _ARCHIVE_EVIDENCE_SUFFIXES
) + tuple(
    f"{key}_{suffix}"
    for key in SERVICE_SIGNING_INPUT_KEYS
    for suffix in _SIGNING_INPUT_SUFFIXES
)
SERVICE_TRANSACTION_SPEC = RecordSpec(SERVICE_TRANSACTION_FIELDS, schema="1")

SERVICE_RETAINED_TRANSACTION_FIELDS = (
    "schema",
    "transaction",
    "operation",
    "service",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "key_action",
    "archive_state",
    "archive_name",
    "archive_members",
    "owner",
    "created_epoch",
)
SERVICE_RETAINED_TERMINAL_FIELDS = (
    "schema",
    "transaction",
    "operation",
    "service",
    "outcome",
    "committed",
    "transaction_identity",
    "transaction_sha256",
    "rollback_completion_identity",
    "rollback_completion_sha256",
)
SERVICE_RETAINED_ROLLBACK_FIELDS = (
    "schema",
    "transaction",
    "operation",
    "service",
    "outcome",
    "published_count",
    "completed_count",
    "rollback_order",
    "rollback_evidence_sha256",
)
SERVICE_RETAINED_TRANSACTION_SPEC = RecordSpec(
    SERVICE_RETAINED_TRANSACTION_FIELDS, schema="1"
)
SERVICE_RETAINED_TERMINAL_SPEC = RecordSpec(
    SERVICE_RETAINED_TERMINAL_FIELDS, schema="1"
)
SERVICE_RETAINED_ROLLBACK_SPEC = RecordSpec(
    SERVICE_RETAINED_ROLLBACK_FIELDS, schema="1"
)


class ServiceTransactionError(ValueError):
    """A managed service transaction journal violates the Python contract."""


@dataclass(frozen=True, slots=True)
class ServiceRetainedRecord(Mapping[str, str]):
    record: OrderedRecord

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self):
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


class ServiceOperation(Enum):
    ISSUE = "service-issue"
    RENEW = "service-renew"


class ServicePhase(Enum):
    STAGING = "staging"
    BACKING_UP = "backing-up"
    PLANNED = "planned"
    PUBLISHING = "publishing"
    VERIFYING = "verifying"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling-back"
    CLEANING_UP = "cleaning-up"
    TERMINAL = "terminal"


class ServiceRecoveryMode(Enum):
    ROLLBACK = "rollback"
    CLEANUP_ONLY = "cleanup-only"


class ServiceOutcome(Enum):
    NONE = "none"
    SUCCEEDED = "succeeded"
    FAILED_PRE_COMMIT = "failed-pre-commit"


class ServiceKeyAction(Enum):
    REUSE = "reuse"
    CREATE = "create"
    ROTATE = "rotate"


class ServiceArchiveState(Enum):
    NONE = "none"
    ISSUE_KEY = "issue-key"
    RENEW = "renew"


def service_cleanup_owned_keys(
    operation: ServiceOperation,
    outcome: ServiceOutcome,
) -> tuple[str, ...]:
    """Return every cleanup-owned name applicable to one terminal outcome."""

    if not isinstance(operation, ServiceOperation):
        raise TypeError("operation must be a ServiceOperation")
    if not isinstance(outcome, ServiceOutcome):
        raise TypeError("outcome must be a ServiceOutcome")
    if operation is ServiceOperation.RENEW and outcome is ServiceOutcome.SUCCEEDED:
        return SERVICE_CLEANUP_OWNED_KEYS
    return tuple(key for key in SERVICE_CLEANUP_OWNED_KEYS if key != "archive-marker")


ParsedIdentity: TypeAlias = DirectoryIdentity | FileIdentity | FileObjectState | IdentitySentinel


@dataclass(frozen=True, slots=True)
class ServiceMutation:
    key: str
    destination: str
    pre_identity: ParsedIdentity
    pre_sha256: str | None
    stage: str | None
    stage_identity: ParsedIdentity
    stage_object: ParsedIdentity
    stage_sha256: str | None
    backup: str | None
    backup_identity: ParsedIdentity
    backup_object: ParsedIdentity
    backup_sha256: str | None
    post_identity: ParsedIdentity
    post_sha256: str | None
    rollback_identity: ParsedIdentity
    rollback_sha256: str | None
    replace: bool
    archive_source: str | None
    archive_source_identity: FileIdentity | IdentitySentinel
    archive_source_sha256: str | None


@dataclass(frozen=True, slots=True)
class ServiceSigningInput:
    key: str
    source: str
    source_identity: FileIdentity
    source_sha256: str
    stage: str
    stage_identity: FileIdentity | IdentitySentinel
    stage_object: FileObjectState | IdentitySentinel
    stage_sha256: str | None


@dataclass(frozen=True, slots=True)
class ServiceTransaction(Mapping[str, str]):
    record: OrderedRecord
    pki_dir: str
    operation: ServiceOperation
    phase: ServicePhase
    recovery_mode: ServiceRecoveryMode
    outcome: ServiceOutcome
    key_action: ServiceKeyAction
    archive_state: ServiceArchiveState
    archive_members: tuple[str, ...]
    staging_order: tuple[str, ...]
    backup_order: tuple[str, ...]
    publication_order: tuple[str, ...]
    rollback_order: tuple[str, ...]
    mutations: tuple[ServiceMutation, ...]
    signing_inputs: tuple[ServiceSigningInput, ...]
    identities: tuple[tuple[str, ParsedIdentity], ...]
    paths: tuple[tuple[str, str], ...]

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self):
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()

    def identity(self, field: str) -> ParsedIdentity:
        return dict(self.identities)[field]


_TRANSACTION_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_EPOCH = re.compile(r"0|[1-9][0-9]*", re.ASCII)
_DECIMAL = re.compile(r"0|[1-9][0-9]*", re.ASCII)
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_SERIAL = re.compile(r"(?:[0-9A-F]{2})+", re.ASCII)
_ARCHIVE_NAME = re.compile(r"[0-9]{8}-[0-9]{6}(?:-[0-9]{2})?", re.ASCII)
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_FILE_DESTINATIONS = {
    "service_config": "services/{service}/openssl.cnf",
    "service_csr": "services/{service}/csr/tls.csr",
    "service_certificate": "services/{service}/certs/tls.crt",
    "service_chain": "services/{service}/chain/ca-chain.crt",
    "service_fullchain": "services/{service}/chain/fullchain.crt",
    "service_issuer": "services/{service}/issuer",
    "ca_index": "authorities/intermediates/{intermediate}/index.txt",
    "ca_index_attr": "authorities/intermediates/{intermediate}/index.txt.attr",
    "ca_serial": "authorities/intermediates/{intermediate}/serial",
    "ca_index_old": "authorities/intermediates/{intermediate}/index.txt.old",
    "ca_index_attr_old": "authorities/intermediates/{intermediate}/index.txt.attr.old",
    "ca_serial_old": "authorities/intermediates/{intermediate}/serial.old",
    "ca_newcert": "authorities/intermediates/{intermediate}/newcerts/{serial}.pem",
    "service_key": "services/{service}/private/tls.key",
    "archive_marker": "services/{service}/archive/{archive}/.platform-pki-renew-archive",
    "archive_certificate": "services/{service}/archive/{archive}/tls.crt",
    "archive_csr": "services/{service}/archive/{archive}/tls.csr",
    "archive_chain": "services/{service}/archive/{archive}/ca-chain.crt",
    "archive_fullchain": "services/{service}/archive/{archive}/fullchain.crt",
    "archive_config": "services/{service}/archive/{archive}/openssl.cnf",
    "archive_issuer": "services/{service}/archive/{archive}/issuer",
    "archive_key": "services/{service}/archive/{archive}/tls.key",
}
_DIRECTORY_DESTINATIONS = {
    "service_root": "services/{service}",
    "service_private_dir": "services/{service}/private",
    "service_csr_dir": "services/{service}/csr",
    "service_certs_dir": "services/{service}/certs",
    "service_chain_dir": "services/{service}/chain",
    "archive_root": "services/{service}/archive",
    "archive_dir": "services/{service}/archive/{archive}",
}
_ARCHIVE_MEMBER_KEYS = {
    ".platform-pki-renew-archive": "archive_marker",
    "tls.crt": "archive_certificate",
    "tls.csr": "archive_csr",
    "ca-chain.crt": "archive_chain",
    "fullchain.crt": "archive_fullchain",
    "openssl.cnf": "archive_config",
    "issuer": "archive_issuer",
    "tls.key": "archive_key",
}
_ARCHIVE_SOURCE_KEYS = {
    "archive_certificate": "service_certificate",
    "archive_csr": "service_csr",
    "archive_chain": "service_chain",
    "archive_fullchain": "service_fullchain",
    "archive_config": "service_config",
    "archive_issuer": "service_issuer",
    "archive_key": "service_key",
}
_PRIVATE_PRE_KEYS = frozenset(
    (
        "service_config",
        "service_csr",
        "service_issuer",
        "service_key",
        "ca_index",
        "ca_index_attr",
        "ca_serial",
        "ca_index_old",
        "ca_index_attr_old",
        "ca_serial_old",
    )
)
_FIXED_STAGE_MODES = {
    "service_config": 0o600,
    "service_csr": 0o600,
    "service_certificate": 0o644,
    "service_chain": 0o644,
    "service_fullchain": 0o644,
    "service_issuer": 0o600,
    "service_key": 0o600,
    "ca_index": 0o600,
    "ca_index_attr": 0o600,
    "ca_serial": 0o600,
    "ca_newcert": 0o600,
    "archive_marker": 0o600,
}
_CA_OLD_SOURCE_KEYS = {
    "ca_index_old": "ca_index",
    "ca_index_attr_old": "ca_index_attr",
    "ca_serial_old": "ca_serial",
}
_SIGNING_INPUT_SOURCES = {
    "signing_inventory": "inventory/services.yml",
    "signing_root_certificate": "authorities/roots/{root}/certs/root-ca.crt",
    "signing_ca_key": "authorities/intermediates/{intermediate}/private/intermediate-ca.key",
    "signing_ca_certificate": "authorities/intermediates/{intermediate}/certs/intermediate-ca.crt",
    "signing_ca_config": "authorities/intermediates/{intermediate}/openssl.cnf",
    "signing_ca_crlnumber": "authorities/intermediates/{intermediate}/crlnumber",
    "signing_service_key": "services/{service}/private/tls.key",
}
_PRIVATE_SIGNING_INPUTS = frozenset(
    (
        "signing_ca_key",
        "signing_ca_config",
        "signing_ca_crlnumber",
        "signing_service_key",
    )
)
_EXACT_SIGNING_METADATA_COPIES = frozenset(
    (
        "signing_root_certificate",
        "signing_ca_key",
        "signing_ca_certificate",
        "signing_ca_crlnumber",
    )
)
_NORMALIZED_PRIVATE_COPIES = frozenset(
    ("signing_inventory", "signing_service_key")
)


def managed_publication_order(
    operation: ServiceOperation,
    key_action: ServiceKeyAction,
    archive_state: ServiceArchiveState,
    archive_members: tuple[str, ...],
    *,
    create_archive_root: bool,
    created_service_directories: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return the exact planned mutation order derived from the retained writers."""

    if not isinstance(operation, ServiceOperation):
        raise TypeError("operation must be a ServiceOperation")
    if tuple(
        key for key in SERVICE_CONTAINER_ORDER if key in created_service_directories
    ) != created_service_directories or len(set(created_service_directories)) != len(
        created_service_directories
    ):
        raise ValueError("created service directories are not canonical")
    order: list[str] = list(created_service_directories)
    order.extend(
        MANAGED_ISSUE_PUBLICATION_ORDER
        if operation is ServiceOperation.ISSUE
        else MANAGED_RENEW_PUBLICATION_ORDER
    )
    if key_action in {ServiceKeyAction.CREATE, ServiceKeyAction.ROTATE}:
        order.append("service_key")
    if archive_state is not ServiceArchiveState.NONE:
        if create_archive_root:
            order.append("archive_root")
        order.append("archive_dir")
        order.extend(_ARCHIVE_MEMBER_KEYS[member] for member in archive_members)
    return tuple(order)


def managed_rollback_order(publication_order: tuple[str, ...]) -> tuple[str, ...]:
    """Return the retained Bash rollback order for a published prefix."""

    reverse = tuple(reversed(publication_order))
    ordinary = tuple(
        key
        for key in reverse
        if key not in SERVICE_CONTAINER_ORDER
        and key not in {"archive_root", "archive_dir"}
    )
    archive_containers = tuple(
        key for key in reverse if key in {"archive_root", "archive_dir"}
    )
    service_containers = tuple(
        key for key in reverse if key in SERVICE_CONTAINER_ORDER
    )
    return (*ordinary, *archive_containers, *service_containers)


def _rollback_evidence_digest(
    record: OrderedRecord, rollback_order: tuple[str, ...]
) -> str:
    lines = [
        "schema=1",
        f'transaction={record["transaction"]}',
        f'published_count={record["published_count"]}',
        f'archive_root_restored={record["archive_root_restored"]}',
        f'archive_root_restored_identity={record["archive_root_restored_identity"]}',
    ]
    for index, key in enumerate(rollback_order):
        pre_identity = record[f"{key}_pre_identity"]
        pre_sha256 = (
            record[f"{key}_pre_sha256"]
            if key in _FILE_MUTATION_KEYS
            else "none"
        )
        if pre_identity == "absent":
            restore_object = "absent"
            restore_sha256 = "none"
        else:
            restore_object = record[f"{key}_backup_object"]
            restore_sha256 = record[f"{key}_backup_sha256"]
        lines.extend(
            (
                f"rollback_{index}_key={key}",
                f"rollback_{index}_pre_identity={pre_identity}",
                f"rollback_{index}_pre_sha256={pre_sha256}",
                f"rollback_{index}_restore_object={restore_object}",
                f"rollback_{index}_restore_sha256={restore_sha256}",
            )
        )
    return sha256(("\n".join(lines) + "\n").encode("ascii")).hexdigest()


def _canonical_root(path: os.PathLike[str] | str) -> str:
    value = os.fspath(path)
    if isinstance(value, bytes):
        raise TypeError("pki_dir must be a text path")
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value or "\0" in value:
        raise ServiceTransactionError("pki_dir must be a canonical absolute path")
    return value


def _enum(kind, value: str, field: str):
    try:
        return kind(value)
    except ValueError:
        raise ServiceTransactionError(f"service transaction field {field} is invalid") from None


def _pattern(value: str, pattern: re.Pattern[str], field: str) -> str:
    if pattern.fullmatch(value) is None:
        raise ServiceTransactionError(f"service transaction field {field} is invalid")
    return value


def _serial(value: str, field: str) -> str:
    serial = _pattern(value, _SERIAL, field)
    if len(serial) > 2 and serial.startswith("00"):
        raise ServiceTransactionError(
            f"service transaction field {field} is not a canonical serial"
        )
    return serial


def _boolean(value: str, field: str, *, allow_none: bool = False) -> bool | None:
    if allow_none and value == "none":
        return None
    if value not in {"false", "true"}:
        raise ServiceTransactionError(f"service transaction field {field} is not boolean")
    return value == "true"


def _digest(value: str, field: str, *, allow_none: bool = False) -> str | None:
    if allow_none and value == "none":
        return None
    if _DIGEST.fullmatch(value) is None:
        raise ServiceTransactionError(f"service transaction digest {field} is invalid")
    return value


def _parse_retained(
    data: bytes,
    spec: RecordSpec,
    *,
    terminal: bool,
) -> ServiceRetainedRecord:
    try:
        record = spec.parse(data)
    except RecordError as error:
        raise ServiceTransactionError(str(error)) from None
    transaction_id = record["transaction"].removeprefix("service-")
    _pattern(transaction_id, _TRANSACTION_ID, "transaction")
    if record["transaction"] != f"service-{transaction_id}":
        raise ServiceTransactionError("retained service transaction binding is invalid")
    _enum(ServiceOperation, record["operation"], "operation")
    _pattern(record["service"], _SERVICE, "service")
    if terminal:
        outcome = _enum(ServiceOutcome, record["outcome"], "outcome")
        committed = _boolean(record["committed"], "committed")
        if outcome is ServiceOutcome.NONE or committed != (
            outcome is ServiceOutcome.SUCCEEDED
        ):
            raise ServiceTransactionError("retained service terminal outcome is invalid")
        try:
            transaction_identity = parse_file_identity(record["transaction_identity"])
            rollback_identity = parse_file_identity(
                record["rollback_completion_identity"],
                allowed_sentinels=frozenset((IdentitySentinel.NONE,)),
            )
        except PersistedIdentityError as error:
            raise ServiceTransactionError(str(error)) from None
        assert isinstance(transaction_identity, FileIdentity)
        if (
            transaction_identity.permissions != SERVICE_TRANSACTION_FILE_MODE
            or transaction_identity.links != SERVICE_TRANSACTION_LINKS
            or transaction_identity.kind != "regular"
        ):
            raise ServiceTransactionError(
                "retained service terminal transaction identity is unsafe"
            )
        _digest(record["transaction_sha256"], "transaction_sha256")
        rollback_digest = _digest(
            record["rollback_completion_sha256"],
            "rollback_completion_sha256",
            allow_none=True,
        )
        if outcome is ServiceOutcome.FAILED_PRE_COMMIT:
            if not isinstance(rollback_identity, FileIdentity) or rollback_digest is None:
                raise ServiceTransactionError(
                    "retained service terminal rollback evidence is incomplete"
                )
            if (
                rollback_identity.permissions != SERVICE_TRANSACTION_FILE_MODE
                or rollback_identity.links != SERVICE_TRANSACTION_LINKS
                or rollback_identity.kind != "regular"
            ):
                raise ServiceTransactionError(
                    "retained service terminal rollback identity is unsafe"
                )
        elif rollback_identity is not IdentitySentinel.NONE or rollback_digest is not None:
            raise ServiceTransactionError(
                "retained service terminal has unexpected rollback evidence"
            )
    else:
        root = _pattern(record["issuer_root"], _ROOT_GENERATION, "issuer_root")
        intermediate = _pattern(
            record["issuer_intermediate"],
            _INTERMEDIATE_GENERATION,
            "issuer_intermediate",
        )
        if not intermediate.startswith(f"{root}-i"):
            raise ServiceTransactionError(
                "retained service transaction issuer generations do not match"
            )
        _serial(record["serial"], "serial")
        key_action = _enum(ServiceKeyAction, record["key_action"], "key_action")
        archive_state = _enum(
            ServiceArchiveState, record["archive_state"], "archive_state"
        )
        operation = _enum(ServiceOperation, record["operation"], "operation")
        members = _archive_members(operation, archive_state, record["archive_members"])
        if operation is ServiceOperation.ISSUE:
            expected_archive = (
                ServiceArchiveState.ISSUE_KEY
                if key_action is ServiceKeyAction.ROTATE
                else ServiceArchiveState.NONE
            )
            expected_members = (
                ("tls.key",)
                if expected_archive is ServiceArchiveState.ISSUE_KEY
                else ()
            )
        else:
            if key_action is ServiceKeyAction.CREATE:
                raise ServiceTransactionError(
                    "retained service renewal cannot create a missing key"
                )
            expected_archive = ServiceArchiveState.RENEW
            expected_members = members
            if not members or members[0] != ".platform-pki-renew-archive":
                raise ServiceTransactionError(
                    "retained service renewal archive lacks its marker"
                )
            if (key_action is ServiceKeyAction.ROTATE) != ("tls.key" in members):
                raise ServiceTransactionError(
                    "retained service renewal key archive conflicts with key action"
                )
        if archive_state is not expected_archive or members != expected_members:
            raise ServiceTransactionError(
                "retained service transaction archive state is invalid"
            )
        if archive_state is ServiceArchiveState.NONE:
            if record["archive_name"] != "none":
                raise ServiceTransactionError(
                    "retained non-archiving service transaction has an archive name"
                )
        else:
            _pattern(record["archive_name"], _ARCHIVE_NAME, "archive_name")
        _pattern(record["owner"], _DECIMAL, "owner")
        _pattern(record["created_epoch"], _EPOCH, "created_epoch")
    return ServiceRetainedRecord(record)


def parse_service_retained_transaction(data: bytes) -> ServiceRetainedRecord:
    """Parse one canonical immutable managed-service transaction record."""

    return _parse_retained(
        data, SERVICE_RETAINED_TRANSACTION_SPEC, terminal=False
    )


def parse_service_retained_terminal(data: bytes) -> ServiceRetainedRecord:
    """Parse one canonical immutable managed-service terminal record."""

    return _parse_retained(data, SERVICE_RETAINED_TERMINAL_SPEC, terminal=True)


def parse_service_retained_rollback(data: bytes) -> ServiceRetainedRecord:
    """Parse one canonical immutable managed-service rollback completion."""

    try:
        record = SERVICE_RETAINED_ROLLBACK_SPEC.parse(data)
    except RecordError as error:
        raise ServiceTransactionError(str(error)) from None
    transaction_id = record["transaction"].removeprefix("service-")
    _pattern(transaction_id, _TRANSACTION_ID, "transaction")
    if record["transaction"] != f"service-{transaction_id}":
        raise ServiceTransactionError(
            "retained service rollback transaction binding is invalid"
        )
    _enum(ServiceOperation, record["operation"], "operation")
    _pattern(record["service"], _SERVICE, "service")
    if record["outcome"] != ServiceOutcome.FAILED_PRE_COMMIT.value:
        raise ServiceTransactionError("retained service rollback outcome is invalid")
    published = int(_pattern(record["published_count"], _DECIMAL, "published_count"))
    completed = int(_pattern(record["completed_count"], _DECIMAL, "completed_count"))
    order = (
        ()
        if record["rollback_order"] == "none"
        else tuple(record["rollback_order"].split(","))
    )
    if (
        completed != published
        or len(order) != completed
        or len(set(order)) != len(order)
        or any(key not in SERVICE_CONTINUITY_KEYS for key in order)
        or (not order and record["rollback_order"] != "none")
    ):
        raise ServiceTransactionError(
            "retained service rollback completion is not an exact sequence"
        )
    _digest(record["rollback_evidence_sha256"], "rollback_evidence_sha256")
    return ServiceRetainedRecord(record)


def _serialize_retained(
    values: Mapping[str, str] | ServiceRetainedRecord,
    spec: RecordSpec,
    parser,
) -> bytes:
    source = values.record if isinstance(values, ServiceRetainedRecord) else values
    try:
        data = spec.serialize(source)
    except RecordError as error:
        raise ServiceTransactionError(str(error)) from None
    parser(data)
    return data


def serialize_service_retained_transaction(
    values: Mapping[str, str] | ServiceRetainedRecord,
) -> bytes:
    return _serialize_retained(
        values,
        SERVICE_RETAINED_TRANSACTION_SPEC,
        parse_service_retained_transaction,
    )


def serialize_service_retained_terminal(
    values: Mapping[str, str] | ServiceRetainedRecord,
) -> bytes:
    return _serialize_retained(
        values,
        SERVICE_RETAINED_TERMINAL_SPEC,
        parse_service_retained_terminal,
    )


def serialize_service_retained_rollback(
    values: Mapping[str, str] | ServiceRetainedRecord,
) -> bytes:
    return _serialize_retained(
        values,
        SERVICE_RETAINED_ROLLBACK_SPEC,
        parse_service_retained_rollback,
    )


def _mode_is_safe(mode: int, *, private: bool) -> bool:
    prohibited = 0o077 if private else 0o022
    return mode & prohibited == 0


def _copied_metadata_matches(source: FileIdentity, copy: FileIdentity) -> bool:
    return (
        copy.uid == source.uid
        and copy.permissions == source.permissions
        and copy.size == source.size
        and copy.mtime_ns == source.mtime_ns
    )


def _replace_policy(
    operation: ServiceOperation,
    key_action: ServiceKeyAction,
) -> dict[str, bool]:
    values = (
        SERVICE_ISSUE_REPLACE_POLICY
        if operation is ServiceOperation.ISSUE
        else SERVICE_RENEW_REPLACE_POLICY
    )
    policy: dict[str, bool] = dict(
        zip(SERVICE_CA_PUBLICATION_ORDER, values, strict=True)
    )
    if key_action in {ServiceKeyAction.CREATE, ServiceKeyAction.ROTATE}:
        policy["service_key"] = key_action is ServiceKeyAction.ROTATE
    return policy


def _identity(
    value: str,
    field: str,
    kind: str,
    owner: int,
    *,
    sentinels: frozenset[IdentitySentinel] = frozenset(),
    expected_mode: int | None = None,
    safe_directory: bool = False,
) -> ParsedIdentity:
    try:
        if kind == "directory":
            identity = parse_directory_identity(value, allowed_sentinels=sentinels)
        elif kind == "full-directory":
            identity = parse_file_identity(value, allowed_sentinels=sentinels)
        elif kind == "file":
            identity = parse_file_identity(value, allowed_sentinels=sentinels)
        elif kind == "object":
            identity = parse_file_object_state(value, allowed_sentinels=sentinels)
        else:  # pragma: no cover - internal declaration error
            raise AssertionError(kind)
    except PersistedIdentityError as error:
        raise ServiceTransactionError(
            f"service transaction identity {field} is invalid: {error}"
        ) from None
    if not isinstance(identity, IdentitySentinel):
        if identity.uid != owner:
            raise ServiceTransactionError(f"service transaction identity {field} has the wrong owner")
        if kind in {"directory", "full-directory"}:
            if identity.kind != "directory":
                raise ServiceTransactionError(
                    f"service transaction identity {field} is not a directory"
                )
            if expected_mode is not None and identity.permissions != expected_mode:
                raise ServiceTransactionError(f"service transaction directory {field} has the wrong mode")
            if safe_directory and not _mode_is_safe(
                identity.permissions, private=False
            ):
                raise ServiceTransactionError(
                    f"service transaction directory {field} has an unsafe mode"
                )
        elif identity.kind != "regular" or identity.links != SERVICE_TRANSACTION_LINKS:
            raise ServiceTransactionError(f"service transaction identity {field} is not a single-link file")
        elif expected_mode is not None and identity.permissions != expected_mode:
            raise ServiceTransactionError(
                f"service transaction file {field} has the wrong mode"
            )
    return identity


def _exact_path(value: str, expected: str, field: str) -> str:
    if not os.path.isabs(value) or os.path.normpath(value) != value or value != expected:
        raise ServiceTransactionError(f"service transaction path {field} is outside its contract")
    return value


def _archive_members(
    operation: ServiceOperation,
    archive_state: ServiceArchiveState,
    value: str,
) -> tuple[str, ...]:
    members = () if value == "none" else tuple(value.split(","))
    if not members or any(not member for member in members):
        if archive_state is ServiceArchiveState.NONE and value == "none":
            return ()
        raise ServiceTransactionError("service transaction archive members are invalid")
    expected_order = (
        MANAGED_ISSUE_ARCHIVE_MEMBER_ORDER
        if operation is ServiceOperation.ISSUE
        else MANAGED_RENEW_ARCHIVE_MEMBER_ORDER
    )
    if len(set(members)) != len(members) or tuple(
        member for member in expected_order if member in members
    ) != members:
        raise ServiceTransactionError("service transaction archive members are not canonical")
    return members


def _cleanup_matrix(record: OrderedRecord, operation: ServiceOperation, outcome: ServiceOutcome) -> None:
    archive_marker = _boolean(record["archive_marker_removed"], "archive_marker_removed", allow_none=True)
    stage = _boolean(record["stage_removed"], "stage_removed")
    backup = _boolean(record["backup_removed"], "backup_removed")
    terminal = record["terminal_identity"] != "none"
    checkpoint = record["checkpoint"]
    cleanup_owned = service_cleanup_owned_keys(operation, outcome)
    steps = [*cleanup_owned, "terminal", "journal"]
    if operation is not ServiceOperation.RENEW or outcome is not ServiceOutcome.SUCCEEDED:
        if archive_marker is True:
            raise ServiceTransactionError("archive marker cleanup evidence is not applicable")
    states = {
        "archive-marker": archive_marker is True,
        "stage": stage,
        "backup": backup,
        "terminal": terminal,
    }
    legal: set[tuple[str, tuple[bool, ...]]] = set()
    for index, step in enumerate(steps):
        before = tuple(position < index for position in range(len(steps) - 1))
        if step == "journal":
            legal.add(("journal-cleanup-pending", before))
            continue
        legal.add((f"cleanup-{step}-pending", before))
        legal.add((f"cleanup-{step}-done", tuple(position <= index for position in range(len(steps) - 1))))
    evidence = tuple(states[step] for step in (*cleanup_owned, "terminal"))
    if (checkpoint, evidence) not in legal:
        raise ServiceTransactionError("service transaction cleanup evidence conflicts with checkpoint")


def parse_service_transaction(
    data: bytes,
    *,
    pki_dir: os.PathLike[str] | str,
) -> ServiceTransaction:
    """Parse one canonical journal without consulting live state."""

    try:
        record = SERVICE_TRANSACTION_SPEC.parse(data)
    except RecordError as error:
        raise ServiceTransactionError(str(error)) from None
    root = _canonical_root(pki_dir)
    operation = _enum(ServiceOperation, record["operation"], "operation")
    phase = _enum(ServicePhase, record["phase"], "phase")
    recovery_mode = _enum(ServiceRecoveryMode, record["recovery_mode"], "recovery_mode")
    outcome = _enum(ServiceOutcome, record["outcome"], "outcome")
    key_action = _enum(ServiceKeyAction, record["key_action"], "key_action")
    archive_state = _enum(ServiceArchiveState, record["archive_state"], "archive_state")
    committed = _boolean(record["committed"], "committed")
    if phase in {
        ServicePhase.COMMITTED,
        ServicePhase.CLEANING_UP,
        ServicePhase.TERMINAL,
    } and (
        record["rollback_count"] != "0"
        or any(
            record[f"{key}_rollback_identity"] != "none"
            for key in _MUTATION_KEYS
        )
        or any(
            record[f"{key}_rollback_sha256"] != "none"
            for key in _FILE_MUTATION_KEYS
        )
    ):
        raise ServiceTransactionError(
            "service transaction post-boundary state retains rollback evidence"
        )
    service = _pattern(record["service"], _SERVICE, "service")
    issuer_root = _pattern(record["issuer_root"], _ROOT_GENERATION, "issuer_root")
    intermediate = _pattern(record["issuer_intermediate"], _INTERMEDIATE_GENERATION, "issuer_intermediate")
    if not intermediate.startswith(f"{issuer_root}-i"):
        raise ServiceTransactionError("service transaction issuer generations do not match")
    serial = _serial(record["serial"], "serial")
    owner = int(_pattern(record["owner"], _DECIMAL, "owner"))
    _pattern(record["created_epoch"], _EPOCH, "created_epoch")
    transaction_id = record["transaction"].removeprefix("service-")
    _pattern(transaction_id, _TRANSACTION_ID, "transaction")
    if record["transaction"] != f"service-{transaction_id}":
        raise ServiceTransactionError("service transaction binding is invalid")
    members = _archive_members(operation, archive_state, record["archive_members"])

    if operation is ServiceOperation.ISSUE:
        if key_action not in {ServiceKeyAction.REUSE, ServiceKeyAction.CREATE, ServiceKeyAction.ROTATE}:
            raise ServiceTransactionError("managed issue key action is invalid")
        expected_archive = ServiceArchiveState.ISSUE_KEY if key_action is ServiceKeyAction.ROTATE else ServiceArchiveState.NONE
        expected_members = ("tls.key",) if expected_archive is ServiceArchiveState.ISSUE_KEY else ()
    else:
        if key_action not in {ServiceKeyAction.REUSE, ServiceKeyAction.ROTATE}:
            raise ServiceTransactionError("managed renewal cannot create a missing key")
        expected_archive = ServiceArchiveState.RENEW
        expected_members = members
        if not members or members[0] != ".platform-pki-renew-archive":
            raise ServiceTransactionError("managed renewal archive lacks its marker")
    if archive_state is not expected_archive or members != expected_members:
        raise ServiceTransactionError("service transaction archive state conflicts with operation")
    if archive_state is ServiceArchiveState.NONE:
        if record["archive_name"] != "none":
            raise ServiceTransactionError("non-archiving service transaction has an archive name")
        archive_name = "none"
    else:
        archive_name = _pattern(record["archive_name"], _ARCHIVE_NAME, "archive_name")

    transaction_dir = os.path.join(root, SERVICE_TRANSACTION_TREE_RELATIVE_PATH, record["transaction"])
    stage_dir = os.path.join(transaction_dir, "stage")
    inputs_dir = os.path.join(stage_dir, "inputs")
    backup_dir = os.path.join(transaction_dir, "backup")
    paths = {
        "journal_path": _exact_path(
            record["journal_path"], os.path.join(root, SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH), "journal_path"
        ),
        "transaction_dir": _exact_path(record["transaction_dir"], transaction_dir, "transaction_dir"),
        "transaction_record_path": _exact_path(
            record["transaction_record_path"], os.path.join(transaction_dir, "transaction"), "transaction_record_path"
        ),
        "stage_dir": _exact_path(record["stage_dir"], stage_dir, "stage_dir"),
        "inputs_dir": _exact_path(record["inputs_dir"], inputs_dir, "inputs_dir"),
        "backup_dir": _exact_path(record["backup_dir"], backup_dir, "backup_dir"),
        "terminal_path": _exact_path(record["terminal_path"], os.path.join(transaction_dir, "terminal"), "terminal_path"),
    }
    identities: dict[str, ParsedIdentity] = {}
    identities["journal_identity"] = _identity(
        record["journal_identity"],
        "journal_identity",
        "object",
        owner,
        expected_mode=SERVICE_TRANSACTION_FILE_MODE,
    )
    journal_identity = identities["journal_identity"]
    assert isinstance(journal_identity, FileObjectState)
    if journal_identity.size != len(data):
        raise ServiceTransactionError(
            "service journal object state does not bind canonical bytes"
        )
    for field in (
        "transaction_identity",
        "stage_dir_identity",
        "inputs_dir_identity",
        "backup_dir_identity",
    ):
        identities[field] = _identity(
            record[field],
            field,
            "directory",
            owner,
            expected_mode=SERVICE_TRANSACTION_DIRECTORY_MODE,
        )
    for field in ("transaction_record_identity",):
        identities[field] = _identity(
            record[field],
            field,
            "file",
            owner,
            expected_mode=SERVICE_TRANSACTION_FILE_MODE,
        )
    identities["current_key_identity"] = _identity(
        record["current_key_identity"],
        "current_key_identity",
        "file",
        owner,
        sentinels=frozenset((IdentitySentinel.ABSENT,)),
    )
    current_key = identities["current_key_identity"]
    current_key_sha256 = _digest(
        record["current_key_sha256"],
        "current_key_sha256",
        allow_none=True,
    )
    if (key_action is ServiceKeyAction.CREATE) != (
        current_key is IdentitySentinel.ABSENT
    ) or (current_key is IdentitySentinel.ABSENT) != (
        current_key_sha256 is None
    ):
        raise ServiceTransactionError(
            "service transaction current key evidence conflicts with key action"
        )
    if isinstance(current_key, FileIdentity) and not _mode_is_safe(
        current_key.permissions, private=True
    ):
        raise ServiceTransactionError(
            "service transaction current key permissions are too open"
        )
    retained_transaction = serialize_service_retained_transaction(
        {
            "schema": "1",
            "transaction": record["transaction"],
            "operation": record["operation"],
            "service": service,
            "issuer_root": issuer_root,
            "issuer_intermediate": intermediate,
            "serial": serial,
            "key_action": record["key_action"],
            "archive_state": record["archive_state"],
            "archive_name": record["archive_name"],
            "archive_members": record["archive_members"],
            "owner": record["owner"],
            "created_epoch": record["created_epoch"],
        }
    )
    expected_transaction_sha256 = sha256(retained_transaction).hexdigest()
    if record["transaction_record_sha256"] != expected_transaction_sha256:
        raise ServiceTransactionError(
            "service transaction record digest does not bind canonical bytes"
        )
    transaction_record_identity = identities["transaction_record_identity"]
    assert isinstance(transaction_record_identity, FileIdentity)
    if transaction_record_identity.size != len(retained_transaction):
        raise ServiceTransactionError(
            "service transaction record identity does not bind canonical bytes"
        )
    identities["terminal_identity"] = _identity(
        record["terminal_identity"], "terminal_identity", "file", owner,
        sentinels=frozenset((IdentitySentinel.NONE,)),
        expected_mode=SERVICE_TRANSACTION_FILE_MODE,
    )
    if (record["terminal_identity"] == "none") != (record["terminal_sha256"] == "none"):
        raise ServiceTransactionError("service terminal evidence is incomplete")
    if record["terminal_sha256"] != "none" and _DIGEST.fullmatch(record["terminal_sha256"]) is None:
        raise ServiceTransactionError("service terminal digest is invalid")
    terminal_identity = identities["terminal_identity"]
    if not isinstance(terminal_identity, IdentitySentinel):
        retained_terminal = serialize_service_retained_terminal(
            {
                "schema": "1",
                "transaction": record["transaction"],
                "operation": record["operation"],
                "service": service,
                "outcome": record["outcome"],
                "committed": record["committed"],
                "transaction_identity": record["transaction_record_identity"],
                "transaction_sha256": expected_transaction_sha256,
                "rollback_completion_identity": record[
                    "rollback_completion_identity"
                ],
                "rollback_completion_sha256": record[
                    "rollback_completion_sha256"
                ],
            }
        )
        if record["terminal_sha256"] != sha256(retained_terminal).hexdigest():
            raise ServiceTransactionError(
                "service terminal digest does not bind canonical bytes"
            )
        assert isinstance(terminal_identity, FileIdentity)
        if terminal_identity.size != len(retained_terminal):
            raise ServiceTransactionError(
                "service terminal identity does not bind canonical bytes"
            )
    archive_root = os.path.join(root, "services", service, "archive")
    archive_dir = os.path.join(archive_root, archive_name) if archive_name != "none" else None
    archive_root_pre = _identity(
        record["archive_root_snapshot_identity"], "archive_root_snapshot_identity", "full-directory", owner,
        sentinels=frozenset((IdentitySentinel.ABSENT, IdentitySentinel.NONE)),
        safe_directory=True,
    )
    identities["archive_root_snapshot_identity"] = archive_root_pre
    if archive_state is ServiceArchiveState.NONE:
        if archive_root_pre is not IdentitySentinel.NONE:
            raise ServiceTransactionError("non-archiving transaction has archive identities")

    create_archive_root = archive_root_pre is IdentitySentinel.ABSENT
    archive_root_restore_required = (
        archive_state is not ServiceArchiveState.NONE and not create_archive_root
    )
    if archive_root_restore_required:
        paths["archive_root_reference_path"] = _exact_path(
            record["archive_root_reference_path"],
            os.path.join(transaction_dir, "archive-root-reference"),
            "archive_root_reference_path",
        )
        identities["archive_root_reference_identity"] = _identity(
            record["archive_root_reference_identity"],
            "archive_root_reference_identity",
            "file",
            owner,
            expected_mode=SERVICE_TRANSACTION_FILE_MODE,
        )
        reference = identities["archive_root_reference_identity"]
        assert isinstance(reference, FileIdentity)
        assert isinstance(archive_root_pre, FileIdentity)
        if (
            reference.permissions != SERVICE_TRANSACTION_FILE_MODE
            or reference.size != 0
            or reference.mtime_ns != archive_root_pre.mtime_ns
        ):
            raise ServiceTransactionError(
                "service archive-root reference does not bind original metadata"
            )
        if record["archive_root_reference_sha256"] != _EMPTY_SHA256:
            raise ServiceTransactionError(
                "service archive-root reference digest is invalid"
            )
        archive_root_restored = _boolean(
            record["archive_root_restored"], "archive_root_restored"
        )
        identities["archive_root_restored_identity"] = _identity(
            record["archive_root_restored_identity"],
            "archive_root_restored_identity",
            "full-directory",
            owner,
            sentinels=frozenset((IdentitySentinel.NONE,)),
        )
        restored_identity = identities["archive_root_restored_identity"]
        if archive_root_restored:
            if isinstance(restored_identity, IdentitySentinel):
                raise ServiceTransactionError(
                    "service archive-root restoration lacks exact identity evidence"
                )
            assert isinstance(restored_identity, FileIdentity)
            if (
                restored_identity.directory != archive_root_pre.directory
                or restored_identity.mtime_ns != archive_root_pre.mtime_ns
            ):
                raise ServiceTransactionError(
                    "service archive-root restoration does not match original metadata"
                )
        elif restored_identity is not IdentitySentinel.NONE:
            raise ServiceTransactionError(
                "service archive-root restoration evidence is premature"
            )
    else:
        if (
            record["archive_root_reference_path"] != "none"
            or record["archive_root_reference_identity"] != "none"
            or record["archive_root_reference_sha256"] != "none"
            or record["archive_root_restored"] != "none"
            or record["archive_root_restored_identity"] != "none"
        ):
            raise ServiceTransactionError(
                "service transaction has inapplicable archive-root restoration evidence"
            )
        archive_root_restored = None
    mutations: list[ServiceMutation] = []
    mutation_by_key: dict[str, ServiceMutation] = {}
    replace_policy = _replace_policy(operation, key_action)
    none = frozenset((IdentitySentinel.NONE,))
    absent_none = frozenset((IdentitySentinel.ABSENT, IdentitySentinel.NONE))
    created_service_directories: list[str] = []

    for key in _DIRECTORY_MUTATION_KEYS:
        fields = {
            suffix: record[f"{key}_{suffix}"]
            for suffix in _DIRECTORY_MUTATION_SUFFIXES
        }
        enabled = key in SERVICE_CONTAINER_ORDER or (
            archive_state is not ServiceArchiveState.NONE
            and key in {"archive_root", "archive_dir"}
        )
        if not enabled:
            if set(fields.values()) != {"none"}:
                raise ServiceTransactionError(
                    f"disabled service mutation {key} has evidence"
                )
            continue
        relative = _DIRECTORY_DESTINATIONS[key].format(
            service=service, archive=archive_name
        )
        destination = _exact_path(
            fields["destination"],
            os.path.join(root, relative),
            f"{key}_destination",
        )
        pre = _identity(
            fields["pre_identity"],
            f"{key}_pre_identity",
            "directory",
            owner,
            sentinels=frozenset((IdentitySentinel.ABSENT,)),
            safe_directory=True,
        )
        post = _identity(
            fields["post_identity"],
            f"{key}_post_identity",
            "directory",
            owner,
            sentinels=none,
            safe_directory=True,
        )
        rollback = _identity(
            fields["rollback_identity"],
            f"{key}_rollback_identity",
            "directory",
            owner,
            sentinels=absent_none,
            safe_directory=True,
        )
        if pre is IdentitySentinel.ABSENT:
            if not isinstance(post, IdentitySentinel) and (
                post.permissions != SERVICE_TRANSACTION_DIRECTORY_MODE
            ):
                raise ServiceTransactionError(
                    f"created service directory {key} has the wrong mode"
                )
            if key in SERVICE_CONTAINER_ORDER:
                created_service_directories.append(key)
        else:
            assert isinstance(pre, DirectoryIdentity)
            assert isinstance(post, DirectoryIdentity)
            if post != pre:
                raise ServiceTransactionError(
                    f"existing service directory {key} changed identity"
                )
            if rollback is not IdentitySentinel.NONE:
                raise ServiceTransactionError(
                    f"existing service directory {key} has rollback evidence"
                )
        if key == "archive_root":
            if archive_root_pre is IdentitySentinel.ABSENT:
                expected_pre = IdentitySentinel.ABSENT
            else:
                assert isinstance(archive_root_pre, FileIdentity)
                expected_pre = archive_root_pre.directory
            if pre != expected_pre:
                raise ServiceTransactionError(
                    "service archive-root mutation does not bind its snapshot"
                )
        elif key == "archive_dir" and pre is not IdentitySentinel.ABSENT:
            raise ServiceTransactionError(
                "service archive destination was not preauthorized absent"
            )
        mutation = ServiceMutation(
            key=key,
            destination=destination,
            pre_identity=pre,
            pre_sha256=None,
            stage=None,
            stage_identity=IdentitySentinel.NONE,
            stage_object=IdentitySentinel.NONE,
            stage_sha256=None,
            backup=None,
            backup_identity=IdentitySentinel.NONE,
            backup_object=IdentitySentinel.NONE,
            backup_sha256=None,
            post_identity=post,
            post_sha256=None,
            rollback_identity=rollback,
            rollback_sha256=None,
            replace=False,
            archive_source=None,
            archive_source_identity=IdentitySentinel.NONE,
            archive_source_sha256=None,
        )
        mutations.append(mutation)
        mutation_by_key[key] = mutation

    if (
        mutation_by_key["service_root"].pre_identity is IdentitySentinel.ABSENT
        and any(
            mutation_by_key[key].pre_identity is not IdentitySentinel.ABSENT
            for key in SERVICE_CONTAINER_ORDER[1:]
        )
    ):
        raise ServiceTransactionError(
            "service child directory exists without its parent pre-state"
        )

    publication_order = managed_publication_order(
        operation,
        key_action,
        archive_state,
        members,
        create_archive_root=create_archive_root,
        created_service_directories=tuple(created_service_directories),
    )
    enabled_files = set(publication_order) & set(_FILE_MUTATION_KEYS)
    enabled_input_keys = tuple(
        key
        for key in SERVICE_SIGNING_INPUT_KEYS
        if key != "signing_service_key" or key_action is ServiceKeyAction.REUSE
    )
    enabled_file_order = tuple(
        key for key in publication_order if key in enabled_files
    )
    staging_order = (*enabled_input_keys, *enabled_file_order)
    stage_positions = {key: index for index, key in enumerate(staging_order)}
    staged = int(_pattern(record["staged_count"], _DECIMAL, "staged_count"))
    backed_up = int(
        _pattern(record["backed_up_count"], _DECIMAL, "backed_up_count")
    )
    published = int(_pattern(record["published_count"], _DECIMAL, "published_count"))
    rolled_back = int(_pattern(record["rollback_count"], _DECIMAL, "rollback_count"))
    rollback_completed = int(
        _pattern(
            record["rollback_completion_count"],
            _DECIMAL,
            "rollback_completion_count",
        )
    )
    if (
        staged > len(staging_order)
        or published > len(publication_order)
        or rolled_back > published
        or rollback_completed > published
    ):
        raise ServiceTransactionError("service transaction mutation counts are invalid")
    backup_order: list[str] = []
    for key in _FILE_MUTATION_KEYS:
        fields = {
            suffix: record[f"{key}_{suffix}"]
            for suffix in _FILE_MUTATION_SUFFIXES
        }
        archive_fields = (
            {
                suffix: record[f"{key}_{suffix}"]
                for suffix in _ARCHIVE_EVIDENCE_SUFFIXES
            }
            if key in _ARCHIVE_MUTATION_KEYS
            else {}
        )
        if key not in enabled_files:
            if set(fields.values()) != {"none"} or (
                archive_fields and set(archive_fields.values()) != {"none"}
            ):
                raise ServiceTransactionError(f"disabled service mutation {key} has evidence")
            continue
        relative = _FILE_DESTINATIONS[key].format(
            service=service,
            intermediate=intermediate,
            serial=serial,
            archive=archive_name,
        )
        expected_destination = os.path.join(root, relative)
        destination = _exact_path(fields["destination"], expected_destination, f"{key}_destination")
        pre = _identity(
            fields["pre_identity"],
            f"{key}_pre_identity",
            "file",
            owner,
            sentinels=frozenset((IdentitySentinel.ABSENT,)),
        )
        if key in {"ca_index", "ca_index_attr", "ca_serial"} and (
            pre is IdentitySentinel.ABSENT
        ):
            raise ServiceTransactionError(
                f"service transaction required CA state {key} is absent"
            )
        replace = replace_policy.get(key, False)
        if not replace and pre is not IdentitySentinel.ABSENT:
            raise ServiceTransactionError(
                f"no-clobber service mutation {key} has existing pre-state"
            )
        if isinstance(pre, FileIdentity) and not _mode_is_safe(
            pre.permissions, private=key in _PRIVATE_PRE_KEYS
        ):
            raise ServiceTransactionError(
                f"service mutation {key} pre-state has an unsafe mode"
            )
        stage = _exact_path(fields["stage"], os.path.join(stage_dir, key), f"{key}_stage")
        stage_done = stage_positions[key] < staged
        stage_identity = _identity(
            fields["stage_identity"],
            f"{key}_stage_identity",
            "file",
            owner,
            sentinels=none,
        )
        stage_object = _identity(
            fields["stage_object"],
            f"{key}_stage_object",
            "object",
            owner,
            sentinels=none,
        )
        stage_sha256 = _digest(
            fields["stage_sha256"], f"{key}_stage_sha256", allow_none=True
        )
        if stage_done:
            if not isinstance(stage_identity, FileIdentity) or not isinstance(
                stage_object, FileObjectState
            ) or stage_sha256 is None:
                raise ServiceTransactionError(
                    f"service mutation {key} lacks completed stage evidence"
                )
            if stage_identity.state != stage_object:
                raise ServiceTransactionError(
                    f"service mutation {key} stage identity does not bind its object state"
                )
            expected_stage_mode = _FIXED_STAGE_MODES.get(key)
            if (
                expected_stage_mode is not None
                and stage_identity.permissions != expected_stage_mode
            ):
                raise ServiceTransactionError(
                    f"service mutation {key} stage has the wrong mode"
                )
        elif (
            stage_identity is not IdentitySentinel.NONE
            or stage_object is not IdentitySentinel.NONE
            or stage_sha256 is not None
        ):
            raise ServiceTransactionError(
                f"service mutation {key} has stage evidence beyond its completed prefix"
            )
        pre_sha256 = _digest(
            fields["pre_sha256"], f"{key}_pre_sha256", allow_none=True
        )
        if pre is IdentitySentinel.ABSENT:
            if pre_sha256 is not None or any(
                fields[name] != "none"
                for name in (
                    "backup",
                    "backup_identity",
                    "backup_object",
                    "backup_sha256",
                )
            ):
                raise ServiceTransactionError(
                    f"absent service mutation {key} has backup evidence"
                )
            backup = None
            backup_identity = backup_object = IdentitySentinel.NONE
            backup_sha256 = None
        else:
            assert isinstance(pre, FileIdentity)
            if pre_sha256 is None:
                raise ServiceTransactionError(
                    f"existing service mutation {key} lacks a pre-state digest"
                )
            backup = _exact_path(
                fields["backup"],
                os.path.join(backup_dir, key),
                f"{key}_backup",
            )
            backup_order.append(key)
            backup_done = len(backup_order) <= backed_up
            backup_identity = _identity(
                fields["backup_identity"],
                f"{key}_backup_identity",
                "file",
                owner,
                sentinels=none,
            )
            backup_object = _identity(
                fields["backup_object"],
                f"{key}_backup_object",
                "object",
                owner,
                sentinels=none,
            )
            backup_sha256 = _digest(
                fields["backup_sha256"], f"{key}_backup_sha256", allow_none=True
            )
            if backup_done:
                if not isinstance(
                    backup_identity, FileIdentity
                ) or not isinstance(
                    backup_object, FileObjectState
                ) or backup_sha256 is None:
                    raise ServiceTransactionError(
                        f"service mutation {key} lacks completed backup evidence"
                    )
                if backup_identity.state != backup_object:
                    raise ServiceTransactionError(
                        f"service mutation {key} backup identity does not bind its object state"
                    )
                if backup_identity.dev == pre.dev and backup_identity.ino == pre.ino:
                    raise ServiceTransactionError(
                        f"service mutation {key} backup is not a private copy"
                    )
                if backup_sha256 != pre_sha256 or not _copied_metadata_matches(
                    pre, backup_identity
                ):
                    raise ServiceTransactionError(
                        f"service mutation {key} backup does not bind displaced pre-state"
                    )
            elif (
                backup_identity is not IdentitySentinel.NONE
                or backup_object is not IdentitySentinel.NONE
                or backup_sha256 is not None
            ):
                raise ServiceTransactionError(
                    f"service mutation {key} has backup evidence beyond its completed prefix"
                )
        post = _identity(
            fields["post_identity"],
            f"{key}_post_identity",
            "file",
            owner,
            sentinels=none,
        )
        rollback = _identity(
            fields["rollback_identity"],
            f"{key}_rollback_identity",
            "file",
            owner,
            sentinels=absent_none,
        )
        post_sha256 = _digest(
            fields["post_sha256"], f"{key}_post_sha256", allow_none=True
        )
        rollback_sha256 = _digest(
            fields["rollback_sha256"],
            f"{key}_rollback_sha256",
            allow_none=True,
        )
        if isinstance(post, IdentitySentinel):
            if post_sha256 is not None:
                raise ServiceTransactionError(
                    f"service mutation {key} has digest without publication identity"
                )
        else:
            assert isinstance(post, FileIdentity)
            if not isinstance(stage_object, FileObjectState) or stage_sha256 is None:
                raise ServiceTransactionError(
                    f"service mutation {key} publication precedes completed staging"
                )
            if post.state != stage_object or post_sha256 != stage_sha256:
                raise ServiceTransactionError(
                    f"service mutation {key} publication does not bind its stage"
                )
        if isinstance(rollback, IdentitySentinel):
            if rollback_sha256 is not None:
                raise ServiceTransactionError(
                    f"service mutation {key} has digest without rollback identity"
                )
        elif rollback_sha256 is None:
            raise ServiceTransactionError(
                f"service mutation {key} rollback identity lacks a digest"
            )
        archive_source = None
        archive_source_identity: FileIdentity | IdentitySentinel = IdentitySentinel.NONE
        archive_source_sha256 = None
        if key in _ARCHIVE_MUTATION_KEYS:
            if key == "archive_marker":
                if any(
                    archive_fields[suffix] != "none"
                    for suffix in ("source", "source_identity", "source_sha256")
                ):
                    raise ServiceTransactionError(
                        "service archive marker cannot claim displaced source evidence"
                    )
                if stage_done and stage_sha256 != _EMPTY_SHA256:
                    raise ServiceTransactionError(
                        "service archive marker staged digest is not canonical"
                    )
                if stage_done and (
                    not isinstance(stage_identity, FileIdentity)
                    or stage_identity.permissions != SERVICE_TRANSACTION_FILE_MODE
                    or stage_identity.size != 0
                ):
                    raise ServiceTransactionError(
                        "service archive marker staged identity is invalid"
                    )
            else:
                source_key = _ARCHIVE_SOURCE_KEYS[key]
                source_mutation = mutation_by_key[source_key]
                archive_source = _exact_path(
                    archive_fields["source"],
                    source_mutation.destination,
                    f"{key}_source",
                )
                parsed_source_identity = _identity(
                    archive_fields["source_identity"],
                    f"{key}_source_identity",
                    "file",
                    owner,
                )
                assert isinstance(parsed_source_identity, FileIdentity)
                archive_source_identity = parsed_source_identity
                archive_source_sha256 = _digest(
                    archive_fields["source_sha256"], f"{key}_source_sha256"
                )
                if archive_source_identity != source_mutation.pre_identity:
                    raise ServiceTransactionError(
                        f"service archive source {key} does not bind displaced pre-state"
                    )
                if (
                    archive_source_sha256 != source_mutation.pre_sha256
                    or (stage_done and archive_source_sha256 != stage_sha256)
                ):
                    raise ServiceTransactionError(
                        f"service archive source {key} does not bind staged content"
                    )
                if stage_done and (
                    not isinstance(stage_identity, FileIdentity)
                    or (
                        stage_identity.dev == archive_source_identity.dev
                        and stage_identity.ino == archive_source_identity.ino
                    )
                    or not _copied_metadata_matches(
                        archive_source_identity, stage_identity
                    )
                ):
                    raise ServiceTransactionError(
                        f"service archive stage {key} does not preserve source metadata"
                    )
        if stage_done and key in _CA_OLD_SOURCE_KEYS:
            source_mutation = mutation_by_key[_CA_OLD_SOURCE_KEYS[key]]
            assert isinstance(stage_identity, FileIdentity)
            if not isinstance(source_mutation.pre_identity, FileIdentity):
                raise ServiceTransactionError(
                    f"service CA old-state {key} lacks authoritative pre-state"
                )
            if (
                stage_sha256 != source_mutation.pre_sha256
                or not _copied_metadata_matches(
                    source_mutation.pre_identity, stage_identity
                )
                or (
                    stage_identity.dev == source_mutation.pre_identity.dev
                    and stage_identity.ino == source_mutation.pre_identity.ino
                )
            ):
                raise ServiceTransactionError(
                    f"service CA old-state {key} does not bind authoritative pre-state"
                )
        if stage_done and key == "ca_newcert":
            service_certificate = mutation_by_key["service_certificate"]
            assert isinstance(service_certificate.stage_identity, FileIdentity)
            assert isinstance(stage_identity, FileIdentity)
            if (
                stage_sha256 != service_certificate.stage_sha256
                or stage_identity.size != service_certificate.stage_identity.size
            ):
                raise ServiceTransactionError(
                    "service CA newcert does not bind staged service certificate"
                )
        if stage_done and key == "service_issuer":
            assert isinstance(stage_identity, FileIdentity)
            issuer_bytes = (
                f"root={issuer_root}\nintermediate={intermediate}\n".encode("ascii")
            )
            if (
                stage_sha256 != sha256(issuer_bytes).hexdigest()
                or stage_identity.size != len(issuer_bytes)
            ):
                raise ServiceTransactionError(
                    "service issuer does not bind the claimed issuer generations"
                )
        mutation = ServiceMutation(
            key=key,
            destination=destination,
            pre_identity=pre,
            pre_sha256=pre_sha256,
            stage=stage,
            stage_identity=stage_identity,
            stage_object=stage_object,
            stage_sha256=stage_sha256,
            backup=backup,
            backup_identity=backup_identity,
            backup_object=backup_object,
            backup_sha256=backup_sha256,
            post_identity=post,
            post_sha256=post_sha256,
            rollback_identity=rollback,
            rollback_sha256=rollback_sha256,
            replace=replace,
            archive_source=archive_source,
            archive_source_identity=archive_source_identity,
            archive_source_sha256=archive_source_sha256,
        )
        mutations.append(mutation)
        mutation_by_key[key] = mutation

    if backed_up > len(backup_order):
        raise ServiceTransactionError("service transaction backup count is invalid")

    for key in ("ca_index", "ca_index_attr", "ca_serial"):
        if mutation_by_key[key].pre_identity is IdentitySentinel.ABSENT:
            raise ServiceTransactionError(f"service transaction required CA state {key} is absent")
    if mutation_by_key["ca_newcert"].pre_identity is not IdentitySentinel.ABSENT:
        raise ServiceTransactionError("service transaction CA newcert destination is not absent")
    if "service_key" in mutation_by_key:
        key_pre = mutation_by_key["service_key"].pre_identity
        if (key_action is ServiceKeyAction.CREATE) != (key_pre is IdentitySentinel.ABSENT):
            raise ServiceTransactionError("service key publication pre-state conflicts with key action")
        if key_pre != current_key:
            raise ServiceTransactionError("service key publication does not bind the current key")
        if (
            key_action is ServiceKeyAction.ROTATE
            and mutation_by_key["service_key"].pre_sha256 != current_key_sha256
        ):
            raise ServiceTransactionError(
                "service key publication digest does not bind the current key"
            )
    if operation is ServiceOperation.RENEW:
        expected_renew_members = [".platform-pki-renew-archive"]
        for member in MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[1:-1]:
            source_key = _ARCHIVE_SOURCE_KEYS[_ARCHIVE_MEMBER_KEYS[member]]
            if mutation_by_key[source_key].pre_identity is not IdentitySentinel.ABSENT:
                expected_renew_members.append(member)
        if key_action is ServiceKeyAction.ROTATE:
            expected_renew_members.append("tls.key")
        if members != tuple(expected_renew_members):
            raise ServiceTransactionError(
                "managed renewal archive members do not match displaced service state"
            )

    signing_inputs: list[ServiceSigningInput] = []
    for key in SERVICE_SIGNING_INPUT_KEYS:
        fields = {
            suffix: record[f"{key}_{suffix}"]
            for suffix in _SIGNING_INPUT_SUFFIXES
        }
        enabled = key != "signing_service_key" or key_action is ServiceKeyAction.REUSE
        if not enabled:
            if set(fields.values()) != {"none"}:
                raise ServiceTransactionError(
                    f"disabled service signing input {key} has evidence"
                )
            continue
        source = _exact_path(
            fields["source"],
            os.path.join(
                root,
                _SIGNING_INPUT_SOURCES[key].format(
                    root=issuer_root,
                    intermediate=intermediate,
                    service=service,
                ),
            ),
            f"{key}_source",
        )
        source_identity = _identity(
            fields["source_identity"],
            f"{key}_source_identity",
            "file",
            owner,
        )
        assert isinstance(source_identity, FileIdentity)
        if not _mode_is_safe(
            source_identity.permissions,
            private=key in _PRIVATE_SIGNING_INPUTS,
        ):
            raise ServiceTransactionError(
                f"service signing input {key} source has an unsafe mode"
            )
        source_sha256 = _digest(
            fields["source_sha256"], f"{key}_source_sha256"
        )
        assert source_sha256 is not None
        stage = _exact_path(
            fields["stage"],
            os.path.join(inputs_dir, key),
            f"{key}_stage",
        )
        stage_done = stage_positions[key] < staged
        stage_identity = _identity(
            fields["stage_identity"],
            f"{key}_stage_identity",
            "file",
            owner,
            sentinels=none,
        )
        stage_object = _identity(
            fields["stage_object"],
            f"{key}_stage_object",
            "object",
            owner,
            sentinels=none,
        )
        stage_sha256 = _digest(
            fields["stage_sha256"], f"{key}_stage_sha256", allow_none=True
        )
        if stage_done:
            if not isinstance(stage_identity, FileIdentity) or not isinstance(
                stage_object, FileObjectState
            ) or stage_sha256 is None:
                raise ServiceTransactionError(
                    f"service signing input {key} lacks completed stage evidence"
                )
            if stage_identity.state != stage_object:
                raise ServiceTransactionError(
                    f"service signing input {key} stage does not bind its object state"
                )
            if (
                stage_identity.dev == source_identity.dev
                and stage_identity.ino == source_identity.ino
            ):
                raise ServiceTransactionError(
                    f"service signing input {key} stage is not a private copy"
                )
        elif (
            stage_identity is not IdentitySentinel.NONE
            or stage_object is not IdentitySentinel.NONE
            or stage_sha256 is not None
        ):
            raise ServiceTransactionError(
                f"service signing input {key} has stage evidence beyond its completed prefix"
            )
        if stage_done and key in _EXACT_SIGNING_METADATA_COPIES:
            assert isinstance(stage_identity, FileIdentity)
            if stage_sha256 != source_sha256 or not _copied_metadata_matches(
                source_identity, stage_identity
            ):
                raise ServiceTransactionError(
                    f"service signing input {key} does not preserve its source"
                )
        elif stage_done and key == "signing_ca_config":
            assert isinstance(stage_identity, FileIdentity)
            if stage_identity.permissions != SERVICE_TRANSACTION_FILE_MODE:
                raise ServiceTransactionError(
                    "service signing configuration stage has the wrong mode"
                )
        elif stage_done:
            assert key in _NORMALIZED_PRIVATE_COPIES
            assert isinstance(stage_identity, FileIdentity)
            normalized_copy_matches = (
                stage_sha256 == source_sha256
                and stage_identity.permissions == SERVICE_TRANSACTION_FILE_MODE
                and stage_identity.uid == source_identity.uid
                and stage_identity.size == source_identity.size
                and stage_identity.mtime_ns == source_identity.mtime_ns
            )
            if key == "signing_service_key" and (
                source_identity != current_key
                or source_sha256 != current_key_sha256
                or stage_sha256 != current_key_sha256
                or not normalized_copy_matches
            ):
                raise ServiceTransactionError(
                    "service signing key stage does not bind the current key"
                )
            if key == "signing_inventory" and not normalized_copy_matches:
                raise ServiceTransactionError(
                    "service inventory private stage does not preserve its source"
                )
        signing_inputs.append(
            ServiceSigningInput(
                key,
                source,
                source_identity,
                source_sha256,
                stage,
                stage_identity,
                stage_object,
                stage_sha256,
            )
        )

    backup_order_tuple = tuple(backup_order)
    if backed_up > 0 and staged != len(staging_order):
        raise ServiceTransactionError(
            "service transaction backup progress precedes completed staging"
        )
    if published > 0 and (
        staged != len(staging_order) or backed_up != len(backup_order_tuple)
    ):
        raise ServiceTransactionError(
            "service transaction publication precedes completed preparation"
        )
    pending_directory_stage = (
        phase is ServicePhase.PUBLISHING
        and record["checkpoint"] == "publication-pending"
        and published < len(publication_order)
        and record["mutation"] == publication_order[published]
        and mutation_by_key[publication_order[published]].stage is None
        and isinstance(
            mutation_by_key[publication_order[published]].post_identity,
            DirectoryIdentity,
        )
    )
    post_presence = tuple(
        mutation_by_key[key].post_identity is not IdentitySentinel.NONE
        for key in publication_order
    )
    if post_presence != tuple(
        index < published or (pending_directory_stage and index == published)
        for index in range(len(publication_order))
    ):
        raise ServiceTransactionError("service transaction post identities are not the published prefix")
    if phase in {
        ServicePhase.COMMITTED,
        ServicePhase.CLEANING_UP,
        ServicePhase.TERMINAL,
    } and (
        rolled_back != 0
        or any(
            mutation.rollback_identity is not IdentitySentinel.NONE
            or mutation.rollback_sha256 is not None
            for mutation in mutations
        )
    ):
        raise ServiceTransactionError(
            "service transaction post-boundary state retains rollback evidence"
        )
    rollback_order = managed_rollback_order(publication_order[:published])
    rollback_presence = tuple(mutation_by_key[key].rollback_identity is not IdentitySentinel.NONE for key in rollback_order)
    if rollback_presence != tuple(index < rolled_back for index in range(len(rollback_order))):
        raise ServiceTransactionError("service transaction rollback identities are not the reverse prefix")
    for key in rollback_order[:rolled_back]:
        mutation = mutation_by_key[key]
        if mutation.pre_identity is IdentitySentinel.ABSENT:
            if (
                mutation.rollback_identity is not IdentitySentinel.ABSENT
                or mutation.rollback_sha256 is not None
            ):
                raise ServiceTransactionError(
                    f"service transaction rollback evidence {key} does not restore absence"
                )
        else:
            assert isinstance(mutation.pre_identity, FileIdentity)
            assert isinstance(mutation.backup_object, FileObjectState)
            if not isinstance(mutation.rollback_identity, FileIdentity):
                raise ServiceTransactionError(
                    f"service transaction rollback evidence {key} is not restored file state"
                )
            if (
                mutation.rollback_identity.state != mutation.backup_object
                or mutation.rollback_sha256 != mutation.pre_sha256
                or mutation.rollback_sha256 != mutation.backup_sha256
                or not _copied_metadata_matches(
                    mutation.pre_identity, mutation.rollback_identity
                )
            ):
                raise ServiceTransactionError(
                    f"service transaction rollback evidence {key} does not bind its backup"
                )

    completion_path_value = record["rollback_completion_path"]
    completion_started = completion_path_value != "none"
    if completion_started:
        completion_path = _exact_path(
            completion_path_value,
            os.path.join(transaction_dir, "rollback-complete"),
            "rollback_completion_path",
        )
        paths["rollback_completion_path"] = completion_path
    completion_identity = _identity(
        record["rollback_completion_identity"],
        "rollback_completion_identity",
        "file",
        owner,
        sentinels=none,
        expected_mode=SERVICE_TRANSACTION_FILE_MODE,
    )
    identities["rollback_completion_identity"] = completion_identity
    completion_sha256 = _digest(
        record["rollback_completion_sha256"],
        "rollback_completion_sha256",
        allow_none=True,
    )
    completion_present = not isinstance(completion_identity, IdentitySentinel)
    if not completion_started:
        if (
            completion_present
            or completion_sha256 is not None
            or rollback_completed != 0
        ):
            raise ServiceTransactionError(
                "service rollback completion evidence is incomplete"
            )
    elif not completion_present:
        if completion_sha256 is not None or rollback_completed != 0:
            raise ServiceTransactionError(
                "service rollback completion evidence is premature"
            )
    else:
        assert isinstance(completion_identity, FileIdentity)
        expected_rollback_record = serialize_service_retained_rollback(
            {
                "schema": "1",
                "transaction": record["transaction"],
                "operation": record["operation"],
                "service": service,
                "outcome": ServiceOutcome.FAILED_PRE_COMMIT.value,
                "published_count": str(published),
                "completed_count": str(published),
                "rollback_order": (
                    ",".join(rollback_order) if rollback_order else "none"
                ),
                "rollback_evidence_sha256": _rollback_evidence_digest(
                    record, rollback_order
                ),
            }
        )
        if (
            rollback_completed != published
            or completion_sha256 != sha256(expected_rollback_record).hexdigest()
            or completion_identity.size != len(expected_rollback_record)
        ):
            raise ServiceTransactionError(
                "service rollback completion does not bind the full reverse prefix"
            )

    archive_root_restore_needed = (
        archive_root_restore_required
        and "archive_dir" in publication_order[:published]
        and not committed
    )
    archive_root_restore_boundary = (
        rollback_order.index("archive_dir") + 1
        if archive_root_restore_needed
        else None
    )
    if archive_root_restored is True and not archive_root_restore_needed:
        raise ServiceTransactionError(
            "service archive-root restoration was not required"
        )

    checkpoint = record["checkpoint"]
    active = record["mutation"]
    prepared = (
        staged == len(staging_order)
        and backed_up == len(backup_order_tuple)
    )
    committed_prefixes = prepared and published == len(publication_order)
    if (
        phase
        in {
            ServicePhase.COMMITTED,
            ServicePhase.CLEANING_UP,
            ServicePhase.TERMINAL,
        }
        and committed
        and outcome is ServiceOutcome.SUCCEEDED
        and not committed_prefixes
    ):
        raise ServiceTransactionError(
            "service transaction does not retain complete committed prefixes"
        )
    uncommitted = (
        not committed and recovery_mode is ServiceRecoveryMode.ROLLBACK
    )
    no_completion = not completion_started and rollback_completed == 0
    if phase is ServicePhase.STAGING:
        if checkpoint == "staging-pending":
            index = staged
        elif checkpoint == "staging-done":
            index = staged - 1
        else:
            index = -1
        legal = (
            0 <= index < len(staging_order)
            and active == staging_order[index]
            and backed_up == published == rolled_back == 0
            and uncommitted
            and outcome is ServiceOutcome.NONE
            and no_completion
        )
    elif phase is ServicePhase.BACKING_UP:
        if checkpoint == "backup-pending":
            index = backed_up
        elif checkpoint == "backup-done":
            index = backed_up - 1
        else:
            index = -1
        legal = (
            staged == len(staging_order)
            and 0 <= index < len(backup_order_tuple)
            and active == backup_order_tuple[index]
            and published == rolled_back == 0
            and uncommitted
            and outcome is ServiceOutcome.NONE
            and no_completion
        )
    elif phase is ServicePhase.PLANNED:
        legal = checkpoint == "planned" and active == "none" and prepared and published == 0 and rolled_back == 0 and uncommitted and outcome is ServiceOutcome.NONE and no_completion
    elif phase is ServicePhase.PUBLISHING:
        if checkpoint == "publication-pending":
            index = published
        elif checkpoint == "publication-done":
            index = published - 1
        else:
            index = -1
        legal = 0 <= index < len(publication_order) and active == publication_order[index] and prepared and rolled_back == 0 and uncommitted and outcome is ServiceOutcome.NONE and no_completion
    elif phase is ServicePhase.VERIFYING:
        legal = checkpoint in {"verification-pending", "verification-done"} and active == "none" and prepared and published == len(publication_order) and rolled_back == 0 and uncommitted and outcome is ServiceOutcome.NONE and no_completion
    elif phase is ServicePhase.COMMITTED:
        legal = checkpoint == "commit-done" and active == "none" and committed_prefixes and rolled_back == 0 and committed and recovery_mode is ServiceRecoveryMode.CLEANUP_ONLY and outcome is ServiceOutcome.SUCCEEDED and no_completion
    elif phase is ServicePhase.ROLLING_BACK:
        if checkpoint == "rollback-pending":
            index = rolled_back
        elif checkpoint == "rollback-done":
            index = rolled_back - 1
        else:
            index = -1
        restoration_ordered = True
        if archive_root_restore_boundary is not None and checkpoint in {
            "rollback-pending",
            "rollback-done",
        }:
            if checkpoint == "rollback-pending":
                restoration_expected = rolled_back >= archive_root_restore_boundary
            else:
                restoration_expected = rolled_back > archive_root_restore_boundary
            restoration_ordered = (
                archive_root_restored is restoration_expected
            )
        if not restoration_ordered:
            raise ServiceTransactionError(
                "service archive-root restoration ordering is invalid"
            )
        legal = 0 <= index < len(rollback_order) and active == rollback_order[index] and uncommitted and outcome is ServiceOutcome.FAILED_PRE_COMMIT and no_completion and restoration_ordered
        if checkpoint in {
            "archive-root-restore-pending",
            "archive-root-restore-done",
        }:
            legal = (
                archive_root_restore_needed
                and rolled_back == archive_root_restore_boundary
                and active == "none"
                and not committed
                and recovery_mode is ServiceRecoveryMode.ROLLBACK
                and outcome is ServiceOutcome.FAILED_PRE_COMMIT
                and archive_root_restored
                == (checkpoint == "archive-root-restore-done")
            )
        root_restoration_complete = (
            not archive_root_restore_needed or archive_root_restored is True
        )
        if checkpoint in {
            "rollback-completion-pending",
            "rollback-completion-done",
            "rollback-evidence-clear-pending",
        }:
            expected_present = checkpoint != "rollback-completion-pending"
            legal = (
                rolled_back == published
                and active == "none"
                and uncommitted
                and outcome is ServiceOutcome.FAILED_PRE_COMMIT
                and root_restoration_complete
                and completion_started
                and completion_present is expected_present
                and (
                    rollback_completed == published
                    if expected_present
                    else rollback_completed == 0
                )
            )
    elif phase in {ServicePhase.CLEANING_UP, ServicePhase.TERMINAL}:
        root_restoration_complete = (
            committed
            or not archive_root_restore_needed
            or archive_root_restored is True
        )
        terminal_outcome_valid = (
            committed
            and outcome is ServiceOutcome.SUCCEEDED
            and no_completion
        ) or (
            not committed
            and outcome is ServiceOutcome.FAILED_PRE_COMMIT
            and completion_present
            and rollback_completed == published
        )
        legal = active == "none" and rolled_back == 0 and root_restoration_complete and recovery_mode is ServiceRecoveryMode.CLEANUP_ONLY and terminal_outcome_valid
        if legal:
            _cleanup_matrix(record, operation, outcome)
            legal = (phase is ServicePhase.TERMINAL) == (checkpoint == "journal-cleanup-pending")
    else:  # pragma: no cover - exhaustive enum
        legal = False
    if not legal:
        raise ServiceTransactionError("service transaction phase and evidence are inconsistent")
    if phase not in {ServicePhase.ROLLING_BACK, ServicePhase.CLEANING_UP, ServicePhase.TERMINAL} and archive_root_restored is True:
        raise ServiceTransactionError(
            "service transaction has premature archive-root restoration evidence"
        )
    if phase not in {ServicePhase.CLEANING_UP, ServicePhase.TERMINAL}:
        if any(record[field] not in {"false", "none"} for field in ("archive_marker_removed", "stage_removed", "backup_removed")) or record["terminal_identity"] != "none":
            raise ServiceTransactionError("service transaction has premature cleanup evidence")

    return ServiceTransaction(
        record,
        root,
        operation,
        phase,
        recovery_mode,
        outcome,
        key_action,
        archive_state,
        members,
        staging_order,
        backup_order_tuple,
        publication_order,
        managed_rollback_order(publication_order),
        tuple(mutations),
        tuple(signing_inputs),
        tuple(sorted(identities.items())),
        tuple(sorted(paths.items())),
    )


def serialize_service_transaction(
    values: Mapping[str, str] | ServiceTransaction,
    *,
    pki_dir: os.PathLike[str] | str,
) -> bytes:
    """Validate and serialize the canonical fixed writer order."""

    source = values.record if isinstance(values, ServiceTransaction) else values
    try:
        data = SERVICE_TRANSACTION_SPEC.serialize(source)
    except RecordError as error:
        raise ServiceTransactionError(str(error)) from None
    parse_service_transaction(data, pki_dir=pki_dir)
    return data
