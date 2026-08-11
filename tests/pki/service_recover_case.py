"""Real-filesystem cases for isolated managed-service recovery tests."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from src.platform_pki.filesystem import FileIdentity, identity_at
from src.platform_pki.persisted_identity import (
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
)
from src.platform_pki.service_transaction import (
    SERVICE_CONTAINER_ORDER,
    SERVICE_RETAINED_TRANSACTION_FIELDS,
    SERVICE_SIGNING_INPUT_KEYS,
    SERVICE_TRANSACTION_FIELDS,
    ServiceKeyAction,
    ServiceOperation,
    parse_service_transaction,
)
from tests.test_platform_pki_service_transaction_foundation import (
    PKI_DIR as MODEL_PKI_DIR,
    _backup_order,
    _order,
    _payload,
    _service_values,
    _staging_order,
)


TRANSACTION = "service-0123456789abcdef0123456789abcdef"


@dataclass(frozen=True, slots=True)
class ServiceRecoveryCase:
    pki: Path
    transaction: str
    values: dict[str, str]
    original_destinations: dict[str, bytes | None]


def _identity(path: Path) -> FileIdentity:
    value = identity_at(path)
    assert isinstance(value, FileIdentity)
    return value


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(mode)


def _copy(source: Path, destination: Path, *, mode: int | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(source, destination)
    if mode is not None:
        destination.chmod(mode)


def _mode(value: str) -> int:
    return int(value.split(":", 5)[3], 8)


def _replace_root(values: dict[str, str], pki: Path) -> None:
    root = os.fspath(pki)
    for field, value in tuple(values.items()):
        if value.startswith(MODEL_PKI_DIR):
            values[field] = root + value.removeprefix(MODEL_PKI_DIR)


def _set_file(values: dict[str, str], prefix: str, path: Path, data: bytes) -> None:
    identity = _identity(path)
    digest = hashlib.sha256(data).hexdigest()
    values[f"{prefix}_identity"] = serialize_file_identity(identity)
    values[f"{prefix}_sha256"] = digest


def _bind_journal(values: dict[str, str], journal: Path) -> bytes:
    journal.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    journal.write_bytes(b"")
    journal.chmod(0o600)
    state = _identity(journal).state
    size = 0
    while True:
        values["journal_identity"] = serialize_file_object_state(
            type(state)(
                state.dev,
                state.ino,
                state.uid,
                state.permissions,
                state.links,
                size,
                state.kind,
            )
        )
        data = _payload(SERVICE_TRANSACTION_FIELDS, values)
        if len(data) == size:
            break
        size = len(data)
    journal.write_bytes(data)
    assert _identity(journal).state.size == len(data)
    parse_service_transaction(data, pki_dir=os.fspath(journal.parents[2]))
    return data


def build_service_recovery_case(
    root: Path,
    *,
    operation: ServiceOperation = ServiceOperation.ISSUE,
    key_action: ServiceKeyAction | None = None,
    archive_members: tuple[str, ...] | None = None,
    existing_archive_root: bool = False,
    existing_service_directories: tuple[str, ...] = SERVICE_CONTAINER_ORDER,
    staged_count: int | None = None,
    backed_up_count: int | None = None,
    published: int | None = None,
    publication_pending: bool = False,
    directory_stage_pending: bool = False,
    committed: bool = False,
) -> ServiceRecoveryCase:
    if sum(
        value is not None
        for value in (staged_count, backed_up_count, published)
    ) > 1:
        raise ValueError("only one incomplete transaction prefix may be selected")
    if publication_pending and (published is None or committed):
        raise ValueError("publication_pending requires an uncommitted prefix")
    if directory_stage_pending and not publication_pending:
        raise ValueError("directory_stage_pending requires publication_pending")
    pki = root / "pki"
    pki.mkdir(mode=0o700)
    values = _service_values(
        operation=operation,
        key_action=key_action,
        archive_members=archive_members,
        existing_archive_root=existing_archive_root,
        existing_service_directories=existing_service_directories,
    )
    _replace_root(values, pki)
    values["owner"] = str(os.geteuid())

    for relative in (
        "locks",
        "state",
        "state/rollover",
        "state/rollovers",
        "state/generation-reservations",
        "state/service",
        "state/service/transactions",
        f"state/service/transactions/{TRANSACTION}",
        f"state/service/transactions/{TRANSACTION}/stage",
        f"state/service/transactions/{TRANSACTION}/stage/inputs",
        f"state/service/transactions/{TRANSACTION}/backup",
        "authorities",
        "authorities/roots",
        "authorities/roots/g1",
        "authorities/roots/g1/certs",
        "authorities/intermediates",
        "authorities/intermediates/g1-i1",
        "authorities/intermediates/g1-i1/private",
        "authorities/intermediates/g1-i1/certs",
        "authorities/intermediates/g1-i1/newcerts",
        "inventory",
        "services",
    ):
        (pki / relative).mkdir(exist_ok=True, mode=0o700)

    _write(
        pki / "state/active-issuer",
        b"root=g1\nintermediate=g1-i1\n",
        0o600,
    )

    for key in SERVICE_CONTAINER_ORDER:
        path = Path(values[f"{key}_destination"])
        if values[f"{key}_pre_identity"] != "absent":
            path.mkdir(exist_ok=True, mode=0o700)
            path.chmod(0o700)
            directory = _identity(path).directory
            serialized = serialize_directory_identity(directory)
            values[f"{key}_pre_identity"] = serialized
            values[f"{key}_post_identity"] = serialized

    if values["archive_state"] != "none":
        archive_root = Path(values["archive_root_destination"])
        if existing_archive_root:
            archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            archive_root.chmod(0o700)
            snapshot = _identity(archive_root)
            values["archive_root_snapshot_identity"] = serialize_file_identity(snapshot)
            values["archive_root_pre_identity"] = serialize_directory_identity(
                snapshot.directory
            )
            values["archive_root_post_identity"] = serialize_directory_identity(
                snapshot.directory
            )

    source_data: dict[str, bytes] = {}
    for key in SERVICE_SIGNING_INPUT_KEYS:
        source_value = values[f"{key}_source"]
        if source_value == "none":
            continue
        source = Path(source_value)
        if source.exists():
            data = source.read_bytes()
        else:
            data = f"source:{key}".encode("ascii")
            _write(source, data, _mode(values[f"{key}_source_identity"]))
        source_data[key] = data
        identity = _identity(source)
        values[f"{key}_source_identity"] = serialize_file_identity(identity)
        values[f"{key}_source_sha256"] = hashlib.sha256(data).hexdigest()

    order = _order(values)
    original: dict[str, bytes | None] = {}
    for key in order:
        destination = Path(values[f"{key}_destination"])
        if f"{key}_pre_sha256" not in values:
            original[key] = None if values[f"{key}_pre_identity"] == "absent" else b""
            continue
        if values[f"{key}_pre_identity"] == "absent":
            original[key] = None
            continue
        if destination.exists():
            data = destination.read_bytes()
        else:
            data = f"pre:{key}".encode("ascii")
            _write(destination, data, _mode(values[f"{key}_pre_identity"]))
        original[key] = data
        identity = _identity(destination)
        values[f"{key}_pre_identity"] = serialize_file_identity(identity)
        values[f"{key}_pre_sha256"] = hashlib.sha256(data).hexdigest()

    service_key = pki / "services/app/private/tls.key"
    if values["key_action"] != "create":
        key_identity = _identity(service_key)
        values["current_key_identity"] = serialize_file_identity(key_identity)
        values["current_key_sha256"] = hashlib.sha256(
            service_key.read_bytes()
        ).hexdigest()
        if values["signing_service_key_source"] != "none":
            values["signing_service_key_source_identity"] = values[
                "current_key_identity"
            ]
            values["signing_service_key_source_sha256"] = values[
                "current_key_sha256"
            ]
        if values["service_key_destination"] != "none":
            values["service_key_pre_identity"] = values["current_key_identity"]
            values["service_key_pre_sha256"] = values["current_key_sha256"]

    for key in order:
        source_field = f"{key}_source"
        if source_field not in values or values[source_field] == "none":
            continue
        source = Path(values[source_field])
        data = source.read_bytes()
        values[f"{key}_source_identity"] = serialize_file_identity(
            _identity(source)
        )
        values[f"{key}_source_sha256"] = hashlib.sha256(data).hexdigest()

    for key in SERVICE_SIGNING_INPUT_KEYS:
        stage_value = values[f"{key}_stage"]
        if stage_value == "none":
            continue
        source = Path(values[f"{key}_source"])
        stage = Path(stage_value)
        if key == "signing_ca_config":
            data = b"processed:signing_ca_config"
            _write(stage, data, 0o600)
        else:
            _copy(
                source,
                stage,
                mode=(0o600 if key in {"signing_inventory", "signing_service_key"} else None),
            )
            data = stage.read_bytes()
        identity = _identity(stage)
        values[f"{key}_stage_identity"] = serialize_file_identity(identity)
        values[f"{key}_stage_object"] = serialize_file_object_state(identity.state)
        values[f"{key}_stage_sha256"] = hashlib.sha256(data).hexdigest()

    mutation_by_key: dict[str, Path] = {}
    for key in order:
        stage_field = f"{key}_stage"
        if stage_field not in values or values[stage_field] == "none":
            continue
        stage = Path(values[stage_field])
        mutation_by_key[key] = stage
        if key == "archive_marker":
            _write(stage, b"", 0o600)
        elif key.startswith("archive_"):
            source = Path(values[f"{key}_source"])
            _copy(source, stage)
        elif key in {"ca_index_old", "ca_index_attr_old", "ca_serial_old"}:
            source_key = {
                "ca_index_old": "ca_index",
                "ca_index_attr_old": "ca_index_attr",
                "ca_serial_old": "ca_serial",
            }[key]
            _copy(Path(values[f"{source_key}_destination"]), stage)
        elif key == "ca_newcert":
            _copy(mutation_by_key["service_certificate"], stage, mode=0o600)
        elif key == "service_issuer":
            _write(stage, b"root=g1\nintermediate=g1-i1\n", 0o600)
        else:
            _write(stage, f"stage:{key}".encode("ascii"), _mode(values[f"{key}_stage_identity"]))
        data = stage.read_bytes()
        identity = _identity(stage)
        values[f"{key}_stage_identity"] = serialize_file_identity(identity)
        values[f"{key}_stage_object"] = serialize_file_object_state(identity.state)
        values[f"{key}_stage_sha256"] = hashlib.sha256(data).hexdigest()

    for key in order:
        if f"{key}_backup" not in values or values[f"{key}_backup"] == "none":
            continue
        destination = Path(values[f"{key}_destination"])
        backup = Path(values[f"{key}_backup"])
        _copy(destination, backup)
        data = backup.read_bytes()
        identity = _identity(backup)
        values[f"{key}_backup_identity"] = serialize_file_identity(identity)
        values[f"{key}_backup_object"] = serialize_file_object_state(identity.state)
        values[f"{key}_backup_sha256"] = hashlib.sha256(data).hexdigest()

    staging_order = _staging_order(values)
    backup_order = _backup_order(values)
    if staged_count is not None:
        if not 0 <= staged_count < len(staging_order):
            raise ValueError("staged_count must select an incomplete prefix")
        for key in staging_order[staged_count:]:
            Path(values[f"{key}_stage"]).unlink()
            values[f"{key}_stage_identity"] = "none"
            values[f"{key}_stage_object"] = "none"
            values[f"{key}_stage_sha256"] = "none"
        for key in backup_order:
            Path(values[f"{key}_backup"]).unlink()
            values[f"{key}_backup_identity"] = "none"
            values[f"{key}_backup_object"] = "none"
            values[f"{key}_backup_sha256"] = "none"
        values["staged_count"] = str(staged_count)
        values["backed_up_count"] = "0"
    elif backed_up_count is not None:
        if not 0 <= backed_up_count < len(backup_order):
            raise ValueError("backed_up_count must select an incomplete prefix")
        for key in backup_order[backed_up_count:]:
            Path(values[f"{key}_backup"]).unlink()
            values[f"{key}_backup_identity"] = "none"
            values[f"{key}_backup_object"] = "none"
            values[f"{key}_backup_sha256"] = "none"
        values["backed_up_count"] = str(backed_up_count)

    transaction_dir = Path(values["transaction_dir"])
    values["transaction_identity"] = serialize_directory_identity(
        _identity(transaction_dir).directory
    )
    values["stage_dir_identity"] = serialize_directory_identity(
        _identity(Path(values["stage_dir"])).directory
    )
    values["inputs_dir_identity"] = serialize_directory_identity(
        _identity(Path(values["inputs_dir"])).directory
    )
    values["backup_dir_identity"] = serialize_directory_identity(
        _identity(Path(values["backup_dir"])).directory
    )

    if existing_archive_root:
        reference = Path(values["archive_root_reference_path"])
        _write(reference, b"", 0o600)
        snapshot = _identity(Path(values["archive_root_destination"]))
        os.utime(reference, ns=(snapshot.mtime_ns, snapshot.mtime_ns))
        reference_identity = _identity(reference)
        values["archive_root_reference_identity"] = serialize_file_identity(
            reference_identity
        )
        values["archive_root_reference_sha256"] = hashlib.sha256(b"").hexdigest()
        values["archive_root_snapshot_identity"] = serialize_file_identity(snapshot)
        values["archive_root_pre_identity"] = serialize_directory_identity(
            snapshot.directory
        )
        values["archive_root_post_identity"] = serialize_directory_identity(
            snapshot.directory
        )

    retained = {field: values[field] for field in SERVICE_RETAINED_TRANSACTION_FIELDS}
    transaction_data = _payload(SERVICE_RETAINED_TRANSACTION_FIELDS, retained)
    transaction_path = Path(values["transaction_record_path"])
    _write(transaction_path, transaction_data, 0o600)
    values["transaction_record_identity"] = serialize_file_identity(
        _identity(transaction_path)
    )
    values["transaction_record_sha256"] = hashlib.sha256(transaction_data).hexdigest()

    count = (
        len(order)
        if committed or published == -1
        else (published or 0)
    )
    if directory_stage_pending and f"{order[count]}_stage" in values:
        raise ValueError("directory_stage_pending requires a directory mutation")
    mutation_count = count + (1 if publication_pending else 0)
    for index, key in enumerate(order[:mutation_count]):
        destination = Path(values[f"{key}_destination"])
        if f"{key}_stage" not in values:
            target = (
                Path(values["stage_dir"]) / key
                if directory_stage_pending and index == count
                else destination
            )
            target.mkdir(parents=True, exist_ok=False, mode=0o700)
            target.chmod(0o700)
            values[f"{key}_post_identity"] = serialize_directory_identity(
                _identity(target).directory
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.replace(Path(values[f"{key}_stage"]), destination)
            identity = _identity(destination)
            values[f"{key}_post_identity"] = serialize_file_identity(identity)
            values[f"{key}_post_sha256"] = values[f"{key}_stage_sha256"]
    values["published_count"] = str(count)
    if committed:
        assert count == len(order)
        values.update(
            phase="committed",
            checkpoint="commit-done",
            mutation="none",
            committed="true",
            recovery_mode="cleanup-only",
            outcome="succeeded",
        )
    elif publication_pending:
        key = order[count]
        if f"{key}_post_sha256" in values:
            values[f"{key}_post_identity"] = "none"
            values[f"{key}_post_sha256"] = "none"
        values.update(
            phase="publishing",
            checkpoint="publication-pending",
            mutation=key,
        )
    elif count:
        values.update(
            phase="publishing",
            checkpoint="publication-done",
            mutation=order[count - 1],
        )
    elif staged_count is not None:
        values.update(
            phase="staging",
            checkpoint="staging-pending" if staged_count == 0 else "staging-done",
            mutation=staging_order[staged_count if staged_count == 0 else staged_count - 1],
        )
    elif backed_up_count is not None:
        values.update(
            phase="backing-up",
            checkpoint=("backup-pending" if backed_up_count == 0 else "backup-done"),
            mutation=backup_order[
                backed_up_count if backed_up_count == 0 else backed_up_count - 1
            ],
        )

    journal = Path(values["journal_path"])
    _bind_journal(values, journal)
    return ServiceRecoveryCase(pki, TRANSACTION, values, original)
