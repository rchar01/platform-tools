"""Non-public operational recovery for Python managed-service transactions."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import NoReturn, TextIO

from .errors import ApplicationError
from .faults import DEFAULT_FAULT_HOOK, DEFAULT_PAUSE_HOOK, FaultHook, PauseHook
from .filesystem import (
    ABSENT,
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FileObjectState,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_at,
    identity_from_stat,
)
from .operational import (
    acquire_operational_locks,
    detect_layout,
    prepare_control_state,
    require_pki_directory,
    require_terminal_rollover_history,
)
from .persisted_identity import (
    IdentitySentinel,
    parse_file_identity,
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
)
from .publication import (
    PublicationError,
    TreeReadiness,
    atomic_write_bytes,
    fsync_tree,
    replace_exact,
    remove_exact_tree,
    stage_file_bytes,
    unlink_exact,
)
from .service_transaction import (
    SERVICE_CONTINUITY_KEYS,
    SERVICE_RETAINED_TRANSACTION_FIELDS,
    SERVICE_TRANSACTION_DIRECTORY_MODE,
    SERVICE_TRANSACTION_FIELDS,
    SERVICE_TRANSACTION_FILE_MODE,
    SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH,
    SERVICE_TRANSACTION_TREE_RELATIVE_PATH,
    ServiceMutation,
    ServiceOperation,
    ServiceOutcome,
    ServicePhase,
    ServiceRecoveryMode,
    ServiceTransaction,
    ServiceTransactionError,
    _rollback_evidence_digest,
    managed_rollback_order,
    parse_service_retained_rollback,
    parse_service_retained_terminal,
    parse_service_retained_transaction,
    parse_service_transaction,
    serialize_service_retained_rollback,
    serialize_service_retained_terminal,
    serialize_service_transaction,
    service_cleanup_owned_keys,
)


MAX_SERVICE_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_SERVICE_EVIDENCE_BYTES = 64 * 1024 * 1024
_TRANSACTION = re.compile(r"service-[0-9a-f]{32}", re.ASCII)
_OWNER = os.geteuid()
_PRIVATE_DIRECTORY = DirectoryPolicy(
    owner=_OWNER, mode=SERVICE_TRANSACTION_DIRECTORY_MODE
)
_JOURNAL_FILE = FilePolicy(
    owner=_OWNER,
    mode=SERVICE_TRANSACTION_FILE_MODE,
    links=1,
    max_size=MAX_SERVICE_JOURNAL_BYTES,
)

_JOURNAL_REWRITE_LABELS = (
    "publication-reconcile",
    "publication-directory-stage-discard",
    *(f"rollback-{key}-pending" for key in SERVICE_CONTINUITY_KEYS),
    *(f"rollback-{key}-evidence" for key in SERVICE_CONTINUITY_KEYS),
    "archive-root-restore-pending",
    "archive-root-restore-evidence",
    "rollback-completion-pending",
    "rollback-completion-evidence",
    "rollback-clear-pending",
    "rollback-clear-evidence",
    "cleanup-start",
    "cleanup-archive-marker-evidence",
    "cleanup-archive-marker-next",
    "cleanup-stage-evidence",
    "cleanup-stage-next",
    "cleanup-backup-evidence",
    "cleanup-backup-next",
    "cleanup-terminal-evidence",
    "cleanup-terminal-next",
)
SERVICE_RECOVERY_CHECKPOINTS = (
    "journal-loaded",
    *(point for label in _JOURNAL_REWRITE_LABELS for point in (
        f"{label}-before-journal-rewrite",
        f"{label}-after-journal-rewrite",
    )),
    *(point for key in SERVICE_CONTINUITY_KEYS for point in (
        f"rollback-{key}-before-mutation",
        f"rollback-{key}-after-mutation",
    )),
    "archive-root-restore-before-mutation",
    "archive-root-restore-after-mutation",
    "rollback-completion-before-mutation",
    "rollback-completion-after-mutation",
    "publication-reconcile-before-evidence",
    "publication-directory-stage-discard-before-mutation",
    "publication-directory-stage-discard-after-mutation",
    "cleanup-archive-marker-before-mutation",
    "cleanup-archive-marker-after-mutation",
    "cleanup-stage-before-mutation",
    "cleanup-stage-after-mutation",
    "cleanup-backup-before-mutation",
    "cleanup-backup-after-mutation",
    "cleanup-terminal-before-mutation",
    "cleanup-terminal-after-mutation",
    "journal-before-mutation",
    "journal-after-mutation",
)
SERVICE_BOOTSTRAP_RELATIVE_PATH = "state/service/bootstrap"
SERVICE_BOOTSTRAP_FIELDS = (
    "schema",
    "operation",
    "transaction",
    "transaction_dir",
    "owner",
    "created_epoch",
)
_SERVICE_BOOTSTRAP_OPERATION = "service-issue-bootstrap"
_SERVICE_BOOTSTRAP_STAGE = re.compile(
    r"\.(service-[0-9a-f]{32})\.bootstrap\.publish", re.ASCII
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _checkpoint(point: str, fault: FaultHook, pause: PauseHook) -> None:
    fault(point)
    pause(point)


def _actual(path: str, label: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemError:
        _die(f"{label} could not be inspected safely")


def _parent(path: str) -> tuple[OpenedDirectory, str]:
    parent_path, name = os.path.split(path)
    try:
        return OpenedDirectory(parent_path), name
    except FilesystemError:
        _die("Managed service recovery parent path is unsafe")


def _same_expected(
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


def _file_identity(value: object, field: str) -> FileIdentity:
    if not isinstance(value, FileIdentity):
        raise TypeError(f"{field} must contain a full file identity")
    return value


def _file_object(value: object, field: str) -> FileObjectState:
    if not isinstance(value, FileObjectState):
        raise TypeError(f"{field} must contain a file object state")
    return value


def _directory_identity(value: object, field: str) -> DirectoryIdentity:
    if not isinstance(value, DirectoryIdentity):
        raise TypeError(f"{field} must contain a directory identity")
    return value


def _read_exact_file(
    path: str,
    expected: FileIdentity | FileObjectState,
    digest: str,
    label: str,
) -> tuple[bytes, FileIdentity]:
    if expected.size > MAX_SERVICE_EVIDENCE_BYTES:
        _die(f"{label} exceeds the managed recovery read limit")
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=expected.uid,
                mode=expected.permissions,
                links=1,
                max_size=MAX_SERVICE_EVIDENCE_BYTES,
            ),
            expected_identity=expected,
        ) as opened:
            data = opened.read(MAX_SERVICE_EVIDENCE_BYTES)
            identity = opened.identity
    except FilesystemError:
        _die(f"{label} identity changed")
    if hashlib.sha256(data).hexdigest() != digest:
        _die(f"{label} digest changed")
    assert identity is not None
    return data, identity


def _validate_directory(
    path: str,
    expected: DirectoryIdentity,
    label: str,
) -> FileIdentity:
    try:
        with OpenedDirectory(
            path,
            policy=DirectoryPolicy(
                owner=expected.uid,
                mode=expected.permissions,
            ),
            expected_identity=expected,
        ) as opened:
            return opened.recheck()
    except FilesystemError:
        _die(f"{label} identity changed")
    raise AssertionError("unreachable")


def _publication_identity(result: object) -> FileIdentity:
    identity = getattr(result, "destination_identity", None)
    if identity is None:
        identity = getattr(result, "identity", None)
    if not isinstance(identity, FileIdentity):
        raise TypeError("publication returned no file identity")
    return identity


def _write_all_at(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    try:
        while offset < len(view):
            written = os.pwrite(descriptor, view[offset:], offset)
            if written <= 0:
                raise OSError("journal write made no progress")
            offset += written
    finally:
        view.release()


def _self_sized_journal_bytes(
    values: dict[str, str],
    state: FileObjectState,
    pki_dir: str,
) -> bytes:
    size = 0
    while True:
        candidate = replace(state, size=size)
        values["journal_identity"] = serialize_file_object_state(candidate)
        try:
            data = "".join(
                f"{field}={values[field]}\n" for field in SERVICE_TRANSACTION_FIELDS
            ).encode("ascii")
        except (KeyError, UnicodeEncodeError):
            _die("Managed service recovery journal could not be serialized safely")
        if len(data) == size:
            try:
                parse_service_transaction(data, pki_dir=pki_dir)
            except ServiceTransactionError as error:
                _die(str(error))
            return data
        size = len(data)


@dataclass(slots=True)
class _Control:
    path: str
    pki_dir: str
    values: dict[str, str]
    identity: FileIdentity
    fault: FaultHook
    pause: PauseHook

    def recheck(self) -> None:
        try:
            with OpenedFile(
                self.path,
                policy=_JOURNAL_FILE,
                expected_identity=self.identity,
            ):
                pass
        except FilesystemError:
            _die("Managed service recovery journal identity changed")

    def write(
        self,
        label: str,
        *,
        pre_rewrite_check: Callable[[], None] | None = None,
    ) -> ServiceTransaction:
        if label not in _JOURNAL_REWRITE_LABELS:
            raise ValueError("unknown managed service journal rewrite label")
        if pre_rewrite_check is not None and not callable(pre_rewrite_check):
            raise TypeError("pre_rewrite_check must be callable or None")
        _checkpoint(f"{label}-before-journal-rewrite", self.fault, self.pause)
        self.recheck()
        parent, name = _parent(self.path)
        stage = None
        try:
            try:
                stage = stage_file_bytes(
                    parent,
                    name,
                    b"",
                    mode=SERVICE_TRANSACTION_FILE_MODE,
                    owner=_OWNER,
                )
                data = _self_sized_journal_bytes(
                    self.values, stage.identity.state, self.pki_dir
                )
                expected_stage_state = replace(stage.identity.state, size=len(data))
                os.ftruncate(stage.fileno(), len(data))
                _write_all_at(stage.fileno(), data)
                os.fsync(stage.fileno())
                staged_identity = identity_from_stat(os.fstat(stage.fileno()))
                stage.identity = staged_identity
                if staged_identity.state != expected_stage_state:
                    _die("Managed service recovery journal stage is inconsistent")
                with parent.open_file(
                    stage.name,
                    policy=_JOURNAL_FILE,
                    expected_identity=staged_identity,
                ) as opened_stage:
                    if opened_stage.read(MAX_SERVICE_JOURNAL_BYTES) != data:
                        _die("Managed service recovery journal stage is inconsistent")
                if pre_rewrite_check is not None:
                    pre_rewrite_check()
                result = replace_exact(
                    parent,
                    stage.name,
                    staged_identity,
                    parent,
                    name,
                    self.identity,
                )
                stage.mark_consumed()
                self.identity = _publication_identity(result)
            except (OSError, FilesystemError, PublicationError):
                _die("Managed service recovery journal could not be rewritten safely")
        finally:
            if stage is not None:
                try:
                    stage.cleanup()
                    stage.close()
                except PublicationError:
                    _die("Managed service recovery journal stage requires inspection")
            parent.close()
        _checkpoint(f"{label}-after-journal-rewrite", self.fault, self.pause)
        try:
            return parse_service_transaction(data, pki_dir=self.pki_dir)
        except ServiceTransactionError:
            raise AssertionError("rewritten service journal did not parse") from None


def _load_journal(
    path: str,
    pki_dir: str,
    fault: FaultHook,
    pause: PauseHook,
) -> tuple[_Control, ServiceTransaction]:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(path, policy=_JOURNAL_FILE) as opened:
            data = opened.read(MAX_SERVICE_JOURNAL_BYTES)
            identity = opened.identity
        record = parse_service_transaction(data, pki_dir=pki_dir)
    except FilesystemError:
        _die("No safe managed service recovery journal exists")
    except ServiceTransactionError as error:
        _die(str(error))
    assert identity is not None
    if record.identity("journal_identity") != identity.state:
        _die("Managed service recovery journal does not bind its live object")
    return _Control(path, pki_dir, dict(record.items()), identity, fault, pause), record


def service_bootstrap_bytes(
    pki_dir: str,
    transaction: str,
    *,
    created_epoch: int,
) -> bytes:
    """Return one canonical managed-issue bootstrap reservation."""

    if _TRANSACTION.fullmatch(transaction) is None:
        raise ValueError("transaction must be a canonical managed service ID")
    if isinstance(created_epoch, bool) or not isinstance(created_epoch, int) or created_epoch < 0:
        raise ValueError("created_epoch must be a nonnegative integer")
    values = {
        "schema": "1",
        "operation": _SERVICE_BOOTSTRAP_OPERATION,
        "transaction": transaction,
        "transaction_dir": (
            f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
        ),
        "owner": str(_OWNER),
        "created_epoch": str(created_epoch),
    }
    return "".join(f"{field}={values[field]}\n" for field in SERVICE_BOOTSTRAP_FIELDS).encode(
        "ascii"
    )


def _parse_service_bootstrap(data: bytes, pki_dir: str, transaction: str) -> dict[str, str]:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Managed service bootstrap record has invalid content")
    if len(lines) != len(SERVICE_BOOTSTRAP_FIELDS) or not data.endswith(b"\n"):
        _die("Managed service bootstrap record has invalid content")
    values: dict[str, str] = {}
    for expected, line in zip(SERVICE_BOOTSTRAP_FIELDS, lines, strict=True):
        if "=" not in line:
            _die("Managed service bootstrap record has invalid content")
        key, value = line.split("=", 1)
        if key != expected or not value:
            _die("Managed service bootstrap record has invalid content")
        values[key] = value
    expected_dir = f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
    if (
        values["schema"] != "1"
        or values["operation"] != _SERVICE_BOOTSTRAP_OPERATION
        or values["transaction"] != transaction
        or values["transaction_dir"] != expected_dir
        or values["owner"] != str(_OWNER)
        or re.fullmatch(r"0|[1-9][0-9]*", values["created_epoch"], re.ASCII) is None
    ):
        _die("Managed service bootstrap record is outside its contract")
    return values


def publish_service_bootstrap(
    pki_dir: str,
    transaction: str,
    *,
    created_epoch: int,
    fault_hook: FaultHook,
    pause_hook: PauseHook,
) -> FileIdentity:
    """Durably reserve a transaction before its private tree exists."""

    data = service_bootstrap_bytes(pki_dir, transaction, created_epoch=created_epoch)
    stage_name = f".{transaction}.bootstrap.publish"
    bootstrap_name = "bootstrap"
    descriptor = -1
    try:
        with OpenedDirectory(f"{pki_dir}/state/service", policy=_PRIVATE_DIRECTORY) as parent:
            with parent.open_directory(
                "bootstrap-history", policy=_PRIVATE_DIRECTORY
            ) as history:
                if history.identity_at(transaction) is not ABSENT:
                    _die("Managed service transaction ID was already consumed")
            if parent.identity_at(bootstrap_name) is not ABSENT:
                _die("Managed service bootstrap recovery is already required")
            if parent.identity_at(stage_name) is not ABSENT:
                _die("Managed service bootstrap stage already exists")
            _checkpoint("bootstrap-stage-before-mutation", fault_hook, pause_hook)
            descriptor = os.open(
                stage_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=parent.fileno(),
            )
            _checkpoint("bootstrap-stage-after-mutation", fault_hook, pause_hook)
            view = memoryview(data)
            try:
                _checkpoint("bootstrap-write-before-mutation", fault_hook, pause_hook)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError
                    view = view[written:]
                _checkpoint("bootstrap-write-after-mutation", fault_hook, pause_hook)
            finally:
                view.release()
            os.fchmod(descriptor, 0o600)
            _checkpoint("bootstrap-file-fsync-before-mutation", fault_hook, pause_hook)
            os.fsync(descriptor)
            _checkpoint("bootstrap-file-fsync-after-mutation", fault_hook, pause_hook)
            staged = identity_from_stat(os.fstat(descriptor))
            os.close(descriptor)
            descriptor = -1
            _checkpoint("bootstrap-publication-before-mutation", fault_hook, pause_hook)
            os.link(
                stage_name,
                bootstrap_name,
                src_dir_fd=parent.fileno(),
                dst_dir_fd=parent.fileno(),
                follow_symlinks=False,
            )
            _checkpoint("bootstrap-publication-after-mutation", fault_hook, pause_hook)
            published = parent.identity_at(bootstrap_name)
            active_stage = parent.identity_at(stage_name)
            if published != active_stage or not isinstance(published, FileIdentity):
                _die("Managed service bootstrap publication is ambiguous")
            os.unlink(stage_name, dir_fd=parent.fileno())
            _checkpoint("bootstrap-stage-unlink-after-mutation", fault_hook, pause_hook)
            os.fsync(parent.fileno())
            actual = parent.identity_at(bootstrap_name)
            if not isinstance(actual, FileIdentity) or actual.state != staged.state:
                _die("Managed service bootstrap publication changed")
            with parent.open_file(
                bootstrap_name,
                policy=_JOURNAL_FILE,
                expected_identity=actual,
            ) as opened:
                if opened.read(MAX_SERVICE_JOURNAL_BYTES) != data:
                    _die("Managed service bootstrap publication changed")
            return actual
    except (OSError, FilesystemError):
        _die("Managed service bootstrap record could not be published safely")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raise AssertionError("unreachable")


def _validate_bootstrap_tree(
    parent: OpenedDirectory,
    transaction: str,
    expected: FileIdentity,
) -> tuple[OpenedDirectory, TreeReadiness]:
    try:
        transaction_dir = parent.open_directory(
            transaction,
            policy=_PRIVATE_DIRECTORY,
            expected_identity=expected,
        )
        allowed = {
            "stage": "directory",
            "backup": "directory",
            "transaction": "regular",
            "archive-root-reference": "regular",
        }
        entries = set(os.listdir(transaction_dir.fileno()))
        if entries - set(allowed):
            _die("Managed service bootstrap transaction contains an unexpected entry")
        for name in entries:
            actual = transaction_dir.identity_at(name)
            if not isinstance(actual, FileIdentity) or actual.kind != allowed[name]:
                _die("Managed service bootstrap transaction contains an unsafe entry")
            if actual.kind == "regular":
                with transaction_dir.open_file(
                    name,
                    policy=FilePolicy(owner=_OWNER, mode=0o600, links=1),
                    expected_identity=actual,
                ):
                    pass
                continue
            with transaction_dir.open_directory(
                name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=actual,
            ) as directory:
                children = set(os.listdir(directory.fileno()))
                if name == "backup" and children:
                    _die("Managed service bootstrap backup directory is not empty")
                if name == "stage":
                    if children - {"inputs"}:
                        _die("Managed service bootstrap stage contains an unexpected entry")
                    if "inputs" in children:
                        with directory.open_directory(
                            "inputs", policy=_PRIVATE_DIRECTORY
                        ) as inputs:
                            if os.listdir(inputs.fileno()):
                                _die("Managed service bootstrap inputs directory is not empty")
        readiness = fsync_tree(transaction_dir, parent, transaction)
        return transaction_dir, readiness
    except FilesystemError:
        _die("Managed service bootstrap transaction tree is unsafe")
    raise AssertionError("unreachable")


def clear_service_bootstrap(
    pki_dir: str,
    transaction: str,
    *,
    remove_tree: bool,
    fault_hook: FaultHook = DEFAULT_FAULT_HOOK,
    pause_hook: PauseHook = DEFAULT_PAUSE_HOOK,
) -> bool:
    """Reconcile and remove one exact bootstrap reservation and optional partial tree."""

    stage_name = f".{transaction}.bootstrap.publish"
    bootstrap_name = "bootstrap"
    data = b""
    try:
        with OpenedDirectory(f"{pki_dir}/state/service", policy=_PRIVATE_DIRECTORY) as parent:
            stage = parent.identity_at(stage_name)
            bootstrap = parent.identity_at(bootstrap_name)
            if stage is not ABSENT:
                if not isinstance(stage, FileIdentity) or stage.kind != "regular":
                    _die("Managed service bootstrap stage is unsafe")
                if bootstrap is not ABSENT and bootstrap != stage:
                    _die("Managed service bootstrap publication is ambiguous")
                try:
                    with parent.open_file(
                        stage_name,
                        policy=FilePolicy(
                            owner=_OWNER,
                            mode=SERVICE_TRANSACTION_FILE_MODE,
                            links=2 if bootstrap is not ABSENT else 1,
                            max_size=MAX_SERVICE_JOURNAL_BYTES,
                        ),
                        expected_identity=stage,
                    ) as staged:
                        staged.recheck()
                except FilesystemError:
                    _die("Managed service bootstrap stage is unsafe")
                _checkpoint("bootstrap-stage-cleanup-before-mutation", fault_hook, pause_hook)
                if bootstrap is ABSENT:
                    transaction_path = (
                        f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
                    )
                    if remove_tree and os.path.lexists(transaction_path):
                        _die("Managed service transaction tree lacks a bootstrap reservation")
                    data = service_bootstrap_bytes(
                        pki_dir, transaction, created_epoch=0
                    )
                    descriptor = os.open(
                        stage_name,
                        os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent.fileno(),
                    )
                    try:
                        if identity_from_stat(os.fstat(descriptor)) != stage:
                            _die("Managed service bootstrap stage changed")
                        _checkpoint(
                            "bootstrap-stage-abandon-before-mutation",
                            fault_hook,
                            pause_hook,
                        )
                        os.ftruncate(descriptor, 0)
                        view = memoryview(data)
                        try:
                            while view:
                                written = os.write(descriptor, view)
                                if written <= 0:
                                    raise OSError
                                view = view[written:]
                        finally:
                            view.release()
                        os.fchmod(descriptor, SERVICE_TRANSACTION_FILE_MODE)
                        os.fsync(descriptor)
                        rewritten = identity_from_stat(os.fstat(descriptor))
                        _checkpoint(
                            "bootstrap-stage-abandon-after-mutation",
                            fault_hook,
                            pause_hook,
                        )
                    finally:
                        os.close(descriptor)
                    with parent.open_directory(
                        "bootstrap-history", policy=_PRIVATE_DIRECTORY
                    ) as history:
                        if history.identity_at(transaction) is not ABSENT:
                            _die("Managed service bootstrap history already exists")
                        if parent.identity_at(stage_name) != rewritten:
                            _die("Managed service bootstrap stage changed")
                        os.rename(
                            stage_name,
                            transaction,
                            src_dir_fd=parent.fileno(),
                            dst_dir_fd=history.fileno(),
                        )
                        os.fsync(history.fileno())
                        os.fsync(parent.fileno())
                        historical = history.identity_at(transaction)
                        if (
                            not isinstance(historical, FileIdentity)
                            or historical.dev != rewritten.dev
                            or historical.ino != rewritten.ino
                            or historical.uid != rewritten.uid
                            or historical.permissions != rewritten.permissions
                            or historical.links != 1
                            or historical.size != rewritten.size
                            or historical.kind != rewritten.kind
                            or parent.identity_at(stage_name) is not ABSENT
                        ):
                            _die("Managed service bootstrap history publication changed")
                    _checkpoint(
                        "bootstrap-stage-cleanup-after-mutation", fault_hook, pause_hook
                    )
                    return True
                else:
                    if (
                        parent.identity_at(stage_name) != stage
                        or parent.identity_at(bootstrap_name) != bootstrap
                    ):
                        _die("Managed service bootstrap publication changed")
                    os.unlink(stage_name, dir_fd=parent.fileno())
                    os.fsync(parent.fileno())
                    current = parent.identity_at(bootstrap_name)
                    if (
                        not isinstance(current, FileIdentity)
                        or current.dev != stage.dev
                        or current.ino != stage.ino
                        or current.uid != stage.uid
                        or current.permissions != stage.permissions
                        or current.links != 1
                        or current.size != stage.size
                        or current.kind != stage.kind
                        or parent.identity_at(stage_name) is not ABSENT
                    ):
                        _die("Managed service bootstrap publication changed")
                    bootstrap = current
                _checkpoint("bootstrap-stage-cleanup-after-mutation", fault_hook, pause_hook)
                bootstrap = parent.identity_at(bootstrap_name)
            if bootstrap is ABSENT:
                return False
            if not isinstance(bootstrap, FileIdentity) or bootstrap.kind != "regular":
                _die("Managed service bootstrap record is unsafe")
            with parent.open_file(
                bootstrap_name,
                policy=_JOURNAL_FILE,
                expected_identity=bootstrap,
            ) as opened:
                data = opened.read(MAX_SERVICE_JOURNAL_BYTES)
                bootstrap = opened.recheck()
            _parse_service_bootstrap(data, pki_dir, transaction)

            transactions_path = f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}"
            with OpenedDirectory(transactions_path, policy=_PRIVATE_DIRECTORY) as transactions:
                tree = transactions.identity_at(transaction)
                if remove_tree and tree is not ABSENT:
                    if not isinstance(tree, FileIdentity) or tree.kind != "directory":
                        _die("Managed service bootstrap transaction tree is unsafe")
                    opened, readiness = _validate_bootstrap_tree(
                        transactions, transaction, tree
                    )
                    opened.close()
                    _checkpoint("bootstrap-tree-cleanup-before-mutation", fault_hook, pause_hook)
                    remove_exact_tree(transactions, transaction, tree, readiness)
                    _checkpoint("bootstrap-tree-cleanup-after-mutation", fault_hook, pause_hook)
                elif not remove_tree and tree is ABSENT:
                    _die("Managed service journal lacks its bootstrapped transaction tree")
            with parent.open_directory(
                "bootstrap-history", policy=_PRIVATE_DIRECTORY
            ) as history:
                if history.identity_at(transaction) is not ABSENT:
                    _die("Managed service bootstrap history already exists")
                current = parent.identity_at(bootstrap_name)
                if current != bootstrap:
                    _die("Managed service bootstrap record changed before cleanup")
                _checkpoint(
                    "bootstrap-record-cleanup-before-mutation", fault_hook, pause_hook
                )
                os.rename(
                    bootstrap_name,
                    transaction,
                    src_dir_fd=parent.fileno(),
                    dst_dir_fd=history.fileno(),
                )
                os.fsync(history.fileno())
                os.fsync(parent.fileno())
                historical = history.identity_at(transaction)
                if (
                    parent.identity_at(bootstrap_name) is not ABSENT
                    or not isinstance(historical, FileIdentity)
                    or historical.dev != bootstrap.dev
                    or historical.ino != bootstrap.ino
                    or historical.uid != bootstrap.uid
                    or historical.permissions != bootstrap.permissions
                    or historical.links != 1
                    or historical.size != bootstrap.size
                    or historical.kind != bootstrap.kind
                ):
                    _die("Managed service bootstrap history publication changed")
                with history.open_file(
                    transaction,
                    policy=_JOURNAL_FILE,
                    expected_identity=historical,
                ) as opened:
                    if opened.read(MAX_SERVICE_JOURNAL_BYTES) != data:
                        _die("Managed service bootstrap history publication changed")
                _checkpoint(
                    "bootstrap-record-cleanup-after-mutation", fault_hook, pause_hook
                )
            return True
    except (OSError, FilesystemError, PublicationError):
        _die("Managed service bootstrap cleanup requires inspection")
    raise AssertionError("unreachable")


def _require_compatible_state(pki_dir: str) -> None:
    if detect_layout(pki_dir) != "generation":
        _die("Managed service recovery requires complete generation-aware PKI state")
    incompatible = (
        ("state/csr/recovery-journal", "CSR signing recovery"),
        ("state/csr/finalization-recovery-journal", "CSR finalization recovery"),
        ("state/rollover/recovery-required", "PKI rollover recovery"),
    )
    for relative, label in incompatible:
        if os.path.lexists(f"{pki_dir}/{relative}"):
            _die(f"{label} must be completed before managed service recovery")
    rollover = f"{pki_dir}/state/rollover/journal"
    if os.path.lexists(rollover):
        require_terminal_rollover_history(
            pki_dir,
            rollover,
            error_message=(
                "PKI migration or rollover state blocks managed service recovery"
            ),
        )


def _validate_active_authority(record: ServiceTransaction) -> None:
    active = f"{record.pki_dir}/state/active-issuer"
    expected = (
        f"root={record['issuer_root']}\n"
        f"intermediate={record['issuer_intermediate']}\n"
    ).encode("ascii")
    try:
        with OpenedFile(
            active,
            policy=FilePolicy(owner=_OWNER, mode=0o600, links=1, max_size=4096),
        ) as opened:
            if opened.read(4096) != expected:
                _die("Active issuer does not match the managed service journal")
    except FilesystemError:
        _die("Active issuer state is unsafe")
    for path, label in (
        (
            f"{record.pki_dir}/authorities/roots/{record['issuer_root']}",
            "root authority",
        ),
        (
            f"{record.pki_dir}/authorities/intermediates/"
            f"{record['issuer_intermediate']}",
            "intermediate authority",
        ),
    ):
        try:
            with OpenedDirectory(path, policy=_PRIVATE_DIRECTORY):
                pass
        except FilesystemError:
            _die(f"Managed service {label} path is unsafe")


def _mutation_map(record: ServiceTransaction) -> dict[str, ServiceMutation]:
    return {mutation.key: mutation for mutation in record.mutations}


def _expected_terminal_bytes(record: ServiceTransaction) -> bytes:
    return serialize_service_retained_terminal(
        {
            "schema": "1",
            "transaction": record["transaction"],
            "operation": record["operation"],
            "service": record["service"],
            "outcome": record["outcome"],
            "committed": record["committed"],
            "transaction_identity": record["transaction_record_identity"],
            "transaction_sha256": record["transaction_record_sha256"],
            "rollback_completion_identity": record[
                "rollback_completion_identity"
            ],
            "rollback_completion_sha256": record[
                "rollback_completion_sha256"
            ],
        }
    )


def _expected_rollback_bytes(record: ServiceTransaction) -> bytes:
    order = managed_rollback_order(
        record.publication_order[: int(record["published_count"])]
    )
    return serialize_service_retained_rollback(
        {
            "schema": "1",
            "transaction": record["transaction"],
            "operation": record["operation"],
            "service": record["service"],
            "outcome": ServiceOutcome.FAILED_PRE_COMMIT.value,
            "published_count": record["published_count"],
            "completed_count": record["published_count"],
            "rollback_order": ",".join(order) if order else "none",
            "rollback_evidence_sha256": _rollback_evidence_digest(
                record.record, order
            ),
        }
    )


def _validate_retained_evidence(record: ServiceTransaction) -> None:
    transaction_identity = _directory_identity(
        record.identity("transaction_identity"), "transaction_identity"
    )
    _validate_directory(
        record["transaction_dir"], transaction_identity, "Service transaction directory"
    )
    expected_transaction = _file_identity(
        record.identity("transaction_record_identity"),
        "transaction_record_identity",
    )
    transaction_data, _ = _read_exact_file(
        record["transaction_record_path"],
        expected_transaction,
        record["transaction_record_sha256"],
        "Retained service transaction",
    )
    try:
        retained = parse_service_retained_transaction(transaction_data)
    except ServiceTransactionError:
        _die("Retained service transaction bytes are invalid")
    if any(
        retained[field] != record[field]
        for field in SERVICE_RETAINED_TRANSACTION_FIELDS
    ):
        _die("Retained service transaction does not match the journal")

    reference = record["archive_root_reference_path"]
    if reference != "none":
        _read_exact_file(
            reference,
            _file_identity(
                record.identity("archive_root_reference_identity"),
                "archive_root_reference_identity",
            ),
            record["archive_root_reference_sha256"],
            "Archive-root metadata reference",
        )

    completion = record["rollback_completion_path"]
    completion_identity = record.identity("rollback_completion_identity")
    if isinstance(completion_identity, FileIdentity):
        data, _ = _read_exact_file(
            completion,
            completion_identity,
            record["rollback_completion_sha256"],
            "Rollback completion record",
        )
        if data != _expected_rollback_bytes(record):
            _die("Rollback completion record bytes changed")
    elif (
        completion != "none"
        and _actual(completion, "Rollback completion record") is not ABSENT
    ):
        _die("Rollback completion record lacks journal identity evidence")

    terminal_identity = record.identity("terminal_identity")
    terminal = record["terminal_path"]
    if isinstance(terminal_identity, FileIdentity):
        data, _ = _read_exact_file(
            terminal,
            terminal_identity,
            record["terminal_sha256"],
            "Managed service terminal record",
        )
        if data != _expected_terminal_bytes(record):
            _die("Managed service terminal record bytes changed")
    elif _actual(terminal, "Managed service terminal record") is not ABSENT:
        _die("Managed service terminal record lacks journal identity evidence")


def _validate_signing_inputs(record: ServiceTransaction) -> None:
    for item in record.signing_inputs:
        _read_exact_file(
            item.source,
            item.source_identity,
            item.source_sha256,
            f"Managed service input {item.key}",
        )


def _validate_file_state(
    path: str,
    expected: FileIdentity | FileObjectState,
    digest: str,
    label: str,
) -> FileIdentity:
    _data, identity = _read_exact_file(path, expected, digest, label)
    return identity


def _validate_destinations(
    record: ServiceTransaction,
) -> tuple[FileIdentity | DirectoryIdentity | None, bool]:
    mutations = _mutation_map(record)
    published = int(record["published_count"])
    rolled = int(record["rollback_count"])
    rollback_order = managed_rollback_order(record.publication_order[:published])
    published_keys = record.publication_order[:published]
    active_publication: FileIdentity | DirectoryIdentity | None = None
    active_rollback_completed = False
    failed_cleanup = (
        record.phase in {ServicePhase.CLEANING_UP, ServicePhase.TERMINAL}
        and record.outcome is ServiceOutcome.FAILED_PRE_COMMIT
    )
    absent_directories: list[str] = []

    for key in record.publication_order:
        mutation = mutations[key]
        if any(
            mutation.destination.startswith(f"{directory}/")
            for directory in absent_directories
        ):
            actual = ABSENT
        else:
            actual = _actual(mutation.destination, f"Service destination {key}")
        if mutation.stage is None and actual is ABSENT:
            absent_directories.append(mutation.destination)
        marker_removed = (
            key == "archive_marker"
            and record["archive_marker_removed"] == "true"
        )
        if marker_removed:
            expected_kind = "absent"
        elif record["committed"] == "true":
            expected_kind = "post"
        elif failed_cleanup:
            expected_kind = "pre"
        elif key in rollback_order[:rolled]:
            expected_kind = "pre"
        elif key in published_keys:
            expected_kind = "post"
        else:
            expected_kind = "pre"

        publication_pending = (
            record.phase is ServicePhase.PUBLISHING
            and record["checkpoint"] == "publication-pending"
            and record["mutation"] == key
            and key == record.publication_order[published]
        )
        rollback_pending = (
            record.phase is ServicePhase.ROLLING_BACK
            and record["checkpoint"] == "rollback-pending"
            and record["mutation"] == key
            and rolled < len(rollback_order)
            and key == rollback_order[rolled]
        )

        pre_matches = _same_expected(actual, mutation.pre_identity)
        post_matches = _same_expected(actual, mutation.post_identity)
        if isinstance(mutation.post_identity, FileIdentity) and post_matches:
            _validate_file_state(
                mutation.destination,
                mutation.post_identity,
                mutation.post_sha256 or "",
                f"Published service destination {key}",
            )
        if isinstance(mutation.pre_identity, FileIdentity) and pre_matches:
            _validate_file_state(
                mutation.destination,
                mutation.pre_identity,
                mutation.pre_sha256 or "",
                f"Original service destination {key}",
            )
        if failed_cleanup and isinstance(mutation.pre_identity, FileIdentity):
            restored = _file_object(
                mutation.backup_object, f"{key}_backup_object"
            )
            pre_matches = _same_expected(actual, restored)
            if pre_matches:
                _validate_file_state(
                    mutation.destination,
                    restored,
                    mutation.pre_sha256 or "",
                    f"Restored service destination {key}",
                )
        elif key in rollback_order[:rolled] and isinstance(
            mutation.pre_identity, FileIdentity
        ):
            restored = _file_identity(
                mutation.rollback_identity, f"{key}_rollback_identity"
            )
            pre_matches = _same_expected(actual, restored)
            if pre_matches:
                _validate_file_state(
                    mutation.destination,
                    restored,
                    mutation.rollback_sha256 or "",
                    f"Restored service destination {key}",
                )
        elif rollback_pending and isinstance(mutation.pre_identity, FileIdentity):
            restored = _file_object(
                mutation.backup_object, f"{key}_backup_object"
            )
            if _same_expected(actual, restored):
                _validate_file_state(
                    mutation.destination,
                    restored,
                    mutation.pre_sha256 or "",
                    f"Restored service destination {key}",
                )
                pre_matches = True
                active_rollback_completed = True
        elif rollback_pending and mutation.pre_identity is IdentitySentinel.ABSENT:
            active_rollback_completed = actual is ABSENT

        if publication_pending and not pre_matches:
            if isinstance(mutation.stage_object, FileObjectState):
                post_matches = _same_expected(actual, mutation.stage_object)
                if post_matches:
                    active_publication = _validate_file_state(
                        mutation.destination,
                        mutation.stage_object,
                        mutation.stage_sha256 or "",
                        f"Published service destination {key}",
                    )
            elif isinstance(mutation.post_identity, DirectoryIdentity):
                post_matches = _same_expected(actual, mutation.post_identity)
                if post_matches:
                    active_publication = mutation.post_identity
            if post_matches:
                assert active_publication is not None

        if rollback_pending and active_rollback_completed:
            continue
        if expected_kind == "absent":
            if actual is not ABSENT:
                _die("Renewal archive marker reappeared after cleanup")
            continue
        if expected_kind == "post" and not post_matches:
            _die(f"Published service destination {key} identity changed")
        if expected_kind == "pre" and not pre_matches:
            if not (publication_pending and active_publication is not None):
                _die(f"Original service destination {key} identity changed")

    return active_publication, active_rollback_completed


def _directory_entries(directory: OpenedDirectory, label: str) -> frozenset[str]:
    try:
        names = frozenset(os.listdir(directory.fileno()))
        directory.recheck()
        return names
    except (OSError, FilesystemError):
        _die(f"{label} has unsafe entries")


def _pending_directory_stage(
    record: ServiceTransaction,
) -> tuple[ServiceMutation, str, DirectoryIdentity] | None:
    if (
        record.phase is not ServicePhase.PUBLISHING
        or record["checkpoint"] != "publication-pending"
    ):
        return None
    mutation = _mutation_map(record)[record["mutation"]]
    if mutation.stage is not None or not isinstance(
        mutation.post_identity, DirectoryIdentity
    ):
        return None
    return (
        mutation,
        os.path.join(record["stage_dir"], mutation.key),
        mutation.post_identity,
    )


def _validate_private_tree(
    record: ServiceTransaction,
    *,
    stage: bool,
    active_publication_completed: bool,
    active_rollback_completed: bool,
) -> None:
    root_field = "stage_dir" if stage else "backup_dir"
    identity_field = f"{root_field}_identity"
    removed_field = "stage_removed" if stage else "backup_removed"
    path = record[root_field]
    actual = _actual(path, f"Service {root_field}")
    step = "stage" if stage else "backup"
    removal_pending = record.phase is ServicePhase.CLEANING_UP and record[
        "checkpoint"
    ] == f"cleanup-{step}-pending"
    if actual is ABSENT:
        if record[removed_field] != "true":
            _die(f"Managed service {root_field} disappeared before cleanup")
        return
    if record[removed_field] == "true":
        _die(f"Managed service {root_field} reappeared after cleanup")
    expected_root = _directory_identity(record.identity(identity_field), identity_field)
    root_identity = _validate_directory(path, expected_root, f"Service {root_field}")
    try:
        root = OpenedDirectory(path, expected_identity=root_identity)
    except FilesystemError:
        _die(f"Service {root_field} identity changed")
    try:
        mutations = _mutation_map(record)
        if stage:
            pending_directory = _pending_directory_stage(record)
            all_mutations = {
                mutation.key: mutation
                for mutation in record.mutations
                if mutation.stage is not None
            }
            recorded = {
                key: mutation
                for key, mutation in all_mutations.items()
                if isinstance(mutation.stage_identity, FileIdentity)
            }
            allowed = dict(recorded)
            if (
                record.phase is ServicePhase.STAGING
                and record["checkpoint"] == "staging-pending"
                and record["mutation"] in all_mutations
            ):
                key = record["mutation"]
                allowed[key] = all_mutations[key]
            root_names = _directory_entries(root, "Managed service stage")
            allowed_names = {*allowed, "inputs"}
            if pending_directory is not None:
                allowed_names.add(pending_directory[0].key)
            if not root_names <= allowed_names:
                _die("Managed service stage has unexpected entries")
            if pending_directory is not None:
                pending_mutation, _pending_path, pending_identity = pending_directory
                if pending_mutation.key in root_names:
                    try:
                        pending = root.open_directory(
                            pending_mutation.key,
                            policy=_PRIVATE_DIRECTORY,
                            expected_identity=pending_identity,
                        )
                    except FilesystemError:
                        _die("Managed service directory stage identity changed")
                    try:
                        if _directory_entries(
                            pending, "Managed service directory stage"
                        ):
                            _die("Managed service directory stage is not empty")
                    finally:
                        pending.close()
                    if active_publication_completed:
                        _die("Managed service directory stage reappeared after publication")
            inputs_expected = _directory_identity(
                record.identity("inputs_dir_identity"), "inputs_dir_identity"
            )
            if "inputs" in root_names:
                inputs = root.open_directory(
                    "inputs", expected_identity=inputs_expected
                )
                try:
                    input_names = _directory_entries(
                        inputs, "Managed service input stage"
                    )
                    all_inputs = {item.key: item for item in record.signing_inputs}
                    recorded_inputs = {
                        key: item
                        for key, item in all_inputs.items()
                        if isinstance(item.stage_identity, FileIdentity)
                    }
                    allowed_inputs = dict(recorded_inputs)
                    if (
                        record.phase is ServicePhase.STAGING
                        and record["checkpoint"] == "staging-pending"
                    ):
                        active = record["mutation"]
                        pending = all_inputs
                        if active in pending:
                            allowed_inputs[active] = pending[active]
                    if not input_names <= set(allowed_inputs):
                        _die("Managed service input stage has unexpected entries")
                    for name in input_names:
                        item = allowed_inputs[name]
                        if isinstance(item.stage_identity, FileIdentity):
                            _read_exact_file(
                                item.stage,
                                item.stage_identity,
                                item.stage_sha256 or "",
                                f"Managed service staged input {name}",
                            )
                        else:
                            _validate_unrecorded_private_file(item.stage, name)
                    if not removal_pending and not set(recorded_inputs) <= input_names:
                        _die("Managed service input stage prefix is incomplete")
                finally:
                    inputs.close()
            elif not removal_pending:
                _die("Managed service input stage disappeared before cleanup")
            published = int(record["published_count"])
            consumed = set(record.publication_order[:published])
            if active_publication_completed:
                consumed.add(record["mutation"])
            for name in root_names - {"inputs"}:
                if (
                    pending_directory is not None
                    and name == pending_directory[0].key
                ):
                    continue
                mutation = allowed[name]
                if isinstance(mutation.stage_identity, FileIdentity):
                    _read_exact_file(
                        mutation.stage or "",
                        mutation.stage_identity,
                        mutation.stage_sha256 or "",
                        f"Managed service stage {name}",
                    )
                else:
                    _validate_unrecorded_private_file(mutation.stage or "", name)
            if not removal_pending:
                required = set(recorded) - consumed
                if not required <= root_names:
                    _die("Managed service stage prefix is incomplete")
        else:
            root_names = _directory_entries(root, "Managed service backup")
            all_backups = {
                mutation.key: mutation
                for mutation in record.mutations
                if mutation.backup is not None
            }
            recorded = {
                key: mutation
                for key, mutation in all_backups.items()
                if isinstance(mutation.backup_identity, FileIdentity)
            }
            allowed = dict(recorded)
            if (
                record.phase is ServicePhase.BACKING_UP
                and record["checkpoint"] == "backup-pending"
                and record["mutation"] in all_backups
            ):
                key = record["mutation"]
                allowed[key] = all_backups[key]
            if not root_names <= set(allowed):
                _die("Managed service backup has unexpected entries")
            rollback_order = managed_rollback_order(
                record.publication_order[: int(record["published_count"])]
            )
            rolled = set(rollback_order[: int(record["rollback_count"])])
            if (
                record.phase in {ServicePhase.CLEANING_UP, ServicePhase.TERMINAL}
                and record.outcome is ServiceOutcome.FAILED_PRE_COMMIT
            ):
                rolled = set(rollback_order)
            if active_rollback_completed:
                rolled.add(record["mutation"])
            for name in root_names:
                mutation = allowed[name]
                if isinstance(mutation.backup_identity, FileIdentity):
                    _read_exact_file(
                        mutation.backup or "",
                        mutation.backup_identity,
                        mutation.backup_sha256 or "",
                        f"Managed service backup {name}",
                    )
                else:
                    _validate_unrecorded_private_file(mutation.backup or "", name)
            if not removal_pending:
                required = set(recorded) - rolled
                if not required <= root_names:
                    _die("Managed service backup prefix is incomplete")
    finally:
        root.close()


def _validate_unrecorded_private_file(path: str, label: str) -> FileIdentity:
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=_OWNER,
                forbidden_bits=0o077,
                links=1,
                max_size=MAX_SERVICE_EVIDENCE_BYTES,
            ),
        ) as opened:
            opened.read(MAX_SERVICE_EVIDENCE_BYTES)
            return opened.identity
    except FilesystemError:
        _die(f"Unrecorded managed service {label} stage is unsafe")
    raise AssertionError("unreachable")


def _preflight(
    record: ServiceTransaction,
) -> tuple[FileIdentity | DirectoryIdentity | None, bool]:
    _validate_active_authority(record)
    _validate_retained_evidence(record)
    _validate_signing_inputs(record)
    publication, rollback_completed = _validate_destinations(record)
    _validate_private_tree(
        record,
        stage=True,
        active_publication_completed=publication is not None,
        active_rollback_completed=rollback_completed,
    )
    _validate_private_tree(
        record,
        stage=False,
        active_publication_completed=publication is not None,
        active_rollback_completed=rollback_completed,
    )
    return publication, rollback_completed


def validate_service_writer_publication_preflight(
    record: ServiceTransaction,
) -> None:
    """Authenticate one exact unapplied forward-publication boundary."""

    published = int(record["published_count"])
    if (
        record.phase is not ServicePhase.PUBLISHING
        or record["checkpoint"] != "publication-pending"
        or published >= len(record.publication_order)
        or record["mutation"] != record.publication_order[published]
        or record["committed"] != "false"
        or record.recovery_mode is not ServiceRecoveryMode.ROLLBACK
        or record.outcome is not ServiceOutcome.NONE
        or record["rollback_count"] != "0"
        or record["rollback_completion_count"] != "0"
    ):
        _die("Managed service writer is not at a forward publication boundary")
    _require_compatible_state(record.pki_dir)
    publication, rollback_completed = _preflight(record)
    if publication is not None or rollback_completed:
        _die("Managed service publication boundary was already applied")
    pending_directory = _pending_directory_stage(record)
    if pending_directory is not None:
        mutation, path, expected = pending_directory
        actual = _actual(path, "Managed service directory stage")
        if not _same_expected(actual, expected):
            _die("Managed service directory stage identity changed")
        try:
            with OpenedDirectory(
                path,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected,
            ) as opened:
                if _directory_entries(opened, "Managed service directory stage"):
                    _die("Managed service directory stage is not empty")
        except FilesystemError:
            _die(f"Managed service directory stage {mutation.key} is unsafe")


def _record_post_identity(
    control: _Control,
    record: ServiceTransaction,
    key: str,
    published: FileIdentity | DirectoryIdentity,
) -> Callable[[], None]:
    mutation = _mutation_map(record)[key]
    _checkpoint(
        "publication-reconcile-before-evidence",
        control.fault,
        control.pause,
    )
    control.recheck()

    def recheck_publication() -> None:
        if isinstance(published, DirectoryIdentity):
            actual = _validate_directory(
                mutation.destination,
                published,
                f"Published service destination {key}",
            )
            if actual.directory != published:
                _die(f"Published service destination {key} identity changed")
            return
        actual = _validate_file_state(
            mutation.destination,
            published,
            mutation.stage_sha256 or "",
            f"Published service destination {key}",
        )
        if actual != published:
            _die(f"Published service destination {key} identity changed")

    recheck_publication()
    if mutation.stage is None:
        if not isinstance(published, DirectoryIdentity):
            raise AssertionError("directory publication lacks authenticated identity")
        control.values[f"{key}_post_identity"] = serialize_directory_identity(
            published
        )
    else:
        if not isinstance(published, FileIdentity):
            raise AssertionError("file publication lacks authenticated identity")
        control.values[f"{key}_post_identity"] = serialize_file_identity(published)
        control.values[f"{key}_post_sha256"] = mutation.stage_sha256 or "none"
    control.values["published_count"] = str(int(record["published_count"]) + 1)
    control.values["checkpoint"] = "publication-done"
    return recheck_publication


def _record_rollback_identity(
    control: _Control,
    record: ServiceTransaction,
    key: str,
) -> None:
    mutation = _mutation_map(record)[key]
    if mutation.pre_identity is IdentitySentinel.ABSENT:
        control.values[f"{key}_rollback_identity"] = "absent"
        if mutation.stage is not None:
            control.values[f"{key}_rollback_sha256"] = "none"
    else:
        actual = _actual(mutation.destination, f"Restored service destination {key}")
        if not isinstance(actual, FileIdentity):
            _die(f"Restored service destination {key} is absent")
        control.values[f"{key}_rollback_identity"] = serialize_file_identity(actual)
        control.values[f"{key}_rollback_sha256"] = mutation.pre_sha256 or "none"
    control.values["rollback_count"] = str(int(record["rollback_count"]) + 1)
    control.values["checkpoint"] = "rollback-done"


def _reconcile_pending_window(
    control: _Control,
    record: ServiceTransaction,
    publication: FileIdentity | DirectoryIdentity | None,
    rollback_completed: bool,
) -> ServiceTransaction:
    if publication is not None:
        recheck = _record_post_identity(
            control,
            record,
            record["mutation"],
            publication,
        )
        return control.write(
            "publication-reconcile",
            pre_rewrite_check=recheck,
        )
    if rollback_completed:
        key = record["mutation"]
        _record_rollback_identity(control, record, key)
        return control.write(f"rollback-{key}-evidence")
    pending_directory = _pending_directory_stage(record)
    if pending_directory is not None:
        mutation, path, expected = pending_directory
        actual = _actual(path, "Managed service directory stage")
        if actual is not ABSENT:
            if not _same_expected(actual, expected):
                _die("Managed service directory stage identity changed")
            _checkpoint(
                "publication-directory-stage-discard-before-mutation",
                control.fault,
                control.pause,
            )
            control.recheck()
            _remove_empty_directory(
                path,
                expected,
                f"Managed service directory stage {mutation.key}",
            )
            _checkpoint(
                "publication-directory-stage-discard-after-mutation",
                control.fault,
                control.pause,
            )
        control.values[f"{mutation.key}_post_identity"] = "none"
        return control.write("publication-directory-stage-discard")
    if (
        record.phase is ServicePhase.ROLLING_BACK
        and record["checkpoint"] == "archive-root-restore-pending"
    ):
        snapshot = _file_identity(
            record.identity("archive_root_snapshot_identity"),
            "archive_root_snapshot_identity",
        )
        actual = _actual(
            _mutation_map(record)["archive_root"].destination,
            "Archive root",
        )
        if (
            isinstance(actual, FileIdentity)
            and actual.directory == snapshot.directory
            and actual.mtime_ns == snapshot.mtime_ns
        ):
            control.values["archive_root_restored"] = "true"
            control.values["archive_root_restored_identity"] = serialize_file_identity(
                actual
            )
            control.values["checkpoint"] = "archive-root-restore-done"
            return control.write("archive-root-restore-evidence")
    return record


def _set_rollback_pending(
    control: _Control,
    record: ServiceTransaction,
    key: str,
) -> ServiceTransaction:
    control.values.update(
        phase=ServicePhase.ROLLING_BACK.value,
        checkpoint="rollback-pending",
        mutation=key,
        outcome=ServiceOutcome.FAILED_PRE_COMMIT.value,
    )
    return control.write(f"rollback-{key}-pending")


def _remove_empty_directory(
    path: str,
    expected: DirectoryIdentity,
    label: str,
) -> None:
    parent, name = _parent(path)
    child = None
    try:
        child = parent.open_directory(name, expected_identity=expected)
        if _directory_entries(child, label):
            _die(f"{label} is not empty")
        try:
            readiness = fsync_tree(child, parent, name)
            if readiness.snapshot:
                _die(f"{label} is not empty")
            remove_exact_tree(
                parent,
                name,
                readiness.root_identity,
                readiness,
            )
        except PublicationError:
            _die(f"{label} could not be removed safely")
        if parent.identity_at(name) is not ABSENT:
            _die(f"{label} removal is ambiguous")
    finally:
        if child is not None:
            child.close()
        parent.close()


def _rollback_mutation(
    control: _Control,
    record: ServiceTransaction,
    key: str,
) -> None:
    mutation = _mutation_map(record)[key]
    _checkpoint(f"rollback-{key}-before-mutation", control.fault, control.pause)
    control.recheck()
    if mutation.pre_identity is IdentitySentinel.ABSENT:
        actual = _actual(mutation.destination, f"Published service destination {key}")
        if actual is ABSENT:
            _die(f"Published service destination {key} identity changed")
        elif not isinstance(actual, FileIdentity):
            _die(f"Published service destination {key} is unsafe")
        elif actual.kind == "regular":
            expected = _file_identity(
                mutation.post_identity, f"{key}_post_identity"
            )
            if actual != expected:
                _die(f"Published service destination {key} identity changed")
            parent, name = _parent(mutation.destination)
            try:
                try:
                    unlink_exact(parent, name, expected)
                except PublicationError:
                    _die(f"Cannot roll back service destination {key}")
            finally:
                parent.close()
        else:
            expected = _directory_identity(
                mutation.post_identity, f"{key}_post_identity"
            )
            _remove_empty_directory(
                mutation.destination, expected, f"Service directory {key}"
            )
    else:
        post = _file_identity(mutation.post_identity, f"{key}_post_identity")
        backup = _file_identity(
            mutation.backup_identity, f"{key}_backup_identity"
        )
        source_parent, source_name = _parent(mutation.backup or "")
        destination_parent, destination_name = _parent(mutation.destination)
        try:
            try:
                replace_exact(
                    source_parent,
                    source_name,
                    backup,
                    destination_parent,
                    destination_name,
                    post,
                )
            except PublicationError:
                _die(f"Cannot restore service destination {key}")
        finally:
            destination_parent.close()
            source_parent.close()
    _checkpoint(f"rollback-{key}-after-mutation", control.fault, control.pause)


def _restore_archive_root(
    control: _Control,
    record: ServiceTransaction,
) -> FileIdentity:
    mutation = _mutation_map(record)["archive_root"]
    snapshot = _file_identity(
        record.identity("archive_root_snapshot_identity"),
        "archive_root_snapshot_identity",
    )
    parent, name = _parent(mutation.destination)
    root = None
    try:
        root = parent.open_directory(name, expected_identity=snapshot.directory)
        _checkpoint(
            "archive-root-restore-before-mutation", control.fault, control.pause
        )
        control.recheck()
        try:
            current = os.fstat(root.fileno())
            os.utime(
                root.fileno(),
                ns=(current.st_atime_ns, snapshot.mtime_ns),
            )
            os.fsync(root.fileno())
            os.fsync(parent.fileno())
            restored = identity_from_stat(os.fstat(root.fileno()))
        except OSError:
            _die("Archive-root metadata could not be restored safely")
        if (
            restored.directory != snapshot.directory
            or restored.mtime_ns != snapshot.mtime_ns
            or parent.identity_at(name) != restored
        ):
            _die("Archive-root metadata restoration is ambiguous")
        _checkpoint(
            "archive-root-restore-after-mutation", control.fault, control.pause
        )
        return restored
    finally:
        if root is not None:
            root.close()
        parent.close()


def _archive_restore_needed(record: ServiceTransaction) -> bool:
    return (
        record["archive_root_restored"] == "false"
        and record["archive_root_snapshot_identity"] not in {"absent", "none"}
        and "archive_dir" in record.publication_order[: int(record["published_count"])]
    )


def _ensure_rollback_completion(
    control: _Control,
    record: ServiceTransaction,
) -> ServiceTransaction:
    if record["rollback_completion_path"] == "none":
        control.values.update(
            phase=ServicePhase.ROLLING_BACK.value,
            checkpoint="rollback-completion-pending",
            mutation="none",
            outcome=ServiceOutcome.FAILED_PRE_COMMIT.value,
            rollback_completion_path=(
                f"{record['transaction_dir']}/rollback-complete"
            ),
        )
        record = control.write("rollback-completion-pending")
    completion = record["rollback_completion_path"]
    expected = _expected_rollback_bytes(record)
    actual = _actual(completion, "Rollback completion record")
    if actual is ABSENT:
        _checkpoint(
            "rollback-completion-before-mutation", control.fault, control.pause
        )
        control.recheck()
        parent, name = _parent(completion)
        try:
            try:
                result = atomic_write_bytes(parent, name, expected)
                actual = _publication_identity(result)
            except PublicationError:
                _die("Rollback completion record could not be published safely")
        finally:
            parent.close()
        _checkpoint(
            "rollback-completion-after-mutation", control.fault, control.pause
        )
    elif record.identity("rollback_completion_identity") is IdentitySentinel.NONE:
        _die("Rollback completion record lacks journal identity evidence")
    if not isinstance(actual, FileIdentity):
        _die("Rollback completion record has an unsafe type")
    data, actual = _read_exact_file(
        completion,
        actual,
        hashlib.sha256(expected).hexdigest(),
        "Rollback completion record",
    )
    if data != expected:
        _die("Rollback completion record bytes changed")
    if record.identity("rollback_completion_identity") is IdentitySentinel.NONE:
        control.values.update(
            checkpoint="rollback-completion-done",
            rollback_completion_count=record["published_count"],
            rollback_completion_identity=serialize_file_identity(actual),
            rollback_completion_sha256=hashlib.sha256(expected).hexdigest(),
        )
        record = control.write("rollback-completion-evidence")
    return record


def _enter_failed_cleanup(
    control: _Control,
    record: ServiceTransaction,
) -> ServiceTransaction:
    if record["checkpoint"] != "rollback-evidence-clear-pending":
        control.values["checkpoint"] = "rollback-evidence-clear-pending"
        record = control.write("rollback-clear-pending")
    control.values["rollback_count"] = "0"
    for key in managed_rollback_order(record.publication_order):
        control.values[f"{key}_rollback_identity"] = "none"
        if f"{key}_rollback_sha256" in control.values:
            control.values[f"{key}_rollback_sha256"] = "none"
    control.values.update(
        phase=ServicePhase.CLEANING_UP.value,
        checkpoint="cleanup-stage-pending",
        mutation="none",
        recovery_mode=ServiceRecoveryMode.CLEANUP_ONLY.value,
    )
    return control.write("rollback-clear-evidence")


def _recover_precommit(
    control: _Control,
    record: ServiceTransaction,
) -> ServiceTransaction:
    while True:
        rolled = int(record["rollback_count"])
        order = managed_rollback_order(
            record.publication_order[: int(record["published_count"])]
        )
        if rolled < len(order):
            if _archive_restore_needed(record) and order.index("archive_dir") < rolled:
                if record["checkpoint"] != "archive-root-restore-pending":
                    control.values.update(
                        phase=ServicePhase.ROLLING_BACK.value,
                        checkpoint="archive-root-restore-pending",
                        mutation="none",
                        outcome=ServiceOutcome.FAILED_PRE_COMMIT.value,
                    )
                    record = control.write("archive-root-restore-pending")
                restored = _restore_archive_root(control, record)
                control.values.update(
                    checkpoint="archive-root-restore-done",
                    archive_root_restored="true",
                    archive_root_restored_identity=serialize_file_identity(restored),
                )
                record = control.write("archive-root-restore-evidence")
                continue
            key = order[rolled]
            if not (
                record.phase is ServicePhase.ROLLING_BACK
                and record["checkpoint"] == "rollback-pending"
                and record["mutation"] == key
            ):
                record = _set_rollback_pending(control, record, key)
            _rollback_mutation(control, record, key)
            _record_rollback_identity(control, record, key)
            record = control.write(f"rollback-{key}-evidence")
            continue
        if _archive_restore_needed(record):
            if record["checkpoint"] != "archive-root-restore-pending":
                control.values.update(
                    phase=ServicePhase.ROLLING_BACK.value,
                    checkpoint="archive-root-restore-pending",
                    mutation="none",
                    outcome=ServiceOutcome.FAILED_PRE_COMMIT.value,
                )
                record = control.write("archive-root-restore-pending")
            restored = _restore_archive_root(control, record)
            control.values.update(
                checkpoint="archive-root-restore-done",
                archive_root_restored="true",
                archive_root_restored_identity=serialize_file_identity(restored),
            )
            record = control.write("archive-root-restore-evidence")
            continue
        record = _ensure_rollback_completion(control, record)
        return _enter_failed_cleanup(control, record)


def _validate_exact_recorded_file(
    path: str,
    expected: FileIdentity,
    digest: str,
    label: str,
) -> None:
    _read_exact_file(path, expected, digest, label)


def _cleanup_private_tree(record: ServiceTransaction, *, stage: bool) -> None:
    root_field = "stage_dir" if stage else "backup_dir"
    root_path = record[root_field]
    actual = _actual(root_path, "Managed service private cleanup tree")
    if actual is ABSENT:
        _die("Managed service private cleanup tree disappeared before mutation")
    if not isinstance(actual, FileIdentity) or actual.kind != "directory":
        _die("Managed service private cleanup tree is unsafe")
    expected_root = _directory_identity(
        record.identity(f"{root_field}_identity"), f"{root_field}_identity"
    )
    if actual.directory != expected_root:
        _die("Managed service private cleanup tree identity changed")
    parent, root_name = _parent(root_path)
    try:
        root = parent.open_directory(root_name, expected_identity=expected_root)
    except FilesystemError:
        parent.close()
        _die("Managed service private cleanup tree identity changed")
    input_members = {}
    try:
        if stage:
            names = _directory_entries(root, "Managed service stage cleanup")
            consumed = set(
                record.publication_order[: int(record["published_count"])]
            )
            members = {
                mutation.key: mutation
                for mutation in record.mutations
                if mutation.stage is not None
                and isinstance(mutation.stage_identity, FileIdentity)
                and mutation.key not in consumed
            }
            if names != {*members, "inputs"}:
                _die("Managed service stage cleanup prefix changed")
            for name in sorted(members):
                mutation = members[name]
                _validate_exact_recorded_file(
                    mutation.stage or "",
                    _file_identity(
                        mutation.stage_identity, f"{name}_stage_identity"
                    ),
                    mutation.stage_sha256 or "",
                    f"Service stage {name}",
                )

            inputs_path = f"{root_path}/inputs"
            inputs_expected = _directory_identity(
                record.identity("inputs_dir_identity"), "inputs_dir_identity"
            )
            inputs = root.open_directory("inputs", expected_identity=inputs_expected)
            try:
                input_names = _directory_entries(
                    inputs, "Managed service input cleanup"
                )
                input_members = {
                    item.key: item
                    for item in record.signing_inputs
                    if isinstance(item.stage_identity, FileIdentity)
                }
                if input_names != set(input_members):
                    _die("Managed service input cleanup prefix changed")
                for name in sorted(input_members):
                    item = input_members[name]
                    _validate_exact_recorded_file(
                        item.stage,
                        _file_identity(
                            item.stage_identity, f"{name}_stage_identity"
                        ),
                        item.stage_sha256 or "",
                        f"Service input stage {name}",
                    )
            finally:
                inputs.close()
        else:
            names = _directory_entries(root, "Managed service backup cleanup")
            consumed = (
                set(
                    managed_rollback_order(
                        record.publication_order[
                            : int(record["published_count"])
                        ]
                    )
                )
                if record.outcome is ServiceOutcome.FAILED_PRE_COMMIT
                else set()
            )
            members = {
                mutation.key: mutation
                for mutation in record.mutations
                if mutation.backup is not None
                and isinstance(mutation.backup_identity, FileIdentity)
                and mutation.key not in consumed
            }
            if names != set(members):
                _die("Managed service backup cleanup prefix changed")
            for name in sorted(members):
                mutation = members[name]
                _validate_exact_recorded_file(
                    mutation.backup or "",
                    _file_identity(
                        mutation.backup_identity, f"{name}_backup_identity"
                    ),
                    mutation.backup_sha256 or "",
                    f"Service backup {name}",
                )
        try:
            readiness = fsync_tree(root, parent, root_name)
        except PublicationError:
            _die("Managed service private cleanup tree changed")
        if readiness.root_identity.directory != expected_root:
            _die("Managed service private cleanup tree identity changed")

        if stage:
            for name in sorted(members):
                mutation = members[name]
                _validate_exact_recorded_file(
                    mutation.stage or "",
                    _file_identity(
                        mutation.stage_identity, f"{name}_stage_identity"
                    ),
                    mutation.stage_sha256 or "",
                    f"Service stage {name}",
                )
            for name in sorted(input_members):
                item = input_members[name]
                _validate_exact_recorded_file(
                    item.stage,
                    _file_identity(
                        item.stage_identity, f"{name}_stage_identity"
                    ),
                    item.stage_sha256 or "",
                    f"Service input stage {name}",
                )
        else:
            for name in sorted(members):
                mutation = members[name]
                _validate_exact_recorded_file(
                    mutation.backup or "",
                    _file_identity(
                        mutation.backup_identity, f"{name}_backup_identity"
                    ),
                    mutation.backup_sha256 or "",
                    f"Service backup {name}",
                )
        try:
            remove_exact_tree(
                parent,
                root_name,
                readiness.root_identity,
                readiness,
            )
        except PublicationError:
            _die("Managed service private cleanup tree could not be removed safely")
    finally:
        root.close()
        parent.close()


def _cleanup_step_order(record: ServiceTransaction) -> tuple[str, ...]:
    return (
        *service_cleanup_owned_keys(record.operation, record.outcome),
        "terminal",
        "journal",
    )


def _next_cleanup_pending(
    control: _Control,
    record: ServiceTransaction,
    completed: str,
) -> ServiceTransaction:
    steps = _cleanup_step_order(record)
    following = steps[steps.index(completed) + 1]
    if following == "journal":
        control.values.update(
            phase=ServicePhase.TERMINAL.value,
            checkpoint="journal-cleanup-pending",
        )
    else:
        control.values["checkpoint"] = f"cleanup-{following}-pending"
    return control.write(
        "cleanup-terminal-next"
        if completed == "terminal"
        else f"cleanup-{completed}-next"
    )


def _ensure_cleanup_started(
    control: _Control,
    record: ServiceTransaction,
) -> ServiceTransaction:
    if record.phase is not ServicePhase.COMMITTED:
        return record
    first = _cleanup_step_order(record)[0]
    control.values.update(
        phase=ServicePhase.CLEANING_UP.value,
        checkpoint=f"cleanup-{first}-pending",
        mutation="none",
    )
    return control.write("cleanup-start")


def _publish_terminal(
    control: _Control,
    record: ServiceTransaction,
) -> FileIdentity:
    expected = _expected_terminal_bytes(record)
    actual = _actual(record["terminal_path"], "Managed service terminal record")
    if actual is ABSENT:
        _checkpoint(
            "cleanup-terminal-before-mutation", control.fault, control.pause
        )
        control.recheck()
        parent, name = _parent(record["terminal_path"])
        try:
            try:
                result = atomic_write_bytes(parent, name, expected)
                actual = _publication_identity(result)
            except PublicationError:
                _die("Managed service terminal record could not be published safely")
        finally:
            parent.close()
        _checkpoint(
            "cleanup-terminal-after-mutation", control.fault, control.pause
        )
    elif record.identity("terminal_identity") is IdentitySentinel.NONE:
        _die("Managed service terminal record lacks journal identity evidence")
    if not isinstance(actual, FileIdentity):
        _die("Managed service terminal record has an unsafe type")
    data, actual = _read_exact_file(
        record["terminal_path"],
        actual,
        hashlib.sha256(expected).hexdigest(),
        "Managed service terminal record",
    )
    if data != expected:
        _die("Managed service terminal record bytes changed")
    return actual


def _recover_cleanup(
    control: _Control,
    record: ServiceTransaction,
) -> ServiceTransaction:
    record = _ensure_cleanup_started(control, record)
    while record.phase is not ServicePhase.TERMINAL:
        checkpoint = record["checkpoint"]
        if checkpoint.endswith("-done"):
            completed = checkpoint.removeprefix("cleanup-").removesuffix("-done")
            record = _next_cleanup_pending(control, record, completed)
            continue
        step = checkpoint.removeprefix("cleanup-").removesuffix("-pending")
        if step == "archive-marker":
            marker = _mutation_map(record)["archive_marker"]
            actual = _actual(marker.destination, "Renewal archive marker")
            if actual is ABSENT:
                _die("Renewal archive marker disappeared before cleanup")
            expected = _file_identity(
                marker.post_identity, "archive_marker_post_identity"
            )
            if actual != expected:
                _die("Renewal archive marker identity changed")
            _read_exact_file(
                marker.destination,
                expected,
                marker.post_sha256 or "",
                "Renewal archive marker",
            )
            _checkpoint(
                "cleanup-archive-marker-before-mutation",
                control.fault,
                control.pause,
            )
            control.recheck()
            parent, name = _parent(marker.destination)
            try:
                try:
                    unlink_exact(parent, name, expected)
                except PublicationError:
                    _die("Renewal archive marker could not be removed safely")
            finally:
                parent.close()
            _checkpoint(
                "cleanup-archive-marker-after-mutation",
                control.fault,
                control.pause,
            )
            control.values.update(
                checkpoint="cleanup-archive-marker-done",
                archive_marker_removed="true",
            )
            record = control.write("cleanup-archive-marker-evidence")
        elif step in {"stage", "backup"}:
            removed_field = f"{step}_removed"
            _checkpoint(
                f"cleanup-{step}-before-mutation",
                control.fault,
                control.pause,
            )
            control.recheck()
            _cleanup_private_tree(record, stage=step == "stage")
            _checkpoint(
                f"cleanup-{step}-after-mutation",
                control.fault,
                control.pause,
            )
            control.values.update(
                checkpoint=f"cleanup-{step}-done",
                **{removed_field: "true"},
            )
            record = control.write(f"cleanup-{step}-evidence")
        elif step == "terminal":
            terminal = _publish_terminal(control, record)
            expected = _expected_terminal_bytes(record)
            control.values.update(
                checkpoint="cleanup-terminal-done",
                terminal_identity=serialize_file_identity(terminal),
                terminal_sha256=hashlib.sha256(expected).hexdigest(),
            )
            record = control.write("cleanup-terminal-evidence")
        else:
            raise AssertionError("unexpected managed service cleanup checkpoint")
    return record


@dataclass(frozen=True, slots=True)
class _CleanupAbsence:
    key: str
    path: str
    label: str


def _cleanup_absences(
    pki_dir: str,
    record: Mapping[str, str],
    outcome: ServiceOutcome,
) -> tuple[_CleanupAbsence, ...]:
    operation = ServiceOperation(record["operation"])
    transaction_dir = os.path.join(
        pki_dir,
        SERVICE_TRANSACTION_TREE_RELATIVE_PATH,
        record["transaction"],
    )
    paths = {
        "stage": _CleanupAbsence(
            "stage", os.path.join(transaction_dir, "stage"), "Managed service stage"
        ),
        "backup": _CleanupAbsence(
            "backup", os.path.join(transaction_dir, "backup"), "Managed service backup"
        ),
    }
    if "archive-marker" in service_cleanup_owned_keys(operation, outcome):
        marker = os.path.join(
            pki_dir,
            "services",
            record["service"],
            "archive",
            record["archive_name"],
            ".platform-pki-renew-archive",
        )
        paths["archive-marker"] = _CleanupAbsence(
            "archive-marker", marker, "Managed service renewal archive marker"
        )
    return tuple(
        paths[key] for key in service_cleanup_owned_keys(operation, outcome)
    )


def _journal_cleanup_absences(
    record: ServiceTransaction,
) -> tuple[_CleanupAbsence, ...]:
    absences = _cleanup_absences(record.pki_dir, record, record.outcome)
    mutations = _mutation_map(record)
    for absence in absences:
        if absence.key == "stage":
            claimed = record["stage_dir"]
        elif absence.key == "backup":
            claimed = record["backup_dir"]
        else:
            claimed = mutations["archive_marker"].destination
        if absence.path != claimed:
            _die(f"{absence.label} path is outside its cleanup contract")
    return absences


def _require_cleanup_absences(
    absences: tuple[_CleanupAbsence, ...],
    *,
    transaction_directory: OpenedDirectory | None = None,
) -> None:
    for absence in absences:
        if transaction_directory is not None and absence.key in {"stage", "backup"}:
            actual = transaction_directory.identity_at(absence.key)
        else:
            actual = _actual(absence.path, absence.label)
        if actual is not ABSENT:
            _die(f"{absence.label} reappeared after authenticated cleanup")


def _remove_journal(control: _Control, record: ServiceTransaction) -> None:
    _checkpoint("journal-before-mutation", control.fault, control.pause)
    control.recheck()
    _validate_retained_evidence(record)
    control.recheck()
    parent, name = _parent(control.path)
    try:
        _require_cleanup_absences(_journal_cleanup_absences(record))
        try:
            unlink_exact(parent, name, control.identity)
        except PublicationError:
            _die("Managed service journal changed before terminal cleanup")
    finally:
        parent.close()
    _checkpoint("journal-after-mutation", control.fault, control.pause)


def _validate_terminal_transaction(pki_dir: str, transaction: str) -> tuple[str, str]:
    transaction_dir = (
        f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
    )
    try:
        directory = OpenedDirectory(transaction_dir, policy=_PRIVATE_DIRECTORY)
    except FilesystemError:
        _die("No retained managed service transaction exists")
    try:
        transaction_data = b""
        transaction_identity: FileIdentity | None = None
        try:
            with directory.open_file(
                "transaction",
                policy=FilePolicy(
                    owner=_OWNER,
                    mode=SERVICE_TRANSACTION_FILE_MODE,
                    links=1,
                    max_size=MAX_SERVICE_EVIDENCE_BYTES,
                ),
            ) as opened:
                transaction_data = opened.read(MAX_SERVICE_EVIDENCE_BYTES)
                transaction_identity = opened.identity
        except FilesystemError:
            _die("Retained managed service transaction is unsafe")
        assert transaction_identity is not None
        terminal_data = b""
        terminal_identity: FileIdentity | None = None
        try:
            retained = parse_service_retained_transaction(transaction_data)
        except ServiceTransactionError:
            _die("Retained managed service transaction bytes are invalid")
        if retained["transaction"] != transaction:
            _die("Retained managed service transaction ID changed")

        try:
            with directory.open_file(
                "terminal",
                policy=FilePolicy(
                    owner=_OWNER,
                    mode=SERVICE_TRANSACTION_FILE_MODE,
                    links=1,
                    max_size=MAX_SERVICE_EVIDENCE_BYTES,
                ),
            ) as opened:
                terminal_data = opened.read(MAX_SERVICE_EVIDENCE_BYTES)
                terminal_identity = opened.identity
        except FilesystemError:
            _die("Retained managed service terminal is unsafe")
        assert terminal_identity is not None
        try:
            terminal = parse_service_retained_terminal(terminal_data)
        except ServiceTransactionError:
            _die("Retained managed service terminal bytes are invalid")
        if (
            terminal["transaction"] != transaction
            or parse_file_identity(terminal["transaction_identity"])
            != transaction_identity
            or terminal["transaction_sha256"]
            != hashlib.sha256(transaction_data).hexdigest()
            or terminal["operation"] != retained["operation"]
            or terminal["service"] != retained["service"]
            or transaction_identity.uid != int(retained["owner"])
        ):
            _die("Retained managed service terminal binding changed")
        try:
            terminal_outcome = ServiceOutcome(terminal["outcome"])
        except ValueError:
            raise AssertionError("parsed terminal has an invalid outcome") from None
        cleanup_absences = _cleanup_absences(pki_dir, retained, terminal_outcome)

        retained_rollback_identity: FileIdentity | None = None
        if terminal["outcome"] == ServiceOutcome.FAILED_PRE_COMMIT.value:
            rollback_identity = parse_file_identity(
                terminal["rollback_completion_identity"]
            )
            assert isinstance(rollback_identity, FileIdentity)
            if rollback_identity.uid != transaction_identity.uid:
                _die("Retained managed service rollback completion owner changed")
            retained_rollback_identity = rollback_identity
            if rollback_identity.size > MAX_SERVICE_EVIDENCE_BYTES:
                _die("Retained managed service rollback completion exceeds the read limit")
            rollback_data = b""
            try:
                with directory.open_file(
                    "rollback-complete",
                    policy=FilePolicy(
                        owner=rollback_identity.uid,
                        mode=rollback_identity.permissions,
                        links=1,
                        max_size=MAX_SERVICE_EVIDENCE_BYTES,
                    ),
                    expected_identity=rollback_identity,
                ) as opened:
                    rollback_data = opened.read(MAX_SERVICE_EVIDENCE_BYTES)
            except FilesystemError:
                _die("Retained managed service rollback completion identity changed")
            if hashlib.sha256(rollback_data).hexdigest() != terminal[
                "rollback_completion_sha256"
            ]:
                _die("Retained managed service rollback completion digest changed")
            try:
                rollback = parse_service_retained_rollback(rollback_data)
            except ServiceTransactionError:
                _die("Retained managed service rollback completion bytes are invalid")
            if (
                rollback["transaction"] != transaction
                or rollback["operation"] != retained["operation"]
                or rollback["service"] != retained["service"]
            ):
                _die("Retained managed service rollback completion binding changed")
        elif directory.identity_at("rollback-complete") is not ABSENT:
            _die("Retained managed service rollback completion is unexpected")
        _require_cleanup_absences(
            cleanup_absences,
            transaction_directory=directory,
        )
        if (
            directory.identity_at("transaction") != transaction_identity
            or directory.identity_at("terminal") != terminal_identity
            or (
                retained_rollback_identity is not None
                and directory.identity_at("rollback-complete")
                != retained_rollback_identity
            )
        ):
            _die("Retained managed service evidence changed during validation")
        directory.recheck()
        return terminal["service"], terminal["outcome"]
    except FilesystemError:
        _die("Retained managed service transaction directory changed")
    finally:
        directory.close()


def _recover_service_locked(
    pki_dir: str,
    *,
    transaction: str,
    output: TextIO,
    fault_hook: FaultHook,
    pause_hook: PauseHook,
) -> int:
    _require_compatible_state(pki_dir)
    journal_path = f"{pki_dir}/{SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH}"
    has_journal = os.path.lexists(journal_path)
    bootstrap_path = f"{pki_dir}/{SERVICE_BOOTSTRAP_RELATIVE_PATH}"
    bootstrap_stage = f"{pki_dir}/state/service/.{transaction}.bootstrap.publish"
    reconciled_bootstrap = False
    if os.path.lexists(bootstrap_path) or os.path.lexists(bootstrap_stage):
        reconciled_bootstrap = clear_service_bootstrap(
            pki_dir,
            transaction,
            remove_tree=not has_journal,
            fault_hook=fault_hook,
            pause_hook=pause_hook,
        )
    history_path = f"{pki_dir}/state/service/bootstrap-history/{transaction}"
    if os.path.lexists(history_path):
        history_data = b""
        try:
            with OpenedFile(history_path, policy=_JOURNAL_FILE) as historical:
                history_data = historical.read(MAX_SERVICE_JOURNAL_BYTES)
                historical.recheck()
        except FilesystemError:
            _die("Managed service bootstrap history is unsafe")
        _parse_service_bootstrap(history_data, pki_dir, transaction)
        if not has_journal:
            transaction_path = (
                f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
            )
            if os.path.lexists(transaction_path):
                _die("Managed service bootstrap history has unresolved transaction state")
            print(
                (
                    f"[OK] Recovered managed service bootstrap transaction: {transaction}"
                    if reconciled_bootstrap
                    else f"[OK] Managed service bootstrap transaction already recovered: {transaction}"
                ),
                file=output,
            )
            output.flush()
            return 0
    if not has_journal:
        service, outcome = _validate_terminal_transaction(pki_dir, transaction)
        print(
            f"[OK] Managed service transaction already recovered: "
            f"{service} ({outcome})",
            file=output,
        )
        output.flush()
        return 0

    control, record = _load_journal(
        journal_path, pki_dir, fault_hook, pause_hook
    )
    if record["transaction"] != transaction:
        _die("Requested managed service transaction does not match the journal")
    expected_dir = (
        f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
    )
    if record["transaction_dir"] != expected_dir:
        _die("Managed service transaction directory is outside its contract")
    _checkpoint("journal-loaded", fault_hook, pause_hook)
    publication, rollback_completed = _preflight(record)
    control.recheck()
    record = _reconcile_pending_window(
        control,
        record,
        publication,
        rollback_completed,
    )
    if record["committed"] == "true":
        if record.recovery_mode is not ServiceRecoveryMode.CLEANUP_ONLY:
            _die("Committed managed service recovery cannot roll back")
    elif record.phase not in {ServicePhase.CLEANING_UP, ServicePhase.TERMINAL}:
        record = _recover_precommit(control, record)
    record = _recover_cleanup(control, record)
    _remove_journal(control, record)
    print(
        f"[OK] Recovered managed service transaction: "
        f"{record['service']} ({record['outcome']})",
        file=output,
    )
    output.flush()
    return 0


def recover_service_transaction(
    pki_dir: os.PathLike[str] | str,
    *,
    transaction: str,
    output: TextIO | None = None,
    fault_hook: FaultHook = DEFAULT_FAULT_HOOK,
    pause_hook: PauseHook = DEFAULT_PAUSE_HOOK,
) -> int:
    """Recover one exact Python managed-service journal without public dispatch."""

    path = os.fspath(pki_dir)
    if not isinstance(path, str):
        raise TypeError("pki_dir must be a text path")
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("pki_dir must be an absolute normalized path")
    if not isinstance(transaction, str) or _TRANSACTION.fullmatch(transaction) is None:
        raise ValueError("transaction must be a canonical managed service ID")
    if not callable(fault_hook) or not callable(pause_hook):
        raise TypeError("recovery hooks must be callable")
    stream = sys.stdout if output is None else output
    require_pki_directory(path)
    prepare_control_state(path)
    with acquire_operational_locks(path, "inventory"):
        return _recover_service_locked(
            path,
            transaction=transaction,
            output=stream,
            fault_hook=fault_hook,
            pause_hook=pause_hook,
        )


def service_recovery_hooks(
    environment: Mapping[str, str],
) -> tuple[FaultHook, PauseHook]:
    """Build isolated managed-service recovery fault and pause hooks."""

    return (
        FaultHook(
            crash_at=environment.get("PLATFORM_PKI_SERVICE_RECOVER_CRASH_AT"),
            signal_at=environment.get("PLATFORM_PKI_SERVICE_RECOVER_SIGNAL_AT"),
            failure_at=environment.get("PLATFORM_PKI_SERVICE_RECOVER_FAILURE_AT"),
        ),
        PauseHook(
            pause_at=environment.get("PLATFORM_PKI_SERVICE_RECOVER_PAUSE_AT"),
            marker=environment.get("PLATFORM_PKI_SERVICE_RECOVER_PAUSE_MARKER"),
            release=environment.get("PLATFORM_PKI_SERVICE_RECOVER_PAUSE_RELEASE"),
        ),
    )
