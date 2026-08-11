"""Durable writer state machine for Python managed-service transactions.

This module owns journal publication, legal evidence transitions, and exact
planned publication only. It consumes a complete externally prepared
transaction model; it does not plan transactions, create stages or backups, run
OpenSSL, invoke recovery, or implement host-local signing. The recovery module
owns all rollback and terminal cleanup.
"""

from __future__ import annotations

import hashlib
import os
import signal
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import NoReturn

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
from .persisted_identity import (
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
)
from .publication import (
    PublicationError,
    StagedFile,
    TreeReadiness,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    replace_exact,
    stage_file_bytes,
)
from .service_transaction import (
    SERVICE_TRANSACTION_FIELDS,
    SERVICE_TRANSACTION_FILE_MODE,
    ServiceOutcome,
    ServicePhase,
    ServiceRecoveryMode,
    ServiceTransaction,
    ServiceTransactionError,
    parse_service_transaction,
)
from .service_recover import validate_service_writer_publication_preflight


MAX_SERVICE_WRITER_EVIDENCE_BYTES = 64 * 1024 * 1024
_OWNER = os.geteuid()
_HANDLED_SIGNALS = frozenset((signal.SIGHUP, signal.SIGINT, signal.SIGTERM))
_JOURNAL_FILE = FilePolicy(
    owner=_OWNER,
    mode=SERVICE_TRANSACTION_FILE_MODE,
    links=1,
    max_size=4 * 1024 * 1024,
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


@contextmanager
def defer_service_writer_signals() -> Iterator[None]:
    """Defer handled termination signals across mutation/evidence assignments."""

    previous = signal.pthread_sigmask(signal.SIG_BLOCK, _HANDLED_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _checkpoint(point: str, fault: FaultHook, pause: PauseHook) -> None:
    fault(point)
    pause(point)


def _parent(path: str) -> tuple[OpenedDirectory, str]:
    parent_path, name = os.path.split(path)
    try:
        return OpenedDirectory(parent_path), name
    except FilesystemError:
        _die("Managed service writer parent path is unsafe")


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


def _self_sized_bytes(
    values: dict[str, str], state: FileObjectState, pki_dir: str
) -> bytes:
    size = 0
    while True:
        values["journal_identity"] = serialize_file_object_state(
            replace(state, size=size)
        )
        try:
            data = "".join(
                f"{field}={values[field]}\n" for field in SERVICE_TRANSACTION_FIELDS
            ).encode("ascii")
        except (KeyError, UnicodeEncodeError):
            _die("Managed service writer journal could not be serialized safely")
        if len(data) == size:
            try:
                parse_service_transaction(data, pki_dir=pki_dir)
            except ServiceTransactionError as error:
                _die(str(error))
            return data
        size = len(data)


def _stage_journal(
    parent: OpenedDirectory,
    name: str,
    values: dict[str, str],
    pki_dir: str,
) -> tuple[StagedFile, bytes]:
    stage = stage_file_bytes(
        parent,
        name,
        b"",
        mode=SERVICE_TRANSACTION_FILE_MODE,
        owner=_OWNER,
    )
    try:
        data = _self_sized_bytes(values, stage.identity.state, pki_dir)
        expected = replace(stage.identity.state, size=len(data))
        os.ftruncate(stage.fileno(), len(data))
        _write_all_at(stage.fileno(), data)
        os.fsync(stage.fileno())
        stage.identity = identity_from_stat(os.fstat(stage.fileno()))
        if stage.identity.state != expected:
            _die("Managed service writer journal stage is inconsistent")
        with parent.open_file(
            stage.name,
            policy=_JOURNAL_FILE,
            expected_identity=stage.identity,
        ) as opened:
            if opened.read(_JOURNAL_FILE.max_size or len(data)) != data:
                _die("Managed service writer journal stage is inconsistent")
        return stage, data
    except BaseException:
        try:
            stage.cleanup()
        finally:
            stage.close()
        raise


def _read_evidence(path: str, label: str) -> tuple[FileIdentity, str]:
    identity: FileIdentity | None = None
    data = b""
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=_OWNER,
                forbidden_bits=0o022,
                links=1,
                max_size=MAX_SERVICE_WRITER_EVIDENCE_BYTES,
            ),
        ) as opened:
            data = opened.read(MAX_SERVICE_WRITER_EVIDENCE_BYTES)
            identity = opened.recheck()
    except FilesystemError:
        _die(f"Managed service {label} is unsafe")
    assert identity is not None
    return identity, hashlib.sha256(data).hexdigest()


def _actual(path: str, label: str) -> FileIdentity:
    try:
        identity = identity_at(path)
    except FilesystemError:
        _die(f"Managed service {label} could not be inspected safely")
    if not isinstance(identity, FileIdentity):
        _die(f"Managed service {label} is absent")
    return identity


def _cleanup_staged_directory(
    parent: OpenedDirectory,
    name: str,
    expected: FileIdentity,
) -> None:
    child: OpenedDirectory | None = None
    try:
        if parent.identity_at(name) != expected:
            return
        child = parent.open_directory(
            name,
            policy=DirectoryPolicy(owner=_OWNER, mode=0o700),
            expected_identity=expected,
        )
        if os.listdir(child.fileno()):
            return
        readiness = fsync_tree(child, parent, name)
        if readiness.snapshot:
            return
        remove_exact_tree(parent, name, expected, readiness)
    finally:
        if child is not None:
            child.close()


def _stage_directory(
    parent: OpenedDirectory,
    name: str,
    key: str,
    fault: FaultHook,
    pause: PauseHook,
) -> tuple[FileIdentity, TreeReadiness]:
    created: FileIdentity | None = None
    child: OpenedDirectory | None = None
    try:
        parent.recheck()
        if parent.identity_at(name) is not ABSENT:
            _die("Managed service directory stage already exists")
        os.mkdir(name, 0o700, dir_fd=parent.fileno())
        actual = parent.identity_at(name)
        if (
            not isinstance(actual, FileIdentity)
            or actual.kind != "directory"
            or actual.uid != _OWNER
            or actual.permissions != 0o700
        ):
            _die("Managed service directory stage is unsafe")
        created = actual
        _checkpoint(
            f"publish-{key}-after-directory-stage-create",
            fault,
            pause,
        )
        child = parent.open_directory(
            name,
            policy=DirectoryPolicy(owner=_OWNER, mode=0o700),
            expected_identity=created,
        )
        readiness = fsync_tree(child, parent, name)
        if readiness.snapshot or child.recheck() != created:
            _die("Managed service directory stage changed before evidence")
        return created, readiness
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if created is not None:
            try:
                _cleanup_staged_directory(parent, name, created)
            except BaseException as cleanup:
                cleanup_error = cleanup
        if cleanup_error is not None:
            raise error from cleanup_error
        raise
    finally:
        if child is not None:
            child.close()


def _publish_directory(
    key: str,
    source_parent: OpenedDirectory,
    source_name: str,
    source_identity: FileIdentity,
    readiness: TreeReadiness,
    destination_parent: OpenedDirectory,
    destination_name: str,
    fault: FaultHook,
    pause: PauseHook,
) -> FileIdentity:
    def publication_fault(point: str) -> None:
        if point == "publication-after-mutation":
            fault(f"publish-{key}-after-directory-publication")

    def publication_pause(point: str) -> None:
        if point == "publication-after-mutation":
            pause(f"publish-{key}-after-directory-publication")

    try:
        result = publish_no_clobber(
            source_parent,
            source_name,
            source_identity,
            destination_parent,
            destination_name,
            readiness=readiness,
            fault_hook=publication_fault,
            pause_hook=publication_pause,
        )
        return _publication_identity(result)
    except (OSError, FilesystemError, PublicationError):
        _die("Managed service directory publication requires recovery")


def _publish_file(
    record: ServiceTransaction,
    key: str,
    source_parent: OpenedDirectory,
    source_name: str,
    destination_parent: OpenedDirectory,
    destination_name: str,
) -> FileIdentity:
    mutation = next(item for item in record.mutations if item.key == key)
    if mutation.stage is None or not isinstance(mutation.stage_identity, FileIdentity):
        raise AssertionError("planned service file publication lacks staged evidence")
    try:
        if isinstance(mutation.pre_identity, FileIdentity):
            if not mutation.replace:
                raise AssertionError("planned service destination cannot be replaced")
            result = replace_exact(
                source_parent,
                source_name,
                mutation.stage_identity,
                destination_parent,
                destination_name,
                mutation.pre_identity,
            )
        else:
            result = publish_no_clobber(
                source_parent,
                source_name,
                mutation.stage_identity,
                destination_parent,
                destination_name,
            )
        return _publication_identity(result)
    except (OSError, FilesystemError, PublicationError):
        _die("Managed service file publication requires recovery")


def _snapshot_publication_parents(
    record: ServiceTransaction,
) -> dict[str, DirectoryIdentity]:
    parents: dict[str, DirectoryIdentity] = {}
    planned_directories = {
        mutation.destination
        for mutation in record.mutations
        if mutation.stage is None and mutation.key in record.publication_order
    }
    paths_to_bind = {
        f"{record.pki_dir}/authorities/roots/{record['issuer_root']}",
        f"{record.pki_dir}/authorities/intermediates/{record['issuer_intermediate']}",
        record["transaction_dir"],
        record["stage_dir"],
        record["inputs_dir"],
        record["backup_dir"],
        *(os.path.dirname(item.source) for item in record.signing_inputs),
    }
    for key in record.publication_order:
        mutation = next(item for item in record.mutations if item.key == key)
        paths_to_bind.add(os.path.dirname(mutation.destination))
        if mutation.stage is not None:
            paths_to_bind.add(os.path.dirname(mutation.stage))
    for path in paths_to_bind:
        if not os.path.lexists(path):
            if path not in planned_directories:
                _die("Managed service publication parent is absent")
            continue
        try:
            actual = identity_at(path)
        except FilesystemError:
            _die("Managed service publication parent could not be inspected safely")
        if actual is ABSENT:
            if path not in planned_directories:
                _die("Managed service publication parent is absent")
            continue
        if actual.kind != "directory":
            _die("Managed service publication parent is unsafe")
        try:
            with OpenedDirectory(
                path,
                policy=DirectoryPolicy(owner=_OWNER, mode=0o700),
                expected_identity=actual,
            ) as opened:
                parents[path] = opened.recheck().directory
        except FilesystemError:
            _die("Managed service publication parent is unsafe")
    return parents


def _validate_planned_directories(
    parents: dict[str, DirectoryIdentity],
) -> None:
    for path, expected in parents.items():
        try:
            with OpenedDirectory(
                path,
                policy=DirectoryPolicy(owner=_OWNER, mode=0o700),
                expected_identity=expected,
            ) as opened:
                opened.recheck()
        except FilesystemError:
            _die("Managed service planned directory identity changed")


def _open_bound_parent(
    path: str,
    parents: dict[str, DirectoryIdentity],
) -> OpenedDirectory:
    expected = parents.get(path)
    if expected is None:
        _die("Managed service publication parent lacks planned identity")
    try:
        return OpenedDirectory(
            path,
            policy=DirectoryPolicy(owner=_OWNER, mode=0o700),
            expected_identity=expected,
        )
    except FilesystemError:
        _die("Managed service publication parent identity changed")


def _validate_published_result(
    record: ServiceTransaction,
    key: str,
    published: FileIdentity,
) -> None:
    mutation = next(item for item in record.mutations if item.key == key)
    if mutation.stage is None:
        try:
            with OpenedDirectory(
                mutation.destination,
                policy=DirectoryPolicy(owner=_OWNER, mode=0o700),
                expected_identity=published,
            ) as directory:
                if os.listdir(directory.fileno()):
                    _die("Managed service published directory changed before evidence")
                directory.recheck()
        except FilesystemError:
            _die("Managed service published directory changed before evidence")
        return
    if mutation.stage is None or not isinstance(mutation.stage_object, FileObjectState):
        raise AssertionError("planned service publication lacks object evidence")
    if published.state != mutation.stage_object:
        _die("Managed service published file identity changed before evidence")
    identity, digest = _read_evidence(mutation.destination, f"publication {key}")
    if identity != published or digest != mutation.stage_sha256:
        _die("Managed service published file changed before evidence")


@dataclass(slots=True)
class ManagedServiceWriter:
    """One exact managed-service journal and its legal forward transitions."""

    pki_dir: str
    path: str
    values: dict[str, str]
    identity: FileIdentity
    record: ServiceTransaction
    publication_parents: dict[str, DirectoryIdentity] = field(repr=False)
    fault: FaultHook = DEFAULT_FAULT_HOOK
    pause: PauseHook = DEFAULT_PAUSE_HOOK

    @classmethod
    def create(
        cls,
        values: Mapping[str, str],
        *,
        pki_dir: os.PathLike[str] | str,
        fault: FaultHook = DEFAULT_FAULT_HOOK,
        pause: PauseHook = DEFAULT_PAUSE_HOOK,
    ) -> ManagedServiceWriter:
        root = os.fspath(pki_dir)
        if (
            not isinstance(root, str)
            or not os.path.isabs(root)
            or os.path.normpath(root) != root
        ):
            raise ValueError("pki_dir must be an absolute normalized text path")
        if not callable(fault) or not callable(pause):
            raise TypeError("writer hooks must be callable")
        mutable = dict(values)
        path = mutable.get("journal_path", "")
        parent, name = _parent(path)
        stage: StagedFile | None = None
        data = b""
        identity: FileIdentity | None = None
        try:
            if parent.identity_at(name) is not ABSENT:
                _die("A managed service recovery journal already exists")
            with defer_service_writer_signals():
                _checkpoint("journal-before-mutation", fault, pause)
                stage, data = _stage_journal(parent, name, mutable, root)
                result = publish_no_clobber(
                    parent,
                    stage.name,
                    stage.identity,
                    parent,
                    name,
                )
                stage.mark_consumed()
                identity = _publication_identity(result)
                _checkpoint("journal-after-mutation", fault, pause)
        except (OSError, FilesystemError, PublicationError):
            _die("Managed service writer journal could not be published safely")
        finally:
            if stage is not None:
                try:
                    stage.cleanup()
                    stage.close()
                except PublicationError:
                    _die("Managed service writer journal stage requires inspection")
            parent.close()
        assert identity is not None
        try:
            record = parse_service_transaction(data, pki_dir=root)
        except ServiceTransactionError:
            raise AssertionError("published managed service journal did not parse") from None
        parents = _snapshot_publication_parents(record)
        return cls(root, path, mutable, identity, record, parents, fault, pause)

    @classmethod
    def load(
        cls,
        path: os.PathLike[str] | str,
        *,
        pki_dir: os.PathLike[str] | str,
        fault: FaultHook = DEFAULT_FAULT_HOOK,
        pause: PauseHook = DEFAULT_PAUSE_HOOK,
    ) -> ManagedServiceWriter:
        journal = os.fspath(path)
        root = os.fspath(pki_dir)
        if not isinstance(journal, str) or not isinstance(root, str):
            raise TypeError("writer paths must be text")
        data = b""
        identity: FileIdentity | None = None
        record: ServiceTransaction | None = None
        try:
            with OpenedFile(journal, policy=_JOURNAL_FILE) as opened:
                data = opened.read(_JOURNAL_FILE.max_size or 0)
                identity = opened.identity
            record = parse_service_transaction(data, pki_dir=root)
        except FilesystemError:
            _die("No safe managed service writer journal exists")
        except ServiceTransactionError as error:
            _die(str(error))
        assert record is not None and identity is not None
        if record.identity("journal_identity") != identity.state:
            _die("Managed service writer journal does not bind its live object")
        parents = _snapshot_publication_parents(record)
        return cls(
            root,
            journal,
            dict(record.items()),
            identity,
            record,
            parents,
            fault,
            pause,
        )

    def recheck(self) -> None:
        data = b""
        try:
            with OpenedFile(
                self.path,
                policy=_JOURNAL_FILE,
                expected_identity=self.identity,
            ) as opened:
                data = opened.read(_JOURNAL_FILE.max_size or 0)
                opened.recheck()
        except FilesystemError:
            _die("Managed service writer journal identity changed")
        if data != self.record.to_bytes():
            _die("Managed service writer journal bytes changed")
        try:
            current = parse_service_transaction(data, pki_dir=self.pki_dir)
        except ServiceTransactionError as error:
            _die(str(error))
        if current.identity("journal_identity") != self.identity.state:
            _die("Managed service writer journal does not bind its live object")

    def rewrite(
        self,
        label: str,
        *,
        pre_rewrite_check: Callable[[], None] | None = None,
    ) -> ServiceTransaction:
        if not label or any(ord(character) < 0x20 for character in label):
            raise ValueError("writer journal label is invalid")
        if pre_rewrite_check is not None and not callable(pre_rewrite_check):
            raise TypeError("pre_rewrite_check must be callable or None")
        _checkpoint(f"{label}-before-journal-rewrite", self.fault, self.pause)
        self.recheck()
        parent, name = _parent(self.path)
        stage: StagedFile | None = None
        data = b""
        try:
            with defer_service_writer_signals():
                stage, data = _stage_journal(parent, name, self.values, self.pki_dir)
                if pre_rewrite_check is not None:
                    pre_rewrite_check()
                result = replace_exact(
                    parent,
                    stage.name,
                    stage.identity,
                    parent,
                    name,
                    self.identity,
                )
                stage.mark_consumed()
                self.identity = _publication_identity(result)
        except (OSError, FilesystemError, PublicationError):
            _die("Managed service writer journal could not be rewritten safely")
        finally:
            if stage is not None:
                try:
                    stage.cleanup()
                    stage.close()
                except PublicationError:
                    _die("Managed service writer journal stage requires inspection")
            parent.close()
        _checkpoint(f"{label}-after-journal-rewrite", self.fault, self.pause)
        try:
            self.record = parse_service_transaction(data, pki_dir=self.pki_dir)
        except ServiceTransactionError:
            raise AssertionError("rewritten managed service journal did not parse") from None
        return self.record

    def begin_staging(self, key: str) -> ServiceTransaction:
        expected = self.record.staging_order[int(self.record["staged_count"])]
        if key != expected:
            raise ValueError("managed service staging key is out of order")
        self.values.update(
            phase=ServicePhase.STAGING.value,
            checkpoint="staging-pending",
            mutation=key,
        )
        return self.rewrite(f"stage-{key}-pending")

    def record_staging(self, key: str) -> ServiceTransaction:
        if (
            self.record.phase is not ServicePhase.STAGING
            or self.record["checkpoint"] != "staging-pending"
            or self.record["mutation"] != key
        ):
            raise ValueError("managed service staging evidence is not pending")
        path = self.values[f"{key}_stage"]
        identity, digest = _read_evidence(path, f"staged {key}")
        self.values[f"{key}_stage_identity"] = serialize_file_identity(identity)
        self.values[f"{key}_stage_object"] = serialize_file_object_state(identity.state)
        self.values[f"{key}_stage_sha256"] = digest
        self.values["staged_count"] = str(int(self.record["staged_count"]) + 1)
        self.values["checkpoint"] = "staging-done"
        return self.rewrite(f"stage-{key}-evidence")

    def begin_backup(self, key: str) -> ServiceTransaction:
        expected = self.record.backup_order[int(self.record["backed_up_count"])]
        if key != expected:
            raise ValueError("managed service backup key is out of order")
        self.values.update(
            phase=ServicePhase.BACKING_UP.value,
            checkpoint="backup-pending",
            mutation=key,
        )
        return self.rewrite(f"backup-{key}-pending")

    def record_backup(self, key: str) -> ServiceTransaction:
        if (
            self.record.phase is not ServicePhase.BACKING_UP
            or self.record["checkpoint"] != "backup-pending"
            or self.record["mutation"] != key
        ):
            raise ValueError("managed service backup evidence is not pending")
        identity, digest = _read_evidence(
            self.values[f"{key}_backup"], f"backup {key}"
        )
        self.values[f"{key}_backup_identity"] = serialize_file_identity(identity)
        self.values[f"{key}_backup_object"] = serialize_file_object_state(identity.state)
        self.values[f"{key}_backup_sha256"] = digest
        self.values["backed_up_count"] = str(
            int(self.record["backed_up_count"]) + 1
        )
        self.values["checkpoint"] = "backup-done"
        return self.rewrite(f"backup-{key}-evidence")

    def finish_preparation(self) -> ServiceTransaction:
        if (
            int(self.record["staged_count"]) != len(self.record.staging_order)
            or int(self.record["backed_up_count"]) != len(self.record.backup_order)
        ):
            raise ValueError("managed service preparation is incomplete")
        self.values.update(
            phase=ServicePhase.PLANNED.value,
            checkpoint="planned",
            mutation="none",
        )
        return self.rewrite("planning-evidence")

    def begin_publication(self, key: str) -> ServiceTransaction:
        expected = self.record.publication_order[int(self.record["published_count"])]
        if key != expected:
            raise ValueError("managed service publication key is out of order")
        self.values.update(
            phase=ServicePhase.PUBLISHING.value,
            checkpoint="publication-pending",
            mutation=key,
        )
        return self.rewrite(f"publish-{key}-pending")

    def record_publication(
        self,
        key: str,
        published: FileIdentity,
        destination_parent: OpenedDirectory,
        destination_name: str,
    ) -> ServiceTransaction:
        if (
            self.record.phase is not ServicePhase.PUBLISHING
            or self.record["checkpoint"] != "publication-pending"
            or self.record["mutation"] != key
        ):
            raise ValueError("managed service publication evidence is not pending")
        stage_field = f"{key}_stage"
        if stage_field not in self.values:
            expected: FileIdentity | DirectoryIdentity = published.directory
        else:
            expected = published

        def recheck_publication() -> None:
            try:
                actual = destination_parent.identity_at(destination_name)
                destination_parent.recheck()
            except FilesystemError:
                _die("Managed service publication changed before evidence")
            if isinstance(expected, DirectoryIdentity):
                matches = (
                    isinstance(actual, FileIdentity)
                    and actual.kind == "directory"
                    and actual.directory == expected
                )
            else:
                matches = actual == expected
            if not matches:
                _die("Managed service publication changed before evidence")

        _checkpoint(
            f"publish-{key}-before-publication-evidence",
            self.fault,
            self.pause,
        )
        recheck_publication()
        if stage_field not in self.values:
            assert isinstance(expected, DirectoryIdentity)
            self.values[f"{key}_post_identity"] = serialize_directory_identity(
                expected
            )
        else:
            assert isinstance(expected, FileIdentity)
            self.values[f"{key}_post_identity"] = serialize_file_identity(expected)
            self.values[f"{key}_post_sha256"] = self.values[f"{key}_stage_sha256"]
        self.values["published_count"] = str(
            int(self.record["published_count"]) + 1
        )
        self.values["checkpoint"] = "publication-done"
        return self.rewrite(
            f"publish-{key}-evidence",
            pre_rewrite_check=recheck_publication,
        )

    def publish_next(self) -> ServiceTransaction:
        """Publish and journal the next planned object as one signal-deferred step."""

        index = int(self.record["published_count"])
        if index >= len(self.record.publication_order):
            raise ValueError("managed service publication is already complete")
        forward_ready = (
            self.record.phase is ServicePhase.PLANNED
            and self.record["checkpoint"] == "planned"
            and index == 0
        ) or (
            self.record.phase is ServicePhase.PUBLISHING
            and self.record["checkpoint"] == "publication-done"
            and index > 0
            and self.record["mutation"] == self.record.publication_order[index - 1]
        )
        if not forward_ready:
            raise ValueError("managed service journal requires recovery")
        key = self.record.publication_order[index]
        self.begin_publication(key)
        _checkpoint(f"publish-{key}-before-publication", self.fault, self.pause)
        self.recheck()
        mutation = next(item for item in self.record.mutations if item.key == key)
        destination_path, destination_name = os.path.split(mutation.destination)
        destination_parent = _open_bound_parent(
            destination_path,
            self.publication_parents,
        )
        source_parent: OpenedDirectory | None = None
        source_name = ""
        try:
            if mutation.stage is None:
                source_parent = _open_bound_parent(
                    self.record["stage_dir"],
                    self.publication_parents,
                )
                source_name = key
            else:
                source_path, source_name = os.path.split(mutation.stage)
                source_parent = _open_bound_parent(
                    source_path,
                    self.publication_parents,
                )
            self.recheck()
            _validate_planned_directories(self.publication_parents)
            validate_service_writer_publication_preflight(self.record)
            with defer_service_writer_signals():
                if mutation.stage is None:
                    assert source_parent is not None
                    staged, readiness = _stage_directory(
                        source_parent,
                        source_name,
                        key,
                        self.fault,
                        self.pause,
                    )
                    self.values[f"{key}_post_identity"] = (
                        serialize_directory_identity(staged.directory)
                    )
                    self.rewrite(f"publish-{key}-directory-stage-evidence")
                    self.recheck()
                    validate_service_writer_publication_preflight(self.record)
                    _checkpoint(
                        f"publish-{key}-before-directory-publication",
                        self.fault,
                        self.pause,
                    )
                    published = _publish_directory(
                        key,
                        source_parent,
                        source_name,
                        staged,
                        readiness,
                        destination_parent,
                        destination_name,
                        self.fault,
                        self.pause,
                    )
                else:
                    assert source_parent is not None
                    published = _publish_file(
                        self.record,
                        key,
                        source_parent,
                        source_name,
                        destination_parent,
                        destination_name,
                    )
                _checkpoint(
                    f"publish-{key}-after-publication",
                    self.fault,
                    self.pause,
                )
                active_source = source_parent
                assert active_source is not None
                if active_source.identity_at(source_name) is not ABSENT:
                    _die("Managed service publication stage name reappeared")
                active_source.recheck()
                _validate_published_result(self.record, key, published)
                result = self.record_publication(
                    key,
                    published,
                    destination_parent,
                    destination_name,
                )
            if mutation.stage is None:
                self.publication_parents[mutation.destination] = published.directory
            return result
        finally:
            if source_parent is not None:
                source_parent.close()
            destination_parent.close()

    def begin_verification(self) -> ServiceTransaction:
        if int(self.record["published_count"]) != len(self.record.publication_order):
            raise ValueError("managed service publication is incomplete")
        self.values.update(
            phase=ServicePhase.VERIFYING.value,
            checkpoint="verification-pending",
            mutation="none",
        )
        return self.rewrite("verification-pending")

    def finish_verification(self) -> ServiceTransaction:
        if (
            self.record.phase is not ServicePhase.VERIFYING
            or self.record["checkpoint"] != "verification-pending"
        ):
            raise ValueError("managed service verification is not pending")
        self.values["checkpoint"] = "verification-done"
        return self.rewrite("verification-evidence")

    def commit(self) -> ServiceTransaction:
        """Return a committed journal accepted by cleanup-only recovery."""

        if (
            self.record.phase is not ServicePhase.VERIFYING
            or self.record["checkpoint"] != "verification-done"
        ):
            raise ValueError("managed service verification is incomplete")
        self.values.update(
            phase=ServicePhase.COMMITTED.value,
            checkpoint="commit-done",
            mutation="none",
            committed="true",
            recovery_mode=ServiceRecoveryMode.CLEANUP_ONLY.value,
            outcome=ServiceOutcome.SUCCEEDED.value,
        )
        return self.rewrite("commit-evidence")
