"""Legacy-to-generation CA layout migration transaction writer."""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import signal
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, NoReturn

from .backup import BACKUP_RECEIPT_SPEC, _private_metadata_digest, _public_state_digest
from .ca_rollover_recovery import (
    LEGACY_MIGRATION_WRITER_FIELDS,
    MAX_RECOVERY_RECORD_BYTES,
    IntermediateBootstrapRecoveryRecord,
    LegacyMigrationRecoveryRecord,
    RecoveryRecordError,
    RootBootstrapRecoveryRecord,
    parse_recovery_semantics,
)
from .errors import ApplicationError
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
from .inventory import Inventory, InventoryError, parse_inventory
from .operational import (
    acquire_operational_locks,
    detect_layout,
    prepare_control_state,
    require_pilot_common_library,
    require_pki_directory,
    require_program,
    resolve_paths,
    run_external,
)
from .parser import ParseResult
from .paths import absolutize_path, expand_home
from .persisted_identity import (
    format_gnu_stat_timestamp,
    parse_directory_identity,
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
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
from .tree_manifests import TreeManifestError, validate_provenance_manifest


_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_PRIVATE_FILE = FilePolicy(owner=os.geteuid(), mode=0o600, links=1)
_OWNED_FILE = FilePolicy(owner=os.geteuid(), forbidden_bits=0o022, links=1)
_SESSION = re.compile(r"[0-9a-f]{32}", re.ASCII)
_FINGERPRINT = re.compile(r"[^=\n]+=([0-9A-Fa-f:]{95})\n?", re.ASCII)
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_QUARANTINE_NAMES = (
    "pki.env",
    "openssl-root.cnf.tpl",
    "openssl-intermediate.cnf.tpl",
    "openssl-service.cnf.tpl",
)
_MAX_RECORD = 1024 * 1024
_MAX_CONFIG = 16 * 1024 * 1024
_HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
MIGRATION_FAULT_CHECKPOINTS = (
    "after-journal",
    "after-reservations",
    "after-root-rename",
    "after-intermediate-rename",
    "after-configs",
    "after-issuers",
    "after-quarantine",
    "after-active",
)
MIGRATION_MUTATION_CHECKPOINTS = (
    "root-move-before-journal",
    "intermediate-move-before-journal",
    "active-publication-before-journal",
)


class _SignalExit(Exception):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(status)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _ok(message: str) -> None:
    print(f"[OK] {message}", flush=True)


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
    except FilesystemError:
        _die("Migration filesystem state could not be inspected safely")


def _matches(
    actual: FileIdentity | object,
    expected: FileIdentity | FileObjectState | DirectoryIdentity | object,
) -> bool:
    if expected is ABSENT:
        return actual is ABSENT
    if not isinstance(actual, FileIdentity):
        return False
    if isinstance(expected, FileIdentity):
        return actual == expected
    if isinstance(expected, FileObjectState):
        return actual.state == expected
    if isinstance(expected, DirectoryIdentity):
        return actual.kind == "directory" and actual.directory == expected
    return False


def _require_state(
    path: str,
    expected: FileIdentity | FileObjectState | DirectoryIdentity | object,
    label: str,
) -> FileIdentity | object:
    current = _actual(path)
    if not _matches(current, expected):
        if expected is ABSENT:
            _die(f"{label} appeared unexpectedly: {path}")
        _die(f"{label} identity changed: {path}")
    return current


def _parent(path: str, *, private: bool = False) -> tuple[OpenedDirectory, str]:
    directory, name = os.path.split(path)
    try:
        return OpenedDirectory(
            directory,
            policy=_PRIVATE_DIRECTORY if private else DirectoryPolicy(),
        ), name
    except FilesystemError:
        _die("Migration publication parent is unsafe")


def _sync_path(path: str) -> None:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if os.path.isdir(path):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError:
        _die(f"Cannot fsync: {path}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sync_parent(path: str) -> None:
    _sync_path(os.path.dirname(path))


@contextmanager
def _defer_signals() -> Iterator[None]:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, _HANDLED_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _write_new_file(
    path: str,
    data: bytes,
    *,
    mode: int = 0o600,
    mtime_ns: int | None = None,
) -> FileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
        )
        view = memoryview(data)
        try:
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
        finally:
            view.release()
        os.fchmod(descriptor, mode)
        if mtime_ns is not None:
            os.utime(descriptor, ns=(mtime_ns, mtime_ns))
        os.fsync(descriptor)
        return identity_from_stat(os.fstat(descriptor))
    except (OSError, FilesystemError):
        _die("Migration staging file could not be written safely")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raise AssertionError("unreachable")


def _copy_descriptor(
    source: OpenedFile,
    destination: str,
    *,
    mode: int | None = None,
) -> FileIdentity:
    output = -1
    try:
        output = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            source.identity.permissions if mode is None else mode,
        )
        offset = 0
        while offset < source.identity.size:
            block = os.pread(
                source.fileno(), min(64 * 1024, source.identity.size - offset), offset
            )
            if not block:
                raise OSError
            view = memoryview(block)
            try:
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise OSError
                    view = view[written:]
            finally:
                view.release()
            offset += len(block)
        os.fchmod(output, source.identity.permissions if mode is None else mode)
        os.utime(output, ns=(source.identity.mtime_ns, source.identity.mtime_ns))
        os.fsync(output)
        copied = identity_from_stat(os.fstat(output))
        source.recheck()
        return copied
    except (OSError, FilesystemError):
        _die("Migration evidence copy could not be staged safely")
    finally:
        if output >= 0:
            os.close(output)
    raise AssertionError("unreachable")


def _copy_file(source: str, destination: str) -> tuple[FileIdentity, FileIdentity]:
    try:
        with OpenedFile(source, policy=_OWNED_FILE) as opened:
            original = opened.identity
            copied = _copy_descriptor(opened, destination)
            opened.recheck()
            return original, copied
    except FilesystemError:
        _die(f"Migration source file is unsafe or changed: {source}")
    raise AssertionError("unreachable")


def _copy_tree(source: str, destination: str) -> DirectoryIdentity:
    try:
        source_metadata = os.stat(source, follow_symlinks=False)
        if not stat.S_ISDIR(source_metadata.st_mode):
            raise OSError
        os.mkdir(destination, stat.S_IMODE(source_metadata.st_mode))
        with os.scandir(source) as entries:
            children = sorted(entries, key=lambda entry: os.fsencode(entry.name))
        for entry in children:
            source_child = entry.path
            destination_child = os.path.join(destination, entry.name)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                _copy_tree(source_child, destination_child)
            elif stat.S_ISREG(metadata.st_mode):
                _copy_file(source_child, destination_child)
            else:
                _die(f"Migration evidence contains an unsupported object: {source_child}")
        os.chmod(destination, stat.S_IMODE(source_metadata.st_mode), follow_symlinks=False)
        os.utime(
            destination,
            ns=(source_metadata.st_mtime_ns, source_metadata.st_mtime_ns),
            follow_symlinks=False,
        )
        return identity_from_stat(os.stat(destination, follow_symlinks=False)).directory
    except ApplicationError:
        raise
    except (OSError, FilesystemError):
        _die("Migration provenance could not be copied safely")


def _hash_opened(opened: OpenedFile) -> str:
    digest = hashlib.sha256()
    offset = 0
    try:
        while offset < opened.identity.size:
            block = os.pread(
                opened.fileno(), min(64 * 1024, opened.identity.size - offset), offset
            )
            if not block:
                raise OSError
            digest.update(block)
            offset += len(block)
        opened.recheck()
    except (OSError, FilesystemError):
        _die("Migration evidence changed while being hashed")
    return digest.hexdigest()


def _read_map(data: bytes, label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    for line in lines:
        if b"=" not in line:
            _die(f"{label} has invalid content")
        raw_key, raw_value = line.split(b"=", 1)
        try:
            key = raw_key.decode("ascii")
            value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            _die(f"{label} has invalid content")
        if (
            re.fullmatch(r"[a-z0-9_]+", key, re.ASCII) is None
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            _die(f"{label} has invalid content")
        if key in values:
            _die(f"{label} contains duplicate field: {key}")
        values[key] = value
    return values


@dataclass(frozen=True, slots=True)
class _Receipt:
    path: str
    values: dict[str, str]
    identity: FileIdentity
    archive: str
    archive_identity: FileIdentity

    def recheck(self) -> None:
        _require_state(self.path, self.identity, "Migration backup receipt")
        digest = ""
        try:
            with OpenedFile(
                self.archive,
                policy=FilePolicy(links=1),
                expected_identity=self.archive_identity,
            ) as opened:
                digest = _hash_opened(opened)
        except FilesystemError:
            raise ApplicationError(
                "Backup archive identity no longer matches its receipt"
            ) from None
        if digest != self.values["archive_sha256"]:
            _die("Backup archive digest no longer matches its receipt")


def _read_receipt(path: str) -> _Receipt:
    data = b""
    receipt_identity: FileIdentity | None = None
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=_MAX_RECORD
            ),
        ) as opened:
            data = opened.read(_MAX_RECORD)
            receipt_identity = opened.identity
    except FilesystemError:
        raise ApplicationError(
            f"Backup receipt must be a non-symlink regular file: {path}"
        ) from None
    values = _read_map(data, "Backup receipt")
    missing = [field for field in BACKUP_RECEIPT_SPEC.fields if not values.get(field)]
    if missing:
        _die(f"Backup receipt is missing field: {missing[0]}")
    if (
        len(values) != len(BACKUP_RECEIPT_SPEC.fields)
        or values["schema"] != "2"
        or values["layout"] != "legacy"
        or _SESSION.fullmatch(values["session"]) is None
        or re.fullmatch(r"[0-9]+", values["created_epoch"], re.ASCII) is None
    ):
        _die("Backup receipt is not a supported legacy-layout receipt")
    created = int(values["created_epoch"], 10)
    now = int(time.time())
    if now < created or now - created > 86_400:
        _die("Backup receipt is older than the 24-hour migration freshness window")
    archive = values["backup_path"]
    if not os.path.isabs(archive):
        _die(f"Backup archive is missing or unsafe: {archive}")
    archive_identity: FileIdentity | None = None
    digest = ""
    try:
        with OpenedFile(archive, policy=FilePolicy(links=1)) as opened:
            archive_identity = opened.identity
            expected = (
                values["backup_device"],
                values["backup_inode"],
                values["backup_size"],
                values["backup_mode"],
                values["backup_owner"],
            )
            actual = (
                str(archive_identity.dev),
                str(archive_identity.ino),
                str(archive_identity.size),
                f"{archive_identity.permissions:o}",
                str(archive_identity.uid),
            )
            if actual != expected:
                _die("Backup archive identity no longer matches its receipt")
            digest = _hash_opened(opened)
    except FilesystemError:
        raise ApplicationError(f"Backup archive is missing or unsafe: {archive}") from None
    if _SHA256.fullmatch(values["archive_sha256"]) is None or digest != values[
        "archive_sha256"
    ]:
        _die("Backup archive digest no longer matches its receipt")
    assert receipt_identity is not None and archive_identity is not None
    return _Receipt(path, values, receipt_identity, archive, archive_identity)


def _safe_record_path(path: str, label: str) -> None:
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError:
        _die(f"{label} must contain only ASCII characters for recovery records")
    if not encoded or any(byte < 0x20 or byte > 0x7E for byte in encoded):
        _die(f"{label} must contain only ASCII characters for recovery records")


def _absolute_option(value: object, environment: Mapping[str, str]) -> str:
    home = environment.get("HOME")
    if home is None:
        _die("HOME is required")
    try:
        cwd = os.getcwd()
    except OSError:
        _die("Current directory could not be resolved")
    return absolutize_path(expand_home(str(value), home=home), physical_cwd=cwd)


def _require_no_symlink_components(path: str, label: str) -> None:
    current = "/"
    for component in path.split("/"):
        if not component:
            continue
        current = os.path.join(current, component)
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError:
            _die(f"{label} path could not be inspected safely")
        if stat.S_ISLNK(metadata.st_mode):
            _die(f"{label} path component must not be a symlink: {current}")


def _simple_state_record(path: str, label: str) -> dict[str, str]:
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=_MAX_RECORD
            ),
        ) as opened:
            return _read_map(opened.read(_MAX_RECORD), label)
    except FilesystemError:
        raise ApplicationError(f"{label} is unsafe: {path}") from None
    raise AssertionError("unreachable")


def _terminal_journal_identity(path: str, pki_dir: str) -> FileIdentity:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(),
                mode=0o600,
                links=1,
                max_size=MAX_RECOVERY_RECORD_BYTES,
            ),
        ) as opened:
            data = opened.read(MAX_RECOVERY_RECORD_BYTES)
            identity = opened.identity
            opened.recheck()
    except FilesystemError:
        _die(f"PKI recovery is required before this command can continue: {path}")
    try:
        record = parse_recovery_semantics(data, pki_dir=pki_dir)
    except RecoveryRecordError:
        _die(f"PKI recovery is required before this command can continue: {path}")
    terminal = False
    if isinstance(record, (RootBootstrapRecoveryRecord, IntermediateBootstrapRecoveryRecord)):
        terminal = (
            record.committed
            and record.phase == "complete"
            and record.recovery_action is None
            and record.recovery_step is None
        )
    elif isinstance(record, LegacyMigrationRecoveryRecord) and record.committed:
        terminal = (
            record.phase == "complete"
            and (
                record.recovery_action is None
                or record.recovery_action.value == "resume"
            )
            and (
                record.recovery_step is None
                or record.recovery_step == "resume-provenance-done"
            )
        ) or (
            record.phase == "rolled-back"
            and record.recovery_action is not None
            and record.recovery_action.value == "rollback"
            and record.recovery_step == "rollback-provenance-done"
        )
    if not terminal:
        _die(f"PKI recovery is required before this command can continue: {path}")
    assert identity is not None
    return identity


def _require_no_unresolved_state(pki_dir: str) -> FileIdentity | None:
    finalization = f"{pki_dir}/state/csr/finalization-recovery-journal"
    signing = f"{pki_dir}/state/csr/recovery-journal"
    marker = f"{pki_dir}/state/rollover/recovery-required"
    journal = f"{pki_dir}/state/rollover/journal"
    if os.path.lexists(finalization):
        record = _simple_state_record(
            finalization, "CSR candidate finalization recovery journal"
        )
        if record.get("operation") != "csr-finalize":
            _die(
                "Unsupported CSR finalization recovery state blocks this command: "
                f"{finalization}"
            )
        _die(
            "CSR candidate finalization recovery is required before this command can "
            f"continue: {finalization}"
        )
    if os.path.lexists(signing):
        record = _simple_state_record(signing, "Authenticated CSR signing recovery journal")
        if record.get("operation") == "csr-sign":
            _die(
                "Authenticated CSR signing recovery is required before this command "
                f"can continue: {signing}"
            )
        _die(f"Unsupported CSR recovery state blocks this command: {signing}")
    if os.path.lexists(marker):
        try:
            with OpenedFile(marker, policy=_PRIVATE_FILE):
                pass
        except FilesystemError:
            _die(f"PKI recovery marker is unsafe: {marker}")
        _die(f"PKI recovery is required before this command can continue: {marker}")
    if os.path.lexists(journal):
        return _terminal_journal_identity(journal, pki_dir)
    return None


def _prepare_generation_parents(pki_dir: str) -> None:
    for path in (
        f"{pki_dir}/authorities",
        f"{pki_dir}/authorities/roots",
        f"{pki_dir}/authorities/intermediates",
    ):
        if not os.path.lexists(path):
            try:
                os.mkdir(path, 0o700)
                _sync_parent(path)
            except FileExistsError:
                pass
            except OSError:
                _die(f"Cannot create generation authority directory: {path}")
        try:
            with OpenedDirectory(path, policy=_PRIVATE_DIRECTORY):
                pass
        except FilesystemError:
            _die(f"Generation authority directory must be current-user-owned with mode 700: {path}")


def _run_openssl(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    failure: str,
) -> bytes:
    result = run_external(argv, environment)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    if result.status:
        _die(failure)
    return result.stdout


def _fingerprint(path: str, environment: Mapping[str, str]) -> str:
    output = _run_openssl(
        ("openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"),
        environment,
        f"Certificate fingerprint is unreadable: {path}",
    )
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError:
        _die(f"Certificate fingerprint is unreadable: {path}")
    match = _FINGERPRINT.fullmatch(text)
    if match is None:
        _die(f"Certificate fingerprint is unreadable: {path}")
    return match.group(1).replace(":", "").upper()


def _validate_managed_tree(root: str, label: str) -> None:
    try:
        root_metadata = os.stat(root, follow_symlinks=False)
    except OSError:
        _die(f"{label} must be a non-symlink directory: {root}")
    if not stat.S_ISDIR(root_metadata.st_mode):
        _die(f"{label} must be a non-symlink directory: {root}")
    if root_metadata.st_uid != os.geteuid():
        _die(f"{label} contains foreign-owned state: {root}")
    if stat.S_IMODE(root_metadata.st_mode) & 0o022:
        _die(f"{label} contains group- or world-writable state: {root}")
    root_device = root_metadata.st_dev
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = tuple(entries)
        except OSError:
            _die(f"{label} could not be enumerated safely")
        for entry in children:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                _die(f"{label} could not be enumerated safely")
            path = entry.path
            if stat.S_ISLNK(metadata.st_mode):
                _die(f"{label} contains a symbolic link: {path}")
            if metadata.st_uid != os.geteuid():
                _die(f"{label} contains foreign-owned state: {path}")
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                _die(f"{label} contains group- or world-writable state: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_dev == root_device:
                    pending.append(path)
            elif not stat.S_ISREG(metadata.st_mode):
                _die(f"{label} contains an unsupported path type: {path}")
            elif metadata.st_nlink != 1:
                _die(f"{label} contains hard-linked state: {path}")


def _require_regular(path: str) -> FileIdentity:
    try:
        with OpenedFile(path, policy=_OWNED_FILE) as opened:
            return opened.identity
    except FilesystemError:
        raise ApplicationError(f"Required file is missing: {path}") from None
    raise AssertionError("unreachable")


def _load_inventory(path: str, label: str, *, private: bool) -> tuple[Inventory, FileIdentity]:
    policy = (
        _PRIVATE_FILE
        if private
        else FilePolicy(owner=os.geteuid(), forbidden_bits=0o022, links=1)
    )
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(path, policy=policy, expected_identity=None) as opened:
            data = opened.read(_MAX_RECORD)
            identity = opened.identity
        assert identity is not None
        return parse_inventory(data), identity
    except InventoryError as error:
        raise ApplicationError(str(error)) from None
    except FilesystemError:
        if private:
            raise ApplicationError(
                f"Canonical private inventory is missing or unsafe: {path}"
            ) from None
        raise ApplicationError(
            f"Service inventory is missing or unreadable: {path}; "
            "run platform-pki-inventory-install"
        ) from None


def _validate_certificate(path: str, environment: Mapping[str, str], failure: str) -> None:
    _run_openssl(("openssl", "x509", "-in", path, "-noout"), environment, failure)


def _validate_legacy_state(
    pki_dir: str,
    inventory: Inventory,
    environment: Mapping[str, str],
) -> None:
    for relative, label in (
        ("root-ca", "Legacy root CA"),
        ("intermediate-ca", "Legacy intermediate CA"),
        ("services", "Legacy service state"),
        ("export", "Legacy export state"),
    ):
        _validate_managed_tree(f"{pki_dir}/{relative}", label)
    required = (
        "root-ca/private/root-ca.key",
        "root-ca/certs/root-ca.crt",
        "root-ca/openssl.cnf",
        "root-ca/index.txt",
        "root-ca/index.txt.attr",
        "root-ca/serial",
        "root-ca/crlnumber",
        "intermediate-ca/private/intermediate-ca.key",
        "intermediate-ca/certs/intermediate-ca.crt",
        "intermediate-ca/certs/ca-chain.crt",
        "intermediate-ca/openssl.cnf",
        "intermediate-ca/index.txt",
        "intermediate-ca/index.txt.attr",
        "intermediate-ca/serial",
        "intermediate-ca/crlnumber",
    )
    for relative in required:
        path = f"{pki_dir}/{relative}"
        try:
            with OpenedFile(path):
                pass
        except FilesystemError:
            _die(f"Legacy PKI state is incomplete: {path}")
    services = {service.name for service in inventory.services}
    service_root = f"{pki_dir}/services"
    try:
        with os.scandir(service_root) as entries:
            directories = tuple(entry for entry in entries if entry.is_dir(follow_symlinks=False))
    except OSError:
        _die("Legacy service state could not be enumerated safely")
    for entry in directories:
        name = entry.name
        if _SERVICE.fullmatch(name) is None:
            _die(f"Invalid service name: {name}")
        if name not in services:
            _die(f"Legacy service directory is absent from inventory: {name}")
        certificates = f"{entry.path}/certs"
        if os.path.isdir(certificates) and not os.path.islink(certificates):
            tls = f"{certificates}/tls.crt"
            try:
                with OpenedFile(tls):
                    pass
            except FilesystemError:
                _die(f"Legacy service certificate directory is incomplete: {name}")
            with os.scandir(certificates) as cert_entries:
                for certificate in cert_entries:
                    if certificate.is_file(follow_symlinks=False) and certificate.name != "tls.crt":
                        _die(
                            "Legacy service certificate directory contains unexpected "
                            f"state: {certificate.path}"
                        )
    for service in inventory.services:
        certificate = f"{pki_dir}/services/{service.name}/certs/tls.crt"
        if os.path.isfile(certificate) and not os.path.islink(certificate):
            _validate_certificate(
                certificate,
                environment,
                f"Legacy service certificate is invalid: {certificate}",
            )
    root_certificate = f"{pki_dir}/root-ca/certs/root-ca.crt"
    intermediate_certificate = f"{pki_dir}/intermediate-ca/certs/intermediate-ca.crt"
    _validate_certificate(root_certificate, environment, "Legacy root certificate is invalid")
    _validate_certificate(
        intermediate_certificate,
        environment,
        "Legacy intermediate certificate is invalid",
    )
    for directory in (f"{pki_dir}/root-ca/newcerts", f"{pki_dir}/intermediate-ca/newcerts"):
        try:
            with os.scandir(directory) as entries:
                certificates = tuple(
                    entry.path for entry in entries if entry.is_file(follow_symlinks=False)
                )
        except FileNotFoundError:
            certificates = ()
        except OSError:
            _die(f"Legacy newcerts state could not be enumerated: {directory}")
        for certificate in certificates:
            _validate_certificate(
                certificate,
                environment,
                f"Legacy newcerts entry is invalid: {certificate}",
            )


def _read_active_pair(path: str) -> tuple[str, str]:
    data = b""
    try:
        with OpenedFile(path, policy=_PRIVATE_FILE) as opened:
            data = opened.read(4096)
    except FilesystemError:
        raise ApplicationError("Active issuer manifest is invalid") from None
    if data != b"root=g1\nintermediate=g1-i1\n":
        _die("Existing generation layout is not the completed legacy migration pair")
    return "g1", "g1-i1"


def _generation_noop(pki_dir: str, environment: Mapping[str, str]) -> int:
    root, intermediate = _read_active_pair(f"{pki_dir}/state/active-issuer")
    for path in (
        f"{pki_dir}/authorities/roots/{root}",
        f"{pki_dir}/authorities/intermediates/{intermediate}",
    ):
        try:
            with OpenedDirectory(path, policy=_PRIVATE_DIRECTORY):
                pass
        except FilesystemError:
            _die("PKI active authority state is invalid")
    _run_openssl(
        (
            "openssl",
            "verify",
            "-CAfile",
            f"{pki_dir}/authorities/roots/{root}/certs/root-ca.crt",
            f"{pki_dir}/authorities/intermediates/{intermediate}/certs/intermediate-ca.crt",
        ),
        environment,
        "Active intermediate does not verify against its recorded root",
    )
    _ok("Legacy PKI migration is already complete; no changes made")
    return 0


def _confirm(
    parsed: ParseResult,
    root_fingerprint: str,
    intermediate_fingerprint: str,
) -> None:
    if "--yes" in parsed.provided:
        expected_root = str(parsed.values.get("--expected-root-sha256") or "")
        expected_intermediate = str(
            parsed.values.get("--expected-intermediate-sha256") or ""
        )
        if (
            re.fullmatch(r"[0-9A-Fa-f]{64}", expected_root, re.ASCII) is None
            or re.fullmatch(r"[0-9A-Fa-f]{64}", expected_intermediate, re.ASCII)
            is None
        ):
            _die("--yes requires both expected 64-hex SHA-256 fingerprints")
        if (
            expected_root.upper() != root_fingerprint
            or expected_intermediate.upper() != intermediate_fingerprint
        ):
            _die("Expected CA fingerprints do not match legacy certificates")
        return
    if not sys.stdin.isatty():
        _die("Migration confirmation requires a TTY or --yes with both expected fingerprints")
    print(
        f"Type migrate {root_fingerprint} {intermediate_fingerprint} to continue: ",
        file=sys.stderr,
        end="",
        flush=True,
    )
    confirmation = sys.stdin.readline().rstrip("\n")
    if confirmation != f"migrate {root_fingerprint} {intermediate_fingerprint}":
        _die("Migration confirmation did not match")


def _reservation_state(path: str) -> FileIdentity | object:
    current = _actual(path)
    if current is ABSENT:
        return ABSENT
    if not isinstance(current, FileIdentity) or current.kind != "regular":
        _die(f"Expected a regular file or absent path: {path}")
    try:
        _PRIVATE_FILE.validate(current)
    except FilesystemError:
        _die(f"Expected a regular file or absent path: {path}")
    return current


def _adopt_reservation(
    path: str,
    generation: str,
    kind: str,
    fingerprint: str,
    source_identity: str,
    original: FileIdentity | object,
) -> None:
    if original is ABSENT:
        return
    assert isinstance(original, FileIdentity)
    record = _simple_state_record(path, "Legacy migration generation reservation")
    expected = {
        "generation": generation,
        "kind": kind,
        "status": "abandoned",
        "fingerprint_sha256": fingerprint,
        "source_identity": source_identity,
    }
    if record != expected or _actual(path) != original:
        _die(f"Generation reservation cannot be safely adopted: {path}")


def _reservation_bytes(
    generation: str,
    kind: str,
    status: str,
    fingerprint: str,
    source_identity: str,
) -> bytes:
    return (
        f"generation={generation}\n"
        f"kind={kind}\n"
        f"status={status}\n"
        f"fingerprint_sha256={fingerprint}\n"
        f"source_identity={source_identity}\n"
    ).encode("ascii")


def _transform_config(source: str, destination: str, old: str, new: str) -> FileIdentity:
    transformed = b""
    try:
        with OpenedFile(source, policy=_OWNED_FILE) as opened:
            data = opened.read(_MAX_CONFIG)
            lines = data.split(b"\n")
            if lines[-1] == b"":
                lines.pop()
            expected = f"dir = {old}".encode("ascii")
            replacement = f"dir = {new}".encode("ascii")
            count = sum(line == expected for line in lines)
            if count != 1:
                _die(f"Managed OpenSSL configuration has an unexpected directory: {source}")
            transformed = b"\n".join(
                replacement if line == expected else line for line in lines
            ) + b"\n"
            opened.recheck()
        return _write_new_file(destination, transformed, mode=0o600)
    except FilesystemError:
        raise ApplicationError(
            f"Managed OpenSSL configuration is unsafe: {source}"
        ) from None


def _baseline_bytes(
    state_digest: str,
    root_key: str,
    intermediate_key: str,
) -> bytes:
    lines = [f"public_state_sha256={state_digest}\n"]
    for path in (root_key, intermediate_key):
        if not os.path.lexists(path):
            continue
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except OSError:
            _die("Cannot inspect migration private-key metadata")
        lines.append(
            "private_metadata="
            f"{path}|{metadata.st_dev}|{metadata.st_ino}|{metadata.st_uid}|"
            f"{stat.S_IMODE(metadata.st_mode):o}|{metadata.st_size}|"
            f"{format_gnu_stat_timestamp(metadata.st_mtime_ns)}|"
            f"{format_gnu_stat_timestamp(metadata.st_ctime_ns)}\n"
        )
    return "".join(lines).encode("ascii")


def _directory_identity(value: str) -> DirectoryIdentity:
    try:
        identity = parse_directory_identity(value)
    except ValueError:
        _die("Migration recovery directory identity is invalid")
    if not isinstance(identity, DirectoryIdentity):  # pragma: no cover - no sentinels
        raise AssertionError("directory identity parser returned a sentinel")
    return identity


def _manifest_bytes(root: str) -> bytes:
    root_bytes = os.fsencode(root)
    entries: list[tuple[bytes, str]] = []
    pending = [root]
    root_device = os.stat(root, follow_symlinks=False).st_dev
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            current = tuple(children)
        for entry in current:
            path = entry.path
            metadata = entry.stat(follow_symlinks=False)
            if metadata.st_dev != root_device:
                _die(f"Migration provenance contains a cross-device member: {path}")
            relative = os.fsencode(path)[len(root_bytes) + 1 :]
            if relative == b"provenance-manifest":
                continue
            if b"|" in relative or b"\n" in relative:
                _die(f"Migration provenance contains an unsafe path: {path}")
            identity = identity_from_stat(metadata)
            if identity.kind == "directory":
                row = (
                    f"directory|{os.fsdecode(relative)}|"
                    f"{serialize_directory_identity(identity.directory)}|-\n"
                )
                pending.append(path)
            else:
                digest = "secret" if relative.startswith(b"quarantine/") else ""
                if not digest:
                    try:
                        with OpenedFile(path, expected_identity=identity) as opened:
                            digest = _hash_opened(opened)
                    except FilesystemError:
                        _die("Migration provenance changed while its manifest was created")
                kind = "regular empty file" if identity.size == 0 else "regular file"
                row = (
                    f"{kind}|{os.fsdecode(relative)}|"
                    f"{serialize_file_identity(identity)}|{digest}\n"
                )
            entries.append((relative, row))
    try:
        return "".join(row for _relative, row in sorted(entries)).encode("ascii")
    except UnicodeEncodeError:
        _die("Migration provenance paths must be ASCII")


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
            with parent.open_directory(name, expected_identity=root_identity) as root:
                with OpenedFile(
                    manifest_path,
                    policy=_PRIVATE_FILE,
                    expected_identity=manifest_identity,
                ) as manifest:
                    validate_provenance_manifest(
                        root,
                        parent,
                        name,
                        manifest,
                        manifest_identity,
                        manifest_digest,
                    )
        except (FilesystemError, TreeManifestError, PublicationError):
            _die("Migration provenance contents do not match their manifest")
    finally:
        parent.close()


def _file_digest(path: str, expected: FileIdentity, label: str) -> str:
    try:
        with OpenedFile(path, expected_identity=expected) as opened:
            return _hash_opened(opened)
    except FilesystemError:
        raise ApplicationError(f"{label} identity changed: {path}") from None
    raise AssertionError("unreachable")


def _tree_state(
    root: str,
) -> tuple[tuple[str, FileIdentity | DirectoryIdentity], ...]:
    root_bytes = os.fsencode(root)
    pending = [root]
    result: list[tuple[str, FileIdentity | DirectoryIdentity]] = []
    while pending:
        directory = pending.pop()
        try:
            metadata = os.stat(directory, follow_symlinks=False)
            identity = identity_from_stat(metadata)
            if identity.kind != "directory":
                raise OSError
            relative = os.fsdecode(os.fsencode(directory)[len(root_bytes) :].lstrip(b"/"))
            result.append((relative, identity.directory))
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: os.fsencode(entry.name))
        except (OSError, FilesystemError):
            _die(f"Reviewed migration tree is unsafe or changed: {root}")
        for entry in children:
            try:
                child = identity_from_stat(entry.stat(follow_symlinks=False))
            except (OSError, FilesystemError):
                _die(f"Reviewed migration tree is unsafe or changed: {root}")
            child_relative = os.fsdecode(
                os.fsencode(entry.path)[len(root_bytes) :].lstrip(b"/")
            )
            if child.kind == "directory":
                pending.append(entry.path)
            elif child.kind != "regular":
                _die(f"Reviewed migration tree contains an unsupported object: {entry.path}")
            else:
                result.append((child_relative, child))
    return tuple(sorted(result))


def _private_state(
    pki_dir: str,
    root_authority: str,
    intermediate_authority: str,
) -> tuple[tuple[str, FileIdentity], ...]:
    pki_bytes = os.fsencode(pki_dir)
    authority_roots = (
        (os.fsencode(root_authority), b"root-ca"),
        (os.fsencode(intermediate_authority), b"intermediate-ca"),
    )
    result: list[tuple[str, FileIdentity]] = []
    pending = [pki_dir]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = tuple(entries)
        except OSError:
            _die("Reviewed private migration metadata could not be enumerated safely")
        for entry in children:
            path_bytes = os.fsencode(entry.path)
            relative = path_bytes[len(pki_bytes) + 1 :]
            for authority, logical in authority_roots:
                if path_bytes == authority or path_bytes.startswith(authority + b"/"):
                    relative = logical + path_bytes[len(authority) :]
                    break
            if relative.startswith(b"state/rollover/migrate-") or relative.startswith(
                b"legacy/.migrate-"
            ) or relative.startswith(b"legacy/migrate-"):
                continue
            try:
                identity = identity_from_stat(entry.stat(follow_symlinks=False))
            except (OSError, FilesystemError):
                _die("Reviewed private migration metadata changed")
            if identity.kind == "directory":
                pending.append(entry.path)
                continue
            components = relative.split(b"/")
            selected = (
                b"private" in components[:-1]
                or b"quarantine" in components[:-1]
                or b"passphrase" in relative
                or b"pass-file" in relative
                or relative.endswith(b".key")
            )
            if not selected:
                continue
            if identity.kind != "regular":
                _die(f"Private state path is unsafe: {entry.path}")
            result.append((os.fsdecode(relative), identity))
    return tuple(sorted(result))


def _public_state(
    pki_dir: str,
    root_authority: str,
    intermediate_authority: str,
) -> tuple[tuple[str, FileIdentity], ...]:
    pki_bytes = os.fsencode(pki_dir)
    roots = (
        (f"{pki_dir}/inventory", b"inventory"),
        (root_authority, b"root-ca"),
        (intermediate_authority, b"intermediate-ca"),
        (f"{pki_dir}/services", b"services"),
        (f"{pki_dir}/export", b"export"),
    )
    result: list[tuple[str, FileIdentity]] = []
    active = f"{pki_dir}/state/active-issuer"
    active_identity = _actual(active)
    if isinstance(active_identity, FileIdentity):
        result.append(("state/active-issuer", active_identity))
    elif active_identity is not ABSENT:
        _die("Reviewed public migration state is unsafe")
    for root, logical_root in roots:
        if not os.path.lexists(root):
            continue
        root_bytes = os.fsencode(root)
        pending = [root]
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as entries:
                    children = tuple(entries)
            except OSError:
                _die("Reviewed public migration state could not be enumerated safely")
            for entry in children:
                try:
                    identity = identity_from_stat(entry.stat(follow_symlinks=False))
                except (OSError, FilesystemError):
                    _die("Reviewed public migration state changed")
                relative = logical_root + os.fsencode(entry.path)[len(root_bytes) :]
                if identity.kind == "directory":
                    pending.append(entry.path)
                    continue
                components = relative.split(b"/")
                if (
                    identity.kind != "regular"
                    or b"private" in components[:-1]
                    or b"backups" in components[:-1]
                    or relative.endswith(b".key")
                ):
                    continue
                result.append((os.fsdecode(relative), identity))
    return tuple(sorted(result))


def _expected_state(
    reviewed: tuple[tuple[str, FileIdentity | DirectoryIdentity], ...],
    overrides: Mapping[str, FileIdentity | None],
) -> tuple[tuple[str, FileIdentity | DirectoryIdentity], ...]:
    expected = dict(reviewed)
    for path, identity in overrides.items():
        if identity is None:
            expected.pop(path, None)
        else:
            expected[path] = identity
    return tuple(sorted(expected.items()))


@dataclass(frozen=True, slots=True)
class _ReviewedState:
    transaction: _Transaction
    receipt: _Receipt
    inventory_path: str
    private_inventory_path: str
    root_tree: tuple[tuple[str, FileIdentity | DirectoryIdentity], ...]
    intermediate_tree: tuple[tuple[str, FileIdentity | DirectoryIdentity], ...]
    private_state: tuple[tuple[str, FileIdentity], ...]
    public_state: tuple[tuple[str, FileIdentity], ...]

    def recheck(
        self,
        root_path: str,
        intermediate_path: str,
        *,
        root_overrides: Mapping[str, FileIdentity | None] | None = None,
        intermediate_overrides: Mapping[str, FileIdentity | None] | None = None,
        public_overrides: Mapping[str, FileIdentity | None] | None = None,
        quarantined: frozenset[str] = frozenset(),
    ) -> None:
        full = self.transaction.full
        self.receipt.recheck()
        _require_state(self.inventory_path, full["inventory"], "Service inventory")
        _require_state(
            self.private_inventory_path,
            full["private_inventory"],
            "Canonical private inventory",
        )
        if _tree_state(root_path) != _expected_state(
            self.root_tree, root_overrides or {}
        ):
            _die("Reviewed root authority tree changed")
        if _tree_state(intermediate_path) != _expected_state(
            self.intermediate_tree, intermediate_overrides or {}
        ):
            _die("Reviewed intermediate authority tree changed")
        if (
            _private_state(self.transaction.pki_dir, root_path, intermediate_path)
            != self.private_state
        ):
            _die("Current private metadata differs from the reviewed migration state")
        if _public_state(
            self.transaction.pki_dir, root_path, intermediate_path
        ) != _expected_state(self.public_state, public_overrides or {}):
            _die("Current public PKI state differs from the reviewed migration state")
        for basename in _QUARANTINE_NAMES:
            original = full.get(f"quarantine:{basename}")
            if original is None:
                continue
            moved = basename in quarantined
            _require_state(
                f"{self.transaction.pki_dir}/{basename}",
                ABSENT if moved else original,
                "Legacy quarantine source",
            )
            _require_state(
                f"{self.transaction.transaction_dir}/quarantine/{basename}",
                original if moved else ABSENT,
                "Legacy quarantine destination",
            )


def _publish_file(
    source: str,
    destination: str,
    source_identity: FileIdentity,
    destination_identity: FileIdentity | object,
    *,
    pre_publish_check: Callable[[], None] | None = None,
) -> FileIdentity:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
    try:
        current = destination_parent.identity_at(destination_name)
        if not _matches(current, destination_identity):
            _die("Migration publication destination changed")
        if current is ABSENT:
            result = publish_no_clobber(
                source_parent,
                source_name,
                source_identity,
                destination_parent,
                destination_name,
                pre_publish_check=pre_publish_check,
            )
        else:
            assert isinstance(current, FileIdentity)
            result = replace_exact(
                source_parent,
                source_name,
                source_identity,
                destination_parent,
                destination_name,
                current,
                pre_exchange_check=pre_publish_check,
            )
        return _publication_identity(result)
    except PublicationAmbiguousError:
        raise
    except (FilesystemError, PublicationError):
        _die("Migration staged-file publication failed")
    finally:
        destination_parent.close()
        source_parent.close()


def _move_tree(
    source: str,
    destination: str,
    expected: DirectoryIdentity,
    *,
    pre_publish_check: Callable[[], None] | None = None,
) -> DirectoryIdentity:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
    identity: FileIdentity | None = None
    readiness = None
    try:
        try:
            with source_parent.open_directory(
                source_name, expected_identity=expected
            ) as opened:
                readiness = fsync_tree(opened, source_parent, source_name)
                identity = opened.identity
            assert identity is not None and readiness is not None
            result = publish_no_clobber(
                source_parent,
                source_name,
                identity,
                destination_parent,
                destination_name,
                readiness=readiness,
                pre_publish_check=pre_publish_check,
            )
            return result.identity.directory
        except (FilesystemError, PublicationError):
            raise ApplicationError("Migration directory publication failed") from None
    finally:
        destination_parent.close()
        source_parent.close()


def _remove_tree(path: str, expected: DirectoryIdentity) -> None:
    parent, name = _parent(path)
    identity: FileIdentity | None = None
    readiness = None
    try:
        try:
            with parent.open_directory(name, expected_identity=expected) as root:
                readiness = fsync_tree(root, parent, name)
                identity = root.identity
            assert identity is not None and readiness is not None
            remove_exact_tree(parent, name, identity, readiness)
        except (FilesystemError, PublicationError):
            raise ApplicationError(
                "Cannot remove committed migration transaction staging"
            ) from None
    finally:
        parent.close()


def _remove_marker(path: str) -> None:
    parent, name = _parent(path, private=True)
    try:
        current = parent.identity_at(name)
        if current is not ABSENT:
            if not isinstance(current, FileIdentity) or current.kind != "regular":
                _die("Migration recovery marker is unsafe")
            unlink_exact(parent, name, current)
        else:
            os.fsync(parent.fileno())
    except (FilesystemError, PublicationError, OSError):
        _die("Migration recovery marker cleanup failed")
    finally:
        parent.close()


@dataclass(slots=True)
class _Transaction:
    pki_dir: str
    transaction: str
    transaction_dir: str
    transaction_identity: DirectoryIdentity
    journal: str
    marker: str
    values: dict[str, str]
    full: dict[str, Any] = field(default_factory=dict)
    journal_identity: FileIdentity | None = None
    mutation_started: bool = False
    committed: bool = False

    def write_journal(self, phase: str, *, committed: bool = False) -> None:
        self.values["phase"] = phase
        self.values["committed"] = "true" if committed else "false"
        if tuple(self.values) != LEGACY_MIGRATION_WRITER_FIELDS:
            raise ValueError("legacy migration journal values are not in writer order")
        try:
            data = "".join(
                f"{field}={self.values[field]}\n"
                for field in LEGACY_MIGRATION_WRITER_FIELDS
            ).encode("ascii")
        except UnicodeEncodeError:
            _die("Migration recovery journal contains unsupported path characters")
        try:
            parse_recovery_semantics(data, pki_dir=self.pki_dir)
        except RecoveryRecordError:
            _die("Migration recovery journal could not be validated")
        parent, name = _parent(self.journal, private=True)
        try:
            expected = self.journal_identity if self.journal_identity is not None else ABSENT
            try:
                result = atomic_write_bytes(
                    parent,
                    name,
                    data,
                    expected_destination=expected,
                )
                self.journal_identity = _publication_identity(result)
            except (FilesystemError, PublicationError):
                _die("Migration recovery journal could not be published safely")
        finally:
            parent.close()

    def checkpoint(self, point: str, environment: Mapping[str, str]) -> None:
        if point not in (*MIGRATION_FAULT_CHECKPOINTS, *MIGRATION_MUTATION_CHECKPOINTS):
            raise ValueError("unknown migration checkpoint")
        if environment.get("PLATFORM_PKI_MIGRATE_CRASH_AT") == point:
            os.kill(os.getpid(), signal.SIGKILL)
        if environment.get("PLATFORM_PKI_MIGRATE_SIGNAL_AT") == point:
            try:
                process_signal = signal.Signals(
                    int(environment.get("PLATFORM_PKI_MIGRATE_SIGNAL", signal.SIGTERM))
                )
            except (TypeError, ValueError):
                raise ValueError("invalid migration test signal") from None
            if process_signal not in _HANDLED_SIGNALS:
                raise ValueError("unsupported migration test signal")
            os.kill(os.getpid(), process_signal)
        if environment.get("PLATFORM_PKI_MIGRATE_FAIL_AT") == point:
            _die(f"Injected migration interruption at {point}")

    def publish_marker(self) -> None:
        data = (
            f"transaction={self.transaction}\n"
            "action=run platform-pki-ca-rollover recover\n"
        ).encode("ascii")
        parent, name = _parent(self.marker, private=True)
        try:
            current = parent.identity_at(name)
            expected = current if isinstance(current, FileIdentity) else ABSENT
            try:
                atomic_write_bytes(parent, name, data, expected_destination=expected)
            except (FilesystemError, PublicationError):
                _die("Migration recovery marker could not be published safely")
        finally:
            parent.close()


def _authority_location(
    legacy: str,
    generation: str,
    source_identity: DirectoryIdentity,
    label: str,
    *,
    require_legacy: bool = False,
) -> str:
    legacy_state = _actual(legacy)
    generation_state = _actual(generation)
    if (legacy_state is ABSENT) == (generation_state is ABSENT):
        _die(f"{label} paths are simultaneously present or absent")
    current = legacy_state if legacy_state is not ABSENT else generation_state
    location = legacy if legacy_state is not ABSENT else generation
    if not _matches(current, source_identity):
        suffix = "legacy" if location == legacy else "generation"
        _die(f"{label} {suffix} identity changed")
    if require_legacy and location != legacy:
        _die(f"{label} moved before migration mutation")
    return location


def _journal_values(
    transaction: _Transaction,
    receipt: _Receipt,
    root_fingerprint: str,
    intermediate_fingerprint: str,
    values: Mapping[str, str],
) -> dict[str, str]:
    result = {
        "schema": "2",
        "operation": "legacy-migrate",
        "transaction": transaction.transaction,
        "phase": "pre-mutation",
        "legacy_root": values["legacy_root"],
        "legacy_intermediate": values["legacy_intermediate"],
        "new_root": values["new_root"],
        "new_intermediate": values["new_intermediate"],
        "root_source_identity": values["root_source_identity"],
        "intermediate_source_identity": values["intermediate_source_identity"],
        "root_sha256": root_fingerprint,
        "intermediate_sha256": intermediate_fingerprint,
        "transaction_dir": transaction.transaction_dir,
        "transaction_identity": serialize_directory_identity(
            transaction.transaction_identity
        ),
        "provenance_stage": values["provenance_stage"],
        "provenance_dir": values["provenance_dir"],
        "provenance_identity": values["provenance_identity"],
        "provenance_manifest": values["provenance_manifest"],
        "provenance_manifest_identity": values["provenance_manifest_identity"],
        "provenance_manifest_sha256": values["provenance_manifest_sha256"],
        "receipt_identity": serialize_file_identity(receipt.identity),
        "services_sha256": values["services_sha256"],
        "services_identity": values["services_identity"],
        "backup_receipt": receipt.path,
        "private_repo": values["private_repo"],
        "backup_session": values["backup_session"],
        "backup_session_original_identity": values[
            "backup_session_original_identity"
        ],
        "backup_session_published_identity": values[
            "backup_session_published_identity"
        ],
        "root_reservation": values["root_reservation"],
        "root_reservation_original_identity": values[
            "root_reservation_original_identity"
        ],
        "root_reservation_reserved_identity": values[
            "root_reservation_reserved_identity"
        ],
        "root_reservation_consumed_identity": values[
            "root_reservation_consumed_identity"
        ],
        "root_reservation_rollback_identity": values[
            "root_reservation_rollback_identity"
        ],
        "intermediate_reservation": values["intermediate_reservation"],
        "intermediate_reservation_original_identity": values[
            "intermediate_reservation_original_identity"
        ],
        "intermediate_reservation_reserved_identity": values[
            "intermediate_reservation_reserved_identity"
        ],
        "intermediate_reservation_consumed_identity": values[
            "intermediate_reservation_consumed_identity"
        ],
        "intermediate_reservation_rollback_identity": values[
            "intermediate_reservation_rollback_identity"
        ],
        "root_config_original_identity": values["root_config_original_identity"],
        "root_config_published_identity": values["root_config_published_identity"],
        "root_config_rollback_identity": values["root_config_rollback_identity"],
        "root_config_backup_identity": values["root_config_backup_identity"],
        "intermediate_config_original_identity": values[
            "intermediate_config_original_identity"
        ],
        "intermediate_config_published_identity": values[
            "intermediate_config_published_identity"
        ],
        "intermediate_config_rollback_identity": values[
            "intermediate_config_rollback_identity"
        ],
        "intermediate_config_backup_identity": values[
            "intermediate_config_backup_identity"
        ],
        "issuer_ledger": values["issuer_ledger"],
        "issuer_ledger_identity": values["issuer_ledger_identity"],
        "issuer_ledger_sha256": values["issuer_ledger_sha256"],
        "quarantine_ledger": values["quarantine_ledger"],
        "quarantine_ledger_identity": values["quarantine_ledger_identity"],
        "quarantine_ledger_sha256": values["quarantine_ledger_sha256"],
        "active_manifest": values["active_manifest"],
        "active_original_identity": values["active_original_identity"],
        "active_published_identity": values["active_published_identity"],
        "committed": "false",
    }
    if tuple(result) != LEGACY_MIGRATION_WRITER_FIELDS:
        raise AssertionError("legacy migration journal field order drifted")
    return result


def _build_transaction(
    pki_dir: str,
    private_repo: str,
    receipt: _Receipt,
    inventory: Inventory,
    inventory_path: str,
    inventory_identity: FileIdentity,
    private_inventory_path: str,
    private_inventory_identity: FileIdentity,
    root_fingerprint: str,
    intermediate_fingerprint: str,
    journal_identity: FileIdentity | None,
) -> _Transaction:
    legacy_root = f"{pki_dir}/root-ca"
    legacy_intermediate = f"{pki_dir}/intermediate-ca"
    new_root = f"{pki_dir}/authorities/roots/g1"
    new_intermediate = f"{pki_dir}/authorities/intermediates/g1-i1"
    root_source: DirectoryIdentity | None = None
    intermediate_source: DirectoryIdentity | None = None
    root_source_full: FileIdentity | None = None
    intermediate_source_full: FileIdentity | None = None
    try:
        with OpenedDirectory(legacy_root, policy=_PRIVATE_DIRECTORY) as opened:
            root_source = opened.directory_identity
            root_source_full = opened.identity
        with OpenedDirectory(legacy_intermediate, policy=_PRIVATE_DIRECTORY) as opened:
            intermediate_source = opened.directory_identity
            intermediate_source_full = opened.identity
    except FilesystemError:
        raise ApplicationError("Legacy CA directory is unsafe") from None
    assert (
        root_source is not None
        and intermediate_source is not None
        and root_source_full is not None
        and intermediate_source_full is not None
    )
    if root_source.dev != os.stat(f"{pki_dir}/authorities/roots").st_dev or (
        intermediate_source.dev
        != os.stat(f"{pki_dir}/authorities/intermediates").st_dev
    ):
        _die("Legacy CA directories and generation destinations must be on the same filesystem")
    root_source_text = f"{root_source.dev}:{root_source.ino}"
    intermediate_source_text = f"{intermediate_source.dev}:{intermediate_source.ino}"
    root_reservation = f"{pki_dir}/state/generation-reservations/g1"
    intermediate_reservation = f"{pki_dir}/state/generation-reservations/g1-i1"
    root_original = _reservation_state(root_reservation)
    intermediate_original = _reservation_state(intermediate_reservation)
    _adopt_reservation(
        root_reservation,
        "g1",
        "root",
        root_fingerprint,
        root_source_text,
        root_original,
    )
    _adopt_reservation(
        intermediate_reservation,
        "g1-i1",
        "intermediate",
        intermediate_fingerprint,
        intermediate_source_text,
        intermediate_original,
    )

    journal = f"{pki_dir}/state/rollover/journal"
    _require_state(
        journal,
        ABSENT if journal_identity is None else journal_identity,
        "Existing PKI recovery journal",
    )
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    transaction_name = f"migrate-{timestamp}-{os.getpid()}"
    transaction_dir = f"{pki_dir}/state/rollover/{transaction_name}"
    transaction_identity: DirectoryIdentity | None = None
    try:
        os.mkdir(transaction_dir, 0o700)
        with OpenedDirectory(transaction_dir, policy=_PRIVATE_DIRECTORY) as opened:
            transaction_identity = opened.directory_identity
    except (OSError, FilesystemError):
        raise ApplicationError("Cannot create migration transaction directory") from None
    assert transaction_identity is not None
    transaction = _Transaction(
        pki_dir,
        transaction_name,
        transaction_dir,
        transaction_identity,
        journal,
        f"{pki_dir}/state/rollover/recovery-required",
        {},
        journal_identity=journal_identity,
    )
    full = transaction.full

    root_config = f"{legacy_root}/openssl.cnf"
    intermediate_config = f"{legacy_intermediate}/openssl.cnf"
    root_original_full, root_backup = _copy_file(
        root_config, f"{transaction_dir}/root-openssl.cnf"
    )
    intermediate_original_full, intermediate_backup = _copy_file(
        intermediate_config, f"{transaction_dir}/intermediate-openssl.cnf"
    )
    root_published = _transform_config(
        root_config,
        f"{transaction_dir}/root-openssl.new",
        legacy_root,
        new_root,
    )
    intermediate_published = _transform_config(
        intermediate_config,
        f"{transaction_dir}/intermediate-openssl.new",
        legacy_intermediate,
        new_intermediate,
    )
    _write_new_file(
        f"{transaction_dir}/baseline",
        _baseline_bytes(
            receipt.values["state_manifest_sha256"],
            f"{legacy_root}/private/root-ca.key",
            f"{legacy_intermediate}/private/intermediate-ca.key",
        ),
    )
    services = tuple(
        service.name
        for service in inventory.services
        if os.path.isfile(f"{pki_dir}/services/{service.name}/certs/tls.crt")
        and not os.path.islink(f"{pki_dir}/services/{service.name}/certs/tls.crt")
    )
    services_identity = _write_new_file(
        f"{transaction_dir}/services",
        "".join(f"{service}\n" for service in services).encode("ascii"),
    )
    try:
        os.mkdir(f"{transaction_dir}/issuer-stage", 0o700)
        os.mkdir(f"{transaction_dir}/quarantine", 0o700)
    except OSError:
        _die("Cannot create migration evidence directories")

    backup_session = (
        f"{pki_dir}/state/rollover/backup-session-{receipt.values['session']}"
    )
    backup_original = _actual(backup_session)
    if backup_original is not ABSENT:
        _die("Backup migration session was already consumed")
    full["backup_session_published"] = _write_new_file(
        f"{transaction_dir}/backup-session.publish",
        (
            f"session={receipt.values['session']}\n"
            f"archive_sha256={receipt.values['archive_sha256']}\n"
            f"transaction={transaction_name}\n"
        ).encode("ascii"),
    )
    for prefix, generation, kind, fingerprint, source in (
        ("root", "g1", "root", root_fingerprint, root_source_text),
        (
            "intermediate",
            "g1-i1",
            "intermediate",
            intermediate_fingerprint,
            intermediate_source_text,
        ),
    ):
        for status, suffix in (
            ("reserved", "reserved"),
            ("consumed", "consumed"),
            ("abandoned", "abandoned"),
        ):
            full[f"{prefix}_{suffix}"] = _write_new_file(
                f"{transaction_dir}/{prefix}-{suffix}.publish",
                _reservation_bytes(generation, kind, status, fingerprint, source),
            )
    full["root_config_rollback"] = _copy_file(
        f"{transaction_dir}/root-openssl.cnf",
        f"{transaction_dir}/root-openssl.rollback",
    )[1]
    full["intermediate_config_rollback"] = _copy_file(
        f"{transaction_dir}/intermediate-openssl.cnf",
        f"{transaction_dir}/intermediate-openssl.rollback",
    )[1]
    full["active_published"] = _write_new_file(
        f"{transaction_dir}/active.publish",
        b"root=g1\nintermediate=g1-i1\n",
    )
    active = f"{pki_dir}/state/active-issuer"
    active_original = _actual(active)
    if active_original is not ABSENT:
        _die("Legacy migration active manifest destination already exists")

    issuer_rows = []
    for service in services:
        issuer = f"{pki_dir}/services/{service}/issuer"
        original = _actual(issuer)
        if original is not ABSENT:
            _die(f"Service issuer record already exists during legacy migration: {issuer}")
        stage = f"{transaction_dir}/issuer-stage/{service}"
        published = _write_new_file(stage, b"root=g1\nintermediate=g1-i1\n")
        full[f"issuer:{service}"] = published
        issuer_rows.append(
            f"{service}|absent|{serialize_file_object_state(published.state)}\n"
        )
    issuer_ledger = f"{transaction_dir}/issuer-identities"
    issuer_identity = _write_new_file(
        issuer_ledger, "".join(issuer_rows).encode("ascii")
    )
    quarantine_rows = []
    for basename in _QUARANTINE_NAMES:
        source = f"{pki_dir}/{basename}"
        current = _actual(source)
        if current is ABSENT:
            continue
        if not isinstance(current, FileIdentity) or current.kind != "regular":
            _die(f"Legacy quarantine source is unsafe: {source}")
        try:
            _OWNED_FILE.validate(current)
        except FilesystemError:
            _die(f"Legacy quarantine source is unsafe: {source}")
        full[f"quarantine:{basename}"] = current
        quarantine_rows.append(
            f"{basename}|{serialize_file_object_state(current.state)}\n"
        )
    quarantine_ledger = f"{transaction_dir}/quarantine-identities"
    quarantine_identity = _write_new_file(
        quarantine_ledger, "".join(quarantine_rows).encode("ascii")
    )
    try:
        with OpenedDirectory(
            f"{pki_dir}/state/rollover", policy=_PRIVATE_DIRECTORY
        ) as parent:
            with parent.open_directory(
                transaction_name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=transaction_identity,
            ) as opened:
                fsync_tree(opened, parent, transaction_name)
    except (FilesystemError, PublicationError):
        _die("Migration transaction evidence could not be synchronized")

    legacy = f"{pki_dir}/legacy"
    if not os.path.lexists(legacy):
        try:
            os.mkdir(legacy, 0o700)
            _sync_parent(legacy)
        except OSError:
            _die("Cannot create migration provenance directory")
    try:
        with OpenedDirectory(legacy, policy=_PRIVATE_DIRECTORY):
            pass
    except FilesystemError:
        _die(f"Migration provenance directory must be a non-symlink directory: {legacy}")
    provenance_stage = f"{legacy}/.{transaction_name}.publish"
    provenance_dir = f"{legacy}/{transaction_name}"
    _require_state(provenance_stage, ABSENT, "Migration provenance stage")
    _require_state(provenance_dir, ABSENT, "Migration provenance destination")
    _copy_tree(transaction_dir, provenance_stage)
    for basename in _QUARANTINE_NAMES:
        current = full.get(f"quarantine:{basename}")
        if current is None:
            continue
        source = f"{pki_dir}/{basename}"
        _require_state(source, current, "Legacy provenance source")
        _copy_file(source, f"{provenance_stage}/quarantine/{basename}")
    _write_new_file(
        f"{provenance_stage}/README",
        b"Legacy singleton CA directories were moved without copying private keys.\n"
        b"Original managed OpenSSL configurations and quarantined legacy scaffolding are retained here.\n",
    )
    manifest_path = f"{provenance_stage}/provenance-manifest"
    manifest_identity = _write_new_file(manifest_path, _manifest_bytes(provenance_stage))
    manifest_digest = _file_digest(
        manifest_path, manifest_identity, "Migration provenance manifest"
    )
    provenance_identity: DirectoryIdentity | None = None
    try:
        with OpenedDirectory(legacy, policy=_PRIVATE_DIRECTORY) as parent:
            with parent.open_directory(
                f".{transaction_name}.publish", policy=_PRIVATE_DIRECTORY
            ) as opened:
                fsync_tree(opened, parent, f".{transaction_name}.publish")
                provenance_identity = opened.directory_identity
    except (FilesystemError, PublicationError):
        raise ApplicationError("Migration provenance could not be synchronized") from None
    assert provenance_identity is not None

    full.update(
        root_config_original=root_original_full,
        intermediate_config_original=intermediate_original_full,
        root_config_backup=root_backup,
        intermediate_config_backup=intermediate_backup,
        root_config_published=root_published,
        intermediate_config_published=intermediate_published,
        services=services_identity,
        issuer_ledger=issuer_identity,
        quarantine_ledger=quarantine_identity,
        provenance_manifest=manifest_identity,
    )
    values = {
        "legacy_root": legacy_root,
        "legacy_intermediate": legacy_intermediate,
        "new_root": new_root,
        "new_intermediate": new_intermediate,
        "root_source_identity": root_source_text,
        "intermediate_source_identity": intermediate_source_text,
        "provenance_stage": provenance_stage,
        "provenance_dir": provenance_dir,
        "provenance_identity": serialize_directory_identity(provenance_identity),
        "provenance_manifest": manifest_path,
        "provenance_manifest_identity": serialize_file_identity(manifest_identity),
        "provenance_manifest_sha256": manifest_digest,
        "services_sha256": _file_digest(
            f"{transaction_dir}/services", services_identity, "Migration service snapshot"
        ),
        "services_identity": serialize_file_identity(services_identity),
        "private_repo": private_repo,
        "backup_session": backup_session,
        "backup_session_original_identity": "absent",
        "backup_session_published_identity": serialize_file_object_state(
            full["backup_session_published"].state
        ),
        "root_reservation": root_reservation,
        "root_reservation_original_identity": (
            "absent"
            if root_original is ABSENT
            else serialize_file_object_state(root_original.state)  # type: ignore[union-attr]
        ),
        "root_reservation_reserved_identity": serialize_file_object_state(
            full["root_reserved"].state
        ),
        "root_reservation_consumed_identity": serialize_file_object_state(
            full["root_consumed"].state
        ),
        "root_reservation_rollback_identity": serialize_file_object_state(
            full["root_abandoned"].state
        ),
        "intermediate_reservation": intermediate_reservation,
        "intermediate_reservation_original_identity": (
            "absent"
            if intermediate_original is ABSENT
            else serialize_file_object_state(intermediate_original.state)  # type: ignore[union-attr]
        ),
        "intermediate_reservation_reserved_identity": serialize_file_object_state(
            full["intermediate_reserved"].state
        ),
        "intermediate_reservation_consumed_identity": serialize_file_object_state(
            full["intermediate_consumed"].state
        ),
        "intermediate_reservation_rollback_identity": serialize_file_object_state(
            full["intermediate_abandoned"].state
        ),
        "root_config_original_identity": serialize_file_object_state(
            root_original_full.state
        ),
        "root_config_published_identity": serialize_file_object_state(
            root_published.state
        ),
        "root_config_rollback_identity": serialize_file_object_state(
            full["root_config_rollback"].state
        ),
        "root_config_backup_identity": serialize_file_object_state(root_backup.state),
        "intermediate_config_original_identity": serialize_file_object_state(
            intermediate_original_full.state
        ),
        "intermediate_config_published_identity": serialize_file_object_state(
            intermediate_published.state
        ),
        "intermediate_config_rollback_identity": serialize_file_object_state(
            full["intermediate_config_rollback"].state
        ),
        "intermediate_config_backup_identity": serialize_file_object_state(
            intermediate_backup.state
        ),
        "issuer_ledger": issuer_ledger,
        "issuer_ledger_identity": serialize_file_identity(issuer_identity),
        "issuer_ledger_sha256": _file_digest(
            issuer_ledger, issuer_identity, "Migration issuer ledger"
        ),
        "quarantine_ledger": quarantine_ledger,
        "quarantine_ledger_identity": serialize_file_identity(quarantine_identity),
        "quarantine_ledger_sha256": _file_digest(
            quarantine_ledger, quarantine_identity, "Migration quarantine ledger"
        ),
        "active_manifest": active,
        "active_original_identity": "absent",
        "active_published_identity": serialize_file_object_state(
            full["active_published"].state
        ),
    }
    transaction.values = _journal_values(
        transaction,
        receipt,
        root_fingerprint,
        intermediate_fingerprint,
        values,
    )
    full["inventory"] = inventory_identity
    full["private_inventory"] = private_inventory_identity
    full["root_source_directory"] = root_source_full
    full["intermediate_source_directory"] = intermediate_source_full
    full["root_original"] = root_original
    full["intermediate_original"] = intermediate_original
    full["root_tree"] = _tree_state(legacy_root)
    full["intermediate_tree"] = _tree_state(legacy_intermediate)
    full["private_state"] = _private_state(
        pki_dir, legacy_root, legacy_intermediate
    )
    full["public_state"] = _public_state(
        pki_dir, legacy_root, legacy_intermediate
    )
    return transaction


def _preflight(
    transaction: _Transaction,
    receipt: _Receipt,
    inventory_path: str,
    private_inventory_path: str,
) -> None:
    values = transaction.values
    full = transaction.full
    receipt.recheck()
    _require_state(inventory_path, full["inventory"], "Service inventory")
    _require_state(
        private_inventory_path,
        full["private_inventory"],
        "Canonical private inventory",
    )
    for key, path, digest, label in (
        (
            "issuer_ledger",
            values["issuer_ledger"],
            values["issuer_ledger_sha256"],
            "Migration issuer ledger",
        ),
        (
            "quarantine_ledger",
            values["quarantine_ledger"],
            values["quarantine_ledger_sha256"],
            "Migration quarantine ledger",
        ),
        (
            "services",
            f"{transaction.transaction_dir}/services",
            values["services_sha256"],
            "Migration service snapshot",
        ),
    ):
        if _file_digest(path, full[key], label) != digest:
            _die(f"{label} digest changed")
    provenance_identity = full["provenance_manifest"]
    _validate_provenance(
        values["provenance_stage"],
        _directory_identity(values["provenance_identity"]),
        values["provenance_manifest"],
        provenance_identity,
        values["provenance_manifest_sha256"],
    )
    root_identity = full["root_source_directory"].directory
    intermediate_identity = full["intermediate_source_directory"].directory
    _authority_location(
        values["legacy_root"],
        values["new_root"],
        root_identity,
        "Root authority",
        require_legacy=True,
    )
    _authority_location(
        values["legacy_intermediate"],
        values["new_intermediate"],
        intermediate_identity,
        "Intermediate authority",
        require_legacy=True,
    )
    for path, expected, label in (
        (
            f"{values['legacy_root']}/openssl.cnf",
            full["root_config_original"],
            "Root OpenSSL configuration",
        ),
        (
            f"{values['legacy_intermediate']}/openssl.cnf",
            full["intermediate_config_original"],
            "Intermediate OpenSSL configuration",
        ),
        (
            f"{transaction.transaction_dir}/root-openssl.new",
            full["root_config_published"],
            "Staged root OpenSSL configuration",
        ),
        (
            f"{transaction.transaction_dir}/intermediate-openssl.new",
            full["intermediate_config_published"],
            "Staged intermediate OpenSSL configuration",
        ),
        (
            f"{transaction.transaction_dir}/root-openssl.rollback",
            full["root_config_rollback"],
            "Staged root OpenSSL rollback",
        ),
        (
            f"{transaction.transaction_dir}/intermediate-openssl.rollback",
            full["intermediate_config_rollback"],
            "Staged intermediate OpenSSL rollback",
        ),
        (
            f"{transaction.transaction_dir}/backup-session.publish",
            full["backup_session_published"],
            "Staged backup migration session",
        ),
        (
            f"{transaction.transaction_dir}/active.publish",
            full["active_published"],
            "Staged active issuer manifest",
        ),
    ):
        _require_state(path, expected, label)
    for prefix in ("root", "intermediate"):
        for status in ("reserved", "consumed", "abandoned"):
            _require_state(
                f"{transaction.transaction_dir}/{prefix}-{status}.publish",
                full[f"{prefix}_{status}"],
                f"Staged {prefix} {status} reservation",
            )
    for path, expected, label in (
        (values["backup_session"], ABSENT, "Backup migration session"),
        (
            values["root_reservation"],
            full["root_original"],
            "Root generation reservation",
        ),
        (
            values["intermediate_reservation"],
            full["intermediate_original"],
            "Intermediate generation reservation",
        ),
        (values["active_manifest"], ABSENT, "Active issuer manifest"),
        (values["provenance_dir"], ABSENT, "Migration provenance destination"),
    ):
        _require_state(path, expected, label)
    for key, expected in (
        ("root_reservation", values["root_reservation_original_identity"]),
        (
            "intermediate_reservation",
            values["intermediate_reservation_original_identity"],
        ),
    ):
        current = _actual(values[key])
        if expected == "absent":
            if current is not ABSENT:
                _die(f"{key.replace('_', ' ').title()} identity changed")
        elif not isinstance(current, FileIdentity) or serialize_file_object_state(
            current.state
        ) != expected:
            _die(f"{key.replace('_', ' ').title()} identity changed")
    services = _read_lines(f"{transaction.transaction_dir}/services")
    for service in services:
        _require_state(
            f"{transaction.pki_dir}/services/{service}/issuer",
            ABSENT,
            f"Service {service} issuer",
        )
        _require_state(
            f"{transaction.transaction_dir}/issuer-stage/{service}",
            full[f"issuer:{service}"],
            f"Staged issuer {service}",
        )
    for basename in _QUARANTINE_NAMES:
        expected = full.get(f"quarantine:{basename}")
        if expected is None:
            continue
        _require_state(
            f"{transaction.pki_dir}/{basename}", expected, "Legacy quarantine source"
        )
        _require_state(
            f"{transaction.transaction_dir}/quarantine/{basename}",
            ABSENT,
            "Legacy quarantine destination",
        )
    if (
        _public_state_digest(transaction.pki_dir, "legacy")
        != receipt.values["state_manifest_sha256"]
    ):
        _die("Current public PKI state differs from the backed-up state manifest")


def _read_lines(path: str) -> tuple[str, ...]:
    data = b""
    try:
        with OpenedFile(path, policy=_PRIVATE_FILE) as opened:
            data = opened.read(_MAX_RECORD)
    except FilesystemError:
        raise ApplicationError("Migration service snapshot changed") from None
    try:
        return tuple(data.decode("ascii").splitlines())
    except UnicodeDecodeError:
        _die("Migration service snapshot has invalid content")


def _run_transaction(
    transaction: _Transaction,
    receipt: _Receipt,
    inventory_path: str,
    private_inventory_path: str,
    environment: Mapping[str, str],
) -> int:
    values = transaction.values
    full = transaction.full
    _preflight(transaction, receipt, inventory_path, private_inventory_path)
    reviewed = _ReviewedState(
        transaction,
        receipt,
        inventory_path,
        private_inventory_path,
        full["root_tree"],
        full["intermediate_tree"],
        full["private_state"],
        full["public_state"],
    )
    root_overrides: dict[str, FileIdentity | None] = {}
    intermediate_overrides: dict[str, FileIdentity | None] = {}
    public_overrides: dict[str, FileIdentity | None] = {}
    quarantined: set[str] = set()

    def recheck(root_path: str, intermediate_path: str) -> None:
        reviewed.recheck(
            root_path,
            intermediate_path,
            root_overrides=root_overrides,
            intermediate_overrides=intermediate_overrides,
            public_overrides=public_overrides,
            quarantined=frozenset(quarantined),
        )

    with _defer_signals():
        transaction.write_journal("pre-mutation")
        transaction.mutation_started = True
    transaction.checkpoint("after-journal", environment)

    with _defer_signals():
        _publish_file(
            f"{transaction.transaction_dir}/backup-session.publish",
            values["backup_session"],
            full["backup_session_published"],
            ABSENT,
        )
        for prefix, destination in (
            ("root", values["root_reservation"]),
            ("intermediate", values["intermediate_reservation"]),
        ):
            original = values[f"{prefix}_reservation_original_identity"]
            expected = ABSENT if original == "absent" else full[f"{prefix}_original"]
            full[f"{prefix}_reserved_destination"] = _publish_file(
                f"{transaction.transaction_dir}/{prefix}-reserved.publish",
                destination,
                full[f"{prefix}_reserved"],
                expected,
            )
        transaction.write_journal("reserved")
    transaction.checkpoint("after-reservations", environment)

    with _defer_signals():
        recheck(values["legacy_root"], values["legacy_intermediate"])
        _move_tree(
            values["legacy_root"],
            values["new_root"],
            full["root_source_directory"].directory,
            pre_publish_check=lambda: recheck(
                values["legacy_root"], values["legacy_intermediate"]
            ),
        )
    transaction.checkpoint("root-move-before-journal", environment)
    with _defer_signals():
        transaction.write_journal("root-renamed")
    transaction.checkpoint("after-root-rename", environment)
    with _defer_signals():
        recheck(values["new_root"], values["legacy_intermediate"])
        _move_tree(
            values["legacy_intermediate"],
            values["new_intermediate"],
            full["intermediate_source_directory"].directory,
            pre_publish_check=lambda: recheck(
                values["new_root"], values["legacy_intermediate"]
            ),
        )
    transaction.checkpoint("intermediate-move-before-journal", environment)
    with _defer_signals():
        transaction.write_journal("intermediate-renamed")
    transaction.checkpoint("after-intermediate-rename", environment)

    with _defer_signals():
        recheck(values["new_root"], values["new_intermediate"])
        root_config_destination = _publish_file(
            f"{transaction.transaction_dir}/root-openssl.new",
            f"{values['new_root']}/openssl.cnf",
            full["root_config_published"],
            full["root_config_original"],
            pre_publish_check=lambda: recheck(
                values["new_root"], values["new_intermediate"]
            ),
        )
        root_overrides["openssl.cnf"] = root_config_destination
        public_overrides["root-ca/openssl.cnf"] = root_config_destination
        intermediate_config_destination = _publish_file(
            f"{transaction.transaction_dir}/intermediate-openssl.new",
            f"{values['new_intermediate']}/openssl.cnf",
            full["intermediate_config_published"],
            full["intermediate_config_original"],
            pre_publish_check=lambda: recheck(
                values["new_root"], values["new_intermediate"]
            ),
        )
        intermediate_overrides["openssl.cnf"] = intermediate_config_destination
        public_overrides["intermediate-ca/openssl.cnf"] = (
            intermediate_config_destination
        )
        if root_config_destination.state != full["root_config_published"].state:
            _die("Published root OpenSSL configuration identity changed")
        if (
            intermediate_config_destination.state
            != full["intermediate_config_published"].state
        ):
            _die("Published intermediate OpenSSL configuration identity changed")
        transaction.write_journal("configs-published")
    transaction.checkpoint("after-configs", environment)

    with _defer_signals():
        recheck(values["new_root"], values["new_intermediate"])
        for service in _read_lines(f"{transaction.transaction_dir}/services"):
            issuer_destination = _publish_file(
                f"{transaction.transaction_dir}/issuer-stage/{service}",
                f"{transaction.pki_dir}/services/{service}/issuer",
                full[f"issuer:{service}"],
                ABSENT,
                pre_publish_check=lambda: recheck(
                    values["new_root"], values["new_intermediate"]
                ),
            )
            if issuer_destination.state != full[f"issuer:{service}"].state:
                _die(f"Published service issuer identity changed: {service}")
            public_overrides[f"services/{service}/issuer"] = issuer_destination
        transaction.write_journal("issuers-published")
    transaction.checkpoint("after-issuers", environment)

    with _defer_signals():
        recheck(values["new_root"], values["new_intermediate"])
        for basename in _QUARANTINE_NAMES:
            expected = full.get(f"quarantine:{basename}")
            if expected is None:
                continue
            full[f"quarantine:{basename}"] = _publish_file(
                f"{transaction.pki_dir}/{basename}",
                f"{transaction.transaction_dir}/quarantine/{basename}",
                expected,
                ABSENT,
                pre_publish_check=lambda: recheck(
                    values["new_root"], values["new_intermediate"]
                ),
            )
            quarantined.add(basename)
        transaction.write_journal("quarantined")
    transaction.checkpoint("after-quarantine", environment)

    with _defer_signals():
        recheck(values["new_root"], values["new_intermediate"])
        for prefix, destination in (
            ("root", values["root_reservation"]),
            ("intermediate", values["intermediate_reservation"]),
        ):
            _publish_file(
                f"{transaction.transaction_dir}/{prefix}-consumed.publish",
                destination,
                full[f"{prefix}_consumed"],
                full[f"{prefix}_reserved_destination"],
                pre_publish_check=lambda: recheck(
                    values["new_root"], values["new_intermediate"]
                ),
            )
        transaction.write_journal("active-pending")
        _publish_file(
            f"{transaction.transaction_dir}/active.publish",
            values["active_manifest"],
            full["active_published"],
            ABSENT,
            pre_publish_check=lambda: recheck(
                values["new_root"], values["new_intermediate"]
            ),
        )
    transaction.checkpoint("active-publication-before-journal", environment)
    with _defer_signals():
        transaction.write_journal("active-published")
    transaction.checkpoint("after-active", environment)

    with _defer_signals():
        _move_tree(
            values["provenance_stage"],
            values["provenance_dir"],
            _directory_identity(values["provenance_identity"]),
        )
        transaction.write_journal("provenance-published")
        transaction.write_journal("complete", committed=True)
        _remove_marker(transaction.marker)
        transaction.committed = True
    _remove_tree(transaction.transaction_dir, transaction.transaction_identity)
    _ok("Migrated legacy PKI state to root g1 and intermediate g1-i1")
    return 0


def migrate_ca_rollover(
    parsed: ParseResult,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Migrate one authenticated legacy layout through the schema-2 writer."""

    if not isinstance(parsed, ParseResult):
        raise TypeError("parsed must be a ParseResult")
    selected_environment = dict(os.environ if environment is None else environment)
    require_pilot_common_library(selected_environment)
    require_program("openssl", selected_environment)
    paths = resolve_paths(parsed.values, selected_environment)
    _safe_record_path(paths.pki_dir, "PKI directory")
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    _require_no_symlink_components(paths.pki_dir, "PKI directory")
    receipt_path = _absolute_option(parsed["--backup-receipt"], selected_environment)
    private_repo = _absolute_option(parsed["--private-repo"], selected_environment)
    _safe_record_path(receipt_path, "Backup receipt path")
    _safe_record_path(private_repo, "Private repository path")
    receipt = _read_receipt(receipt_path)
    _safe_record_path(receipt.archive, "Backup archive path")
    previous_umask = os.umask(0o077)
    previous_handlers: dict[signal.Signals, Any] = {}
    transaction: _Transaction | None = None

    def handled_signal(signum: int, _frame: object) -> NoReturn:
        raise _SignalExit(128 + signum)

    for process_signal in _HANDLED_SIGNALS:
        previous_handlers[process_signal] = signal.signal(process_signal, handled_signal)
    try:
        try:
            with acquire_operational_locks(paths.pki_dir, "export"):
                existing_journal_identity = _require_no_unresolved_state(paths.pki_dir)
                layout = detect_layout(paths.pki_dir)
                if layout == "generation":
                    return _generation_noop(paths.pki_dir, selected_environment)
                if layout != "legacy":
                    _die(
                        "Legacy migration refuses incomplete or ambiguous layout: "
                        f"{layout}"
                    )
                _prepare_generation_parents(paths.pki_dir)
                if detect_layout(paths.pki_dir) != "legacy":
                    _die(
                        "Legacy migration destination preparation found incomplete or "
                        "ambiguous state"
                    )
                if (
                    _public_state_digest(paths.pki_dir, "legacy")
                    != receipt.values["state_manifest_sha256"]
                ):
                    _die(
                        "Current public PKI state differs from the backed-up state manifest"
                    )
                if (
                    _private_metadata_digest(paths.pki_dir)
                    != receipt.values["private_metadata_sha256"]
                ):
                    _die("Current private metadata differs from the backed-up state")
                legacy_root = f"{paths.pki_dir}/root-ca"
                legacy_intermediate = f"{paths.pki_dir}/intermediate-ca"
                for authority in (legacy_root, legacy_intermediate):
                    try:
                        with OpenedDirectory(authority, policy=_PRIVATE_DIRECTORY):
                            pass
                    except FilesystemError:
                        _die(f"Legacy CA directory must be current-user-owned with mode 700: {authority}")
                root_certificate = f"{legacy_root}/certs/root-ca.crt"
                intermediate_certificate = (
                    f"{legacy_intermediate}/certs/intermediate-ca.crt"
                )
                for path in (
                    root_certificate,
                    intermediate_certificate,
                    f"{legacy_root}/openssl.cnf",
                    f"{legacy_intermediate}/openssl.cnf",
                ):
                    _require_regular(path)
                _run_openssl(
                    (
                        "openssl",
                        "verify",
                        "-CAfile",
                        root_certificate,
                        intermediate_certificate,
                    ),
                    selected_environment,
                    "Legacy intermediate does not verify against the legacy root",
                )
                root_fingerprint = _fingerprint(root_certificate, selected_environment)
                intermediate_fingerprint = _fingerprint(
                    intermediate_certificate, selected_environment
                )
                _confirm(parsed, root_fingerprint, intermediate_fingerprint)
                inventory_path = f"{paths.pki_dir}/inventory/services.yml"
                inventory, inventory_identity = _load_inventory(
                    inventory_path, "Service inventory", private=False
                )
                _validate_legacy_state(
                    paths.pki_dir, inventory, selected_environment
                )
                _require_no_symlink_components(private_repo, "Private repository")
                private_inventory_path = f"{private_repo}/pki/services.yml"
                private_inventory, private_inventory_identity = _load_inventory(
                    private_inventory_path,
                    "Canonical private inventory",
                    private=True,
                )
                if sorted(inventory.canonical_bytes.splitlines()) != sorted(
                    private_inventory.canonical_bytes.splitlines()
                ):
                    _die(
                        "Active inventory differs semantically from the canonical private "
                        "inventory; install and review it before migration"
                    )
                for service in inventory.services:
                    certificate = (
                        f"{paths.pki_dir}/services/{service.name}/certs/tls.crt"
                    )
                    if not os.path.lexists(certificate):
                        continue
                    try:
                        with OpenedFile(certificate, policy=_OWNED_FILE):
                            pass
                    except FilesystemError:
                        _die(f"Current service certificate is unsafe: {certificate}")
                    _run_openssl(
                        (
                            "openssl",
                            "verify",
                            "-CAfile",
                            root_certificate,
                            "-untrusted",
                            intermediate_certificate,
                            certificate,
                        ),
                        selected_environment,
                        f"Service does not verify through the legacy issuer: {service.name}",
                    )
                transaction = _build_transaction(
                    paths.pki_dir,
                    private_repo,
                    receipt,
                    inventory,
                    inventory_path,
                    inventory_identity,
                    private_inventory_path,
                    private_inventory_identity,
                    root_fingerprint,
                    intermediate_fingerprint,
                    existing_journal_identity,
                )
                assert transaction is not None
                return _run_transaction(
                    transaction,
                    receipt,
                    inventory_path,
                    private_inventory_path,
                    selected_environment,
                )
        except _SignalExit as error:
            if transaction is not None and transaction.mutation_started and not transaction.committed:
                for process_signal in _HANDLED_SIGNALS:
                    signal.signal(process_signal, signal.SIG_IGN)
                try:
                    transaction.publish_marker()
                except ApplicationError:
                    return 1
            return error.status
        except ApplicationError:
            if transaction is not None and transaction.mutation_started and not transaction.committed:
                for process_signal in _HANDLED_SIGNALS:
                    signal.signal(process_signal, signal.SIG_IGN)
                transaction.publish_marker()
            raise
        except (OSError, FilesystemError, PublicationError) as error:
            if transaction is not None and transaction.mutation_started and not transaction.committed:
                for process_signal in _HANDLED_SIGNALS:
                    signal.signal(process_signal, signal.SIG_IGN)
                transaction.publish_marker()
            raise ApplicationError("Legacy migration failed safely") from error
    finally:
        os.umask(previous_umask)
        for process_signal, handler in previous_handlers.items():
            signal.signal(process_signal, handler)
