"""Prepare immutable generation-aware CA rollover candidates."""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import signal
import subprocess
import sys
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any, NoReturn, cast

from .backup import _private_metadata_digest, _public_state_digest
from .ca_passphrase_verify import _open_passphrase
from .ca_rollover_recovery import (
    ROOT_DB_KEYS,
    ROLLOVER_PREPARE_DECLARED_FIELDS,
    RecoveryAction,
    RecoveryRecordError,
    RolloverPrepareRecoveryRecord,
    parse_recovery_semantics,
    serialize_typed_recovery_rewrite,
)
from .errors import ApplicationError, shell_status
from .filesystem import (
    ABSENT,
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_at,
    identity_from_stat,
    validate_trusted_ancestors,
    walk_metadata,
)
from .faults import FaultHook
from .intermediate_create import (
    _certificate_dates,
    _certificate_fingerprint,
    _intermediate_config,
    _root_config,
    _validate_config_value,
    _validate_days,
)
from .operational import (
    acquire_operational_locks,
    detect_layout,
    prepare_control_state,
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
)
from .parser import ParseResult
from .paths import absolutize_path, expand_home
from .persisted_identity import (
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
)
from .publication import (
    PublicationError,
    atomic_write_bytes,
    fsync_tree,
    publish_no_clobber,
    replace_exact,
    unlink_exact,
)
from .root_create import (
    _ChildFailure,
    _SignalExit,
    _publication_identity,
    _run_with_passphrase,
    _secure_generated_file,
)
from .tree_manifests import (
    TreeManifestError,
    remove_manifested_tree,
    validate_tree_manifest,
)


_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_PRIVATE_FILE = FilePolicy(owner=os.geteuid(), mode=0o600, links=1)
_PUBLIC_CERTIFICATE = FilePolicy(owner=os.geteuid(), mode=0o644, links=1)
_MAX_RECORD = 256 * 1024
_MAX_CERTIFICATE = 4 * 1024 * 1024
_MAX_TREE_ENTRIES = 65_536
_ROOT_GENERATION = re.compile(r"g([1-9][0-9]*)", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(
    r"g([1-9][0-9]*)-i([1-9][0-9]*)", re.ASCII
)
_SESSION = re.compile(r"[0-9a-f]{32}", re.ASCII)
_SERIAL = re.compile(r"[0-9A-Fa-f]+", re.ASCII)
_RECEIPT_FIELDS = frozenset(
    (
        "schema",
        "layout",
        "session",
        "backup_path",
        "backup_device",
        "backup_inode",
        "backup_size",
        "backup_mode",
        "backup_owner",
        "archive_sha256",
        "created_at",
        "created_epoch",
        "state_manifest_sha256",
        "private_metadata_sha256",
    )
)
_PREPARTIAL_NAMES = (
    "trust_snapshot",
    "root_stage_key",
    "root_stage_cert",
    "root_stage_index",
    "root_stage_index_backup",
    "root_stage_index_attr",
    "root_stage_index_attr_backup",
    "root_stage_serial",
    "root_stage_serial_backup",
    "root_stage_crlnumber",
    "root_stage_crlnumber_backup",
    "root_stage_index_old_backup",
    "root_stage_index_attr_old_backup",
    "root_stage_serial_old_backup",
    "root_stage_crlnumber_old_backup",
    "candidate_root_key",
    "candidate_root_cert",
    "candidate_intermediate_key",
    "candidate_intermediate_csr",
    "candidate_intermediate_cert",
    "candidate_chain",
)
_ROOT_DB_RELATIVES = {
    "index": "index.txt",
    "index_attr": "index.txt.attr",
    "serial": "serial",
    "crlnumber": "crlnumber",
    "index_old": "index.txt.old",
    "index_attr_old": "index.txt.attr.old",
    "serial_old": "serial.old",
    "crlnumber_old": "crlnumber.old",
}


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _actual(path: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemError:
        _die("Rollover preparation filesystem state could not be inspected safely")


def _identity(path: str) -> FileIdentity:
    value = _actual(path)
    if not isinstance(value, FileIdentity):
        _die(f"Required file is missing: {path}")
    return value


def _directory_identity(path: str) -> DirectoryIdentity:
    value = _identity(path)
    if value.kind != "directory":
        _die(f"Required directory is missing: {path}")
    return value.directory


def _full_or_absent(path: str) -> str:
    value = _actual(path)
    return "absent" if value is ABSENT else serialize_file_identity(value)  # type: ignore[arg-type]


def _require_full_or_absent(path: str, expected: str, label: str) -> None:
    if _full_or_absent(path) != expected:
        _die(f"{label} identity changed before publication")


def _object_or_absent(path: str) -> str:
    value = _actual(path)
    return "absent" if value is ABSENT else serialize_file_object_state(value.state)  # type: ignore[union-attr]


def _sha256_file(path: str, expected: FileIdentity | None = None) -> str:
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), links=1),
            expected_identity=expected,
        ) as opened:
            digest = hashlib.sha256()
            offset = 0
            while offset < opened.identity.size:
                chunk = os.pread(
                    opened.fileno(), min(64 * 1024, opened.identity.size - offset), offset
                )
                if not chunk:
                    raise OSError
                digest.update(chunk)
                offset += len(chunk)
            opened.recheck()
            return digest.hexdigest()
    except (OSError, FilesystemError):
        _die(f"File changed while being hashed: {path}")
    raise AssertionError("unreachable")


def _read_record(opened: OpenedFile, label: str) -> dict[str, str]:
    try:
        data = opened.read(_MAX_RECORD)
    except FilesystemError:
        _die(f"{label} changed while reading")
    if not data.endswith(b"\n"):
        _die(f"{label} has invalid content")
    values: dict[str, str] = {}
    for raw in data[:-1].split(b"\n"):
        if b"=" not in raw:
            _die(f"{label} has invalid content")
        key, value = raw.split(b"=", 1)
        if (
            re.fullmatch(rb"[a-z0-9_]+", key) is None
            or key.decode("ascii") in values
            or any(byte < 0x20 or byte > 0x7E for byte in value)
        ):
            _die(f"{label} has invalid content")
        values[key.decode("ascii")] = value.decode("ascii")
    return values


def _read_backup_receipt(path: str) -> tuple[OpenedFile, dict[str, str], OpenedFile]:
    try:
        receipt = OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=_MAX_RECORD
            ),
        )
    except FilesystemError:
        _die(f"Backup receipt is unsafe: {path}")
    try:
        values = _read_record(receipt, "Backup receipt")
        actual_fields = set(values)
        if actual_fields != set(_RECEIPT_FIELDS):
            missing = [field for field in _RECEIPT_FIELDS if field not in actual_fields]
            if missing:
                _die(f"Backup receipt is missing field: {sorted(missing)[0]}")
            _die("Backup receipt is not a supported generation-layout receipt")
        if (
            values["schema"] != "2"
            or values["layout"] != "generation"
            or _SESSION.fullmatch(values["session"]) is None
            or re.fullmatch(r"[0-9]+", values["created_epoch"], re.ASCII) is None
        ):
            _die("Backup receipt is not a supported generation-layout receipt")
        now = int(datetime.datetime.now(datetime.UTC).timestamp())
        created = int(values["created_epoch"], 10)
        if now < created or now - created > 86_400:
            _die("Backup receipt is older than the 24-hour preparation freshness window")
        archive_path = values["backup_path"]
        if not os.path.isabs(archive_path):
            _die("Backup archive path is unsafe or missing")
        try:
            archive = OpenedFile(
                archive_path,
                policy=FilePolicy(owner=int(values["backup_owner"]), links=1),
            )
        except (ValueError, FilesystemError):
            _die("Backup archive path is unsafe or missing")
        identity = archive.identity
        expected = (
            str(identity.dev),
            str(identity.ino),
            str(identity.size),
            f"{identity.permissions:o}",
            str(identity.uid),
        )
        actual = tuple(
            values[key]
            for key in (
                "backup_device",
                "backup_inode",
                "backup_size",
                "backup_mode",
                "backup_owner",
            )
        )
        if identity.kind != "regular" or expected != actual:
            archive.close()
            _die("Backup archive identity no longer matches its receipt")
        digest = hashlib.sha256()
        offset = 0
        try:
            while offset < identity.size:
                chunk = os.pread(
                    archive.fileno(), min(64 * 1024, identity.size - offset), offset
                )
                if not chunk:
                    raise OSError
                digest.update(chunk)
                offset += len(chunk)
            archive.recheck()
        except (OSError, FilesystemError):
            archive.close()
            _die("Backup archive changed while hashing")
        if digest.hexdigest() != values["archive_sha256"]:
            archive.close()
            _die("Backup archive digest no longer matches its receipt")
        return receipt, values, archive
    except BaseException:
        receipt.close()
        raise


def _validate_trust_consumers(data: bytes) -> None:
    for offset, byte in enumerate(data):
        if (byte < 0x20 and byte != 0x0A) or byte == 0x7F:
            line_number = data.count(b"\n", 0, offset) + 1
            _die(
                "Trust consumer checklist contains unsupported characters at line "
                f"{line_number}"
            )
    consumer = ""
    kind = ""
    saw_document = False
    saw_consumers = False
    count = 0
    seen: set[str] = set()
    for line_number, raw in enumerate(data.split(b"\n"), 1):
        try:
            line = raw.decode("ascii")
        except UnicodeDecodeError:
            _die(
                f"Trust consumer checklist contains unsupported characters at line {line_number}"
            )
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line == "---":
            if saw_document or saw_consumers:
                _die(
                    "Trust consumer document marker is duplicate or misplaced at line "
                    f"{line_number}"
                )
            saw_document = True
            continue
        if line == "consumers:":
            if saw_consumers:
                _die("Trust consumer checklist contains duplicate consumers")
            saw_consumers = True
            continue
        if not saw_consumers:
            _die(f"Trust consumer content exists outside consumers at line {line_number}")
        match = re.fullmatch(r"  ([A-Za-z0-9][A-Za-z0-9_.-]*):", line, re.ASCII)
        if match is not None:
            if consumer and not kind:
                _die(f"Trust consumer {consumer} is missing kind")
            consumer = match[1]
            kind = ""
            if consumer in seen:
                _die(f"Trust consumer ID is duplicated: {consumer}")
            seen.add(consumer)
            count += 1
            continue
        match = re.fullmatch(r"    kind: +(managed|manual)", line, re.ASCII)
        if match is not None:
            if not consumer or kind:
                _die(
                    f"Trust consumer kind is duplicate or misplaced at line {line_number}"
                )
            kind = match[1]
            continue
        _die(f"Unsupported trust consumer grammar at line {line_number}")
    if not saw_consumers or not count:
        _die("Trust consumer checklist must contain at least one consumer")
    if consumer and not kind:
        _die(f"Trust consumer {consumer} is missing kind")


def _open_trust_source(path: str) -> tuple[OpenedFile, bytes]:
    try:
        opened = OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), forbidden_bits=0o022, links=1),
        )
        data = opened.read(opened.identity.size)
        _validate_trust_consumers(data)
        opened.recheck()
        return opened, data
    except FilesystemError:
        _die(
            "Trust consumer source must be a readable non-symlink regular file: "
            f"{path}"
        )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    try:
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
    finally:
        view.release()


def _write_new_file(path: str, data: bytes, mode: int) -> FileIdentity:
    descriptor = -1
    identity: FileIdentity | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
        )
        _write_all(descriptor, data)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        identity = identity_from_stat(os.fstat(descriptor))
        if identity.uid != os.geteuid() or identity.permissions != mode:
            raise OSError
        parent = os.open(
            os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        assert identity is not None
        return identity
    except (OSError, FilesystemError):
        _die(f"Rollover preparation file could not be written safely: {path}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _replace_file_bytes(path: str, expected: FileIdentity, data: bytes, mode: int) -> FileIdentity:
    descriptor = -1
    try:
        before = identity_from_stat(os.lstat(path))
        if before != expected:
            raise OSError
        descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if identity_from_stat(os.fstat(descriptor)) != expected:
            raise OSError
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, data)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        after = identity_from_stat(os.fstat(descriptor))
        if identity_from_stat(os.lstat(path)) != after:
            raise OSError
        return after
    except (OSError, FilesystemError):
        _die(f"Rollover preparation file changed while being written: {path}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _copy_into_existing(
    source: OpenedFile,
    destination: str,
    expected: FileIdentity,
    mode: int,
    copy_command: str,
    environment: Mapping[str, str],
) -> FileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if identity_from_stat(os.fstat(descriptor)) != expected:
            raise OSError
        source.recheck()
        try:
            result = subprocess.run(
                (
                    copy_command,
                    "-p",
                    "--",
                    f"/proc/self/fd/{source.fileno()}",
                    f"/proc/self/fd/{descriptor}",
                ),
                stdin=subprocess.DEVNULL,
                env=dict(environment),
                shell=False,
                close_fds=True,
                pass_fds=(source.fileno(), descriptor),
                check=False,
            )
        except OSError:
            raise _ChildFailure(127) from None
        if result.returncode:
            raise _ChildFailure(shell_status(result.returncode))
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        copied = identity_from_stat(os.fstat(descriptor))
        if identity_from_stat(os.lstat(destination)) != copied:
            raise OSError
        source.recheck()
        return copied
    except _ChildFailure:
        raise
    except (OSError, FilesystemError):
        _die(f"Required authority file could not be copied safely: {destination}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _mkdir(path: str, mode: int = 0o700) -> DirectoryIdentity:
    identity: DirectoryIdentity | None = None
    try:
        os.mkdir(path, mode)
        with OpenedDirectory(path, policy=DirectoryPolicy(owner=os.geteuid(), mode=mode)) as opened:
            identity = opened.directory_identity
        parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        assert identity is not None
        return identity
    except (OSError, FilesystemError):
        _die(f"Cannot create rollover preparation directory: {path}")


def _hash_opened(opened: OpenedFile) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < opened.identity.size:
        try:
            chunk = os.pread(
                opened.fileno(), min(64 * 1024, opened.identity.size - offset), offset
            )
        except OSError:
            _die("Managed PKI tree file could not be hashed")
        if not chunk:
            _die("Managed PKI tree file changed while being hashed")
        digest.update(chunk)
        offset += len(chunk)
    try:
        opened.recheck()
    except FilesystemError:
        _die("Managed PKI tree file changed while being hashed")
    return digest.hexdigest()


def _tree_manifest_bytes(root_path: str, *excluded: str) -> bytes:
    excluded_set = frozenset(excluded)
    rows: list[tuple[bytes, bytes]] = []
    try:
        with OpenedDirectory(root_path, policy=_PRIVATE_DIRECTORY) as root:
            entries = tuple(walk_metadata(root, xdev=True))[1:]
            if len(entries) > _MAX_TREE_ENTRIES:
                _die("Managed PKI tree exceeds the manifest entry bound")
            for entry in entries:
                relative = "/".join(entry.relative)
                digest = ""
                if relative in excluded_set:
                    continue
                if "|" in relative or "\n" in relative:
                    _die(f"Managed PKI tree contains an unsafe path: {root_path}/{relative}")
                if entry.uid != os.geteuid() or entry.permissions & 0o022:
                    _die(f"Managed PKI tree contains unsafe state: {root_path}/{relative}")
                if entry.kind == "directory":
                    identity = DirectoryIdentity(
                        entry.dev,
                        entry.ino,
                        entry.uid,
                        entry.permissions,
                        "directory",
                    )
                    object_type = "directory"
                    digest = "-"
                    serialized = serialize_directory_identity(identity)
                elif entry.kind == "regular":
                    identity = FileIdentity(
                        entry.dev,
                        entry.ino,
                        entry.uid,
                        entry.permissions,
                        entry.links,
                        entry.size,
                        entry.mtime_ns,
                        entry.ctime_ns,
                        "regular",
                    )
                    if identity.links != 1:
                        _die(f"Managed PKI tree contains hard-linked state: {root_path}/{relative}")
                    object_type = "regular empty file" if not identity.size else "regular file"
                    sensitive = (
                        "private" in entry.relative[:-1]
                        or relative.endswith(".key")
                        or "passphrase" in relative
                    )
                    if sensitive:
                        digest = "secret"
                    else:
                        with OpenedFile(
                            os.path.join(root_path, *entry.relative),
                            policy=FilePolicy(owner=os.geteuid(), links=1),
                            expected_identity=identity,
                        ) as opened:
                            digest = _hash_opened(opened)
                    serialized = serialize_file_identity(identity)
                else:
                    _die(f"Managed PKI tree contains an unsupported object: {root_path}/{relative}")
                rows.append(
                    (
                        os.fsencode(relative),
                        f"{object_type}|{relative}|{serialized}|{digest}\n".encode(
                            "ascii"
                        ),
                    )
                )
            root.recheck()
    except FilesystemError:
        _die(f"Managed PKI tree changed while being inspected: {root_path}")
    return b"".join(row for _relative, row in sorted(rows))


def _write_manifest(path: str, root: str, *excluded: str) -> tuple[FileIdentity, str]:
    data = _tree_manifest_bytes(root, *excluded)
    identity = _write_new_file(path, data, 0o600)
    return identity, hashlib.sha256(data).hexdigest()


def _parent(path: str) -> tuple[OpenedDirectory, str]:
    directory, name = os.path.split(path)
    try:
        return OpenedDirectory(directory, policy=_PRIVATE_DIRECTORY), name
    except FilesystemError:
        _die("Rollover preparation publication parent is unsafe")


def _publish_file(
    source: str,
    destination: str,
    expected_source: FileIdentity,
    expected_destination: FileIdentity | object,
) -> FileIdentity:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
    try:
        if expected_destination is ABSENT:
            result = publish_no_clobber(
                source_parent,
                source_name,
                expected_source,
                destination_parent,
                destination_name,
            )
        else:
            assert isinstance(expected_destination, FileIdentity)
            result = replace_exact(
                source_parent,
                source_name,
                expected_source,
                destination_parent,
                destination_name,
                expected_destination,
            )
        return _publication_identity(result)
    except (FilesystemError, PublicationError):
        _die(f"Rollover preparation file publication failed: {destination}")
    finally:
        destination_parent.close()
        source_parent.close()


def _publish_tree(source: str, destination: str, expected: DirectoryIdentity) -> DirectoryIdentity:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
    source_identity: FileIdentity | None = None
    readiness = None
    try:
        with source_parent.open_directory(
            source_name, policy=_PRIVATE_DIRECTORY, expected_identity=expected
        ) as opened:
            readiness = fsync_tree(opened, source_parent, source_name)
            source_identity = opened.identity
        assert source_identity is not None and readiness is not None
        result = publish_no_clobber(
            source_parent,
            source_name,
            source_identity,
            destination_parent,
            destination_name,
            readiness=readiness,
        )
        return _publication_identity(result).directory
    except (FilesystemError, PublicationError):
        _die(f"Rollover preparation directory publication failed: {destination}")
    finally:
        destination_parent.close()
        source_parent.close()


def _remove_file(path: str, expected: FileIdentity) -> None:
    parent, name = _parent(path)
    try:
        unlink_exact(parent, name, expected)
    except (FilesystemError, PublicationError):
        _die("Preparation transaction manifest changed before cleanup")
    finally:
        parent.close()


def _fsync_private_tree(path: str) -> None:
    parent, name = _parent(path)
    try:
        with parent.open_directory(
            name,
            policy=_PRIVATE_DIRECTORY,
            expected_identity=_directory_identity(path),
        ) as opened:
            fsync_tree(opened, parent, name)
    except FilesystemError:
        _die(f"Rollover preparation tree could not be synchronized: {path}")
    finally:
        parent.close()


def _validate_manifested_tree(
    root: str,
    manifest_path: str,
    manifest_identity: str,
    manifest_digest: str,
    *,
    excluded: str | None = None,
) -> None:
    parent, name = _parent(root)
    try:
        with (
            parent.open_directory(
                name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=_directory_identity(root),
            ) as opened,
            OpenedFile(manifest_path, policy=_PRIVATE_FILE) as manifest,
        ):
            validate_tree_manifest(
                opened,
                parent,
                name,
                manifest,
                manifest_identity,
                manifest_digest,
                excluded=excluded,
            )
    except (FilesystemError, TreeManifestError):
        _die(f"PKI tree contents do not match their manifest: {root}")
    finally:
        parent.close()


def _capture(
    argv: tuple[str, ...],
    *,
    input_data: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    try:
        result = subprocess.run(
            argv,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(os.environ),
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
            check=False,
        )
    except OSError:
        _die(f"{argv[0]} is required")
    if result.returncode:
        raise _ChildFailure(shell_status(result.returncode))
    return result.stdout


def _certificate_public_key_digest(openssl: str, certificate: str) -> str:
    public = _capture((openssl, "x509", "-in", certificate, "-pubkey", "-noout"))
    der = _capture(
        (openssl, "pkey", "-pubin", "-outform", "DER"), input_data=public
    )
    return hashlib.sha256(der).hexdigest()


def _certificate_subject(openssl: str, certificate: str) -> bytes:
    return _capture(
        (openssl, "x509", "-in", certificate, "-noout", "-subject", "-nameopt", "RFC2253")
    )


def _certificate_expiry(certificate: str, stage: str) -> str:
    _start, end = _certificate_dates(certificate, stage)
    return datetime.datetime.fromtimestamp(end, datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _checkend(openssl: str, certificate: str, seconds: int) -> bool:
    try:
        _capture(
            (openssl, "x509", "-in", certificate, "-checkend", str(seconds), "-noout")
        )
    except _ChildFailure:
        return False
    return True


def _require_certificate_profile(openssl: str, certificate: str, pathlen: int, label: str) -> None:
    constraints = _capture(
        (openssl, "x509", "-in", certificate, "-noout", "-ext", "basicConstraints")
    )
    usage = _capture(
        (openssl, "x509", "-in", certificate, "-noout", "-ext", "keyUsage")
    )
    expected_constraints = (
        f"X509v3 Basic Constraints: critical\n    CA:TRUE, pathlen:{pathlen}\n".encode()
    )
    if constraints != expected_constraints:
        _die(
            f"{label} must have critical CA:TRUE Basic Constraints with pathlen:{pathlen}"
        )
    if usage != b"X509v3 Key Usage: critical\n    Certificate Sign, CRL Sign\n":
        _die(f"{label} must have critical Certificate Sign and CRL Sign Key Usage only")


def _verify(openssl: str, argv: tuple[str, ...], message: str) -> None:
    try:
        _capture((openssl, *argv))
    except _ChildFailure:
        _die(message)


def _require_key_match(
    openssl: str,
    key: str,
    certificate: str,
    passphrase: OpenedFile | None,
    stage: str,
) -> None:
    certificate_public = f"{stage}/cert.pub"
    key_public = f"{stage}/key.pub"
    cert_data = _capture((openssl, "x509", "-in", certificate, "-pubkey", "-noout"))
    _write_new_file(certificate_public, cert_data, 0o600)
    argv = (openssl, "pkey", "-in", key, "-pubout", "-out", key_public)
    _run_with_passphrase(passphrase, argv, "-passin")
    _secure_generated_file(key_public, 0o600)
    first_data = b""
    second_data = b""
    try:
        with OpenedFile(certificate_public, policy=_PRIVATE_FILE) as first:
            first_data = first.read(first.identity.size)
        with OpenedFile(key_public, policy=_PRIVATE_FILE) as second:
            second_data = second.read(second.identity.size)
    except FilesystemError:
        _die("Generated public-key comparison evidence changed")
    for path in (certificate_public, key_public):
        current = _identity(path)
        _remove_file(path, current)
    if first_data != second_data:
        _die(f"Private key and certificate do not match: {certificate}")


def _next_root(pki_dir: str) -> str:
    maximum = 0
    for directory, reservations in (
        (f"{pki_dir}/state/generation-reservations", True),
        (f"{pki_dir}/authorities/roots", False),
    ):
        try:
            entries = tuple(os.scandir(directory))
        except OSError:
            _die("Root generation state could not be inspected")
        for entry in entries:
            if reservations and _INTERMEDIATE_GENERATION.fullmatch(entry.name):
                continue
            match = _ROOT_GENERATION.fullmatch(entry.name)
            if match is None:
                _die(f"Invalid root generation state entry: {entry.path}")
            identity = _actual(entry.path)
            if not isinstance(identity, FileIdentity):
                _die(f"Invalid root generation state entry: {entry.path}")
            if reservations:
                if identity.kind != "regular" or identity.permissions != 0o600 or identity.links != 1:
                    _die(f"Unsafe root generation reservation: {entry.path}")
            elif identity.kind != "directory" or identity.permissions != 0o700:
                _die(f"Root authority generation must be current-user-owned with mode 700: {entry.path}")
            maximum = max(maximum, int(match[1]))
    return f"g{maximum + 1}"


def _next_intermediate(pki_dir: str, root: str) -> str:
    maximum = 0
    pattern = re.compile(re.escape(root) + r"-i([1-9][0-9]*)", re.ASCII)
    for directory, reservations in (
        (f"{pki_dir}/state/generation-reservations", True),
        (f"{pki_dir}/authorities/intermediates", False),
    ):
        try:
            entries = tuple(os.scandir(directory))
        except OSError:
            _die("Intermediate generation state could not be inspected")
        for entry in entries:
            if not entry.name.startswith(f"{root}-i"):
                continue
            match = pattern.fullmatch(entry.name)
            if match is None:
                _die(f"Invalid intermediate generation state entry: {entry.path}")
            identity = _actual(entry.path)
            if not isinstance(identity, FileIdentity):
                _die(f"Invalid intermediate generation state entry: {entry.path}")
            if reservations:
                if identity.kind != "regular" or identity.permissions != 0o600 or identity.links != 1:
                    _die(f"Unsafe intermediate generation reservation: {entry.path}")
            elif identity.kind != "directory" or identity.permissions != 0o700:
                _die(
                    "Intermediate authority generation must be current-user-owned with mode 700: "
                    f"{entry.path}"
                )
            maximum = max(maximum, int(match[1]))
    return f"{root}-i{maximum + 1}"


def _reservation_bytes(generation: str, kind: str, status: str, transaction: str) -> bytes:
    return (
        f"generation={generation}\nkind={kind}\nstatus={status}\n"
        f"transaction={transaction}\n"
    ).encode("ascii")


@dataclass(slots=True)
class _Preparation:
    pki_dir: str
    preparation_type: str
    transaction: str
    transaction_dir: str
    journal: str
    marker: str
    values: dict[str, str]
    environment: Mapping[str, str]
    journal_identity: FileIdentity | None
    transaction_identity: DirectoryIdentity | None = None
    committed: bool = False

    def fault(self, point: str) -> None:
        if self.environment.get("PLATFORM_PKI_PREPARE_CRASH_AT") == point:
            os.kill(os.getpid(), signal.SIGKILL)
        if self.environment.get("PLATFORM_PKI_PREPARE_SIGNAL_AT") == point:
            raise _SignalExit(143)
        if self.environment.get("PLATFORM_PKI_PREPARE_FAIL_AT") == point:
            _die(f"Injected rollover preparation failure at {point}")

    def write_journal(self, phase: str, *, committed: bool = False) -> RolloverPrepareRecoveryRecord:
        self.values["phase"] = phase
        self.values["committed"] = "true" if committed else "false"
        try:
            data = serialize_typed_recovery_rewrite(self.values, pki_dir=self.pki_dir)
            parent, name = _parent(self.journal)
            try:
                result = atomic_write_bytes(
                    parent,
                    name,
                    data,
                    expected_destination=(
                        self.journal_identity if self.journal_identity is not None else ABSENT
                    ),
                )
                self.journal_identity = _publication_identity(result)
            finally:
                parent.close()
            parsed = parse_recovery_semantics(data, pki_dir=self.pki_dir)
            assert isinstance(parsed, RolloverPrepareRecoveryRecord)
            return parsed
        except (RecoveryRecordError, FilesystemError, PublicationError):
            _die("Rollover preparation journal could not be published safely")

    def _refresh_transaction_manifest(self) -> None:
        if self.transaction_identity is None:
            return
        sequence = int(self.values["transaction_tree_manifest_sequence"], 10) + 1
        path = (
            f"{self.pki_dir}/state/rollover/.{self.transaction}."
            f"transaction-tree.{sequence}"
        )
        identity, digest = _write_manifest(path, self.transaction_dir)
        self.values.update(
            transaction_tree_manifest_pending=path,
            transaction_tree_manifest_pending_destination=path,
            transaction_tree_manifest_pending_identity=serialize_file_identity(identity),
            transaction_tree_manifest_pending_sha256=digest,
        )
        self.write_journal(self.values["phase"], committed=self.values["committed"] == "true")
        self.fault("transaction-manifest-staged")
        if _identity(path) != identity or _sha256_file(path, identity) != digest:
            _die("Preparation transaction manifest changed before publication")
        self.fault("transaction-manifest-published")
        old = self.values["transaction_tree_manifest"]
        if old != "none":
            old_identity = _identity(old)
            if serialize_file_identity(old_identity) != self.values[
                "transaction_tree_manifest_identity"
            ]:
                _die("Preparation transaction manifest changed before cleanup")
            _remove_file(old, old_identity)
            self.fault("transaction-manifest-superseded")
        self.values.update(
            transaction_tree_manifest=path,
            transaction_tree_manifest_identity=serialize_file_identity(identity),
            transaction_tree_manifest_sha256=digest,
            transaction_tree_manifest_sequence=str(sequence),
            transaction_tree_manifest_pending="none",
            transaction_tree_manifest_pending_destination="none",
            transaction_tree_manifest_pending_identity="none",
            transaction_tree_manifest_pending_sha256="none",
        )
        self.write_journal(self.values["phase"], committed=self.values["committed"] == "true")

    def checkpoint(self, point: str) -> None:
        self.values["recovery_step"] = point
        self._refresh_transaction_manifest()
        self.write_journal("recovering")
        self.fault(point)

    def file_destination(self, path: str, field_name: str, mode: int, point: str) -> FileIdentity:
        if _actual(path) is not ABSENT:
            _die(f"Preparation output destination already exists: {path}")
        identity = _write_new_file(path, b"", mode)
        self.values[f"{field_name}_pre_identity"] = serialize_file_identity(identity)
        self.checkpoint(f"{point}-pending")
        return identity

    def copied_file(
        self,
        source: OpenedFile,
        destination: str,
        field_name: str,
        mode: int,
        point: str,
    ) -> FileIdentity:
        before = self.file_destination(destination, field_name, mode, point)
        try:
            copied = _copy_into_existing(
                source,
                destination,
                before,
                mode,
                self.environment.get("PLATFORM_PKI_PREPARE_CP", "cp"),
                self.environment,
            )
        except (ApplicationError, _ChildFailure):
            current = _actual(destination)
            if isinstance(current, FileIdentity):
                self.values[f"{field_name}_partial_identity"] = serialize_file_identity(current)
            self.checkpoint(f"{point}-child-failed")
            _die(f"Sensitive child operation failed during {point}")
        self.values[f"{field_name}_identity"] = serialize_file_identity(copied)
        self.checkpoint(f"{point}-done")
        return copied

    def child_failed(self, point: str, *fields_and_paths: str) -> NoReturn:
        for index in range(0, len(fields_and_paths), 2):
            field_name = fields_and_paths[index]
            path = fields_and_paths[index + 1]
            current = _actual(path)
            if isinstance(current, FileIdentity):
                self.values[f"{field_name}_partial_identity"] = serialize_file_identity(current)
        self.checkpoint(f"{point}-child-failed")
        _die(f"Sensitive child operation failed during {point}")

    def publish_marker(self) -> None:
        current = _actual(self.marker)
        expected = current if isinstance(current, FileIdentity) else ABSENT
        parent, name = _parent(self.marker)
        try:
            atomic_write_bytes(
                parent,
                name,
                (
                    f"transaction={self.transaction}\n"
                    "action=run platform-pki-ca-rollover recover\n"
                ).encode("ascii"),
                expected_destination=expected,
            )
        except (FilesystemError, PublicationError):
            _die("Rollover preparation recovery marker could not be published")
        finally:
            parent.close()


@dataclass(slots=True)
class _RootDatabaseEntry:
    path: str
    identity: str
    current_identity: str
    digest: str | None
    opened: OpenedFile | None
    parent: OpenedDirectory
    name: str

    def recheck(self) -> None:
        try:
            self.parent.recheck()
            current = self.parent.identity_at(self.name)
            if self.opened is not None:
                if self.current_identity == self.identity:
                    self.opened.recheck()
                digest = hashlib.sha256()
                offset = 0
                while offset < self.opened.identity.size:
                    chunk = os.pread(
                        self.opened.fileno(),
                        min(64 * 1024, self.opened.identity.size - offset),
                        offset,
                    )
                    if not chunk:
                        raise OSError
                    digest.update(chunk)
                    offset += len(chunk)
                if digest.hexdigest() != self.digest:
                    raise OSError
        except (OSError, FilesystemError):
            _die(
                "Root database source changed during rollover preparation: "
                f"{self.path}"
            )
        current_identity = (
            "absent"
            if current is ABSENT
            else serialize_file_identity(cast(FileIdentity, current))
        )
        if current_identity != self.current_identity:
            _die(
                "Root database source changed during rollover preparation: "
                f"{self.path}"
            )


@dataclass(slots=True)
class _RootDatabaseSnapshot:
    entries: dict[str, _RootDatabaseEntry]
    issued_serial: str

    def recheck(self) -> None:
        for entry in self.entries.values():
            entry.recheck()


def _signing_serial_opened(serial_file: OpenedFile) -> str:
    try:
        serial = serial_file.read(4096).decode("ascii").strip()
    except (FilesystemError, UnicodeDecodeError):
        _die("Root CA serial is invalid")
    if _SERIAL.fullmatch(serial) is None:
        _die("Root CA serial is invalid")
    issued = serial.upper()
    while issued.startswith("00") and len(issued) > 2:
        issued = issued[2:]
    return issued


def _snapshot_root_database(
    preparation: _Preparation,
    active_root_dir: str,
    stack: ExitStack,
) -> _RootDatabaseSnapshot:
    entries: dict[str, _RootDatabaseEntry] = {}

    def capture(key: str, path: str) -> None:
        parent, name = _parent(path)
        stack.enter_context(parent)
        try:
            current = parent.identity_at(name)
            opened = None
            identity = "absent"
            digest = None
            if isinstance(current, FileIdentity):
                opened = stack.enter_context(
                    OpenedFile(
                        name,
                        policy=_PRIVATE_FILE,
                        expected_identity=current,
                        dir_fd=parent,
                    )
                )
                identity = serialize_file_identity(opened.identity)
                digest = hashlib.sha256(opened.read(opened.identity.size)).hexdigest()
        except FilesystemError:
            _die(f"Root database source is unsafe or changed: {path}")
        entries[key] = _RootDatabaseEntry(
            path, identity, identity, digest, opened, parent, name
        )

    for key, relative in _ROOT_DB_RELATIVES.items():
        capture(key, f"{active_root_dir}/{relative}")
    serial = entries["serial"].opened
    if serial is None:
        _die(f"Required file is missing: {entries['serial'].path}")
    issued = _signing_serial_opened(serial)
    capture("newcert", f"{active_root_dir}/newcerts/{issued}.pem")
    preparation.fault("root-db-snapshot-ready")
    snapshot = _RootDatabaseSnapshot(entries, issued)
    snapshot.recheck()
    if entries["newcert"].identity != "absent":
        _die("Root issued-certificate destination already exists")
    return snapshot


def _initial_values(
    *,
    pki_dir: str,
    preparation_type: str,
    transaction: str,
    active_root: str,
    active_intermediate: str,
    active_manifest: str,
    active_identity: FileIdentity,
    candidate_root: str,
    candidate_intermediate: str,
    backup_receipt: str,
    receipt_identity: FileIdentity,
    receipt: Mapping[str, str],
    trust_source: str,
    trust_source_identity: FileIdentity | None,
    trust_snapshot_sha256: str,
) -> dict[str, str]:
    transaction_dir = f"{pki_dir}/state/rollover/{transaction}"
    values = {field: "none" for field in ROLLOVER_PREPARE_DECLARED_FIELDS}
    values.update(
        schema="5",
        operation="rollover-prepare",
        transaction=transaction,
        type=preparation_type,
        phase="planned",
        committed="false",
        recovery_action="none",
        recovery_step="none",
        terminal_outcome="none",
        active_root=active_root,
        active_intermediate=active_intermediate,
        active_manifest=active_manifest,
        active_identity=serialize_file_identity(active_identity),
        candidate_root=candidate_root,
        candidate_intermediate=candidate_intermediate,
        candidate_root_dir=f"{pki_dir}/authorities/roots/{candidate_root}",
        candidate_intermediate_dir=f"{pki_dir}/authorities/intermediates/{candidate_intermediate}",
        transaction_dir=transaction_dir,
        long_stage=f"{transaction_dir}/rollover-state",
        long_dir=f"{pki_dir}/state/rollovers/{transaction}",
        pointer=f"{pki_dir}/state/active-rollover",
        pointer_identity="absent",
        backup_receipt=backup_receipt,
        receipt_identity=serialize_file_identity(receipt_identity),
        backup_session=f"{pki_dir}/state/rollover/backup-session-{receipt['session']}",
        root_reservation=f"{pki_dir}/state/generation-reservations/{candidate_root}",
        intermediate_reservation=f"{pki_dir}/state/generation-reservations/{candidate_intermediate}",
        trust_snapshot_sha256=trust_snapshot_sha256,
        trust_source=trust_source,
        trust_source_identity=(
            serialize_file_identity(trust_source_identity)
            if trust_source_identity is not None
            else "none"
        ),
        root_mutated="false",
        transaction_tree_manifest_sequence="0",
    )
    values["backup_session_original_identity"] = _object_or_absent(
        values["backup_session"]
    )
    values["backup_session_identity"] = "absent"
    for kind in ("root", "intermediate"):
        for status in ("reserved", "consumed", "abandoned"):
            values[f"{kind}_reservation_{status}_identity"] = "absent"
    for key in ROOT_DB_KEYS:
        for suffix in ("pre", "post"):
            values[f"root_{key}_{suffix}_identity"] = "pending"
        for suffix in ("backup", "rollback", "source"):
            values[f"root_{key}_{suffix}_identity"] = "absent"
        values[f"signing_{key}_pre_identity"] = "none"
        values[f"signing_{key}_partial_identity"] = "none"
        values[f"signing_{key}_was_absent"] = "false"
    for name in _PREPARTIAL_NAMES:
        values[f"{name}_pre_identity"] = "none"
        values[f"{name}_partial_identity"] = "none"
    if frozenset(values) != frozenset(ROLLOVER_PREPARE_DECLARED_FIELDS):
        raise AssertionError("schema-5 preparation field initialization is incomplete")
    return values


def _open_active_issuer(pki_dir: str) -> tuple[OpenedFile, str, str]:
    path = f"{pki_dir}/state/active-issuer"
    try:
        opened = OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), mode=0o600, links=1, max_size=4096),
        )
        data = opened.read(opened.identity.size)
    except FilesystemError:
        _die(f"Active issuer manifest must be current-user-owned, singly linked, and mode 600: {path}")
    match = re.fullmatch(
        rb"root=(g[1-9][0-9]*)\nintermediate=(g[1-9][0-9]*-i[1-9][0-9]*)\n",
        data,
    )
    if match is None:
        opened.close()
        _die(f"Active issuer manifest has invalid content: {path}")
    root, intermediate = (part.decode("ascii") for part in match.groups())
    if not intermediate.startswith(f"{root}-i"):
        opened.close()
        _die("Active issuer manifest selects mismatched generations")
    return opened, root, intermediate


def _open_inventory(pki_dir: str):
    from .inventory import InventoryError, parse_inventory

    path = f"{pki_dir}/inventory/services.yml"
    try:
        opened = OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), forbidden_bits=0o022, links=1),
        )
        data = opened.read(opened.identity.size)
        inventory = parse_inventory(data)
        opened.recheck()
        return opened, inventory
    except InventoryError as error:
        _die(str(error))
    except FilesystemError:
        _die(
            f"Service inventory is missing or unreadable: {path}; "
            "run platform-pki-inventory-install"
        )


def _init_ca_database(directory: str) -> None:
    for relative, data in (
        ("index.txt", b""),
        ("index.txt.attr", b"unique_subject = no\n"),
        ("serial", b"1000\n"),
        ("crlnumber", b"1000\n"),
    ):
        _write_new_file(f"{directory}/{relative}", data, 0o600)


def _stage_directories(preparation: _Preparation, root: str, intermediate: str, *, root_candidate: bool) -> None:
    if root_candidate:
        preparation.checkpoint("candidate-root-stage-pending")
        preparation.checkpoint("candidate-root-directory-pending")
        preparation.values["root_stage_identity"] = serialize_directory_identity(_mkdir(root))
        preparation.checkpoint("candidate-root-directory-done")
        preparation.checkpoint("candidate-root-private-pending")
        preparation.values["root_stage_private_identity"] = serialize_directory_identity(
            _mkdir(f"{root}/private")
        )
        preparation.checkpoint("candidate-root-private-done")
        for name in ("certs", "newcerts", "crl"):
            _mkdir(f"{root}/{name}")
        preparation.checkpoint("candidate-intermediate-directory-pending")
        preparation.values["intermediate_stage_identity"] = serialize_directory_identity(
            _mkdir(intermediate)
        )
        preparation.checkpoint("candidate-intermediate-directory-done")
        preparation.checkpoint("candidate-intermediate-private-pending")
        preparation.values["intermediate_stage_private_identity"] = serialize_directory_identity(
            _mkdir(f"{intermediate}/private")
        )
        preparation.checkpoint("candidate-intermediate-private-done")
        for name in ("certs", "csr", "newcerts", "crl"):
            _mkdir(f"{intermediate}/{name}")
        return
    preparation.checkpoint("sensitive-stage-pending")
    preparation.checkpoint("sensitive-root-stage-pending")
    preparation.values["root_stage_identity"] = serialize_directory_identity(_mkdir(root))
    preparation.checkpoint("sensitive-root-stage-done")
    preparation.checkpoint("sensitive-root-private-pending")
    preparation.values["root_stage_private_identity"] = serialize_directory_identity(
        _mkdir(f"{root}/private")
    )
    preparation.checkpoint("sensitive-root-private-done")
    for name in ("certs", "newcerts", "crl"):
        _mkdir(f"{root}/{name}")
    preparation.checkpoint("sensitive-intermediate-stage-pending")
    preparation.values["intermediate_stage_identity"] = serialize_directory_identity(
        _mkdir(intermediate)
    )
    preparation.checkpoint("sensitive-intermediate-stage-done")
    preparation.checkpoint("sensitive-intermediate-private-pending")
    preparation.values["intermediate_stage_private_identity"] = serialize_directory_identity(
        _mkdir(f"{intermediate}/private")
    )
    preparation.checkpoint("sensitive-intermediate-private-done")
    for name in ("certs", "csr", "newcerts", "crl"):
        _mkdir(f"{intermediate}/{name}")


def _run_generated(
    preparation: _Preparation,
    point: str,
    field_name: str,
    path: str,
    mode: int,
    argv: tuple[str, ...],
    passphrase: OpenedFile | None,
    option: str,
) -> FileIdentity:
    preparation.file_destination(path, field_name, mode, point)
    try:
        _run_with_passphrase(passphrase, argv, option)
    except _ChildFailure:
        preparation.child_failed(point, field_name, path)
    identity = _secure_generated_file(path, mode)
    preparation.values[f"{field_name}_identity"] = serialize_file_identity(identity)
    preparation.checkpoint(f"{point}-done")
    return identity


def _sign_intermediate(
    preparation: _Preparation,
    openssl: str,
    stage_root: str,
    stage_intermediate: str,
    issued: str,
    days: str,
    root_passphrase: OpenedFile | None,
) -> tuple[str, FileIdentity]:
    preparation.values["issued_serial"] = issued
    certificate = f"{stage_intermediate}/certs/intermediate-ca.crt"
    preparation.file_destination(
        certificate, "candidate_intermediate_cert", 0o644, "intermediate-signing"
    )
    signing_paths = {
        **{key: f"{stage_root}/{relative}" for key, relative in _ROOT_DB_RELATIVES.items()},
        "newcert": f"{stage_root}/newcerts/{issued}.pem",
    }
    placeholder_identities: dict[str, FileIdentity] = {}
    for key, path in signing_paths.items():
        current = _actual(path)
        if current is ABSENT:
            current = _write_new_file(path, b"", 0o600)
            preparation.values[f"signing_{key}_was_absent"] = "true"
            placeholder_identities[key] = current
        assert isinstance(current, FileIdentity)
        preparation.values[f"signing_{key}_pre_identity"] = serialize_file_identity(current)
    preparation.checkpoint("intermediate-signing-db-ready")
    argv = (
        openssl,
        "ca",
        "-batch",
        "-config",
        f"{stage_root}/openssl.cnf",
        "-extensions",
        "v3_intermediate_ca",
        "-days",
        days,
        "-notext",
        "-md",
        "sha384",
        "-in",
        f"{stage_intermediate}/csr/intermediate-ca.csr",
        "-out",
        certificate,
    )
    try:
        _run_with_passphrase(root_passphrase, argv, "-passin")
    except _ChildFailure:
        fields: list[str] = ["candidate_intermediate_cert", certificate]
        for key, path in signing_paths.items():
            fields.extend((f"signing_{key}", path))
        preparation.child_failed("intermediate-signing", *fields)
    for key in ("index_old", "index_attr_old", "serial_old", "crlnumber_old", "newcert"):
        placeholder = placeholder_identities.get(key)
        if placeholder is not None and _actual(signing_paths[key]) == placeholder:
            _remove_file(signing_paths[key], placeholder)
    _fsync_private_tree(stage_root)
    identity = _secure_generated_file(certificate, 0o644)
    preparation.values["candidate_intermediate_cert_identity"] = serialize_file_identity(
        identity
    )
    preparation.checkpoint("intermediate-signing-done")
    return issued, identity


def _signing_serial(stage_root: str) -> str:
    serial_path = f"{stage_root}/serial"
    serial = ""
    try:
        with OpenedFile(serial_path, policy=_PRIVATE_FILE) as serial_file:
            serial = serial_file.read(4096).decode("ascii").strip()
    except (FilesystemError, UnicodeDecodeError):
        _die("Root CA serial is invalid")
    if _SERIAL.fullmatch(serial) is None:
        _die("Root CA serial is invalid")
    issued = serial.upper()
    while issued.startswith("00") and len(issued) > 2:
        issued = issued[2:]
    return issued


def _validate_candidates(
    preparation: _Preparation,
    openssl: str,
    root_key: str,
    root_certificate: str,
    intermediate_key: str,
    intermediate_certificate: str,
    root_passphrase: OpenedFile | None,
    intermediate_passphrase: OpenedFile | None,
    stage: str,
    old_root_certificate: str,
    old_intermediate_certificate: str,
    max_service_days: int,
    safety_days: int,
) -> tuple[str, str, str, str]:
    _require_key_match(openssl, root_key, root_certificate, root_passphrase, stage)
    _require_key_match(
        openssl,
        intermediate_key,
        intermediate_certificate,
        intermediate_passphrase,
        stage,
    )
    _require_certificate_profile(openssl, root_certificate, 1, "Candidate root certificate")
    _require_certificate_profile(
        openssl, intermediate_certificate, 0, "Candidate intermediate certificate"
    )
    _verify(
        openssl,
        ("verify", "-check_ss_sig", "-CAfile", root_certificate, root_certificate),
        "Candidate root self-signature is invalid",
    )
    _verify(
        openssl,
        ("verify", "-CAfile", root_certificate, intermediate_certificate),
        "Candidate intermediate chain is invalid",
    )
    child_start, child_end = _certificate_dates(intermediate_certificate, stage)
    _issuer_start, issuer_end = _certificate_dates(root_certificate, stage)
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    if child_start > now + 300:
        _die("Child certificate notBefore is more than five minutes in the future")
    if child_start > now or child_end <= now:
        _die("Child certificate is not currently valid")
    if child_end > issuer_end - safety_days * 86400:
        _die(
            "Child certificate exceeds issuer validity safety margin of "
            f"{safety_days} day(s)"
        )
    if not _checkend(
        openssl,
        intermediate_certificate,
        (max_service_days + safety_days) * 86400,
    ):
        _die(
            "Candidate intermediate validity cannot cover the maximum inventory "
            "service lifetime and safety margin"
        )
    root_fp = _certificate_fingerprint(root_certificate, stage)
    intermediate_fp = _certificate_fingerprint(intermediate_certificate, stage)
    old_root_fp = _certificate_fingerprint(old_root_certificate, stage)
    old_intermediate_fp = _certificate_fingerprint(old_intermediate_certificate, stage)
    root_key_fp = _certificate_public_key_digest(openssl, root_certificate)
    intermediate_key_fp = _certificate_public_key_digest(openssl, intermediate_certificate)
    old_root_key_fp = _certificate_public_key_digest(openssl, old_root_certificate)
    old_intermediate_key_fp = _certificate_public_key_digest(
        openssl, old_intermediate_certificate
    )
    if preparation.preparation_type == "root" and root_fp == old_root_fp:
        _die("Candidate root certificate fingerprint matches the active root")
    if intermediate_fp == old_intermediate_fp:
        _die("Candidate intermediate certificate fingerprint matches the active intermediate")
    if preparation.preparation_type == "root" and root_key_fp == old_root_key_fp:
        _die("Candidate root public key matches the active root")
    if intermediate_key_fp == old_intermediate_key_fp:
        _die("Candidate intermediate public key matches the active intermediate")
    if _certificate_subject(openssl, intermediate_certificate) == _certificate_subject(
        openssl, old_intermediate_certificate
    ):
        _die("Candidate intermediate subject matches the active intermediate")
    if preparation.preparation_type == "root" and _certificate_subject(
        openssl, root_certificate
    ) == _certificate_subject(openssl, old_root_certificate):
        _die("Candidate root subject matches the active root")
    return root_fp, intermediate_fp, old_root_fp, old_intermediate_fp


def _validate_source(opened: OpenedFile, message: str) -> None:
    try:
        opened.recheck()
    except FilesystemError:
        _die(message)


def _finish(
    preparation: _Preparation,
    recheck_authorization_inputs: Callable[[], None],
) -> None:
    from . import ca_rollover_recover as recovery
    from .ca_rollover_recovery import PreparationTerminalOutcome

    assert preparation.journal_identity is not None
    data = serialize_typed_recovery_rewrite(
        preparation.values, pki_dir=preparation.pki_dir
    )
    record = parse_recovery_semantics(data, pki_dir=preparation.pki_dir)
    assert isinstance(record, RolloverPrepareRecoveryRecord)
    journal = recovery._Journal(
        preparation.pki_dir,
        preparation.journal,
        preparation.values,
        preparation.journal_identity,
    )
    write_control = recovery._write_control

    def checked_write_control(path: str, data: bytes) -> FileIdentity:
        preparation.fault(
            "terminal-receipt-publication"
            if "/state/rollover/terminal-" in path
            else "terminal-marker-publication"
        )
        recheck_authorization_inputs()
        return write_control(path, data)

    recovery._write_control = checked_write_control
    try:
        recheck_authorization_inputs()
        recovery._finish_preparation(
            journal,
            record,
            RecoveryAction.RESUME,
            PreparationTerminalOutcome.RESUMED,
            preparation.marker,
            cast(FaultHook, preparation.fault),
            preparation.environment,
        )
    finally:
        recovery._write_control = write_control
    preparation.journal_identity = journal.identity
    preparation.committed = True


def _run_preparation(
    *,
    pki_dir: str,
    preparation_type: str,
    backup_receipt_path: str,
    root_name: str,
    intermediate_name: str,
    organization: str,
    country: str,
    root_days: str,
    intermediate_days: str,
    safety_days: str,
    private_repo: str | None,
    root_passphrase: OpenedFile | None,
    intermediate_passphrase: OpenedFile | None,
    environment: Mapping[str, str],
) -> int:
    openssl = environment.get("PLATFORM_PKI_PREPARE_OPENSSL", "openssl")
    if detect_layout(pki_dir) != "generation":
        _die("Rollover preparation requires a complete generation-aware layout")
    active_manifest_path = f"{pki_dir}/state/active-issuer"
    active, active_root, active_intermediate = _open_active_issuer(pki_dir)
    preparation: _Preparation | None = None
    stack = ExitStack()
    stack.enter_context(active)
    try:
        for path, label in (
            (f"{pki_dir}/authorities/roots/{active_root}", "Root authority generation"),
            (
                f"{pki_dir}/authorities/intermediates/{active_intermediate}",
                "Intermediate authority generation",
            ),
        ):
            try:
                stack.enter_context(OpenedDirectory(path, policy=_PRIVATE_DIRECTORY))
            except FilesystemError:
                _die(f"{label} must be current-user-owned with mode 700: {path}")
        pointer = f"{pki_dir}/state/active-rollover"
        if _actual(pointer) is not ABSENT:
            _die("An active rollover already exists")
        try:
            existing = tuple(os.scandir(f"{pki_dir}/state/rollovers"))
        except OSError:
            _die("Existing rollover state could not be inspected")
        if existing:
            _die("Existing rollover state must be completed or recovered before preparation")

        inventory_file, inventory = _open_inventory(pki_dir)
        stack.enter_context(inventory_file)
        max_service_days = int(environment.get("PLATFORM_PKI_SERVICE_DAYS", "397"), 10)
        _validate_days(str(max_service_days))
        for service in inventory.services:
            if service.days is not None:
                max_service_days = max(max_service_days, int(service.days, 10))

        receipt_file, receipt, archive_file = _read_backup_receipt(backup_receipt_path)
        stack.enter_context(receipt_file)
        stack.enter_context(archive_file)
        if _public_state_digest(pki_dir, "generation") != receipt["state_manifest_sha256"]:
            _die("Current public PKI state differs from the backed-up state manifest")
        if _private_metadata_digest(pki_dir) != receipt["private_metadata_sha256"]:
            _die("Current private metadata differs from the backed-up state")

        trust_source = "none"
        trust_source_file: OpenedFile | None = None
        trust_data = b""
        trust_digest = "none"
        if preparation_type == "root":
            assert private_repo is not None
            try:
                validate_trusted_ancestors(private_repo)
                validate_trusted_ancestors(f"{private_repo}/pki")
            except FilesystemError:
                _die(f"Private repository ancestor is unsafe: {private_repo}")
            trust_source = f"{private_repo}/pki/trust-consumers.yml"
            trust_source_file, trust_data = _open_trust_source(trust_source)
            stack.enter_context(trust_source_file)
            trust_digest = hashlib.sha256(trust_data).hexdigest()

        active_root_dir = f"{pki_dir}/authorities/roots/{active_root}"
        old_root_certificate_path = f"{active_root_dir}/certs/root-ca.crt"
        old_intermediate_certificate_path = (
            f"{pki_dir}/authorities/intermediates/{active_intermediate}/certs/"
            "intermediate-ca.crt"
        )
        old_root_key_path = f"{active_root_dir}/private/root-ca.key"
        old_root_key: OpenedFile | None = None
        try:
            old_root_certificate = stack.enter_context(
                OpenedFile(old_root_certificate_path, policy=_PUBLIC_CERTIFICATE)
            )
            old_intermediate_certificate = stack.enter_context(
                OpenedFile(old_intermediate_certificate_path, policy=_PUBLIC_CERTIFICATE)
            )
            if preparation_type == "intermediate":
                old_root_key = stack.enter_context(
                    OpenedFile(old_root_key_path, policy=_PRIVATE_FILE)
                )
        except FilesystemError:
            _die("Active CA authority source is unsafe")
        _verify(
            openssl,
            (
                "verify",
                "-CAfile",
                old_root_certificate_path,
                old_intermediate_certificate_path,
            ),
            "Active intermediate does not verify against its recorded root",
        )

        root_days_value = int(root_days, 10)
        intermediate_days_value = int(intermediate_days, 10)
        safety_days_value = int(safety_days, 10)
        if preparation_type == "intermediate":
            if not _checkend(
                openssl,
                old_root_certificate_path,
                (intermediate_days_value + safety_days_value) * 86400,
            ):
                _die(
                    "Requested intermediate validity exceeds the active root validity safety margin"
                )
        elif root_days_value < intermediate_days_value + safety_days_value:
            _die(
                "Requested intermediate validity exceeds the candidate root validity safety margin"
            )
        if intermediate_days_value < max_service_days + safety_days_value:
            _die(
                "Requested intermediate validity cannot cover the maximum inventory "
                "service lifetime and safety margin"
            )

        candidate_root = (
            _next_root(pki_dir) if preparation_type == "root" else active_root
        )
        candidate_intermediate = _next_intermediate(pki_dir, candidate_root)
        root_token = candidate_root.upper()
        intermediate_token = candidate_intermediate.upper()
        boundary = r"(?:^|[^A-Z0-9]){}(?:[^A-Z0-9]|$)"
        if preparation_type == "root" and (
            re.search(boundary.format(re.escape(root_token)), root_name.upper()) is None
            or re.search(
                boundary.format(re.escape(intermediate_token)),
                intermediate_name.upper(),
            )
            is None
        ):
            _die("Root and intermediate names must identify their new generation IDs")
        if preparation_type == "intermediate" and re.search(
            boundary.format(re.escape(intermediate_token)), intermediate_name.upper()
        ) is None:
            _die("Intermediate name must identify its new generation ID")
        candidate_root_dir = f"{pki_dir}/authorities/roots/{candidate_root}"
        candidate_intermediate_dir = (
            f"{pki_dir}/authorities/intermediates/{candidate_intermediate}"
        )
        if _actual(candidate_intermediate_dir) is not ABSENT:
            _die("Candidate intermediate destination already exists")
        if preparation_type == "root" and _actual(candidate_root_dir) is not ABSENT:
            _die("Candidate root destination already exists")

        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
        transaction = f"prepare-{preparation_type}-{timestamp}-{os.getpid()}"
        transaction_dir = f"{pki_dir}/state/rollover/{transaction}"
        journal_path = f"{pki_dir}/state/rollover/journal"
        current_journal = _actual(journal_path)
        if current_journal is not ABSENT and not isinstance(current_journal, FileIdentity):
            _die("Existing rollover preparation journal is unsafe")
        values = _initial_values(
            pki_dir=pki_dir,
            preparation_type=preparation_type,
            transaction=transaction,
            active_root=active_root,
            active_intermediate=active_intermediate,
            active_manifest=active_manifest_path,
            active_identity=active.identity,
            candidate_root=candidate_root,
            candidate_intermediate=candidate_intermediate,
            backup_receipt=backup_receipt_path,
            receipt_identity=receipt_file.identity,
            receipt=receipt,
            trust_source=trust_source,
            trust_source_identity=(
                trust_source_file.identity if trust_source_file is not None else None
            ),
            trust_snapshot_sha256=trust_digest,
        )
        preparation = _Preparation(
            pki_dir,
            preparation_type,
            transaction,
            transaction_dir,
            journal_path,
            f"{pki_dir}/state/rollover/recovery-required",
            values,
            environment,
            current_journal if isinstance(current_journal, FileIdentity) else None,
        )
        preparation.write_journal("planned")
        preparation.fault("after-journal")

        preparation.checkpoint("transaction-dir-pending")
        preparation.transaction_identity = _mkdir(transaction_dir)
        values["transaction_identity"] = serialize_directory_identity(
            preparation.transaction_identity
        )
        preparation.checkpoint("transaction-dir-done")
        long_stage = values["long_stage"]
        preparation.checkpoint("long-stage-pending")
        values["long_identity"] = serialize_directory_identity(_mkdir(long_stage))
        preparation.checkpoint("long-stage-created")
        if preparation_type == "root":
            assert trust_source_file is not None
            preparation.copied_file(
                trust_source_file,
                f"{long_stage}/trust-consumers.yml",
                "trust_snapshot",
                0o600,
                "trust-snapshot",
            )
        preparation.checkpoint("long-stage-done")

        backup_stage = f"{transaction_dir}/backup-session.publish"
        backup_stage_identity = _write_new_file(
            backup_stage,
            (
                f"session={receipt['session']}\narchive_sha256={receipt['archive_sha256']}\n"
                f"transaction={transaction}\n"
            ).encode("ascii"),
            0o600,
        )
        values["backup_session_identity"] = serialize_file_object_state(
            backup_stage_identity.state
        )
        reservation_stage: dict[tuple[str, str], tuple[str, FileIdentity]] = {}
        for kind, generation in (
            ("intermediate", candidate_intermediate),
            *(((("root", candidate_root),) if preparation_type == "root" else ())),
        ):
            for status in ("reserved", "consumed", "abandoned"):
                path = f"{transaction_dir}/{kind}-{status}"
                identity = _write_new_file(
                    path,
                    _reservation_bytes(generation, kind, status, transaction),
                    0o600,
                )
                reservation_stage[(kind, status)] = (path, identity)
                values[f"{kind}_reservation_{status}_identity"] = (
                    serialize_file_object_state(identity.state)
                )
        with OpenedDirectory(transaction_dir, policy=_PRIVATE_DIRECTORY) as opened:
            parent, name = _parent(transaction_dir)
            try:
                fsync_tree(opened, parent, name)
            finally:
                parent.close()
        preparation._refresh_transaction_manifest()
        preparation.write_journal("transaction-staged")
        preparation.fault("after-transaction")

        preparation.checkpoint("backup-session-pending")
        published_backup = _publish_file(
            backup_stage,
            values["backup_session"],
            backup_stage_identity,
            ABSENT,
        )
        if published_backup.state != backup_stage_identity.state:
            _die("Published backup preparation session identity is invalid")
        preparation.checkpoint("backup-session-done")
        for kind in (("root",) if preparation_type == "root" else ()):
            preparation.checkpoint("reserve-root-pending")
            path, identity = reservation_stage[(kind, "reserved")]
            _publish_file(path, values["root_reservation"], identity, ABSENT)
            preparation.checkpoint("reserve-root-done")
        preparation.checkpoint("reserve-intermediate-pending")
        path, identity = reservation_stage[("intermediate", "reserved")]
        _publish_file(path, values["intermediate_reservation"], identity, ABSENT)
        preparation.checkpoint("reserve-intermediate-done")
        preparation.write_journal("reserved")
        preparation.fault("after-reservations")

        stage = f"{transaction_dir}/stage"
        values["stage_dir"] = stage
        preparation.checkpoint("stage-dir-pending")
        values["stage_identity"] = serialize_directory_identity(_mkdir(stage))
        preparation.checkpoint("stage-dir-done")
        stage_root = f"{stage}/root"
        stage_intermediate = f"{stage}/intermediate"
        values["root_stage"] = stage_root
        _stage_directories(
            preparation,
            stage_root,
            stage_intermediate,
            root_candidate=preparation_type == "root",
        )

        root_backup = f"{stage}/root-backup"
        db_paths: dict[str, str] = {}
        db_pre_snapshot: dict[str, str] = {}
        root_db_snapshot: _RootDatabaseSnapshot | None = None
        if preparation_type == "intermediate":
            assert old_root_key is not None
            _mkdir(root_backup)
            root_db_snapshot = _snapshot_root_database(
                preparation, active_root_dir, stack
            )
            db_paths = {
                key: entry.path for key, entry in root_db_snapshot.entries.items()
            }
            db_pre_snapshot = {
                key: entry.identity for key, entry in root_db_snapshot.entries.items()
            }
            for key, identity in db_pre_snapshot.items():
                values[f"root_{key}_pre_identity"] = identity
            values["root_stage_key_identity"] = serialize_file_identity(
                preparation.copied_file(
                    old_root_key,
                    f"{stage_root}/private/root-ca.key",
                    "root_stage_key",
                    0o600,
                    "copied-root-key",
                )
            )
            preparation.copied_file(
                old_root_certificate,
                f"{stage_root}/certs/root-ca.crt",
                "root_stage_cert",
                0o644,
                "copied-root-cert",
            )
            for key in ("index", "index_attr", "serial", "crlnumber"):
                relative = _ROOT_DB_RELATIVES[key]
                source = root_db_snapshot.entries[key].opened
                if source is None:
                    _die(
                        f"Required file is missing: "
                        f"{root_db_snapshot.entries[key].path}"
                    )
                preparation.copied_file(
                    source,
                    f"{stage_root}/{relative}",
                    f"root_stage_{key}",
                    0o600,
                    f"copied-root-{key}",
                )
                preparation.copied_file(
                    source,
                    f"{root_backup}/{relative}",
                    f"root_stage_{key}_backup",
                    0o600,
                    f"backup-root-{key}",
                )
            for key in ("index_old", "index_attr_old", "serial_old", "crlnumber_old"):
                relative = _ROOT_DB_RELATIVES[key]
                source = root_db_snapshot.entries[key].opened
                if source is None:
                    continue
                preparation.copied_file(
                    source,
                    f"{root_backup}/{relative}",
                    f"root_stage_{key}_backup",
                    0o600,
                    f"backup-root-{key}",
                )
            _write_new_file(
                f"{stage_root}/openssl.cnf",
                _root_config(country, organization, intermediate_name, stage_root),
                0o600,
            )
            preparation.checkpoint("sensitive-stage-done")
            root_key_path = f"{stage_root}/private/root-ca.key"
            root_certificate_path = f"{stage_root}/certs/root-ca.crt"
        else:
            _init_ca_database(stage_root)
            _write_new_file(
                f"{stage_root}/openssl.cnf",
                _root_config(country, organization, root_name, stage_root),
                0o600,
            )
            preparation.checkpoint("candidate-root-stage-done")
            root_key_path = f"{stage_root}/private/root-ca.key"
            root_certificate_path = f"{stage_root}/certs/root-ca.crt"
            _run_generated(
                preparation,
                "root-key",
                "candidate_root_key",
                root_key_path,
                0o600,
                (
                    openssl,
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:secp384r1",
                    "-aes-256-cbc",
                    "-out",
                    root_key_path,
                ),
                root_passphrase,
                "-pass",
            )
            _run_generated(
                preparation,
                "root-certificate",
                "candidate_root_cert",
                root_certificate_path,
                0o644,
                (
                    openssl,
                    "req",
                    "-config",
                    f"{stage_root}/openssl.cnf",
                    "-key",
                    root_key_path,
                    "-new",
                    "-x509",
                    "-days",
                    root_days,
                    "-sha384",
                    "-extensions",
                    "v3_root_ca",
                    "-out",
                    root_certificate_path,
                ),
                root_passphrase,
                "-passin",
            )

        preparation.checkpoint("intermediate-stage-config-pending")
        _init_ca_database(stage_intermediate)
        _write_new_file(
            f"{stage_intermediate}/openssl.cnf",
            _intermediate_config(
                country,
                organization,
                intermediate_name,
                candidate_intermediate_dir,
            ),
            0o600,
        )
        preparation.checkpoint("intermediate-stage-config-done")
        intermediate_key_path = f"{stage_intermediate}/private/intermediate-ca.key"
        intermediate_csr_path = f"{stage_intermediate}/csr/intermediate-ca.csr"
        intermediate_certificate_path = (
            f"{stage_intermediate}/certs/intermediate-ca.crt"
        )
        _run_generated(
            preparation,
            "intermediate-key",
            "candidate_intermediate_key",
            intermediate_key_path,
            0o600,
            (
                openssl,
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:secp384r1",
                "-aes-256-cbc",
                "-out",
                intermediate_key_path,
            ),
            intermediate_passphrase,
            "-pass",
        )
        _run_generated(
            preparation,
            "intermediate-csr",
            "candidate_intermediate_csr",
            intermediate_csr_path,
            0o600,
            (
                openssl,
                "req",
                "-config",
                f"{stage_intermediate}/openssl.cnf",
                "-key",
                intermediate_key_path,
                "-new",
                "-sha384",
                "-out",
                intermediate_csr_path,
            ),
            intermediate_passphrase,
            "-passin",
        )
        issued = (
            root_db_snapshot.issued_serial
            if root_db_snapshot is not None
            else _signing_serial(stage_root)
        )
        issued, _intermediate_identity = _sign_intermediate(
            preparation,
            openssl,
            stage_root,
            stage_intermediate,
            issued,
            intermediate_days,
            root_passphrase,
        )
        chain_path = f"{stage_intermediate}/certs/ca-chain.crt"
        chain_pre = preparation.file_destination(
            chain_path, "candidate_chain", 0o644, "chain"
        )
        intermediate_data = b""
        root_data = b""
        try:
            with OpenedFile(
                intermediate_certificate_path, policy=_PUBLIC_CERTIFICATE
            ) as intermediate_certificate_file:
                intermediate_data = intermediate_certificate_file.read(
                    _MAX_CERTIFICATE
                )
            with OpenedFile(
                root_certificate_path, policy=_PUBLIC_CERTIFICATE
            ) as root_certificate_file:
                root_data = root_certificate_file.read(_MAX_CERTIFICATE)
        except FilesystemError:
            preparation.child_failed("chain", "candidate_chain", chain_path)
        chain_identity = _replace_file_bytes(
            chain_path, chain_pre, intermediate_data + root_data, 0o644
        )
        values["candidate_chain_identity"] = serialize_file_identity(chain_identity)
        preparation.checkpoint("chain-done")
        if preparation_type == "root":
            preparation.checkpoint("candidate-root-config-pending")
            config_path = f"{stage_root}/openssl.cnf"
            config_identity = _identity(config_path)
            _replace_file_bytes(
                config_path,
                config_identity,
                _root_config(country, organization, root_name, candidate_root_dir),
                0o600,
            )
            preparation.checkpoint("candidate-root-config-done")

        root_fp, intermediate_fp, old_root_fp, old_intermediate_fp = (
            _validate_candidates(
                preparation,
                openssl,
                root_key_path,
                root_certificate_path,
                intermediate_key_path,
                intermediate_certificate_path,
                root_passphrase,
                intermediate_passphrase,
                stage,
                old_root_certificate_path,
                old_intermediate_certificate_path,
                max_service_days,
                safety_days_value,
            )
        )
        if preparation_type == "root":
            candidate_root_data = b""
            with OpenedFile(
                root_certificate_path, policy=_PUBLIC_CERTIFICATE
            ) as candidate_root_certificate:
                candidate_root_data = candidate_root_certificate.read(
                    _MAX_CERTIFICATE
                )
            trust_bundle_digest = hashlib.sha256(
                old_root_certificate.read(_MAX_CERTIFICATE) + candidate_root_data
            ).hexdigest()
        else:
            trust_bundle_digest = "none"
        values.update(
            root_fingerprint=root_fp,
            intermediate_fingerprint=intermediate_fp,
            root_expiry=_certificate_expiry(root_certificate_path, stage),
            intermediate_expiry=_certificate_expiry(
                intermediate_certificate_path, stage
            ),
            trust_bundle_sha256=trust_bundle_digest,
        )

        db_backups: dict[str, str] = {}
        if preparation_type == "intermediate":
            db_backups = {
                **{
                    key: f"{root_backup}/{relative}"
                    for key, relative in _ROOT_DB_RELATIVES.items()
                },
                "newcert": "none",
            }
            for key in ROOT_DB_KEYS:
                relative = (
                    f"newcerts/{issued}.pem"
                    if key == "newcert"
                    else _ROOT_DB_RELATIVES[key]
                )
                source_path = f"{stage_root}/{relative}"
                pre = db_pre_snapshot[key]
                post = _full_or_absent(source_path)
                if post == "absent":
                    post = pre
                backup = (
                    "absent"
                    if db_backups[key] == "none"
                    else _full_or_absent(db_backups[key])
                )
                values[f"root_{key}_post_identity"] = post
                values[f"root_{key}_backup_identity"] = backup
                values[f"root_{key}_rollback_identity"] = backup
                values[f"root_{key}_source_identity"] = _full_or_absent(source_path)
            values["root_mutated"] = "true"

        preparation.checkpoint("evidence-stage-pending")
        if preparation_type == "root":
            path = f"{long_stage}/candidate-root-tree.manifest"
            manifest_identity, manifest_digest = _write_manifest(path, stage_root)
            values.update(
                candidate_root_tree_manifest=path,
                candidate_root_tree_manifest_identity=serialize_file_identity(
                    manifest_identity
                ),
                candidate_root_tree_manifest_sha256=manifest_digest,
            )
        else:
            path = f"{long_stage}/root-signing-stage-tree.manifest"
            manifest_identity, manifest_digest = _write_manifest(path, stage_root)
            values.update(
                root_stage_tree_manifest=path,
                root_stage_tree_manifest_identity=serialize_file_identity(
                    manifest_identity
                ),
                root_stage_tree_manifest_sha256=manifest_digest,
            )
        path = f"{long_stage}/candidate-intermediate-tree.manifest"
        manifest_identity, manifest_digest = _write_manifest(path, stage_intermediate)
        values.update(
            candidate_intermediate_tree_manifest=path,
            candidate_intermediate_tree_manifest_identity=serialize_file_identity(
                manifest_identity
            ),
            candidate_intermediate_tree_manifest_sha256=manifest_digest,
        )
        stage_manifest = f"{transaction_dir}/stage-tree.manifest"
        stage_manifest_identity, stage_manifest_digest = _write_manifest(
            stage_manifest, stage
        )
        values.update(
            stage_tree_manifest=stage_manifest,
            stage_tree_manifest_identity=serialize_file_identity(stage_manifest_identity),
            stage_tree_manifest_sha256=stage_manifest_digest,
        )
        created_at = datetime.datetime.now(datetime.UTC).replace(
            microsecond=0
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        long_manifest_data = (
            "schema=1\n"
            f"transaction={transaction}\n"
            f"type={preparation_type}\n"
            "phase=prepared\n"
            f"created_at={created_at}\n"
            f"old_root={active_root}\n"
            f"old_intermediate={active_intermediate}\n"
            f"candidate_root={candidate_root}\n"
            f"candidate_intermediate={candidate_intermediate}\n"
            f"old_root_fingerprint={old_root_fp}\n"
            f"old_intermediate_fingerprint={old_intermediate_fp}\n"
            f"candidate_root_fingerprint={root_fp}\n"
            f"candidate_intermediate_fingerprint={intermediate_fp}\n"
            f"candidate_root_expiry={values['root_expiry']}\n"
            f"candidate_intermediate_expiry={values['intermediate_expiry']}\n"
            f"trust_bundle_sha256={trust_bundle_digest}\n"
            f"trust_snapshot_sha256={trust_digest}\n"
            "candidate_root_tree_sha256="
            f"{values['candidate_root_tree_manifest_sha256']}\n"
            "candidate_intermediate_tree_sha256="
            f"{values['candidate_intermediate_tree_manifest_sha256']}\n"
            f"backup_state_sha256={receipt['state_manifest_sha256']}\n"
        ).encode("ascii")
        long_manifest_path = f"{long_stage}/manifest"
        long_manifest_identity = _write_new_file(
            long_manifest_path, long_manifest_data, 0o600
        )
        values["long_manifest_identity"] = serialize_file_identity(
            long_manifest_identity
        )
        values["long_manifest_sha256"] = hashlib.sha256(long_manifest_data).hexdigest()
        if preparation_type == "root":
            values["trust_snapshot_identity"] = serialize_file_identity(
                _identity(f"{long_stage}/trust-consumers.yml")
            )
        long_tree_path = f"{long_stage}/tree.manifest"
        long_tree_identity, long_tree_digest = _write_manifest(
            long_tree_path, long_stage, "tree.manifest"
        )
        values.update(
            long_tree_manifest=long_tree_path,
            long_tree_manifest_identity=serialize_file_identity(long_tree_identity),
            long_tree_manifest_sha256=long_tree_digest,
        )
        pointer_stage = f"{transaction_dir}/active-rollover.publish"
        pointer_stage_identity = _write_new_file(
            pointer_stage,
            (
                f"transaction={transaction}\n"
                f"tree_manifest_sha256={long_tree_digest}\n"
            ).encode("ascii"),
            0o600,
        )
        values["pointer_identity"] = serialize_file_object_state(
            pointer_stage_identity.state
        )
        preparation.checkpoint("evidence-stage-done")

        if preparation_type == "root":
            values["candidate_root_identity"] = serialize_directory_identity(
                _directory_identity(stage_root)
            )
            values["candidate_root_key_identity"] = serialize_file_identity(
                _identity(root_key_path)
            )
            values["candidate_root_cert_identity"] = serialize_file_identity(
                _identity(root_certificate_path)
            )
        else:
            assert old_root_key is not None
            values["candidate_root_identity"] = serialize_directory_identity(
                _directory_identity(active_root_dir)
            )
            values["candidate_root_key_identity"] = serialize_file_identity(
                old_root_key.identity
            )
            values["candidate_root_cert_identity"] = serialize_file_identity(
                old_root_certificate.identity
            )
        values["candidate_root_cert_sha256"] = _sha256_file(root_certificate_path)
        values["candidate_intermediate_identity"] = serialize_directory_identity(
            _directory_identity(stage_intermediate)
        )
        values["candidate_intermediate_key_identity"] = serialize_file_identity(
            _identity(intermediate_key_path)
        )
        values["candidate_intermediate_csr_identity"] = serialize_file_identity(
            _identity(intermediate_csr_path)
        )
        values["candidate_intermediate_cert_identity"] = serialize_file_identity(
            _identity(intermediate_certificate_path)
        )
        values["candidate_intermediate_cert_sha256"] = _sha256_file(
            intermediate_certificate_path
        )
        values["candidate_chain_identity"] = serialize_file_identity(
            _identity(chain_path)
        )
        values["candidate_chain_sha256"] = _sha256_file(chain_path)
        values["long_identity"] = serialize_directory_identity(
            _directory_identity(long_stage)
        )
        preparation.write_journal("staged")
        preparation.fault("after-staged")

        source_rechecks = [
            (active, "Active issuer changed during rollover preparation"),
            (inventory_file, "Service inventory changed during rollover preparation"),
            (receipt_file, "Backup receipt changed during rollover preparation"),
            (archive_file, "Backup archive changed during rollover preparation"),
            (old_root_certificate, "Active root certificate changed during rollover preparation"),
            (old_intermediate_certificate, "Active intermediate certificate changed during rollover preparation"),
        ]
        if old_root_key is not None:
            source_rechecks.append(
                (old_root_key, "Active root key changed during rollover preparation")
            )
        for opened, message in source_rechecks:
            _validate_source(opened, message)
        if trust_source_file is not None:
            _validate_source(
                trust_source_file,
                "Trust consumer source changed during rollover preparation",
            )
        for passphrase, message in (
            (root_passphrase, "Root passphrase file changed during rollover preparation"),
            (
                intermediate_passphrase,
                "Intermediate passphrase file changed during rollover preparation",
            ),
        ):
            if passphrase is not None:
                _validate_source(passphrase, message)

        def recheck_authorization_inputs() -> None:
            for opened, message in source_rechecks:
                _validate_source(opened, message)
            if trust_source_file is not None:
                _validate_source(
                    trust_source_file,
                    "Trust consumer source changed during rollover preparation",
                )
            if root_db_snapshot is not None:
                root_db_snapshot.recheck()
            for passphrase, message in (
                (
                    root_passphrase,
                    "Root passphrase file changed during rollover preparation",
                ),
                (
                    intermediate_passphrase,
                    "Intermediate passphrase file changed during rollover preparation",
                ),
            ):
                if passphrase is not None:
                    _validate_source(passphrase, message)

        if preparation_type == "root":
            _validate_manifested_tree(
                stage_root,
                values["candidate_root_tree_manifest"],
                values["candidate_root_tree_manifest_identity"],
                values["candidate_root_tree_manifest_sha256"],
            )
            preparation.checkpoint("publish-root-pending")
            recheck_authorization_inputs()
            _publish_tree(
                stage_root,
                candidate_root_dir,
                _directory_identity(stage_root),
            )
            preparation.checkpoint("publish-root-done")
            preparation.fault("after-root-candidate")
        _validate_manifested_tree(
            stage_intermediate,
            values["candidate_intermediate_tree_manifest"],
            values["candidate_intermediate_tree_manifest_identity"],
            values["candidate_intermediate_tree_manifest_sha256"],
        )
        preparation.checkpoint("publish-intermediate-pending")
        recheck_authorization_inputs()
        _publish_tree(
            stage_intermediate,
            candidate_intermediate_dir,
            _directory_identity(stage_intermediate),
        )
        preparation.checkpoint("publish-intermediate-done")
        preparation.fault("after-intermediate-candidate")

        if preparation_type == "intermediate":
            _validate_manifested_tree(
                stage_root,
                values["root_stage_tree_manifest"],
                values["root_stage_tree_manifest_identity"],
                values["root_stage_tree_manifest_sha256"],
            )
            for key in ROOT_DB_KEYS:
                relative = (
                    f"newcerts/{issued}.pem"
                    if key == "newcert"
                    else _ROOT_DB_RELATIVES[key]
                )
                source = f"{stage_root}/{relative}"
                source_actual = _actual(source)
                if source_actual is ABSENT:
                    continue
                assert isinstance(source_actual, FileIdentity)
                preparation.checkpoint(f"publish-root-db-{key}-pending")
                source_actual = _actual(source)
                if not isinstance(source_actual, FileIdentity) or serialize_file_identity(
                    source_actual
                ) != values[f"root_{key}_source_identity"]:
                    _die(f"Staged root {key} publication source identity changed")
                destination_actual = _actual(db_paths[key])
                expected_text = values[f"root_{key}_pre_identity"]
                if expected_text == "absent":
                    if destination_actual is not ABSENT:
                        _die(f"Root {key} identity changed before publication")
                elif not isinstance(destination_actual, FileIdentity) or serialize_file_identity(
                    destination_actual
                ) != expected_text:
                    _die(f"Root {key} identity changed before publication")
                recheck_authorization_inputs()
                published = _publish_file(
                    source, db_paths[key], source_actual, destination_actual
                )
                values[f"root_{key}_post_identity"] = serialize_file_identity(published)
                assert root_db_snapshot is not None
                snapshot_entry = root_db_snapshot.entries[key]
                snapshot_entry.current_identity = values[f"root_{key}_post_identity"]
                preparation.checkpoint(f"publish-root-db-{key}-done")
            preparation.fault("after-root-db")

        if preparation_type == "root":
            preparation.checkpoint("consume-root-pending")
            source, source_identity = reservation_stage[("root", "consumed")]
            destination = _identity(values["root_reservation"])
            _publish_file(
                source, values["root_reservation"], source_identity, destination
            )
            preparation.checkpoint("consume-root-done")
        preparation.checkpoint("consume-intermediate-pending")
        source, source_identity = reservation_stage[("intermediate", "consumed")]
        destination = _identity(values["intermediate_reservation"])
        _publish_file(
            source, values["intermediate_reservation"], source_identity, destination
        )
        preparation.checkpoint("consume-intermediate-done")
        preparation.fault("after-consumed")

        if preparation_type == "intermediate":
            preparation.checkpoint("cleanup-root-stage-pending")
            parent, name = _parent(stage_root)
            manifest = OpenedFile(values["root_stage_tree_manifest"], policy=_PRIVATE_FILE)
            try:
                remove_manifested_tree(
                    parent,
                    name,
                    _directory_identity(stage_root),
                    manifest,
                    values["root_stage_tree_manifest_identity"],
                    values["root_stage_tree_manifest_sha256"],
                )
            except (FilesystemError, PublicationError):
                _die("Cannot remove sensitive root signing stage")
            finally:
                manifest.close()
                parent.close()
            preparation.fault("cleanup-root-stage-removed")
            preparation.checkpoint("cleanup-root-stage-done")

        _validate_manifested_tree(
            long_stage,
            values["long_tree_manifest"],
            values["long_tree_manifest_identity"],
            values["long_tree_manifest_sha256"],
            excluded="tree.manifest",
        )
        preparation.checkpoint("publish-state-pending")
        _require_full_or_absent(values["long_dir"], "absent", "Rollover state")
        _validate_manifested_tree(
            long_stage,
            values["long_tree_manifest"],
            values["long_tree_manifest_identity"],
            values["long_tree_manifest_sha256"],
            excluded="tree.manifest",
        )
        recheck_authorization_inputs()
        _publish_tree(long_stage, values["long_dir"], _directory_identity(long_stage))
        preparation.checkpoint("publish-state-done")
        preparation.fault("after-state")
        preparation.checkpoint("publish-pointer-pending")
        _require_full_or_absent(pointer, "absent", "Active rollover pointer")
        if _object_or_absent(pointer_stage) != values["pointer_identity"]:
            _die("Staged active rollover pointer identity changed before publication")
        recheck_authorization_inputs()
        _publish_file(pointer_stage, pointer, pointer_stage_identity, ABSENT)
        preparation.checkpoint("publish-pointer-done")
        preparation.fault("after-pointer")
        preparation.fault("terminal-publication-pending")
        recheck_authorization_inputs()
        _finish(preparation, recheck_authorization_inputs)
        print(
            f"[OK] Prepared {preparation_type} rollover transaction {transaction} "
            f"with candidate {candidate_root}/{candidate_intermediate}",
            flush=True,
        )
        return 0
    finally:
        try:
            if preparation is not None and not preparation.committed:
                if preparation.values.get("committed") == "true":
                    preparation.committed = True
                else:
                    preparation.publish_marker()
        finally:
            stack.close()


def prepare_ca_rollover(parsed: ParseResult) -> int:
    """Prepare one root or intermediate candidate through Python dispatch."""

    environment = dict(os.environ)
    preparation_type = str(parsed["--type"])
    if preparation_type not in {"root", "intermediate"}:
        _die("Candidate type must not be empty")
    if preparation_type == "intermediate" and any(
        option in parsed.provided
        for option in ("--root-name", "--root-days", "--private-repo")
    ):
        _die(
            "--root-name, --root-days, and --private-repo are forbidden for "
            "intermediate preparation"
        )
    root_name = str(parsed.values.get("--root-name") or "")
    if preparation_type == "root" and not root_name:
        _die("--root-name is required for root preparation")
    intermediate_name = str(parsed["--intermediate-name"])
    organization = str(parsed["--org"])
    country = str(parsed["--country"])
    for value in (intermediate_name, organization, country):
        _validate_config_value("Rollover certificate field", value)
    if preparation_type == "root":
        _validate_config_value("Rollover root common name", root_name)
    root_days = _validate_days(
        str(
            parsed.values.get("--root-days")
            or environment.get("PLATFORM_PKI_ROOT_DAYS")
            or "3650"
        )
    )
    intermediate_days = _validate_days(
        str(
            parsed.values.get("--intermediate-days")
            or environment.get("PLATFORM_PKI_INTERMEDIATE_DAYS")
            or "1825"
        )
    )
    safety_days = _validate_days(str(parsed["--issuer-safety-days"]))
    paths = resolve_paths(parsed.values, environment)
    _validate_config_value("PKI directory", paths.pki_dir)
    try:
        paths.pki_dir.encode("ascii")
    except UnicodeEncodeError:
        _die("PKI directory must contain only ASCII characters for recovery records")
    home = environment.get("HOME")
    if home is None:
        _die("HOME is required")
    try:
        cwd = os.getcwd()
    except OSError:
        _die("Current directory could not be resolved")
    receipt_input = expand_home(str(parsed["--backup-receipt"]), home=home)
    receipt_path = absolutize_path(receipt_input, physical_cwd=cwd)
    private_repo: str | None = None
    if preparation_type == "root":
        private_input = expand_home(
            str(parsed.values.get("--private-repo") or "../platform-private"),
            home=home,
        )
        private_repo = absolutize_path(private_input, physical_cwd=cwd)
    for label, value in (
        ("Backup receipt", receipt_path),
        ("Private repository", private_repo),
    ):
        if value is None:
            continue
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            _die(f"{label} path must contain only ASCII characters for recovery records")
    root_passphrase_path = parsed.values.get("--root-pass-file")
    intermediate_passphrase_path = parsed.values.get("--intermediate-pass-file")
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    root_passphrase = (
        _open_passphrase(
            expand_home(str(root_passphrase_path), home=home)
        )
        if root_passphrase_path is not None
        else None
    )
    intermediate_passphrase = (
        _open_passphrase(
            expand_home(str(intermediate_passphrase_path), home=home)
        )
        if intermediate_passphrase_path is not None
        else None
    )
    require_program(environment.get("PLATFORM_PKI_PREPARE_OPENSSL", "openssl"), environment)
    previous_umask = os.umask(0o077)
    previous_handlers: dict[signal.Signals, Any] = {}

    def handled_signal(signum: int, _frame: object) -> NoReturn:
        raise _SignalExit(128 + signum)

    for process_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[process_signal] = signal.signal(process_signal, handled_signal)
    try:
        try:
            with acquire_operational_locks(paths.pki_dir, "export"):
                require_no_unresolved_state(paths.pki_dir)
                return _run_preparation(
                    pki_dir=paths.pki_dir,
                    preparation_type=preparation_type,
                    backup_receipt_path=receipt_path,
                    root_name=root_name,
                    intermediate_name=intermediate_name,
                    organization=organization,
                    country=country,
                    root_days=root_days,
                    intermediate_days=intermediate_days,
                    safety_days=safety_days,
                    private_repo=private_repo,
                    root_passphrase=root_passphrase,
                    intermediate_passphrase=intermediate_passphrase,
                    environment=environment,
                )
        except _ChildFailure as error:
            return error.status
        except _SignalExit as error:
            return error.status
    finally:
        os.umask(previous_umask)
        if root_passphrase is not None:
            root_passphrase.close()
        if intermediate_passphrase is not None:
            intermediate_passphrase.close()
        for process_signal, handler in previous_handlers.items():
            signal.signal(process_signal, handler)
