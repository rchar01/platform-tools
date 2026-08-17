"""Create one protected PKI archive and its canonical receipt."""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping
from typing import NoReturn

from .errors import ApplicationError, shell_status
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_from_stat,
)
from .operational import (
    acquire_operational_locks,
    detect_layout,
    load_active_issuer,
    prepare_control_state,
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
    run_external,
)
from .parser import ParseResult
from .paths import absolutize_path, expand_home
from .publication import (
    PublicationAmbiguousError,
    PublicationDestinationExistsError,
    PublicationError,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    stage_file_bytes,
)
from .records import RecordSpec


BACKUP_RECEIPT_SPEC = RecordSpec(
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
    ),
    schema="2",
)

_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_PRIVATE_FILE = FilePolicy(owner=os.geteuid(), mode=0o600, links=1)
_TIMESTAMP = re.compile(r"[0-9]{8}-[0-9]{6}", re.ASCII)
_READ_CHUNK = 64 * 1024
_STAGE_ATTEMPTS = 16


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _warn(message: str) -> None:
    print(f"[WARN] {message}", file=sys.stderr, flush=True)


def _ok(message: str) -> None:
    print(f"[OK] {message}", flush=True)


def _run_inherited(argv: tuple[str, ...], environment: Mapping[str, str]) -> int:
    """Run with inherited terminal streams, as required by ``age -p``."""

    try:
        result = subprocess.run(argv, env=environment, shell=False, check=False)
    except OSError:
        _die(f"{argv[0]} is required")
    return shell_status(result.returncode)


def _hash_descriptor(opened: OpenedFile) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        try:
            chunk = os.pread(opened.fileno(), _READ_CHUNK, offset)
        except OSError:
            _die("Backup archive could not be hashed safely")
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    try:
        opened.recheck()
    except FilesystemError:
        _die("Backup archive identity changed while hashing")
    return digest.hexdigest()


def _hash_path(path: bytes) -> str:
    descriptor = -1
    try:
        before = identity_from_stat(os.stat(path, follow_symlinks=False))
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = identity_from_stat(os.fstat(descriptor))
        digest = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(descriptor, _READ_CHUNK, offset)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        after = identity_from_stat(os.stat(path, follow_symlinks=False))
        final = identity_from_stat(os.fstat(descriptor))
        if before != opened or opened != after or after != final:
            _die(f"Cannot hash public PKI state: {os.fsdecode(path)}")
        return digest.hexdigest()
    except ApplicationError:
        raise
    except (OSError, FilesystemError):
        _die(f"Cannot hash public PKI state: {os.fsdecode(path)}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _walk_objects(root: bytes) -> Iterable[tuple[bytes, os.stat_result]]:
    def failed(_error: OSError) -> NoReturn:
        _die("PKI state could not be enumerated safely")

    for directory, names, files in os.walk(
        root, topdown=True, followlinks=False, onerror=failed
    ):
        for name in (*names, *files):
            path = os.path.join(directory, name)
            try:
                result = os.stat(path, follow_symlinks=False)
            except OSError:
                _die("PKI state could not be enumerated safely")
            yield path, result


def _public_state_digest(
    pki_dir: str, layout: str, *, excluded_root: str | None = None
) -> str:
    root = os.fsencode(pki_dir)
    excluded = os.fsencode(excluded_root) if excluded_root is not None else None
    relative_roots = (
        (b"inventory", b"root-ca", b"intermediate-ca", b"services", b"export")
        if layout == "legacy"
        else (
            b"inventory",
            b"authorities",
            b"state/active-issuer",
            b"services",
            b"export",
        )
    )
    lines: list[bytes] = []
    for relative_root in relative_roots:
        path = os.path.join(root, relative_root)
        try:
            result = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _die("PKI public state could not be inspected safely")
        if stat.S_ISREG(result.st_mode):
            lines.append(f"{_hash_path(path)}  ".encode() + relative_root + b"\n")
            continue
        if not stat.S_ISDIR(result.st_mode):
            continue
        for child, child_result in _walk_objects(path):
            if excluded is not None and (
                child == excluded or child.startswith(excluded + b"/")
            ):
                continue
            if not stat.S_ISREG(child_result.st_mode):
                continue
            relative = child[len(root) + 1 :]
            components = relative.split(b"/")
            if (
                b"private" in components[:-1]
                or b"backups" in components[:-1]
                or relative.endswith(b".key")
            ):
                continue
            lines.append(f"{_hash_path(child)}  ".encode() + relative + b"\n")
    return hashlib.sha256(b"".join(sorted(lines))).hexdigest()


def _stat_timestamp(nanoseconds: int) -> str:
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    local = time.localtime(seconds)
    return (
        f"{time.strftime('%Y-%m-%d %H:%M:%S', local)}."
        f"{remainder:09d} {time.strftime('%z', local)}"
    )


def _private_metadata_digest(
    pki_dir: str, *, excluded_root: str | None = None
) -> str:
    root = os.fsencode(pki_dir)
    excluded = os.fsencode(excluded_root) if excluded_root is not None else None
    lines: list[bytes] = []
    for path, result in _walk_objects(root):
        if excluded is not None and (
            path == excluded or path.startswith(excluded + b"/")
        ):
            continue
        relative = path[len(root) + 1 :]
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
        if stat.S_ISDIR(result.st_mode):
            continue
        if not stat.S_ISREG(result.st_mode) or stat.S_ISLNK(result.st_mode):
            _die(f"Private state path is unsafe: {os.fsdecode(path)}")
        kind = "regular empty file" if result.st_size == 0 else "regular file"
        identity = (
            f"{result.st_dev}:{result.st_ino}:{result.st_uid}:"
            f"{stat.S_IMODE(result.st_mode):o}:{result.st_nlink}:{result.st_size}:"
            f"{_stat_timestamp(result.st_mtime_ns)}:"
            f"{_stat_timestamp(result.st_ctime_ns)}:{kind}"
        ).encode("ascii")
        lines.append(relative + b"|" + identity + b"\n")
    return hashlib.sha256(b"".join(sorted(lines))).hexdigest()


def _receipt_bytes(
    archive_path: str,
    archive: FileIdentity,
    archive_digest: str,
    layout: str,
    state_digest: str,
    private_metadata_digest: str,
    *,
    session: str,
    created_at: str,
    created_epoch: int,
) -> bytes:
    return BACKUP_RECEIPT_SPEC.serialize(
        {
            "schema": "2",
            "layout": layout,
            "session": session,
            "backup_path": archive_path,
            "backup_device": str(archive.dev),
            "backup_inode": str(archive.ino),
            "backup_size": str(archive.size),
            "backup_mode": f"{archive.permissions:o}",
            "backup_owner": str(archive.uid),
            "archive_sha256": archive_digest,
            "created_at": created_at,
            "created_epoch": str(created_epoch),
            "state_manifest_sha256": state_digest,
            "private_metadata_sha256": private_metadata_digest,
        }
    )


def _timestamp(environment: Mapping[str, str]) -> str:
    result = run_external(("date", "-u", "+%Y%m%d-%H%M%S"), environment)
    if result.status or result.stderr:
        _die("Cannot create PKI backup timestamp")
    try:
        value = result.stdout.removesuffix(b"\n").decode("ascii")
    except UnicodeDecodeError:
        _die("Cannot create PKI backup timestamp")
    if _TIMESTAMP.fullmatch(value) is None:
        _die("Cannot create PKI backup timestamp")
    return value


def _candidate_name(parent: OpenedDirectory, timestamp: str, extension: str) -> str:
    number = 0
    while True:
        suffix = "" if number == 0 else f"-{number:02d}"
        name = f"platform-pki-{timestamp}{suffix}{extension}"
        if parent.identity_at(name) is ABSENT:
            return name
        number += 1


def _reserve_stage(parent: OpenedDirectory) -> tuple[str, OpenedDirectory]:
    for _attempt in range(_STAGE_ATTEMPTS):
        name = f".platform-pki-backup.{secrets.token_hex(8)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            return name, parent.open_directory(name, policy=_PRIVATE_DIRECTORY)
        except FileExistsError:
            continue
        except (OSError, FilesystemError):
            break
    _die("Cannot create PKI backup staging directory")


def _safe_record_path(path: str) -> None:
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError:
        _die("Backup path cannot be represented in a canonical receipt")
    if not encoded or any(byte < 0x20 or byte > 0x7E for byte in encoded):
        _die("Backup path cannot be represented in a canonical receipt")


def _prepare_backup_directory(path: str) -> str:
    missing: list[str] = []
    existing = path
    while not os.path.lexists(existing):
        parent, name = os.path.split(existing)
        if not name or parent == existing:
            _die(f"Backup directory could not be prepared safely: {path}")
        missing.append(name)
        existing = parent
    try:
        real = os.path.realpath(existing, strict=True)
        current = OpenedDirectory(real)
        try:
            for name in reversed(missing):
                identity = current.identity_at(name)
                if identity is ABSENT:
                    os.mkdir(name, 0o700, dir_fd=current.fileno())
                child = current.open_directory(name)
                if child.identity.uid != os.geteuid():
                    child.close()
                    _die(
                        "Backup directory must be owned by the current user: "
                        f"{path}"
                    )
                os.fchmod(child.fileno(), 0o700)
                child.close()
                child = current.open_directory(name, policy=_PRIVATE_DIRECTORY)
                current.close()
                current = child
            if not missing:
                if current.identity.uid != os.geteuid() or real == "/":
                    _die(
                        "Backup directory must be owned by the current user: "
                        f"{path}"
                    )
                os.fchmod(current.fileno(), 0o700)
                current.close()
                current = OpenedDirectory(real, policy=_PRIVATE_DIRECTORY)
            current.recheck()
            return os.path.realpath(f"/proc/self/fd/{current.fileno()}")
        finally:
            current.close()
    except (OSError, FilesystemError):
        _die(
            "Backup directory must be a current-user-owned private directory: "
            f"{path}"
        )


def _cleanup_stage(
    parent_path: str,
    stage_name: str,
    stage_identity: FileIdentity,
) -> None:
    readiness = None
    try:
        with OpenedDirectory(parent_path, policy=_PRIVATE_DIRECTORY) as parent:
            current = parent.identity_at(stage_name)
            if current is ABSENT:
                return
            if (
                current.kind != "directory"
                or current.directory != stage_identity.directory
            ):
                raise FilesystemError("stage identity changed")
            with parent.open_directory(
                stage_name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=stage_identity.directory,
            ) as stage:
                readiness = fsync_tree(stage, parent, stage_name)
            assert readiness is not None
            remove_exact_tree(
                parent,
                stage_name,
                readiness.root_identity,
                readiness,
            )
    except (FilesystemError, PublicationError):
        _warn(
            "PKI backup staging cleanup could not be proven complete; "
            f"private staging evidence retained at: {parent_path}/{stage_name}"
        )


def backup(parsed: ParseResult) -> int:
    """Run the unified backup workflow."""

    environment = dict(os.environ)
    require_program("tar", environment)
    tar_help = run_external(("tar", "--help"), environment)
    if b"--no-wildcards" not in tar_help.stdout:
        _die(
            "tar with --no-wildcards support is required for safe PKI backup exclusions"
        )

    paths = resolve_paths(parsed.values, environment)
    require_pki_directory(paths.pki_dir)
    if os.path.islink(paths.pki_dir):
        _die(f"PKI directory must be a non-symlink directory: {paths.pki_dir}")
    prepare_control_state(paths.pki_dir)

    try:
        cwd = os.getcwd()
    except OSError:
        _die("Current directory could not be resolved")
    backup_value = parsed.values.get("--backup-dir")
    backup_input = (
        f"{paths.pki_dir}/backups"
        if backup_value is None
        else absolutize_path(
            expand_home(str(backup_value), home=environment.get("HOME", "")),
            physical_cwd=cwd,
        )
    )
    backup_real = _prepare_backup_directory(backup_input)
    try:
        pki_real = os.path.realpath(paths.pki_dir, strict=True)
    except OSError:
        _die("PKI directory could not be resolved")
    if backup_real == pki_real:
        _die(f"Backup directory cannot be the PKI directory itself: {backup_real}")
    _safe_record_path(backup_real)

    try:
        lexical_parent = os.path.realpath(
            os.path.dirname(backup_input),
            strict=True,
        )
    except OSError:
        _die("Backup directory could not be resolved")
    lexical_backup = os.path.join(lexical_parent, os.path.basename(backup_input))
    pki_base = os.path.basename(pki_real)
    excludes: list[str] = []
    for path in (backup_real, lexical_backup):
        if path == pki_real or not path.startswith(f"{pki_real}/"):
            continue
        relative = path[len(pki_real) + 1 :]
        value = f"{pki_base}/{relative}"
        if value not in excludes:
            excludes.append(value)

    previous_umask = os.umask(0o077)
    stage_name: str | None = None
    stage_identity: FileIdentity | None = None
    archive_path: str | None = None
    receipt_state = "absent"
    publication_complete = False
    try:
        with OpenedDirectory(backup_real, policy=_PRIVATE_DIRECTORY) as backup_parent:
            stage_name, stage = _reserve_stage(backup_parent)
            stage_identity = stage.identity
            stage_path = f"{backup_real}/{stage_name}"
            try:
                with acquire_operational_locks(paths.pki_dir, "export"):
                    require_no_unresolved_state(paths.pki_dir)
                    layout = detect_layout(paths.pki_dir)
                    if layout not in ("legacy", "generation"):
                        _die(
                            "PKI backup refuses incomplete or ambiguous layout: "
                            f"{layout}"
                        )
                    if layout == "generation":
                        require_program("openssl", environment)
                        load_active_issuer(paths.pki_dir, environment)
                    state_digest = _public_state_digest(
                        paths.pki_dir, layout, excluded_root=stage_path
                    )
                    private_digest = _private_metadata_digest(
                        paths.pki_dir, excluded_root=stage_path
                    )

                    _warn(
                        "PKI backup contains secrets, including private keys and CA database files"
                    )
                    plain_name = "platform-pki.tar.gz"
                    tar_argv = ["tar"]
                    for exclusion in excludes:
                        tar_argv.extend(("--no-wildcards", "--exclude", exclusion))
                    tar_argv.extend(
                        (
                            "-C",
                            os.path.dirname(pki_real),
                            "-czf",
                            f"{stage_path}/{plain_name}",
                            "--",
                            pki_base,
                        )
                    )
                    status = _run_inherited(tuple(tar_argv), environment)
                    if status:
                        return status
                    archive_digest = ""
                    try:
                        plain = stage.open_file(plain_name, policy=_PRIVATE_FILE)
                    except FilesystemError:
                        _die("PKI backup archive is unsafe after creation")
                    plain.close()

                    allow_plain = bool(parsed.values.get("--allow-plain-backup"))
                    source_name = plain_name
                    extension = ".tar.gz"
                    if not allow_plain:
                        require_program("age", environment)
                        encrypted_name = "platform-pki.tar.gz.age"
                        recipients = tuple(parsed.values.get("--age-recipient", ()))
                        age_argv = ["age"]
                        for recipient in recipients:
                            age_argv.extend(("-r", str(recipient)))
                        if not recipients:
                            age_argv.append("-p")
                        age_argv.extend(
                            (
                                "-o",
                                f"{stage_path}/{encrypted_name}",
                                f"{stage_path}/{plain_name}",
                            )
                        )
                        status = _run_inherited(tuple(age_argv), environment)
                        if status:
                            return status
                        try:
                            encrypted = stage.open_file(
                                encrypted_name, policy=_PRIVATE_FILE
                            )
                        except FilesystemError:
                            _die(
                                "Encrypted PKI backup archive is unsafe after creation"
                            )
                        encrypted.close()
                        source_name = encrypted_name
                        extension = ".tar.gz.age"

                    try:
                        final_layout = detect_layout(paths.pki_dir)
                        final_state_digest = _public_state_digest(
                            paths.pki_dir, layout, excluded_root=stage_path
                        )
                        final_private_digest = _private_metadata_digest(
                            paths.pki_dir, excluded_root=stage_path
                        )
                    except ApplicationError:
                        _die("PKI state changed while creating the backup archive")
                    if (
                        final_layout != layout
                        or final_state_digest != state_digest
                        or final_private_digest != private_digest
                    ):
                        _die("PKI state changed while creating the backup archive")

                    timestamp = _timestamp(environment)
                    while True:
                        destination_name = _candidate_name(
                            backup_parent, timestamp, extension
                        )
                        source_identity = stage.identity_at(source_name)
                        if not isinstance(source_identity, FileIdentity):
                            _die("PKI backup archive disappeared before publication")
                        try:
                            published = publish_no_clobber(
                                stage,
                                source_name,
                                source_identity,
                                backup_parent,
                                destination_name,
                            )
                            break
                        except PublicationDestinationExistsError:
                            continue
                        except PublicationAmbiguousError:
                            archive_path = f"{backup_real}/{destination_name}"
                            _warn(
                                "PKI backup publication requires inspection: "
                                f"{archive_path}"
                            )
                            return 1
                        except PublicationError:
                            _die(
                                "Failed to publish PKI backup: "
                                f"{backup_real}/{destination_name}"
                            )

                    archive_path = f"{backup_real}/{destination_name}"
                    archive_identity = published.identity
                    try:
                        with backup_parent.open_file(
                            destination_name,
                            policy=_PRIVATE_FILE,
                            expected_identity=archive_identity,
                        ) as archive:
                            archive_digest = _hash_descriptor(archive)
                            now = datetime.datetime.now(datetime.UTC).replace(
                                microsecond=0
                            )
                            receipt = _receipt_bytes(
                                archive_path,
                                archive_identity,
                                archive_digest,
                                layout,
                                state_digest,
                                private_digest,
                                session=secrets.token_hex(16),
                                created_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                created_epoch=int(now.timestamp()),
                            )
                            receipt_name = f"{destination_name}.receipt"
                            if backup_parent.identity_at(receipt_name) is not ABSENT:
                                _die(
                                    "Backup receipt destination exists: "
                                    f"{archive_path}.receipt"
                                )
                            staged_receipt = None
                            receipt_result = None
                            try:
                                staged_receipt = stage_file_bytes(
                                    backup_parent,
                                    receipt_name,
                                    receipt,
                                    mode=0o600,
                                )
                                with staged_receipt:
                                    archive.recheck()
                                    try:
                                        receipt_result = publish_no_clobber(
                                            backup_parent,
                                            staged_receipt.name,
                                            staged_receipt.identity,
                                            backup_parent,
                                            receipt_name,
                                        )
                                    except PublicationDestinationExistsError:
                                        _die(
                                            "Backup receipt destination exists: "
                                            f"{archive_path}.receipt"
                                        )
                                    except PublicationAmbiguousError:
                                        receipt_state = "ambiguous"
                                        staged_receipt.mark_consumed()
                                        _warn(
                                            "Backup receipt staging evidence may "
                                            "remain at: "
                                            f"{backup_real}/{staged_receipt.name}"
                                        )
                                        _die(
                                            "Backup receipt publication requires "
                                            f"inspection: {archive_path}.receipt"
                                        )
                                    except PublicationError:
                                        _die(
                                            "Failed to publish backup receipt: "
                                            f"{archive_path}.receipt"
                                        )
                                    staged_receipt.mark_consumed()
                                    receipt_state = "confirmed"
                            except ApplicationError:
                                if (
                                    staged_receipt is not None
                                    and not staged_receipt.consumed
                                ):
                                    _warn(
                                        "Backup receipt staging cleanup requires "
                                        "inspection: "
                                        f"{backup_real}/{staged_receipt.name}"
                                    )
                                raise

                            assert receipt_result is not None
                            try:
                                with backup_parent.open_file(
                                    receipt_name,
                                    policy=_PRIVATE_FILE,
                                    expected_identity=receipt_result.identity,
                                ) as published_receipt:
                                    archive.recheck()
                                    published_receipt.recheck()
                                    backup_parent.recheck()
                                    if allow_plain:
                                        _warn(
                                            "Created unencrypted PKI backup because "
                                            "--allow-plain-backup was used: "
                                            f"{archive_path}"
                                        )
                                    else:
                                        _ok(
                                            "Created encrypted PKI backup: "
                                            f"{archive_path}"
                                        )
                                    _ok(f"Backup receipt: {archive_path}.receipt")
                                    publication_complete = True
                            except FilesystemError:
                                _die(
                                    "Published PKI backup or receipt identity changed"
                                )
                            return 0
                    except FilesystemError:
                        _die("Published PKI backup archive identity is invalid")
            finally:
                stage.close()
    except ApplicationError:
        if archive_path is not None and receipt_state == "absent":
            _warn(
                "PKI backup archive was published without a receipt and must be "
                f"retained for inspection: {archive_path}"
            )
        elif archive_path is not None and receipt_state == "ambiguous":
            _warn(
                "PKI backup receipt publication is uncertain; archive and possible "
                "receipt must be retained for inspection: "
                f"{archive_path} {archive_path}.receipt"
            )
        elif archive_path is not None and not publication_complete:
            _warn(
                "PKI backup archive and receipt publication must be retained for "
                f"inspection: {archive_path} {archive_path}.receipt"
            )
        raise
    except (FilesystemError, OSError):
        if archive_path is not None and receipt_state == "absent":
            _warn(
                "PKI backup archive was published without a receipt and must be "
                f"retained for inspection: {archive_path}"
            )
        elif archive_path is not None and receipt_state == "ambiguous":
            _warn(
                "PKI backup receipt publication is uncertain; archive and possible "
                "receipt must be retained for inspection: "
                f"{archive_path} {archive_path}.receipt"
            )
        elif archive_path is not None and not publication_complete:
            _warn(
                "PKI backup archive and receipt publication must be retained for "
                f"inspection: {archive_path} {archive_path}.receipt"
            )
        _die("PKI backup filesystem operation failed")
    finally:
        os.umask(previous_umask)
        if stage_name is not None and stage_identity is not None:
            _cleanup_stage(backup_real, stage_name, stage_identity)
    raise AssertionError("unreachable")
