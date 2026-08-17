"""Generation-aware root CA bootstrap writer."""

from __future__ import annotations

import datetime
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, NoReturn

from .ca_passphrase_verify import _fresh_descriptor, _open_passphrase
from .ca_rollover_recovery import (
    ROOT_BOOTSTRAP_WRITER_FIELDS,
    RecoveryRecordError,
    parse_recovery_semantics,
)
from .errors import ApplicationError, shell_status
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
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
)
from .parser import ParseResult
from .paths import default_namespace, expand_home
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
    remove_exact_tree,
    replace_exact,
    unlink_exact,
)


_ROOT_GENERATION = re.compile(r"g([1-9][0-9]*)", re.ASCII)
_INTERMEDIATE_RESERVATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_FINGERPRINT = re.compile(r"[^=\n]+=([0-9A-Fa-f:]{95})\n?", re.ASCII)
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_MAX_PUBLIC_KEY = 1024 * 1024
ROOT_FAULT_VARIABLES = (
    "PLATFORM_PKI_ROOT_CRASH_AT",
    "PLATFORM_PKI_ROOT_SIGNAL_AT",
    "PLATFORM_PKI_ROOT_FAIL_AT",
)
ROOT_FAULT_CHECKPOINTS = (
    "after-journal",
    "after-reservation",
    "after-authority",
    "after-reservation-consumed",
    "after-bootstrap",
)
_HANDLED_SIGNALS = frozenset((signal.SIGHUP, signal.SIGINT, signal.SIGTERM))


class _ChildFailure(Exception):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(status)


class _SignalExit(Exception):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(status)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _publication_identity(result: object) -> FileIdentity:
    identity = getattr(result, "destination_identity", None)
    if identity is None:
        identity = getattr(result, "identity", None)
    if not isinstance(identity, FileIdentity):
        raise TypeError("publication result has no destination identity")
    return identity


@contextmanager
def _defer_handled_signals() -> Iterator[None]:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, _HANDLED_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _parent(path: str, *, private: bool = True) -> tuple[OpenedDirectory, str]:
    directory, name = os.path.split(path)
    try:
        return OpenedDirectory(
            directory,
            policy=_PRIVATE_DIRECTORY if private else DirectoryPolicy(),
        ), name
    except FilesystemError:
        _die("Root bootstrap publication parent is unsafe")


def _atomic_write(
    path: str,
    data: bytes,
    *,
    expected: FileIdentity | object = ABSENT,
) -> FileIdentity:
    parent, name = _parent(path)
    try:
        result = atomic_write_bytes(
            parent,
            name,
            data,
            expected_destination=expected,
        )
        return _publication_identity(result)
    except (FilesystemError, PublicationError):
        _die("Root bootstrap control record could not be published safely")
    finally:
        parent.close()


def _actual(path: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemError:
        _die("Root bootstrap filesystem state could not be inspected safely")


def _matches(
    actual: FileIdentity | object,
    expected: FileIdentity | FileObjectState | DirectoryIdentity,
) -> bool:
    if not isinstance(actual, FileIdentity):
        return False
    if isinstance(expected, FileIdentity):
        return actual == expected
    if isinstance(expected, DirectoryIdentity):
        return actual.kind == "directory" and actual.directory == expected
    return actual.state == expected


def _validate_config_value(label: str, value: str) -> None:
    if not value:
        _die(f"{label} must be non-empty")
    if "$" in value:
        _die(f"{label} must not contain OpenSSL variable expansion syntax")
    if "\n" in value or "\r" in value:
        _die(f"{label} must not contain newlines")
    if any(unicodedata.category(character) == "Cc" for character in value):
        _die(f"{label} must not contain control characters")
    if value[0].isspace() or value[-1].isspace():
        _die(f"{label} must not start or end with whitespace")


def _validate_record_path(label: str, value: str) -> None:
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _die(f"{label} must contain only ASCII characters for recovery records")


def _validate_days(value: str) -> str:
    if re.fullmatch(r"[0-9]+", value, re.ASCII) is None:
        _die(f"Days value must be numeric: {value}")
    normalized = value.lstrip("0") or "0"
    if len(normalized) > 6 or (len(normalized) == 6 and normalized > "365000"):
        _die(f"Days value must be at most 365000: {value}")
    if normalized == "0":
        _die(f"Days value must be at least 1: {value}")
    return value


def _require_no_symlink_components(path: str, label: str) -> None:
    current = "/" if path.startswith("/") else ""
    for component in path.split("/"):
        if not component:
            continue
        if current == "/":
            current = f"/{component}"
        elif current:
            current = f"{current}/{component}"
        else:
            current = component
        try:
            metadata = os.lstat(current)
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            _die(f"{label} path component must not be a symlink: {current}")


def _expand_passphrase(value: object, environment: Mapping[str, str]) -> str | None:
    if value is None:
        return None
    assert isinstance(value, str)
    home = environment.get("HOME")
    if home is None:
        _die("HOME is required")
    return expand_home(value, home=home)


def _open_root_passphrase(path: str) -> OpenedFile:
    if not os.path.exists(path):
        _die(f"Passphrase file is missing: {path}")
    return _open_passphrase(path)


def _next_generation(pki_dir: str) -> str:
    maximum = 0
    locations = (
        (f"{pki_dir}/state/generation-reservations", True),
        (f"{pki_dir}/authorities/roots", False),
    )
    for directory, reservations in locations:
        try:
            entries = tuple(os.scandir(directory))
        except OSError:
            _die("Root generation state could not be inspected")
        for entry in entries:
            name = entry.name
            if reservations and _INTERMEDIATE_RESERVATION.fullmatch(name) is not None:
                continue
            match = _ROOT_GENERATION.fullmatch(name)
            if match is None:
                _die(f"Invalid root generation state entry: {entry.path}")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                _die("Root generation state could not be inspected")
            if reservations:
                safe = (
                    stat.S_ISREG(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600
                    and metadata.st_nlink == 1
                )
                if not safe:
                    _die(f"Unsafe root generation reservation: {entry.path}")
            else:
                safe = (
                    stat.S_ISDIR(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o700
                )
                if not safe:
                    _die(
                        "Root authority generation must be current-user-owned "
                        f"with mode 700: {entry.path}"
                    )
            maximum = max(maximum, int(match.group(1)))
    return f"g{maximum + 1}"


def _record_bytes(fields: tuple[str, ...], values: Mapping[str, str]) -> bytes:
    if tuple(values) != fields:
        raise ValueError("record values are not in writer order")
    try:
        return "".join(f"{field}={values[field]}\n" for field in fields).encode("ascii")
    except UnicodeEncodeError:
        _die("Root bootstrap recovery record contains unsupported path characters")


def _reservation_bytes(
    generation: str,
    transaction: str,
    status: str,
    *,
    fingerprint: str | None = None,
) -> bytes:
    lines = [
        f"generation={generation}\n",
        "kind=root\n",
        f"status={status}\n",
    ]
    if fingerprint is not None:
        lines.append(f"fingerprint_sha256={fingerprint}\n")
    lines.append(f"transaction={transaction}\n")
    return "".join(lines).encode("ascii")


def _root_config(country: str, organization: str, name: str, authority: str) -> bytes:
    return f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {authority}
certs = $dir/certs
crl_dir = $dir/crl
new_certs_dir = $dir/newcerts
database = $dir/index.txt
serial = $dir/serial
private_key = $dir/private/root-ca.key
certificate = $dir/certs/root-ca.crt
default_md = sha384
policy = policy_platform
email_in_dn = no
copy_extensions = none
unique_subject = no

[ policy_platform ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
prompt = no
distinguished_name = dn
default_md = sha384
x509_extensions = v3_root_ca
string_mask = utf8only

[ dn ]
C = {country}
O = {organization}
CN = {name}

[ v3_root_ca ]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""".encode("utf-8")


def _write_new_file(path: str, data: bytes, mode: int) -> None:
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
        os.fsync(descriptor)
    except OSError:
        _die("Root authority staging file could not be written safely")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _secure_generated_file(path: str, mode: int) -> FileIdentity:
    descriptor = -1
    try:
        before = identity_from_stat(os.lstat(path))
        if before.kind != "regular" or before.uid != os.geteuid() or before.links != 1:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if identity_from_stat(os.fstat(descriptor)) != before:
            raise OSError
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        after = identity_from_stat(os.fstat(descriptor))
        current = identity_from_stat(os.lstat(path))
        if after != current or after.permissions != mode:
            raise OSError
        return after
    except (OSError, FilesystemError):
        _die("OpenSSL generated an unsafe root authority file")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _run_child(argv: tuple[str, ...], *, pass_fds: tuple[int, ...] = (), stdout: int | None = None) -> None:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=None,
            stdout=stdout,
            stderr=None,
            env=dict(os.environ),
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
        )
        returncode = process.wait()
    except BaseException:
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=1)
            except (OSError, subprocess.SubprocessError):
                try:
                    process.kill()
                except OSError:
                    pass
        raise
    if returncode:
        raise _ChildFailure(shell_status(returncode))


def _run_with_passphrase(
    passphrase: OpenedFile | None,
    argv: tuple[str, ...],
    option: str,
    *,
    stdout: int | None = None,
) -> None:
    if passphrase is None:
        _run_child(argv, stdout=stdout)
        return
    descriptor = _fresh_descriptor(
        passphrase, "Cannot duplicate passphrase file descriptor for OpenSSL"
    )
    try:
        _run_child(
            (*argv, option, f"fd:{descriptor}"),
            pass_fds=(descriptor,),
            stdout=stdout,
        )
    finally:
        os.close(descriptor)


def _redirected_child(path: str, argv: tuple[str, ...]) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        _run_child(argv, stdout=descriptor)
        os.fsync(descriptor)
    except OSError:
        _die("OpenSSL output could not be staged safely")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_and_remove(path: str, maximum: int) -> bytes:
    parent, name = _parent(path)
    data = b""
    identity: FileIdentity | None = None
    try:
        with parent.open_file(
            name,
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=maximum
            ),
        ) as opened:
            data = opened.read(maximum)
            identity = opened.identity
        assert identity is not None
        unlink_exact(parent, name, identity)
        return data
    except (FilesystemError, PublicationError):
        _die("OpenSSL staged output changed unexpectedly")
    finally:
        parent.close()


def _remove_tree(path: str, expected: DirectoryIdentity) -> None:
    parent_path, name = os.path.split(path)
    identity: FileIdentity | None = None
    readiness = None
    try:
        with OpenedDirectory(parent_path, policy=_PRIVATE_DIRECTORY) as parent:
            with parent.open_directory(
                name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected,
            ) as root:
                readiness = fsync_tree(root, parent, name)
                identity = root.identity
            assert identity is not None and readiness is not None
            remove_exact_tree(parent, name, identity, readiness)
    except (FilesystemError, PublicationError):
        _die("Journaled root bootstrap tree could not be removed safely")


def _remove_empty_created_directory(
    parent: OpenedDirectory,
    name: str,
    failure: str,
) -> None:
    try:
        os.rmdir(name, dir_fd=parent.fileno())
        os.fsync(parent.fileno())
    except OSError:
        raise ApplicationError(failure) from None


@dataclass(slots=True)
class _Transaction:
    pki_dir: str
    generation: str
    transaction: str
    transaction_dir: str
    transaction_identity: DirectoryIdentity
    authority_dir: str
    reservation: str
    reserved_stage: str
    reserved_identity: FileIdentity
    abandoned_stage: str
    abandoned_identity: FileIdentity
    journal: str
    marker: str
    journal_identity: FileIdentity | None = None
    marker_identity: FileIdentity | None = None
    reservation_identity: FileObjectState | None = None
    consumed_identity: FileObjectState | None = None
    bootstrap_identity: FileIdentity | None = None
    stage_dir: str | None = None
    stage_identity: DirectoryIdentity | None = None
    authority_identity: DirectoryIdentity | None = None
    committed: bool = False

    def write_journal(
        self,
        phase: str,
        *,
        committed: bool = False,
        recovery_action: str = "none",
        recovery_step: str = "none",
    ) -> None:
        authority_identity = self.authority_identity or self.stage_identity
        values = {
            "schema": "3",
            "operation": "root-bootstrap",
            "transaction": self.transaction,
            "phase": phase,
            "generation": self.generation,
            "authority_dir": self.authority_dir,
            "authority_identity": (
                serialize_directory_identity(authority_identity)
                if authority_identity is not None
                else "none"
            ),
            "stage_dir": self.stage_dir or "none",
            "stage_identity": serialize_directory_identity(self.stage_identity) if self.stage_identity is not None else "none",
            "transaction_dir": self.transaction_dir,
            "transaction_identity": serialize_directory_identity(self.transaction_identity),
            "reservation": self.reservation,
            "reservation_identity": serialize_file_object_state(self.reservation_identity) if self.reservation_identity is not None else "absent",
            "reservation_reserved_identity": serialize_file_object_state(self.reserved_identity.state),
            "reservation_consumed_identity": serialize_file_object_state(self.consumed_identity) if self.consumed_identity is not None else "absent",
            "reservation_abandoned_identity": serialize_file_object_state(self.abandoned_identity.state),
            "bootstrap_identity": serialize_file_identity(self.bootstrap_identity) if self.bootstrap_identity is not None else "absent",
            "recovery_action": recovery_action,
            "recovery_step": recovery_step,
            "committed": "true" if committed else "false",
        }
        data = _record_bytes(ROOT_BOOTSTRAP_WRITER_FIELDS, values)
        try:
            parse_recovery_semantics(data, pki_dir=self.pki_dir)
        except RecoveryRecordError:
            _die("Root bootstrap recovery journal could not be validated")
        with _defer_handled_signals():
            self.journal_identity = _atomic_write(
                self.journal,
                data,
                expected=(
                    self.journal_identity
                    if self.journal_identity is not None
                    else ABSENT
                ),
            )

    def checkpoint(self, point: str, environment: Mapping[str, str]) -> None:
        if point not in ROOT_FAULT_CHECKPOINTS:
            raise ValueError("unknown root bootstrap checkpoint")
        crash_variable, signal_variable, failure_variable = ROOT_FAULT_VARIABLES
        if environment.get(crash_variable) == point:
            os.kill(os.getpid(), signal.SIGKILL)
        if environment.get(signal_variable) == point:
            raise _SignalExit(143)
        if environment.get(failure_variable) == point:
            _die(f"Injected root bootstrap failure at {point}")

    def publish_marker(self) -> None:
        with _defer_handled_signals():
            self.marker_identity = _atomic_write(
                self.marker,
                f"transaction={self.transaction}\naction=run platform-pki-ca-rollover recover\n".encode("ascii"),
            )

    def rollback(self) -> None:
        bootstrap = f"{self.pki_dir}/state/bootstrap-root"
        current_bootstrap = _actual(bootstrap)
        if current_bootstrap is not ABSENT and (
            self.bootstrap_identity is None
            or not _matches(current_bootstrap, self.bootstrap_identity)
        ):
            _die("Bootstrap root manifest identity changed before rollback")
        current_authority = _actual(self.authority_dir)
        if current_authority is not ABSENT and (
            self.authority_identity is None
            or not _matches(current_authority, self.authority_identity)
        ):
            _die("Published root authority identity changed before rollback")
        current_stage = ABSENT if self.stage_dir is None else _actual(self.stage_dir)
        if current_stage is not ABSENT and (
            self.stage_identity is None or not _matches(current_stage, self.stage_identity)
        ):
            _die("Root authority staging identity changed before rollback")
        current_reservation = _actual(self.reservation)
        allowed = [self.reserved_identity.state, self.abandoned_identity.state]
        if self.consumed_identity is not None:
            allowed.append(self.consumed_identity)
        if current_reservation is not ABSENT and not any(
            _matches(current_reservation, value) for value in allowed
        ):
            _die("Root generation reservation changed before rollback")
        if not _matches(current_reservation, self.abandoned_identity.state):
            abandoned = _actual(self.abandoned_stage)
            if not _matches(abandoned, self.abandoned_identity):
                _die("Abandoned root reservation stage changed before rollback")

        if current_bootstrap is not ABSENT:
            assert isinstance(current_bootstrap, FileIdentity)
            self.write_journal("recovering", recovery_action="rollback", recovery_step="bootstrap-pending")
            parent, name = _parent(bootstrap)
            try:
                unlink_exact(parent, name, current_bootstrap)
            finally:
                parent.close()
            self.write_journal("recovering", recovery_action="rollback", recovery_step="bootstrap-done")
        if current_authority is not ABSENT:
            assert self.authority_identity is not None
            self.write_journal("recovering", recovery_action="rollback", recovery_step="authority-pending")
            _remove_tree(self.authority_dir, self.authority_identity)
            self.write_journal("recovering", recovery_action="rollback", recovery_step="authority-done")
        if current_stage is not ABSENT:
            assert self.stage_dir is not None and self.stage_identity is not None
            self.write_journal("recovering", recovery_action="rollback", recovery_step="stage-pending")
            _remove_tree(self.stage_dir, self.stage_identity)
            self.stage_dir = None
            self.write_journal("recovering", recovery_action="rollback", recovery_step="stage-done")
        if not _matches(current_reservation, self.abandoned_identity.state):
            self.write_journal("recovering", recovery_action="rollback", recovery_step="reservation-pending")
            source_parent, source_name = _parent(self.abandoned_stage)
            destination_parent, destination_name = _parent(self.reservation)
            try:
                if current_reservation is ABSENT:
                    result = publish_no_clobber(
                        source_parent,
                        source_name,
                        self.abandoned_identity,
                        destination_parent,
                        destination_name,
                    )
                else:
                    assert isinstance(current_reservation, FileIdentity)
                    result = replace_exact(
                        source_parent,
                        source_name,
                        self.abandoned_identity,
                        destination_parent,
                        destination_name,
                        current_reservation,
                    )
                self.reservation_identity = _publication_identity(result).state
            finally:
                destination_parent.close()
                source_parent.close()
            self.write_journal("recovering", recovery_action="rollback", recovery_step="reservation-done")
        else:
            self.reservation_identity = self.abandoned_identity.state
        self.write_journal(
            "rolled-back",
            committed=True,
            recovery_action="rollback",
            recovery_step="complete",
        )
        if self.marker_identity is not None:
            parent, name = _parent(self.marker)
            try:
                unlink_exact(parent, name, self.marker_identity)
            finally:
                parent.close()


def _create_transaction(pki_dir: str, generation: str) -> _Transaction:
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    transaction = f"root-bootstrap-{timestamp}-{os.getpid()}"
    transaction_dir = f"{pki_dir}/state/rollover/{transaction}"
    transaction_identity: DirectoryIdentity | None = None
    transaction_created = False
    try:
        with OpenedDirectory(
            f"{pki_dir}/state/rollover", policy=_PRIVATE_DIRECTORY
        ) as transaction_parent:
            os.mkdir(transaction, 0o700, dir_fd=transaction_parent.fileno())
            transaction_created = True
            try:
                with transaction_parent.open_directory(
                    transaction, policy=_PRIVATE_DIRECTORY
                ) as opened:
                    transaction_identity = opened.directory_identity
            except BaseException:
                _remove_empty_created_directory(
                    transaction_parent,
                    transaction,
                    "Root bootstrap transaction setup failed and retained an "
                    "unidentified private transaction directory",
                )
                transaction_created = False
                raise
        reserved_stage = f"{transaction_dir}/reservation-reserved"
        abandoned_stage = f"{transaction_dir}/reservation-abandoned"
        reserved = _atomic_write(
            reserved_stage,
            _reservation_bytes(generation, transaction, "reserved"),
        )
        abandoned = _atomic_write(
            abandoned_stage,
            _reservation_bytes(generation, transaction, "abandoned"),
        )
        with OpenedDirectory(f"{pki_dir}/state/rollover", policy=_PRIVATE_DIRECTORY) as parent:
            with parent.open_directory(transaction, policy=_PRIVATE_DIRECTORY) as opened:
                fsync_tree(opened, parent, transaction)
                transaction_identity = opened.directory_identity
    except BaseException as error:
        if transaction_created and transaction_identity is not None:
            try:
                _remove_tree(transaction_dir, transaction_identity)
            except BaseException as cleanup_error:
                raise ApplicationError(
                    "Root bootstrap transaction setup failed and retained an "
                    "identity-bound private transaction directory"
                ) from cleanup_error
        if isinstance(error, ApplicationError):
            raise
        _die("Cannot create root bootstrap transaction directory")
    assert transaction_identity is not None
    journal = f"{pki_dir}/state/rollover/journal"
    current_journal = _actual(journal)
    if current_journal is not ABSENT and not isinstance(current_journal, FileIdentity):
        _die("Existing root bootstrap recovery journal is unsafe")
    return _Transaction(
        pki_dir,
        generation,
        transaction,
        transaction_dir,
        transaction_identity,
        f"{pki_dir}/authorities/roots/{generation}",
        f"{pki_dir}/state/generation-reservations/{generation}",
        reserved_stage,
        reserved,
        abandoned_stage,
        abandoned,
        journal,
        f"{pki_dir}/state/rollover/recovery-required",
        journal_identity=(
            current_journal if isinstance(current_journal, FileIdentity) else None
        ),
    )


def _create_stage(transaction: _Transaction) -> None:
    parent_path = f"{transaction.pki_dir}/authorities/roots"
    created_name: str | None = None
    created_identity: DirectoryIdentity | None = None
    try:
        with _defer_handled_signals():
            with OpenedDirectory(parent_path, policy=_PRIVATE_DIRECTORY) as parent:
                for _attempt in range(32):
                    name = f".platform-pki-root-create.{secrets.token_urlsafe(6)}"
                    try:
                        os.mkdir(name, 0o700, dir_fd=parent.fileno())
                    except FileExistsError:
                        continue
                    created_name = name
                    break
                else:
                    _die("Cannot create root staging directory")
                try:
                    with parent.open_directory(name, policy=_PRIVATE_DIRECTORY) as stage:
                        created_identity = stage.directory_identity
                except BaseException:
                    _remove_empty_created_directory(
                        parent,
                        name,
                        "Root authority staging setup failed and retained an "
                        "unidentified private directory",
                    )
                    created_name = None
                    raise
                transaction.stage_identity = created_identity
                transaction.stage_dir = f"{parent_path}/{name}"
    except (OSError, FilesystemError) as error:
        if created_name is not None and created_identity is not None:
            try:
                _remove_tree(f"{parent_path}/{created_name}", created_identity)
            except ApplicationError as cleanup_error:
                raise ApplicationError(
                    "Root authority staging setup failed and retained an "
                    "identity-bound private directory"
                ) from cleanup_error
        if isinstance(error, ApplicationError):
            raise
        _die("Cannot create root staging directory")


def _stage_authority(
    transaction: _Transaction,
    country: str,
    organization: str,
    name: str,
    days: str,
    passphrase: OpenedFile | None,
    unencrypted: bool,
) -> str:
    assert transaction.stage_dir is not None
    stage = transaction.stage_dir
    try:
        for directory in ("certs", "private", "crl", "newcerts"):
            os.mkdir(f"{stage}/{directory}", 0o700)
    except OSError:
        _die("Root authority staging directories could not be created safely")
    for relative, data in (
        ("index.txt", b""),
        ("index.txt.attr", b"unique_subject = no\n"),
        ("serial", b"1000\n"),
        ("crlnumber", b"1000\n"),
    ):
        _write_new_file(f"{stage}/{relative}", data, 0o600)
    config = f"{stage}/openssl.cnf"
    key = f"{stage}/private/root-ca.key"
    certificate = f"{stage}/certs/root-ca.crt"
    _write_new_file(
        config,
        _root_config(country, organization, name, transaction.authority_dir),
        0o600,
    )

    genpkey = (
        "openssl",
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:secp384r1",
    )
    if unencrypted:
        print(
            "[WARN] Creating an unencrypted root CA private key because "
            "--allow-unencrypted-root-key was used",
            file=sys.stderr,
            flush=True,
        )
        _run_child((*genpkey, "-out", key))
    else:
        _run_with_passphrase(
            passphrase,
            (*genpkey, "-aes-256-cbc", "-out", key),
            "-pass",
        )
    _secure_generated_file(key, 0o600)

    _run_with_passphrase(
        passphrase,
        (
            "openssl",
            "req",
            "-config",
            config,
            "-key",
            key,
            "-new",
            "-x509",
            "-days",
            days,
            "-sha384",
            "-extensions",
            "v3_root_ca",
            "-out",
            certificate,
        ),
        "-passin",
    )
    _secure_generated_file(certificate, 0o644)

    certificate_public = f"{stage}/cert.pub"
    key_public = f"{stage}/key.pub"
    _redirected_child(
        certificate_public,
        ("openssl", "x509", "-in", certificate, "-pubkey", "-noout"),
    )
    key_arguments = ("openssl", "pkey", "-in", key, "-pubout", "-out", key_public)
    _run_with_passphrase(passphrase, key_arguments, "-passin")
    _secure_generated_file(key_public, 0o600)
    if _read_and_remove(certificate_public, _MAX_PUBLIC_KEY) != _read_and_remove(
        key_public, _MAX_PUBLIC_KEY
    ):
        _die("Generated root CA key and certificate do not match")

    fingerprint_output = f"{stage}/fingerprint"
    _redirected_child(
        fingerprint_output,
        ("openssl", "x509", "-in", certificate, "-noout", "-fingerprint", "-sha256"),
    )
    try:
        text = _read_and_remove(fingerprint_output, 4096).decode("ascii")
    except UnicodeDecodeError:
        _die("Generated root CA fingerprint is invalid")
    match = _FINGERPRINT.fullmatch(text)
    if match is None:
        _die("Generated root CA fingerprint is invalid")
    return match.group(1).replace(":", "").upper()


def _publish_authority(transaction: _Transaction) -> None:
    assert transaction.stage_dir is not None and transaction.stage_identity is not None
    parent_path, stage_name = os.path.split(transaction.stage_dir)
    destination_name = transaction.generation
    identity: FileIdentity | None = None
    readiness = None
    published: FileIdentity | None = None
    try:
        with _defer_handled_signals():
            with OpenedDirectory(parent_path, policy=_PRIVATE_DIRECTORY) as parent:
                with parent.open_directory(
                    stage_name,
                    policy=_PRIVATE_DIRECTORY,
                    expected_identity=transaction.stage_identity,
                ) as stage:
                    readiness = fsync_tree(stage, parent, stage_name)
                    identity = stage.identity
                assert identity is not None and readiness is not None
                result = publish_no_clobber(
                    parent,
                    stage_name,
                    identity,
                    parent,
                    destination_name,
                    readiness=readiness,
                )
                published = _publication_identity(result)
            assert published is not None
            transaction.authority_identity = published.directory
            transaction.stage_dir = None
    except (FilesystemError, PublicationError):
        _die(f"Cannot publish root generation: {transaction.authority_dir}")


def _publish_reservation(
    transaction: _Transaction,
    source: str,
    source_identity: FileIdentity,
    destination_identity: FileIdentity | object,
) -> FileIdentity:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(transaction.reservation)
    try:
        if destination_identity is ABSENT:
            result = publish_no_clobber(
                source_parent,
                source_name,
                source_identity,
                destination_parent,
                destination_name,
            )
        else:
            assert isinstance(destination_identity, FileIdentity)
            result = replace_exact(
                source_parent,
                source_name,
                source_identity,
                destination_parent,
                destination_name,
                destination_identity,
            )
        return _publication_identity(result)
    except (FilesystemError, PublicationError):
        _die("Root generation reservation could not be published safely")
    finally:
        destination_parent.close()
        source_parent.close()


def _abort(transaction: _Transaction, original: BaseException) -> None:
    try:
        transaction.publish_marker()
        transaction.rollback()
    except BaseException as rollback_error:
        raise ApplicationError(
            "Root bootstrap rollback failed; retained recovery evidence requires "
            "platform-pki ca-rollover recover"
        ) from rollback_error
    raise original


def _run_transaction(
    pki_dir: str,
    country: str,
    organization: str,
    name: str,
    days: str,
    passphrase: OpenedFile | None,
    unencrypted: bool,
    force: bool,
    environment: Mapping[str, str],
) -> int:
    active = f"{pki_dir}/state/active-issuer"
    bootstrap = f"{pki_dir}/state/bootstrap-root"
    if os.path.lexists(active):
        _die(
            "An active issuer exists; use platform-pki ca-rollover instead of "
            "replacing the root CA"
        )
    if os.path.lexists(bootstrap):
        _die("A bootstrap root already exists; create its first intermediate or recover it")
    layout = detect_layout(pki_dir)
    if layout == "legacy":
        _die(
            "Legacy PKI state requires migration; create a fresh backup and follow "
            "platform-pki ca-rollover status/migrate"
        )
    if layout != "empty":
        _die("PKI state is incomplete or ambiguous; run platform-pki ca-rollover status")
    if force:
        _die(
            "--force cannot delete unproven root state; recover the journaled "
            "disposable transaction instead"
        )

    generation = _next_generation(pki_dir)
    transaction: _Transaction | None = None
    try:
        with _defer_handled_signals():
            transaction = _create_transaction(pki_dir, generation)
            transaction.write_journal("prepared")
        transaction.checkpoint("after-journal", environment)

        with _defer_handled_signals():
            reservation = _publish_reservation(
                transaction,
                transaction.reserved_stage,
                transaction.reserved_identity,
                ABSENT,
            )
            transaction.reservation_identity = reservation.state
        transaction.write_journal("reserved")
        transaction.checkpoint("after-reservation", environment)

        _create_stage(transaction)
        transaction.write_journal("staged")
        fingerprint = _stage_authority(
            transaction,
            country,
            organization,
            name,
            days,
            passphrase,
            unencrypted,
        )
        if passphrase is not None:
            try:
                passphrase.recheck()
            except FilesystemError:
                _die("Passphrase file changed during root creation")
        _publish_authority(transaction)
        transaction.write_journal("authority-published")
        transaction.checkpoint("after-authority", environment)

        consumed_stage = f"{transaction.transaction_dir}/reservation-consumed"
        with _defer_handled_signals():
            consumed = _atomic_write(
                consumed_stage,
                _reservation_bytes(
                    generation,
                    transaction.transaction,
                    "consumed",
                    fingerprint=fingerprint,
                ),
            )
            transaction.consumed_identity = consumed.state
            transaction.write_journal("reservation-consume-pending")
        current_reservation = _actual(transaction.reservation)
        if not isinstance(current_reservation, FileIdentity):
            _die("Reserved root generation identity changed")
        with _defer_handled_signals():
            published_consumed = _publish_reservation(
                transaction,
                consumed_stage,
                consumed,
                current_reservation,
            )
            transaction.reservation_identity = published_consumed.state
        transaction.write_journal("reservation-consumed")
        transaction.checkpoint("after-reservation-consumed", environment)

        with _defer_handled_signals():
            transaction.bootstrap_identity = _atomic_write(
                bootstrap,
                f"root={generation}\nfingerprint_sha256={fingerprint}\n".encode("ascii"),
            )
        transaction.write_journal("bootstrap-published")
        transaction.checkpoint("after-bootstrap", environment)
        with _defer_handled_signals():
            transaction.write_journal("complete", committed=True)
            transaction.committed = True
    except (_ChildFailure, _SignalExit, ApplicationError) as error:
        if transaction is None:
            raise
        _abort(transaction, error)
    except (OSError, FilesystemError, PublicationError):
        if transaction is None:
            raise ApplicationError("Root CA creation failed safely") from None
        _abort(transaction, ApplicationError("Root CA creation failed safely"))

    print(
        f"[OK] Created root CA generation {generation}: "
        f"{transaction.authority_dir}/certs/root-ca.crt",
        flush=True,
    )
    return 0


def create_root(parsed: ParseResult) -> int:
    """Create one root authority through unified dispatch."""

    environment = dict(os.environ)
    name = str(parsed["--name"])
    organization = str(parsed["--org"])
    country = str(parsed["--country"])
    days = _validate_days(
        str(parsed.values.get("--days") or environment.get("PLATFORM_PKI_ROOT_DAYS") or "3650")
    )
    _validate_config_value("Root CA common name", name)
    _validate_config_value("Organization name", organization)
    _validate_config_value("Country code", country)
    home = environment.get("HOME")
    if home is None:
        _die("HOME is required")
    namespace_value = parsed.values.get("--namespace")
    namespace = expand_home(
        namespace_value
        if namespace_value is not None
        else default_namespace(
            home=home,
            xdg_config_home=environment.get("XDG_CONFIG_HOME"),
        ),
        home=home,
    )
    pki_value = parsed.values.get("--pki-dir")
    raw_pki_dir = expand_home(
        pki_value if pki_value is not None else f"{namespace}/pki",
        home=home,
    )
    _validate_config_value("PKI directory", raw_pki_dir)
    paths = resolve_paths(parsed.values, environment)
    _validate_config_value("PKI directory", paths.pki_dir)
    _validate_record_path("PKI directory", paths.pki_dir)
    passphrase_path = _expand_passphrase(parsed.values.get("--root-pass-file"), environment)
    passphrase = _open_root_passphrase(passphrase_path) if passphrase_path is not None else None
    require_program("openssl", environment)
    require_pki_directory(paths.pki_dir)
    _require_no_symlink_components(paths.pki_dir, "PKI directory")
    prepare_control_state(paths.pki_dir)
    _require_no_symlink_components(paths.pki_dir, "PKI directory")
    previous_umask = os.umask(0o077)

    previous_handlers: dict[signal.Signals, Any] = {}

    def handled_signal(signum: int, _frame: object) -> NoReturn:
        raise _SignalExit(128 + signum)

    for process_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[process_signal] = signal.signal(process_signal, handled_signal)
    try:
        try:
            with acquire_operational_locks(paths.pki_dir, "root"):
                require_no_unresolved_state(paths.pki_dir)
                return _run_transaction(
                    paths.pki_dir,
                    country,
                    organization,
                    name,
                    days,
                    passphrase,
                    "--allow-unencrypted-root-key" in parsed.provided,
                    "--force" in parsed.provided,
                    environment,
                )
        except _ChildFailure as error:
            return error.status
        except _SignalExit as error:
            return error.status
    finally:
        os.umask(previous_umask)
        if passphrase is not None:
            passphrase.close()
        for process_signal, handler in previous_handlers.items():
            signal.signal(process_signal, handler)
