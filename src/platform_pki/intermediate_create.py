"""Generation-aware intermediate CA bootstrap transaction writer."""

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
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, NoReturn

from .ca_passphrase_verify import _open_passphrase
from .ca_rollover_recovery import (
    INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS,
    ROOT_DB_KEYS,
    RecoveryRecordError,
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
from .operational import (
    acquire_operational_locks,
    prepare_control_state,
    require_no_unresolved_state,
    require_pilot_common_library,
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
from .root_create import (
    _ChildFailure,
    _SignalExit,
    _defer_handled_signals,
    _publication_identity,
    _read_and_remove,
    _remove_empty_created_directory,
    _run_child,
    _run_with_passphrase,
    _secure_generated_file,
    _validate_days,
)


_ROOT_GENERATION = re.compile(r"g([1-9][0-9]*)", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i([1-9][0-9]*)", re.ASCII)
_FINGERPRINT = re.compile(r"[^=\n]+=([0-9A-Fa-f:]{95})\n?", re.ASCII)
_SERIAL = re.compile(r"[0-9A-Fa-f]+", re.ASCII)
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_PRIVATE_FILE = FilePolicy(owner=os.geteuid(), mode=0o600, links=1)
_PUBLIC_CERTIFICATE = FilePolicy(owner=os.geteuid(), mode=0o644, links=1)
_MAX_RECORD = 4096
_MAX_CERTIFICATE = 4 * 1024 * 1024
INTERMEDIATE_FAULT_VARIABLES = (
    "PLATFORM_PKI_INTERMEDIATE_CRASH_AT",
    "PLATFORM_PKI_INTERMEDIATE_SIGNAL_AT",
    "PLATFORM_PKI_INTERMEDIATE_FAIL_AT",
)
INTERMEDIATE_LITERAL_CHECKPOINTS = (
    "after-journal",
    "after-reservation",
    "after-intermediate",
    "after-root-db",
    "after-reservation-consumed",
    "after-active",
    "after-bootstrap",
    "cleanup-pending",
    "cleanup-removed",
    "cleanup-done",
)
INTERMEDIATE_FAULT_CHECKPOINTS = frozenset(
    (
        *INTERMEDIATE_LITERAL_CHECKPOINTS,
        *(f"root-{key}-{phase}" for key in ROOT_DB_KEYS for phase in ("pending", "done")),
    )
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _actual(path: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemError:
        _die("Intermediate bootstrap filesystem state could not be inspected safely")


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


def _parent(path: str) -> tuple[OpenedDirectory, str]:
    directory, name = os.path.split(path)
    try:
        return OpenedDirectory(directory, policy=_PRIVATE_DIRECTORY), name
    except FilesystemError:
        _die("Intermediate bootstrap publication parent is unsafe")


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
        _die("Intermediate bootstrap control record could not be published safely")
    finally:
        parent.close()


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


def _require_no_symlink_components(path: str, label: str) -> None:
    current = "/" if path.startswith("/") else ""
    for component in path.split("/"):
        if not component:
            continue
        current = (
            f"/{component}"
            if current == "/"
            else f"{current}/{component}"
            if current
            else component
        )
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


def _open_passphrase_file(path: str) -> OpenedFile:
    if not os.path.exists(path):
        _die(f"Passphrase file is missing: {path}")
    return _open_passphrase(path)


def _record_bytes(values: Mapping[str, str]) -> bytes:
    if tuple(values) != INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS:
        raise ValueError("intermediate record values are not in writer order")
    try:
        return "".join(
            f"{field}={values[field]}\n" for field in INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS
        ).encode("ascii")
    except UnicodeEncodeError:
        _die("Intermediate bootstrap recovery record contains unsupported characters")


def _reservation_bytes(
    generation: str,
    transaction: str,
    status: str,
    *,
    fingerprint: str | None = None,
) -> bytes:
    lines = [
        f"generation={generation}\n",
        "kind=intermediate\n",
        f"status={status}\n",
    ]
    if fingerprint is not None:
        lines.append(f"fingerprint_sha256={fingerprint}\n")
    lines.append(f"transaction={transaction}\n")
    return "".join(lines).encode("ascii")


def _read_bootstrap(path: str) -> tuple[str, str, FileIdentity]:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(owner=os.geteuid(), mode=0o600, links=1, max_size=_MAX_RECORD),
        ) as opened:
            data = opened.read(_MAX_RECORD)
            identity = opened.identity
    except FilesystemError:
        _die("Bootstrap root manifest is missing; create the root CA first")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Bootstrap root manifest is invalid")
    if (
        len(lines) != 2
        or not lines[0].startswith("root=")
        or not lines[1].startswith("fingerprint_sha256=")
    ):
        _die("Bootstrap root manifest is invalid")
    root = lines[0].removeprefix("root=")
    fingerprint = lines[1].removeprefix("fingerprint_sha256=")
    if _ROOT_GENERATION.fullmatch(root) is None or re.fullmatch(
        r"[0-9A-Fa-f]{64}", fingerprint, re.ASCII
    ) is None:
        _die("Bootstrap root manifest is invalid")
    assert identity is not None
    return root, fingerprint.upper(), identity


def _next_generation(pki_dir: str, root: str) -> str:
    maximum = 0
    locations = (
        f"{pki_dir}/state/generation-reservations",
        f"{pki_dir}/authorities/intermediates",
    )
    prefix = f"{root}-i"
    for directory in locations:
        try:
            entries = tuple(os.scandir(directory))
        except OSError:
            _die("Intermediate generation state could not be inspected")
        for entry in entries:
            if not entry.name.startswith(prefix):
                continue
            match = _INTERMEDIATE_GENERATION.fullmatch(entry.name)
            if match is None or not entry.name.startswith(f"{root}-i"):
                _die(f"Invalid intermediate generation state entry: {entry.path}")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                _die("Intermediate generation state could not be inspected")
            if directory.endswith("generation-reservations"):
                safe = (
                    stat.S_ISREG(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600
                    and metadata.st_nlink == 1
                )
                if not safe:
                    _die(f"Unsafe intermediate generation reservation: {entry.path}")
            else:
                safe = (
                    stat.S_ISDIR(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o700
                )
                if not safe:
                    _die(
                        "Intermediate authority generation must be current-user-owned "
                        f"with mode 700: {entry.path}"
                    )
            maximum = max(maximum, int(match.group(1)))
    return f"{root}-i{maximum + 1}"


def _write_new_file(path: str, data: bytes, mode: int) -> FileIdentity:
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
        return identity_from_stat(os.fstat(descriptor))
    except (OSError, FilesystemError):
        _die("Intermediate authority staging file could not be written safely")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    raise AssertionError("unreachable")


def _copy_opened_file(
    source: OpenedFile, destination: str, mode: int
) -> FileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
        )
        offset = 0
        while offset < source.identity.size:
            chunk = os.pread(
                source.fileno(), min(64 * 1024, source.identity.size - offset), offset
            )
            if not chunk:
                raise OSError
            view = memoryview(chunk)
            try:
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError
                    view = view[written:]
            finally:
                view.release()
            offset += len(chunk)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        return identity_from_stat(os.fstat(descriptor))
    except (OSError, FilesystemError):
        _die("Required authority file could not be copied safely")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    raise AssertionError("unreachable")


def _copy_file(
    source: str,
    destination: str,
    *,
    source_policy: FilePolicy,
    destination_mode: int,
) -> tuple[FileIdentity, FileIdentity]:
    try:
        with OpenedFile(source, policy=source_policy) as opened:
            source_identity = opened.identity
            copied = _copy_opened_file(opened, destination, destination_mode)
            opened.recheck()
            return source_identity, copied
    except FilesystemError:
        _die(f"Required authority file is unsafe or changed: {source}")
    raise AssertionError("unreachable")


def _copy_root_database_source(
    source: str,
    staged: str,
    backup: str,
    *,
    required: bool,
) -> tuple[FileIdentity, FileIdentity, FileIdentity] | None:
    try:
        opened = OpenedFile(source, policy=_PRIVATE_FILE)
    except FilesystemError:
        current = _actual(source)
        if not required and current is ABSENT:
            return None
        if current is ABSENT:
            _die(f"Required file is missing: {source}")
        _die(f"Root database source is unsafe or changed: {source}")
    with opened:
        source_identity = opened.identity
        staged_identity = _copy_opened_file(opened, staged, 0o600)
        backup_identity = _copy_opened_file(opened, backup, 0o600)
        try:
            opened.recheck()
        except FilesystemError:
            _die(f"Root database source changed while being copied: {source}")
        if staged_identity.permissions != 0o600 or backup_identity.permissions != 0o600:
            _die("Root database destination mode is invalid")
        return source_identity, staged_identity, backup_identity


def _root_config(country: str, organization: str, name: str, authority: str) -> bytes:
    from .root_create import _root_config as render

    return render(country, organization, name, authority)


def _intermediate_config(
    country: str, organization: str, name: str, authority: str
) -> bytes:
    return f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {authority}
certs = $dir/certs
crl_dir = $dir/crl
new_certs_dir = $dir/newcerts
database = $dir/index.txt
serial = $dir/serial
private_key = $dir/private/intermediate-ca.key
certificate = $dir/certs/intermediate-ca.crt
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
string_mask = utf8only

[ dn ]
C = {country}
O = {organization}
CN = {name}

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""".encode("utf-8")


def _remove_tree(path: str, expected: DirectoryIdentity, message: str) -> None:
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
        _die(message)


def _publish_file(
    source: str,
    destination: str,
    source_identity: FileIdentity,
    destination_identity: FileIdentity | object,
) -> FileIdentity:
    source_parent, source_name = _parent(source)
    destination_parent, destination_name = _parent(destination)
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
        _die("Intermediate bootstrap staged-file publication failed")
    finally:
        destination_parent.close()
        source_parent.close()


def _unlink(path: str, expected: FileIdentity, message: str) -> None:
    parent, name = _parent(path)
    try:
        unlink_exact(parent, name, expected)
    except (FilesystemError, PublicationError):
        _die(message)
    finally:
        parent.close()


def _redirected_child(
    path: str, argv: tuple[str, ...], *, pass_fds: tuple[int, ...] = ()
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        _run_child(argv, pass_fds=pass_fds, stdout=descriptor)
        os.fsync(descriptor)
    except OSError:
        _die("OpenSSL output could not be staged safely")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _certificate_fingerprint(
    path: str, stage: str, *, pass_fds: tuple[int, ...] = ()
) -> str:
    output = f"{stage}/fingerprint-{secrets.token_urlsafe(5)}"
    _redirected_child(
        output,
        ("openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"),
        pass_fds=pass_fds,
    )
    try:
        text = _read_and_remove(output, 4096).decode("ascii")
    except UnicodeDecodeError:
        _die("Generated certificate fingerprint is invalid")
    match = _FINGERPRINT.fullmatch(text)
    if match is None:
        _die("Generated certificate fingerprint is invalid")
    return match.group(1).replace(":", "").upper()


def _certificate_dates(
    path: str, stage: str, *, pass_fds: tuple[int, ...] = ()
) -> tuple[int, int]:
    output = f"{stage}/dates-{secrets.token_urlsafe(5)}"
    _redirected_child(
        output,
        ("openssl", "x509", "-in", path, "-noout", "-startdate", "-enddate"),
        pass_fds=pass_fds,
    )
    try:
        lines = _read_and_remove(output, 4096).decode("ascii").splitlines()
        if (
            len(lines) != 2
            or not lines[0].startswith("notBefore=")
            or not lines[1].startswith("notAfter=")
        ):
            raise ValueError
        values = []
        for line in lines:
            parsed = datetime.datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
            values.append(int(parsed.replace(tzinfo=datetime.UTC).timestamp()))
        return values[0], values[1]
    except (UnicodeDecodeError, ValueError):
        _die("Cannot parse certificate validity")


def _validate_child_validity(
    child: str,
    issuer: str,
    safety_days: str,
    stage: str,
    *,
    issuer_fds: tuple[int, ...] = (),
) -> None:
    child_start, child_end = _certificate_dates(child, stage)
    _issuer_start, issuer_end = _certificate_dates(
        issuer, stage, pass_fds=issuer_fds
    )
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    if child_start > now + 300:
        _die("Child certificate notBefore is more than five minutes in the future")
    if child_start > now or child_end <= now:
        _die("Child certificate is not currently valid")
    if child_end > issuer_end - int(safety_days, 10) * 86400:
        _die(
            "Child certificate exceeds issuer validity safety margin of "
            f"{safety_days} day(s)"
        )


@dataclass(slots=True)
class _Transaction:
    pki_dir: str
    root_generation: str
    generation: str
    transaction: str
    transaction_dir: str
    transaction_identity: DirectoryIdentity
    root_dir: str
    authority_dir: str
    reservation: str
    reserved_stage: str
    reserved_identity: FileIdentity
    abandoned_stage: str
    abandoned_identity: FileIdentity
    bootstrap_stage: str
    bootstrap_rollback_identity: FileIdentity
    bootstrap_fingerprint: str
    bootstrap_identity: FileIdentity
    journal: str
    marker: str
    journal_identity: FileIdentity | None = None
    reservation_identity: FileObjectState | None = None
    consumed_identity: FileObjectState | None = None
    stage_dir: str | None = None
    stage_identity: DirectoryIdentity | None = None
    root_stage: str | None = None
    root_stage_identity: DirectoryIdentity | None = None
    authority_identity: DirectoryIdentity | None = None
    active_identity: FileIdentity | None = None
    issued_serial: str | None = None
    root_mutated: bool = False
    committed: bool = False
    recovery_action: str = "none"
    recovery_step: str = "none"
    db_paths: dict[str, str] = field(default_factory=dict)
    db_backups: dict[str, str] = field(default_factory=dict)
    db_pre: dict[str, FileObjectState | object] = field(
        default_factory=lambda: {key: "pending" for key in ROOT_DB_KEYS}
    )
    db_pre_full: dict[str, FileIdentity | object] = field(default_factory=dict)
    db_post: dict[str, FileObjectState | object] = field(
        default_factory=lambda: {key: "pending" for key in ROOT_DB_KEYS}
    )
    db_backup: dict[str, FileObjectState | object] = field(
        default_factory=lambda: {key: ABSENT for key in ROOT_DB_KEYS}
    )

    def _identity_value(self, value: object) -> str:
        if value is ABSENT:
            return "absent"
        if value == "pending":
            return "pending"
        assert isinstance(value, FileObjectState)
        return serialize_file_object_state(value)

    def write_journal(self, phase: str, *, committed: bool = False) -> None:
        values: dict[str, str] = {
            "schema": "3",
            "operation": "intermediate-bootstrap",
            "transaction": self.transaction,
            "phase": phase,
            "root_generation": self.root_generation,
            "intermediate_generation": self.generation,
            "root_dir": self.root_dir,
            "intermediate_dir": self.authority_dir,
            "intermediate_identity": (
                serialize_directory_identity(self.authority_identity)
                if self.authority_identity is not None
                else "none"
            ),
            "stage_dir": self.stage_dir or "none",
            "stage_identity": (
                serialize_directory_identity(self.stage_identity)
                if self.stage_identity is not None
                else "none"
            ),
            "root_stage": self.root_stage or "none",
            "root_stage_identity": (
                serialize_directory_identity(self.root_stage_identity)
                if self.root_stage_identity is not None
                else "none"
            ),
            "transaction_dir": self.transaction_dir,
            "transaction_identity": serialize_directory_identity(self.transaction_identity),
            "bootstrap_fingerprint": self.bootstrap_fingerprint,
            "issued_serial": self.issued_serial or "none",
            "reservation": self.reservation,
            "reservation_identity": (
                serialize_file_object_state(self.reservation_identity)
                if self.reservation_identity is not None
                else "absent"
            ),
            "reservation_reserved_identity": serialize_file_object_state(
                self.reserved_identity.state
            ),
            "reservation_consumed_identity": (
                serialize_file_object_state(self.consumed_identity)
                if self.consumed_identity is not None
                else "absent"
            ),
            "reservation_abandoned_identity": serialize_file_object_state(
                self.abandoned_identity.state
            ),
            "active_identity": (
                serialize_file_identity(self.active_identity)
                if self.active_identity is not None
                else "absent"
            ),
            "bootstrap_identity": serialize_file_identity(self.bootstrap_identity),
            "bootstrap_rollback_identity": serialize_file_object_state(
                self.bootstrap_rollback_identity.state
            ),
            "root_mutated": "true" if self.root_mutated else "false",
            "recovery_action": self.recovery_action,
            "recovery_step": self.recovery_step,
        }
        for key in ROOT_DB_KEYS:
            values[f"root_{key}_pre_identity"] = self._identity_value(self.db_pre[key])
            values[f"root_{key}_post_identity"] = self._identity_value(self.db_post[key])
            values[f"root_{key}_backup_identity"] = self._identity_value(
                self.db_backup[key]
            )
        values["committed"] = "true" if committed else "false"
        data = _record_bytes(values)
        try:
            parse_recovery_semantics(data, pki_dir=self.pki_dir)
        except RecoveryRecordError:
            _die("Intermediate bootstrap recovery journal could not be validated")
        with _defer_handled_signals():
            self.journal_identity = _atomic_write(
                self.journal,
                data,
                expected=self.journal_identity if self.journal_identity is not None else ABSENT,
            )

    def checkpoint(self, point: str, environment: Mapping[str, str]) -> None:
        if point not in INTERMEDIATE_FAULT_CHECKPOINTS:
            raise ValueError("unknown intermediate bootstrap checkpoint")
        crash_variable, signal_variable, failure_variable = INTERMEDIATE_FAULT_VARIABLES
        if environment.get(crash_variable) == point:
            os.kill(os.getpid(), signal.SIGKILL)
        if environment.get(signal_variable) == point:
            raise _SignalExit(143)
        if environment.get(failure_variable) == point:
            _die(f"Injected intermediate bootstrap failure at {point}")

    def publish_marker(self) -> None:
        current = _actual(self.marker)
        expected = current if isinstance(current, FileIdentity) else ABSENT
        with _defer_handled_signals():
            _atomic_write(
                self.marker,
                (
                    f"transaction={self.transaction}\n"
                    "action=run platform-pki-ca-rollover recover\n"
                ).encode("ascii"),
                expected=expected,
            )

    def rollback(self) -> None:
        active = f"{self.pki_dir}/state/active-issuer"
        bootstrap = f"{self.pki_dir}/state/bootstrap-root"
        current_active = _actual(active)
        if current_active is not ABSENT and (
            self.active_identity is None or not _matches(current_active, self.active_identity)
        ):
            _die("Active issuer manifest identity changed before rollback")
        current_bootstrap = _actual(bootstrap)
        if current_bootstrap is not ABSENT and not (
            _matches(current_bootstrap, self.bootstrap_identity)
            or _matches(current_bootstrap, self.bootstrap_rollback_identity.state)
        ):
            _die("Bootstrap root manifest identity changed before rollback")
        if current_bootstrap is ABSENT and not _matches(
            _actual(self.bootstrap_stage), self.bootstrap_rollback_identity
        ):
            _die("Bootstrap rollback stage changed before rollback")
        current_authority = _actual(self.authority_dir)
        if current_authority is not ABSENT and (
            self.authority_identity is None
            or not _matches(current_authority, self.authority_identity)
        ):
            _die("Published intermediate authority identity changed before rollback")
        current_stage = ABSENT if self.stage_dir is None else _actual(self.stage_dir)
        if current_stage is not ABSENT and (
            self.stage_identity is None or not _matches(current_stage, self.stage_identity)
        ):
            _die("Intermediate authority staging identity changed before rollback")
        current_reservation = _actual(self.reservation)
        allowed_reservations: list[object] = [
            self.reserved_identity.state,
            self.abandoned_identity.state,
        ]
        if self.consumed_identity is not None:
            allowed_reservations.append(self.consumed_identity)
        if current_reservation is not ABSENT and not any(
            _matches(current_reservation, value) for value in allowed_reservations
        ):
            _die("Intermediate generation reservation changed before rollback")
        if not _matches(current_reservation, self.abandoned_identity.state) and not _matches(
            _actual(self.abandoned_stage), self.abandoned_identity
        ):
            _die("Abandoned intermediate reservation stage changed before rollback")

        db_current: dict[str, FileIdentity | object] = {}
        if self.root_mutated:
            for key in ROOT_DB_KEYS:
                current = _actual(self.db_paths[key])
                db_current[key] = current
                allowed = (self.db_pre[key], self.db_post[key], self.db_backup[key])
                if not any(_matches(current, value) for value in allowed):
                    _die(f"Root {key} identity changed before rollback")
                if (
                    _matches(current, self.db_post[key])
                    and self.db_pre[key] != self.db_post[key]
                    and self.db_pre[key] is not ABSENT
                    and not _matches(_actual(self.db_backups[key]), self.db_backup[key])
                ):
                    _die(f"Root {key} rollback copy changed before rollback")

        self.recovery_action = "rollback"
        if current_active is not ABSENT:
            assert self.active_identity is not None
            self.recovery_step = "active-pending"
            self.write_journal("recovering")
            with _defer_handled_signals():
                _unlink(active, self.active_identity, "Cannot remove active issuer manifest")
            self.recovery_step = "active-done"
            self.write_journal("recovering")
        if current_bootstrap is ABSENT:
            self.recovery_step = "bootstrap-pending"
            self.write_journal("recovering")
            with _defer_handled_signals():
                _publish_file(
                    self.bootstrap_stage,
                    bootstrap,
                    self.bootstrap_rollback_identity,
                    ABSENT,
                )
            self.recovery_step = "bootstrap-done"
            self.write_journal("recovering")
        if self.root_mutated:
            for key in ROOT_DB_KEYS:
                current = db_current[key]
                if _matches(current, self.db_post[key]) and self.db_pre[key] != self.db_post[key]:
                    self.recovery_step = f"root-{key}-pending"
                    self.write_journal("recovering")
                    if self.db_pre[key] is ABSENT:
                        assert isinstance(current, FileIdentity)
                        with _defer_handled_signals():
                            _unlink(
                                self.db_paths[key],
                                current,
                                f"Cannot remove published root {key}",
                            )
                    else:
                        backup = _actual(self.db_backups[key])
                        assert isinstance(backup, FileIdentity) and isinstance(current, FileIdentity)
                        with _defer_handled_signals():
                            _publish_file(
                                self.db_backups[key],
                                self.db_paths[key],
                                backup,
                                current,
                            )
                    self.recovery_step = f"root-{key}-done"
                    self.write_journal("recovering")
        if current_authority is not ABSENT:
            assert self.authority_identity is not None
            self.recovery_step = "authority-pending"
            self.write_journal("recovering")
            with _defer_handled_signals():
                _remove_tree(
                    self.authority_dir,
                    self.authority_identity,
                    "Cannot remove published intermediate authority",
                )
            self.recovery_step = "authority-done"
            self.write_journal("recovering")
        if current_stage is not ABSENT:
            assert self.stage_dir is not None and self.stage_identity is not None
            self.recovery_step = "stage-pending"
            self.write_journal("recovering")
            with _defer_handled_signals():
                _remove_tree(
                    self.stage_dir,
                    self.stage_identity,
                    "Cannot remove intermediate bootstrap staging",
                )
                self.stage_dir = None
                self.stage_identity = None
                self.root_stage = None
                self.root_stage_identity = None
            self.recovery_step = "stage-done"
            self.write_journal("recovering")
        if not _matches(current_reservation, self.abandoned_identity.state):
            self.recovery_step = "reservation-pending"
            self.write_journal("recovering")
            destination = _actual(self.reservation)
            with _defer_handled_signals():
                published = _publish_file(
                    self.abandoned_stage,
                    self.reservation,
                    self.abandoned_identity,
                    destination,
                )
                self.reservation_identity = published.state
            self.recovery_step = "reservation-done"
            self.write_journal("recovering")
        else:
            self.reservation_identity = self.abandoned_identity.state
        self.recovery_step = "complete"
        self.write_journal("rolled-back", committed=True)
        # Final Bash intentionally performs an unbound rm -f here; recovery does too.
        parent, name = _parent(self.marker)
        try:
            try:
                os.unlink(name, dir_fd=parent.fileno())
            except FileNotFoundError:
                pass
            os.fsync(parent.fileno())
        except OSError:
            _die("Recovery marker cleanup failed")
        finally:
            parent.close()


def _create_transaction(
    pki_dir: str,
    root: str,
    generation: str,
    fingerprint: str,
    bootstrap_identity: FileIdentity,
) -> _Transaction:
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    transaction = f"intermediate-bootstrap-{timestamp}-{os.getpid()}"
    transaction_dir = f"{pki_dir}/state/rollover/{transaction}"
    transaction_identity: DirectoryIdentity | None = None
    created = False
    try:
        with OpenedDirectory(f"{pki_dir}/state/rollover", policy=_PRIVATE_DIRECTORY) as parent:
            os.mkdir(transaction, 0o700, dir_fd=parent.fileno())
            created = True
            try:
                with parent.open_directory(transaction, policy=_PRIVATE_DIRECTORY) as opened:
                    transaction_identity = opened.directory_identity
            except BaseException:
                _remove_empty_created_directory(
                    parent,
                    transaction,
                    "Intermediate bootstrap setup retained an unidentified transaction directory",
                )
                created = False
                raise
        reserved_path = f"{transaction_dir}/reservation-reserved"
        abandoned_path = f"{transaction_dir}/reservation-abandoned"
        bootstrap_path = f"{transaction_dir}/bootstrap-rollback"
        reserved = _atomic_write(
            reserved_path, _reservation_bytes(generation, transaction, "reserved")
        )
        abandoned = _atomic_write(
            abandoned_path, _reservation_bytes(generation, transaction, "abandoned")
        )
        bootstrap = _atomic_write(
            bootstrap_path,
            f"root={root}\nfingerprint_sha256={fingerprint}\n".encode("ascii"),
        )
        with OpenedDirectory(f"{pki_dir}/state/rollover", policy=_PRIVATE_DIRECTORY) as parent:
            with parent.open_directory(transaction, policy=_PRIVATE_DIRECTORY) as opened:
                fsync_tree(opened, parent, transaction)
                transaction_identity = opened.directory_identity
    except BaseException as error:
        if created and transaction_identity is not None:
            try:
                _remove_tree(
                    transaction_dir,
                    transaction_identity,
                    "Cannot remove failed intermediate transaction setup",
                )
            except BaseException as cleanup_error:
                raise ApplicationError(
                    "Intermediate bootstrap setup failed and retained an identity-bound transaction directory"
                ) from cleanup_error
        if isinstance(error, ApplicationError):
            raise
        _die("Cannot create intermediate bootstrap transaction directory")
    assert transaction_identity is not None
    journal = f"{pki_dir}/state/rollover/journal"
    current_journal = _actual(journal)
    if current_journal is not ABSENT and not isinstance(current_journal, FileIdentity):
        _die("Existing intermediate bootstrap recovery journal is unsafe")
    return _Transaction(
        pki_dir=pki_dir,
        root_generation=root,
        generation=generation,
        transaction=transaction,
        transaction_dir=transaction_dir,
        transaction_identity=transaction_identity,
        root_dir=f"{pki_dir}/authorities/roots/{root}",
        authority_dir=f"{pki_dir}/authorities/intermediates/{generation}",
        reservation=f"{pki_dir}/state/generation-reservations/{generation}",
        reserved_stage=reserved_path,
        reserved_identity=reserved,
        abandoned_stage=abandoned_path,
        abandoned_identity=abandoned,
        bootstrap_stage=bootstrap_path,
        bootstrap_rollback_identity=bootstrap,
        bootstrap_fingerprint=fingerprint,
        bootstrap_identity=bootstrap_identity,
        journal=journal,
        marker=f"{pki_dir}/state/rollover/recovery-required",
        journal_identity=current_journal if isinstance(current_journal, FileIdentity) else None,
    )


def _create_stage(transaction: _Transaction) -> None:
    parent_path = f"{transaction.pki_dir}/authorities/intermediates"
    created_name: str | None = None
    created_identity: DirectoryIdentity | None = None
    try:
        with _defer_handled_signals():
            with OpenedDirectory(parent_path, policy=_PRIVATE_DIRECTORY) as parent:
                for _attempt in range(32):
                    name = f".platform-pki-intermediate-create.{secrets.token_urlsafe(4)}"
                    try:
                        os.mkdir(name, 0o700, dir_fd=parent.fileno())
                    except FileExistsError:
                        continue
                    created_name = name
                    break
                else:
                    _die("Cannot create intermediate staging directory")
                try:
                    with parent.open_directory(name, policy=_PRIVATE_DIRECTORY) as stage:
                        created_identity = stage.directory_identity
                except BaseException:
                    _remove_empty_created_directory(
                        parent,
                        name,
                        "Intermediate staging setup retained an unidentified directory",
                    )
                    created_name = None
                    raise
                transaction.stage_dir = f"{parent_path}/{name}"
                transaction.stage_identity = created_identity
    except (OSError, FilesystemError) as error:
        if created_name is not None and created_identity is not None:
            try:
                _remove_tree(
                    f"{parent_path}/{created_name}",
                    created_identity,
                    "Cannot remove failed intermediate staging setup",
                )
            except BaseException as cleanup_error:
                raise ApplicationError(
                    "Intermediate staging setup retained an identity-bound private directory"
                ) from cleanup_error
        if isinstance(error, ApplicationError):
            raise
        _die("Cannot create intermediate staging directory")


def _stage_authorities(
    transaction: _Transaction,
    country: str,
    organization: str,
    name: str,
    days: str,
    safety_days: str,
    root_passphrase: OpenedFile | None,
    intermediate_passphrase: OpenedFile | None,
    unencrypted: bool,
) -> tuple[str, FileIdentity, FileIdentity, FileIdentity]:
    assert transaction.stage_dir is not None
    stage = transaction.stage_dir
    stage_root = f"{stage}/root"
    stage_intermediate = f"{stage}/intermediate"
    backup = f"{stage}/root-backup"
    directories = (
        stage_root,
        f"{stage_root}/private",
        f"{stage_root}/certs",
        f"{stage_root}/newcerts",
        f"{stage_root}/crl",
        stage_intermediate,
        f"{stage_intermediate}/private",
        f"{stage_intermediate}/certs",
        f"{stage_intermediate}/csr",
        f"{stage_intermediate}/newcerts",
        f"{stage_intermediate}/crl",
        backup,
    )
    try:
        for directory in directories:
            os.mkdir(directory, 0o700)
        with OpenedDirectory(stage_root, policy=_PRIVATE_DIRECTORY) as opened_root:
            transaction.root_stage = stage_root
            transaction.root_stage_identity = opened_root.directory_identity
    except (OSError, FilesystemError):
        _die("Intermediate authority staging directories could not be created safely")

    root_key = f"{transaction.root_dir}/private/root-ca.key"
    root_certificate = f"{transaction.root_dir}/certs/root-ca.crt"
    root_key_identity, _staged_root_key_identity = _copy_file(
        root_key,
        f"{stage_root}/private/root-ca.key",
        source_policy=_PRIVATE_FILE,
        destination_mode=0o600,
    )
    staged_root_certificate = f"{stage_root}/certs/root-ca.crt"
    root_certificate_identity, staged_root_certificate_identity = _copy_file(
        root_certificate,
        staged_root_certificate,
        source_policy=_PUBLIC_CERTIFICATE,
        destination_mode=0o644,
    )
    relatives = {
        "index": "index.txt",
        "index_attr": "index.txt.attr",
        "serial": "serial",
        "crlnumber": "crlnumber",
        "index_old": "index.txt.old",
        "index_attr_old": "index.txt.attr.old",
        "serial_old": "serial.old",
        "crlnumber_old": "crlnumber.old",
    }
    for key in ROOT_DB_KEYS[:-1]:
        relative = relatives[key]
        source = f"{transaction.root_dir}/{relative}"
        copied = _copy_root_database_source(
            source,
            f"{stage_root}/{relative}",
            f"{backup}/{relative}",
            required=key in ("index", "index_attr", "serial", "crlnumber"),
        )
        if copied is None:
            transaction.db_pre[key] = ABSENT
            transaction.db_pre_full[key] = ABSENT
            continue
        source_identity, _staged_identity, backup_identity = copied
        transaction.db_backup[key] = backup_identity.state
        transaction.db_pre[key] = source_identity.state
        transaction.db_pre_full[key] = source_identity
    _write_new_file(
        f"{stage_root}/openssl.cnf",
        _root_config(country, organization, name, stage_root),
        0o600,
    )
    for relative, data in (
        ("index.txt", b""),
        ("index.txt.attr", b"unique_subject = no\n"),
        ("serial", b"1000\n"),
        ("crlnumber", b"1000\n"),
    ):
        _write_new_file(f"{stage_intermediate}/{relative}", data, 0o600)
    _write_new_file(
        f"{stage_intermediate}/openssl.cnf",
        _intermediate_config(
            country, organization, name, transaction.authority_dir
        ),
        0o600,
    )

    intermediate_key = f"{stage_intermediate}/private/intermediate-ca.key"
    intermediate_csr = f"{stage_intermediate}/csr/intermediate-ca.csr"
    intermediate_certificate = f"{stage_intermediate}/certs/intermediate-ca.crt"
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
            "[WARN] Creating an unencrypted intermediate CA private key because "
            "--allow-unencrypted-intermediate-key was used",
            file=sys.stderr,
            flush=True,
        )
        _run_child((*genpkey, "-out", intermediate_key))
    else:
        _run_with_passphrase(
            intermediate_passphrase,
            (*genpkey, "-aes-256-cbc", "-out", intermediate_key),
            "-pass",
        )
    _secure_generated_file(intermediate_key, 0o600)
    _run_with_passphrase(
        intermediate_passphrase,
        (
            "openssl",
            "req",
            "-config",
            f"{stage_intermediate}/openssl.cnf",
            "-key",
            intermediate_key,
            "-new",
            "-sha384",
            "-out",
            intermediate_csr,
        ),
        "-passin",
    )
    _secure_generated_file(intermediate_csr, 0o600)

    raw_serial = ""
    try:
        with OpenedFile(f"{stage_root}/serial", policy=_PRIVATE_FILE) as serial_file:
            raw_serial = serial_file.read(4096).decode("ascii").strip()
    except (FilesystemError, UnicodeDecodeError):
        _die("Root CA serial is invalid")
    if _SERIAL.fullmatch(raw_serial) is None:
        _die("Root CA serial is invalid")
    issued = raw_serial.upper()
    while issued.startswith("00") and len(issued) > 2:
        issued = issued[2:]
    transaction.issued_serial = issued
    transaction.db_paths = {
        **{
            key: f"{transaction.root_dir}/{relative}"
            for key, relative in relatives.items()
        },
        "newcert": f"{transaction.root_dir}/newcerts/{issued}.pem",
    }
    transaction.db_backups = {
        **{key: f"{backup}/{relative}" for key, relative in relatives.items()},
        "newcert": "none",
    }
    current_newcert = _actual(transaction.db_paths["newcert"])
    if current_newcert is not ABSENT:
        _die("Root issued-certificate destination already exists")
    transaction.db_pre["newcert"] = ABSENT
    transaction.db_pre_full["newcert"] = ABSENT

    _run_with_passphrase(
        root_passphrase,
        (
            "openssl",
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
            intermediate_csr,
            "-out",
            intermediate_certificate,
        ),
        "-passin",
    )
    _secure_generated_file(intermediate_certificate, 0o644)
    child_data = b""
    root_data = b""
    try:
        with OpenedFile(intermediate_certificate, policy=_PUBLIC_CERTIFICATE) as child:
            child_data = child.read(_MAX_CERTIFICATE)
        with OpenedFile(
            staged_root_certificate,
            policy=_PUBLIC_CERTIFICATE,
            expected_identity=staged_root_certificate_identity,
        ) as root_file:
            root_data = root_file.read(_MAX_CERTIFICATE)
            root_reference = f"/proc/self/fd/{root_file.fileno()}"
            root_fds = (root_file.fileno(),)
            _run_child(
                (
                    "openssl",
                    "verify",
                    "-CAfile",
                    root_reference,
                    intermediate_certificate,
                ),
                pass_fds=root_fds,
                stdout=subprocess.DEVNULL,
            )
            _validate_child_validity(
                intermediate_certificate,
                root_reference,
                safety_days,
                stage,
                issuer_fds=root_fds,
            )
            if (
                _certificate_fingerprint(
                    root_reference, stage, pass_fds=root_fds
                )
                != transaction.bootstrap_fingerprint
            ):
                _die(
                    "Bootstrap root manifest fingerprint does not match the root certificate"
                )
            root_file.recheck()
    except FilesystemError:
        _die("CA chain source changed during intermediate creation")
    _write_new_file(
        f"{stage_intermediate}/certs/ca-chain.crt", child_data + root_data, 0o644
    )
    return (
        _certificate_fingerprint(intermediate_certificate, stage),
        root_key_identity,
        root_certificate_identity,
        staged_root_certificate_identity,
    )


def _publish_authority(transaction: _Transaction) -> None:
    assert transaction.stage_dir is not None and transaction.stage_identity is not None
    source = f"{transaction.stage_dir}/intermediate"
    identity: FileIdentity | None = None
    readiness = None
    try:
        with _defer_handled_signals():
            source_parent, source_name = _parent(source)
            destination_parent, destination_name = _parent(transaction.authority_dir)
            try:
                with source_parent.open_directory(
                    source_name, policy=_PRIVATE_DIRECTORY
                ) as authority:
                    readiness = fsync_tree(authority, source_parent, source_name)
                    identity = authority.identity
                assert identity is not None and readiness is not None
                result = publish_no_clobber(
                    source_parent,
                    source_name,
                    identity,
                    destination_parent,
                    destination_name,
                    readiness=readiness,
                )
                transaction.authority_identity = _publication_identity(result).directory
            finally:
                destination_parent.close()
                source_parent.close()
    except (FilesystemError, PublicationError):
        _die(f"Cannot publish intermediate generation: {transaction.authority_dir}")


def _prepare_db_post(transaction: _Transaction) -> None:
    assert transaction.root_stage is not None and transaction.issued_serial is not None
    relatives = {
        "index": "index.txt",
        "index_attr": "index.txt.attr",
        "serial": "serial",
        "crlnumber": "crlnumber",
        "index_old": "index.txt.old",
        "index_attr_old": "index.txt.attr.old",
        "serial_old": "serial.old",
        "crlnumber_old": "crlnumber.old",
        "newcert": f"newcerts/{transaction.issued_serial}.pem",
    }
    for key in ROOT_DB_KEYS:
        current = _actual(f"{transaction.root_stage}/{relatives[key]}")
        if current is ABSENT:
            transaction.db_post[key] = transaction.db_pre[key]
        else:
            assert isinstance(current, FileIdentity)
            transaction.db_post[key] = current.state
    if transaction.db_post["newcert"] is ABSENT:
        _die("OpenSSL did not stage the issued intermediate certificate")


def _publish_root_db(
    transaction: _Transaction, environment: Mapping[str, str]
) -> None:
    assert transaction.root_stage is not None and transaction.issued_serial is not None
    relatives = {
        "index": "index.txt",
        "index_attr": "index.txt.attr",
        "serial": "serial",
        "crlnumber": "crlnumber",
        "index_old": "index.txt.old",
        "index_attr_old": "index.txt.attr.old",
        "serial_old": "serial.old",
        "crlnumber_old": "crlnumber.old",
        "newcert": f"newcerts/{transaction.issued_serial}.pem",
    }
    for key in ROOT_DB_KEYS:
        source = f"{transaction.root_stage}/{relatives[key]}"
        source_actual = _actual(source)
        if source_actual is ABSENT:
            continue
        assert isinstance(source_actual, FileIdentity)
        transaction.write_journal(f"root-{key}-pending")
        transaction.checkpoint(f"root-{key}-pending", environment)
        destination_actual = _actual(transaction.db_paths[key])
        expected = transaction.db_pre_full[key]
        if not _matches(destination_actual, expected):
            _die(f"Root {key} identity changed before publication")
        with _defer_handled_signals():
            published = _publish_file(
                source,
                transaction.db_paths[key],
                source_actual,
                destination_actual,
            )
            if published.state != transaction.db_post[key]:
                _die(f"Published root {key} identity is invalid")
        transaction.write_journal(f"root-{key}-done")
        transaction.checkpoint(f"root-{key}-done", environment)


def _abort(transaction: _Transaction, original: BaseException) -> NoReturn:
    try:
        transaction.publish_marker()
        transaction.rollback()
    except BaseException as rollback_error:
        raise ApplicationError(
            "Intermediate bootstrap rollback failed; retained recovery evidence "
            "requires platform-pki-ca-rollover recover"
        ) from rollback_error
    raise original


def _run_transaction(
    pki_dir: str,
    country: str,
    organization: str,
    name: str,
    days: str,
    safety_days: str,
    root_passphrase: OpenedFile | None,
    intermediate_passphrase: OpenedFile | None,
    unencrypted: bool,
    force: bool,
    environment: Mapping[str, str],
) -> int:
    active = f"{pki_dir}/state/active-issuer"
    bootstrap = f"{pki_dir}/state/bootstrap-root"
    if os.path.lexists(f"{pki_dir}/root-ca") or os.path.lexists(
        f"{pki_dir}/intermediate-ca"
    ):
        _die(
            "Legacy PKI state requires migration; create a fresh backup and follow "
            "platform-pki-ca-rollover status/migrate"
        )
    if os.path.lexists(active):
        _die(
            "An active issuer exists; use platform-pki-ca-rollover instead of "
            "replacing the intermediate CA"
        )
    if not os.path.lexists(bootstrap):
        _die("Bootstrap root manifest is missing; create the root CA first")
    root, bootstrap_fingerprint, bootstrap_identity = _read_bootstrap(bootstrap)
    root_dir = f"{pki_dir}/authorities/roots/{root}"
    try:
        with OpenedDirectory(root_dir, policy=_PRIVATE_DIRECTORY):
            pass
    except FilesystemError:
        _die(f"Root authority generation must be current-user-owned with mode 700: {root_dir}")
    if force:
        _die(
            "--force cannot delete unproven intermediate state; recover the "
            "journaled disposable transaction instead"
        )
    generation = _next_generation(pki_dir, root)
    transaction: _Transaction | None = None
    try:
        with _defer_handled_signals():
            transaction = _create_transaction(
                pki_dir,
                root,
                generation,
                bootstrap_fingerprint,
                bootstrap_identity,
            )
            transaction.write_journal("prepared")
        transaction.checkpoint("after-journal", environment)

        with _defer_handled_signals():
            reservation = _publish_file(
                transaction.reserved_stage,
                transaction.reservation,
                transaction.reserved_identity,
                ABSENT,
            )
            transaction.reservation_identity = reservation.state
        transaction.write_journal("reserved")
        transaction.checkpoint("after-reservation", environment)

        _create_stage(transaction)
        transaction.write_journal("staged")
        (
            fingerprint,
            root_key_identity,
            root_certificate_identity,
            staged_root_certificate_identity,
        ) = _stage_authorities(
            transaction,
            country,
            organization,
            name,
            days,
            safety_days,
            root_passphrase,
            intermediate_passphrase,
            unencrypted,
        )
        assert transaction.stage_dir is not None and transaction.root_stage is not None
        root_key = f"{transaction.root_dir}/private/root-ca.key"
        root_certificate = f"{transaction.root_dir}/certs/root-ca.crt"
        staged_root_certificate = f"{transaction.root_stage}/certs/root-ca.crt"
        for passphrase, label in (
            (root_passphrase, "Root passphrase file"),
            (intermediate_passphrase, "Intermediate passphrase file"),
        ):
            if passphrase is not None:
                try:
                    passphrase.recheck()
                except FilesystemError:
                    _die(f"{label} changed during intermediate creation")
        try:
            with OpenedFile(
                staged_root_certificate,
                policy=_PUBLIC_CERTIFICATE,
                expected_identity=staged_root_certificate_identity,
            ) as staged_certificate:
                staged_certificate.recheck()
        except FilesystemError:
            _die("Staged root certificate identity changed during intermediate creation")
        try:
            with OpenedFile(
                root_certificate,
                policy=_PUBLIC_CERTIFICATE,
                expected_identity=root_certificate_identity,
            ) as authoritative_root_certificate:
                authoritative_root_certificate.recheck()
        except FilesystemError:
            _die("Root certificate identity changed during intermediate creation")
        try:
            with OpenedFile(
                root_key,
                policy=_PRIVATE_FILE,
                expected_identity=root_key_identity,
            ) as authoritative_root_key:
                authoritative_root_key.recheck()
        except FilesystemError:
            _die("Root key identity changed during intermediate creation")
        _publish_authority(transaction)
        transaction.write_journal("intermediate-published")
        transaction.checkpoint("after-intermediate", environment)

        with _defer_handled_signals():
            transaction.root_mutated = True
            _prepare_db_post(transaction)
            transaction.write_journal("root-db-pending")
        _publish_root_db(transaction, environment)
        transaction.write_journal("root-db-published")
        transaction.checkpoint("after-root-db", environment)

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
            _die("Reserved intermediate generation identity changed")
        with _defer_handled_signals():
            published = _publish_file(
                consumed_stage,
                transaction.reservation,
                consumed,
                current_reservation,
            )
            transaction.reservation_identity = published.state
        transaction.write_journal("reservation-consumed")
        transaction.checkpoint("after-reservation-consumed", environment)

        with _defer_handled_signals():
            transaction.active_identity = _atomic_write(
                active,
                f"root={root}\nintermediate={generation}\n".encode("ascii"),
            )
            transaction.write_journal("active-published")
        transaction.checkpoint("after-active", environment)

        current_bootstrap = _actual(bootstrap)
        if not _matches(current_bootstrap, transaction.bootstrap_identity):
            _die("Bootstrap manifest changed during intermediate creation")
        assert isinstance(current_bootstrap, FileIdentity)
        with _defer_handled_signals():
            _unlink(
                bootstrap,
                current_bootstrap,
                "Cannot remove identity-matched bootstrap manifest",
            )
        transaction.checkpoint("after-bootstrap", environment)

        assert transaction.root_stage is not None and transaction.root_stage_identity is not None
        if not _matches(_actual(transaction.root_stage), transaction.root_stage_identity):
            _die("Sensitive root signing stage identity changed before cleanup")
        transaction.write_journal("cleanup-pending")
        transaction.checkpoint("cleanup-pending", environment)
        with _defer_handled_signals():
            _remove_tree(
                transaction.root_stage,
                transaction.root_stage_identity,
                "Cannot remove sensitive root signing stage",
            )
        transaction.checkpoint("cleanup-removed", environment)
        transaction.write_journal("cleanup-done")
        transaction.checkpoint("cleanup-done", environment)
        with _defer_handled_signals():
            transaction.write_journal("complete", committed=True)
            transaction.root_mutated = False
            transaction.committed = True
        assert transaction.stage_dir is not None and transaction.stage_identity is not None
        _remove_tree(
            transaction.stage_dir,
            transaction.stage_identity,
            "Cannot remove completed intermediate bootstrap staging",
        )
    except (_ChildFailure, _SignalExit, ApplicationError) as error:
        if transaction is None:
            raise
        if transaction.committed:
            raise
        _abort(transaction, error)
    except (OSError, FilesystemError, PublicationError):
        if transaction is None:
            raise ApplicationError("Intermediate CA creation failed safely") from None
        if transaction.committed:
            raise ApplicationError("Intermediate CA creation completed but final reporting failed") from None
        _abort(transaction, ApplicationError("Intermediate CA creation failed safely"))

    print(
        f"[OK] Created intermediate CA generation {generation}: "
        f"{transaction.authority_dir}/certs/intermediate-ca.crt",
        flush=True,
    )
    return 0


def create_intermediate(parsed: ParseResult) -> int:
    """Create the first intermediate through compatibility or unified dispatch."""

    environment = dict(os.environ)
    require_pilot_common_library(environment)
    name = str(parsed["--name"])
    organization = str(parsed["--org"])
    country = str(parsed["--country"])
    days = _validate_days(
        str(
            parsed.values.get("--days")
            or environment.get("PLATFORM_PKI_INTERMEDIATE_DAYS")
            or "1825"
        )
    )
    safety_days = _validate_days(str(parsed["--issuer-safety-days"]))
    _validate_config_value("Intermediate CA common name", name)
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
        pki_value if pki_value is not None else f"{namespace}/pki", home=home
    )
    _validate_config_value("PKI directory", raw_pki_dir)
    paths = resolve_paths(parsed.values, environment)
    _validate_config_value("PKI directory", paths.pki_dir)
    _validate_record_path("PKI directory", paths.pki_dir)
    root_path = _expand_passphrase(parsed.values.get("--root-pass-file"), environment)
    intermediate_path = _expand_passphrase(
        parsed.values.get("--intermediate-pass-file"), environment
    )
    root_passphrase = _open_passphrase_file(root_path) if root_path is not None else None
    intermediate_passphrase = (
        _open_passphrase_file(intermediate_path)
        if intermediate_path is not None
        else None
    )
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
            with acquire_operational_locks(paths.pki_dir, "intermediate"):
                require_no_unresolved_state(paths.pki_dir)
                return _run_transaction(
                    paths.pki_dir,
                    country,
                    organization,
                    name,
                    days,
                    safety_days,
                    root_passphrase,
                    intermediate_passphrase,
                    "--allow-unencrypted-intermediate-key" in parsed.provided,
                    "--force" in parsed.provided,
                    environment,
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
