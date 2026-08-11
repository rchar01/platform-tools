"""Non-public managed-custody service issuance orchestration."""

from __future__ import annotations

import datetime
import hashlib
import io
import os
import re
import secrets
import shutil
import signal
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from types import FrameType
from typing import NoReturn, TextIO

from .ca_passphrase_verify import _fresh_descriptor, _open_passphrase
from .errors import ApplicationError
from .faults import DEFAULT_FAULT_HOOK, DEFAULT_PAUSE_HOOK, FaultHook, PauseHook
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
)
from .inventory import InventoryError, InventoryService, parse_inventory
from .operational import (
    acquire_operational_locks,
    load_active_issuer,
    prepare_control_state,
    require_generation_layout,
    require_pki_directory,
    require_program,
)
from .persisted_identity import (
    serialize_directory_identity,
    serialize_file_identity,
)
from .service_recover import (
    SERVICE_BOOTSTRAP_RELATIVE_PATH,
    clear_service_bootstrap,
    publish_service_bootstrap,
    recover_service_transaction,
)
from .service_transaction import (
    SERVICE_CONTAINER_ORDER,
    SERVICE_RETAINED_TRANSACTION_FIELDS,
    SERVICE_SIGNING_INPUT_KEYS,
    SERVICE_TRANSACTION_FIELDS,
    SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH,
    SERVICE_TRANSACTION_TREE_RELATIVE_PATH,
    ServiceArchiveState,
    ServiceKeyAction,
    ServiceOperation,
    managed_publication_order,
    serialize_service_retained_transaction,
)
from .service_writer import ManagedServiceWriter
from .subprocesses import ProcessResult, run_process


_OWNER = os.geteuid()
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_SAFE_DIRECTORY = DirectoryPolicy(owner=_OWNER, forbidden_bits=0o022)
_MAX_EVIDENCE = 64 * 1024 * 1024
_PROCESS_OPTIONS = {
    "timeout": 120.0,
    "term_grace": 1.0,
    "stdout_limit": 4 * 1024 * 1024,
    "stderr_limit": 1024 * 1024,
}
_HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
_SERIAL = re.compile(r"[0-9A-Fa-f]+", re.ASCII)
_ARCHIVE_NAME = re.compile(r"[0-9]{8}-[0-9]{6}(?:-[0-9]{2})?", re.ASCII)
_OPENSSL_PATH = re.compile(r"/[A-Za-z0-9._/-]+", re.ASCII)

SERVICE_ISSUE_CHECKPOINTS = (
    "planning-after-journal",
    "openssl-before-mutation",
    "openssl-after-mutation",
    "verification-before-mutation",
    "verification-after-mutation",
    "commit-after-mutation",
)

_DIRECTORY_DESTINATIONS = {
    "service_root": "services/{service}",
    "service_private_dir": "services/{service}/private",
    "service_csr_dir": "services/{service}/csr",
    "service_certs_dir": "services/{service}/certs",
    "service_chain_dir": "services/{service}/chain",
    "archive_root": "services/{service}/archive",
    "archive_dir": "services/{service}/archive/{archive}",
}
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
    "archive_key": "services/{service}/archive/{archive}/tls.key",
}
_SIGNING_INPUT_SOURCES = {
    "signing_inventory": "inventory/services.yml",
    "signing_root_certificate": "authorities/roots/{root}/certs/root-ca.crt",
    "signing_ca_key": (
        "authorities/intermediates/{intermediate}/private/intermediate-ca.key"
    ),
    "signing_ca_certificate": (
        "authorities/intermediates/{intermediate}/certs/intermediate-ca.crt"
    ),
    "signing_ca_config": "authorities/intermediates/{intermediate}/openssl.cnf",
    "signing_ca_crlnumber": "authorities/intermediates/{intermediate}/crlnumber",
    "signing_service_key": "services/{service}/private/tls.key",
}
_PRIVATE_INPUTS = {
    "signing_ca_key",
    "signing_ca_config",
    "signing_ca_crlnumber",
    "signing_service_key",
}
_PRIVATE_DESTINATIONS = {
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
    "archive_key",
}
_FIXED_OUTPUT_MODES = {
    "service_csr": 0o600,
    "service_certificate": 0o644,
    "service_chain": 0o644,
    "service_fullchain": 0o644,
    "service_issuer": 0o600,
    "ca_index": 0o600,
    "ca_index_attr": 0o600,
    "ca_serial": 0o600,
    "ca_newcert": 0o600,
    "service_key": 0o600,
}


class _SignalExit(ApplicationError):
    pass


@dataclass(frozen=True, slots=True)
class _Evidence:
    path: str
    identity: FileIdentity
    digest: str
    data: bytes | None = None


@dataclass(slots=True)
class _DetachedFile:
    descriptor: int
    mode: int
    mtime_ns: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass(slots=True)
class _Plan:
    pki_dir: str
    service: InventoryService
    root: str
    intermediate: str
    days: str
    safety_days: str
    transaction: str
    work_dir: str
    values: dict[str, str]
    evidence: dict[str, _Evidence]


@dataclass(slots=True)
class _Setup:
    transaction: str | None = None


def _die(message: str, *, status: int = 1) -> NoReturn:
    raise ApplicationError(message, status=status)


def _checkpoint(point: str, fault: FaultHook, pause: PauseHook) -> None:
    fault(point)
    pause(point)


@contextmanager
def _handled_signals() -> Iterator[None]:
    previous: dict[signal.Signals, object] = {}

    def stop(signum: int, _frame: FrameType | None) -> NoReturn:
        process_signal = signal.Signals(signum)
        raise _SignalExit(
            f"Managed service issuance interrupted by {process_signal.name}",
            status=128 + signum,
        )

    try:
        for process_signal in _HANDLED_SIGNALS:
            previous[process_signal] = signal.signal(process_signal, stop)
        yield
    finally:
        for process_signal, handler in previous.items():
            signal.signal(process_signal, handler)  # type: ignore[arg-type]


def _validate_days(value: str) -> str:
    if re.fullmatch(r"[0-9]+", value, re.ASCII) is None:
        _die(f"Days value must be numeric: {value}")
    normalized = value.lstrip("0") or "0"
    if len(normalized) > 6 or (len(normalized) == 6 and normalized > "365000"):
        _die(f"Days value must be at most 365000: {value}")
    if normalized == "0":
        _die(f"Days value must be at least 1: {value}")
    return value


def _validate_openssl_value(label: str, value: str) -> None:
    if not value:
        _die(f"{label} must be non-empty")
    if "$" in value:
        _die(f"{label} must not contain OpenSSL variable expansion syntax")
    if "\n" in value or "\r" in value:
        _die(f"{label} must not contain newlines")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        _die(f"{label} must not contain control characters")
    if value[:1].isspace() or value[-1:].isspace():
        _die(f"{label} must not start or end with whitespace")


def _validate_openssl_path(label: str, value: str) -> None:
    _validate_openssl_value(label, value)
    if (
        _OPENSSL_PATH.fullmatch(value) is None
        or "//" in value
        or any(component in {"", ".", ".."} for component in value.split("/")[1:])
    ):
        _die(
            f"{label} must be an absolute path using only letters, digits, slash, "
            "dot, underscore, and hyphen"
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot_file(
    path: str,
    label: str,
    *,
    private: bool,
    required: bool = True,
    keep_data: bool = False,
) -> _Evidence | None:
    data = b""
    identity: FileIdentity | None = None
    if not required and not os.path.lexists(path):
        return None
    try:
        actual = identity_at(path)
    except FilesystemError:
        _die(f"{label} is unsafe: {path}")
    if actual is ABSENT:
        if required:
            _die(f"Required file is missing: {path}")
        return None
    if not isinstance(actual, FileIdentity) or actual.kind != "regular":
        _die(f"{label} must be a regular file: {path}")
    policy = FilePolicy(
        owner=_OWNER,
        forbidden_bits=0o077 if private else 0o022,
        links=1,
        max_size=_MAX_EVIDENCE,
    )
    try:
        with OpenedFile(path, policy=policy, expected_identity=actual) as opened:
            data = opened.read(_MAX_EVIDENCE)
            identity = opened.recheck()
    except FilesystemError:
        _die(f"{label} is unsafe: {path}")
    assert identity is not None
    return _Evidence(path, identity, _sha256(data), data if keep_data else None)


def _snapshot_directory(path: str, label: str) -> DirectoryIdentity | None:
    if not os.path.lexists(path):
        return None
    try:
        actual = identity_at(path)
    except FilesystemError:
        _die(f"{label} must be a non-symlink directory: {path}")
    if actual is ABSENT:
        return None
    if not isinstance(actual, FileIdentity) or actual.kind != "directory":
        _die(f"{label} must be a non-symlink directory: {path}")
    try:
        with OpenedDirectory(
            path,
            policy=_SAFE_DIRECTORY,
            expected_identity=actual,
        ) as opened:
            return opened.recheck().directory
    except FilesystemError:
        _die(f"{label} is group- or world-writable: {path}")


def _ensure_private_child(parent: OpenedDirectory, name: str) -> OpenedDirectory:
    actual = parent.identity_at(name)
    if actual is ABSENT:
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            os.fsync(parent.fileno())
        except OSError:
            _die("Managed service control directory could not be prepared safely")
    try:
        return parent.open_directory(name, policy=_PRIVATE_DIRECTORY)
    except FilesystemError:
        _die("Managed service control directory is unsafe")


def _prepare_service_control(pki_dir: str) -> None:
    try:
        with OpenedDirectory(f"{pki_dir}/state", policy=_PRIVATE_DIRECTORY) as state:
            service = _ensure_private_child(state, "service")
            try:
                transactions = _ensure_private_child(service, "transactions")
                transactions.close()
                history = _ensure_private_child(service, "bootstrap-history")
                history.close()
            finally:
                service.close()
    except FilesystemError:
        _die("Managed service control directory is unsafe")


def _create_transaction_tree(
    pki_dir: str,
    transaction: str,
    fault: FaultHook,
    pause: PauseHook,
) -> tuple[str, str, str, DirectoryIdentity]:
    transaction_identity: DirectoryIdentity | None = None
    try:
        with OpenedDirectory(
            f"{pki_dir}/state", policy=_PRIVATE_DIRECTORY
        ) as state:
            service = _ensure_private_child(state, "service")
            try:
                transactions = _ensure_private_child(service, "transactions")
                try:
                    if transactions.identity_at(transaction) is not ABSENT:
                        _die("Managed service transaction ID already exists")
                    _checkpoint("bootstrap-tree-before-mutation", fault, pause)
                    os.mkdir(transaction, 0o700, dir_fd=transactions.fileno())
                    _checkpoint("bootstrap-tree-after-mutation", fault, pause)
                    os.fsync(transactions.fileno())
                    current = transactions.open_directory(
                        transaction, policy=_PRIVATE_DIRECTORY
                    )
                    try:
                        _checkpoint("bootstrap-stage-dir-before-mutation", fault, pause)
                        os.mkdir("stage", 0o700, dir_fd=current.fileno())
                        _checkpoint("bootstrap-stage-dir-after-mutation", fault, pause)
                        _checkpoint("bootstrap-backup-dir-before-mutation", fault, pause)
                        os.mkdir("backup", 0o700, dir_fd=current.fileno())
                        _checkpoint("bootstrap-backup-dir-after-mutation", fault, pause)
                        stage = current.open_directory("stage", policy=_PRIVATE_DIRECTORY)
                        try:
                            _checkpoint("bootstrap-inputs-dir-before-mutation", fault, pause)
                            os.mkdir("inputs", 0o700, dir_fd=stage.fileno())
                            _checkpoint("bootstrap-inputs-dir-after-mutation", fault, pause)
                            os.fsync(stage.fileno())
                        finally:
                            stage.close()
                        os.fsync(current.fileno())
                        transaction_identity = current.recheck().directory
                    finally:
                        current.close()
                finally:
                    transactions.close()
            finally:
                service.close()
    except (OSError, FilesystemError):
        _die("Managed service transaction tree could not be created safely")
    transaction_dir = (
        f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"
    )
    assert transaction_identity is not None
    return (
        transaction_dir,
        f"{transaction_dir}/stage",
        f"{transaction_dir}/backup",
        transaction_identity,
    )


def _write_new_file(path: str, data: bytes, mode: int, *, mtime_ns: int | None = None) -> FileIdentity:
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
        identity = identity_from_stat(os.fstat(descriptor))
        parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return identity
    except (OSError, FilesystemError):
        _die("Managed service private file could not be staged safely")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _copy_descriptor(
    source: int,
    destination: str,
    *,
    mode: int,
    mtime_ns: int,
) -> FileIdentity:
    output = -1
    try:
        output = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
        )
        offset = 0
        while True:
            block = os.pread(source, 64 * 1024, offset)
            if not block:
                break
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
        os.fchmod(output, mode)
        os.utime(output, ns=(mtime_ns, mtime_ns))
        os.fsync(output)
        identity = identity_from_stat(os.fstat(output))
        parent = os.open(
            os.path.dirname(destination),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return identity
    except (OSError, FilesystemError):
        _die("Managed service private copy could not be staged safely")
    finally:
        if output >= 0:
            os.close(output)
    raise AssertionError("unreachable")


def _copy_evidence(
    evidence: _Evidence,
    destination: str,
    *,
    mode: int | None = None,
) -> FileIdentity:
    try:
        with OpenedFile(
            evidence.path,
            policy=FilePolicy(
                owner=evidence.identity.uid,
                mode=evidence.identity.permissions,
                links=1,
                max_size=_MAX_EVIDENCE,
            ),
            expected_identity=evidence.identity,
        ) as source:
            data = source.read(_MAX_EVIDENCE)
            if _sha256(data) != evidence.digest:
                _die("Managed service planned source digest changed")
            if evidence.data is not None and data != evidence.data:
                _die("Managed service inventory snapshot changed")
            identity = _copy_descriptor(
                source.fileno(),
                destination,
                mode=evidence.identity.permissions if mode is None else mode,
                mtime_ns=evidence.identity.mtime_ns,
            )
            source.recheck()
            return identity
    except FilesystemError:
        _die("Managed service planned source identity changed")
    raise AssertionError("unreachable")


def _recheck_evidence(evidence: _Evidence, label: str) -> None:
    try:
        with OpenedFile(
            evidence.path,
            policy=FilePolicy(
                owner=evidence.identity.uid,
                mode=evidence.identity.permissions,
                links=1,
                max_size=_MAX_EVIDENCE,
            ),
            expected_identity=evidence.identity,
        ) as opened:
            data = opened.read(_MAX_EVIDENCE)
            if _sha256(data) != evidence.digest:
                _die(f"{label} digest changed")
            opened.recheck()
    except FilesystemError:
        _die(f"{label} identity changed")


def _canonical_serial(data: bytes, path: str) -> str:
    try:
        value = data.decode("ascii").strip()
    except UnicodeDecodeError:
        _die(f"Intermediate CA serial is invalid: {path}")
    if _SERIAL.fullmatch(value) is None:
        _die(f"Intermediate CA serial is invalid: {value}")
    if len(value) < 2 or len(value) % 2:
        _die(f"Intermediate CA serial must contain an even number of hexadecimal digits: {value}")
    value = value.upper()
    while len(value) > 2 and value.startswith("00"):
        value = value[2:]
    return value


def _service_config(service: InventoryService) -> bytes:
    lines = [
        "[ req ]",
        "prompt = no",
        "distinguished_name = dn",
        "default_md = sha384",
        "req_extensions = req_ext",
        "string_mask = utf8only",
        "",
        "[ dn ]",
        f"CN = {service.common_name}",
        "",
        "[ req_ext ]",
        "subjectAltName = @alt_names",
        "",
        "[ server_cert ]",
        "basicConstraints = critical, CA:false",
        "keyUsage = critical, digitalSignature",
        "extendedKeyUsage = serverAuth",
        "subjectAltName = @alt_names",
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid,issuer",
        "",
        "[ alt_names ]",
    ]
    lines.extend(f"DNS.{index} = {value}" for index, value in enumerate(service.dns, 1))
    lines.extend(f"IP.{index} = {value}" for index, value in enumerate(service.ips, 1))
    return ("\n".join(lines) + "\n").encode("ascii")


def _processed_ca_config(data: bytes, source: str, authority: str, work: str, inputs: str) -> bytes:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        _die(f"Intermediate CA configuration is invalid: {source}")
    section = ""
    ca_sections = ca_default_sections = default_ca_count = 0
    required: set[str] = set()
    output: list[str] = []
    path_values = {
        "dir": authority,
        "certs": "${dir}/certs",
        "crl_dir": "${dir}/crl",
        "new_certs_dir": "${dir}/newcerts",
        "database": "${dir}/index.txt",
        "serial": "${dir}/serial",
        "crlnumber": "${dir}/crlnumber",
        "private_key": "${dir}/private/intermediate-ca.key",
        "certificate": "${dir}/certs/intermediate-ca.crt",
        "crl": "${dir}/crl/intermediate-ca.crl",
        "randfile": "${dir}/private/.rand",
    }
    replacements = {
        "dir": work,
        "certs": "$dir/certs",
        "crl_dir": "$dir/crl",
        "new_certs_dir": "$dir/newcerts",
        "database": "$dir/index.txt",
        "serial": "$dir/serial",
        "crlnumber": f"{inputs}/signing_ca_crlnumber",
        "private_key": f"{inputs}/signing_ca_key",
        "certificate": f"{inputs}/signing_ca_certificate",
        "crl": "$dir/crl/intermediate-ca.crl",
        "randfile": "$dir/private/.rand",
    }
    for original in lines:
        stripped = original.lstrip()
        if re.match(r"^\.include(?:\s|=|$)", stripped):
            _die(f"Intermediate CA configuration must not contain include directives: {source}")
        match = re.match(r"^\[\s*([^]]+?)\s*\]\s*(?:[#;].*)?$", stripped)
        if match:
            section = match.group(1).strip()
            if section == "ca":
                ca_sections += 1
                if ca_sections != 1:
                    _die(f"Intermediate CA configuration contains duplicate ca sections: {source}")
            elif section == "CA_default":
                ca_default_sections += 1
                if ca_default_sections != 1:
                    _die(f"Intermediate CA configuration contains duplicate CA_default sections: {source}")
            output.append(original)
            continue
        setting = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*$", stripped)
        if setting is None:
            output.append(original)
            continue
        key, value = setting.group(1), setting.group(2)
        lower = key.lower()
        if section == "ca" and key == "default_ca":
            if value != "CA_default" or default_ca_count:
                _die(f"Intermediate CA configuration must select CA_default: {source}")
            default_ca_count += 1
        if lower in {*path_values, "oid_file"}:
            if section != "CA_default":
                _die(f"Intermediate CA signing path '{key}' must be in CA_default: {source}")
            if lower in required:
                _die(f"Intermediate CA configuration contains duplicate signing path '{key}': {source}")
            required.add(lower)
            if lower == "oid_file":
                _die(f"Intermediate CA configuration must not use oid_file during staged signing: {source}")
            normalized = value.replace("$dir", "${dir}")
            if normalized != path_values[lower]:
                _die(f"Intermediate CA signing path '{key}' escapes the managed CA directory: {source}")
            output.append(f"{key} = {replacements[lower]}")
            continue
        if section == "CA_default":
            allowed = {
                "default_md": "sha384",
                "policy": "policy_platform",
                "email_in_dn": "no",
                "copy_extensions": "none",
                "unique_subject": "no",
            }
            if lower not in allowed:
                _die(f"Intermediate CA configuration contains unsupported CA_default directive '{key}': {source}")
            if value != allowed[lower]:
                _die(f"Intermediate CA configuration has an unsafe {key}: {source}")
        elif not section:
            _die(f"Intermediate CA configuration contains a global directive '{key}': {source}")
        output.append(original)
    needed = {"dir", "certs", "crl_dir", "new_certs_dir", "database", "serial", "private_key", "certificate"}
    if ca_sections != 1 or ca_default_sections != 1 or default_ca_count != 1:
        _die(f"Intermediate CA configuration is missing the required ca signing contract: {source}")
    missing = next((key for key in needed if key not in required), None)
    if missing is not None:
        _die(f"Intermediate CA configuration is missing signing path '{missing}': {source}")
    return ("\n".join(output) + "\n").encode("utf-8")


def _run_openssl(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    *,
    pass_fds: tuple[int, ...] = (),
    label: str,
) -> bytes:
    try:
        result = run_process(
            argv,
            env=environment,
            pass_fds=pass_fds,
            **_PROCESS_OPTIONS,
        )
    except ApplicationError:
        _die(f"OpenSSL {label} failed")
    assert isinstance(result, ProcessResult)
    if result.status:
        _die(f"OpenSSL {label} failed", status=result.status)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    return result.stdout


def _certificate_dates(path: str, environment: Mapping[str, str]) -> tuple[int, int]:
    output = _run_openssl(
        ("openssl", "x509", "-in", path, "-noout", "-dates"),
        environment,
        label="certificate validity inspection",
    )
    try:
        lines = output.decode("ascii").splitlines()
        if len(lines) != 2 or not lines[0].startswith("notBefore=") or not lines[1].startswith("notAfter="):
            raise ValueError
        values = []
        for line in lines:
            parsed = datetime.datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
            values.append(int(parsed.replace(tzinfo=datetime.UTC).timestamp()))
        return values[0], values[1]
    except (UnicodeDecodeError, ValueError):
        _die("Cannot parse certificate validity")


def _validate_child_validity(child: str, issuer: str, safety_days: str, environment: Mapping[str, str]) -> None:
    child_start, child_end = _certificate_dates(child, environment)
    _issuer_start, issuer_end = _certificate_dates(issuer, environment)
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    if child_start > now + 300:
        _die("Child certificate notBefore is more than five minutes in the future")
    if child_start > now or child_end <= now:
        _die("Child certificate is not currently valid")
    if child_end > issuer_end - int(safety_days, 10) * 86400:
        _die(f"Child certificate exceeds issuer validity safety margin of {safety_days} day(s)")


def _archive_name(pki_dir: str, service: str, now: datetime.datetime) -> str:
    base = now.astimezone(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    for index in range(100):
        value = base if index == 0 else f"{base}-{index:02d}"
        if not os.path.lexists(f"{pki_dir}/services/{service}/archive/{value}"):
            return value
    _die("No available service archive destination exists")


def _path(pki_dir: str, relative: str) -> str:
    return f"{pki_dir}/{relative}"


def _directory_identity(path: str) -> DirectoryIdentity:
    try:
        actual = identity_at(path)
    except FilesystemError:
        _die("Managed service transaction directory is unsafe")
    if not isinstance(actual, FileIdentity) or actual.kind != "directory":
        _die("Managed service transaction directory is absent")
    return actual.directory


def _plan(
    pki_dir: str,
    service_name: str,
    *,
    days_override: str | None,
    safety_days: str,
    rotate_key: bool,
    environment: Mapping[str, str],
    setup: _Setup,
    fault: FaultHook,
    pause: PauseHook,
) -> _Plan:
    journal = _path(pki_dir, SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH)
    if os.path.lexists(journal):
        _die(f"Managed service recovery is required before this command can continue: {journal}")
    bootstrap = _path(pki_dir, SERVICE_BOOTSTRAP_RELATIVE_PATH)
    if os.path.lexists(bootstrap):
        _die(f"Managed service bootstrap recovery is required before this command can continue: {bootstrap}")
    require_generation_layout(pki_dir)
    root, intermediate = load_active_issuer(pki_dir, environment)
    _prepare_service_control(pki_dir)
    active_issuer = _snapshot_file(
        _path(pki_dir, "state/active-issuer"),
        "Active issuer record",
        private=True,
        keep_data=True,
    )
    assert active_issuer is not None and active_issuer.data is not None
    if active_issuer.data != f"root={root}\nintermediate={intermediate}\n".encode("ascii"):
        _die("Active issuer record changed during managed service planning")

    inventory_path = _path(pki_dir, "inventory/services.yml")
    inventory_evidence = _snapshot_file(
        inventory_path,
        "Service inventory",
        private=False,
        keep_data=True,
    )
    assert inventory_evidence is not None and inventory_evidence.data is not None
    try:
        inventory = parse_inventory(inventory_evidence.data)
    except InventoryError as error:
        _die(str(error))
    service = next((item for item in inventory.services if item.name == service_name), None)
    if service is None:
        _die(f"Service is not defined in {inventory_path}: {service_name}")
    if service.key_custody != "managed":
        _die(f"Host-local service issuance requires authenticated CSR inputs: {service_name}")
    days = _validate_days(
        days_override
        or service.days
        or environment.get("PLATFORM_PKI_SERVICE_DAYS", "")
        or "397"
    )

    authority = _path(pki_dir, f"authorities/intermediates/{intermediate}")
    for directory, label in (
        (pki_dir, "PKI directory"),
        (_path(pki_dir, f"authorities/roots/{root}"), "Root CA directory"),
        (authority, "Intermediate CA directory"),
        (f"{authority}/private", "Intermediate CA private directory"),
        (f"{authority}/certs", "Intermediate CA certificate directory"),
        (f"{authority}/newcerts", "Intermediate CA new-certificates directory"),
        (_path(pki_dir, "services"), "Services directory"),
    ):
        if _snapshot_directory(directory, label) is None:
            _die(f"{label} must be a non-symlink directory: {directory}")

    evidence: dict[str, _Evidence] = {
        "active_issuer": active_issuer,
        "signing_inventory": inventory_evidence,
    }
    for key in SERVICE_SIGNING_INPUT_KEYS:
        if key == "signing_inventory" or key == "signing_service_key":
            continue
        source = _path(
            pki_dir,
            _SIGNING_INPUT_SOURCES[key].format(
                root=root,
                intermediate=intermediate,
                service=service_name,
            ),
        )
        item = _snapshot_file(
            source,
            {
                "signing_root_certificate": "Root CA certificate",
                "signing_ca_key": "Intermediate CA key",
                "signing_ca_certificate": "Intermediate CA certificate",
                "signing_ca_config": "Intermediate CA configuration",
                "signing_ca_crlnumber": "Intermediate CA CRL number",
            }[key],
            private=key in _PRIVATE_INPUTS,
            keep_data=key == "signing_ca_config",
        )
        assert item is not None
        evidence[key] = item

    service_root = _path(pki_dir, f"services/{service_name}")
    key_path = f"{service_root}/private/tls.key"
    certificate_path = f"{service_root}/certs/tls.crt"
    certificate = _snapshot_file(
        certificate_path,
        "Service certificate",
        private=False,
        required=False,
    )
    if certificate is not None:
        _die(
            "Service certificate already exists; use platform-pki-service-renew: "
            f"{certificate_path}"
        )
    current_key = _snapshot_file(
        key_path,
        "Service private key",
        private=True,
        required=False,
    )
    key_action = (
        ServiceKeyAction.CREATE
        if current_key is None
        else ServiceKeyAction.ROTATE
        if rotate_key
        else ServiceKeyAction.REUSE
    )
    if current_key is not None:
        evidence["current_key"] = current_key
    if key_action is ServiceKeyAction.REUSE:
        evidence["signing_service_key"] = current_key  # type: ignore[assignment]

    ca_serial_evidence = _snapshot_file(
        f"{authority}/serial", "Intermediate CA serial", private=True
    )
    assert ca_serial_evidence is not None
    evidence["planned_ca_serial"] = ca_serial_evidence
    serial_data = b""
    with OpenedFile(
        ca_serial_evidence.path,
        policy=FilePolicy(
            owner=ca_serial_evidence.identity.uid,
            mode=ca_serial_evidence.identity.permissions,
            links=1,
            max_size=_MAX_EVIDENCE,
        ),
        expected_identity=ca_serial_evidence.identity,
    ) as serial_file:
        serial_data = serial_file.read(_MAX_EVIDENCE)
    serial = _canonical_serial(serial_data, ca_serial_evidence.path)
    newcert_path = f"{authority}/newcerts/{serial}.pem"
    if identity_at(newcert_path) is not ABSENT:
        _die(f"Intermediate CA issued-certificate destination already exists: {newcert_path}")

    transaction = f"service-{secrets.token_hex(16)}"
    setup.transaction = transaction
    created_epoch = int(datetime.datetime.now(datetime.UTC).timestamp())
    work_dir = os.path.join(
        tempfile.gettempdir(), f".platform-pki-{transaction}"
    )
    for label, value in (
        ("PKI directory", pki_dir),
        ("Managed service OpenSSL work directory", work_dir),
        ("Managed service transaction directory", f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}"),
        ("Managed service signing input directory", f"{pki_dir}/{SERVICE_TRANSACTION_TREE_RELATIVE_PATH}/{transaction}/stage/inputs"),
    ):
        _validate_openssl_path(label, value)
    _validate_openssl_value("Managed service name", service.name)
    _validate_openssl_value("Managed service common name", service.common_name)
    for dns in service.dns:
        _validate_openssl_value("Managed service DNS SAN", dns)
    for ip in service.ips:
        _validate_openssl_value("Managed service IP SAN", ip)
    for key, item in evidence.items():
        _recheck_evidence(item, f"Managed service planned {key}")
    publish_service_bootstrap(
        pki_dir,
        transaction,
        created_epoch=created_epoch,
        fault_hook=fault,
        pause_hook=pause,
    )
    transaction_dir, stage_dir, backup_dir, transaction_identity = _create_transaction_tree(
        pki_dir, transaction, fault, pause
    )
    inputs_dir = f"{stage_dir}/inputs"
    archive_state = (
        ServiceArchiveState.ISSUE_KEY
        if key_action is ServiceKeyAction.ROTATE
        else ServiceArchiveState.NONE
    )
    archive = (
        _archive_name(pki_dir, service_name, datetime.datetime.now(datetime.UTC))
        if archive_state is not ServiceArchiveState.NONE
        else "none"
    )
    archive_members = ("tls.key",) if archive_state is ServiceArchiveState.ISSUE_KEY else ()

    values = {field: "none" for field in SERVICE_TRANSACTION_FIELDS}
    values.update(
        schema="1",
        operation=ServiceOperation.ISSUE.value,
        transaction=transaction,
        phase="staging",
        checkpoint="staging-pending",
        mutation="none",
        committed="false",
        recovery_mode="rollback",
        outcome="none",
        service=service_name,
        issuer_root=root,
        issuer_intermediate=intermediate,
        serial=serial,
        key_action=key_action.value,
        current_key_identity=(
            "absent" if current_key is None else serialize_file_identity(current_key.identity)
        ),
        current_key_sha256="none" if current_key is None else current_key.digest,
        archive_state=archive_state.value,
        archive_name=archive,
        archive_members=",".join(archive_members) if archive_members else "none",
        owner=str(_OWNER),
        created_epoch=str(created_epoch),
        staged_count="0",
        backed_up_count="0",
        published_count="0",
        rollback_count="0",
        rollback_completion_count="0",
        rollback_completion_path="none",
        rollback_completion_identity="none",
        rollback_completion_sha256="none",
        journal_path=journal,
        journal_identity="none",
        transaction_dir=transaction_dir,
        transaction_identity=serialize_directory_identity(transaction_identity),
        transaction_record_path=f"{transaction_dir}/transaction",
        transaction_record_identity="none",
        transaction_record_sha256="none",
        stage_dir=stage_dir,
        stage_dir_identity=serialize_directory_identity(_directory_identity(stage_dir)),
        inputs_dir=inputs_dir,
        inputs_dir_identity=serialize_directory_identity(_directory_identity(inputs_dir)),
        backup_dir=backup_dir,
        backup_dir_identity=serialize_directory_identity(_directory_identity(backup_dir)),
        archive_root_snapshot_identity="none",
        archive_root_reference_path="none",
        archive_root_reference_identity="none",
        archive_root_reference_sha256="none",
        archive_root_restored="none",
        archive_root_restored_identity="none",
        archive_marker_removed="none",
        stage_removed="false",
        backup_removed="false",
        terminal_path=f"{transaction_dir}/terminal",
        terminal_identity="none",
        terminal_sha256="none",
    )

    existing_directories: list[str] = []
    for key in SERVICE_CONTAINER_ORDER:
        destination = _path(
            pki_dir,
            _DIRECTORY_DESTINATIONS[key].format(service=service_name, archive=archive),
        )
        identity = _snapshot_directory(destination, f"Service {key} directory")
        values[f"{key}_destination"] = destination
        values[f"{key}_pre_identity"] = (
            "absent" if identity is None else serialize_directory_identity(identity)
        )
        values[f"{key}_post_identity"] = (
            "none" if identity is None else serialize_directory_identity(identity)
        )
        values[f"{key}_rollback_identity"] = "none"
        if identity is not None:
            existing_directories.append(key)

    existing_archive_root = False
    if archive_state is ServiceArchiveState.ISSUE_KEY:
        archive_root = _path(pki_dir, f"services/{service_name}/archive")
        archive_root_identity = _snapshot_directory(archive_root, "Service archive directory")
        archive_root_full: FileIdentity | None = None
        if archive_root_identity is not None:
            actual = identity_at(archive_root)
            assert isinstance(actual, FileIdentity)
            archive_root_full = actual
            existing_archive_root = True
        values.update(
            archive_root_destination=archive_root,
            archive_root_pre_identity=(
                "absent"
                if archive_root_identity is None
                else serialize_directory_identity(archive_root_identity)
            ),
            archive_root_post_identity=(
                "none"
                if archive_root_identity is None
                else serialize_directory_identity(archive_root_identity)
            ),
            archive_root_rollback_identity="none",
            archive_dir_destination=f"{archive_root}/{archive}",
            archive_dir_pre_identity="absent",
            archive_dir_post_identity="none",
            archive_dir_rollback_identity="none",
            archive_root_snapshot_identity=(
                "absent"
                if archive_root_full is None
                else serialize_file_identity(archive_root_full)
            ),
        )
        if archive_root_full is not None:
            reference = f"{transaction_dir}/archive-root-reference"
            reference_identity = _write_new_file(
                reference, b"", 0o600, mtime_ns=archive_root_full.mtime_ns
            )
            values.update(
                archive_root_reference_path=reference,
                archive_root_reference_identity=serialize_file_identity(
                    reference_identity
                ),
                archive_root_reference_sha256=_sha256(b""),
                archive_root_restored="false",
            )

    created_directories = tuple(
        key for key in SERVICE_CONTAINER_ORDER if key not in existing_directories
    )
    publication_order = managed_publication_order(
        ServiceOperation.ISSUE,
        key_action,
        archive_state,
        archive_members,
        create_archive_root=(
            archive_state is ServiceArchiveState.ISSUE_KEY and not existing_archive_root
        ),
        created_service_directories=created_directories,
    )

    for key in publication_order:
        if key in _DIRECTORY_DESTINATIONS:
            continue
        relative = _FILE_DESTINATIONS[key].format(
            service=service_name,
            intermediate=intermediate,
            serial=serial,
            archive=archive,
        )
        destination = _path(pki_dir, relative)
        pre = _snapshot_file(
            destination,
            f"Managed service destination {key}",
            private=key in _PRIVATE_DESTINATIONS,
            required=False,
        )
        if key in {"ca_index", "ca_index_attr", "ca_serial"} and pre is None:
            _die(f"Required file is missing: {destination}")
        if key == "ca_newcert" and pre is not None:
            _die(f"Intermediate CA issued-certificate destination already exists: {destination}")
        if key == "service_key" and current_key is not None:
            pre = current_key
        values[f"{key}_destination"] = destination
        values[f"{key}_pre_identity"] = (
            "absent" if pre is None else serialize_file_identity(pre.identity)
        )
        values[f"{key}_pre_sha256"] = "none" if pre is None else pre.digest
        values[f"{key}_stage"] = f"{stage_dir}/{key}"
        values[f"{key}_stage_identity"] = "none"
        values[f"{key}_stage_object"] = "none"
        values[f"{key}_stage_sha256"] = "none"
        values[f"{key}_post_identity"] = "none"
        values[f"{key}_post_sha256"] = "none"
        values[f"{key}_rollback_identity"] = "none"
        values[f"{key}_rollback_sha256"] = "none"
        if pre is not None:
            evidence[f"destination:{key}"] = pre
            values[f"{key}_backup"] = f"{backup_dir}/{key}"
            values[f"{key}_backup_identity"] = "none"
            values[f"{key}_backup_object"] = "none"
            values[f"{key}_backup_sha256"] = "none"

    if key_action is ServiceKeyAction.ROTATE:
        assert current_key is not None
        values.update(
            archive_key_source=key_path,
            archive_key_source_identity=serialize_file_identity(current_key.identity),
            archive_key_source_sha256=current_key.digest,
        )

    for key in SERVICE_SIGNING_INPUT_KEYS:
        if key == "signing_service_key" and key_action is not ServiceKeyAction.REUSE:
            continue
        item = evidence[key]
        values[f"{key}_source"] = item.path
        values[f"{key}_source_identity"] = serialize_file_identity(item.identity)
        values[f"{key}_source_sha256"] = item.digest
        values[f"{key}_stage"] = f"{inputs_dir}/{key}"
        values[f"{key}_stage_identity"] = "none"
        values[f"{key}_stage_object"] = "none"
        values[f"{key}_stage_sha256"] = "none"

    staging_order = (
        tuple(
            key
            for key in SERVICE_SIGNING_INPUT_KEYS
            if key != "signing_service_key" or key_action is ServiceKeyAction.REUSE
        )
        + tuple(key for key in publication_order if key not in _DIRECTORY_DESTINATIONS)
    )
    values["mutation"] = staging_order[0]

    retained_values = {
        field: values[field] for field in SERVICE_RETAINED_TRANSACTION_FIELDS
    }
    retained = serialize_service_retained_transaction(retained_values)
    retained_identity = _write_new_file(
        values["transaction_record_path"], retained, 0o600
    )
    values["transaction_record_identity"] = serialize_file_identity(retained_identity)
    values["transaction_record_sha256"] = _sha256(retained)

    if os.path.lexists(work_dir):
        _die("Managed service OpenSSL work path already exists")
    return _Plan(
        pki_dir,
        service,
        root,
        intermediate,
        days,
        safety_days,
        transaction,
        work_dir,
        values,
        evidence,
    )


def _advance_staging(
    writer: ManagedServiceWriter,
    key: str,
    create: object,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    _checkpoint(f"staging-{key}-before-mutation", fault, pause)
    assert callable(create)
    create()
    _checkpoint(f"staging-{key}-after-mutation", fault, pause)
    writer.record_staging(key)
    staged = int(writer.record["staged_count"])
    if staged < len(writer.record.staging_order):
        writer.begin_staging(writer.record.staging_order[staged])


def _advance_backup(
    writer: ManagedServiceWriter,
    key: str,
    evidence: _Evidence,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    _checkpoint(f"backup-{key}-before-mutation", fault, pause)
    _copy_evidence(evidence, writer.values[f"{key}_backup"])
    _checkpoint(f"backup-{key}-after-mutation", fault, pause)
    writer.record_backup(key)
    backed_up = int(writer.record["backed_up_count"])
    if backed_up < len(writer.record.backup_order):
        writer.begin_backup(writer.record.backup_order[backed_up])


def _copy_path(source: str, destination: str, mode: int) -> None:
    item = _snapshot_file(source, "OpenSSL work output", private=mode & 0o077 == 0)
    assert item is not None
    _copy_evidence(item, destination, mode=mode)


def _write_concat(destination: str, sources: tuple[str, ...], mode: int) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
    )
    try:
        for source in sources:
            with OpenedFile(source, policy=FilePolicy(links=1, max_size=_MAX_EVIDENCE)) as opened:
                offset = 0
                while True:
                    block = os.pread(opened.fileno(), 64 * 1024, offset)
                    if not block:
                        break
                    view = memoryview(block)
                    try:
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise OSError("managed service chain write made no progress")
                            view = view[written:]
                    finally:
                        view.release()
                    offset += len(block)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _detach_outputs(work: str, paths: Mapping[str, str]) -> dict[str, _DetachedFile]:
    detached: dict[str, _DetachedFile] = {}
    try:
        for key, relative in paths.items():
            path = f"{work}/{relative}"
            metadata = os.lstat(path)
            identity = identity_from_stat(metadata)
            if identity.kind != "regular" or identity.uid != _OWNER or identity.links != 1:
                raise OSError
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            if identity_from_stat(os.fstat(descriptor)) != identity:
                os.close(descriptor)
                raise OSError
            detached[key] = _DetachedFile(
                descriptor, identity.permissions, identity.mtime_ns
            )
        shutil.rmtree(work)
        return detached
    except (OSError, FilesystemError):
        for item in detached.values():
            item.close()
        _die("OpenSSL produced unsafe managed service staging output")


def _openssl_outputs(
    plan: _Plan,
    writer: ManagedServiceWriter,
    environment: Mapping[str, str],
    passphrase: OpenedFile | None,
    fault: FaultHook,
    pause: PauseHook,
) -> dict[str, _DetachedFile]:
    _checkpoint("openssl-before-mutation", fault, pause)
    work = plan.work_dir
    try:
        os.mkdir(work, 0o700)
        for name in ("private", "certs", "crl", "newcerts"):
            os.mkdir(f"{work}/{name}", 0o700)
        for key, name in (
            ("ca_index", "index.txt"),
            ("ca_index_attr", "index.txt.attr"),
            ("ca_serial", "serial"),
        ):
            _copy_evidence(plan.evidence[f"destination:{key}"], f"{work}/{name}")

        key = (
            writer.values["signing_service_key_stage"]
            if plan.values["key_action"] == ServiceKeyAction.REUSE.value
            else f"{work}/tls.key"
        )
        if plan.values["key_action"] != ServiceKeyAction.REUSE.value:
            _run_openssl(
                (
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:secp384r1",
                    "-out",
                    key,
                ),
                environment,
                label="service key generation",
            )
            os.chmod(key, 0o600)
        _run_openssl(
            (
                "openssl",
                "req",
                "-config",
                writer.values["service_config_stage"],
                "-key",
                key,
                "-new",
                "-sha384",
                "-out",
                f"{work}/tls.csr",
            ),
            environment,
            label="service CSR generation",
        )
        os.chmod(f"{work}/tls.csr", 0o600)
        argv = (
            "openssl",
            "ca",
            "-batch",
            "-config",
            writer.values["signing_ca_config_stage"],
            "-extfile",
            writer.values["service_config_stage"],
            "-extensions",
            "server_cert",
            "-days",
            plan.days,
            "-notext",
            "-md",
            "sha384",
            "-in",
            f"{work}/tls.csr",
            "-out",
            f"{work}/tls.crt",
        )
        pass_fds: tuple[int, ...] = ()
        descriptor = -1
        if passphrase is not None:
            descriptor = _fresh_descriptor(
                passphrase,
                "Cannot duplicate passphrase file descriptor for OpenSSL",
            )
            argv = (*argv, "-passin", f"fd:{descriptor}")
            pass_fds = (descriptor,)
        try:
            _run_openssl(
                argv,
                environment,
                pass_fds=pass_fds,
                label="managed service signing",
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        os.chmod(f"{work}/tls.crt", 0o644)
        _validate_child_validity(
            f"{work}/tls.crt",
            writer.values["signing_ca_certificate_stage"],
            plan.safety_days,
            environment,
        )
        _write_concat(
            f"{work}/ca-chain.crt",
            (
                writer.values["signing_ca_certificate_stage"],
                writer.values["signing_root_certificate_stage"],
            ),
            0o644,
        )
        _write_concat(
            f"{work}/fullchain.crt",
            (f"{work}/tls.crt", writer.values["signing_ca_certificate_stage"]),
            0o644,
        )
        _write_new_file(
            f"{work}/issuer",
            (
                f"root={plan.root}\nintermediate={plan.intermediate}\n"
            ).encode("ascii"),
            0o600,
        )
        os.chmod(f"{work}/index.txt", 0o600)
        os.chmod(f"{work}/index.txt.attr", 0o600)
        os.chmod(f"{work}/serial", 0o600)
        os.chmod(f"{work}/newcerts/{plan.values['serial']}.pem", 0o600)
        outputs = {
            "service_csr": "tls.csr",
            "service_certificate": "tls.crt",
            "service_chain": "ca-chain.crt",
            "service_fullchain": "fullchain.crt",
            "service_issuer": "issuer",
            "ca_index": "index.txt",
            "ca_index_attr": "index.txt.attr",
            "ca_serial": "serial",
            "ca_index_old": "index.txt.old",
            "ca_index_attr_old": "index.txt.attr.old",
            "ca_serial_old": "serial.old",
            "ca_newcert": f"newcerts/{plan.values['serial']}.pem",
        }
        if plan.values["key_action"] != ServiceKeyAction.REUSE.value:
            outputs["service_key"] = "tls.key"
        detached = _detach_outputs(work, outputs)
    except BaseException:
        if os.path.isdir(work) and not os.path.islink(work):
            shutil.rmtree(work, ignore_errors=True)
        raise
    _checkpoint("openssl-after-mutation", fault, pause)
    return detached


def _stage_operation(
    plan: _Plan,
    writer: ManagedServiceWriter,
    environment: Mapping[str, str],
    passphrase: OpenedFile | None,
    fault: FaultHook,
    pause: PauseHook,
    output: TextIO,
) -> None:
    _recheck_evidence(plan.evidence["active_issuer"], "Active issuer record")
    config_source = plan.evidence["signing_ca_config"]
    assert config_source.data is not None
    processed_config = _processed_ca_config(
        config_source.data,
        config_source.path,
        _path(plan.pki_dir, f"authorities/intermediates/{plan.intermediate}"),
        plan.work_dir,
        writer.values["inputs_dir"],
    )
    service_config = _service_config(plan.service)
    for key in tuple(writer.record.staging_order):
        if key == "signing_ca_config":
            create = lambda: _write_new_file(
                writer.values[f"{key}_stage"], processed_config, 0o600
            )
        elif key.startswith("signing_"):
            evidence = plan.evidence[key]
            mode = (
                0o600
                if key in {"signing_inventory", "signing_service_key"}
                else evidence.identity.permissions
            )
            create = lambda evidence=evidence, key=key, mode=mode: _copy_evidence(
                evidence, writer.values[f"{key}_stage"], mode=mode
            )
        elif key == "service_config":
            create = lambda: _write_new_file(
                writer.values["service_config_stage"], service_config, 0o600
            )
        else:
            break
        _advance_staging(writer, key, create, fault, pause)

    if plan.values["key_action"] == ServiceKeyAction.REUSE.value:
        print(
            f"[INFO] Reusing existing service private key: "
            f"{plan.values['current_key_identity'] and _path(plan.pki_dir, f'services/{plan.service.name}/private/tls.key')}",
            file=output,
        )

    detached = _openssl_outputs(
        plan, writer, environment, passphrase, fault, pause
    )
    try:
        while int(writer.record["staged_count"]) < len(writer.record.staging_order):
            key = writer.record.staging_order[int(writer.record["staged_count"])]
            if key == "archive_key":
                evidence = plan.evidence["current_key"]
                create = lambda evidence=evidence: _copy_evidence(
                    evidence, writer.values["archive_key_stage"]
                )
            else:
                item = detached[key]
                mode = _FIXED_OUTPUT_MODES.get(key, item.mode)
                create = lambda item=item, key=key, mode=mode: _copy_descriptor(
                    item.descriptor,
                    writer.values[f"{key}_stage"],
                    mode=mode,
                    mtime_ns=item.mtime_ns,
                )
            _advance_staging(writer, key, create, fault, pause)
    finally:
        for item in detached.values():
            item.close()

    writer.begin_backup(writer.record.backup_order[0])
    while int(writer.record["backed_up_count"]) < len(writer.record.backup_order):
        key = writer.record.backup_order[int(writer.record["backed_up_count"])]
        _advance_backup(
            writer,
            key,
            plan.evidence[f"destination:{key}"],
            fault,
            pause,
        )
    writer.finish_preparation()


def _extension(path: str, name: str, environment: Mapping[str, str]) -> tuple[bool, str]:
    data = _run_openssl(
        ("openssl", "x509", "-in", path, "-noout", "-ext", name),
        environment,
        label="published certificate verification",
    )
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Published certificate verification returned invalid output")
    if not lines or not lines[0].startswith("X509v3 ") or ":" not in lines[0]:
        _die(f"Published certificate extension {name} is invalid")
    header = lines[0].split(":", 1)[1].strip()
    if header not in {"", "critical"}:
        _die(f"Published certificate extension {name} criticality is invalid")
    value = " ".join(line.strip() for line in lines[1:] if line.strip())
    if not value:
        _die(f"Published certificate extension {name} is empty")
    return header == "critical", value


def _certificate_metadata(
    path: str,
    environment: Mapping[str, str],
) -> dict[str, str]:
    output = _run_openssl(
        (
            "openssl",
            "x509",
            "-in",
            path,
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-dates",
            "-nameopt",
            "RFC2253",
        ),
        environment,
        label="published certificate metadata verification",
    )
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Published certificate metadata is invalid")
    prefixes = ("subject=", "issuer=", "serial=", "notBefore=", "notAfter=")
    if len(lines) != len(prefixes) or any(
        not line.startswith(prefix) for line, prefix in zip(lines, prefixes, strict=True)
    ):
        _die("Published certificate metadata is invalid")
    return {
        prefix[:-1]: line[len(prefix) :]
        for line, prefix in zip(lines, prefixes, strict=True)
    }


def _certificate_text(path: str, environment: Mapping[str, str]) -> str:
    output = _run_openssl(
        (
            "openssl",
            "x509",
            "-in",
            path,
            "-noout",
            "-text",
            "-nameopt",
            "RFC2253",
        ),
        environment,
        label="published certificate profile verification",
    )
    try:
        return output.decode("ascii")
    except UnicodeDecodeError:
        _die("Published certificate profile is invalid")


def _parse_sans(value: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    dns: list[str] = []
    ips: list[str] = []
    for item in (part.strip() for part in value.split(",")):
        if item.startswith("DNS:") and len(item) > 4:
            dns.append(item[4:])
        elif item.startswith("IP Address:") and len(item) > 11:
            ips.append(item[11:])
        else:
            _die("Published certificate contains an unsupported SAN")
    if len(dns) != len(set(dns)) or len(ips) != len(set(ips)):
        _die("Published certificate contains duplicate SANs")
    return tuple(dns), tuple(ips)


def _verify_published(plan: _Plan, environment: Mapping[str, str]) -> None:
    service_root = _path(plan.pki_dir, f"services/{plan.service.name}")
    key = f"{service_root}/private/tls.key"
    certificate = f"{service_root}/certs/tls.crt"
    root = _path(plan.pki_dir, f"authorities/roots/{plan.root}/certs/root-ca.crt")
    intermediate = _path(
        plan.pki_dir,
        f"authorities/intermediates/{plan.intermediate}/certs/intermediate-ca.crt",
    )
    _run_openssl(
        (
            "openssl",
            "verify",
            "-CAfile",
            root,
            "-untrusted",
            intermediate,
            certificate,
        ),
        environment,
        label="published certificate chain verification",
    )
    metadata = _certificate_metadata(certificate, environment)
    issuer_metadata = _certificate_metadata(intermediate, environment)
    expected_subject = f"CN={plan.service.common_name}"
    if metadata["subject"] != expected_subject:
        _die(f"Certificate subject does not match inventory common_name: {certificate}")
    if metadata["issuer"] != issuer_metadata["subject"]:
        _die(f"Certificate issuer does not match the planned intermediate: {certificate}")
    if metadata["serial"].upper() != plan.values["serial"]:
        _die(f"Certificate serial does not match the planned CA serial: {certificate}")
    certificate_public = _run_openssl(
        ("openssl", "x509", "-in", certificate, "-pubkey", "-noout"),
        environment,
        label="published certificate key extraction",
    )
    key_public = _run_openssl(
        ("openssl", "pkey", "-in", key, "-pubout"),
        environment,
        label="published private key verification",
    )
    if certificate_public != key_public:
        _die(f"Private key does not match certificate for service: {plan.service.name}")
    text = _certificate_text(certificate, environment)
    if "Version: 3 (0x2)" not in text:
        _die(f"Certificate is not X.509 version 3: {certificate}")
    signatures = set(
        re.findall(r"^\s*Signature Algorithm: ([^\r\n]+)$", text, re.MULTILINE)
    )
    if signatures != {"ecdsa-with-SHA384"}:
        _die(f"Certificate signature algorithm is not ECDSA with SHA-384: {certificate}")
    if (
        "Public Key Algorithm: id-ecPublicKey" not in text
        or "Public-Key: (384 bit)" not in text
        or "ASN1 OID: secp384r1" not in text
    ):
        _die(f"Certificate public key is not P-384 EC: {certificate}")
    extension_names = tuple(
        re.findall(r"^\s{12}X509v3 ([^:\r\n]+):", text, re.MULTILINE)
    )
    expected_extensions = {
        "Basic Constraints",
        "Key Usage",
        "Extended Key Usage",
        "Subject Alternative Name",
        "Subject Key Identifier",
        "Authority Key Identifier",
    }
    if len(extension_names) != len(set(extension_names)) or set(extension_names) != expected_extensions:
        _die(f"Certificate extension profile is not exact: {certificate}")

    basic_critical, basic = _extension(certificate, "basicConstraints", environment)
    key_usage_critical, key_usage = _extension(certificate, "keyUsage", environment)
    eku_critical, eku = _extension(certificate, "extendedKeyUsage", environment)
    san_critical, sans = _extension(certificate, "subjectAltName", environment)
    ski_critical, ski = _extension(certificate, "subjectKeyIdentifier", environment)
    aki_critical, aki = _extension(certificate, "authorityKeyIdentifier", environment)
    issuer_ski_critical, issuer_ski = _extension(
        intermediate, "subjectKeyIdentifier", environment
    )
    if not basic_critical or basic != "CA:FALSE":
        _die(f"Certificate basic constraints profile is invalid: {certificate}")
    if not key_usage_critical or key_usage != "Digital Signature":
        _die(f"Certificate key usage profile is invalid: {certificate}")
    if eku_critical or eku != "TLS Web Server Authentication":
        _die(f"Certificate extended key usage profile is invalid: {certificate}")
    if san_critical:
        _die(f"Certificate subjectAltName must not be critical: {certificate}")
    actual_dns, actual_ips = _parse_sans(sans)
    if set(actual_dns) != set(plan.service.dns) or len(actual_dns) != len(plan.service.dns):
        _die(f"Certificate DNS SAN set does not match inventory: {certificate}")
    if set(actual_ips) != set(plan.service.ips) or len(actual_ips) != len(plan.service.ips):
        _die(f"Certificate IP SAN set does not match inventory: {certificate}")
    key_identifier = re.compile(r"(?:[0-9A-F]{2}:){19}[0-9A-F]{2}", re.ASCII)
    if ski_critical or key_identifier.fullmatch(ski) is None:
        _die(f"Certificate subject key identifier is invalid: {certificate}")
    if issuer_ski_critical or key_identifier.fullmatch(issuer_ski) is None:
        _die(f"Intermediate subject key identifier is invalid: {intermediate}")
    if aki_critical or aki != issuer_ski:
        _die(f"Certificate authority key identifier does not match its issuer: {certificate}")

    child_start, child_end = _certificate_dates(certificate, environment)
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    if abs(child_start - now) > 300:
        _die("Child certificate notBefore is outside the five-minute issuance tolerance")
    if child_end - child_start != int(plan.days, 10) * 86400:
        _die(f"Certificate validity does not match the planned days policy: {certificate}")
    _validate_child_validity(
        certificate,
        intermediate,
        plan.safety_days,
        environment,
    )
    _run_openssl(
        (
            "openssl",
            "x509",
            "-in",
            certificate,
            "-checkend",
            str(30 * 86400),
            "-noout",
        ),
        environment,
        label="published certificate lifetime verification",
    )


def issue_managed_service(
    service: str,
    *,
    pki_dir: os.PathLike[str] | str,
    days: str | None = None,
    issuer_safety_days: str = "1",
    intermediate_pass_file: os.PathLike[str] | str | None = None,
    rotate_key: bool = False,
    environment: Mapping[str, str] | None = None,
    output: TextIO | None = None,
    fault_hook: FaultHook = DEFAULT_FAULT_HOOK,
    pause_hook: PauseHook = DEFAULT_PAUSE_HOOK,
) -> int:
    """Issue one managed service through the Python transaction writer."""

    root = os.fspath(pki_dir)
    if not isinstance(root, str) or not os.path.isabs(root) or os.path.normpath(root) != root:
        raise ValueError("pki_dir must be an absolute normalized text path")
    _validate_openssl_path("PKI directory", root)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", service, re.ASCII) is None:
        _die(f"Invalid service name: {service}")
    if days is not None:
        _validate_days(days)
    safety_days = _validate_days(issuer_safety_days)
    if not isinstance(rotate_key, bool):
        raise TypeError("rotate_key must be a boolean")
    if not callable(fault_hook) or not callable(pause_hook):
        raise TypeError("service issue hooks must be callable")
    process_environment = dict(os.environ if environment is None else environment)
    stream = sys.stdout if output is None else output
    require_program("openssl", process_environment)
    require_pki_directory(root)
    prepare_control_state(root)

    transaction: str | None = None
    plan: _Plan | None = None
    setup = _Setup()
    committed = False
    passphrase: OpenedFile | None = None
    if intermediate_pass_file is not None:
        passphrase = _open_passphrase(os.fspath(intermediate_pass_file))
    try:
        with _handled_signals():
            with acquire_operational_locks(root, "inventory"):
                plan = _plan(
                    root,
                    service,
                    days_override=days,
                    safety_days=safety_days,
                    rotate_key=rotate_key,
                    environment=process_environment,
                    setup=setup,
                    fault=fault_hook,
                    pause=pause_hook,
                )
                transaction = plan.transaction
                writer = ManagedServiceWriter.create(
                    plan.values,
                    pki_dir=root,
                    fault=fault_hook,
                    pause=pause_hook,
                )
                clear_service_bootstrap(
                    root,
                    transaction,
                    remove_tree=False,
                    fault_hook=fault_hook,
                    pause_hook=pause_hook,
                )
                _checkpoint("planning-after-journal", fault_hook, pause_hook)
                _stage_operation(
                    plan,
                    writer,
                    process_environment,
                    passphrase,
                    fault_hook,
                    pause_hook,
                    stream,
                )
                _recheck_evidence(plan.evidence["active_issuer"], "Active issuer record")
                while int(writer.record["published_count"]) < len(
                    writer.record.publication_order
                ):
                    writer.publish_next()
                writer.begin_verification()
                _checkpoint("verification-before-mutation", fault_hook, pause_hook)
                _recheck_evidence(plan.evidence["active_issuer"], "Active issuer record")
                _verify_published(plan, process_environment)
                _recheck_evidence(plan.evidence["active_issuer"], "Active issuer record")
                _checkpoint("verification-after-mutation", fault_hook, pause_hook)
                writer.finish_verification()
                writer.commit()
                committed = True
                _checkpoint("commit-after-mutation", fault_hook, pause_hook)
    except BaseException as primary:
        if transaction is None:
            transaction = setup.transaction
        if transaction is not None and os.path.lexists(
            _path(root, SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH)
        ):
            try:
                recover_service_transaction(
                    root,
                    transaction=transaction,
                    output=io.StringIO(),
                )
            except BaseException as recovery:
                raise primary from recovery
        elif transaction is not None and (
            os.path.lexists(_path(root, SERVICE_BOOTSTRAP_RELATIVE_PATH))
            or os.path.lexists(
                _path(root, f"state/service/.{transaction}.bootstrap.publish")
            )
        ):
            try:
                recover_service_transaction(
                    root,
                    transaction=transaction,
                    output=io.StringIO(),
                )
            except BaseException as cleanup:
                raise primary from cleanup
        raise
    finally:
        if passphrase is not None:
            passphrase.close()

    assert transaction is not None and plan is not None and committed
    recover_service_transaction(
        root,
        transaction=transaction,
        output=io.StringIO(),
    )
    print(f"[OK] Verified service certificate: {service}", file=stream)
    if plan.values["archive_state"] == ServiceArchiveState.ISSUE_KEY.value:
        print(
            f"[WARN] Archived previous service private key: "
            f"{plan.values['archive_key_destination']}",
            file=stream,
        )
    print(
        f"[OK] Issued service certificate: "
        f"{plan.values['service_certificate_destination']}",
        file=stream,
    )
    stream.flush()
    return 0
