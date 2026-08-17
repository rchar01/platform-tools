"""Read-only operational status for final-Bash CA rollover state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from contextlib import ExitStack

from .ca_rollover_recovery import (
    IntermediateBootstrapRecoveryRecord,
    LegacyMigrationRecoveryRecord,
    PreparationTerminalOutcome,
    RecoveryOperation,
    RecoveryRecordError,
    RecoveryStatusHeader,
    RolloverPrepareRecoveryRecord,
    RootBootstrapRecoveryRecord,
    is_terminal_bootstrap_record,
    parse_preparation_terminal_marker,
    parse_recovery_fields,
    parse_recovery_semantics,
    parse_recovery_status_header,
)
from .errors import ApplicationError
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    DirectoryIdentity,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    MetadataEntry,
    OpenedDirectory,
    OpenedFile,
    identity_at,
    open_descendant_file,
    walk_metadata,
)
from .operational import (
    acquire_operational_locks,
    detect_layout,
    prepare_control_state,
    require_pki_directory,
    require_program,
    resolve_paths,
    validate_service_name,
)
from .parser import ParseResult
from .persisted_identity import (
    PersistedIdentityError,
    parse_directory_identity,
    parse_file_identity,
)
from .subprocesses import ProcessResult, run_process
from .tree_manifests import (
    MAX_TREE_MANIFEST_BYTES,
    MAX_TREE_MANIFEST_DEPTH,
    MAX_TREE_MANIFEST_ENTRIES,
)


_UID = os.geteuid()
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=_UID, mode=0o700)
_PRIVATE_RECORD = FilePolicy(owner=_UID, mode=0o600, links=1, max_size=1024 * 1024)
_PUBLIC_CERTIFICATE = FilePolicy(
    owner=_UID, forbidden_bits=0o022, links=1, max_size=1024 * 1024
)
_TRANSACTION = re.compile(
    r"prepare-(root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII
)
_SAFE_RECOVERY_VALUE = re.compile(r"[a-z0-9-]+", re.ASCII)
_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_UPPER_SHA256 = re.compile(r"[0-9A-F]{64}", re.ASCII)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII
)
_ROLLOVER_FIELDS = (
    "schema",
    "transaction",
    "type",
    "phase",
    "created_at",
    "old_root",
    "old_intermediate",
    "candidate_root",
    "candidate_intermediate",
    "old_root_fingerprint",
    "old_intermediate_fingerprint",
    "candidate_root_fingerprint",
    "candidate_intermediate_fingerprint",
    "candidate_root_expiry",
    "candidate_intermediate_expiry",
    "trust_bundle_sha256",
    "trust_snapshot_sha256",
    "candidate_root_tree_sha256",
    "candidate_intermediate_tree_sha256",
    "backup_state_sha256",
)


def _lexists(path: str) -> bool:
    return os.path.lexists(path)


def _before_output() -> None:
    """Test seam immediately before final status-state rechecks."""


def _write(value: str) -> None:
    sys.stdout.write(value)
    sys.stdout.flush()


def _read_bytes(
    path: str, label: str, retained: list[OpenedFile], *, max_size: int | None = None
) -> bytes:
    policy = _PRIVATE_RECORD
    if max_size is not None:
        policy = FilePolicy(owner=_UID, mode=0o600, links=1, max_size=max_size)
    try:
        opened = OpenedFile(path, policy=policy)
        retained.append(opened)
        return opened.read(policy.max_size or 0)
    except FilesystemError:
        raise ApplicationError(f"{label} is unsafe: {path}") from None


def _read_record(
    path: str, label: str, retained: list[OpenedFile]
) -> dict[str, str]:
    data = _read_bytes(path, label, retained)

    values: dict[str, str] = {}
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for line in lines:
        if b"=" not in line:
            raise ApplicationError(f"{label} has invalid content")
        raw_key, raw_value = line.split(b"=", 1)
        if (
            re.fullmatch(rb"[a-z0-9_]+", raw_key, re.ASCII) is None
            or any(byte < 32 or byte == 127 for byte in raw_value)
        ):
            raise ApplicationError(f"{label} has invalid content")
        key = raw_key.decode("ascii")
        if key in values:
            raise ApplicationError(f"{label} contains duplicate field: {key}")
        values[key] = raw_value.decode("utf-8", "surrogateescape")
    return values


def _read_pair(
    path: str, label: str, retained: list[OpenedFile]
) -> tuple[str, str]:
    data = b""
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ApplicationError(
            f"{label} manifest must be a non-symlink regular file: {path}"
        ) from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApplicationError(
            f"{label} manifest must be a non-symlink regular file: {path}"
        )
    if (
        metadata.st_uid != _UID
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ApplicationError(
            f"{label} manifest must be current-user-owned, singly linked, and mode 600: {path}"
        )
    try:
        opened = OpenedFile(path, policy=_PRIVATE_RECORD)
        retained.append(opened)
        data = opened.read(_PRIVATE_RECORD.max_size or 0)
    except FilesystemError:
        raise ApplicationError(f"{label} manifest identity changed while opening") from None
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if (
        len(lines) != 2
        or not lines[0].startswith(b"root=")
        or not lines[1].startswith(b"intermediate=")
    ):
        raise ApplicationError(f"{label} manifest has invalid content: {path}")
    try:
        root = lines[0][5:].decode("ascii")
        intermediate = lines[1][13:].decode("ascii")
    except UnicodeDecodeError:
        raise ApplicationError(f"{label} manifest has invalid content: {path}") from None
    if _ROOT_GENERATION.fullmatch(root) is None:
        raise ApplicationError(f"Invalid root generation ID: {root}")
    if _INTERMEDIATE_GENERATION.fullmatch(intermediate) is None:
        raise ApplicationError(f"Invalid intermediate generation ID: {intermediate}")
    if not intermediate.startswith(f"{root}-i"):
        raise ApplicationError(f"{label} manifest selects mismatched generations")
    return root, intermediate


def _require_private_directory(path: str, label: str) -> OpenedDirectory:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ApplicationError(f"{label} must be a non-symlink directory: {path}") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApplicationError(f"{label} must be a non-symlink directory: {path}")
    if metadata.st_uid != _UID or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ApplicationError(f"{label} must be current-user-owned with mode 700: {path}")
    try:
        return OpenedDirectory(path, policy=_PRIVATE_DIRECTORY)
    except FilesystemError:
        raise ApplicationError(f"{label} changed while opening: {path}") from None


def _run_external(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    *,
    pass_fds: tuple[int, ...] = (),
) -> ProcessResult:
    result = run_process(
        argv,
        env=environment,
        pass_fds=pass_fds,
        timeout=30.0,
        term_grace=1.0,
        stdout_limit=4 * 1024 * 1024,
        stderr_limit=1024 * 1024,
    )
    assert isinstance(result, ProcessResult)
    return result


def _run_text(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    *,
    pass_fds: tuple[int, ...] = (),
) -> tuple[int, str]:
    result = _run_external(argv, environment, pass_fds=pass_fds)
    sys.stderr.buffer.write(result.stderr)
    sys.stderr.buffer.flush()
    if result.status:
        return result.status, ""
    try:
        return 0, result.stdout.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError:
        raise ApplicationError("External command returned invalid text") from None


def _certificate_observables(
    certificate: OpenedFile, environment: Mapping[str, str]
) -> tuple[int, str, str]:
    descriptor = certificate.fileno()
    path = f"/proc/self/fd/{descriptor}"
    status, fingerprint = _run_text(
        ("openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"),
        environment,
        pass_fds=(descriptor,),
    )
    if status:
        return status, "", ""
    fingerprint = fingerprint.partition("=")[2].replace(":", "")
    status, enddate = _run_text(
        ("openssl", "x509", "-in", path, "-noout", "-enddate"),
        environment,
        pass_fds=(descriptor,),
    )
    if status:
        return status, "", ""
    status, expiry = _run_text(
        (
            "date",
            "-u",
            "-d",
            enddate.removeprefix("notAfter="),
            "+%Y-%m-%dT%H:%M:%SZ",
        ),
        environment,
    )
    return status, fingerprint, expiry


def _open_certificate(
    stack: ExitStack,
    authority: OpenedDirectory,
    name: str,
    path: str,
) -> OpenedFile:
    try:
        return stack.enter_context(
            open_descendant_file(
                authority,
                ("certs", name),
                directory_policy=_PRIVATE_DIRECTORY,
                file_policy=_PUBLIC_CERTIFICATE,
            )
        )
    except FilesystemError:
        raise ApplicationError(f"Required file is missing: {path}") from None


def _recheck_certificates(certificates: tuple[OpenedFile, ...]) -> None:
    checked: set[int] = set()
    try:
        for certificate in certificates:
            descriptor = certificate.fileno()
            if descriptor not in checked:
                certificate.recheck()
                checked.add(descriptor)
    except FilesystemError:
        raise ApplicationError("Certificate identity changed before status output") from None


def _recheck_status_state(
    records: tuple[OpenedFile, ...],
    required_absences: tuple[str, ...],
    certificates: tuple[OpenedFile, ...] = (),
) -> None:
    _before_output()
    try:
        for record in records:
            record.recheck()
        for path in required_absences:
            try:
                present = identity_at(path) is not ABSENT
            except FilesystemError:
                present = _lexists(path)
            if present:
                raise FilesystemError("status-required absence changed")
    except FilesystemError:
        raise ApplicationError("Status record identity changed before output") from None
    _recheck_certificates(certificates)


def _emit(
    value: str,
    retained: list[OpenedFile],
    required_absences: list[str],
    certificates: tuple[OpenedFile, ...] = (),
) -> None:
    _recheck_status_state(tuple(retained), tuple(required_absences), certificates)
    _write(value)


def _require_no_unresolved_journal(
    pki_dir: str, retained: list[OpenedFile], required_absences: list[str]
) -> None:
    finalization = f"{pki_dir}/state/csr/finalization-recovery-journal"
    signing = f"{pki_dir}/state/csr/recovery-journal"
    marker = f"{pki_dir}/state/rollover/recovery-required"
    journal = f"{pki_dir}/state/rollover/journal"
    if _lexists(finalization):
        state = _read_record(
            finalization, "CSR candidate finalization recovery journal", retained
        )
        if state.get("operation") != "csr-finalize":
            raise ApplicationError(
                f"Unsupported CSR finalization recovery state blocks this command: {finalization}"
            )
        raise ApplicationError(
            "CSR candidate finalization recovery is required before this command can continue: "
            f"{finalization}"
        )
    required_absences.append(finalization)
    if _lexists(signing):
        state = _read_record(
            signing, "Authenticated CSR signing recovery journal", retained
        )
        if state.get("operation") == "csr-sign":
            raise ApplicationError(
                "Authenticated CSR signing recovery is required before this command can continue: "
                f"{signing}"
            )
        raise ApplicationError(f"Unsupported CSR recovery state blocks this command: {signing}")
    required_absences.append(signing)
    if _lexists(marker):
        raise ApplicationError(
            f"PKI recovery is required before this command can continue: {marker}"
        )
    if marker not in required_absences:
        required_absences.append(marker)
    if _lexists(journal):
        data = _read_bytes(journal, "PKI recovery journal", retained, max_size=256 * 1024)
        try:
            state = parse_recovery_semantics(data, pki_dir=pki_dir)
        except RecoveryRecordError:
            raise ApplicationError("PKI recovery journal has invalid recovery state") from None
        terminal = is_terminal_bootstrap_record(state) or state.committed and (
            isinstance(state, LegacyMigrationRecoveryRecord)
            and (
                state.phase == "complete"
                and (state.recovery_action is None or state.recovery_action.value == "resume")
                and state.recovery_step in (None, "resume-provenance-done")
                or state.phase == "rolled-back"
                and state.recovery_action is not None
                and state.recovery_action.value == "rollback"
                and state.recovery_step == "rollback-provenance-done"
            )
        )
        if not terminal:
            raise ApplicationError(
                f"PKI recovery is required before this command can continue: {journal}"
            )
    elif journal not in required_absences:
        required_absences.append(journal)


def _load_active_issuer(
    pki_dir: str,
    environment: Mapping[str, str],
    stack: ExitStack,
    retained: list[OpenedFile],
    required_absences: list[str],
) -> tuple[str, str, OpenedFile, OpenedFile]:
    _require_no_unresolved_journal(pki_dir, retained, required_absences)
    active = f"{pki_dir}/state/active-issuer"
    root, intermediate = _read_pair(active, "Active issuer", retained)
    root_path = f"{pki_dir}/authorities/roots/{root}"
    intermediate_path = f"{pki_dir}/authorities/intermediates/{intermediate}"
    root_dir = stack.enter_context(
        _require_private_directory(root_path, "Root authority generation")
    )
    intermediate_dir = stack.enter_context(
        _require_private_directory(
            intermediate_path,
            "Intermediate authority generation",
        )
    )
    root_certificate = _open_certificate(
        stack, root_dir, "root-ca.crt", f"{root_path}/certs/root-ca.crt"
    )
    intermediate_certificate = _open_certificate(
        stack,
        intermediate_dir,
        "intermediate-ca.crt",
        f"{intermediate_path}/certs/intermediate-ca.crt",
    )
    root_descriptor = root_certificate.fileno()
    intermediate_descriptor = intermediate_certificate.fileno()
    result = _run_external(
        (
            "openssl",
            "verify",
            "-CAfile",
            f"/proc/self/fd/{root_descriptor}",
            f"/proc/self/fd/{intermediate_descriptor}",
        ),
        environment,
        pass_fds=(root_descriptor, intermediate_descriptor),
    )
    sys.stderr.buffer.write(result.stderr)
    sys.stderr.buffer.flush()
    if result.status:
        raise ApplicationError("Active intermediate does not verify against its recorded root")
    _recheck_certificates((root_certificate, intermediate_certificate))
    return root, intermediate, root_certificate, intermediate_certificate


def _service_directories(
    pki_dir: str, retained: list[OpenedFile]
) -> tuple[tuple[str, tuple[str, str]], ...]:
    services_dir = f"{pki_dir}/services"
    try:
        names = sorted(
            (name for name in os.listdir(services_dir) if not name.startswith(".")),
            key=os.fsencode,
        )
    except FileNotFoundError:
        return ()
    except OSError:
        raise ApplicationError("Service state could not be inspected") from None
    result = []
    for name in names:
        path = f"{services_dir}/{name}"
        try:
            metadata = os.lstat(path)
        except OSError:
            raise ApplicationError(f"Service state directory is unsafe: {path}") from None
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ApplicationError(f"Service state directory is unsafe: {path}")
        validate_service_name(name)
        issuer = f"{path}/issuer"
        try:
            issuer_metadata = os.lstat(issuer)
        except OSError:
            raise ApplicationError(
                f"Service {name} issuer manifest is missing or unsafe"
            ) from None
        if not stat.S_ISREG(issuer_metadata.st_mode) or stat.S_ISLNK(
            issuer_metadata.st_mode
        ):
            raise ApplicationError(f"Service {name} issuer manifest is missing or unsafe")
        pair = _read_pair(issuer, f"Service {name} issuer", retained)
        result.append((name, pair))
    return tuple(result)


def _metadata_identity(entry: MetadataEntry) -> FileIdentity:
    if entry.kind not in ("regular", "directory"):
        raise ApplicationError("PKI tree contains an unsupported object")
    return FileIdentity(
        dev=entry.dev,
        ino=entry.ino,
        uid=entry.uid,
        permissions=entry.permissions,
        links=entry.links,
        size=entry.size,
        mtime_ns=entry.mtime_ns,
        ctime_ns=entry.ctime_ns,
        kind=entry.kind,
    )


def _secret_member(relative: tuple[str, ...]) -> bool:
    encoded = b"/".join(os.fsencode(part) for part in relative)
    return (
        b"private" in (os.fsencode(part) for part in relative[:-1])
        or encoded.endswith(b".key")
        or b"passphrase" in encoded
    )


def _hash_opened(opened: OpenedFile) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < opened.identity.size:
        try:
            chunk = os.pread(
                opened.fileno(), min(64 * 1024, opened.identity.size - offset), offset
            )
        except OSError:
            raise ApplicationError("PKI tree public member could not be read") from None
        if not chunk:
            raise ApplicationError("PKI tree public member changed while reading")
        digest.update(chunk)
        offset += len(chunk)
    try:
        opened.recheck()
    except FilesystemError:
        raise ApplicationError("PKI tree public member changed while reading") from None
    return digest.hexdigest()


def _validate_tree(
    root_path: str,
    manifest_path: str,
    digest: str,
    excluded: str | None = None,
    opened_members: Mapping[tuple[str, ...], OpenedFile] | None = None,
    retained: list[OpenedFile] | None = None,
) -> None:
    parent_path, root_name = os.path.split(root_path)
    try:
        manifest = OpenedFile(
            manifest_path,
            policy=FilePolicy(owner=_UID, links=1, max_size=MAX_TREE_MANIFEST_BYTES),
        )
        if retained is not None:
            retained.append(manifest)
        with OpenedDirectory(parent_path) as parent, parent.open_directory(
            root_name
        ) as root:
            data = manifest.read(MAX_TREE_MANIFEST_BYTES)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ApplicationError("PKI tree manifest digest changed")
            if data and not data.endswith(b"\n"):
                raise ApplicationError("PKI tree manifest has invalid content")
            lines = data[:-1].split(b"\n") if data else []
            if len(lines) > MAX_TREE_MANIFEST_ENTRIES:
                raise ApplicationError("PKI tree manifest has invalid content")
            expected: dict[
                tuple[str, ...], tuple[FileIdentity | DirectoryIdentity, bytes]
            ] = {}
            previous: bytes | None = None
            for line in lines:
                fields = line.split(b"|")
                if len(fields) != 4:
                    raise ApplicationError("PKI tree manifest has invalid content")
                raw_type, raw_relative, raw_identity, raw_digest = fields
                components = raw_relative.split(b"/")
                if (
                    not raw_relative
                    or raw_relative.startswith(b"/")
                    or any(part in (b"", b".", b"..") for part in components)
                    or len(components) > MAX_TREE_MANIFEST_DEPTH
                    or previous is not None
                    and raw_relative <= previous
                ):
                    raise ApplicationError("PKI tree manifest has invalid content")
                previous = raw_relative
                relative = tuple(os.fsdecode(part) for part in components)
                try:
                    identity_text = raw_identity.decode("ascii")
                    if raw_type == b"directory":
                        parsed = parse_directory_identity(identity_text)
                        assert isinstance(parsed, DirectoryIdentity)
                        identity: FileIdentity | DirectoryIdentity = parsed
                        if raw_digest != b"-":
                            raise ValueError
                    elif raw_type in (b"regular file", b"regular empty file"):
                        parsed_file = parse_file_identity(identity_text)
                        assert isinstance(parsed_file, FileIdentity)
                        identity = parsed_file
                        expected_type = (
                            b"regular empty file" if identity.size == 0 else b"regular file"
                        )
                        if raw_type != expected_type:
                            raise ValueError
                        if _secret_member(relative):
                            if raw_digest != b"secret":
                                raise ValueError
                        elif _LOWER_SHA256.fullmatch(
                            raw_digest.decode("ascii")
                        ) is None:
                            raise ValueError
                    else:
                        raise ValueError
                except (AssertionError, PersistedIdentityError, UnicodeDecodeError, ValueError):
                    raise ApplicationError("PKI tree manifest has invalid content") from None
                expected[relative] = (identity, raw_digest)

            excluded_relative = (excluded,) if excluded is not None else None
            actual: dict[tuple[str, ...], FileIdentity] = {}
            for entry in walk_metadata(root, xdev=True):
                if not entry.relative or entry.relative == excluded_relative:
                    continue
                if (
                    entry.dev != root.identity.dev
                    or len(entry.relative) > MAX_TREE_MANIFEST_DEPTH
                    or entry.uid != _UID
                    or entry.permissions & 0o022
                    or entry.kind == "regular"
                    and entry.links != 1
                ):
                    raise ApplicationError("PKI tree contents do not match their manifest")
                actual[entry.relative] = _metadata_identity(entry)
            if len(actual) > MAX_TREE_MANIFEST_ENTRIES or actual.keys() != expected.keys():
                raise ApplicationError("PKI tree contents do not match their manifest")
            for relative, identity in actual.items():
                expected_identity, expected_digest = expected[relative]
                if identity.kind == "directory":
                    if (
                        not isinstance(expected_identity, DirectoryIdentity)
                        or identity.directory != expected_identity
                    ):
                        raise ApplicationError("PKI tree contents do not match their manifest")
                    continue
                if not isinstance(expected_identity, FileIdentity) or identity != expected_identity:
                    raise ApplicationError("PKI tree contents do not match their manifest")
                if _secret_member(relative):
                    continue
                supplied = None if opened_members is None else opened_members.get(relative)
                if supplied is not None:
                    if supplied.identity != identity or _hash_opened(supplied) != expected_digest.decode(
                        "ascii"
                    ):
                        raise ApplicationError(
                            "PKI tree contents do not match their manifest"
                        )
                    continue
                with open_descendant_file(
                    root, relative, expected_identity=identity
                ) as opened:
                    if _hash_opened(opened) != expected_digest.decode("ascii"):
                        raise ApplicationError(
                            "PKI tree contents do not match their manifest"
                        )
            manifest.recheck()
            root.recheck()
            parent.recheck()
    except FilesystemError:
        if not _lexists(manifest_path):
            raise ApplicationError("PKI tree manifest identity changed") from None
        raise ApplicationError(
            f"PKI tree contents do not match their manifest: {root_path}"
        ) from None
    except ApplicationError as error:
        if str(error) == "PKI tree manifest digest changed":
            raise
        if str(error).startswith("PKI tree contents do not match"):
            raise ApplicationError(
                f"PKI tree contents do not match their manifest: {root_path}"
            ) from None
        if str(error).startswith("PKI tree manifest"):
            raise
        raise ApplicationError(
            f"PKI tree contents do not match their manifest: {root_path}"
        ) from None


def _marker_header(data: bytes) -> tuple[str, str, str]:
    try:
        terminal = parse_preparation_terminal_marker(data)
    except RecoveryRecordError:
        try:
            fields = parse_recovery_fields(data)
        except RecoveryRecordError:
            fields = None
        if fields is not None and dict(fields).get("terminal_outcome", "none") != "none":
            raise ApplicationError(
                "PKI recovery marker has invalid terminal preparation state"
            ) from None
        lines = data.splitlines(keepends=True)
        if len(lines) != 2 or not data.endswith(b"\n"):
            raise ApplicationError("PKI recovery marker has invalid recovery state") from None
        expected = b"action=run platform-pki-ca-rollover recover\n"
        if not lines[0].startswith(b"transaction=") or lines[1] != expected:
            raise ApplicationError("PKI recovery marker has invalid recovery state") from None
        try:
            transaction = lines[0][12:-1].decode("ascii")
        except UnicodeDecodeError:
            raise ApplicationError("PKI recovery marker has invalid recovery state") from None
        patterns = (
            (
                re.compile(r"migrate-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII),
                "legacy-migrate",
            ),
            (
                re.compile(r"root-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+", re.ASCII),
                "root-bootstrap",
            ),
            (
                re.compile(
                    r"intermediate-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+",
                    re.ASCII,
                ),
                "intermediate-bootstrap",
            ),
            (_TRANSACTION, "rollover-prepare"),
        )
        for pattern, operation in patterns:
            if pattern.fullmatch(transaction):
                return transaction, operation, "none"
        raise ApplicationError("PKI recovery marker has invalid recovery state") from None
    return (
        terminal.transaction,
        RecoveryOperation.ROLLOVER_PREPARE.value,
        terminal.outcome.value,
    )


def _recovery_status(
    pki_dir: str,
    output_format: str,
    retained: list[OpenedFile],
    required_absences: list[str],
) -> int | None:
    journal_path = f"{pki_dir}/state/rollover/journal"
    marker_path = f"{pki_dir}/state/rollover/recovery-required"
    marker_exists = _lexists(marker_path)
    journal_exists = _lexists(journal_path)
    marker_transaction = ""
    marker_operation = ""
    marker_outcome = "none"
    if marker_exists:
        marker_data = _read_bytes(marker_path, "PKI recovery marker", retained)
        marker_transaction, marker_operation, marker_outcome = _marker_header(marker_data)
    else:
        required_absences.append(marker_path)
    journal: (
        RootBootstrapRecoveryRecord
        | IntermediateBootstrapRecoveryRecord
        | LegacyMigrationRecoveryRecord
        | RolloverPrepareRecoveryRecord
        | RecoveryStatusHeader
        | None
    ) = None
    if journal_exists:
        journal_data = _read_bytes(
            journal_path, "PKI recovery journal", retained, max_size=256 * 1024
        )
        try:
            journal = parse_recovery_semantics(journal_data, pki_dir=pki_dir)
        except RecoveryRecordError:
            try:
                header = parse_recovery_status_header(journal_data)
            except RecoveryRecordError:
                raise ApplicationError(
                    "PKI recovery journal has invalid recovery state"
                ) from None
            if header.committed:
                raise ApplicationError(
                    "PKI recovery journal has invalid recovery state"
                ) from None
            journal = header
        journal_requires_recovery = (
            isinstance(journal, (RolloverPrepareRecoveryRecord, RecoveryStatusHeader))
            or not journal.committed
        )
    else:
        required_absences.append(journal_path)
        journal_requires_recovery = False
    if not marker_exists and not journal_requires_recovery:
        return None

    transaction = journal["transaction"] if journal is not None else marker_transaction
    operation = journal.operation.value if journal is not None else marker_operation
    phase = journal.phase if journal is not None else "terminal-cleanup"
    terminal_outcome = marker_outcome
    if isinstance(journal, RolloverPrepareRecoveryRecord):
        terminal_outcome = (
            journal.terminal_outcome.value
            if journal.terminal_outcome is not None
            else "none"
        )
    if marker_exists and journal is not None and (
        transaction != marker_transaction
        or operation != marker_operation
        or marker_outcome != "none"
        and terminal_outcome != marker_outcome
    ):
        raise ApplicationError("PKI recovery marker and journal do not match")
    if any(
        _SAFE_RECOVERY_VALUE.fullmatch(value) is None
        for value in (transaction, operation, phase, terminal_outcome)
    ):
        raise ApplicationError("PKI recovery state contains an unsafe status scalar")
    action = "rollback"
    if isinstance(journal, RolloverPrepareRecoveryRecord):
        if terminal_outcome == "resumed":
            action = "resume"
        elif terminal_outcome == "rolled-back":
            action = "rollback"
        elif journal.recovery_action is not None:
            action = journal.recovery_action.value
        elif journal["candidate_intermediate_identity"] != "none":
            action = "resume"
    elif marker_outcome != "none":
        try:
            action = PreparationTerminalOutcome(marker_outcome).action.value
        except ValueError:
            raise ApplicationError("Preparation recovery state has an invalid terminal outcome") from None
    if output_format == "json":
        _emit(
            '{"schema":2,"status":"recovery-required","recovery_required":true,'
            f'"transaction":"{transaction}","operation":"{operation}",'
            f'"phase":"{phase}","terminal_outcome":"{terminal_outcome}",'
            f'"required_action":"{action}"}}\n',
            retained,
            required_absences,
        )
    else:
        _emit(
            "status=recovery-required\n"
            "recovery_required=true\n"
            f"transaction={transaction}\n"
            f"operation={operation}\n"
            f"phase={phase}\n"
            f"terminal_outcome={terminal_outcome}\n"
            f"required_action={action}\n"
            "action=run platform-pki ca-rollover recover --transaction "
            f"{transaction} --action {action}\n",
            retained,
            required_absences,
        )
    return 2


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def ca_rollover_status(parsed: ParseResult) -> int:
    """Report exact recovery, layout, active, and prepared rollover state."""

    environment = dict(os.environ)
    paths = resolve_paths(parsed.values, environment)
    output_format = str(parsed["--format"])
    require_program("openssl", environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    require_program("flock", environment)

    with acquire_operational_locks(paths.pki_dir, "export"), ExitStack() as certificates:
        retained: list[OpenedFile] = []
        required_absences: list[str] = []
        certificates.callback(lambda: [record.close() for record in retained])
        recovery = _recovery_status(
            paths.pki_dir, output_format, retained, required_absences
        )
        if recovery is not None:
            return recovery

        layout = detect_layout(paths.pki_dir)
        if layout == "legacy":
            if output_format == "json":
                _emit(
                    '{"schema":1,"status":"legacy","recovery_required":false,'
                    '"required_action":"backup-and-migrate"}\n',
                    retained,
                    required_absences,
                )
            else:
                _emit(
                    "status=legacy\nrecovery_required=false\n"
                    "action=run platform-pki backup, then platform-pki ca-rollover migrate\n",
                    retained,
                    required_absences,
                )
            return 1
        if layout != "generation":
            if output_format == "json":
                _emit(
                    f'{{"schema":1,"status":"{layout}","recovery_required":false,'
                    '"required_action":"repair-layout"}\n',
                    retained,
                    required_absences,
                )
            else:
                _emit(
                    f"status={layout}\nrecovery_required=false\n"
                    "action=repair incomplete or ambiguous PKI layout before continuing\n",
                    retained,
                    required_absences,
                )
            return 2

        (
            active_root,
            active_intermediate,
            active_root_certificate,
            active_intermediate_certificate,
        ) = _load_active_issuer(
            paths.pki_dir,
            environment,
            certificates,
            retained,
            required_absences,
        )
        status, active_root_fp, active_root_expiry = _certificate_observables(
            active_root_certificate, environment
        )
        if status:
            return status
        status, active_intermediate_fp, active_intermediate_expiry = (
            _certificate_observables(
                active_intermediate_certificate, environment
            )
        )
        if status:
            return status
        service_issuers = _service_directories(paths.pki_dir, retained)
        pointer = f"{paths.pki_dir}/state/active-rollover"
        if not _lexists(pointer):
            required_absences.append(pointer)
            for service, pair in service_issuers:
                if pair != (
                    active_root,
                    active_intermediate,
                ):
                    raise ApplicationError(
                        f"Service {service} issuer does not select the active issuer"
                    )
            if output_format == "json":
                _emit(
                    _json(
                        {
                            "schema": 1,
                            "status": "ready",
                            "recovery_required": False,
                            "phase": "idle",
                            "active": {
                                "root": {
                                    "generation": active_root,
                                    "fingerprint_sha256": active_root_fp,
                                    "expires_at": active_root_expiry,
                                },
                                "intermediate": {
                                    "generation": active_intermediate,
                                    "fingerprint_sha256": active_intermediate_fp,
                                    "expires_at": active_intermediate_expiry,
                                },
                            },
                            "candidate": None,
                            "retired": [],
                            "trust_snapshot_sha256": None,
                            "services_on_old_issuer": [],
                            "required_action": None,
                        }
                    )
                    + "\n",
                    retained,
                    required_absences,
                    (active_root_certificate, active_intermediate_certificate),
                )
            else:
                _emit(
                    "status=ready\nrecovery_required=false\nphase=idle\n"
                    f"active_root={active_root}\n"
                    f"active_root_fingerprint_sha256={active_root_fp}\n"
                    f"active_root_expires_at={active_root_expiry}\n"
                    f"active_intermediate={active_intermediate}\n"
                    f"active_intermediate_fingerprint_sha256={active_intermediate_fp}\n"
                    f"active_intermediate_expires_at={active_intermediate_expiry}\n"
                    "candidate_root=none\ncandidate_intermediate=none\nretired=none\n"
                    "trust_snapshot_sha256=none\nservices_on_old_issuer=none\naction=none\n",
                    retained,
                    required_absences,
                    (active_root_certificate, active_intermediate_certificate),
                )
            return 0

        pointer_record = _read_record(pointer, "Active rollover pointer", retained)
        transaction = pointer_record.get("transaction", "")
        rollover_tree_digest = pointer_record.get("tree_manifest_sha256", "")
        if not (
            len(pointer_record) == 2
            and _TRANSACTION.fullmatch(transaction)
            and _LOWER_SHA256.fullmatch(rollover_tree_digest)
        ):
            raise ApplicationError("Active rollover pointer is invalid")
        rollover_dir = f"{paths.pki_dir}/state/rollovers/{transaction}"
        try:
            metadata = os.lstat(rollover_dir)
        except OSError:
            raise ApplicationError("Rollover transaction state directory is unsafe") from None
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ApplicationError("Rollover transaction state directory is unsafe")
        _validate_tree(
            rollover_dir,
            f"{rollover_dir}/tree.manifest",
            rollover_tree_digest,
            "tree.manifest",
            retained=retained,
        )
        manifest = _read_record(
            f"{rollover_dir}/manifest", "Rollover manifest", retained
        )
        for field in _ROLLOVER_FIELDS:
            if field not in manifest:
                raise ApplicationError(f"Rollover manifest is missing field: {field}")
        rollover_type = manifest["type"]
        if not (
            len(manifest) == 20
            and manifest["schema"] == "1"
            and manifest["transaction"] == transaction
            and rollover_type in ("root", "intermediate")
            and manifest["phase"] == "prepared"
        ):
            raise ApplicationError("Rollover transaction manifest is invalid")
        old_root = manifest["old_root"]
        old_intermediate = manifest["old_intermediate"]
        candidate_root = manifest["candidate_root"]
        candidate_intermediate = manifest["candidate_intermediate"]
        for generation in (old_root, candidate_root):
            if _ROOT_GENERATION.fullmatch(generation) is None:
                raise ApplicationError(f"Invalid root generation ID: {generation}")
        for generation in (old_intermediate, candidate_intermediate):
            if _INTERMEDIATE_GENERATION.fullmatch(generation) is None:
                raise ApplicationError(f"Invalid intermediate generation ID: {generation}")
        if not (
            old_root == active_root
            and old_intermediate == active_intermediate
            and old_intermediate.startswith(f"{old_root}-i")
            and candidate_intermediate.startswith(f"{candidate_root}-i")
        ):
            raise ApplicationError("Prepared rollover generation relationships are invalid")
        if not (
            _TIMESTAMP.fullmatch(manifest["created_at"])
            and all(
                _UPPER_SHA256.fullmatch(manifest[field])
                for field in (
                    "old_root_fingerprint",
                    "old_intermediate_fingerprint",
                    "candidate_root_fingerprint",
                    "candidate_intermediate_fingerprint",
                )
            )
            and _LOWER_SHA256.fullmatch(manifest["backup_state_sha256"])
        ):
            raise ApplicationError("Rollover manifest public metadata is invalid")
        if rollover_type == "root":
            if not (
                candidate_root != old_root
                and _LOWER_SHA256.fullmatch(manifest["trust_bundle_sha256"])
                and _LOWER_SHA256.fullmatch(manifest["trust_snapshot_sha256"])
                and _LOWER_SHA256.fullmatch(manifest["candidate_root_tree_sha256"])
            ):
                raise ApplicationError("Root rollover trust metadata is invalid")
        elif not (
            candidate_root == old_root
            and manifest["trust_bundle_sha256"] == "none"
            and manifest["trust_snapshot_sha256"] == "none"
            and manifest["candidate_root_tree_sha256"] == "none"
        ):
            raise ApplicationError("Intermediate rollover trust metadata is invalid")
        if _LOWER_SHA256.fullmatch(manifest["candidate_intermediate_tree_sha256"]) is None:
            raise ApplicationError("Candidate intermediate tree metadata is invalid")

        candidate_root_path = f"{paths.pki_dir}/authorities/roots/{candidate_root}"
        candidate_intermediate_path = (
            f"{paths.pki_dir}/authorities/intermediates/{candidate_intermediate}"
        )
        candidate_root_cert_path = (
            f"{paths.pki_dir}/authorities/roots/{candidate_root}/certs/root-ca.crt"
        )
        candidate_intermediate_cert_path = (
            f"{paths.pki_dir}/authorities/intermediates/{candidate_intermediate}/certs/intermediate-ca.crt"
        )
        if candidate_root == active_root:
            candidate_root_certificate = active_root_certificate
        else:
            candidate_root_directory = certificates.enter_context(
                _require_private_directory(
                    candidate_root_path, "Root authority generation"
                )
            )
            candidate_root_certificate = _open_certificate(
                certificates,
                candidate_root_directory,
                "root-ca.crt",
                candidate_root_cert_path,
            )
        candidate_intermediate_directory = certificates.enter_context(
            _require_private_directory(
                candidate_intermediate_path, "Intermediate authority generation"
            )
        )
        candidate_intermediate_certificate = _open_certificate(
            certificates,
            candidate_intermediate_directory,
            "intermediate-ca.crt",
            candidate_intermediate_cert_path,
        )
        if rollover_type == "root":
            _validate_tree(
                f"{paths.pki_dir}/authorities/roots/{candidate_root}",
                f"{rollover_dir}/candidate-root-tree.manifest",
                manifest["candidate_root_tree_sha256"],
                opened_members={
                    ("certs", "root-ca.crt"): candidate_root_certificate
                },
                retained=retained,
            )
        _validate_tree(
            f"{paths.pki_dir}/authorities/intermediates/{candidate_intermediate}",
            f"{rollover_dir}/candidate-intermediate-tree.manifest",
            manifest["candidate_intermediate_tree_sha256"],
            opened_members={
                ("certs", "intermediate-ca.crt"): candidate_intermediate_certificate
            },
            retained=retained,
        )
        root_descriptor = candidate_root_certificate.fileno()
        intermediate_descriptor = candidate_intermediate_certificate.fileno()
        verification = _run_external(
            (
                "openssl",
                "verify",
                "-CAfile",
                f"/proc/self/fd/{root_descriptor}",
                f"/proc/self/fd/{intermediate_descriptor}",
            ),
            environment,
            pass_fds=(root_descriptor, intermediate_descriptor),
        )
        sys.stderr.buffer.write(verification.stderr)
        sys.stderr.buffer.flush()
        if verification.status:
            raise ApplicationError(
                "Prepared candidate intermediate does not verify against its recorded root"
            )
        status, candidate_root_fp, candidate_root_expiry = _certificate_observables(
            candidate_root_certificate, environment
        )
        if status:
            return status
        status, candidate_intermediate_fp, candidate_intermediate_expiry = (
            _certificate_observables(candidate_intermediate_certificate, environment)
        )
        if status:
            return status
        if not (
            active_root_fp == manifest["old_root_fingerprint"]
            and active_intermediate_fp == manifest["old_intermediate_fingerprint"]
            and candidate_root_fp == manifest["candidate_root_fingerprint"]
            and candidate_intermediate_fp == manifest["candidate_intermediate_fingerprint"]
            and candidate_root_expiry == manifest["candidate_root_expiry"]
            and candidate_intermediate_expiry == manifest["candidate_intermediate_expiry"]
        ):
            raise ApplicationError("Prepared candidate public metadata changed")

        services_on_old = []
        for service, pair in service_issuers:
            if pair == (old_root, old_intermediate):
                services_on_old.append(service)
            elif pair != (candidate_root, candidate_intermediate):
                raise ApplicationError(
                    f"Service {service} issuer selects an unknown rollover pair"
                )
        status_certificates = (
            active_root_certificate,
            active_intermediate_certificate,
            candidate_root_certificate,
            candidate_intermediate_certificate,
        )
        if output_format == "json":
            _emit(
                _json(
                    {
                        "schema": 1,
                        "status": "prepared",
                        "recovery_required": False,
                        "transaction": transaction,
                        "type": rollover_type,
                        "phase": "prepared",
                        "active": {
                            "root": {
                                "generation": old_root,
                                "fingerprint_sha256": manifest["old_root_fingerprint"],
                                "expires_at": active_root_expiry,
                            },
                            "intermediate": {
                                "generation": old_intermediate,
                                "fingerprint_sha256": manifest[
                                    "old_intermediate_fingerprint"
                                ],
                                "expires_at": active_intermediate_expiry,
                            },
                        },
                        "candidate": {
                            "root": {
                                "generation": candidate_root,
                                "fingerprint_sha256": manifest[
                                    "candidate_root_fingerprint"
                                ],
                                "expires_at": manifest["candidate_root_expiry"],
                            },
                            "intermediate": {
                                "generation": candidate_intermediate,
                                "fingerprint_sha256": manifest[
                                    "candidate_intermediate_fingerprint"
                                ],
                                "expires_at": manifest["candidate_intermediate_expiry"],
                            },
                        },
                        "retired": [],
                        "trust_bundle_sha256": manifest["trust_bundle_sha256"],
                        "trust_snapshot_sha256": manifest["trust_snapshot_sha256"],
                        "services_on_old_issuer": services_on_old,
                        "required_action": "immutable-export-evidence",
                    }
                )
                + "\n",
                retained,
                required_absences,
                status_certificates,
            )
        else:
            services_text = ",".join(services_on_old) if services_on_old else "none"
            _emit(
                "status=prepared\nrecovery_required=false\n"
                f"transaction={transaction}\ntype={rollover_type}\nphase=prepared\n"
                f"active_root={old_root}\n"
                f"active_root_fingerprint_sha256={manifest['old_root_fingerprint']}\n"
                f"active_root_expires_at={active_root_expiry}\n"
                f"active_intermediate={old_intermediate}\n"
                "active_intermediate_fingerprint_sha256="
                f"{manifest['old_intermediate_fingerprint']}\n"
                f"active_intermediate_expires_at={active_intermediate_expiry}\n"
                f"candidate_root={candidate_root}\n"
                f"candidate_root_fingerprint_sha256={manifest['candidate_root_fingerprint']}\n"
                f"candidate_root_expires_at={manifest['candidate_root_expiry']}\n"
                f"candidate_intermediate={candidate_intermediate}\n"
                "candidate_intermediate_fingerprint_sha256="
                f"{manifest['candidate_intermediate_fingerprint']}\n"
                f"candidate_intermediate_expires_at={manifest['candidate_intermediate_expiry']}\n"
                "retired=none\n"
                f"trust_bundle_sha256={manifest['trust_bundle_sha256']}\n"
                f"trust_snapshot_sha256={manifest['trust_snapshot_sha256']}\n"
                f"services_on_old_issuer={services_text}\n"
                "action=immutable export/evidence milestone required before activation\n",
                retained,
                required_absences,
                status_certificates,
            )
        return 1
