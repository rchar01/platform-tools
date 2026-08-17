"""Offline approval and protected-directory host-local CSR signing facade."""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
import re
import secrets
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import NoReturn

from .csr_history import CsrHistoryAuthentication, CsrHistoryError, authenticate_active_predecessor
from .csr_protocol import (
    CsrApproval,
    CsrOperation,
    CsrProtocolError,
    CsrRequest,
    parse_csr_approval,
    parse_csr_request,
    serialize_csr_approval,
    validate_request_approval_binding,
)
from .csr_recover import _load_active_signing_authority, _require_compatible_signing_state
from .errors import ApplicationError
from .faults import FaultHook, PauseHook
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
    prepare_control_state,
    require_pki_directory,
    require_program,
    resolve_paths,
)
from .parser import ParseResult
from .paths import expand_home
from .publication import PublicationError, fsync_tree, publish_no_clobber, remove_exact_tree
from .service_issue import (
    HostLocalCsrReview,
    _CsrInput,
    _CsrTrust,
    _csr_input,
    _csr_load_trust,
    _csr_recheck_input,
    _csr_recheck_trust,
    _csr_spki_digest,
    _csr_validate_request,
    _csr_validate_times,
    _csr_verify_signature,
    _recheck_evidence,
    _run_openssl,
    _sha256,
    _snapshot_file,
    issue_host_local_csr,
    renew_host_local_csr,
)
from .ssh_keys import run_ssh_keygen


_OWNER = os.geteuid()
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_PRIVATE_FILE = FilePolicy(owner=_OWNER, mode=0o600, links=1, max_size=1024 * 1024)
_UNTRUSTED_FILE = FilePolicy(links=1, max_size=1024 * 1024)
_REQUEST_NAMES = ("tls.csr", "request", "request.sig")
_APPROVED_NAMES = (*_REQUEST_NAMES, "approval", "approval.sig")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _checkpoint(point: str, fault: FaultHook, pause: PauseHook) -> None:
    fault(point)
    pause(point)


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    path: str
    identity: DirectoryIdentity
    files: Mapping[str, _CsrInput]
    local: bool

    def recheck(self, label: str, *, exact: bool = True) -> None:
        policy = _PRIVATE_DIRECTORY if self.local else DirectoryPolicy()
        file_policy = _PRIVATE_FILE if self.local else _UNTRUSTED_FILE
        seen: set[tuple[int, int]] = set()
        try:
            with OpenedDirectory(
                self.path, policy=policy, expected_identity=self.identity
            ) as directory:
                names = tuple(sorted(os.listdir(directory.fileno())))
                if (exact and names != tuple(sorted(self.files))) or (
                    not exact and not set(self.files) <= set(names)
                ):
                    _die(f"{label} directory contents changed")
                for name, item in self.files.items():
                    with directory.open_file(
                        name,
                        policy=file_policy,
                        expected_identity=item.identity,
                    ) as opened:
                        inode = (opened.identity.dev, opened.identity.ino)
                        if inode in seen or opened.read(1024 * 1024) != item.data:
                            _die(f"{label} file changed: {name}")
                        seen.add(inode)
                        opened.recheck()
                directory.recheck()
        except FilesystemError:
            _die(f"{label} directory changed")


@dataclass(frozen=True, slots=True)
class _ApprovalPreflight:
    request: CsrRequest
    trust: _CsrTrust
    service: InventoryService
    inventory: object
    inventory_digest: str
    csr_digest: str
    csr_spki_digest: str
    approval_key: _CsrInput
    current_certificate: _CsrInput | None
    history: CsrHistoryAuthentication | None
    state_recheck: Callable[[], None]


def _absolute(value: str, environment: Mapping[str, str]) -> str:
    home = environment.get("HOME")
    if home is None:
        _die("HOME is required")
    return os.path.abspath(expand_home(value, home=home))


def _snapshot_directory(path: str, names: tuple[str, ...], *, local: bool) -> _DirectorySnapshot:
    policy = _PRIVATE_DIRECTORY if local else DirectoryPolicy()
    file_policy = _PRIVATE_FILE if local else _UNTRUSTED_FILE
    files: dict[str, _CsrInput] = {}
    directory_identity: DirectoryIdentity | None = None
    seen: set[tuple[int, int]] = set()
    try:
        with OpenedDirectory(path, policy=policy) as directory:
            if tuple(sorted(os.listdir(directory.fileno()))) != tuple(sorted(names)):
                _die("Offline CSR input directory must contain exactly the canonical files")
            for name in names:
                with directory.open_file(name, policy=file_policy) as opened:
                    inode = (opened.identity.dev, opened.identity.ino)
                    data = opened.read(1024 * 1024)
                    if not data:
                        _die(f"Offline CSR input file must not be empty: {name}")
                    if inode in seen:
                        _die("Offline CSR input files must not share an inode")
                    seen.add(inode)
                    files[name] = _CsrInput(
                        f"{path}/{name}", opened.recheck(), data
                    )
            directory_identity = directory.recheck().directory
    except FilesystemError:
        _die("Offline CSR input directory or file is unsafe")
    assert directory_identity is not None
    return _DirectorySnapshot(path, directory_identity, files, local)


def _write_file(directory: OpenedDirectory, name: str, data: bytes) -> _CsrInput:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory.fileno(),
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
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        identity = identity_from_stat(os.fstat(descriptor))
        os.fsync(directory.fileno())
        return _CsrInput(name, identity, data)
    except (OSError, FilesystemError):
        _die("Offline CSR private staging failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _create_stage(
    parent: OpenedDirectory, prefix: str
) -> tuple[str, OpenedDirectory, DirectoryIdentity]:
    for _attempt in range(16):
        name = f".{prefix}.{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            os.fsync(parent.fileno())
            directory = parent.open_directory(name, policy=_PRIVATE_DIRECTORY)
            return name, directory, directory.identity.directory
        except FileExistsError:
            continue
        except (OSError, FilesystemError):
            break
    _die("Offline CSR private staging directory could not be created")


def _reject_retained_approval_stage(
    parent: OpenedDirectory, output_name: str
) -> None:
    prefix = f".{output_name}.approve."
    try:
        retained = any(name.startswith(prefix) for name in os.listdir(parent.fileno()))
        parent.recheck()
    except (OSError, FilesystemError):
        _die("Offline CSR output parent changed during retained-stage inspection")
    if retained:
        _die(
            "Retained offline CSR approval stage requires inspection and explicit removal"
        )


def _cleanup_stage(
    parent: OpenedDirectory,
    name: str,
    expected: DirectoryIdentity,
    *,
    expected_snapshot: _DirectorySnapshot | None = None,
    empty_only: bool = False,
) -> None:
    if parent.identity_at(name) is ABSENT:
        return
    current: FileIdentity | None = None
    readiness = None
    try:
        with parent.open_directory(
            name, policy=_PRIVATE_DIRECTORY, expected_identity=expected
        ) as directory:
            if expected_snapshot is not None:
                expected_snapshot.recheck("Offline CSR private staging")
            elif empty_only and os.listdir(directory.fileno()):
                _die("Offline CSR private staging changed before cleanup")
            current = directory.recheck()
            readiness = fsync_tree(directory, parent, name)
            if expected_snapshot is not None:
                expected_snapshot.recheck("Offline CSR private staging")
            elif empty_only and os.listdir(directory.fileno()):
                _die("Offline CSR private staging changed before cleanup")
        assert current is not None and readiness is not None
        remove_exact_tree(parent, name, current, readiness)
    except (FilesystemError, PublicationError):
        _die("Offline CSR private staging changed before cleanup")


def _derive_key(
    path: str,
    environment: Mapping[str, str],
    expected_blob: str,
    label: str,
) -> _CsrInput:
    identity: FileIdentity | None = None
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=_OWNER, forbidden_bits=0o077, links=1, max_size=1024 * 1024
            ),
        ) as key:
            if key.identity.size == 0:
                _die(f"{label} is empty")
            result = run_ssh_keygen(
                ("ssh-keygen", "-y", "-f", f"/proc/self/fd/{key.fileno()}"),
                environment,
                pass_fds=(key.fileno(),),
            )
            if result.status:
                _die(f"Cannot derive {label} public key")
            fields = result.stdout.decode("ascii", errors="replace").strip().split()
            if len(fields) < 2 or fields[:2] != ["ssh-ed25519", expected_blob]:
                _die(f"{label} does not match installed trust")
            identity = key.recheck()
    except FilesystemError:
        _die(f"{label} must be a safe current-user-owned private key")
    assert identity is not None
    return _CsrInput(path, identity, b"")


def _recheck_key(item: _CsrInput, environment: Mapping[str, str], blob: str, label: str) -> None:
    current = _derive_key(item.path, environment, blob, label)
    if current.identity != item.identity:
        _die(f"{label} changed during approval")


def _temporary_work(parent: str) -> tuple[str, DirectoryIdentity]:
    path = tempfile.mkdtemp(prefix=".platform-pki-offline-csr.", dir=parent)
    os.chmod(path, 0o700)
    return path, identity_from_stat(
        os.stat(path, follow_symlinks=False)
    ).directory


def _remove_work(path: str, expected: DirectoryIdentity) -> None:
    parent_path, name = os.path.split(path)
    try:
        with OpenedDirectory(parent_path) as parent:
            _cleanup_stage(parent, name, expected)
    except FilesystemError:
        _die("Offline CSR validation directory changed before cleanup")


def _request_preflight(
    pki_dir: str,
    source: _DirectorySnapshot,
    service_name: str,
    operation: str,
    request_id: str,
    approval_key_path: str,
    current_cert_path: str | None,
    environment: Mapping[str, str],
    *,
    creating: bool,
) -> _ApprovalPreflight:
    _require_compatible_signing_state(pki_dir)
    inventory_evidence = _snapshot_file(
        f"{pki_dir}/inventory/services.yml",
        "Service inventory",
        private=False,
        keep_data=True,
    )
    assert inventory_evidence is not None and inventory_evidence.data is not None
    try:
        inventory = parse_inventory(inventory_evidence.data)
    except InventoryError as error:
        _die(str(error))
    selected = next(
        (item for item in inventory.services if item.name == service_name), None
    )
    if selected is None or selected.key_custody != "host-local" or selected.target is None:
        _die("Offline CSR service is not an inventory-authorized host-local service")

    trust = _csr_load_trust(pki_dir)
    try:
        request = parse_csr_request(source.files["request"].data)
    except CsrProtocolError as error:
        _die(str(error))
    record = request.record
    if (
        record["service"] != service_name
        or record["operation"] != operation
        or record["request_id"] != request_id
        or record["target"] != selected.target
        or record["requester_principal"] != selected.target
    ):
        _die("Offline CSR explicit coordinates do not match the request")
    if record["response_principal"] != trust.response_principal:
        _die("CSR request response signer does not match installed trust")
    if record["requester_principal"] not in trust.requester_keys:
        _die("CSR requester principal is not trusted")

    inventory_digest = _sha256(inventory_evidence.data)
    csr_digest = _sha256(source.files["tls.csr"].data)
    if record["inventory_sha256"] != inventory_digest or record["csr_sha256"] != csr_digest:
        _die("CSR request inventory or CSR digest binding failed")
    _csr_verify_signature(
        trust.files["requesters.allowed_signers"],
        record["requester_principal"],
        "platform-pki-csr-request-v1",
        source.files["request.sig"],
        source.files["request"].data,
        environment,
        "CSR request",
    )

    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    if now + 300 < request.created_epoch or now > request.expires_epoch + 300:
        _die("CSR request is not currently valid")
    if creating and (request.created_epoch > now or request.expires_epoch <= now):
        _die("CSR request is not nominally current for approval creation")

    work, work_identity = _temporary_work(
        environment.get("TMPDIR") or tempfile.gettempdir()
    )
    csr_spki: str | None = None
    try:
        with OpenedDirectory(work, policy=_PRIVATE_DIRECTORY) as work_directory:
            _write_file(work_directory, "tls.csr", source.files["tls.csr"].data)
            csr_spki = _csr_validate_request(
                f"/proc/{os.getpid()}/fd/{work_directory.fileno()}/tls.csr",
                selected,
                work,
                environment,
            )
    finally:
        _remove_work(work, work_identity)
    assert csr_spki is not None
    if record["csr_spki_sha256"] != csr_spki:
        _die("CSR public-key digest binding failed")

    current: _CsrInput | None = None
    history: CsrHistoryAuthentication | None = None
    state_recheck: Callable[[], None]
    managed_key = f"{pki_dir}/services/{service_name}/private/tls.key"
    managed_certificate = f"{pki_dir}/services/{service_name}/certs/tls.crt"
    if request.operation is CsrOperation.ISSUE:
        if os.path.lexists(managed_key) or os.path.lexists(managed_certificate):
            _die("New host-local issue conflicts with existing managed service state")

        def state_recheck() -> None:
            if os.path.lexists(managed_key) or os.path.lexists(managed_certificate):
                _die("Managed service state changed during offline approval")
    elif request.operation is CsrOperation.MIGRATE:
        key_evidence = _snapshot_file(managed_key, "Managed service private key", private=True)
        certificate_evidence = _snapshot_file(
            managed_certificate, "Managed service certificate", private=False
        )
        assert key_evidence is not None and certificate_evidence is not None
        if record["current_cert_sha256"] != certificate_evidence.digest:
            _die("Migration request does not bind the managed certificate")

        def state_recheck() -> None:
            _recheck_evidence(key_evidence, "Managed service private key")
            _recheck_evidence(certificate_evidence, "Managed service certificate")
    else:
        assert current_cert_path is not None
        current = _csr_input(
            current_cert_path, "Current host-local certificate", private=True
        )
        if record["current_cert_sha256"] != _sha256(current.data):
            _die("Renewal request does not bind the current certificate")
        try:
            history = authenticate_active_predecessor(
                pki_dir,
                selected,
                record["current_cert_sha256"],
                current.path,
                environment,
            )
        except CsrHistoryError as error:
            _die(str(error))
        root_dir, intermediate_dir = _load_active_signing_authority(pki_dir)
        root_certificate = _snapshot_file(
            f"{root_dir}/certs/root-ca.crt", "Root CA certificate", private=False
        )
        intermediate_certificate = _snapshot_file(
            f"{intermediate_dir}/certs/intermediate-ca.crt",
            "Intermediate CA certificate",
            private=False,
        )
        assert root_certificate is not None and intermediate_certificate is not None
        _run_openssl(
            (
                "openssl",
                "verify",
                "-CAfile",
                root_certificate.path,
                "-untrusted",
                intermediate_certificate.path,
                current.path,
            ),
            environment,
            label="current host-local certificate chain verification",
        )

        def state_recheck() -> None:
            assert current is not None and history is not None
            _csr_recheck_input(current, "Current host-local certificate")
            _recheck_evidence(root_certificate, "Root CA certificate")
            _recheck_evidence(
                intermediate_certificate, "Intermediate CA certificate"
            )
            try:
                history()
            except CsrHistoryError as error:
                _die(str(error))

    approval_key = _derive_key(
        approval_key_path,
        environment,
        trust.approver_key,
        "Approval signing key",
    )
    source.recheck("Offline CSR request source")
    _csr_recheck_trust(trust)
    _recheck_evidence(inventory_evidence, "Service inventory")
    if current is not None:
        _csr_recheck_input(current, "Current host-local certificate")
    if history is not None:
        try:
            history()
        except CsrHistoryError as error:
            _die(str(error))
    state_recheck()
    return _ApprovalPreflight(
        request,
        trust,
        selected,
        inventory_evidence,
        inventory_digest,
        csr_digest,
        csr_spki,
        approval_key,
        current,
        history,
        state_recheck,
    )


def _recheck_preflight(
    source: _DirectorySnapshot,
    context: _ApprovalPreflight,
    environment: Mapping[str, str],
    *,
    exact_source: bool = True,
) -> None:
    source.recheck("Offline CSR request source", exact=exact_source)
    _csr_recheck_trust(context.trust)
    _recheck_evidence(context.inventory, "Service inventory")  # type: ignore[arg-type]
    _recheck_key(
        context.approval_key,
        environment,
        context.trust.approver_key,
        "Approval signing key",
    )
    if context.current_certificate is not None:
        _csr_recheck_input(
            context.current_certificate, "Current host-local certificate"
        )
    if context.history is not None:
        try:
            context.history()
        except CsrHistoryError as error:
            _die(str(error))
    context.state_recheck()


def _confirm(expected: str, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        _die("Interactive confirmation requires a TTY; use --yes only after review")
    print(f"Confirmation required: type '{expected}'", file=sys.stderr)
    sys.stderr.flush()
    if sys.stdin.readline().rstrip("\n") != expected:
        _die("Confirmation did not match")


def _approval_summary(context: _ApprovalPreflight) -> None:
    record = context.request.record
    print("Authenticated offline CSR approval review:", file=sys.stderr)
    for name, value in (
        ("operation", record["operation"]),
        ("service", record["service"]),
        ("target", record["target"]),
        ("request_id", record["request_id"]),
        ("request_sha256", _sha256(context.request.to_bytes())),
        ("csr_sha256", context.csr_digest),
        ("inventory_sha256", context.inventory_digest),
        ("requester_principal", record["requester_principal"]),
        ("approver_principal", context.trust.approver_principal),
        ("response_principal", context.trust.response_principal),
    ):
        print(f"  {name}={value}", file=sys.stderr)


def _json(values: Mapping[str, object]) -> None:
    print(json.dumps(values, ensure_ascii=True, separators=(",", ":")))


def _validate_approval(
    context: _ApprovalPreflight,
    source: _DirectorySnapshot,
    approval: _CsrInput,
    signature: _CsrInput,
    environment: Mapping[str, str],
    *,
    exact_source: bool = True,
) -> CsrApproval:
    try:
        parsed = parse_csr_approval(approval.data)
        validate_request_approval_binding(
            context.request,
            parsed,
            signer_keys_match=(
                context.trust.requester_keys[
                    context.request.record["requester_principal"]
                ]
                == context.trust.approver_key
            ),
        )
    except (CsrProtocolError, KeyError) as error:
        _die(str(error))
    if parsed.record["approver_principal"] != context.trust.approver_principal:
        _die("CSR approval principal does not match installed trust")
    _csr_verify_signature(
        context.trust.files["approvers.allowed_signers"],
        parsed.record["approver_principal"],
        "platform-pki-csr-approval-v1",
        signature,
        approval.data,
        environment,
        "CSR approval",
    )
    _csr_validate_times(context.request, parsed)
    _recheck_preflight(
        source, context, environment, exact_source=exact_source
    )
    return parsed


def _approve(arguments: ParseResult, environment: Mapping[str, str]) -> int:
    paths = resolve_paths(arguments.values, environment)
    require_program("openssl", environment)
    require_program("ssh-keygen", environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    service = str(arguments["service"])
    operation = str(arguments["--operation"])
    request_id = str(arguments["--request-id"])
    if _REQUEST_ID.fullmatch(request_id) is None:
        _die("Offline CSR request ID must be 32 lowercase hexadecimal characters")
    input_dir = _absolute(str(arguments["--input-dir"]), environment)
    output_dir = _absolute(str(arguments["--output-dir"]), environment)
    approval_key = _absolute(str(arguments["--approval-key"]), environment)
    current_value = arguments.values.get("--current-cert-file")
    current_cert = (
        None if current_value is None else _absolute(str(current_value), environment)
    )
    fault = FaultHook(
        crash_at=environment.get("PLATFORM_PKI_OFFLINE_CSR_CRASH_AT"),
        signal_at=environment.get("PLATFORM_PKI_OFFLINE_CSR_SIGNAL_AT"),
        failure_at=environment.get("PLATFORM_PKI_OFFLINE_CSR_FAILURE_AT"),
        signum=int(environment.get("PLATFORM_PKI_OFFLINE_CSR_SIGNAL", "15")),
    )
    pause = PauseHook(
        pause_at=environment.get("PLATFORM_PKI_OFFLINE_CSR_PAUSE_AT"),
        marker=environment.get("PLATFORM_PKI_OFFLINE_CSR_PAUSE_MARKER"),
        release=environment.get("PLATFORM_PKI_OFFLINE_CSR_PAUSE_RELEASE"),
    )
    source = _snapshot_directory(input_dir, _REQUEST_NAMES, local=False)
    output_parent_path, output_name = os.path.split(output_dir)
    if not output_name or output_name in {".", ".."}:
        _die("Offline CSR output directory must name an exact destination")

    with acquire_operational_locks(paths.pki_dir, "inventory"):
        try:
            output_parent = OpenedDirectory(
                output_parent_path, policy=_PRIVATE_DIRECTORY
            )
        except FilesystemError:
            _die("Offline CSR output parent must be current-user-owned and mode 700")
        with output_parent:
            _reject_retained_approval_stage(output_parent, output_name)
            existing_identity = output_parent.identity_at(output_name)
            if existing_identity is not ABSENT:
                existing = _snapshot_directory(output_dir, _APPROVED_NAMES, local=True)
                for name in _REQUEST_NAMES:
                    if existing.files[name].data != source.files[name].data:
                        _die("Existing offline CSR approval conflicts with the request")
                context = _request_preflight(
                    paths.pki_dir,
                    source,
                    service,
                    operation,
                    request_id,
                    approval_key,
                    current_cert,
                    environment,
                    creating=False,
                )
                parsed = _validate_approval(
                    context,
                    source,
                    existing.files["approval"],
                    existing.files["approval.sig"],
                    environment,
                )
                _approval_summary(context)
                _confirm(
                    f"approve {service} {request_id}",
                    "--yes" in arguments.provided,
                )
                existing.recheck("Existing offline CSR approval")
                _json(
                    {
                        "status": "existing",
                        "service": service,
                        "request_id": request_id,
                        "approval_dir": output_dir,
                        "approval_sha256": _sha256(parsed.to_bytes()),
                    }
                )
                return 0

            stage_name, stage, stage_identity = _create_stage(
                output_parent, f"{output_name}.approve"
            )
            published = False
            cleanup_snapshot: _DirectorySnapshot | None = None
            try:
                _checkpoint("approval-stage-created", fault, pause)
                for name in _REQUEST_NAMES:
                    _write_file(stage, name, source.files[name].data)
                stage_path = f"{output_parent_path}/{stage_name}"
                stage_descriptor_path = f"/proc/{os.getpid()}/fd/{stage.fileno()}"
                staged_source = _snapshot_directory(
                    stage_path, _REQUEST_NAMES, local=True
                )
                cleanup_snapshot = staged_source
                context = _request_preflight(
                    paths.pki_dir,
                    staged_source,
                    service,
                    operation,
                    request_id,
                    approval_key,
                    current_cert,
                    environment,
                    creating=True,
                )
                _approval_summary(context)
                _confirm(
                    f"approve {service} {request_id}",
                    "--yes" in arguments.provided,
                )
                created = int(datetime.datetime.now(datetime.UTC).timestamp())
                if (
                    context.request.created_epoch > created
                    or context.request.expires_epoch <= created
                ):
                    _die("CSR request is not nominally current for approval creation")
                expires = min(created + 86400, context.request.expires_epoch)
                if expires <= created:
                    _die("CSR approval validity interval would be empty")
                record = context.request.record
                approval_data = serialize_csr_approval(
                    {
                        "schema": "1",
                        "request_id": request_id,
                        "nonce": record["nonce"],
                        "created_epoch": str(created),
                        "expires_epoch": str(expires),
                        "approver_principal": context.trust.approver_principal,
                        "request_sha256": _sha256(context.request.to_bytes()),
                        "csr_sha256": context.csr_digest,
                        "inventory_sha256": context.inventory_digest,
                        "operation": operation,
                        "service": service,
                        "target": record["target"],
                        "profile": record["profile"],
                    }
                )
                approval_item = _write_file(stage, "approval", approval_data)
                cleanup_snapshot = _snapshot_directory(
                    stage_path, (*_REQUEST_NAMES, "approval"), local=True
                )
                try:
                    with OpenedFile(
                        approval_key,
                        policy=FilePolicy(
                            owner=_OWNER,
                            forbidden_bits=0o077,
                            links=1,
                            max_size=1024 * 1024,
                        ),
                        expected_identity=context.approval_key.identity,
                    ) as key:
                        result = run_ssh_keygen(
                            (
                                "ssh-keygen",
                                "-Y",
                                "sign",
                                "-f",
                                f"/proc/self/fd/{key.fileno()}",
                                "-n",
                                "platform-pki-csr-approval-v1",
                                f"{stage_descriptor_path}/approval",
                            ),
                            environment,
                            pass_fds=(key.fileno(), stage.fileno()),
                        )
                        if result.status:
                            _die("CSR approval signing failed")
                        key.recheck()
                except FilesystemError:
                    _die("Approval signing key changed during signing")
                signature_path = f"{stage_descriptor_path}/approval.sig"
                signature_item: _CsrInput | None = None
                descriptor = -1
                try:
                    descriptor = os.open(
                        signature_path,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    )
                    os.fchmod(descriptor, 0o600)
                    os.fsync(descriptor)
                    signature_identity = identity_from_stat(os.fstat(descriptor))
                    if (
                        signature_identity.kind != "regular"
                        or signature_identity.uid != _OWNER
                        or signature_identity.permissions != 0o600
                        or signature_identity.links != 1
                        or signature_identity.size <= 0
                        or signature_identity.size > 1024 * 1024
                    ):
                        raise OSError
                    signature_data = os.pread(
                        descriptor, signature_identity.size + 1, 0
                    )
                    if len(signature_data) != signature_identity.size:
                        raise OSError
                    signature_item = _CsrInput(
                        f"{stage_path}/approval.sig",
                        signature_identity,
                        signature_data,
                    )
                    os.close(descriptor)
                    descriptor = -1
                except OSError:
                    _die("CSR approval signature could not be protected")
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                assert signature_item is not None
                cleanup_snapshot = _snapshot_directory(
                    stage_path, _APPROVED_NAMES, local=True
                )
                _validate_approval(
                    context,
                    staged_source,
                    _CsrInput(
                        f"{stage_path}/approval",
                        approval_item.identity,
                        approval_data,
                    ),
                    signature_item,
                    environment,
                    exact_source=False,
                )
                source.recheck("Offline CSR request source")
                _checkpoint("approval-validated", fault, pause)
                final_snapshot = _snapshot_directory(
                    stage_path, _APPROVED_NAMES, local=True
                )
                authenticated = {
                    **staged_source.files,
                    "approval": _CsrInput(
                        f"{stage_path}/approval",
                        approval_item.identity,
                        approval_data,
                    ),
                    "approval.sig": signature_item,
                }
                if any(
                    final_snapshot.files[name].identity != authenticated[name].identity
                    or final_snapshot.files[name].data != authenticated[name].data
                    for name in _APPROVED_NAMES
                ):
                    _die("Offline CSR approval changed after authentication")
                cleanup_snapshot = final_snapshot
                durable_stage = output_parent.open_directory(
                    stage_name, policy=_PRIVATE_DIRECTORY
                )
                try:
                    readiness = fsync_tree(
                        durable_stage, output_parent, stage_name
                    )

                    def pre_publish() -> None:
                        source.recheck("Offline CSR request source")
                        final_snapshot.recheck(
                            "Authenticated offline CSR approval stage"
                        )
                        _recheck_preflight(
                            staged_source,
                            context,
                            environment,
                            exact_source=False,
                        )

                    _checkpoint("approval-before-publication", fault, pause)
                    result = publish_no_clobber(
                        output_parent,
                        stage_name,
                        durable_stage.recheck(),
                        output_parent,
                        output_name,
                        readiness=readiness,
                        pre_publish_check=pre_publish,
                    )
                finally:
                    durable_stage.close()
                published = True
                _checkpoint("approval-after-publication", fault, pause)
                final = _snapshot_directory(output_dir, _APPROVED_NAMES, local=True)
                if any(
                    final.files[name].data != final_snapshot.files[name].data
                    for name in _APPROVED_NAMES
                ) or final.identity != result.identity.directory:
                    _die("Published offline CSR approval changed")
                _json(
                    {
                        "status": "created",
                        "service": service,
                        "request_id": request_id,
                        "approval_dir": output_dir,
                        "approval_sha256": _sha256(approval_data),
                    }
                )
                return 0
            finally:
                stage.close()
                if not published:
                    _cleanup_stage(
                        output_parent,
                        stage_name,
                        stage_identity,
                        expected_snapshot=cleanup_snapshot,
                        empty_only=cleanup_snapshot is None,
                    )
    raise AssertionError("unreachable")


def _sign(arguments: ParseResult, environment: Mapping[str, str]) -> int:
    paths = resolve_paths(arguments.values, environment)
    require_pki_directory(paths.pki_dir)
    service = str(arguments["service"])
    operation = str(arguments["--operation"])
    request_id = str(arguments["--request-id"])
    if _REQUEST_ID.fullmatch(request_id) is None:
        _die("Offline CSR request ID must be 32 lowercase hexadecimal characters")
    input_dir = _absolute(str(arguments["--input-dir"]), environment)
    response_key = _absolute(str(arguments["--response-key"]), environment)
    pass_value = arguments.values.get("--intermediate-pass-file")
    passphrase = None if pass_value is None else _absolute(str(pass_value), environment)
    current_value = arguments.values.get("--current-cert-file")
    current_cert = None if current_value is None else _absolute(str(current_value), environment)
    source = _snapshot_directory(input_dir, _APPROVED_NAMES, local=False)
    try:
        request = parse_csr_request(source.files["request"].data)
        approval = parse_csr_approval(source.files["approval"].data)
    except CsrProtocolError as error:
        _die(str(error))
    if any(
        (
            request.record["service"] != service,
            request.record["operation"] != operation,
            request.record["request_id"] != request_id,
            approval.record["service"] != service,
            approval.record["operation"] != operation,
            approval.record["request_id"] != request_id,
        )
    ):
        _die("Offline CSR explicit coordinates do not match the approved request")

    temporary_parent = environment.get("TMPDIR") or tempfile.gettempdir()
    stage_path, stage_identity = _temporary_work(temporary_parent)
    stage = OpenedDirectory(stage_path, policy=_PRIVATE_DIRECTORY)
    try:
        for name in _APPROVED_NAMES:
            _write_file(stage, name, source.files[name].data)
        stage_snapshot = _snapshot_directory(
            stage_path, _APPROVED_NAMES, local=True
        )

        confirmed = False

        def review(values: HostLocalCsrReview) -> bool:
            nonlocal confirmed
            source.recheck("Offline CSR approved source")
            stage_snapshot.recheck("Offline CSR protected signing stage")
            print("Authenticated offline CSR signing review:", file=sys.stderr)
            for name in (
                "operation",
                "service",
                "target",
                "request_id",
                "request_sha256",
                "approval_sha256",
                "csr_sha256",
                "inventory_sha256",
                "response_principal",
            ):
                print(f"  {name}={getattr(values, name)}", file=sys.stderr)
            print(
                "  warning=request ID and nonce will be permanently consumed",
                file=sys.stderr,
            )
            _confirm(
                f"sign {operation} {service} {request_id}",
                "--yes" in arguments.provided,
            )
            source.recheck("Offline CSR approved source")
            stage_snapshot.recheck("Offline CSR protected signing stage")
            confirmed = True
            return True

        fault = FaultHook(
            crash_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT"),
            signal_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_SIGNAL_AT"),
            failure_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_FAILURE_AT"),
            signum=int(
                environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_SIGNAL", "15")
            ),
        )
        pause = PauseHook(
            pause_at=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_AT"),
            marker=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_MARKER"),
            release=environment.get("PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_RELEASE"),
        )
        options = {
            "pki_dir": paths.pki_dir,
            "request_file": f"{stage_path}/request",
            "request_signature": f"{stage_path}/request.sig",
            "approval_file": f"{stage_path}/approval",
            "approval_signature": f"{stage_path}/approval.sig",
            "csr_file": f"{stage_path}/tls.csr",
            "response_key": response_key,
            "intermediate_pass_file": passphrase,
            "issuer_safety_days": str(arguments["--issuer-safety-days"]),
            "environment": environment,
            "output": io.StringIO(),
            "fault_hook": fault,
            "pause_hook": pause,
            "precommit_review": review,
        }
        if operation == "renew":
            assert current_cert is not None
            status = renew_host_local_csr(
                service, current_cert_file=current_cert, **options
            )
        else:
            status = issue_host_local_csr(service, **options)
        if status != 0 or not confirmed:
            _die("Offline CSR signing did not complete")
        _json(
            {
                "status": "signed",
                "operation": operation,
                "service": service,
                "request_id": request_id,
                "recovery_action": "none",
            }
        )
        return 0
    finally:
        stage.close()
        _remove_work(stage_path, stage_identity)


def offline_csr(
    arguments: ParseResult,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Run one offline CSR approval or signing leaf."""

    if not isinstance(arguments, ParseResult):
        raise TypeError("arguments must be a ParseResult")
    process_environment = dict(os.environ if environment is None else environment)
    previous_umask = os.umask(0o077)
    try:
        if arguments.spec.route == ("offline-csr", "approve"):
            return _approve(arguments, process_environment)
        if arguments.spec.route == ("offline-csr", "sign"):
            return _sign(arguments, process_environment)
        raise ValueError("unsupported offline CSR route")
    finally:
        os.umask(previous_umask)
