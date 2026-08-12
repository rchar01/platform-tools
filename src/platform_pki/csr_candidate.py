"""Public verification and immutable decisions for host-local CSR candidates."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import signal
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Literal, NoReturn

from .csr_history import (
    CSR_ACTIVE_FIELDS,
    CSR_DECISION_FIELDS,
    CsrCandidateSourceAuthentication,
    CsrCandidateInventoryAuthentication,
    CsrFreshDeploymentAuthentication,
    CsrHistoryAuthentication,
    CsrHistoryError,
    CsrManagedPredecessorAuthentication,
    CsrOptionalActiveAuthentication,
    authenticate_candidate_source,
    authenticate_candidate_inventory,
    authenticate_fresh_deployment,
    authenticate_managed_predecessor,
    authenticate_optional_active_history,
    authenticate_retained_terminal_outcome,
)
from .csr_protocol import CsrOperation
from .csr_recover import recover_finalization_locked, recovery_hooks
from .csr_recovery import (
    CANDIDATE_FINALIZATION_JOURNAL_FIELDS,
    CANDIDATE_SOURCE_PATHS,
    CsrRecoveryError,
    parse_finalization_journal,
)
from .errors import ApplicationError
from .filesystem import (
    ABSENT,
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    identity_from_stat,
    fsync_directory,
)
from .operational import (
    acquire_operational_locks,
    prepare_control_state,
    require_generation_layout,
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
    validate_service_name,
)
from .parser import ParseResult
from .persisted_identity import (
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
)
from .publication import (
    PublicationError,
    TreeReadiness,
    atomic_write_bytes,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    stage_file_bytes,
    unlink_exact,
)
from .records import RecordError, RecordSpec


_OWNER = os.geteuid()
_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_FILE = FilePolicy(owner=_OWNER, mode=0o600, links=1, max_size=64 * 1024 * 1024)
_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DECISION_SPEC = RecordSpec(CSR_DECISION_FIELDS, schema="1")
_ACTIVE_SPEC = RecordSpec(CSR_ACTIVE_FIELDS, schema="1")
_OUTCOME_FILES = frozenset(
    ("deployment", "deployment.sig", "deployers.allowed_signers", "decision")
)
_STAGE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


@contextmanager
def _handled_signals() -> Iterator[None]:
    previous: dict[signal.Signals, object] = {}

    def stop(signum: int, _frame: object) -> NoReturn:
        process_signal = signal.Signals(signum)
        raise ApplicationError(
            f"CSR candidate operation interrupted by {process_signal.name}",
            status=128 + signum,
        )

    try:
        for process_signal in _HANDLED_SIGNALS:
            previous[process_signal] = signal.signal(process_signal, stop)
        yield
    finally:
        for process_signal, handler in previous.items():
            signal.signal(process_signal, handler)  # type: ignore[arg-type]


@contextmanager
def _defer_handled_signals() -> Iterator[None]:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, _HANDLED_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _stage_suffix() -> str:
    return "".join(secrets.choice(_STAGE_ALPHABET) for _ in range(6))


def _history(call: Callable[[], object]) -> object:
    try:
        return call()
    except CsrHistoryError as error:
        _die(str(error))


def _ensure_child(parent: OpenedDirectory, name: str, label: str) -> OpenedDirectory:
    try:
        if parent.identity_at(name) is ABSENT:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            fsync_directory(parent)
        return parent.open_directory(name, policy=_DIRECTORY)
    except (OSError, FilesystemError):
        _die(f"Cannot create or validate {label}")


def _prepare_directory(pki_dir: str, components: tuple[str, ...], label: str) -> OpenedDirectory:
    current: OpenedDirectory | None = None
    try:
        current = OpenedDirectory(pki_dir, policy=_DIRECTORY)
        for name in components:
            child = _ensure_child(current, name, label)
            current.close()
            current = child
        return current
    except BaseException:
        if current is not None:
            current.close()
        raise


def _write_file(directory: OpenedDirectory, name: str, data: bytes) -> FileIdentity:
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
                    raise OSError("write made no progress")
                view = view[written:]
        finally:
            view.release()
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        identity = identity_from_stat(os.fstat(descriptor))
        _FILE.validate(identity)
        if identity.size != len(data) or directory.identity_at(name) != identity:
            raise OSError("staged identity mismatch")
        return identity
    except (OSError, FilesystemError):
        _die(f"Cannot stage CSR outcome member: {name}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _decision_values(
    source: CsrCandidateSourceAuthentication,
    deployment: CsrFreshDeploymentAuthentication,
    action: Literal["finalize", "abandon"],
    predecessor: Mapping[str, str],
) -> dict[str, str]:
    request_id = source.response["request_id"]
    resulting = (
        request_id
        if action == "finalize"
        else predecessor["request_id"]
        if predecessor["kind"] == "host-local"
        else "none"
    )
    return {
        "schema": "1",
        "action": action,
        "state": "finalized" if action == "finalize" else "abandoned",
        "service": source.response["service"],
        "target": source.response["target"],
        "request_id": request_id,
        "operation": source.response["operation"],
        "request_sha256": source.response["request_sha256"],
        "response_sha256": source.response_sha256,
        "response_signature_sha256": source.response_signature_sha256,
        "candidate_sha256": source.candidate_sha256,
        "artifact_manifest_sha256": source.artifact_manifest_sha256,
        "certificate_sha256": source.certificate_sha256,
        "certificate_spki_sha256": source.certificate_spki_sha256,
        "chain_sha256": source.chain_sha256,
        "fullchain_sha256": source.fullchain_sha256,
        "deployment_sha256": deployment.deployment_sha256,
        "deployment_signature_sha256": deployment.deployment_signature_sha256,
        "deployers_sha256": deployment.deployers_sha256,
        "predecessor_kind": predecessor["kind"],
        "predecessor_request_id": predecessor["request_id"],
        "predecessor_certificate_sha256": predecessor["certificate_sha256"],
        "predecessor_certificate_spki_sha256": predecessor["certificate_spki_sha256"],
        "predecessor_intermediate_sha256": predecessor["intermediate_sha256"],
        "predecessor_response_sha256": predecessor["response_sha256"],
        "predecessor_artifact_manifest_sha256": predecessor["artifact_manifest_sha256"],
        "predecessor_deployment_sha256": predecessor["deployment_sha256"],
        "predecessor_decision_sha256": predecessor["decision_sha256"],
        "resulting_active_request_id": resulting,
        "created_epoch": deployment.deployment["created_epoch"],
    }


def _active_values(
    source: CsrCandidateSourceAuthentication,
    deployment: CsrFreshDeploymentAuthentication,
    decision_sha256: str,
) -> dict[str, str]:
    return {
        "schema": "1",
        "service": source.response["service"],
        "target": source.response["target"],
        "request_id": source.response["request_id"],
        "operation": source.response["operation"],
        "certificate_sha256": source.certificate_sha256,
        "certificate_spki_sha256": source.certificate_spki_sha256,
        "response_sha256": source.response_sha256,
        "artifact_manifest_sha256": source.artifact_manifest_sha256,
        "deployment_sha256": deployment.deployment_sha256,
        "decision_sha256": decision_sha256,
        "activation_epoch": deployment.deployment["activation_epoch"],
        "rollback_hold_until_epoch": deployment.deployment[
            "rollback_hold_until_epoch"
        ],
        "updated_epoch": deployment.deployment["created_epoch"],
    }


def _predecessor_from_history(history: CsrHistoryAuthentication) -> dict[str, str]:
    return {
        "kind": "host-local",
        "request_id": history.root_request_id,
        "certificate_sha256": history.certificate_sha256,
        "certificate_spki_sha256": history.certificate_spki_sha256,
        "intermediate_sha256": history.intermediate_sha256,
        "response_sha256": history.response_sha256,
        "artifact_manifest_sha256": history.artifact_manifest_sha256,
        "deployment_sha256": history.deployment_sha256,
        "decision_sha256": history.decision_sha256,
    }


def _predecessor_from_decision(history: CsrHistoryAuthentication) -> dict[str, str]:
    decision = history.decision
    return {
        "kind": decision["predecessor_kind"],
        "request_id": decision["predecessor_request_id"],
        "certificate_sha256": decision["predecessor_certificate_sha256"],
        "certificate_spki_sha256": decision[
            "predecessor_certificate_spki_sha256"
        ],
        "intermediate_sha256": decision["predecessor_intermediate_sha256"],
        "response_sha256": decision["predecessor_response_sha256"],
        "artifact_manifest_sha256": decision[
            "predecessor_artifact_manifest_sha256"
        ],
        "deployment_sha256": decision["predecessor_deployment_sha256"],
        "decision_sha256": decision["predecessor_decision_sha256"],
    }


def _empty_predecessor() -> dict[str, str]:
    return {
        "kind": "none",
        "request_id": "none",
        "certificate_sha256": "none",
        "certificate_spki_sha256": "none",
        "intermediate_sha256": "none",
        "response_sha256": "none",
        "artifact_manifest_sha256": "none",
        "deployment_sha256": "none",
        "decision_sha256": "none",
    }


def _new_predecessor(
    pki_dir: str,
    source: CsrCandidateSourceAuthentication,
    service: object,
    active: CsrOptionalActiveAuthentication,
    environment: Mapping[str, str],
) -> tuple[dict[str, str], CsrManagedPredecessorAuthentication | None]:
    operation = CsrOperation(source.response["operation"])
    if operation is CsrOperation.RENEW:
        if active.history is None:
            _die(f"Host-local active accepted-evidence pointer is missing: {source.response['service']}")
        if active.history.certificate_sha256 != source.current_cert_sha256:
            _die("Renewal predecessor does not match the request current certificate")
        return _predecessor_from_history(active.history), None
    if operation is CsrOperation.MIGRATE:
        if active.history is not None:
            _die("Migration cannot finalize while a host-local active pointer exists")
        managed = _history(
            lambda: authenticate_managed_predecessor(
                pki_dir,
                service,  # type: ignore[arg-type]
                source.current_cert_sha256,
                environment,
            )
        )
        assert isinstance(managed, CsrManagedPredecessorAuthentication)
        result = _empty_predecessor()
        result.update(
            kind="managed",
            certificate_sha256=managed.certificate_sha256,
            certificate_spki_sha256=managed.certificate_spki_sha256,
            intermediate_sha256=managed.intermediate_sha256,
        )
        return result, managed
    if active.history is not None:
        _die("Issue cannot finalize while a host-local active pointer exists")
    if source.current_cert_sha256 != "none":
        _die("Issue candidate unexpectedly binds a predecessor")
    return _empty_predecessor(), None


def _existing_outcome(
    pki_dir: str,
    service: object,
    request_id: str,
    environment: Mapping[str, str],
) -> CsrHistoryAuthentication | None:
    path = f"{pki_dir}/state/csr/outcomes/{getattr(service, 'name')}/{request_id}"
    if not os.path.lexists(path):
        return None
    result = _history(
        lambda: authenticate_retained_terminal_outcome(
            pki_dir, service, request_id, environment  # type: ignore[arg-type]
        )
    )
    assert isinstance(result, CsrHistoryAuthentication)
    return result


def _status(
    source: CsrCandidateSourceAuthentication,
    outcome: CsrHistoryAuthentication | None,
    active: CsrOptionalActiveAuthentication,
    output_format: str,
) -> int:
    state = "pending" if outcome is None else outcome.root_state
    accepted = "inactive"
    if active.history is not None and active.history.root_request_id == source.response["request_id"]:
        if (
            outcome is None
            or state != "finalized"
            or active.history.certificate_sha256 != source.certificate_sha256
            or active.history.certificate_spki_sha256
            != source.certificate_spki_sha256
            or active.history.response_sha256 != source.response_sha256
            or active.history.artifact_manifest_sha256
            != source.artifact_manifest_sha256
            or active.history.deployment_sha256 != outcome.deployment_sha256
            or active.history.decision_sha256 != outcome.decision_sha256
        ):
            _die(
                "Active accepted-evidence pointer does not bind the exact finalized outcome"
            )
        accepted = "active"
    elif state == "finalized":
        accepted = "superseded"
    values = {
        "schema": 1,
        "kind": "csr-candidate-status",
        "service": source.response["service"],
        "request_id": source.response["request_id"],
        "state": state,
        "accepted_evidence_state": accepted,
        "live_state_claimed": False,
    }
    if output_format == "json":
        print(json.dumps(values, sort_keys=True, separators=(",", ":")))
    else:
        print(f"service={values['service']}")
        print(f"request_id={values['request_id']}")
        print(f"state={state}")
        print(f"accepted_evidence_state={accepted}")
        print("live_state_claimed=false")
    return 0


def _create_outcome_stage(
    parent: OpenedDirectory,
    request_id: str,
    deployment: CsrFreshDeploymentAuthentication,
    decision: bytes,
) -> tuple[str, OpenedDirectory, FileIdentity, Mapping[str, FileIdentity], TreeReadiness]:
    for _attempt in range(16):
        name = f".platform-pki-csr-outcome.{request_id}.{_stage_suffix()}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            break
        except FileExistsError:
            continue
        except OSError:
            _die("Cannot create CSR outcome stage")
    else:
        _die("Cannot create CSR outcome stage")
    directory: OpenedDirectory | None = None
    created_identity: FileIdentity | None = None
    try:
        directory = parent.open_directory(name, policy=_DIRECTORY)
        created_identity = directory.recheck()
        if parent.identity_at(name) != created_identity:
            _die("CSR outcome stage changed during creation")
        files = {
            "deployment": _write_file(
                directory, "deployment", deployment.deployment_bytes
            ),
            "deployment.sig": _write_file(
                directory, "deployment.sig", deployment.signature_bytes
            ),
            "deployers.allowed_signers": _write_file(
                directory, "deployers.allowed_signers", deployment.deployers_bytes
            ),
            "decision": _write_file(directory, "decision", decision),
        }
        if frozenset(os.listdir(directory.fileno())) != _OUTCOME_FILES:
            _die("Staged CSR outcome has unexpected entries")
        directory.close()
        directory = parent.open_directory(name, policy=_DIRECTORY)
        readiness = fsync_tree(directory, parent, name)
        return name, directory, directory.identity, files, readiness
    except BaseException:
        if directory is not None:
            directory.close()
        with _defer_handled_signals():
            try:
                if created_identity is None:
                    raise FilesystemError("outcome stage identity is unavailable")
                partial = parent.open_directory(
                    name,
                    policy=_DIRECTORY,
                    expected_identity=created_identity.directory,
                )
                try:
                    partial_identity = partial.recheck()
                    partial_readiness = fsync_tree(partial, parent, name)
                finally:
                    partial.close()
                remove_exact_tree(
                    parent,
                    name,
                    partial_identity,
                    partial_readiness,
                )
            except (FilesystemError, PublicationError):
                retained = os.path.realpath(f"/proc/self/fd/{parent.fileno()}")
                print(
                    "[WARN] Partial CSR outcome stage could not be removed safely "
                    "after identity change at: "
                    f"{retained}/{name}",
                    file=sys.stderr,
                    flush=True,
                )
        raise


def _cleanup_stage(
    parent: OpenedDirectory,
    name: str,
    directory: OpenedDirectory,
    identity: FileIdentity,
    readiness: TreeReadiness,
) -> None:
    with _defer_handled_signals():
        directory.close()
        try:
            remove_exact_tree(parent, name, identity, readiness)
        except PublicationError:
            print(
                "[WARN] CSR candidate staging evidence retained for inspection: "
                f"{os.path.realpath(f'/proc/self/fd/{parent.fileno()}')}/{name}",
                file=sys.stderr,
                flush=True,
            )


def _publish_abandon(
    pki_dir: str,
    service_name: str,
    request_id: str,
    source: CsrCandidateSourceAuthentication,
    deployment: CsrFreshDeploymentAuthentication,
    predecessor: Mapping[str, str],
    rechecks: tuple[Callable[[], None], ...],
) -> int:
    parent = _prepare_directory(
        pki_dir, ("state", "csr", "outcomes", service_name), "CSR outcome directory"
    )
    stage: tuple[str, OpenedDirectory, FileIdentity, Mapping[str, FileIdentity], TreeReadiness] | None = None
    try:
        decision = _DECISION_SPEC.serialize(
            _decision_values(source, deployment, "abandon", predecessor)
        )
        with _defer_handled_signals():
            stage = _create_outcome_stage(parent, request_id, deployment, decision)
        name, directory, identity, _files, readiness = stage
        for recheck in rechecks:
            recheck()
        def pre_publish_check() -> None:
            for recheck in rechecks:
                recheck()
        try:
            with _defer_handled_signals():
                publish_no_clobber(
                    parent,
                    name,
                    identity,
                    parent,
                    request_id,
                    readiness=readiness,
                    pre_publish_check=pre_publish_check,
                )
                directory.close()
                stage = None
        except PublicationError:
            _die("Cannot publish immutable CSR abandonment outcome")
        print(
            "[OK] Abandoned authenticated CSR candidate evidence without revocation: "
            f"{pki_dir}/state/csr/outcomes/{service_name}/{request_id}"
        )
        return 0
    except RecordError:
        _die("Cannot serialize CSR candidate decision")
    finally:
        if stage is not None:
            _cleanup_stage(parent, stage[0], stage[1], stage[2], stage[4])
        parent.close()


def _journal_bytes(values: Mapping[str, str], pki_dir: str) -> bytes:
    try:
        data = b"".join(
            f"{field}={values[field]}\n".encode("ascii")
            for field in CANDIDATE_FINALIZATION_JOURNAL_FIELDS
        )
        parse_finalization_journal(data, pki_dir=pki_dir)
        return data
    except CsrRecoveryError as error:
        _die(str(error))
    except (KeyError, UnicodeEncodeError):
        _die("CSR finalization recovery journal could not be serialized safely")


def _exact_journal_published(
    parent: OpenedDirectory, journal: bytes, pki_dir: str
) -> bool:
    data = b""
    try:
        identity = parent.identity_at("finalization-recovery-journal")
        if identity is ABSENT:
            return False
        if not isinstance(identity, FileIdentity):
            _die("CSR finalization recovery journal is unsafe")
        with parent.open_file(
            "finalization-recovery-journal",
            policy=_FILE,
            expected_identity=identity,
        ) as opened:
            data = opened.read(_FILE.max_size or 0)
            opened.recheck()
        parent.recheck()
    except FilesystemError:
        _die("CSR finalization recovery journal could not be reconciled safely")
    if data != journal:
        _die("Existing CSR finalization recovery journal conflicts with this decision")
    try:
        parse_finalization_journal(data, pki_dir=pki_dir)
    except CsrRecoveryError as error:
        _die(str(error))
    return True


def _publish_finalize(
    pki_dir: str,
    service_name: str,
    request_id: str,
    source: CsrCandidateSourceAuthentication,
    deployment: CsrFreshDeploymentAuthentication,
    predecessor: Mapping[str, str],
    active: CsrOptionalActiveAuthentication,
    rechecks: tuple[Callable[[], None], ...],
    environment: Mapping[str, str],
) -> int:
    outcome_parent = _prepare_directory(
        pki_dir, ("state", "csr", "outcomes", service_name), "CSR outcome directory"
    )
    active_parent = _prepare_directory(
        pki_dir, ("state", "csr", "active"), "CSR active pointer directory"
    )
    outcome_stage = None
    active_stage_name: str | None = None
    active_stage_identity: FileIdentity | None = None
    journal_written = False
    active_pre_sha = "none"
    fault, pause = recovery_hooks(environment)
    try:
        decision = _DECISION_SPEC.serialize(
            _decision_values(source, deployment, "finalize", predecessor)
        )
        decision_sha = hashlib.sha256(decision).hexdigest()
        with _defer_handled_signals():
            outcome_stage = _create_outcome_stage(
                outcome_parent, request_id, deployment, decision
            )
            fault("outcome-staged")
        outcome_name, outcome_directory, outcome_identity, outcome_files, outcome_ready = outcome_stage
        active_bytes = _ACTIVE_SPEC.serialize(
            _active_values(source, deployment, decision_sha)
        )
        with _defer_handled_signals():
            for _attempt in range(16):
                active_stage_name = (
                    f".platform-pki-active.{service_name}.{_stage_suffix()}"
                )
                try:
                    result = atomic_write_bytes(
                        active_parent, active_stage_name, active_bytes
                    )
                    break
                except PublicationError:
                    continue
            else:
                _die("Cannot create active pointer stage")
            active_stage_identity = getattr(result, "identity", None)
            if not isinstance(active_stage_identity, FileIdentity):
                _die("Cannot validate active pointer stage")
            fault("active-staged")

        active_destination = f"{pki_dir}/state/csr/active/{service_name}"
        if active.history is None:
            active_pre_identity = "absent"
            active_pre_sha = "none"
            active_mode = "create"
        else:
            if active.history.active_identity is None:
                _die("Authenticated active pointer identity is unavailable")
            active_pre_identity = serialize_file_object_state(
                active.history.active_identity.state
            )
            try:
                with active_parent.open_file(
                    service_name,
                    policy=_FILE,
                    expected_identity=active.history.active_identity,
                ) as opened:
                    active_pre_sha = hashlib.sha256(
                        opened.read(_FILE.max_size or 0)
                    ).hexdigest()
            except FilesystemError:
                _die("Pre-finalization active pointer changed")
            active_mode = "exchange"

        values = {field: "none" for field in CANDIDATE_FINALIZATION_JOURNAL_FIELDS}
        values.update(
            schema="1",
            operation="csr-finalize",
            service=service_name,
            request_id=request_id,
            phase="planned",
            outcome_stage=f"{pki_dir}/state/csr/outcomes/{service_name}/{outcome_name}",
            outcome_stage_identity=serialize_directory_identity(
                outcome_identity.directory
            ),
            outcome_destination=f"{pki_dir}/state/csr/outcomes/{service_name}/{request_id}",
            active_stage=f"{pki_dir}/state/csr/active/{active_stage_name}",
            active_stage_identity=serialize_file_object_state(
                active_stage_identity.state
            ),
            active_destination=active_destination,
            active_pre_identity=active_pre_identity,
            active_mode=active_mode,
            active_pre_sha256=active_pre_sha,
            candidate_dir=f"{pki_dir}/state/csr/candidates/{service_name}/{request_id}",
            candidate_dir_identity=serialize_directory_identity(
                source.source_directories["candidate"]
            ),
            response_dir=f"{pki_dir}/state/csr/responses/{service_name}/{request_id}",
            response_dir_identity=serialize_directory_identity(
                source.source_directories["response"]
            ),
            transaction_dir=source.transaction_path,
            transaction_dir_identity=serialize_directory_identity(
                source.transaction_identity
            ),
            response_trust_path=source.response_trust_path,
            response_trust_identity=serialize_file_identity(
                source.response_trust_identity
            ),
            response_trust_sha256=source.response_trust_sha256,
            candidate_path=f"{pki_dir}/state/csr/candidates/{service_name}/{request_id}/candidate",
            candidate_identity=serialize_file_identity(
                source.source_files["candidate_candidate"]
            ),
            candidate_sha256=source.candidate_sha256,
            artifact_dir=f"{pki_dir}/export/certificates/v1/artifacts/{service_name}/{request_id}",
            artifact_dir_identity=serialize_directory_identity(
                source.source_directories["artifact"]
            ),
            artifact_path=f"{pki_dir}/export/certificates/v1/artifacts/{service_name}/{request_id}/artifact",
            artifact_identity=serialize_file_identity(
                source.source_files["artifact_artifact"]
            ),
            artifact_sha256=source.artifact_manifest_sha256,
            response_path=f"{pki_dir}/state/csr/responses/{service_name}/{request_id}/response",
            response_identity=serialize_file_identity(
                source.source_files["response_response"]
            ),
            response_sha256=source.response_sha256,
            response_signature_path=f"{pki_dir}/state/csr/responses/{service_name}/{request_id}/response.sig",
            response_signature_identity=serialize_file_identity(
                source.source_files["response_response_sig"]
            ),
            response_signature_sha256=source.response_signature_sha256,
            deployment_sha256=deployment.deployment_sha256,
            deployment_signature_sha256=deployment.deployment_signature_sha256,
            deployers_sha256=deployment.deployers_sha256,
            decision_sha256=decision_sha,
            active_sha256=hashlib.sha256(active_bytes).hexdigest(),
            outcome_deployment_identity=serialize_file_identity(
                outcome_files["deployment"]
            ),
            outcome_deployment_signature_identity=serialize_file_identity(
                outcome_files["deployment.sig"]
            ),
            outcome_deployers_identity=serialize_file_identity(
                outcome_files["deployers.allowed_signers"]
            ),
            outcome_decision_identity=serialize_file_identity(outcome_files["decision"]),
        )
        for key, _root, _name in CANDIDATE_SOURCE_PATHS:
            values[f"source_{key}_identity"] = serialize_file_identity(
                source.source_files[key]
            )
            values[f"source_{key}_sha256"] = source.source_digests[key]

        for recheck in rechecks:
            recheck()
        journal = _journal_bytes(values, pki_dir)
        with _defer_handled_signals():
            csr_state = OpenedDirectory(f"{pki_dir}/state/csr", policy=_DIRECTORY)
            try:
                journal_stage = stage_file_bytes(
                    csr_state, "finalization-recovery-journal", journal
                )
                def pre_journal_publish_check() -> None:
                    for recheck in rechecks:
                        recheck()
                try:
                    publish_no_clobber(
                        csr_state,
                        journal_stage.name,
                        journal_stage.identity,
                        csr_state,
                        "finalization-recovery-journal",
                        pre_publish_check=pre_journal_publish_check,
                        fault_hook=fault,
                        pause_hook=pause,
                    )
                    journal_stage.mark_consumed()
                except BaseException as error:
                    journal_written = _exact_journal_published(
                        csr_state, journal, pki_dir
                    )
                    if journal_written:
                        journal_stage.mark_consumed()
                    if isinstance(error, PublicationError):
                        _die("Cannot publish CSR finalization recovery journal")
                    raise
                finally:
                    try:
                        journal_stage.cleanup()
                    finally:
                        journal_stage.close()
                journal_written = True
            finally:
                csr_state.close()
        outcome_directory.close()
        outcome_stage = None
        try:
            recover_finalization_locked(
                pki_dir,
                transaction=f"csr-{request_id}",
                output=io.StringIO(),
                fault_hook=fault,
                pause_hook=pause,
            )
        finally:
            if not os.path.lexists(
                f"{pki_dir}/state/csr/finalization-recovery-journal"
            ):
                journal_written = False
                active_stage_name = None
        print(
            "[OK] Finalized authenticated CSR candidate evidence: "
            f"{pki_dir}/state/csr/outcomes/{service_name}/{request_id}"
        )
        return 0
    except RecordError:
        _die("Cannot serialize CSR candidate publication")
    finally:
        if journal_written:
            print(
                "[ERROR] CSR candidate finalization requires explicit recovery",
                file=sys.stderr,
                flush=True,
            )
        else:
            if outcome_stage is not None:
                _cleanup_stage(
                    outcome_parent,
                    outcome_stage[0],
                    outcome_stage[1],
                    outcome_stage[2],
                    outcome_stage[4],
                )
            if active_stage_name is not None and active_stage_identity is not None:
                try:
                    with _defer_handled_signals():
                        unlink_exact(
                            active_parent,
                            active_stage_name,
                            active_stage_identity,
                            fault_hook=fault,
                            pause_hook=pause,
                        )
                except PublicationError:
                    print(
                        "[WARN] CSR active-pointer stage retained for inspection",
                        file=sys.stderr,
                        flush=True,
                    )
        active_parent.close()
        outcome_parent.close()


def csr_candidate(arguments: ParseResult) -> int:
    """Run one public candidate verify, finalize, or abandon action."""

    if not isinstance(arguments, ParseResult):
        raise TypeError("arguments must be a ParseResult")
    environment = dict(os.environ)
    os.umask(0o077)
    service_name = arguments["service"]
    request_id = arguments["--request-id"]
    validate_service_name(service_name)
    if _REQUEST_ID.fullmatch(request_id) is None:
        _die("CSR candidate request ID is invalid")
    for program in ("openssl", "ssh-keygen"):
        require_program(program, environment)
    action = arguments.spec.route[1]
    if action != "verify" and "--yes" not in arguments.provided:
        if not sys.stdin.isatty():
            _die(f"CSR candidate {action} requires a TTY or --yes")
        print(
            f"Type {action} {service_name} {request_id} to continue: ",
            file=sys.stderr,
            end="",
            flush=True,
        )
        if sys.stdin.readline().rstrip("\n") != f"{action} {service_name} {request_id}":
            _die(f"CSR candidate {action} confirmation did not match")

    paths = resolve_paths(arguments.values, environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    with _handled_signals(), acquire_operational_locks(paths.pki_dir, "export"):
        require_no_unresolved_state(paths.pki_dir)
        require_generation_layout(paths.pki_dir)
        inventory_authentication = _history(
            lambda: authenticate_candidate_inventory(paths.pki_dir, service_name)
        )
        assert isinstance(
            inventory_authentication, CsrCandidateInventoryAuthentication
        )
        service = inventory_authentication.service
        if service.key_custody != "host-local":
            _die("CSR candidate command requires key_custody: host-local")
        try:
            source = _history(
                lambda: authenticate_candidate_source(
                    paths.pki_dir, service, request_id, environment
                )
            )
            assert isinstance(source, CsrCandidateSourceAuthentication)
            active = _history(
                lambda: authenticate_optional_active_history(
                    paths.pki_dir, service, environment
                )
            )
            assert isinstance(active, CsrOptionalActiveAuthentication)
            existing = _existing_outcome(
                paths.pki_dir, service, request_id, environment
            )
            if action == "verify":
                return _status(source, existing, active, arguments["--format"])

            manifest_digest = arguments["--artifact-manifest-sha256"]
            if _DIGEST.fullmatch(manifest_digest) is None:
                _die("--artifact-manifest-sha256 must be a lowercase SHA-256 digest")
            if manifest_digest != source.artifact_manifest_sha256:
                _die(
                    "Certificate export manifest digest does not match "
                    "--artifact-manifest-sha256"
                )
            if existing is None:
                predecessor, managed = _new_predecessor(
                    paths.pki_dir, source, service, active, environment
                )
            else:
                predecessor = _predecessor_from_decision(existing)
                managed = None
            evidence_path = os.path.abspath(os.path.expanduser(arguments["--evidence-file"]))
            signature_path = os.path.abspath(
                os.path.expanduser(arguments["--evidence-signature"])
            )
            deployment = _history(
                lambda: authenticate_fresh_deployment(
                    paths.pki_dir,
                    service,
                    source,
                    action,  # type: ignore[arg-type]
                    evidence_path,
                    signature_path,
                    environment,
                    predecessor_kind=predecessor["kind"],
                    predecessor_certificate_sha256=predecessor[
                        "certificate_sha256"
                    ],
                    predecessor_intermediate_sha256=predecessor[
                        "intermediate_sha256"
                    ],
                    retained_outcome=existing,
                )
            )
            assert isinstance(deployment, CsrFreshDeploymentAuthentication)
            if existing is not None:
                if existing.root_action != action:
                    _die("Existing CSR outcome conflicts with the requested decision")
                if (
                    existing.deployment_sha256 != deployment.deployment_sha256
                    or existing.deployment_signature_sha256
                    != deployment.deployment_signature_sha256
                    or existing.deployers_sha256 != deployment.deployers_sha256
                ):
                    _die(
                        "Existing CSR outcome conflicts with the supplied evidence or trust"
                    )
                if action == "finalize":
                    if (
                        active.history is None
                        or active.history.root_request_id != request_id
                        or active.history.deployment_sha256
                        != deployment.deployment_sha256
                        or active.history.decision_sha256 != existing.decision_sha256
                    ):
                        _die(
                            "Existing finalized outcome is not the active accepted evidence"
                        )
                print(
                    f"[OK] Kept exact {existing.root_state} CSR candidate outcome: "
                    f"{paths.pki_dir}/state/csr/outcomes/{service_name}/{request_id}"
                )
                return 0

            rechecks: list[Callable[[], None]] = [
                inventory_authentication,
                source,
                active,
                deployment,
            ]
            if managed is not None:
                rechecks.append(managed)
            if action == "abandon":
                return _publish_abandon(
                    paths.pki_dir,
                    service_name,
                    request_id,
                    source,
                    deployment,
                    predecessor,
                    tuple(rechecks),
                )
            return _publish_finalize(
                paths.pki_dir,
                service_name,
                request_id,
                source,
                deployment,
                predecessor,
                active,
                tuple(rechecks),
                environment,
            )
        except CsrHistoryError as error:
            _die(str(error))
